//! Memory daemon for automatic sync, embed, and reindex.
//!
//! The daemon runs in the background and:
//! - Performs initial sync/embed on startup
//! - Periodically syncs memory file changes
//! - Reponds to commands (sync_now, force_reindex, shutdown)
//! - Tracks health/status (last_sync_at, indexed_files, embedded_chunks)

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::memory::MemoryDb;

/// Daemon command channel messages.
#[derive(Debug)]
pub enum DaemonCommand {
    /// Trigger immediate sync (useful before search)
    SyncNow {
        respond_to: oneshot::Sender<Result<SyncStatus>>,
    },
    /// Force full reindex (clears embeddings, re-syncs, re-embeds)
    ForceReindex {
        respond_to: oneshot::Sender<Result<ReindexResult>>,
    },
    /// Shutdown daemon gracefully
    Shutdown {
        respond_to: oneshot::Sender<()>,
    },
}

/// Sync status snapshot.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncStatus {
    pub last_sync_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub indexed_files: usize,
    pub embedded_chunks: usize,
    pub is_syncing: bool,
}

/// Reindex result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReindexResult {
    pub files_reindexed: usize,
    pub chunks_embedded: usize,
    pub duration_secs: f64,
}

/// Daemon health/status snapshot.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DaemonStatus {
    pub is_running: bool,
    pub sync: SyncStatus,
    pub config: DaemonConfig,
}

/// Daemon configuration from Config.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DaemonConfig {
    pub enabled: bool,
    pub sync_interval_secs: usize,
    pub sync_on_search: bool,
    pub require_embeddings: bool,
    pub allow_lexical_fallback: bool,
    pub embedding_url: String,
    pub embedding_model: String,
    pub target_dims: usize,
}

impl DaemonConfig {
    /// Create a new embedding provider from this config.
    pub fn create_provider(&self) -> crate::memory::EmbeddingProvider {
        crate::memory::EmbeddingProvider::new(
            &self.embedding_url,
            &self.embedding_model,
            None, // no API key for local Ollama
            self.target_dims,
        )
    }
}

/// Memory daemon — in-process background service for memory indexing.
pub struct MemoryDaemon {
    #[allow(dead_code)]
    workspace: String,
    config: DaemonConfig,
    memory: Arc<MemoryDb>,
    command_tx: mpsc::Sender<DaemonCommand>,
    _handle: JoinHandle<()>,
}

impl MemoryDaemon {
    /// Start the memory daemon with the given configuration.
    ///
    /// - Performs initial sync/embed on startup
    /// - Runs periodic sync loop
    /// - Fails fast if Ollama unavailable and require_embeddings=true
    /// - Continues with lexical-only if allow_lexical_fallback=true
    pub async fn start(
        workspace: &std::path::Path,
        config: &Config,
        memory: Arc<MemoryDb>,
    ) -> Result<Self> {
        let workspace_str = workspace.to_string_lossy().to_string();

        // Extract daemon config
        let daemon_config = DaemonConfig {
            enabled: config.memory_daemon_enabled,
            sync_interval_secs: config.memory_sync_interval_secs,
            sync_on_search: config.memory_sync_on_search,
            require_embeddings: config.memory_require_embeddings,
            allow_lexical_fallback: config.memory_allow_lexical_fallback,
            embedding_url: config.memory_embedding_base_url.clone(),
            embedding_model: config.memory_embedding_model.clone(),
            target_dims: config.memory_embedding_target_dims,
        };

        if !daemon_config.enabled {
            log::info!("Memory daemon disabled by config");
            // Return a dummy daemon that's not actually running
            let (command_tx, _command_rx) = mpsc::channel(1);
            let handle = tokio::spawn(async {});
            return Ok(Self {
                workspace: workspace_str,
                config: daemon_config,
                memory,
                command_tx,
                _handle: handle,
            });
        }

        log::info!(
            "Starting memory daemon (interval={}s, model={}, dims={})",
            daemon_config.sync_interval_secs,
            daemon_config.embedding_model,
            daemon_config.target_dims
        );

        // Create embedding provider for verification
        let provider = daemon_config.create_provider();

        // Verify Ollama is reachable (with retry)
        Self::verify_ollama_reachable(&provider, daemon_config.require_embeddings, daemon_config.allow_lexical_fallback).await?;

        // Create command channel
        let (command_tx, mut command_rx) = mpsc::channel::<DaemonCommand>(16);

        // Check if reindex is needed before initial sync
        let needs_reindex = {
            let provider = daemon_config.create_provider();
            memory.needs_full_reindex(&provider.model(), provider.target_dims())
                .unwrap_or(false)
        };

        // Initial sync/embed (with reindex if needed)
        let memory_clone = Arc::clone(&memory);
        let config_clone = daemon_config.clone();
        tokio::spawn(async move {
            if needs_reindex {
                log::warn!("Config changed, forcing full reindex...");
                let provider = config_clone.create_provider();
                if let Err(e) = Self::execute_force_reindex(&memory_clone, &provider).await {
                    log::error!("Forced reindex failed: {}", e);
                }
            } else {
                Self::initial_sync(memory_clone, &config_clone).await;
            }
        });

        // Spawn daemon loop
        let memory_loop = memory.clone();
        let config_loop = daemon_config.clone();
        let interval_secs = daemon_config.sync_interval_secs;
        let handle = tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(Duration::from_secs(interval_secs as u64));
            interval_timer.tick().await; // skip first tick (we just did initial sync)

            loop {
                tokio::select! {
                    // Periodic sync
                    _ = interval_timer.tick() => {
                        let provider = config_loop.create_provider();
                        if let Err(e) = Self::sync_and_embed(&memory_loop, &provider).await {
                            log::warn!("Periodic sync failed: {}", e);
                        }
                    }
                    // Commands
                    Some(cmd) = command_rx.recv() => {
                        match cmd {
                            DaemonCommand::SyncNow { respond_to } => {
                                let provider = config_loop.create_provider();
                                let result = Self::sync_and_embed(&memory_loop, &provider).await;
                                let status = Self::get_sync_status(&*memory_loop);
                                let _ = respond_to.send(result.map(|_| status));
                            }
                            DaemonCommand::ForceReindex { respond_to } => {
                                let provider = config_loop.create_provider();
                                let result = Self::execute_force_reindex(&memory_loop, &provider).await;
                                let _ = respond_to.send(result);
                            }
                            DaemonCommand::Shutdown { respond_to } => {
                                log::info!("Memory daemon shutting down");
                                let _ = respond_to.send(());
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            workspace: workspace_str,
            config: daemon_config,
            memory,
            command_tx,
            _handle: handle,
        })
    }

    /// Verify Ollama is reachable (with retry).
    async fn verify_ollama_reachable(
        provider: &crate::memory::EmbeddingProvider,
        require_embeddings: bool,
        allow_lexical_fallback: bool,
    ) -> Result<()> {
        const MAX_RETRIES: usize = 5;
        const RETRY_DELAY_SECS: u64 = 2;

        for attempt in 1..=MAX_RETRIES {
            match tokio::time::timeout(
                Duration::from_secs(5),
                provider.embed_query("test"),
            ).await {
                Ok(Ok(_)) => {
                    log::info!("Ollama embedding service verified (attempt {})", attempt);
                    return Ok(());
                }
                Ok(Err(e)) => {
                    log::warn!("Ollama verification failed (attempt {}): {}", attempt, e);
                }
                Err(_) => {
                    log::warn!("Ollama verification timeout (attempt {})", attempt);
                }
            }

            if attempt < MAX_RETRIES {
                log::info!("Retrying Ollama connection in {}s...", RETRY_DELAY_SECS);
                tokio::time::sleep(Duration::from_secs(RETRY_DELAY_SECS)).await;
            }
        }

        // After all retries failed
        if require_embeddings {
            anyhow::bail!(
                "Ollama embedding service unreachable after {} attempts (require_embeddings=true). \
                 Ensure Ollama is running and model is pulled: ollama pull {}",
                MAX_RETRIES,
                provider.model()
            );
        } else if allow_lexical_fallback {
            log::warn!(
                "Ollama unreachable, continuing with lexical-only search (require_embeddings=false, allow_lexical_fallback=true)"
            );
            Ok(())
        } else {
            // Invalid config: require_embeddings=false but allow_lexical_fallback=false
            anyhow::bail!(
                "Ollama embedding service unreachable after {} attempts. \
                 Config has require_embeddings=false but allow_lexical_fallback=false, \
                 which is invalid. Either: (1) set require_embeddings=true and ensure Ollama is running, \
                 or (2) set allow_lexical_fallback=true to use keyword-only search.",
                MAX_RETRIES
            );
        }
    }

    /// Perform initial sync on daemon startup.
    async fn initial_sync(memory: Arc<MemoryDb>, config: &DaemonConfig) {
        log::info!("Performing initial memory sync...");

        let start = std::time::Instant::now();
        let provider = config.create_provider();
        match Self::sync_and_embed(&memory, &provider).await {
            Ok(_) => {
                let elapsed = start.elapsed().as_secs_f64();
                log::info!("Initial sync completed in {:.2}s", elapsed);
            }
            Err(e) => {
                log::error!("Initial sync failed: {}", e);
            }
        }
    }

    /// Sync and embed all memory chunks.
    async fn sync_and_embed(memory: &Arc<MemoryDb>, provider: &crate::memory::EmbeddingProvider) -> Result<()> {
        // Run blocking DB sync in spawn_blocking
        let memory_clone = memory.clone();
        let model = provider.model().to_string();
        let target_dims = provider.target_dims();
        let (sync_result, _embed_result) = tokio::task::spawn_blocking(move || {
            let sync_count = memory_clone.sync(&model, target_dims)
                .context("Sync failed")?;
            Ok::<_, anyhow::Error>((sync_count, ()))
        })
        .await??;

        log::debug!("Synced {} files", sync_result);

        // Embed chunks
        let embedded = memory.embed_all_chunks(provider).await?;
        log::debug!("Embedded {} chunks", embedded);

        Ok(())
    }

    /// Force full reindex: clear embeddings, re-sync, re-embed.
    async fn execute_force_reindex(memory: &Arc<MemoryDb>, provider: &crate::memory::EmbeddingProvider) -> Result<ReindexResult> {
        log::info!("Starting forced reindex...");
        let start = std::time::Instant::now();

        // Clear embeddings first
        memory.clear_embeddings().context("Failed to clear embeddings")?;

        // Run in spawn_blocking for DB operations
        let memory_clone = memory.clone();
        let model = provider.model().to_string();

        let files_reindexed = tokio::task::spawn_blocking(move || {
            // Re-sync with force_reindex=true to reindex ALL files, even unchanged ones
            let files = memory_clone.sync_with_options(&model, true, None)
                .context("Reindex sync failed")?;
            Ok::<_, anyhow::Error>(files)
        })
        .await??;

        // Re-embed all chunks
        let chunks_embedded = memory.embed_all_chunks(provider).await?;

        let duration = start.elapsed().as_secs_f64();

        log::info!(
            "Reindex complete: {} files, {} chunks in {:.2}s",
            files_reindexed,
            chunks_embedded,
            duration
        );

        Ok(ReindexResult {
            files_reindexed,
            chunks_embedded,
            duration_secs: duration,
        })
    }

    /// Get current sync status from memory DB.
    fn get_sync_status(memory: &MemoryDb) -> SyncStatus {
        // Get last sync time from metadata
        let last_sync_at = memory.get_index_metadata()
            .ok()
            .flatten()
            .and_then(|meta| {
                meta.last_sync_at
                    .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                    .map(|dt| dt.with_timezone(&Utc))
            });

        // Query real stats from database
        let (indexed_files, embedded_chunks) = {
            // Use index_status() method which is already public
            let status = memory.index_status().unwrap_or_else(|_| crate::memory::IndexStatus {
                files: 0,
                chunks: 0,
                embedded: 0,
                cached: 0,
                fts_available: false,
            });
            (status.files, status.embedded)
        };

        SyncStatus {
            last_sync_at,
            last_error: None,
            indexed_files,
            embedded_chunks,
            is_syncing: false,
        }
    }

    /// Request immediate sync (e.g., before search).
    /// If daemon is disabled, returns error.
    pub async fn sync_now_if_enabled(&self) -> Result<SyncStatus> {
        if !self.config.enabled {
            return Err(anyhow::anyhow!("Memory daemon is not enabled"));
        }
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(DaemonCommand::SyncNow { respond_to: tx })
            .await
            .context("Daemon channel closed")?;

        let status = rx.await
            .context("Daemon response failed")??;
        Ok(status)
    }

    /// Request force reindex.
    pub async fn force_reindex(&self) -> Result<ReindexResult> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(DaemonCommand::ForceReindex { respond_to: tx })
            .await
            .context("Daemon channel closed")?;

        rx.await
            .context("Daemon response failed")?
    }

    /// Get daemon status snapshot.
    pub fn status(&self) -> DaemonStatus {
        let sync_status = Self::get_sync_status(&*self.memory);

        DaemonStatus {
            is_running: self.config.enabled,
            sync: sync_status,
            config: self.config.clone(),
        }
    }

    /// Check if daemon has embedded chunks (for status reporting).
    pub fn has_embeddings(&self) -> bool {
        if !self.config.enabled {
            return false;
        }
        let status = Self::get_sync_status(&*self.memory);
        status.embedded_chunks > 0
    }

    /// Check if embeddings are available or if Ollama is reachable for new embeddings.
    /// This checks both existing embedded chunks AND current Ollama reachability.
    pub fn can_use_embeddings(&self) -> bool {
        if !self.config.enabled {
            return false;
        }

        // If we already have embedded chunks, that's good enough for now
        let status = Self::get_sync_status(&*self.memory);
        if status.embedded_chunks > 0 {
            return true;
        }

        // Otherwise, verify Ollama is actually reachable right now
        let provider = self.config.create_provider();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                match tokio::time::timeout(
                    Duration::from_secs(2),
                    provider.embed_query("test"),
                ).await {
                    Ok(Ok(_)) => {
                        log::info!("Ollama is reachable, enabling hybrid search");
                        true
                    },
                    Ok(Err(e)) => {
                        log::warn!("Ollama query failed: {}, disabling hybrid search", e);
                        false
                    },
                    Err(_) => {
                        log::warn!("Ollama timeout, disabling hybrid search");
                        false
                    },
                }
            })
        })
    }

    /// Shutdown daemon gracefully.
    pub async fn shutdown(self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(DaemonCommand::Shutdown { respond_to: tx })
            .await
            .context("Daemon channel closed")?;

        rx.await.context("Daemon shutdown failed")?;
        self._handle.await.context("Daemon task join failed")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These are basic unit tests. Integration tests for daemon startup/shutdown
    // would require running actual Ollama instances, which is environment-dependent.

    #[test]
    fn test_daemon_config_defaults() {
        let config = DaemonConfig {
            enabled: true,
            sync_interval_secs: 15,
            sync_on_search: true,
            require_embeddings: true,
            allow_lexical_fallback: false,
            embedding_url: "http://localhost:11434/v1".to_string(),
            embedding_model: "nomic-embed-text:v1.5".to_string(),
            target_dims: 512,
        };

        assert_eq!(config.enabled, true);
        assert_eq!(config.sync_interval_secs, 15);
        assert_eq!(config.target_dims, 512);
    }

    #[test]
    fn test_daemon_config_create_provider() {
        let config = DaemonConfig {
            enabled: true,
            sync_interval_secs: 15,
            sync_on_search: true,
            require_embeddings: true,
            allow_lexical_fallback: false,
            embedding_url: "http://localhost:11434/v1".to_string(),
            embedding_model: "test-model".to_string(),
            target_dims: 256,
        };

        let provider = config.create_provider();
        assert_eq!(provider.model(), "test-model");
        assert_eq!(provider.target_dims(), 256);
    }

    #[test]
    fn test_sync_status_serialization() {
        let status = SyncStatus {
            last_sync_at: Some(Utc::now()),
            last_error: None,
            indexed_files: 10,
            embedded_chunks: 50,
            is_syncing: false,
        };

        // Test that it serializes (used in daemon responses)
        let json = serde_json::to_string(&status);
        assert!(json.is_ok());
    }

    #[test]
    fn test_reindex_result_serialization() {
        let result = ReindexResult {
            files_reindexed: 5,
            chunks_embedded: 100,
            duration_secs: 2.5,
        };

        let json = serde_json::to_string(&result);
        assert!(json.is_ok());
    }
}
