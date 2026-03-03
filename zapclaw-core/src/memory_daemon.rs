//! Memory daemon for automatic sync, embed, and reindex.
//!
//! The daemon runs in the background and:
//! - Performs initial sync/embed on startup
//! - Periodically syncs memory file changes
//! - Reponds to commands (sync_now, force_reindex, shutdown)
//! - Tracks health/status (last_sync_at, indexed_files, embedded_chunks)

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// Set to `true` while a forced reindex is in progress.
    ///
    /// During reindex there is a window where embeddings are cleared but
    /// not yet re-generated. `can_use_embeddings()` returns `false` while
    /// this flag is set so callers fall back to lexical search consistently.
    reindexing: Arc<AtomicBool>,
    /// Cached health state — updated by the daemon loop after each sync.
    /// `true` if the last sync+embed succeeded, `false` if it failed.
    /// Replaces the old live-probe approach in `can_use_embeddings()`.
    embeddings_healthy: Arc<AtomicBool>,
    /// Notification for sync coalescing — multiple rapid file changes
    /// trigger at most one extra sync (not N). Held here to keep the Arc
    /// alive alongside the background watcher task.
    #[allow(dead_code)]
    sync_notify: Arc<tokio::sync::Notify>,
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
            let sync_notify = Arc::new(tokio::sync::Notify::new());
            return Ok(Self {
                workspace: workspace_str,
                config: daemon_config,
                memory,
                command_tx,
                _handle: handle,
                reindexing: Arc::new(AtomicBool::new(false)),
                embeddings_healthy: Arc::new(AtomicBool::new(false)),
                sync_notify,
            });
        }

        log::info!(
            "Starting memory daemon (interval={}s, model={}, dims={})",
            daemon_config.sync_interval_secs,
            daemon_config.embedding_model,
            daemon_config.target_dims
        );

        // Create a single shared embedding provider — reused for all syncs.
        // reqwest::Client is Arc-wrapped internally, so cloning is cheap.
        let shared_provider = daemon_config.create_provider();

        // Verify Ollama is reachable (with retry)
        Self::verify_ollama_reachable(&shared_provider, daemon_config.require_embeddings, daemon_config.allow_lexical_fallback).await?;

        // Create command channel
        let (command_tx, mut command_rx) = mpsc::channel::<DaemonCommand>(16);

        // Shared reindexing flag: true while a forced reindex is in progress,
        // so callers can fall back to lexical search during the empty-embeddings window.
        let reindexing = Arc::new(AtomicBool::new(false));

        // Cached health state — starts false, set true only after a successful sync.
        let embeddings_healthy = Arc::new(AtomicBool::new(false));

        // Sync overlap guard — prevents concurrent syncs from piling up.
        // Starts true because the initial sync spawn below holds it.
        let is_syncing = Arc::new(AtomicBool::new(true));

        // Sync coalescing: Arc<Notify> for watcher-triggered syncs.
        // Multiple notify_one() calls before notified().await = exactly 1 wakeup.
        let sync_notify = Arc::new(tokio::sync::Notify::new());

        // Check if reindex is needed before initial sync
        let needs_reindex = memory.needs_full_reindex(shared_provider.model(), shared_provider.target_dims())
            .unwrap_or(false);

        // Initial sync/embed (with reindex if needed).
        // is_syncing is already true — released when this task completes.
        let memory_clone = Arc::clone(&memory);
        let init_provider = shared_provider.clone();
        let reindexing_init = Arc::clone(&reindexing);
        let healthy_init = Arc::clone(&embeddings_healthy);
        let is_syncing_init = Arc::clone(&is_syncing);
        tokio::spawn(async move {
            let result = if needs_reindex {
                log::warn!("Config changed, forcing full reindex...");
                Self::execute_force_reindex(&memory_clone, &init_provider, &reindexing_init).await
                    .map(|_| ())
            } else {
                Self::initial_sync(memory_clone, &init_provider).await
            };
            match result {
                Ok(()) => healthy_init.store(true, Ordering::Relaxed),
                Err(e) => {
                    log::error!("Initial sync failed: {}", e);
                    healthy_init.store(false, Ordering::Relaxed);
                }
            }
            is_syncing_init.store(false, Ordering::Release);
        });

        // Spawn daemon loop
        let memory_loop = memory.clone();
        let interval_secs = daemon_config.sync_interval_secs;
        let loop_provider = shared_provider.clone();
        let reindexing_loop = Arc::clone(&reindexing);
        let sync_notify_loop = Arc::clone(&sync_notify);
        let is_syncing_loop = Arc::clone(&is_syncing);
        let healthy_loop = Arc::clone(&embeddings_healthy);
        let handle = tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(Duration::from_secs(interval_secs as u64));
            // Prevent burst ticks after a long sync — next tick fires interval
            // seconds after the previous tick *completes*, not from schedule.
            interval_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval_timer.tick().await; // skip first tick (we just did initial sync)

            loop {
                tokio::select! {
                    // Periodic sync
                    _ = interval_timer.tick() => {
                        if is_syncing_loop.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
                            log::debug!("Skipping periodic sync — previous sync still in progress");
                            continue;
                        }
                        let start = std::time::Instant::now();
                        match Self::sync_and_embed(&memory_loop, &loop_provider).await {
                            Ok(()) => {
                                log::debug!("Periodic sync completed in {:.1}s", start.elapsed().as_secs_f64());
                                healthy_loop.store(true, Ordering::Relaxed);
                            }
                            Err(e) => {
                                log::warn!("Periodic sync failed after {:.1}s: {}", start.elapsed().as_secs_f64(), e);
                                healthy_loop.store(false, Ordering::Relaxed);
                            }
                        }
                        is_syncing_loop.store(false, Ordering::Release);
                    }
                    // Coalesced sync from filesystem watcher
                    _ = sync_notify_loop.notified() => {
                        if is_syncing_loop.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
                            log::debug!("Skipping watcher-triggered sync — previous sync still in progress");
                            continue;
                        }
                        let start = std::time::Instant::now();
                        match Self::sync_and_embed(&memory_loop, &loop_provider).await {
                            Ok(()) => {
                                log::debug!("Watcher-triggered sync completed in {:.1}s", start.elapsed().as_secs_f64());
                                healthy_loop.store(true, Ordering::Relaxed);
                            }
                            Err(e) => {
                                log::warn!("Watcher-triggered sync failed after {:.1}s: {}", start.elapsed().as_secs_f64(), e);
                                healthy_loop.store(false, Ordering::Relaxed);
                            }
                        }
                        is_syncing_loop.store(false, Ordering::Release);
                    }
                    // Commands
                    Some(cmd) = command_rx.recv() => {
                        match cmd {
                            DaemonCommand::SyncNow { respond_to } => {
                                // If a sync is already in progress (e.g. initial sync),
                                // return current status instead of overlapping.
                                if is_syncing_loop.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
                                    log::debug!("SyncNow: another sync in progress, returning current status");
                                    let status = Self::get_sync_status(&*memory_loop);
                                    let _ = respond_to.send(Ok(status));
                                } else {
                                    let start = std::time::Instant::now();
                                    let result = Self::sync_and_embed(&memory_loop, &loop_provider).await;
                                    match &result {
                                        Ok(()) => {
                                            log::debug!("Manual sync completed in {:.1}s", start.elapsed().as_secs_f64());
                                            healthy_loop.store(true, Ordering::Relaxed);
                                        }
                                        Err(e) => {
                                            log::warn!("Manual sync failed after {:.1}s: {}", start.elapsed().as_secs_f64(), e);
                                            healthy_loop.store(false, Ordering::Relaxed);
                                        }
                                    }
                                    is_syncing_loop.store(false, Ordering::Release);
                                    let status = Self::get_sync_status(&*memory_loop);
                                    let _ = respond_to.send(result.map(|_| status));
                                }
                            }
                            DaemonCommand::ForceReindex { respond_to } => {
                                // ForceReindex is an explicit destructive command — wait
                                // for any in-progress sync to finish by acquiring the guard.
                                while is_syncing_loop.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                }
                                let result = Self::execute_force_reindex(&memory_loop, &loop_provider, &reindexing_loop).await;
                                healthy_loop.store(result.is_ok(), Ordering::Relaxed);
                                is_syncing_loop.store(false, Ordering::Release);
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

        // Spawn filesystem watcher for the memory directory.
        // Triggers sync_notify when MEMORY.md or memory/*.md changes.
        let watch_workspace = workspace.to_path_buf();
        let sync_notify_watcher = Arc::clone(&sync_notify);
        std::thread::spawn(move || {
            Self::run_fs_watcher(watch_workspace, sync_notify_watcher);
        });

        Ok(Self {
            workspace: workspace_str,
            config: daemon_config,
            memory,
            command_tx,
            _handle: handle,
            reindexing,
            embeddings_healthy,
            sync_notify,
        })
    }

    /// Run the filesystem watcher in a blocking thread.
    ///
    /// Watches MEMORY.md and the memory/ subdirectory. When .md files change,
    /// triggers sync_notify (coalescing N rapid events into 1 sync).
    fn run_fs_watcher(workspace: std::path::PathBuf, sync_notify: Arc<tokio::sync::Notify>) {
        use notify::Watcher;
        use notify_debouncer_full::{new_debouncer, DebounceEventResult};
        use std::time::Duration as StdDuration;

        let mut debouncer = match new_debouncer(
            StdDuration::from_millis(300),
            None,
            move |result: DebounceEventResult| {
                match result {
                    Ok(events) => {
                        // React to .md changes (memory files) or .jsonl changes (session transcripts)
                        let has_relevant_change = events.iter().any(|ev| {
                            ev.paths.iter().any(|p| {
                                p.extension().map(|e| e == "md" || e == "jsonl").unwrap_or(false)
                            })
                        });
                        if has_relevant_change {
                            sync_notify.notify_one();
                        }
                    }
                    Err(e) => {
                        log::warn!("Filesystem watcher error: {:?}", e);
                    }
                }
            },
        ) {
            Ok(d) => d,
            Err(e) => {
                log::warn!("Failed to create filesystem watcher: {} — watcher disabled", e);
                return;
            }
        };

        let memory_md = workspace.join("MEMORY.md");
        let memory_dir = workspace.join("memory");
        let sessions_dir = workspace.join(".sessions");

        // Watch MEMORY.md (if it exists)
        if memory_md.exists() {
            if let Err(e) = debouncer.watcher().watch(&memory_md, notify::RecursiveMode::NonRecursive) {
                log::warn!("Failed to watch MEMORY.md: {}", e);
            }
        }

        // Watch memory/ dir (if it exists)
        if memory_dir.exists() {
            if let Err(e) = debouncer.watcher().watch(&memory_dir, notify::RecursiveMode::Recursive) {
                log::warn!("Failed to watch memory/ dir: {}", e);
            }
        }

        // Watch .sessions/ dir for session transcript updates (.jsonl files)
        if sessions_dir.exists() {
            if let Err(e) = debouncer.watcher().watch(&sessions_dir, notify::RecursiveMode::NonRecursive) {
                log::warn!("Failed to watch .sessions/ dir: {}", e);
            }
        }

        if !memory_md.exists() && !memory_dir.exists() {
            log::debug!("No memory files to watch yet — filesystem watcher idle");
        } else {
            log::info!("Memory filesystem watcher active (debounce: 300ms)");
        }

        // Block the thread keeping the watcher alive.
        loop {
            std::thread::sleep(StdDuration::from_secs(60));
        }
    }

    /// Verify Ollama is reachable (with retry).
    async fn verify_ollama_reachable(
        provider: &crate::memory::EmbeddingProvider,
        require_embeddings: bool,
        allow_lexical_fallback: bool,
    ) -> Result<()> {
        const MAX_RETRIES: usize = 3;
        const RETRY_DELAY_SECS: u64 = 3;

        for attempt in 1..=MAX_RETRIES {
            match tokio::time::timeout(
                Duration::from_secs(30),
                provider.embed_query("test"),
            ).await {
                Ok(Ok(_)) => {
                    log::debug!("Ollama embedding service verified (attempt {})", attempt);
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
                "\n\n═══════════════════════════════════════════════════════════════\n\
                  ⚠️  OLLAMA EMBEDDING SERVICE NOT RUNNING\n\
                  ═══════════════════════════════════════════════════════════════\n\n\
                  ZapClaw cannot reach Ollama at: {}\n\
                  Required model: {}\n\n\
                  👉 START OLLAMA WITH THIS COMMAND:\n\
                      ollama serve &\n\n\
                  Then verify it's running:\n\
                      ollama ps\n\n\
                  If the model is missing, pull it:\n\
                      ollama pull {}\n\n\
                  ⚠️  ZapClaw will exit now. Start Ollama and try again.\n\
                  ═══════════════════════════════════════════════════════════════\n",
                provider.base_url(),
                provider.model(),
                provider.model()
            );
        } else if allow_lexical_fallback {
            log::warn!(
                "\n\n═══════════════════════════════════════════════════════════════\n\
                  ⚠️  OLLAMA EMBEDDING SERVICE NOT RUNNING (FALLBACK MODE)\n\
                  ═══════════════════════════════════════════════════════════════\n\n\
                  ZapClaw cannot reach Ollama at: {}\n\
                  Required model: {}\n\n\
                  ✅ Continuing with KEYWORD-ONLY search (embeddings disabled)\n\n\
                  👉 TO ENABLE EMBEDDINGS, START OLLAMA:\n\
                      ollama serve &\n\n\
                  Then verify:\n\
                      ollama ps\n\n\
                  If the model is missing, pull it:\n\
                      ollama pull {}\n\n\
                  ═══════════════════════════════════════════════════════════════\n",
                provider.base_url(),
                provider.model(),
                provider.model()
            );
            Ok(())
        } else {
            // Invalid config: require_embeddings=false but allow_lexical_fallback=false
            anyhow::bail!(
                "\n\n═══════════════════════════════════════════════════════════════\n\
                  ⚠️  INVALID CONFIGURATION: OLLAMA NOT RUNNING\n\
                  ═══════════════════════════════════════════════════════════════\n\n\
                  ZapClaw cannot reach Ollama at: {}\n\
                  Required model: {}\n\n\
                  Your config has:\n\
                    - memory_require_embeddings = false (Ollama optional)\n\
                    - memory_allow_lexical_fallback = false (no fallback allowed)\n\n\
                  This combination is invalid. Fix your config (~/.zapclaw/zapclaw.json):\n\n\
                  Option 1 - Require Ollama (recommended for full search):\n\
                    \"memory_require_embeddings\": true,\n\
                    \"memory_allow_lexical_fallback\": false\n\
                    Then start Ollama: ollama serve &\n\n\
                  Option 2 - Allow keyword-only fallback:\n\
                    \"memory_require_embeddings\": false,\n\
                    \"memory_allow_lexical_fallback\": true\n\n\
                  ═══════════════════════════════════════════════════════════════\n",
                provider.base_url(),
                provider.model()
            );
        }
    }

    /// Perform initial sync on daemon startup.
    async fn initial_sync(memory: Arc<MemoryDb>, provider: &crate::memory::EmbeddingProvider) -> Result<()> {
        log::info!("Performing initial memory sync...");

        let start = std::time::Instant::now();

        // Sync regular memory files
        let model = provider.model().to_string();
        let target_dims = provider.target_dims();
        let memory_clone = memory.clone();
        let sync_result = tokio::task::spawn_blocking(move || {
            memory_clone.sync(&model, target_dims)
        }).await;

        match sync_result {
            Ok(Ok(count)) => log::debug!("Initial file sync: {} files updated", count),
            Ok(Err(e)) => log::error!("Initial file sync failed: {}", e),
            Err(e) => log::error!("Initial file sync task failed: {}", e),
        }

        // Sync session transcript files
        let memory_clone = memory.clone();
        let model = provider.model().to_string();
        let target_dims = provider.target_dims();
        match tokio::task::spawn_blocking(move || {
            memory_clone.sync_sessions(&model, target_dims)
        }).await {
            Ok(Ok(count)) => log::debug!("Initial session sync: {} files updated", count),
            Ok(Err(e)) => log::warn!("Initial session sync failed (non-fatal): {}", e),
            Err(e) => log::warn!("Initial session sync task failed (non-fatal): {}", e),
        }

        // Embed chunks
        let embedded = memory.embed_all_chunks(provider).await?;
        let elapsed = start.elapsed().as_secs_f64();
        log::debug!("Initial sync completed in {:.1}s ({} chunks embedded)", elapsed, embedded);

        Ok(())
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

        // Also sync session transcript files
        let memory_clone = memory.clone();
        let model = provider.model().to_string();
        let target_dims = provider.target_dims();
        match tokio::task::spawn_blocking(move || {
            memory_clone.sync_sessions(&model, target_dims)
        }).await {
            Ok(Ok(n)) => log::debug!("Session sync: {} files updated", n),
            Ok(Err(e)) => log::warn!("Session sync failed (non-fatal): {}", e),
            Err(e) => log::warn!("Session sync task failed (non-fatal): {}", e),
        }

        // Embed chunks
        let embedded = memory.embed_all_chunks(provider).await?;
        log::debug!("Embedded {} chunks", embedded);

        Ok(())
    }

    /// Force full reindex using a crash-safe shadow-table approach.
    ///
    /// **Crash safety guarantee:** the live `embedding_cache` and `chunks.embedding`
    /// are never touched until the final atomic SQLite transaction (the swap). If the
    /// process crashes at any point before that commit, the old embeddings remain
    /// fully intact and will be available on restart.
    ///
    /// Sequence:
    ///  1. Sync files — re-chunks all files, sets `chunks.embedding = '[]'`.
    ///     `embedding_cache` is NOT cleared.
    ///  2. Create `embedding_cache_shadow` — fresh table, old data untouched.
    ///  3. Embed all chunks into shadow — cache hits read from live `embedding_cache`
    ///     (no API calls for unchanged chunks). Live tables still untouched.
    ///  4. Atomic swap — single `BEGIN EXCLUSIVE` transaction:
    ///     update `chunks.embedding` from shadow, replace `embedding_cache` with shadow,
    ///     drop shadow. Either fully commits or fully rolls back.
    ///  5. `reindexing` flag is true only during step 4 (milliseconds, not minutes).
    ///
    /// **Startup recovery:** `MemoryDb::new()` drops any leftover shadow table
    /// (`DROP TABLE IF EXISTS embedding_cache_shadow`) before the daemon starts.
    async fn execute_force_reindex(
        memory: &Arc<MemoryDb>,
        provider: &crate::memory::EmbeddingProvider,
        reindexing: &Arc<AtomicBool>,
    ) -> Result<ReindexResult> {
        log::debug!("Starting crash-safe forced reindex...");
        let start = std::time::Instant::now();

        // Phase 1: Sync files.
        // Regenerates the chunks table (all chunks.embedding reset to '[]').
        // embedding_cache is NOT touched — old embeddings remain intact.
        let memory_clone = Arc::clone(memory);
        let model = provider.model().to_string();

        let files_reindexed = tokio::task::spawn_blocking(move || {
            memory_clone.sync_with_options(&model, true, None)
                .context("Reindex sync failed")
        })
        .await??;

        // Also re-sync session transcript files during force reindex
        let memory_clone = Arc::clone(memory);
        let model = provider.model().to_string();
        let target_dims = provider.target_dims();
        if let Err(e) = tokio::task::spawn_blocking(move || {
            memory_clone.sync_sessions(&model, target_dims)
        }).await? {
            log::warn!("Session sync during reindex failed (non-fatal): {}", e);
        }

        // Phase 2: Create shadow table and build all embeddings into it.
        // Live embedding_cache and chunks.embedding are NOT modified here.
        // If the process crashes here: shadow gets dropped at next startup,
        // and embedding_cache still has the old valid embeddings.
        memory.create_embedding_shadow_table()
            .context("Failed to create embedding shadow table")?;

        let chunks_embedded = memory.embed_all_chunks_to_shadow(provider).await
            .context("Failed to embed chunks into shadow table")?;

        // Phase 3: Atomic swap.
        // The reindexing window shrinks to just the duration of this transaction
        // (typically milliseconds), not the full embed duration (potentially minutes).
        reindexing.store(true, Ordering::Relaxed);

        let swap_result = {
            let m = Arc::clone(memory);
            tokio::task::spawn_blocking(move || m.swap_shadow_to_main()).await?
        };

        reindexing.store(false, Ordering::Relaxed);
        swap_result.context("Shadow-to-main atomic swap failed")?;

        let duration = start.elapsed().as_secs_f64();

        log::debug!(
            "Crash-safe reindex complete: {} files, {} chunks in {:.2}s",
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

    /// Check if embeddings are available based on the daemon's cached health state.
    /// Returns `false` during reindex or if the last sync failed.
    pub fn is_reindexing(&self) -> bool {
        self.reindexing.load(Ordering::Relaxed)
    }

    pub fn can_use_embeddings(&self) -> bool {
        if !self.config.enabled {
            return false;
        }

        // If a reindex is in progress, embeddings are in an empty-window state.
        if self.reindexing.load(Ordering::Relaxed) {
            log::debug!("Reindex in progress — falling back to lexical search");
            return false;
        }

        // Trust the daemon loop's cached health state — no live probe.
        self.embeddings_healthy.load(Ordering::Relaxed)
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
