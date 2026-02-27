use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, Once};
use std::collections::HashMap;

// ── Constants (matching OpenClaw) ───────────────────────────────────────

#[allow(dead_code)]
const VECTOR_TABLE: &str = "chunks_vec";
const FTS_TABLE: &str = "chunks_fts";
const EMBEDDING_CACHE_TABLE: &str = "embedding_cache";
const META_KEY: &str = "memory_index_meta_v1";
#[allow(dead_code)]
const SNIPPET_MAX_CHARS: usize = 700;
const DEFAULT_CHUNK_TOKENS: usize = 512;
const DEFAULT_CHUNK_OVERLAP: usize = 50;

// ── sqlite-vec Extension (P2-4) ────────────────────────────────────────

static VEC_EXT_INIT: Once = Once::new();

/// Register sqlite-vec as an auto-extension (loaded on every new connection).
/// Uses sqlite3_auto_extension via FFI, which does NOT require SQLITE_ENABLE_LOAD_EXTENSION.
fn register_sqlite_vec() {
    VEC_EXT_INIT.call_once(|| {
        // Register sqlite-vec as an auto-extension — loaded on every new connection.
        // This does NOT require SQLITE_ENABLE_LOAD_EXTENSION (not loading from disk).
        unsafe {
            rusqlite::ffi::sqlite3_auto_extension(Some(
                std::mem::transmute(sqlite_vec::sqlite3_vec_init as *const ())
            ));
        }
        log::debug!("sqlite-vec auto-extension registered");
    });
}

/// Deterministic TEXT→i64 mapping for chunk IDs (for chunks_vec rowid).
fn chunk_id_to_vec_rowid(id: &str) -> i64 {
    let hash = hash_text(id); // hex SHA256 string
    let n = u64::from_str_radix(&hash[..16.min(hash.len())], 16).unwrap_or(0);
    (n >> 1) as i64 // shift right to ensure positive i64
}

/// Convert f32 vector to little-endian bytes (for sqlite-vec storage).
fn vec_to_blob(v: &[f32]) -> Vec<u8> {
    v.iter().flat_map(|f| f.to_le_bytes()).collect()
}

/// Upsert a chunk embedding into chunks_vec table.
///
/// sqlite-vec's vec0 virtual tables do NOT support INSERT OR REPLACE / ON CONFLICT,
/// so we use an explicit DELETE + INSERT pattern to achieve idempotent upsert.
fn upsert_chunk_vec(db: &Connection, chunk_id: &str, embedding: &[f32]) -> Result<()> {
    let rowid = chunk_id_to_vec_rowid(chunk_id);
    let blob = vec_to_blob(embedding);
    // Delete any existing row with this deterministic rowid before inserting.
    db.execute("DELETE FROM chunks_vec WHERE rowid = ?", [rowid])?;
    db.execute(
        "INSERT INTO chunks_vec(rowid, embedding, chunk_id) VALUES (?1, ?2, ?3)",
        params![rowid, blob, chunk_id],
    )?;
    Ok(())
}

/// Delete a chunk embedding from chunks_vec table.
fn delete_chunk_vec(db: &Connection, chunk_id: &str) -> Result<()> {
    let rowid = chunk_id_to_vec_rowid(chunk_id);
    db.execute("DELETE FROM chunks_vec WHERE rowid = ?", [rowid])?;
    Ok(())
}

// ── Types ───────────────────────────────────────────────────────────────

/// File-based + SQLite-indexed memory system — exact OpenClaw parity.
///
/// Dual storage architecture:
/// 1. MEMORY.md + memory/*.md — user-editable markdown files (source of truth)
/// 2. SQLite index database — files, chunks, chunks_fts (FTS5), embedding_cache, chunks_vec (sqlite-vec)
///
/// Search pipeline:
///   Files → chunkMarkdown → embedBatch → SQLite → hybrid search (BM25 + vector)
pub struct MemoryDb {
    workspace: PathBuf,
    db: Mutex<Connection>,
    target_dims: usize,
    chunk_tokens: usize,
    chunk_overlap: usize,
    fts_available: bool,
    vec_available: bool, // true if sqlite-vec extension loaded and schema created
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub path: String,
    pub content: String,
    pub line_start: usize,
    pub line_end: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySearchResult {
    pub path: String,
    pub snippet: String,
    pub start_line: usize,
    pub end_line: usize,
    pub score: f32,
    pub citation: Option<String>,
    pub source: String,
    /// Embedding provider name (e.g., "openai-compat"), None if keyword-only
    pub provider: Option<String>,
    /// Embedding model used, None if keyword-only
    pub model: Option<String>,
    /// True if result came from keyword search only (no vector embeddings)
    pub fallback: bool,
}

/// Progress callback for sync pipeline.
pub type SyncProgressFn = Box<dyn Fn(usize, usize, &str) + Send + Sync>;

/// Internal chunk produced by markdown chunking.
#[derive(Debug, Clone)]
struct MemoryChunk {
    start_line: usize,
    end_line: usize,
    text: String,
    hash: String,
}

/// File entry for sync tracking.
#[derive(Debug)]
struct MemoryFileEntry {
    path: String,
    hash: String,
    mtime_ms: i64,
    size: i64,
}

/// Index metadata stored in SQLite meta table.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IndexMeta {
    pub model: String,
    pub target_dims: usize,
    pub chunk_tokens: usize,
    pub chunk_overlap: usize,
    pub schema_version: u32,
    pub last_sync_at: Option<String>, // ISO 8601 timestamp
}

/// Result of a conversation history compaction (returned by `Agent::compact_session`).
#[derive(Debug, Clone)]
pub struct CompactionResult {
    /// Number of messages summarised away.
    pub files_compacted: usize,
    /// Characters freed by the compaction.
    pub chars_freed: usize,
    /// LLM-generated summary text.
    pub summary: Option<String>,
    /// Approximate token count before compaction.
    pub tokens_before: Option<usize>,
    /// Approximate token count after compaction.
    pub tokens_after: Option<usize>,
}

// ── Schema ──────────────────────────────────────────────────────────────

fn ensure_schema(db: &Connection) -> bool {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS files (
            path TEXT PRIMARY KEY,
            source TEXT NOT NULL DEFAULT 'memory',
            hash TEXT NOT NULL,
            mtime INTEGER NOT NULL,
            size INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS chunks (
            id TEXT PRIMARY KEY,
            path TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'memory',
            start_line INTEGER NOT NULL,
            end_line INTEGER NOT NULL,
            hash TEXT NOT NULL,
            model TEXT NOT NULL,
            text TEXT NOT NULL,
            embedding TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_chunks_path ON chunks(path);
        CREATE INDEX IF NOT EXISTS idx_chunks_source ON chunks(source);",
    )
    .ok();

    db.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {} (
            provider TEXT NOT NULL,
            model TEXT NOT NULL,
            provider_key TEXT NOT NULL,
            hash TEXT NOT NULL,
            embedding TEXT NOT NULL,
            dims INTEGER,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (provider, model, provider_key, hash)
        );
        CREATE INDEX IF NOT EXISTS idx_embedding_cache_updated_at ON {}(updated_at);",
        EMBEDDING_CACHE_TABLE, EMBEDDING_CACHE_TABLE,
    ))
    .ok();

    // Try to create FTS5 table
    let fts_ok = db
        .execute_batch(&format!(
            "CREATE VIRTUAL TABLE IF NOT EXISTS {} USING fts5(
                text,
                id UNINDEXED,
                path UNINDEXED,
                source UNINDEXED,
                model UNINDEXED,
                start_line UNINDEXED,
                end_line UNINDEXED
            );",
            FTS_TABLE,
        ))
        .is_ok();

    fts_ok
}

/// Ensure sqlite-vec virtual table schema exists (for vector KNN search).
fn ensure_vec_schema(db: &Connection, dims: usize) -> Result<bool> {
    if dims == 0 {
        return Ok(false);
    }

    db.execute_batch(&format!(
        "CREATE VIRTUAL TABLE IF NOT EXISTS {VECTOR_TABLE} USING vec0(
            embedding float[{dims}] distance_metric=cosine,
            +chunk_id text
        );"
    )).context("Failed to create chunks_vec table")?;

    log::debug!("sqlite-vec chunks_vec table created (dims={})", dims);
    Ok(true)
}

/// Migrate existing chunk embeddings to chunks_vec table.
/// Called on startup when sqlite-vec is first enabled.
fn migrate_existing_to_vec(db: &Connection) -> Result<usize> {
    // Query all chunks with embeddings
    let mut stmt = db.prepare("SELECT id, embedding FROM chunks WHERE embedding != '[]'")?;

    let rows = stmt.query_map([], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })?;

    let mut migrated = 0usize;
    for row in rows {
        let (chunk_id, emb_json) = row?;
        let emb: Vec<f32> = serde_json::from_str(&emb_json).unwrap_or_default();
        if !emb.is_empty() {
            if let Err(e) = upsert_chunk_vec(db, &chunk_id, &emb) {
                log::warn!("Failed to migrate chunk {} to vec: {}", chunk_id, e);
            } else {
                migrated += 1;
            }
        }
    }

    if migrated > 0 {
        log::info!("Migrated {} existing chunks to chunks_vec", migrated);
    }

    Ok(migrated)
}

// ── Hashing ─────────────────────────────────────────────────────────────

fn hash_text(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ── Markdown Chunking (exact OpenClaw port) ─────────────────────────────

fn chunk_markdown(content: &str, tokens: usize, overlap: usize) -> Vec<MemoryChunk> {
    let lines: Vec<&str> = content.split('\n').collect();
    if lines.is_empty() {
        return Vec::new();
    }

    let max_chars = 32.max(tokens * 4);
    let overlap_chars = if overlap > 0 { overlap * 4 } else { 0 };
    let mut chunks = Vec::new();
    let mut current: Vec<(String, usize)> = Vec::new(); // (line, lineNo)
    let mut current_chars: usize = 0;

    let flush = |current: &[(String, usize)], chunks: &mut Vec<MemoryChunk>| {
        if current.is_empty() {
            return;
        }
        let start_line = current[0].1;
        let end_line = current[current.len() - 1].1;
        let text: String = current.iter().map(|(l, _)| l.as_str()).collect::<Vec<_>>().join("\n");
        chunks.push(MemoryChunk {
            start_line,
            end_line,
            text: text.clone(),
            hash: hash_text(&text),
        });
    };

    let carry_overlap = |current: &mut Vec<(String, usize)>, current_chars: &mut usize, overlap_chars: usize| {
        if overlap_chars == 0 || current.is_empty() {
            current.clear();
            *current_chars = 0;
            return;
        }
        let mut acc = 0usize;
        let mut kept = Vec::new();
        for item in current.iter().rev() {
            acc += item.0.len() + 1;
            kept.push(item.clone());
            if acc >= overlap_chars {
                break;
            }
        }
        kept.reverse();
        *current_chars = kept.iter().map(|(l, _)| l.len() + 1).sum();
        *current = kept;
    };

    for (i, line) in lines.iter().enumerate() {
        let line_no = i + 1;
        let segments: Vec<String> = if line.is_empty() {
            vec![String::new()]
        } else {
            let mut segs = Vec::new();
            let mut start = 0;
            while start < line.len() {
                let end = (start + max_chars).min(line.len());
                segs.push(line[start..end].to_string());
                start = end;
            }
            segs
        };

        for segment in &segments {
            let line_size = segment.len() + 1;
            if current_chars + line_size > max_chars && !current.is_empty() {
                flush(&current, &mut chunks);
                carry_overlap(&mut current, &mut current_chars, overlap_chars);
            }
            current.push((segment.clone(), line_no));
            current_chars += line_size;
        }
    }
    flush(&current, &mut chunks);
    chunks
}

// ── Cosine Similarity ───────────────────────────────────────────────────

fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let len = a.len().min(b.len());
    let mut dot = 0.0f32;
    let mut norm_a = 0.0f32;
    let mut norm_b = 0.0f32;
    for i in 0..len {
        dot += a[i] * b[i];
        norm_a += a[i] * a[i];
        norm_b += b[i] * b[i];
    }
    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }
    dot / (norm_a.sqrt() * norm_b.sqrt())
}

/// BM25 rank-to-score (matching OpenClaw's hybrid.ts)
fn bm25_rank_to_score(rank: f64) -> f32 {
    let normalized = if rank.is_finite() { rank.max(0.0) } else { 999.0 };
    (1.0 / (1.0 + normalized)) as f32
}

/// Build FTS5 query from raw text (matching OpenClaw's buildFtsQuery)
fn build_fts_query(raw: &str) -> Option<String> {
    let tokens: Vec<String> = raw
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.is_empty() {
        return None;
    }
    let quoted: Vec<String> = tokens.iter().map(|t| format!("\"{}\"", t.replace('"', ""))).collect();
    Some(quoted.join(" AND "))
}

/// Parse JSON embedding string to f32 vector
fn parse_embedding(raw: &str) -> Vec<f32> {
    serde_json::from_str::<Vec<f32>>(raw).unwrap_or_default()
}

/// Matryoshka projection: truncate embedding to target dimensions and L2-normalize.
///
/// nomic-embed-text:v1.5 supports Matryoshka embeddings (768 dims → 256/512).
/// This function:
/// 1. Rejects vectors shorter than target (error)
/// 2. Truncates prefix to target_dims
/// 3. L2 normalizes the projected vector
///
/// Returns normalized vector of length target_dims.
fn project_matryoshka(vec: &[f32], target_dims: usize) -> Result<Vec<f32>> {
    // Validate input
    if vec.len() < target_dims {
        anyhow::bail!(
            "Cannot project {}-dim vector to {} dims (source too short)",
            vec.len(),
            target_dims
        );
    }

    // Truncate to target_dims
    let mut projected = vec[..target_dims].to_vec();

    // L2 normalize
    let norm: f32 = projected.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 1e-6 {
        for v in projected.iter_mut() {
            *v /= norm;
        }
    }

    Ok(projected)
}

// ── Embedding Provider ──────────────────────────────────────────────────

/// Embedding provider — calls OpenAI-compatible /embeddings endpoint.
/// Matches OpenClaw's embedding provider interface with Matryoshka projection support.
pub struct EmbeddingProvider {
    client: reqwest::Client,
    base_url: String,
    model: String,
    api_key: Option<String>,
    target_dims: usize,
}

impl EmbeddingProvider {
    pub fn new(base_url: &str, model: &str, api_key: Option<String>, target_dims: usize) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .expect("Failed to build embedding HTTP client");
        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            model: model.to_string(),
            api_key,
            target_dims,
        }
    }

    /// Get embeddings for a batch of texts with Matryoshka projection.
    pub async fn embed_batch(&self, texts: &[String]) -> Result<Vec<Vec<f32>>> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        const MAX_ATTEMPTS: usize = 3;
        const RETRY_DELAYS_MS: [u64; 2] = [500, 1500];

        let url = format!("{}/embeddings", self.base_url);
        let body = serde_json::json!({
            "model": self.model,
            "input": texts,
        });

        #[derive(Deserialize)]
        struct EmbeddingResponse {
            data: Vec<EmbeddingData>,
        }
        #[derive(Deserialize)]
        struct EmbeddingData {
            embedding: Vec<f32>,
        }

        let mut last_err = anyhow::anyhow!("embed_batch: no attempts made");

        for attempt in 0..MAX_ATTEMPTS {
            if attempt > 0 {
                let delay = RETRY_DELAYS_MS[attempt - 1];
                log::warn!(
                    "Embedding attempt {}/{} failed, retrying in {}ms...",
                    attempt, MAX_ATTEMPTS, delay
                );
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }

            let mut req = self.client.post(&url).json(&body);
            if let Some(ref key) = self.api_key {
                req = req.header("Authorization", format!("Bearer {}", key));
            }

            let resp = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    // Network-level error — eligible for retry
                    last_err = anyhow::anyhow!("Embedding API request failed: {}", e);
                    continue;
                }
            };

            let status = resp.status();
            let body_text = match resp.text().await {
                Ok(t) => t,
                Err(e) => {
                    last_err = anyhow::anyhow!("Failed to read embedding response body: {}", e);
                    continue;
                }
            };

            if !status.is_success() {
                // 4xx client errors — do not retry, propagate immediately
                if status.is_client_error() {
                    anyhow::bail!(
                        "Embedding API client error ({}): {}",
                        status,
                        &body_text[..body_text.len().min(200)]
                    );
                }
                // 5xx server errors — retry
                last_err = anyhow::anyhow!(
                    "Embedding API server error ({}): {}",
                    status,
                    &body_text[..body_text.len().min(200)]
                );
                continue;
            }

            let parsed: EmbeddingResponse = serde_json::from_str(&body_text)
                .context("Failed to parse embedding response")?;

            // Apply Matryoshka projection to all embeddings
            let mut projected = Vec::with_capacity(parsed.data.len());
            for item in parsed.data {
                let proj = project_matryoshka(&item.embedding, self.target_dims)
                    .context("Failed to project embedding")?;
                projected.push(proj);
            }

            return Ok(projected);
        }

        Err(last_err)
    }

    /// Get embedding for a single query with Matryoshka projection.
    pub async fn embed_query(&self, text: &str) -> Result<Vec<f32>> {
        let results = self.embed_batch(&[text.to_string()]).await?;
        results.into_iter().next().ok_or_else(|| anyhow::anyhow!("No embedding returned"))
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn target_dims(&self) -> usize {
        self.target_dims
    }
}

// ── MemoryDb Implementation ────────────────────────────────────────────

impl MemoryDb {
    /// Create or open a file-based + SQLite-indexed memory store.
    /// Matches OpenClaw's MemoryIndexManager constructor.
    pub fn new(workspace: &Path) -> Result<Self> {
        let memory_dir = workspace.join("memory");
        if !memory_dir.exists() {
            std::fs::create_dir_all(&memory_dir)
                .with_context(|| format!("Failed to create memory directory: {}", memory_dir.display()))?;
        }

        // Ensure MEMORY.md exists
        let memory_md = workspace.join("MEMORY.md");
        if !memory_md.exists() {
            std::fs::write(&memory_md, "# Memory\n\nPersistent notes, preferences, and context.\n")
                .with_context(|| format!("Failed to create MEMORY.md: {}", memory_md.display()))?;
        }

        // Open SQLite index database (matching OpenClaw's store.path)
        let db_path = workspace.join("memory.db");
        let conn = Connection::open(&db_path)
            .with_context(|| format!("Failed to open memory index: {}", db_path.display()))?;

        // WAL mode for concurrent access
        // PRAGMA journal_mode returns a result, so we use query_row to handle it
        let _: String = conn.query_row("PRAGMA journal_mode=WAL;", [], |r| r.get(0))?;

        let fts_available = ensure_schema(&conn);
        if !fts_available {
            log::warn!("FTS5 unavailable — keyword search disabled");
        }

        // Register sqlite-vec extension (P2-4)
        register_sqlite_vec();

        // Create chunks_vec table if it doesn't exist (P2-4)
        // Use default target_dims (512) for initial schema creation
        let default_dims = 512usize;
        let vec_available = match ensure_vec_schema(&conn, default_dims) {
            Ok(available) => {
                if available {
                    // Migrate existing embeddings to chunks_vec
                    match migrate_existing_to_vec(&conn) {
                        Ok(n) => log::debug!("sqlite-vec migration: {} chunks", n),
                        Err(e) => log::warn!("sqlite-vec migration failed (non-fatal): {}", e),
                    }
                }
                available
            }
            Err(e) => {
                log::warn!("sqlite-vec schema initialization failed (non-fatal): {}", e);
                false
            }
        };

        // Startup crash recovery: if a shadow table exists from a previously crashed
        // reindex, drop it. The main embedding_cache is always left intact during
        // reindex (shadow is built first, then atomically swapped), so this is safe.
        if conn.execute_batch("DROP TABLE IF EXISTS embedding_cache_shadow").is_ok() {
            // Check if it actually existed by querying sqlite_master before we dropped it.
            // We just silently drop it regardless — DROP IF EXISTS is idempotent.
            log::debug!("Startup: cleaned up any leftover embedding_cache_shadow table");
        }

        Ok(Self {
            workspace: workspace.to_path_buf(),
            db: Mutex::new(conn),
            target_dims: 512,               // default, updated after sync
            chunk_tokens: DEFAULT_CHUNK_TOKENS,
            chunk_overlap: DEFAULT_CHUNK_OVERLAP,
            fts_available,
            vec_available,
        })
    }

    /// Create an in-memory / temp-dir memory (for testing).
    pub fn in_memory() -> Result<Self> {
        let tmp = std::env::temp_dir().join(format!("zapclaw_mem_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp)?;
        Self::new(&tmp)
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub fn memory_md_path(&self) -> PathBuf {
        self.workspace.join("MEMORY.md")
    }

    pub fn memory_dir(&self) -> PathBuf {
        self.workspace.join("memory")
    }

    // ── File Listing (matching OpenClaw's listMemoryFiles) ─────────────

    /// Workspace directories scanned for .md files (besides MEMORY.md + memory/).
    const EXTRA_DIRS: &'static [&'static str] = &["docs", "notes"];

    /// List all memory files: MEMORY.md + memory/*.md + docs/*.md + notes/*.md
    pub fn list_memory_files(&self) -> Result<Vec<(String, String)>> {
        let mut files = Vec::new();

        let memory_md = self.memory_md_path();
        if memory_md.exists() {
            files.push(("MEMORY.md".to_string(), std::fs::read_to_string(&memory_md)?));
        }

        // Scan memory/, docs/, notes/ for .md files
        let dirs: Vec<(&str, PathBuf)> = std::iter::once(("memory", self.memory_dir()))
            .chain(Self::EXTRA_DIRS.iter().map(|d| (*d, self.workspace.join(d))))
            .collect();

        for (prefix, dir) in dirs {
            if !dir.exists() {
                continue;
            }
            let mut dir_entries: Vec<_> = std::fs::read_dir(&dir)?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map_or(false, |ext| ext == "md"))
                .filter(|e| !e.path().is_symlink()) // skip symlinks — workspace confinement
                .collect();
            dir_entries.sort_by_key(|e| e.file_name());

            for entry in dir_entries {
                let path = format!("{}/{}", prefix, entry.file_name().to_string_lossy());
                let content = std::fs::read_to_string(entry.path())?;
                files.push((path, content));
            }
        }

        Ok(files)
    }

    // ── Session Transcript Source (P1-3) ────────────────────────────────

    /// List all session JSONL files in {workspace}/.sessions/
    fn list_session_files(&self) -> Result<Vec<PathBuf>> {
        let sessions_dir = self.workspace.join(".sessions");
        if !sessions_dir.exists() {
            return Ok(Vec::new());
        }

        let mut files: Vec<PathBuf> = std::fs::read_dir(&sessions_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "jsonl"))
            .filter(|e| !e.path().is_symlink()) // security: skip symlinks
            .map(|e| e.path())
            .collect();

        files.sort(); // deterministic ordering
        Ok(files)
    }

    /// Build searchable text from a session JSONL file.
    /// Filters to "user" and "assistant" roles only, collapses whitespace.
    fn build_session_text(path: &Path) -> Result<Option<String>> {
        use serde_json::Value;

        let content = std::fs::read_to_string(path)?;
        let mut lines = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Parse JSON: { "role": "...", "content": "..." }
            if let Ok(value) = serde_json::from_str::<Value>(line) {
                if let (Some(role), Some(content)) = (
                    value.get("role").and_then(|r| r.as_str()),
                    value.get("content").and_then(|c| c.as_str()),
                ) {
                    // Only index user and assistant messages (skip header, system, tool)
                    if role == "user" || role == "assistant" {
                        // Normalize: collapse whitespace, replace newlines with space
                        let normalized = content.split_whitespace().collect::<Vec<_>>().join(" ");
                        lines.push(format!("{}: {}", role.to_uppercase(), normalized));
                    }
                }
            }
        }

        if lines.is_empty() {
            return Ok(None); // Empty session (no user/assistant content)
        }

        Ok(Some(lines.join("\n")))
    }

    /// Sync session transcript files as searchable memory (source="sessions").
    /// Hash-based dedup: skips unchanged sessions.
    pub fn sync_sessions(&self, model: &str, target_dims: usize) -> Result<usize> {
        let session_files = self.list_session_files()?;
        let mut synced = 0usize;

        for session_path in &session_files {
            // Build session text
            let text = match Self::build_session_text(session_path)? {
                Some(t) => t,
                None => continue, // Skip empty sessions
            };

            // Compute content hash (not file hash)
            let hash = hash_text(&text);

            // Build relative path: "sessions/{filename}"
            let filename = session_path.file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| anyhow::anyhow!("Invalid session filename: {:?}", session_path))?;
            let rel_path = format!("sessions/{}", filename);

            // Check if unchanged
            let existing_hash: Option<String> = self.db.lock().unwrap()
                .prepare("SELECT hash FROM files WHERE path = ? AND source = 'sessions'")
                .ok()
                .and_then(|mut s| s.query_row(params![rel_path], |r| r.get(0)).ok());

            if existing_hash.as_deref() == Some(&hash) {
                continue; // Unchanged, skip
            }

            // Get file metadata
            let meta = std::fs::metadata(session_path)?;
            let mtime_ms = meta.modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);

            let entry = MemoryFileEntry {
                path: rel_path.clone(),
                hash,
                mtime_ms,
                size: meta.len() as i64,
            };

            // Index the session
            self.index_file(&entry, &text, model, "sessions")?;
            synced += 1;
        }

        // Cleanup: remove stale session entries (deleted files)
        let active_paths: std::collections::HashSet<String> = session_files.iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
            .map(|n| format!("sessions/{}", n))
            .collect();

        let stale_paths: Vec<String> = {
            let db = self.db.lock().unwrap();
            let mut stmt = db.prepare("SELECT path FROM files WHERE source = 'sessions'")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            rows.filter_map(|r| r.ok()).collect()
        };

        for stale_path in &stale_paths {
            if !active_paths.contains(stale_path) {
                self.remove_file_index(stale_path, "sessions")?;
            }
        }

        // Update index metadata
        if synced > 0 {
            self.update_index_meta(model, target_dims)?;
        }

        Ok(synced)
    }

    // ── Build File Entry (matching OpenClaw's buildFileEntry) ──────────

    fn build_file_entry(&self, rel_path: &str, abs_path: &Path) -> Result<MemoryFileEntry> {
        let meta = std::fs::metadata(abs_path)?;
        let content = std::fs::read_to_string(abs_path)?;
        let hash = hash_text(&content);
        let mtime_ms = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        Ok(MemoryFileEntry {
            path: rel_path.to_string(),
            hash,
            mtime_ms,
            size: meta.len() as i64,
        })
    }

    // ── Sync Pipeline (matching OpenClaw's syncMemoryFiles) ────────────

    /// Determine the source tag for a file path.
    /// "memory" for MEMORY.md and memory/*.md, "custom" for docs/*.md and notes/*.md, "sessions" for sessions/*.jsonl.
    fn source_for_path(rel_path: &str) -> &'static str {
        if rel_path == "MEMORY.md" || rel_path.starts_with("memory/") {
            "memory"
        } else if rel_path.starts_with("sessions/") {
            "sessions"
        } else {
            "custom"
        }
    }

    /// Clear all embeddings (useful for forcing reindex).
    pub fn clear_embeddings(&self) -> Result<()> {
        self.db.lock().unwrap().execute(
            "UPDATE chunks SET embedding = '[]'",
            [],
        )?;
        log::info!("Cleared all chunk embeddings");
        Ok(())
    }

    /// Prune the embedding cache using LRU eviction when it exceeds `max_entries`.
    ///
    /// Deletes the oldest `(count - max_entries * 0.8)` entries by `updated_at`
    /// to keep the cache below the soft target. Returns the number of entries pruned.
    pub fn prune_embedding_cache_if_needed(&self, max_entries: usize) -> Result<usize> {
        let db = self.db.lock().unwrap();

        let count: i64 = db.query_row(
            "SELECT COUNT(*) FROM embedding_cache",
            [],
            |r| r.get(0),
        )?;

        if count as usize <= max_entries {
            return Ok(0);
        }

        // Target: keep 80% of max_entries, delete the oldest entries
        let target = (max_entries as f64 * 0.8) as usize;
        let to_delete = (count as usize).saturating_sub(target);

        let deleted = db.execute(
            "DELETE FROM embedding_cache WHERE rowid IN \
             (SELECT rowid FROM embedding_cache ORDER BY updated_at ASC LIMIT ?1)",
            rusqlite::params![to_delete as i64],
        )?;

        if deleted > 0 {
            log::info!(
                "Embedding cache pruned: removed {} entries (was {}, target {})",
                deleted, count, target
            );
        }
        Ok(deleted)
    }

    // ── Crash-Safe Reindex (Shadow Table) ──────────────────────────────

    /// Create the embedding shadow table for a crash-safe reindex.
    ///
    /// This drops any leftover shadow from a previous run and creates a fresh one.
    /// All new embeddings are written here first. The live `embedding_cache` is
    /// not touched until `swap_shadow_to_main()` commits the atomic swap.
    pub fn create_embedding_shadow_table(&self) -> Result<()> {
        self.db.lock().unwrap().execute_batch(&format!(
            "DROP TABLE IF EXISTS embedding_cache_shadow;
             CREATE TABLE embedding_cache_shadow (
                 provider TEXT NOT NULL,
                 model TEXT NOT NULL,
                 provider_key TEXT NOT NULL,
                 hash TEXT NOT NULL,
                 embedding TEXT NOT NULL,
                 dims INTEGER,
                 updated_at INTEGER NOT NULL,
                 PRIMARY KEY (provider, model, provider_key, hash)
             );"
        ))?;
        log::debug!("Created embedding_cache_shadow table");
        Ok(())
    }

    /// Build new embeddings into the shadow table without touching the live data.
    ///
    /// - Cache hits are copied from the existing `embedding_cache` (no API calls).
    /// - Cache misses are sent to the embedding API and written into the shadow only.
    /// - `chunks.embedding` and `embedding_cache` are NOT modified.
    ///
    /// Call `swap_shadow_to_main()` after this succeeds to atomically apply.
    pub async fn embed_all_chunks_to_shadow(&self, provider: &EmbeddingProvider) -> Result<usize> {
        // Read all chunks — after force-sync they will all have embedding='[]'.
        let chunk_data: Vec<(String, String, String)> = {
            let db = self.db.lock().unwrap();
            let mut stmt = db.prepare("SELECT id, text, hash FROM chunks")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            rows.filter_map(|r| r.ok()).collect()
        };

        if chunk_data.is_empty() {
            return Ok(0);
        }

        let provider_key = hash_text(&format!(
            "{}:{}:{}", provider.base_url, provider.model, provider.target_dims()
        ));

        let mut to_embed: Vec<(usize, String, String, String)> = Vec::new();
        let mut cached_count = 0usize;

        for (i, (_id, text, hash)) in chunk_data.iter().enumerate() {
            // Check the LIVE embedding_cache for a cache hit (not the shadow).
            let cached: Option<(String, Option<i64>)> = self.db.lock().unwrap()
                .prepare(&format!(
                    "SELECT embedding, dims FROM {} WHERE provider = ? AND model = ? AND provider_key = ? AND hash = ?",
                    EMBEDDING_CACHE_TABLE
                ))
                .ok()
                .and_then(|mut s| {
                    s.query_row(
                        params!["openai-compat", provider.model(), &provider_key, hash],
                        |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?)),
                    )
                    .ok()
                });

            if let Some((cached_emb, dims)) = cached {
                // Copy cache hit into shadow table.
                self.db.lock().unwrap().execute(
                    "INSERT INTO embedding_cache_shadow
                     (provider, model, provider_key, hash, embedding, dims, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT(provider, model, provider_key, hash) DO UPDATE SET
                       embedding=excluded.embedding, dims=excluded.dims, updated_at=excluded.updated_at",
                    params![
                        "openai-compat", provider.model(), &provider_key, hash,
                        cached_emb, dims, Utc::now().timestamp_millis(),
                    ],
                )?;
                cached_count += 1;
            } else {
                to_embed.push((i, String::new(), text.clone(), hash.clone()));
            }
        }

        if to_embed.is_empty() {
            log::info!("Shadow embed: all {} chunks served from cache", cached_count);
            return Ok(cached_count);
        }

        // Batch-embed uncached chunks and write results to shadow only.
        let batch_max_tokens = 8000usize;
        let mut total = cached_count;
        let mut batch_start = 0;

        while batch_start < to_embed.len() {
            let mut batch_end = batch_start;
            let mut batch_tokens = 0usize;
            while batch_end < to_embed.len() {
                let text_tokens = (to_embed[batch_end].2.len() + 3) / 4;
                if batch_tokens + text_tokens > batch_max_tokens && batch_end > batch_start {
                    break;
                }
                batch_tokens += text_tokens;
                batch_end += 1;
            }

            let texts: Vec<String> = to_embed[batch_start..batch_end]
                .iter()
                .map(|(_, _, t, _)| t.clone())
                .collect();

            match provider.embed_batch(&texts).await {
                Ok(embeddings) => {
                    for (j, emb) in embeddings.iter().enumerate() {
                        let idx = batch_start + j;
                        let (_, _, _, ref hash) = to_embed[idx];
                        let emb_json = serde_json::to_string(emb)?;

                        // Write ONLY to shadow — live tables are untouched.
                        self.db.lock().unwrap().execute(
                            "INSERT INTO embedding_cache_shadow
                             (provider, model, provider_key, hash, embedding, dims, updated_at)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                             ON CONFLICT(provider, model, provider_key, hash) DO UPDATE SET
                               embedding=excluded.embedding, dims=excluded.dims, updated_at=excluded.updated_at",
                            params![
                                "openai-compat", provider.model(), &provider_key, hash,
                                emb_json, emb.len() as i64, Utc::now().timestamp_millis(),
                            ],
                        )?;
                        total += 1;
                    }
                }
                Err(e) => {
                    log::warn!("Shadow embedding batch failed: {} — partial shadow table", e);
                    break;
                }
            }
            batch_start = batch_end;
        }

        Ok(total)
    }

    /// Atomically swap the shadow table into the live embedding_cache and apply
    /// new embeddings to `chunks.embedding`.
    ///
    /// Runs as a single `BEGIN EXCLUSIVE` SQLite transaction, so it is either
    /// fully committed or fully rolled back on any failure (including a crash).
    /// After a successful commit the shadow table no longer exists.
    pub fn swap_shadow_to_main(&self) -> Result<usize> {
        let db = self.db.lock().unwrap();

        db.execute_batch("BEGIN EXCLUSIVE")?;

        let result: Result<usize> = (|| {
            // Apply new embeddings from shadow to every chunk.
            // Chunks with no shadow entry keep '[]' (rare: embed_batch failed for them).
            let updated = db.execute(
                "UPDATE chunks SET embedding = COALESCE(
                    (SELECT s.embedding FROM embedding_cache_shadow s
                     WHERE s.hash = chunks.hash LIMIT 1),
                 '[]')",
                [],
            )?;

            // Replace live embedding_cache with shadow contents, then drop shadow.
            db.execute_batch(&format!(
                "DELETE FROM {cache};
                 INSERT INTO {cache} SELECT * FROM embedding_cache_shadow;
                 DROP TABLE embedding_cache_shadow;",
                cache = EMBEDDING_CACHE_TABLE
            ))?;

            Ok(updated)
        })();

        match result {
            Ok(n) => {
                db.execute_batch("COMMIT")?;
                log::info!("Shadow swap committed: {} chunks updated", n);

                // Migrate embeddings to chunks_vec after swap (P2-4)
                if self.vec_available {
                    match migrate_existing_to_vec(&db) {
                        Ok(migrated) => {
                            if migrated > 0 {
                                log::info!("Migrated {} chunks to chunks_vec after swap", migrated);
                            }
                        }
                        Err(e) => {
                            log::warn!("chunks_vec migration after swap failed (non-fatal): {}", e);
                        }
                    }
                }

                Ok(n)
            }
            Err(e) => {
                db.execute_batch("ROLLBACK").ok();
                Err(e.context("Shadow-to-main swap failed; rolled back — old embeddings intact"))
            }
        }
    }

    /// Sync memory files into SQLite index.
    /// Hash-based skip for unchanged files (exact OpenClaw behavior).
    /// Indexes: MEMORY.md, memory/*.md (source=memory), docs/*.md, notes/*.md (source=custom).
    pub fn sync(&self, model: &str, _target_dims: usize) -> Result<usize> {
        let memory_files = self.list_memory_files()?;
        let mut indexed = 0usize;
        let active_paths: std::collections::HashSet<String> =
            memory_files.iter().map(|(p, _)| p.clone()).collect();

        for (rel_path, content) in &memory_files {
            let abs_path = if rel_path == "MEMORY.md" {
                self.memory_md_path()
            } else {
                self.workspace.join(rel_path)
            };
            let source = Self::source_for_path(rel_path);
            let entry = self.build_file_entry(rel_path, &abs_path)?;

            // Check if file unchanged (hash match) — skip if so
            let existing_hash: Option<String> = self.db.lock().unwrap()
                .prepare("SELECT hash FROM files WHERE path = ? AND source = ?")
                .ok()
                .and_then(|mut s| {
                    s.query_row(params![rel_path, source], |r| r.get(0)).ok()
                });

            if existing_hash.as_deref() == Some(&entry.hash) {
                continue; // unchanged
            }

            // Index this file
            self.index_file(&entry, content, model, source)?;
            indexed += 1;
        }

        // Clean up stale entries for both sources
        for source in &["memory", "custom"] {
            let stale_paths: Vec<String> = {
                let db = self.db.lock().unwrap();
                let mut stmt = db.prepare("SELECT path FROM files WHERE source = ?")?;
                let rows = stmt.query_map(params![source], |r| r.get::<_, String>(0))?;
                rows.filter_map(|r| r.ok()).collect()
            };

            for stale_path in &stale_paths {
                if !active_paths.contains(stale_path) {
                    self.remove_file_index(stale_path, source)?;
                }
            }
        }

        // Update index metadata after successful sync
        self.update_index_meta(model, _target_dims)?;

        Ok(indexed)
    }

    /// Update index metadata after successful sync/embed.
    /// Stores model, target_dims, chunk params, and timestamp for reindex decision.
    fn update_index_meta(&self, model: &str, target_dims: usize) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let meta = IndexMeta {
            model: model.to_string(),
            target_dims,
            chunk_tokens: self.chunk_tokens,
            chunk_overlap: self.chunk_overlap,
            schema_version: 1,
            last_sync_at: Some(now),
        };
        let meta_json = serde_json::to_string(&meta)?;

        self.db.lock().unwrap().execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            params![META_KEY, meta_json],
        )?;

        // Note: We can't update self.embedding_model or self.target_dims here
        // because &self is immutable. The fields will be used on next instantiation
        // or we can store them in a separate Arc<RwLock<>> if needed.
        // For now, search_hybrid gets model from provider directly.

        Ok(())
    }

    /// Load index metadata from SQLite.
    fn load_index_meta(&self) -> Result<Option<IndexMeta>> {
        let db = self.db.lock().unwrap();
        let mut stmt = db.prepare("SELECT value FROM meta WHERE key = ?")?;

        let meta_json: Option<String> = stmt
            .query_row(params![META_KEY], |r| r.get(0))
            .ok();

        match meta_json {
            Some(json) => {
                let meta: IndexMeta = serde_json::from_str(&json)
                    .context("Failed to parse index metadata")?;
                Ok(Some(meta))
            }
            None => Ok(None),
        }
    }

    /// Get current index metadata (public API).
    pub fn get_index_metadata(&self) -> Result<Option<IndexMeta>> {
        self.load_index_meta()
    }

    /// Decide whether a full reindex is needed based on current vs desired config.
    ///
    /// Returns true if any of these changed:
    /// - embedding model name
    /// - target dimensions
    /// - chunk tokens
    /// - chunk overlap
    /// - schema version
    pub fn needs_full_reindex(&self, model: &str, target_dims: usize) -> Result<bool> {
        match self.load_index_meta()? {
            None => {
                // No existing metadata - need initial index
                log::debug!("No index metadata found, initial sync needed");
                Ok(true)
            }
            Some(meta) => {
                // Check if any critical params changed
                let needs_reindex = meta.model != model
                    || meta.target_dims != target_dims
                    || meta.chunk_tokens != self.chunk_tokens
                    || meta.chunk_overlap != self.chunk_overlap
                    || meta.schema_version != 1;

                if needs_reindex {
                    log::info!(
                        "Reindex needed: model ({} vs {}), dims ({} vs {}), chunk_tokens ({} vs {}), chunk_overlap ({} vs {})",
                        meta.model, model,
                        meta.target_dims, target_dims,
                        meta.chunk_tokens, self.chunk_tokens,
                        meta.chunk_overlap, self.chunk_overlap
                    );
                }

                Ok(needs_reindex)
            }
        }
    }

    // ── Index File (matching OpenClaw's indexFile) ──────────────────────

    fn index_file(
        &self,
        entry: &MemoryFileEntry,
        content: &str,
        model: &str,
        source: &str,
    ) -> Result<()> {
        // Chunk the content (matching OpenClaw's chunkMarkdown)
        let chunks: Vec<MemoryChunk> = chunk_markdown(content, self.chunk_tokens, self.chunk_overlap)
            .into_iter()
            .filter(|c| !c.text.trim().is_empty())
            .collect();

        let now = chrono::Utc::now().timestamp_millis();

        // Get old chunk IDs for this file (before delete) — for vec cleanup (P2-4)
        let old_chunk_ids: Vec<String> = if self.vec_available {
            {
                let db = self.db.lock().unwrap();
                let mut stmt = db.prepare("SELECT id FROM chunks WHERE path = ? AND source = ?")?;
                let ids: Vec<String> = stmt.query_map(params![entry.path, source], |r| r.get(0))?
                    .filter_map(|r| r.ok()).collect();
                // db dropped here
                ids
            }
        } else { vec![] };

        // Delete old chunks for this file
        if self.fts_available {
            self.db.lock().unwrap().execute(
                &format!("DELETE FROM {} WHERE path = ? AND source = ? AND model = ?", FTS_TABLE),
                params![entry.path, source, model],
            ).ok();
        }
        self.db.lock().unwrap().execute(
            "DELETE FROM chunks WHERE path = ? AND source = ?",
            params![entry.path, source],
        )?;

        // Delete old chunks from chunks_vec (P2-4)
        if self.vec_available {
            let db = self.db.lock().unwrap();
            for id in &old_chunk_ids {
                delete_chunk_vec(&db, id).ok();
            }
        }

        // Insert new chunks
        for chunk in &chunks {
            let id = hash_text(&format!(
                "{}:{}:{}:{}:{}:{}",
                source, entry.path, chunk.start_line, chunk.end_line, chunk.hash, model
            ));

            // Empty embedding — will be filled by embed_chunks if provider available
            let embedding_json = "[]";

            self.db.lock().unwrap().execute(
                "INSERT INTO chunks (id, path, source, start_line, end_line, hash, model, text, embedding, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(id) DO UPDATE SET
                   hash=excluded.hash, model=excluded.model, text=excluded.text,
                   embedding=excluded.embedding, updated_at=excluded.updated_at",
                params![
                    id, entry.path, source, chunk.start_line as i64, chunk.end_line as i64,
                    chunk.hash, model, chunk.text, embedding_json, now,
                ],
            )?;

            // Insert into FTS5 table
            if self.fts_available {
                self.db.lock().unwrap().execute(
                    &format!(
                        "INSERT INTO {} (text, id, path, source, model, start_line, end_line)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        FTS_TABLE,
                    ),
                    params![
                        chunk.text, id, entry.path, source, model,
                        chunk.start_line as i64, chunk.end_line as i64,
                    ],
                ).ok();
            }
        }

        // Update files table
        self.db.lock().unwrap().execute(
            "INSERT INTO files (path, source, hash, mtime, size) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(path) DO UPDATE SET
               source=excluded.source, hash=excluded.hash, mtime=excluded.mtime, size=excluded.size",
            params![entry.path, source, entry.hash, entry.mtime_ms, entry.size],
        )?;

        Ok(())
    }

    /// Remove a file's index entries (matching OpenClaw's stale cleanup).
    fn remove_file_index(&self, path: &str, source: &str) -> Result<()> {
        // Get chunk IDs before deleting (for vec cleanup, P2-4)
        let chunk_ids: Vec<String> = if self.vec_available {
            {
                let db = self.db.lock().unwrap();
                let mut stmt = db.prepare("SELECT id FROM chunks WHERE path = ? AND source = ?")?;
                let ids: Vec<String> = stmt.query_map(params![path, source], |r| r.get(0))?
                    .filter_map(|r| r.ok()).collect();
                // db dropped here
                ids
            }
        } else {
            vec![]
        };

        self.db.lock().unwrap().execute(
            "DELETE FROM files WHERE path = ? AND source = ?",
            params![path, source],
        )?;
        self.db.lock().unwrap().execute(
            "DELETE FROM chunks WHERE path = ? AND source = ?",
            params![path, source],
        )?;
        if self.fts_available {
            self.db.lock().unwrap().execute(
                &format!("DELETE FROM {} WHERE path = ? AND source = ?", FTS_TABLE),
                params![path, source],
            ).ok();
        }

        // Delete from chunks_vec (P2-4)
        if self.vec_available {
            let db = self.db.lock().unwrap();
            for id in &chunk_ids {
                delete_chunk_vec(&db, id).ok();
            }
        }

        Ok(())
    }

    // ── Embed Chunks (with provider, matching OpenClaw flow) ───────────

    /// Update embeddings for all chunks using an embedding provider.
    /// Matches OpenClaw's embedChunksInBatches + embedding cache.
    pub async fn embed_all_chunks(&self, provider: &EmbeddingProvider) -> Result<usize> {
        // Get chunks without embeddings (or with empty embeddings)
        let chunk_data: Vec<(String, String, String)> = {
            let db = self.db.lock().unwrap();
            let mut stmt = db.prepare(
                "SELECT id, text, hash FROM chunks WHERE embedding = '[]'"
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            rows.filter_map(|r| r.ok()).collect()
        };

        if chunk_data.is_empty() {
            return Ok(0);
        }

        // Check embedding cache first (matching OpenClaw's loadEmbeddingCache)
        let mut to_embed: Vec<(usize, String, String, String)> = Vec::new();
        let mut cached_count = 0usize;
        // Include target_dims in cache key to prevent cross-contamination between 256/512
        let provider_key = hash_text(&format!("{}:{}:{}", provider.base_url, provider.model, provider.target_dims()));

        for (i, (id, text, hash)) in chunk_data.iter().enumerate() {
            let cached: Option<String> = self.db.lock().unwrap()
                .prepare(&format!(
                    "SELECT embedding FROM {} WHERE provider = ? AND model = ? AND provider_key = ? AND hash = ?",
                    EMBEDDING_CACHE_TABLE
                ))
                .ok()
                .and_then(|mut s| {
                    s.query_row(
                        params!["openai-compat", provider.model(), &provider_key, hash],
                        |r| r.get(0),
                    )
                    .ok()
                });

            if let Some(cached_emb) = cached {
                // Use cached embedding
                self.db.lock().unwrap().execute(
                    "UPDATE chunks SET embedding = ? WHERE id = ?",
                    params![cached_emb, id],
                )?;

                // Sync to chunks_vec (P2-4)
                if self.vec_available {
                    let emb: Vec<f32> = serde_json::from_str(&cached_emb).unwrap_or_default();
                    if !emb.is_empty() {
                        let db = self.db.lock().unwrap();
                        if let Err(e) = upsert_chunk_vec(&db, id, &emb) {
                            log::warn!("chunks_vec upsert failed (non-fatal): {}", e);
                        }
                    }
                }

                cached_count += 1;
            } else {
                to_embed.push((i, id.clone(), text.clone(), hash.clone()));
            }
        }

        if to_embed.is_empty() {
            return Ok(cached_count);
        }

        // Batch embed (matching OpenClaw's EMBEDDING_BATCH_MAX_TOKENS = 8000)
        let batch_max_tokens = 8000usize;
        let mut total_embedded = cached_count;
        let mut batch_start = 0;

        while batch_start < to_embed.len() {
            let mut batch_end = batch_start;
            let mut batch_tokens = 0usize;
            while batch_end < to_embed.len() {
                let text_tokens = (to_embed[batch_end].2.len() + 3) / 4;
                if batch_tokens + text_tokens > batch_max_tokens && batch_end > batch_start {
                    break;
                }
                batch_tokens += text_tokens;
                batch_end += 1;
            }

            let texts: Vec<String> = to_embed[batch_start..batch_end]
                .iter()
                .map(|(_, _, t, _)| t.clone())
                .collect();

            match provider.embed_batch(&texts).await {
                Ok(embeddings) => {
                    for (j, emb) in embeddings.iter().enumerate() {
                        let idx = batch_start + j;
                        let (_, ref id, _, ref hash) = to_embed[idx];
                        let emb_json = serde_json::to_string(emb)?;

                        // Update chunk embedding
                        self.db.lock().unwrap().execute(
                            "UPDATE chunks SET embedding = ? WHERE id = ?",
                            params![emb_json, id],
                        )?;

                        // Sync to chunks_vec (P2-4)
                        if self.vec_available {
                            let db = self.db.lock().unwrap();
                            if let Err(e) = upsert_chunk_vec(&db, id, emb) {
                                log::warn!("chunks_vec upsert failed (non-fatal): {}", e);
                            }
                        }

                        // Update embedding cache (matching OpenClaw's upsertEmbeddingCache)
                        self.db.lock().unwrap().execute(
                            &format!(
                                "INSERT INTO {} (provider, model, provider_key, hash, embedding, dims, updated_at)
                                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                                 ON CONFLICT(provider, model, provider_key, hash) DO UPDATE SET
                                   embedding=excluded.embedding, dims=excluded.dims, updated_at=excluded.updated_at",
                                EMBEDDING_CACHE_TABLE,
                            ),
                            params![
                                "openai-compat", provider.model(), &provider_key, hash,
                                emb_json, emb.len() as i64, Utc::now().timestamp_millis(),
                            ],
                        )?;

                        total_embedded += 1;
                    }
                }
                Err(e) => {
                    log::warn!("Embedding batch failed: {}; continuing with keyword-only search", e);
                    break;
                }
            }

            batch_start = batch_end;
        }

        // Update index metadata after successful embedding
        if total_embedded > 0 || cached_count > 0 {
            self.update_index_meta(provider.model(), provider.target_dims())?;
            // Update runtime state (note: requires &mut self, so we use a workaround)
            // For now, this is handled by the daemon recreating MemoryDb or via unsafe
        }

        // Prune embedding cache if it has grown beyond the default LRU threshold.
        // Use a conservative default here; callers can pass a configurable value via
        // prune_embedding_cache_if_needed() if needed.
        const DEFAULT_CACHE_MAX: usize = 50_000;
        if let Err(e) = self.prune_embedding_cache_if_needed(DEFAULT_CACHE_MAX) {
            log::warn!("Embedding cache pruning failed (non-fatal): {}", e);
        }

        Ok(total_embedded)
    }

    // ── Hybrid Search (matching OpenClaw's search method) ──────────────

    /// Search memory using hybrid BM25 + vector cosine (exact OpenClaw parity).
    ///
    /// Pipeline:
    /// 1. BM25 keyword search via FTS5 (text weight = 0.3)
    /// 2. Vector cosine similarity on embeddings (vector weight = 0.7)
    /// 3. Weighted merge: score = vectorWeight * vectorScore + textWeight * textScore
    pub fn search(
        &self,
        query: &str,
        max_results: usize,
        min_score: f32,
    ) -> Result<Vec<MemorySearchResult>> {
        let cleaned = query.trim();
        if cleaned.is_empty() {
            return Ok(Vec::new());
        }

        let vector_weight = 0.7f32;
        let text_weight = 0.3f32;
        let candidate_multiplier = 3;
        let candidates = max_results * candidate_multiplier;

        // 1. BM25 keyword search (matching OpenClaw's searchKeyword)
        let keyword_results = if self.fts_available {
            self.search_keyword(cleaned, candidates)?
        } else {
            // Fallback: simple keyword search on chunk text
            self.search_keyword_fallback(cleaned, candidates)?
        };

        // 2. Vector search (matching OpenClaw's searchVector)
        let vector_results = self.search_vector_from_stored(cleaned, candidates)?;

        // 3. If no vector results, return keyword-only
        if vector_results.is_empty() {
            let results: Vec<MemorySearchResult> = keyword_results
                .into_iter()
                .filter(|r| r.score >= min_score)
                .take(max_results)
                .collect();
            return Ok(results);
        }

        // 4. Hybrid merge (matching OpenClaw's mergeHybridResults)
        let merged = self.merge_hybrid_results(
            &vector_results,
            &keyword_results,
            vector_weight,
            text_weight,
        );

        let results: Vec<MemorySearchResult> = merged
            .into_iter()
            .filter(|r| r.score >= min_score)
            .take(max_results)
            .collect();

        Ok(results)
    }

    /// BM25 keyword search via FTS5 (matching OpenClaw's searchKeyword).
    fn search_keyword(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<MemorySearchResult>> {
        let fts_query = match build_fts_query(query) {
            Some(q) => q,
            None => return Ok(Vec::new()),
        };

        let sql = format!(
            "SELECT id, path, source, start_line, end_line, text, bm25({}) AS rank
             FROM {} WHERE {} MATCH ?1
             ORDER BY rank ASC LIMIT ?2",
            FTS_TABLE, FTS_TABLE, FTS_TABLE,
        );

        let db = self.db.lock().unwrap();
        let mut stmt = db.prepare(&sql)?;
        let rows = stmt.query_map(params![fts_query, limit as i64], |r| {
            let rank: f64 = r.get(6)?;
            let text: String = r.get(5)?;
            let path: String = r.get(1)?;
            let start_line: i64 = r.get(3)?;
            let end_line: i64 = r.get(4)?;
            let source: String = r.get(2)?;
            let score = bm25_rank_to_score(rank);
            let snippet = if text.len() > SNIPPET_MAX_CHARS {
                text[..SNIPPET_MAX_CHARS].to_string()
            } else {
                text
            };
            let citation = format!("{}#L{}-L{}", path, start_line, end_line);
            Ok(MemorySearchResult {
                path,
                snippet,
                start_line: start_line as usize,
                end_line: end_line as usize,
                score,
                citation: Some(citation),
                source,
                provider: None,
                model: None,
                fallback: true,
            })
        })?;

        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Fallback keyword search when FTS5 is unavailable.
    fn search_keyword_fallback(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<MemorySearchResult>> {
        let query_lower = query.to_lowercase();
        let terms: Vec<&str> = query_lower.split_whitespace().collect();
        if terms.is_empty() {
            return Ok(Vec::new());
        }

        let db = self.db.lock().unwrap();
        let mut stmt = db.prepare(
            "SELECT id, path, source, start_line, end_line, text FROM chunks"
        )?;
        let mut results: Vec<MemorySearchResult> = Vec::new();

        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, String>(5)?,
            ))
        })?;

        for row in rows {
            let (path, source, start_line, end_line, text) = row?;
            let text_lower = text.to_lowercase();
            let mut score = 0.0f32;
            for term in &terms {
                let matches = text_lower.matches(term).count();
                if matches > 0 {
                    score += matches as f32 / terms.len() as f32;
                }
            }
            if score > 0.0 {
                let snippet = if text.len() > SNIPPET_MAX_CHARS {
                    text[..SNIPPET_MAX_CHARS].to_string()
                } else {
                    text
                };
                let citation = format!("{}#L{}-L{}", path, start_line, end_line);
                results.push(MemorySearchResult {
                    path,
                    snippet,
                    start_line: start_line as usize,
                    end_line: end_line as usize,
                    score,
                    citation: Some(citation),
                    source,
                    provider: None,
                    model: None,
                    fallback: true,
                });
            }
        }

        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(limit);
        Ok(results)
    }

    /// Vector search using stored embeddings (matching OpenClaw's searchVector fallback).
    /// Uses cosine similarity on stored chunk embeddings.
    fn search_vector_from_stored(
        &self,
        _query: &str,
        _limit: usize,
    ) -> Result<Vec<MemorySearchResult>> {
        // Check if any chunks have embeddings
        let has_embeddings: bool = self.db.lock().unwrap()
            .prepare("SELECT COUNT(*) FROM chunks WHERE embedding != '[]' LIMIT 1")
            .ok()
            .and_then(|mut s| s.query_row([], |r| r.get::<_, i64>(0)).ok())
            .map(|c| c > 0)
            .unwrap_or(false);

        if !has_embeddings {
            return Ok(Vec::new());
        }

        // We need a query embedding to do vector search.
        // Without an active embedding provider at search time, we rely on FTS5.
        // Vector search is performed via search_with_query_embedding() below.
        Ok(Vec::new())
    }

    /// KNN vector search using sqlite-vec (O(log n) vs O(n) linear scan).
    /// Only available when vec_available=true (P2-4).
    fn search_vector_knn(
        &self,
        query_vec: &[f32],
        limit: usize,
        provider: &EmbeddingProvider,
    ) -> Result<Vec<MemorySearchResult>> {
        if query_vec.is_empty() || !self.vec_available {
            return Ok(Vec::new());
        }

        let blob = vec_to_blob(query_vec);

        // Phase 1: KNN from sqlite-vec → (chunk_id, distance)
        let knn_results: Vec<(String, f64)> = {
            let db = self.db.lock().unwrap();
            let mut stmt = db.prepare(
                "SELECT chunk_id, distance FROM chunks_vec WHERE embedding MATCH ?1 AND k = ?2"
            )?;
            let results: Vec<(String, f64)> = stmt.query_map(params![blob, limit as i64], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, f64>(1)?))
            })?.filter_map(|r| r.ok()).collect();
            // db and stmt dropped here
            results
        };

        if knn_results.is_empty() {
            return Ok(Vec::new());
        }

        // Phase 2: Bulk fetch chunk data from chunks table
        let ids: Vec<&str> = knn_results.iter().map(|(id, _)| id.as_str()).collect();

        // Build score map: distance → cosine similarity (score = 1.0 - distance)
        let score_map: HashMap<String, f32> = knn_results.iter()
            .map(|(id, dist)| (id.clone(), (1.0 - *dist) as f32))
            .collect();

        // Fetch chunk details
        let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let query = format!(
            "SELECT id, path, source, start_line, end_line, text FROM chunks WHERE id IN ({})",
            placeholders
        );

        let db = self.db.lock().unwrap();
        let mut stmt = db.prepare(&query)?;

        let mut results: Vec<MemorySearchResult> = stmt
            .query_map(rusqlite::params_from_iter(ids.iter()), |r| {
                Ok((
                    r.get::<_, String>(0)?, // id
                    r.get::<_, String>(1)?, // path
                    r.get::<_, String>(2)?, // source
                    r.get::<_, i64>(3)?,    // start_line
                    r.get::<_, i64>(4)?,    // end_line
                    r.get::<_, String>(5)?, // text
                ))
            })?
            .filter_map(|r| r.ok())
            .map(|(id, path, source, start, end, text)| {
                let score = *score_map.get(&id).unwrap_or(&0.0);
                let snippet = if text.len() > SNIPPET_MAX_CHARS {
                    text[..SNIPPET_MAX_CHARS].to_string()
                } else {
                    text
                };
                let citation = format!("{}#L{}-L{}", path, start, end);
                MemorySearchResult {
                    path,
                    snippet,
                    start_line: start as usize,
                    end_line: end as usize,
                    score,
                    citation: Some(citation),
                    source,
                    provider: Some("openai-compat".to_string()),
                    model: Some(provider.model().to_string()),
                    fallback: false,
                }
            })
            .collect();

        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        Ok(results)
    }

    /// Vector search with a pre-computed query embedding.
    /// Called when an embedding provider is available.
    pub fn search_vector_with_embedding(
        &self,
        query_vec: &[f32],
        limit: usize,
        provider: &EmbeddingProvider,
    ) -> Result<Vec<MemorySearchResult>> {
        if query_vec.is_empty() {
            return Ok(Vec::new());
        }

        // Use sqlite-vec KNN if available (P2-4)
        if self.vec_available {
            return self.search_vector_knn(query_vec, limit, provider);
        }

        let db = self.db.lock().unwrap();
        let mut stmt = db.prepare(
            "SELECT id, path, source, start_line, end_line, text, embedding
             FROM chunks WHERE embedding != '[]'"
        )?;

        let mut results: Vec<MemorySearchResult> = Vec::new();

        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
            ))
        })?;

        for row in rows {
            let (path, source, start_line, end_line, text, emb_str) = row?;
            let emb = parse_embedding(&emb_str);
            if emb.is_empty() {
                continue;
            }
            let score = cosine_similarity(query_vec, &emb);
            let snippet = if text.len() > SNIPPET_MAX_CHARS {
                text[..SNIPPET_MAX_CHARS].to_string()
            } else {
                text
            };
            let citation = format!("{}#L{}-L{}", path, start_line, end_line);
            results.push(MemorySearchResult {
                path,
                snippet,
                start_line: start_line as usize,
                end_line: end_line as usize,
                score,
                citation: Some(citation),
                source,
                provider: Some("openai-compat".to_string()),
                model: Some(provider.model().to_string()),
                fallback: false,
            });
        }

        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(limit);
        Ok(results)
    }

    /// Full hybrid search with embedding provider (matching OpenClaw's search method exactly).
    pub async fn search_hybrid(
        &self,
        query: &str,
        max_results: usize,
        min_score: f32,
        provider: &EmbeddingProvider,
        require_embeddings: bool,
    ) -> Result<Vec<MemorySearchResult>> {
        let cleaned = query.trim();
        if cleaned.is_empty() {
            return Ok(Vec::new());
        }

        let vector_weight = 0.7f32;
        let text_weight = 0.3f32;
        let candidates = (max_results * 3).min(200);

        // 1. BM25 keyword search
        let keyword_results = if self.fts_available {
            self.search_keyword(cleaned, candidates)?
        } else {
            self.search_keyword_fallback(cleaned, candidates)?
        };

        // 2. Get query embedding with fallback to lexical-only on failure (if allowed)
        let vector_results = match provider.embed_query(cleaned).await {
            Ok(query_vec) => {
                let has_vector = query_vec.iter().any(|v| *v != 0.0);
                if has_vector {
                    self.search_vector_with_embedding(&query_vec, candidates, provider)?
                } else {
                    Vec::new()
                }
            }
            Err(e) => {
                if require_embeddings {
                    // Strict mode: fail explicitly instead of degrading to keyword-only
                    return Err(anyhow::anyhow!(
                        "Embedding query failed in strict mode (require_embeddings=true): {}. \
                         Search cannot continue without vector embeddings. \
                         Ensure Ollama is running or set require_embeddings=false to allow lexical fallback.",
                        e
                    ));
                } else {
                    // Non-strict mode: degrade to keyword-only
                    log::warn!("Embedding query failed, falling back to keyword-only search: {}", e);
                    Vec::new()
                }
            }
        };

        // 3. Merge
        if vector_results.is_empty() {
            return Ok(keyword_results
                .into_iter()
                .filter(|r| r.score >= min_score)
                .take(max_results)
                .collect());
        }

        let merged = self.merge_hybrid_results(
            &vector_results,
            &keyword_results,
            vector_weight,
            text_weight,
        );

        Ok(merged
            .into_iter()
            .filter(|r| r.score >= min_score)
            .take(max_results)
            .collect())
    }

    /// Merge hybrid results (matching OpenClaw's mergeHybridResults exactly).
    fn merge_hybrid_results(
        &self,
        vector: &[MemorySearchResult],
        keyword: &[MemorySearchResult],
        vector_weight: f32,
        text_weight: f32,
    ) -> Vec<MemorySearchResult> {
        use std::collections::HashMap;

        // key = path:startLine:endLine
        let mut by_key: HashMap<String, (f32, f32, MemorySearchResult)> = HashMap::new();

        for r in vector {
            let key = format!("{}:{}:{}", r.path, r.start_line, r.end_line);
            by_key.insert(key, (r.score, 0.0, r.clone()));
        }

        for r in keyword {
            let key = format!("{}:{}:{}", r.path, r.start_line, r.end_line);
            if let Some(entry) = by_key.get_mut(&key) {
                entry.1 = r.score; // add text score
                // use keyword snippet if available
                if !r.snippet.is_empty() {
                    entry.2.snippet = r.snippet.clone();
                }
            } else {
                by_key.insert(key, (0.0, r.score, r.clone()));
            }
        }

        let mut merged: Vec<MemorySearchResult> = by_key
            .into_values()
            .map(|(vec_score, text_score, mut result)| {
                result.score = vector_weight * vec_score + text_weight * text_score;
                result
            })
            .collect();

        merged.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        merged
    }

    // ── Store (matching OpenClaw's memory flush to files) ──────────────

    pub fn store(&self, _session_id: &str, role: &str, content: &str) -> Result<i64> {
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let date_file = self.memory_dir().join(format!("{}.md", today));
        let entry = format!(
            "\n## {} — {}\n\n{}\n",
            role,
            Utc::now().format("%H:%M:%S UTC"),
            content
        );

        if date_file.exists() {
            let existing = std::fs::read_to_string(&date_file)?;
            std::fs::write(&date_file, format!("{}{}", existing, entry))?;
        } else {
            let header = format!("# Memory — {}\n{}", today, entry);
            std::fs::write(&date_file, header)?;
        }

        Ok(0)
    }

    // ── Retrieve (reads all memory files) ─────────────────────────────

    pub fn retrieve(&self, _session_id: &str) -> Result<Vec<MemoryEntry>> {
        let mut entries = Vec::new();

        let memory_md = self.memory_md_path();
        if memory_md.exists() {
            let content = std::fs::read_to_string(&memory_md)?;
            if !content.trim().is_empty() {
                let line_count = content.lines().count();
                entries.push(MemoryEntry {
                    path: "MEMORY.md".to_string(),
                    content,
                    line_start: 1,
                    line_end: line_count,
                });
            }
        }

        let memory_dir = self.memory_dir();
        if memory_dir.exists() {
            let mut files: Vec<_> = std::fs::read_dir(&memory_dir)?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map_or(false, |ext| ext == "md"))
                .collect();
            files.sort_by_key(|e| e.file_name());

            for file in files {
                let content = std::fs::read_to_string(file.path())?;
                let path = format!("memory/{}", file.file_name().to_string_lossy());
                let line_count = content.lines().count();
                entries.push(MemoryEntry { path, content, line_start: 1, line_end: line_count });
            }
        }

        Ok(entries)
    }

    // ── Read File (matching OpenClaw's readFile) ──────────────────────

    pub fn read_file(&self, rel_path: &str, from: Option<usize>, lines: Option<usize>) -> Result<String> {
        let full_path = self.workspace.join(rel_path);
        if !full_path.exists() {
            anyhow::bail!("Memory file not found: {}", rel_path);
        }
        let canonical = std::fs::canonicalize(&full_path)?;
        let ws_canonical = std::fs::canonicalize(&self.workspace)?;
        if !canonical.starts_with(&ws_canonical) {
            anyhow::bail!("Path escapes workspace: {}", rel_path);
        }
        let content = std::fs::read_to_string(&full_path)?;
        let all_lines: Vec<&str> = content.lines().collect();
        let start = from.unwrap_or(1).saturating_sub(1);
        let count = lines.unwrap_or(all_lines.len());
        let end = (start + count).min(all_lines.len());
        Ok(all_lines[start..end].join("\n"))
    }

    // ── Metrics ─────────────────────────────────────────────────────────

    pub fn total_memory_chars(&self) -> Result<usize> {
        let files = self.list_memory_files()?;
        Ok(files.iter().map(|(_, c)| c.len()).sum())
    }

    pub fn total_memory_tokens(&self) -> Result<usize> {
        Ok((self.total_memory_chars()? + 3) / 4)
    }

    pub fn session_token_count(&self, _session_id: &str) -> Result<usize> {
        self.total_memory_tokens()
    }

    /// Get index status (matching OpenClaw's status method).
    pub fn index_status(&self) -> Result<IndexStatus> {
        let files: i64 = self.db.lock().unwrap().query_row(
            "SELECT COUNT(*) FROM files", [], |r| r.get(0),
        ).unwrap_or(0);
        let chunks: i64 = self.db.lock().unwrap().query_row(
            "SELECT COUNT(*) FROM chunks", [], |r| r.get(0),
        ).unwrap_or(0);
        let embedded: i64 = self.db.lock().unwrap().query_row(
            "SELECT COUNT(*) FROM chunks WHERE embedding != '[]'", [], |r| r.get(0),
        ).unwrap_or(0);
        let cached: i64 = self.db.lock().unwrap().query_row(
            &format!("SELECT COUNT(*) FROM {}", EMBEDDING_CACHE_TABLE), [], |r| r.get(0),
        ).unwrap_or(0);

        Ok(IndexStatus {
            files: files as usize,
            chunks: chunks as usize,
            embedded: embedded as usize,
            cached: cached as usize,
            fts_available: self.fts_available,
        })
    }

    // ── Sync With Options (matching OpenClaw's syncMemoryFiles params) ──

    /// Sync with advanced options: force reindex, progress callback.
    /// Matches OpenClaw's syncMemoryFiles with needsFullReindex + progress.
    pub fn sync_with_options(
        &self,
        model: &str,
        force_reindex: bool,
        progress: Option<&SyncProgressFn>,
    ) -> Result<usize> {
        let memory_files = self.list_memory_files()?;
        let total = memory_files.len();
        let mut indexed = 0usize;
        let mut completed = 0usize;
        let active_paths: std::collections::HashSet<String> =
            memory_files.iter().map(|(p, _)| p.clone()).collect();

        // Parallel file reading + chunking (matching OpenClaw's concurrency pattern)
        // Collect file entries in parallel using std::thread::scope
        let file_entries: Vec<(String, String, MemoryFileEntry)> = std::thread::scope(|s| {
            let handles: Vec<_> = memory_files.iter().map(|(rel_path, content)| {
                let rel = rel_path.clone();
                let cont = content.clone();
                let ws = self.workspace.clone();
                s.spawn(move || {
                    let abs_path = if rel == "MEMORY.md" {
                        ws.join("MEMORY.md")
                    } else {
                        ws.join(&rel)
                    };
                    let meta = std::fs::metadata(&abs_path).ok()?;
                    let hash = hash_text(&cont);
                    let mtime_ms = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_millis() as i64)
                        .unwrap_or(0);
                    let entry = MemoryFileEntry {
                        path: rel.clone(),
                        hash,
                        mtime_ms,
                        size: meta.len() as i64,
                    };
                    Some((rel, cont, entry))
                })
            }).collect();
            handles.into_iter().filter_map(|h| h.join().ok().flatten()).collect()
        });

        // Sequential DB writes (matching OpenClaw: parallel read, sequential write)
        for (rel_path, content, entry) in &file_entries {
            let source = Self::source_for_path(rel_path);

            // Check if file unchanged (hash match) — skip unless force_reindex
            if !force_reindex {
                let existing_hash: Option<String> = self.db.lock().unwrap()
                    .prepare("SELECT hash FROM files WHERE path = ? AND source = ?")
                    .ok()
                    .and_then(|mut s| {
                        s.query_row(params![rel_path, source], |r| r.get(0)).ok()
                    });

                if existing_hash.as_deref() == Some(&entry.hash) {
                    completed += 1;
                    if let Some(progress_fn) = progress {
                        progress_fn(completed, total, rel_path);
                    }
                    continue; // unchanged
                }
            }

            // Index this file
            self.index_file(entry, content, model, source)?;
            indexed += 1;
            completed += 1;
            if let Some(progress_fn) = progress {
                progress_fn(completed, total, rel_path);
            }
        }

        // Clean up stale entries for both sources
        for source in &["memory", "custom"] {
            let stale_paths: Vec<String> = {
                let db = self.db.lock().unwrap();
                let mut stmt = db.prepare("SELECT path FROM files WHERE source = ?")?;
                let rows = stmt.query_map(params![source], |r| r.get::<_, String>(0))?;
                rows.filter_map(|r| r.ok()).collect()
            };

            for stale_path in &stale_paths {
                if !active_paths.contains(stale_path) {
                    self.remove_file_index(stale_path, source)?;
                }
            }
        }

        Ok(indexed)
    }

    // ── Audit Log ───────────────────────────────────────────────────────

    pub fn log_action(&self, action: &str, details: Option<&str>, result: Option<&str>) -> Result<()> {
        let audit_path = self.workspace.join(".audit.log");
        let timestamp = Utc::now().to_rfc3339();
        let line = format!(
            "{} | {} | {} | {}\n",
            timestamp, action, details.unwrap_or("-"), result.unwrap_or("-")
        );
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&audit_path)?;
        file.write_all(line.as_bytes())?;
        Ok(())
    }
}

/// Index status (matching OpenClaw's MemoryProviderStatus).
#[derive(Debug, Clone)]
pub struct IndexStatus {
    pub files: usize,
    pub chunks: usize,
    pub embedded: usize,
    pub cached: usize,
    pub fts_available: bool,
}

// ── Public Constants ────────────────────────────────────────────────────

pub const MEMORY_FLUSH_PROMPT: &str = "\
Pre-compaction memory flush. \
Store durable memories now (use memory/YYYY-MM-DD.md; create memory/ if needed). \
IMPORTANT: If the file already exists, APPEND new content only and do not overwrite existing entries. \
If nothing to store, just continue.";

pub const DEFAULT_COMPACT_KEEP_DAYS: usize = 7;

pub fn estimate_tokens(text: &str) -> usize {
    (text.len() + 3) / 4
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_workspace() -> (tempfile::TempDir, MemoryDb) {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = MemoryDb::new(tmp.path()).unwrap();
        (tmp, db)
    }

    #[test]
    fn test_matryoshka_projection_512() {
        // Test 768-dim projection to 512
        let input: Vec<f32> = (0..768).map(|i| i as f32).collect();
        let projected = project_matryoshka(&input, 512).unwrap();

        assert_eq!(projected.len(), 512);
        // Check L2 normalization (should be close to unit vector)
        let norm: f32 = projected.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5);
    }

    #[test]
    fn test_matryoshka_projection_256() {
        // Test 768-dim projection to 256
        let input: Vec<f32> = (0..768).map(|i| i as f32).collect();
        let projected = project_matryoshka(&input, 256).unwrap();

        assert_eq!(projected.len(), 256);
        // Check L2 normalization
        let norm: f32 = projected.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5);
    }

    #[test]
    fn test_matryoshka_projection_rejects_short_vector() {
        // Test rejection when source vector is shorter than target
        let short: Vec<f32> = vec![1.0, 2.0, 3.0];
        let result = project_matryoshka(&short, 512);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("source too short"));
    }

    #[test]
    fn test_matryoshka_projection_exact_size() {
        // Test projection when source equals target (should still normalize)
        let input: Vec<f32> = vec![3.0, 4.0]; // norm = 5
        let projected = project_matryoshka(&input, 2).unwrap();

        assert_eq!(projected.len(), 2);
        // After L2 normalization: [3/5, 4/5] = [0.6, 0.8]
        assert!((projected[0] - 0.6).abs() < 1e-5);
        assert!((projected[1] - 0.8).abs() < 1e-5);
    }

    #[test]
    fn test_embedding_cache_key_includes_dims() {
        // Verify that cache key includes target_dims to prevent cross-contamination
        let url = "http://localhost:11434/v1";
        let model = "nomic-embed-text:v1.5";

        let provider_256 = EmbeddingProvider::new(url, model, None, 256);
        let provider_512 = EmbeddingProvider::new(url, model, None, 512);

        // Different target_dims should produce different cache keys
        let key_256 = hash_text(&format!("{}:{}:{}", url, model, 256));
        let key_512 = hash_text(&format!("{}:{}:{}", url, model, 512));

        assert_ne!(key_256, key_512, "Cache keys must differ by target_dims");
        assert_eq!(provider_256.target_dims(), 256);
        assert_eq!(provider_512.target_dims(), 512);
    }

    #[test]
    fn test_store_and_retrieve() {
        let (_tmp, db) = temp_workspace();
        db.store("test-session-1", "user", "Hello!").unwrap();
        db.store("test-session-1", "assistant", "Hi there!").unwrap();
        let entries = db.retrieve("test-session-1").unwrap();
        assert!(entries.len() >= 1);
        let today_entry = entries.iter().find(|e| e.path.starts_with("memory/")).unwrap();
        assert!(today_entry.content.contains("Hello!"));
        assert!(today_entry.content.contains("Hi there!"));
    }

    #[test]
    fn test_search_keyword_fts() {
        let (_tmp, db) = temp_workspace();
        db.store("s1", "user", "I prefer dark mode in my editor").unwrap();
        db.store("s1", "user", "My favorite language is Rust").unwrap();
        // Sync to index
        db.sync("test-model", 512).unwrap();
        let results = db.search("dark mode", 5, 0.0).unwrap();
        assert!(!results.is_empty());
        assert!(results[0].snippet.contains("dark mode"));
    }

    #[test]
    fn test_search_empty() {
        let (_tmp, db) = temp_workspace();
        db.sync("test-model", 512).unwrap();
        let results = db.search("nonexistent_query_xyz", 5, 0.0).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_sync_hash_skip() {
        let (_tmp, db) = temp_workspace();
        db.store("s1", "user", "initial content").unwrap();
        let count1 = db.sync("test-model", 512).unwrap();
        assert!(count1 > 0);
        // Second sync should skip (no changes)
        let count2 = db.sync("test-model", 512).unwrap();
        assert_eq!(count2, 0);
    }

    #[test]
    fn test_sync_detects_changes() {
        let (_tmp, db) = temp_workspace();
        db.store("s1", "user", "initial content").unwrap();
        db.sync("test-model", 512).unwrap();
        // Add more content
        db.store("s1", "user", "new content").unwrap();
        let count = db.sync("test-model", 512).unwrap();
        assert!(count > 0); // date file changed
    }

    #[test]
    fn test_chunk_markdown() {
        let content = "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10";
        let chunks = chunk_markdown(content, 4, 1);
        assert!(!chunks.is_empty());
        // Each chunk should have valid line numbers
        for c in &chunks {
            assert!(c.start_line >= 1);
            assert!(c.end_line >= c.start_line);
            assert!(!c.hash.is_empty());
        }
    }

    #[test]
    fn test_cosine_similarity() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert!((cosine_similarity(&a, &b) - 1.0).abs() < 0.001);

        let c = vec![0.0, 1.0, 0.0];
        assert!((cosine_similarity(&a, &c)).abs() < 0.001);
    }

    #[test]
    fn test_build_fts_query() {
        assert_eq!(build_fts_query("hello world"), Some("\"hello\" AND \"world\"".to_string()));
        assert_eq!(build_fts_query(""), None);
        assert_eq!(build_fts_query("   "), None);
    }

    #[test]
    fn test_read_file() {
        let (_tmp, db) = temp_workspace();
        let content = db.read_file("MEMORY.md", None, None).unwrap();
        assert!(content.contains("Memory"));
    }

    #[test]
    fn test_read_file_with_range() {
        let (_tmp, db) = temp_workspace();
        let content = db.read_file("MEMORY.md", Some(1), Some(1)).unwrap();
        assert!(content.contains("Memory"));
    }

    #[test]
    fn test_audit_logging() {
        let (_tmp, db) = temp_workspace();
        db.log_action("test_action", Some("test details"), Some("success")).unwrap();
        let audit = std::fs::read_to_string(db.workspace().join(".audit.log")).unwrap();
        assert!(audit.contains("test_action"));
    }

    #[test]
    fn test_index_status() {
        let (_tmp, db) = temp_workspace();
        db.store("s1", "user", "test content").unwrap();
        db.sync("test-model", 512).unwrap();
        let status = db.index_status().unwrap();
        assert!(status.files > 0);
        assert!(status.chunks > 0);
        assert!(status.fts_available);
    }

    #[test]
    fn test_token_estimation() {
        assert_eq!(estimate_tokens(""), 0);
        assert_eq!(estimate_tokens("hi"), 1);
        assert_eq!(estimate_tokens("hello world"), 3);
    }

    #[test]
    fn test_stale_cleanup() {
        let (_tmp, db) = temp_workspace();
        // Create a file, sync, then delete it
        let test_file = db.memory_dir().join("2020-06-15.md");
        std::fs::write(&test_file, "# test\nsome content").unwrap();
        db.sync("test-model", 512).unwrap();
        let status1 = db.index_status().unwrap();
        // Delete the file
        std::fs::remove_file(&test_file).unwrap();
        db.sync("test-model", 512).unwrap();
        let status2 = db.index_status().unwrap();
        // Should have fewer files after cleanup
        assert!(status2.files < status1.files || status2.chunks < status1.chunks);
    }

    #[test]
    fn test_needs_full_reindex_initial() {
        let (_tmp, db) = temp_workspace();
        // No metadata exists yet
        let needs = db.needs_full_reindex("test-model", 512).unwrap();
        assert!(needs, "Initial state should require reindex");
    }

    #[test]
    fn test_needs_full_reindex_after_sync() {
        let (_tmp, db) = temp_workspace();
        db.store("s1", "user", "test content").unwrap();
        db.sync("test-model", 512).unwrap();

        // After sync, same config should not need reindex
        let needs = db.needs_full_reindex("test-model", 512).unwrap();
        assert!(!needs, "Same config should not need reindex");
    }

    #[test]
    fn test_needs_full_reindex_model_change() {
        let (_tmp, db) = temp_workspace();
        db.store("s1", "user", "test content").unwrap();
        db.sync("test-model", 512).unwrap();

        // Different model should trigger reindex
        let needs = db.needs_full_reindex("different-model", 512).unwrap();
        assert!(needs, "Model change should trigger reindex");
    }

    #[test]
    fn test_needs_full_reindex_dims_change() {
        let (_tmp, db) = temp_workspace();
        db.store("s1", "user", "test content").unwrap();
        db.sync("test-model", 512).unwrap();

        // Different target_dims should trigger reindex
        let needs = db.needs_full_reindex("test-model", 256).unwrap();
        assert!(needs, "Target dims change should trigger reindex");
    }

    #[test]
    fn test_index_metadata_persistence() {
        let (_tmp, db) = temp_workspace();
        db.store("s1", "user", "test content").unwrap();
        db.sync("test-model", 512).unwrap();

        // Load metadata
        let meta = db.get_index_metadata().unwrap();
        assert!(meta.is_some());
        let meta = meta.unwrap();
        assert_eq!(meta.model, "test-model");
        assert_eq!(meta.target_dims, 512);
        assert_eq!(meta.schema_version, 1);
    }
}
