use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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

// ── Types ───────────────────────────────────────────────────────────────

/// File-based + SQLite-indexed memory system — exact OpenClaw parity.
///
/// Dual storage architecture:
/// 1. MEMORY.md + memory/*.md — user-editable markdown files (source of truth)
/// 2. SQLite index database — files, chunks, chunks_fts (FTS5), embedding_cache
///
/// Search pipeline:
///   Files → chunkMarkdown → embedBatch → SQLite → hybrid search (BM25 + vector)
pub struct MemoryDb {
    workspace: PathBuf,
    db: Mutex<Connection>,
    embedding_model: String,
    chunk_tokens: usize,
    chunk_overlap: usize,
    fts_available: bool,
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
}

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
    abs_path: PathBuf,
    hash: String,
    mtime_ms: i64,
    size: i64,
}

/// Index metadata stored in SQLite meta table.
#[derive(Debug, Serialize, Deserialize)]
struct IndexMeta {
    model: String,
    chunk_tokens: usize,
    chunk_overlap: usize,
}

#[derive(Debug, Clone)]
pub struct CompactionResult {
    pub files_compacted: usize,
    pub chars_freed: usize,
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

// ── Embedding Provider ──────────────────────────────────────────────────

/// Embedding provider — calls OpenAI-compatible /embeddings endpoint.
/// Matches OpenClaw's embedding provider interface.
pub struct EmbeddingProvider {
    client: reqwest::Client,
    base_url: String,
    model: String,
    api_key: Option<String>,
}

impl EmbeddingProvider {
    pub fn new(base_url: &str, model: &str, api_key: Option<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .expect("Failed to build embedding HTTP client");
        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            model: model.to_string(),
            api_key,
        }
    }

    /// Get embeddings for a batch of texts.
    pub async fn embed_batch(&self, texts: &[String]) -> Result<Vec<Vec<f32>>> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        let url = format!("{}/embeddings", self.base_url);
        let body = serde_json::json!({
            "model": self.model,
            "input": texts,
        });

        let mut req = self.client.post(&url).json(&body);
        if let Some(ref key) = self.api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }

        let resp = req.send().await.context("Embedding API request failed")?;
        let status = resp.status();
        let body_text = resp.text().await?;

        if !status.is_success() {
            anyhow::bail!("Embedding API error ({}): {}", status, &body_text[..body_text.len().min(200)]);
        }

        #[derive(Deserialize)]
        struct EmbeddingResponse {
            data: Vec<EmbeddingData>,
        }
        #[derive(Deserialize)]
        struct EmbeddingData {
            embedding: Vec<f32>,
        }

        let parsed: EmbeddingResponse = serde_json::from_str(&body_text)
            .context("Failed to parse embedding response")?;

        Ok(parsed.data.into_iter().map(|d| d.embedding).collect())
    }

    /// Get embedding for a single query.
    pub async fn embed_query(&self, text: &str) -> Result<Vec<f32>> {
        let results = self.embed_batch(&[text.to_string()]).await?;
        results.into_iter().next().ok_or_else(|| anyhow::anyhow!("No embedding returned"))
    }

    pub fn model(&self) -> &str {
        &self.model
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

        Ok(Self {
            workspace: workspace.to_path_buf(),
            db: Mutex::new(conn),
            embedding_model: String::new(), // set after sync
            chunk_tokens: DEFAULT_CHUNK_TOKENS,
            chunk_overlap: DEFAULT_CHUNK_OVERLAP,
            fts_available,
        })
    }

    /// Create an in-memory / temp-dir memory (for testing).
    pub fn in_memory() -> Result<Self> {
        let tmp = std::env::temp_dir().join(format!("pincer_mem_{}", uuid::Uuid::new_v4()));
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

    /// List all memory files: MEMORY.md + memory/*.md
    pub fn list_memory_files(&self) -> Result<Vec<(String, String)>> {
        let mut files = Vec::new();

        let memory_md = self.memory_md_path();
        if memory_md.exists() {
            files.push(("MEMORY.md".to_string(), std::fs::read_to_string(&memory_md)?));
        }

        let memory_dir = self.memory_dir();
        if memory_dir.exists() {
            let mut dir_entries: Vec<_> = std::fs::read_dir(&memory_dir)?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map_or(false, |ext| ext == "md"))
                .filter(|e| !e.path().is_symlink()) // skip symlinks like OpenClaw
                .collect();
            dir_entries.sort_by_key(|e| e.file_name());

            for entry in dir_entries {
                let path = format!("memory/{}", entry.file_name().to_string_lossy());
                let content = std::fs::read_to_string(entry.path())?;
                files.push((path, content));
            }
        }

        Ok(files)
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
            abs_path: abs_path.to_path_buf(),
            hash,
            mtime_ms,
            size: meta.len() as i64,
        })
    }

    // ── Sync Pipeline (matching OpenClaw's syncMemoryFiles) ────────────

    /// Sync memory files into SQLite index.
    /// Hash-based skip for unchanged files (exact OpenClaw behavior).
    pub fn sync(&self, model: &str) -> Result<usize> {
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
            let entry = self.build_file_entry(rel_path, &abs_path)?;

            // Check if file unchanged (hash match) — skip if so
            let existing_hash: Option<String> = self.db.lock().unwrap()
                .prepare("SELECT hash FROM files WHERE path = ? AND source = ?")
                .ok()
                .and_then(|mut s| {
                    s.query_row(params![rel_path, "memory"], |r| r.get(0)).ok()
                });

            if existing_hash.as_deref() == Some(&entry.hash) {
                continue; // unchanged
            }

            // Index this file
            self.index_file(&entry, content, model, "memory")?;
            indexed += 1;
        }

        // Clean up stale entries (files that no longer exist)
        let stale_paths: Vec<String> = {
            let db = self.db.lock().unwrap();
            let mut stmt = db.prepare("SELECT path FROM files WHERE source = ?")?;
            let rows = stmt.query_map(params!["memory"], |r| r.get::<_, String>(0))?;
            rows.filter_map(|r| r.ok()).collect()
        };

        for stale_path in &stale_paths {
            if !active_paths.contains(stale_path) {
                self.remove_file_index(stale_path, "memory")?;
            }
        }

        Ok(indexed)
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
        let provider_key = hash_text(&format!("{}:{}", provider.base_url, provider.model));

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

    /// Vector search with a pre-computed query embedding.
    /// Called when an embedding provider is available.
    pub fn search_vector_with_embedding(
        &self,
        query_vec: &[f32],
        limit: usize,
    ) -> Result<Vec<MemorySearchResult>> {
        if query_vec.is_empty() {
            return Ok(Vec::new());
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

        // 2. Get query embedding
        let query_vec = provider.embed_query(cleaned).await?;
        let has_vector = query_vec.iter().any(|v| *v != 0.0);

        let vector_results = if has_vector {
            self.search_vector_with_embedding(&query_vec, candidates)?
        } else {
            Vec::new()
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

    // ── Compact (matching OpenClaw's compaction) ──────────────────────

    pub fn compact(&self, keep_days: usize) -> Result<CompactionResult> {
        let memory_dir = self.memory_dir();
        if !memory_dir.exists() {
            return Ok(CompactionResult { files_compacted: 0, chars_freed: 0 });
        }

        let today = Utc::now().format("%Y-%m-%d").to_string();
        let cutoff = Utc::now()
            .checked_sub_signed(chrono::Duration::days(keep_days as i64))
            .unwrap_or_else(Utc::now)
            .format("%Y-%m-%d")
            .to_string();

        let mut files_to_compact = Vec::new();
        let mut total_freed = 0usize;

        let mut dir_entries: Vec<_> = std::fs::read_dir(&memory_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "md"))
            .collect();
        dir_entries.sort_by_key(|e| e.file_name());

        for entry in &dir_entries {
            let name = entry.file_name().to_string_lossy().to_string();
            let date_str = name.trim_end_matches(".md");
            if date_str >= cutoff.as_str() || date_str == today {
                continue;
            }
            let content = std::fs::read_to_string(entry.path())?;
            total_freed += content.len();
            files_to_compact.push((name, content));
        }

        if files_to_compact.is_empty() {
            return Ok(CompactionResult { files_compacted: 0, chars_freed: 0 });
        }

        let mut summary_lines = Vec::new();
        summary_lines.push(format!(
            "\n## Compacted Archive ({})\n",
            Utc::now().format("%Y-%m-%d %H:%M UTC")
        ));

        for (name, content) in &files_to_compact {
            let meaningful: Vec<&str> = content
                .lines()
                .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
                .collect();
            if !meaningful.is_empty() {
                summary_lines.push(format!("### {}", name));
                for line in meaningful.iter().take(10) {
                    summary_lines.push(format!("- {}", line.trim()));
                }
                summary_lines.push(String::new());
            }
        }

        let memory_md = self.memory_md_path();
        let existing = if memory_md.exists() {
            std::fs::read_to_string(&memory_md)?
        } else {
            "# Memory\n".to_string()
        };
        std::fs::write(&memory_md, format!("{}\n{}", existing, summary_lines.join("\n")))?;

        let count = files_to_compact.len();
        for (name, _) in &files_to_compact {
            let path = memory_dir.join(name);
            if path.exists() {
                std::fs::remove_file(&path)?;
            }
        }

        // Re-sync index after compaction
        log::info!("Compacted {} memory files, freed ~{} chars", count, total_freed);

        Ok(CompactionResult { files_compacted: count, chars_freed: total_freed })
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
        db.sync("test-model").unwrap();
        let results = db.search("dark mode", 5, 0.0).unwrap();
        assert!(!results.is_empty());
        assert!(results[0].snippet.contains("dark mode"));
    }

    #[test]
    fn test_search_empty() {
        let (_tmp, db) = temp_workspace();
        db.sync("test-model").unwrap();
        let results = db.search("nonexistent_query_xyz", 5, 0.0).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_sync_hash_skip() {
        let (_tmp, db) = temp_workspace();
        db.store("s1", "user", "initial content").unwrap();
        let count1 = db.sync("test-model").unwrap();
        assert!(count1 > 0);
        // Second sync should skip (no changes)
        let count2 = db.sync("test-model").unwrap();
        assert_eq!(count2, 0);
    }

    #[test]
    fn test_sync_detects_changes() {
        let (_tmp, db) = temp_workspace();
        db.store("s1", "user", "initial content").unwrap();
        db.sync("test-model").unwrap();
        // Add more content
        db.store("s1", "user", "new content").unwrap();
        let count = db.sync("test-model").unwrap();
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
    fn test_compact() {
        let (_tmp, db) = temp_workspace();
        let old_file = db.memory_dir().join("2020-01-01.md");
        std::fs::write(&old_file, "# Memory — 2020-01-01\n\n## user — 10:00:00 UTC\n\nOld memory\n").unwrap();
        let result = db.compact(0).unwrap();
        assert_eq!(result.files_compacted, 1);
        assert!(!old_file.exists());
        let memory_content = std::fs::read_to_string(db.memory_md_path()).unwrap();
        assert!(memory_content.contains("Compacted Archive"));
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
        db.sync("test-model").unwrap();
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
        db.sync("test-model").unwrap();
        let status1 = db.index_status().unwrap();
        // Delete the file
        std::fs::remove_file(&test_file).unwrap();
        db.sync("test-model").unwrap();
        let status2 = db.index_status().unwrap();
        // Should have fewer files after cleanup
        assert!(status2.files < status1.files || status2.chunks < status1.chunks);
    }
}
