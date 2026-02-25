//! Session persistence — JSONL transcript read/write.
//!
//! Matches OpenClaw's session management:
//! - JSONL transcript files per session
//! - Session metadata store (sessions.json)
//! - Load/resume previous sessions

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::llm::ChatMessage;

// ── Types ───────────────────────────────────────────────────────────────

/// Session metadata stored in sessions.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMeta {
    pub id: String,
    pub created_at: String,
    pub updated_at: String,
    pub model: String,
    pub total_tokens: usize,
    pub compaction_count: usize,
    pub message_count: usize,
}

/// A single entry in the JSONL transcript.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptEntry {
    pub timestamp: String,
    pub role: String, // "header", "system", "user", "assistant", "tool"
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<crate::llm::ToolCall>>,
}

// ── SessionStore ────────────────────────────────────────────────────────

/// Session store — manages JSONL transcripts and session metadata.
pub struct SessionStore {
    workspace: PathBuf,
    /// Per-session write locks. Serialises concurrent writes to the same JSONL file
    /// (e.g. two inbound API requests hitting the same session simultaneously).
    /// Different sessions can still write concurrently — only same-session writes are serialised.
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl SessionStore {
    pub fn new(workspace: &Path) -> Self {
        Self {
            workspace: workspace.to_path_buf(),
            locks: Mutex::new(HashMap::new()),
        }
    }

    /// Return (creating if needed) the per-session write mutex.
    fn session_lock(&self, session_id: &str) -> Arc<Mutex<()>> {
        self.locks
            .lock()
            .unwrap()
            .entry(session_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn sessions_dir(&self) -> PathBuf {
        self.workspace.join(".sessions")
    }

    fn session_file(&self, session_id: &str) -> PathBuf {
        self.sessions_dir().join(format!("{}.jsonl", session_id))
    }

    fn meta_file(&self) -> PathBuf {
        self.sessions_dir().join("sessions.json")
    }

    /// Ensure sessions directory exists.
    fn ensure_dir(&self) -> Result<()> {
        let dir = self.sessions_dir();
        if !dir.exists() {
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("Failed to create sessions dir: {}", dir.display()))?;
        }
        Ok(())
    }

    /// Initialize a new session, writing the header entry.
    pub fn create_session(&self, session_id: &str, model: &str) -> Result<()> {
        self.ensure_dir()?;

        let entry = TranscriptEntry {
            timestamp: Utc::now().to_rfc3339(),
            role: "header".to_string(),
            content: format!("Session {} started", session_id),
            tool_call_id: None,
            tool_name: None,
            tool_calls: None,
        };
        self.append_entry(session_id, &entry)?;

        // Update meta
        let mut metas = self.list_sessions()?;
        metas.push(SessionMeta {
            id: session_id.to_string(),
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            model: model.to_string(),
            total_tokens: 0,
            compaction_count: 0,
            message_count: 0,
        });
        self.save_metas(&metas)?;
        Ok(())
    }

    /// Append a transcript entry to the session JSONL file.
    pub fn append_entry(&self, session_id: &str, entry: &TranscriptEntry) -> Result<()> {
        use std::io::Write;
        self.ensure_dir()?;
        let path = self.session_file(session_id);
        let line = serde_json::to_string(entry)? + "\n";
        let lock = self.session_lock(session_id);
        let _guard = lock.lock().unwrap();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        file.write_all(line.as_bytes())?;
        Ok(())
    }

    /// Rewrite the session JSONL file with a new set of messages, preserving the header entry.
    ///
    /// Used after conversation compaction to persist the compacted history.
    pub fn rewrite_session_messages(&self, session_id: &str, messages: &[ChatMessage]) -> Result<()> {
        use std::io::Write;
        let lock = self.session_lock(session_id);
        let _guard = lock.lock().unwrap();
        let path = self.session_file(session_id);

        // Preserve the original header line if it exists.
        let header_line: String = if path.exists() {
            let existing = std::fs::read_to_string(&path)?;
            existing
                .lines()
                .find(|l| {
                    serde_json::from_str::<TranscriptEntry>(l)
                        .map(|e| e.role == "header")
                        .unwrap_or(false)
                })
                .map(|l| l.to_string())
                .unwrap_or_else(|| {
                    let e = TranscriptEntry {
                        timestamp: Utc::now().to_rfc3339(),
                        role: "header".to_string(),
                        content: format!("Session {} (compacted)", session_id),
                        tool_call_id: None,
                        tool_name: None,
                        tool_calls: None,
                    };
                    serde_json::to_string(&e).unwrap()
                })
        } else {
            let e = TranscriptEntry {
                timestamp: Utc::now().to_rfc3339(),
                role: "header".to_string(),
                content: format!("Session {}", session_id),
                tool_call_id: None,
                tool_name: None,
                tool_calls: None,
            };
            serde_json::to_string(&e).unwrap()
        };

        let mut file = std::fs::File::create(&path)?;
        writeln!(file, "{}", header_line)?;
        for msg in messages {
            let entry = TranscriptEntry {
                timestamp: Utc::now().to_rfc3339(),
                role: msg.role.clone(),
                content: msg.content.clone(),
                tool_call_id: msg.tool_call_id.clone(),
                tool_name: None,
                tool_calls: msg.tool_calls.clone(),
            };
            writeln!(file, "{}", serde_json::to_string(&entry)?)?;
        }
        Ok(())
    }

    /// Append a ChatMessage as a transcript entry.
    pub fn append_message(&self, session_id: &str, msg: &ChatMessage) -> Result<()> {
        let entry = TranscriptEntry {
            timestamp: Utc::now().to_rfc3339(),
            role: msg.role.clone(),
            content: msg.content.clone(),
            tool_call_id: msg.tool_call_id.clone(),
            tool_name: None,
            tool_calls: msg.tool_calls.clone(),
        };
        self.append_entry(session_id, &entry)
    }

    /// Load all messages from a session JSONL file.
    ///
    /// Repairs truncated/malformed last lines from process crashes: if the last
    /// non-empty line fails to parse, it is discarded with a warning rather than
    /// failing the load. Any other malformed line is still a hard error.
    pub fn load_session_messages(&self, session_id: &str) -> Result<Vec<ChatMessage>> {
        let path = self.session_file(session_id);
        if !path.exists() {
            anyhow::bail!("Session not found: {}", session_id);
        }
        let content = std::fs::read_to_string(&path)?;

        // Collect non-empty lines with their original indices for repair detection.
        let content_lines: Vec<(usize, &str)> = content
            .lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty())
            .collect();

        let last_idx = content_lines.last().map(|(i, _)| *i);

        let mut messages = Vec::new();
        for (i, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: TranscriptEntry = match serde_json::from_str(line) {
                Ok(e) => e,
                Err(e) => {
                    if Some(i) == last_idx {
                        // Last line truncated by a crash — discard and continue.
                        log::warn!(
                            "Discarding malformed last JSONL line in session '{}' (likely truncated by crash): {}",
                            session_id, e
                        );
                        continue;
                    }
                    return Err(e).with_context(|| {
                        format!("Failed to parse transcript entry at line {} in session '{}'", i + 1, session_id)
                    });
                }
            };
            // Skip header entries
            if entry.role == "header" {
                continue;
            }
            messages.push(ChatMessage {
                role: entry.role,
                content: entry.content,
                tool_call_id: entry.tool_call_id,
                tool_calls: entry.tool_calls,
                images: None,
            });
        }
        Ok(messages)
    }

    /// List available sessions from sessions.json.
    pub fn list_sessions(&self) -> Result<Vec<SessionMeta>> {
        let path = self.meta_file();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let content = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&content).unwrap_or_default())
    }

    /// Save session metadata list.
    fn save_metas(&self, metas: &[SessionMeta]) -> Result<()> {
        self.ensure_dir()?;
        let json = serde_json::to_string_pretty(metas)?;
        std::fs::write(self.meta_file(), json)?;
        Ok(())
    }

    /// Increment the compaction count for a session.
    pub fn increment_compaction_count(&self, session_id: &str) -> Result<()> {
        let mut metas = self.list_sessions()?;
        if let Some(meta) = metas.iter_mut().find(|m| m.id == session_id) {
            meta.compaction_count += 1;
            meta.updated_at = Utc::now().to_rfc3339();
        }
        self.save_metas(&metas)
    }

    /// Update session metadata (tokens, message count, etc.).
    pub fn update_session_meta(
        &self,
        session_id: &str,
        total_tokens: usize,
        message_count: usize,
    ) -> Result<()> {
        let mut metas = self.list_sessions()?;
        if let Some(meta) = metas.iter_mut().find(|m| m.id == session_id) {
            meta.updated_at = Utc::now().to_rfc3339();
            meta.total_tokens = total_tokens;
            meta.message_count = message_count;
        }
        self.save_metas(&metas)
    }

    /// Check if a session exists.
    pub fn session_exists(&self, session_id: &str) -> bool {
        self.session_file(session_id).exists()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, SessionStore) {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = SessionStore::new(tmp.path());
        (tmp, store)
    }

    #[test]
    fn test_create_and_load_session() {
        let (_tmp, store) = temp_store();
        store.create_session("sess_1", "phi3:mini").unwrap();

        // Append some messages
        let user_msg = ChatMessage {
            role: "user".to_string(),
            content: "Hello!".to_string(),
            tool_call_id: None,
            tool_calls: None,
            images: None,
        };
        store.append_message("sess_1", &user_msg).unwrap();

        let asst_msg = ChatMessage {
            role: "assistant".to_string(),
            content: "Hi there!".to_string(),
            tool_call_id: None,
            tool_calls: None,
            images: None,
        };
        store.append_message("sess_1", &asst_msg).unwrap();

        // Load and verify
        let messages = store.load_session_messages("sess_1").unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].role, "user");
        assert_eq!(messages[0].content, "Hello!");
        assert_eq!(messages[1].role, "assistant");
        assert_eq!(messages[1].content, "Hi there!");
    }

    #[test]
    fn test_list_sessions() {
        let (_tmp, store) = temp_store();
        store.create_session("sess_1", "phi3:mini").unwrap();
        store.create_session("sess_2", "gpt-4o").unwrap();

        let sessions = store.list_sessions().unwrap();
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].id, "sess_1");
        assert_eq!(sessions[1].id, "sess_2");
    }

    #[test]
    fn test_session_meta_update() {
        let (_tmp, store) = temp_store();
        store.create_session("sess_1", "phi3:mini").unwrap();
        store.update_session_meta("sess_1", 5000, 10).unwrap();

        let sessions = store.list_sessions().unwrap();
        assert_eq!(sessions[0].total_tokens, 5000);
        assert_eq!(sessions[0].message_count, 10);
    }

    #[test]
    fn test_nonexistent_session() {
        let (_tmp, store) = temp_store();
        let result = store.load_session_messages("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_session_exists() {
        let (_tmp, store) = temp_store();
        assert!(!store.session_exists("sess_1"));
        store.create_session("sess_1", "phi3:mini").unwrap();
        assert!(store.session_exists("sess_1"));
    }

    #[test]
    fn test_load_session_with_truncated_last_line() {
        use std::io::Write;
        let (tmp, store) = temp_store();
        store.create_session("sess_repair", "phi3:mini").unwrap();

        let user_msg = ChatMessage {
            role: "user".to_string(),
            content: "Hello!".to_string(),
            tool_call_id: None,
            tool_calls: None,
            images: None,
        };
        store.append_message("sess_repair", &user_msg).unwrap();

        // Append a malformed (truncated) last line simulating a crash
        let sessions_dir = tmp.path().join(".sessions");
        let session_file = sessions_dir.join("sess_repair.jsonl");
        let mut file = std::fs::OpenOptions::new().append(true).open(&session_file).unwrap();
        file.write_all(b"{\"timestamp\":\"2026-01-01\",\"role\":\"assistant\",\"content\":\"truncat").unwrap();

        // Should load successfully, discarding the malformed last line
        let messages = store.load_session_messages("sess_repair").unwrap();
        assert_eq!(messages.len(), 1, "malformed last line should be silently discarded");
        assert_eq!(messages[0].content, "Hello!");
    }

    #[test]
    fn test_load_session_middle_line_error_propagates() {
        use std::io::Write;
        let (tmp, store) = temp_store();
        store.create_session("sess_corrupt", "phi3:mini").unwrap();

        let user_msg = ChatMessage {
            role: "user".to_string(),
            content: "msg1".to_string(),
            tool_call_id: None,
            tool_calls: None,
            images: None,
        };
        store.append_message("sess_corrupt", &user_msg).unwrap();

        // Insert corrupt middle line then a valid last line
        let sessions_dir = tmp.path().join(".sessions");
        let session_file = sessions_dir.join("sess_corrupt.jsonl");
        let mut file = std::fs::OpenOptions::new().append(true).open(&session_file).unwrap();
        file.write_all(b"NOT_JSON\n").unwrap();
        file.write_all(b"{\"timestamp\":\"2026-01-01T00:00:00Z\",\"role\":\"user\",\"content\":\"msg2\"}\n").unwrap();

        // Should fail — corrupt line is NOT the last
        let result = store.load_session_messages("sess_corrupt");
        assert!(result.is_err(), "corrupt middle line must return an error");
    }
}
