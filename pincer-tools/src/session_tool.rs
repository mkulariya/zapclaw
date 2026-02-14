use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::sync::Arc;

use pincer_core::agent::Tool;
use pincer_core::memory::MemoryDb;

/// Session info/status tool — show session information, usage, model info.
///
/// Actions:
///   - status: Show current session stats (model, tokens, time)
///   - history: Retrieve conversation history
///   - compact: Trigger manual compaction
pub struct SessionTool {
    memory: Arc<MemoryDb>,
    model_name: String,
    model_aliases: Vec<(String, String)>,
    session_start: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize)]
struct SessionArgs {
    action: String,
    /// Session ID (optional, defaults to current)
    session_id: Option<String>,
    /// Number of history entries to return (for "history")
    limit: Option<usize>,
    /// Days to keep (for "compact", default: 7)
    keep_days: Option<usize>,
}

impl SessionTool {
    pub fn new(memory: Arc<MemoryDb>, model_name: &str, model_aliases: Vec<(String, String)>) -> Self {
        Self {
            memory,
            model_name: model_name.to_string(),
            model_aliases,
            session_start: chrono::Utc::now(),
        }
    }
}

#[async_trait]
impl Tool for SessionTool {
    fn name(&self) -> &str { "session_status" }

    fn description(&self) -> &str {
        "Show session status (model, usage, time), retrieve history, or trigger compaction."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["status", "history", "compact"],
                    "description": "Action: status (show stats), history (get history), compact (trigger compaction)"
                },
                "session_id": {
                    "type": "string",
                    "description": "Session ID (optional, defaults to current)"
                },
                "limit": {
                    "type": "integer",
                    "description": "Number of history entries to return (default: 20)"
                },
                "keep_days": {
                    "type": "integer",
                    "description": "Days of memory to keep during compaction (default: 7)"
                }
            },
            "required": ["action"]
        })
    }



    fn requires_confirmation(&self) -> bool { false }

    async fn execute(&self, args_json: &str) -> Result<String> {
        let args: SessionArgs = serde_json::from_str(args_json)
            .context("Invalid session arguments")?;

        match args.action.as_str() {
            "status" => {
                let now = chrono::Utc::now();
                let uptime = now - self.session_start;
                let memory_tokens = self.memory.total_memory_tokens().unwrap_or(0);
                let memory_chars = self.memory.total_memory_chars().unwrap_or(0);
                let memory_files = self.memory.list_memory_files().unwrap_or_default();

                let mut lines = vec![
                    "📊 Session Status".to_string(),
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".to_string(),
                    format!("  Model:          {}", self.model_name),
                    format!("  Session start:  {}", self.session_start.format("%Y-%m-%d %H:%M:%S UTC")),
                    format!("  Uptime:         {}m {}s", uptime.num_minutes(), uptime.num_seconds() % 60),
                    format!("  Current time:   {}", now.format("%Y-%m-%d %H:%M:%S UTC")),
                    format!("  Memory files:   {}", memory_files.len()),
                    format!("  Memory tokens:  ~{}", memory_tokens),
                    format!("  Memory chars:   {}", memory_chars),
                ];

                if !self.model_aliases.is_empty() {
                    lines.push("  Model aliases:".to_string());
                    for (alias, target) in &self.model_aliases {
                        lines.push(format!("    {} → {}", alias, target));
                    }
                }

                lines.push("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".to_string());
                Ok(lines.join("\n"))
            }

            "history" => {
                let session_id = args.session_id.unwrap_or_else(|| "current".to_string());
                let limit = args.limit.unwrap_or(20);

                let entries = self.memory.retrieve(&session_id)?;
                let start = entries.len().saturating_sub(limit);
                let recent = &entries[start..];

                if recent.is_empty() {
                    return Ok("No history entries found.".to_string());
                }

                let mut lines = vec![format!("Session history (last {} entries):", recent.len())];
                for entry in recent {
                    lines.push(format!("--- {} ---", entry.path));
                    // Show first 10 lines of each entry
                    let preview: Vec<&str> = entry.content.lines().take(10).collect();
                    lines.push(preview.join("\n"));
                }

                Ok(lines.join("\n\n"))
            }

            "compact" => {
                let keep_days = args.keep_days.unwrap_or(7);
                let result = self.memory.compact(keep_days)?;

                if result.files_compacted == 0 {
                    Ok("Nothing to compact — memory is already lean.".to_string())
                } else {
                    Ok(format!(
                        "✅ Compacted {} files, freed ~{} chars (~{} tokens)",
                        result.files_compacted,
                        result.chars_freed,
                        result.chars_freed / 4
                    ))
                }
            }

            _ => anyhow::bail!("Unknown action: {}. Use: status, history, compact", args.action),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_name() {
        let mem = Arc::new(MemoryDb::in_memory().unwrap());
        let tool = SessionTool::new(mem, "phi3:mini", vec![]);
        assert_eq!(tool.name(), "session_status");
        assert!(!tool.requires_confirmation());
    }
}
