use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::sync::Arc;

use safepincer_core::agent::Tool;
use safepincer_core::memory::MemoryDb;

/// Memory search tool — semantically search MEMORY.md + memory/*.md.
///
/// OpenClaw parity: mandatory recall step before answering about prior work.
pub struct MemorySearchTool {
    memory: Arc<MemoryDb>,
}

#[derive(Deserialize)]
struct MemorySearchArgs {
    query: String,
    #[serde(default = "default_max_results")]
    max_results: usize,
    #[serde(default)]
    min_score: f32,
}

fn default_max_results() -> usize { 10 }

impl MemorySearchTool {
    pub fn new(memory: Arc<MemoryDb>) -> Self {
        Self { memory }
    }
}

#[async_trait]
impl Tool for MemorySearchTool {
    fn name(&self) -> &str { "memory_search" }

    fn description(&self) -> &str {
        "Mandatory recall step: search MEMORY.md + memory/*.md before answering questions about prior work, decisions, dates, people, preferences, or todos; returns top snippets with path + lines."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query"
                },
                "max_results": {
                    "type": "integer",
                    "description": "Max results to return (default: 10)"
                },
                "min_score": {
                    "type": "number",
                    "description": "Minimum relevance score (default: 0)"
                }
            },
            "required": ["query"]
        })
    }



    fn requires_confirmation(&self) -> bool { false }

    async fn execute(&self, args_json: &str) -> Result<String> {
        let args: MemorySearchArgs = serde_json::from_str(args_json)
            .context("Invalid memory_search arguments")?;

        let results = self.memory.search(&args.query, args.max_results, args.min_score)?;

        if results.is_empty() {
            return Ok("No memory results found for this query.".to_string());
        }

        let mut output = Vec::new();
        for r in &results {
            let citation = r.citation.as_deref().unwrap_or(&r.path);
            output.push(format!(
                "--- Source: {} (score: {:.2}) ---\n{}",
                citation, r.score, r.snippet
            ));
        }

        Ok(output.join("\n\n"))
    }
}

/// Memory get tool — read specific lines from MEMORY.md or memory/*.md.
///
/// Use after memory_search to pull only the needed lines.
pub struct MemoryGetTool {
    memory: Arc<MemoryDb>,
}

#[derive(Deserialize)]
struct MemoryGetArgs {
    path: String,
    from: Option<usize>,
    lines: Option<usize>,
}

impl MemoryGetTool {
    pub fn new(memory: Arc<MemoryDb>) -> Self {
        Self { memory }
    }
}

#[async_trait]
impl Tool for MemoryGetTool {
    fn name(&self) -> &str { "memory_get" }

    fn description(&self) -> &str {
        "Read specific lines from MEMORY.md or memory/*.md; use after memory_search to pull only needed content."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path within workspace (e.g. 'MEMORY.md' or 'memory/2026-02-14.md')"
                },
                "from": {
                    "type": "integer",
                    "description": "Starting line number (1-indexed, optional)"
                },
                "lines": {
                    "type": "integer",
                    "description": "Number of lines to read (optional, defaults to all)"
                }
            },
            "required": ["path"]
        })
    }



    fn requires_confirmation(&self) -> bool { false }

    async fn execute(&self, args_json: &str) -> Result<String> {
        let args: MemoryGetArgs = serde_json::from_str(args_json)
            .context("Invalid memory_get arguments")?;

        self.memory.read_file(&args.path, args.from, args.lines)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_search_tool_name() {
        let mem = Arc::new(MemoryDb::in_memory().unwrap());
        let tool = MemorySearchTool::new(mem);
        assert_eq!(tool.name(), "memory_search");
    }

    #[test]
    fn test_memory_get_tool_name() {
        let mem = Arc::new(MemoryDb::in_memory().unwrap());
        let tool = MemoryGetTool::new(mem);
        assert_eq!(tool.name(), "memory_get");
    }
}
