use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::path::Path;
use std::process::Stdio;

use safepincer_core::agent::Tool;
use safepincer_core::confiner::Confiner;

/// Regex/literal pattern search across files in the workspace.
///
/// Security properties:
/// - Only searches within confined workspace
/// - Output truncated to prevent token flooding
/// - No file modification capability
pub struct GrepTool {
    confiner: Confiner,
    max_results: usize,
    max_output_chars: usize,
}

#[derive(Deserialize)]
struct GrepArgs {
    pattern: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    is_regex: Option<bool>,
    #[serde(default)]
    case_insensitive: Option<bool>,
    #[serde(default)]
    include: Option<String>,
}

impl GrepTool {
    pub fn new(confiner: Confiner) -> Self {
        Self {
            confiner,
            max_results: 100,
            max_output_chars: 30_000,
        }
    }
}

#[async_trait]
impl Tool for GrepTool {
    fn name(&self) -> &str {
        "grep"
    }

    fn description(&self) -> &str {
        "Search file contents for a pattern. Returns matching lines with file paths and line numbers. Supports regex and glob filters."
    }

    fn requires_confirmation(&self) -> bool {
        false
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Pattern to search for"
                },
                "path": {
                    "type": "string",
                    "description": "Directory or file to search in (relative to workspace, default: workspace root)"
                },
                "is_regex": {
                    "type": "boolean",
                    "description": "Treat pattern as regex (default: false, literal search)"
                },
                "case_insensitive": {
                    "type": "boolean",
                    "description": "Case-insensitive search (default: false)"
                },
                "include": {
                    "type": "string",
                    "description": "Glob filter for filenames (e.g., '*.rs', '*.py')"
                }
            },
            "required": ["pattern"]
        })
    }

    async fn execute(&self, arguments: &str) -> Result<String> {
        let args: GrepArgs = serde_json::from_str(arguments)
            .context("Invalid grep arguments")?;

        let search_path = if let Some(ref p) = args.path {
            self.confiner.validate_path(Path::new(p))
                .context("Invalid search path")?
        } else {
            self.confiner.workspace_root().to_path_buf()
        };

        // Build grep command
        let mut cmd_args = vec![
            "-rn".to_string(), // recursive, line numbers
            "--color=never".to_string(),
        ];

        if args.is_regex.unwrap_or(false) {
            cmd_args.push("-E".to_string()); // Extended regex
        } else {
            cmd_args.push("-F".to_string()); // Literal/fixed string
        }

        if args.case_insensitive.unwrap_or(false) {
            cmd_args.push("-i".to_string());
        }

        if let Some(ref include) = args.include {
            cmd_args.push(format!("--include={}", include));
        }

        // Skip binary files
        cmd_args.push("-I".to_string());

        cmd_args.push("--".to_string());
        cmd_args.push(args.pattern.clone());
        cmd_args.push(search_path.to_string_lossy().to_string());

        let output = tokio::process::Command::new("grep")
            .args(&cmd_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .output()
            .await
            .context("Failed to run grep")?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        if stdout.is_empty() {
            return Ok(format!("No matches found for pattern: '{}'", args.pattern));
        }

        // Truncate results
        let lines: Vec<&str> = stdout.lines().collect();
        let total = lines.len();
        let shown = total.min(self.max_results);
        let mut result = lines[..shown].join("\n");

        if total > shown {
            result.push_str(&format!("\n\n... ({} more matches not shown)", total - shown));
        }

        // Truncate total output
        if result.len() > self.max_output_chars {
            result = result[..self.max_output_chars].to_string();
            result.push_str("\n\n... (output truncated)");
        }

        Ok(format!("{} matches found:\n\n{}", total, result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_grep_literal() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("test.txt"), "hello world\nfoo bar\nhello again").unwrap();
        let confiner = Confiner::new(tmp.path()).unwrap();
        let tool = GrepTool::new(confiner);

        let result = tool.execute(r#"{"pattern": "hello"}"#).await.unwrap();
        assert!(result.contains("hello world"));
        assert!(result.contains("hello again"));
    }

    #[tokio::test]
    async fn test_grep_no_match() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("test.txt"), "foo bar").unwrap();
        let confiner = Confiner::new(tmp.path()).unwrap();
        let tool = GrepTool::new(confiner);

        let result = tool.execute(r#"{"pattern": "nonexistent"}"#).await.unwrap();
        assert!(result.contains("No matches"));
    }
}
