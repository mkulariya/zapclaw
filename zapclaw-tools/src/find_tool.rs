use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::path::Path;
use std::process::Stdio;

use zapclaw_core::agent::Tool;
use zapclaw_core::confiner::Confiner;

/// File discovery tool — find files by glob pattern within the workspace.
///
/// Security: Only searches within the confined workspace.
pub struct FindTool {
    confiner: Confiner,
    max_results: usize,
}

#[derive(Deserialize)]
struct FindArgs {
    pattern: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    file_type: Option<String>, // "f" for files, "d" for dirs
    #[serde(default)]
    max_depth: Option<u32>,
}

impl FindTool {
    pub fn new(confiner: Confiner) -> Self {
        Self {
            confiner,
            max_results: 200,
        }
    }
}

#[async_trait]
impl Tool for FindTool {
    fn name(&self) -> &str {
        "find"
    }

    fn description(&self) -> &str {
        "Find files and directories by name/glob pattern within the workspace. Returns matching paths."
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
                    "description": "Glob pattern to match (e.g., '*.rs', 'Cargo.*', 'src/**/*.ts')"
                },
                "path": {
                    "type": "string",
                    "description": "Directory to search in (relative to workspace, default: workspace root)"
                },
                "file_type": {
                    "type": "string",
                    "description": "Type filter: 'f' for files, 'd' for directories (default: all)"
                },
                "max_depth": {
                    "type": "integer",
                    "description": "Maximum directory depth to search (default: unlimited)"
                }
            },
            "required": ["pattern"]
        })
    }

    async fn execute(&self, arguments: &str) -> Result<String> {
        let args: FindArgs = serde_json::from_str(arguments)
            .context("Invalid find arguments")?;

        let search_path = if let Some(ref p) = args.path {
            self.confiner.validate_path(Path::new(p))
                .context("Invalid search path")?
        } else {
            self.confiner.workspace_root().to_path_buf()
        };

        // Build find command
        let mut cmd_args = vec![
            search_path.to_string_lossy().to_string(),
        ];

        if let Some(depth) = args.max_depth {
            cmd_args.push("-maxdepth".to_string());
            cmd_args.push(depth.to_string());
        }

        if let Some(ref ft) = args.file_type {
            cmd_args.push("-type".to_string());
            cmd_args.push(ft.clone());
        }

        cmd_args.push("-name".to_string());
        cmd_args.push(args.pattern.clone());

        // Exclude common noise
        cmd_args.extend([
            "-not".to_string(), "-path".to_string(), "*/.git/*".to_string(),
            "-not".to_string(), "-path".to_string(), "*/target/*".to_string(),
            "-not".to_string(), "-path".to_string(), "*/node_modules/*".to_string(),
        ]);

        let output = tokio::process::Command::new("find")
            .args(&cmd_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null())
            .output()
            .await
            .context("Failed to run find")?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        if stdout.trim().is_empty() {
            return Ok(format!("No files found matching pattern: '{}'", args.pattern));
        }

        let lines: Vec<&str> = stdout.lines().collect();
        let total = lines.len();
        let shown = total.min(self.max_results);
        let mut result = lines[..shown].join("\n");

        if total > shown {
            result.push_str(&format!("\n\n... ({} more not shown)", total - shown));
        }

        Ok(format!("{} results:\n\n{}", total, result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_find_files() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("test.rs"), "fn main() {}").unwrap();
        std::fs::write(tmp.path().join("test.py"), "print()").unwrap();
        std::fs::create_dir_all(tmp.path().join("sub")).unwrap();
        std::fs::write(tmp.path().join("sub/nested.rs"), "// nested").unwrap();

        let confiner = Confiner::new(tmp.path()).unwrap();
        let tool = FindTool::new(confiner);

        let result = tool.execute(r#"{"pattern": "*.rs"}"#).await.unwrap();
        assert!(result.contains("test.rs"));
        assert!(result.contains("nested.rs"));
        assert!(!result.contains("test.py"));
    }

    #[tokio::test]
    async fn test_find_no_results() {
        let tmp = tempdir().unwrap();
        let confiner = Confiner::new(tmp.path()).unwrap();
        let tool = FindTool::new(confiner);

        let result = tool.execute(r#"{"pattern": "*.xyz"}"#).await.unwrap();
        assert!(result.contains("No files found"));
    }
}
