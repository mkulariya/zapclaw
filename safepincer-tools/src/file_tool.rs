use anyhow::{Context, Result};
use async_trait::async_trait;
use safepincer_core::agent::Tool;
use safepincer_core::confiner::Confiner;
use serde::Deserialize;
use std::sync::Arc;

/// Workspace-confined file operations tool.
///
/// Security properties:
/// - ALL paths validated through Confiner (no escape possible)
/// - NO delete operations (security by design)
/// - Supports: read, write, append, list
/// - Creates parent directories automatically for write/append
pub struct FileTool {
    confiner: Arc<Confiner>,
}

#[derive(Deserialize)]
struct FileArgs {
    operation: String,
    path: String,
    #[serde(default)]
    content: String,
}

impl FileTool {
    pub fn new(confiner: Arc<Confiner>) -> Self {
        Self { confiner }
    }

    fn do_read(&self, path: &str) -> Result<String> {
        let validated = self.confiner.validate_file(std::path::Path::new(path))?;
        std::fs::read_to_string(&validated)
            .with_context(|| format!("Failed to read file: {}", validated.display()))
    }

    fn do_write(&self, path: &str, content: &str) -> Result<String> {
        let validated = self.confiner.validate_file(std::path::Path::new(path))?;

        // Create parent directories if needed
        if let Some(parent) = validated.parent() {
            if !parent.exists() {
                // Validate parent is within workspace before creating
                self.confiner.validate_dir(parent)?;
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
            }
        }

        std::fs::write(&validated, content)
            .with_context(|| format!("Failed to write file: {}", validated.display()))?;

        Ok(format!("Written {} bytes to {}", content.len(), path))
    }

    fn do_append(&self, path: &str, content: &str) -> Result<String> {
        let validated = self.confiner.validate_file(std::path::Path::new(path))?;

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&validated)
            .with_context(|| format!("Failed to open file for append: {}", validated.display()))?;

        file.write_all(content.as_bytes())
            .with_context(|| format!("Failed to append to file: {}", validated.display()))?;

        Ok(format!("Appended {} bytes to {}", content.len(), path))
    }

    fn do_list(&self, path: &str) -> Result<String> {
        let validated = self.confiner.validate_dir(std::path::Path::new(path))?;

        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&validated)
            .with_context(|| format!("Failed to list directory: {}", validated.display()))?
        {
            let entry = entry?;
            let file_type = if entry.file_type()?.is_dir() { "dir" } else { "file" };
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            entries.push(format!(
                "{} {} ({} bytes)",
                file_type,
                entry.file_name().to_string_lossy(),
                size
            ));
        }

        if entries.is_empty() {
            Ok("Directory is empty".to_string())
        } else {
            Ok(entries.join("\n"))
        }
    }
}

#[async_trait]
impl Tool for FileTool {
    fn name(&self) -> &str {
        "file_ops"
    }

    fn description(&self) -> &str {
        "Read, write, append, or list files within the workspace directory. \
         Supports operations: 'read', 'write', 'append', 'list'. \
         All operations are confined to the workspace — no access outside it. \
         Delete operations are not supported for security reasons."
    }

    fn requires_confirmation(&self) -> bool {
        false // File ops within workspace are safe
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": ["read", "write", "append", "list"],
                    "description": "The file operation to perform"
                },
                "path": {
                    "type": "string",
                    "description": "File or directory path (relative to workspace)"
                },
                "content": {
                    "type": "string",
                    "description": "Content to write or append (required for write/append)"
                }
            },
            "required": ["operation", "path"]
        })
    }

    async fn execute(&self, arguments: &str) -> Result<String> {
        let args: FileArgs = serde_json::from_str(arguments)
            .context("Invalid file tool arguments")?;

        match args.operation.as_str() {
            "read" => self.do_read(&args.path),
            "write" => self.do_write(&args.path, &args.content),
            "append" => self.do_append(&args.path, &args.content),
            "list" => self.do_list(&args.path),
            other => anyhow::bail!(
                "Unknown operation: '{}'. Supported: read, write, append, list",
                other
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn setup() -> (tempfile::TempDir, FileTool) {
        let tmp = tempdir().unwrap();
        let confiner = Arc::new(Confiner::new(tmp.path()).unwrap());
        let tool = FileTool::new(confiner);
        (tmp, tool)
    }

    #[tokio::test]
    async fn test_write_and_read() {
        let (_tmp, tool) = setup();
        let filename = "test.txt";

        // Write
        let args = serde_json::json!({
            "operation": "write",
            "path": filename,
            "content": "Hello, SafePincer!"
        });
        let result = tool.execute(&args.to_string()).await;
        assert!(result.is_ok());

        // Read
        let args = serde_json::json!({
            "operation": "read",
            "path": filename
        });
        let result = tool.execute(&args.to_string()).await.unwrap();
        assert_eq!(result, "Hello, SafePincer!");
    }

    #[tokio::test]
    async fn test_append() {
        let (_tmp, tool) = setup();
        let filename = "append_test.txt";

        // Write initial
        let args = serde_json::json!({"operation": "write", "path": filename, "content": "line1\n"});
        tool.execute(&args.to_string()).await.unwrap();

        // Append
        let args = serde_json::json!({"operation": "append", "path": filename, "content": "line2\n"});
        tool.execute(&args.to_string()).await.unwrap();

        // Read
        let args = serde_json::json!({"operation": "read", "path": filename});
        let result = tool.execute(&args.to_string()).await.unwrap();
        assert_eq!(result, "line1\nline2\n");
    }

    #[tokio::test]
    async fn test_list_directory() {
        let (tmp, tool) = setup();

        // Create some files
        std::fs::write(tmp.path().join("a.txt"), "content").unwrap();
        std::fs::write(tmp.path().join("b.txt"), "content").unwrap();

        let args = serde_json::json!({"operation": "list", "path": "."});
        let result = tool.execute(&args.to_string()).await.unwrap();
        assert!(result.contains("a.txt"));
        assert!(result.contains("b.txt"));
    }

    #[tokio::test]
    async fn test_path_escape_blocked() {
        let (_tmp, tool) = setup();

        let args = serde_json::json!({"operation": "read", "path": "/etc/passwd"});
        let result = tool.execute(&args.to_string()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_operation() {
        let (_tmp, tool) = setup();

        let args = serde_json::json!({"operation": "delete", "path": "test.txt"});
        let result = tool.execute(&args.to_string()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown operation"));
    }
}
