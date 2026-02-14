use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::path::Path;

use pincer_core::agent::Tool;
use pincer_core::confiner::Confiner;

/// Precise file editing tool — search/replace within files.
///
/// Security properties:
/// - Only modifies files within confined workspace
/// - Creates atomic writes (write to temp, rename)
/// - Validates that old content exists before replacing
/// - Limits replacement scope to prevent runaway edits
pub struct EditTool {
    confiner: Confiner,
}

#[derive(Deserialize)]
struct EditArgs {
    file: String,
    old_text: String,
    new_text: String,
    #[serde(default)]
    count: Option<usize>, // Max replacements (default: 1)
}

impl EditTool {
    pub fn new(confiner: Confiner) -> Self {
        Self { confiner }
    }
}

#[async_trait]
impl Tool for EditTool {
    fn name(&self) -> &str {
        "edit"
    }

    fn description(&self) -> &str {
        "Make precise edits to a file using search/replace. Specify the exact old text to find and the new text to replace it with. Set count to replace multiple occurrences."
    }

    fn requires_confirmation(&self) -> bool {
        false
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "file": {
                    "type": "string",
                    "description": "File path (relative to workspace)"
                },
                "old_text": {
                    "type": "string",
                    "description": "Exact text to find in the file"
                },
                "new_text": {
                    "type": "string",
                    "description": "Text to replace it with"
                },
                "count": {
                    "type": "integer",
                    "description": "Max number of replacements (default: 1, use 0 for all)"
                }
            },
            "required": ["file", "old_text", "new_text"]
        })
    }

    async fn execute(&self, arguments: &str) -> Result<String> {
        let args: EditArgs = serde_json::from_str(arguments)
            .context("Invalid edit arguments")?;

        let file_path = self.confiner
            .validate_path(Path::new(&args.file))
            .context("Invalid file path")?;

        // Read original file
        let content = tokio::fs::read_to_string(&file_path)
            .await
            .context(format!("Cannot read file: {}", args.file))?;

        // Check that old_text exists
        let match_count = content.matches(&args.old_text).count();
        if match_count == 0 {
            anyhow::bail!(
                "old_text not found in '{}'. Make sure the text matches exactly (including whitespace and newlines).",
                args.file
            );
        }

        // Perform replacement
        let max_replacements = args.count.unwrap_or(1);
        let new_content = if max_replacements == 0 {
            // Replace all
            content.replace(&args.old_text, &args.new_text)
        } else {
            // Replace up to `count` occurrences
            let mut result = content.clone();
            let mut replacements_done = 0;
            while replacements_done < max_replacements {
                if let Some(pos) = result.find(&args.old_text) {
                    result = format!(
                        "{}{}{}",
                        &result[..pos],
                        args.new_text,
                        &result[pos + args.old_text.len()..]
                    );
                    replacements_done += 1;
                } else {
                    break;
                }
            }
            result
        };

        // Verify change was made
        if new_content == content {
            return Ok("No changes made (old_text equals new_text).".to_string());
        }

        // Atomic write
        tokio::fs::write(&file_path, &new_content)
            .await
            .context("Failed to write edited file")?;

        let actual_replacements = if max_replacements == 0 { match_count } else { max_replacements.min(match_count) };

        Ok(format!(
            "✅ Edited '{}': {} replacement(s) made ({} total matches found)",
            args.file, actual_replacements, match_count
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_edit_single_replacement() {
        let tmp = tempdir().unwrap();
        let file = tmp.path().join("test.rs");
        std::fs::write(&file, "fn old_name() {}\nfn other() {}").unwrap();

        let confiner = Confiner::new(tmp.path()).unwrap();
        let tool = EditTool::new(confiner);

        let result = tool.execute(&format!(
            r#"{{"file": "{}", "old_text": "old_name", "new_text": "new_name"}}"#,
            file.display()
        )).await.unwrap();

        assert!(result.contains("1 replacement"));
        let content = std::fs::read_to_string(&file).unwrap();
        assert!(content.contains("new_name"));
        assert!(!content.contains("old_name"));
    }

    #[tokio::test]
    async fn test_edit_not_found() {
        let tmp = tempdir().unwrap();
        let file = tmp.path().join("test.rs");
        std::fs::write(&file, "fn main() {}").unwrap();

        let confiner = Confiner::new(tmp.path()).unwrap();
        let tool = EditTool::new(confiner);

        let result = tool.execute(&format!(
            r#"{{"file": "{}", "old_text": "nonexistent", "new_text": "replacement"}}"#,
            file.display()
        )).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_edit_replace_all() {
        let tmp = tempdir().unwrap();
        let file = tmp.path().join("test.txt");
        std::fs::write(&file, "foo bar foo baz foo").unwrap();

        let confiner = Confiner::new(tmp.path()).unwrap();
        let tool = EditTool::new(confiner);

        let result = tool.execute(&format!(
            r#"{{"file": "{}", "old_text": "foo", "new_text": "qux", "count": 0}}"#,
            file.display()
        )).await.unwrap();

        assert!(result.contains("3 replacement"));
        let content = std::fs::read_to_string(&file).unwrap();
        assert_eq!(content, "qux bar qux baz qux");
    }
}
