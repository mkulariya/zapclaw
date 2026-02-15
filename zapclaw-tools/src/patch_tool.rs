use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::path::Path;

use zapclaw_core::agent::Tool;
use zapclaw_core::confiner::Confiner;

/// Multi-file unified diff patching tool.
///
/// Accepts a unified diff (patch) string and applies it to files
/// in the workspace. Uses the system `patch` command for reliability.
///
/// Security: Only modifies files within the confined workspace.
pub struct PatchTool {
    confiner: Confiner,
}

#[derive(Deserialize)]
struct PatchArgs {
    /// Unified diff content to apply
    patch: String,
    /// Whether to do a dry run only (check without applying)
    #[serde(default)]
    dry_run: Option<bool>,
}

impl PatchTool {
    pub fn new(confiner: Confiner) -> Self {
        Self { confiner }
    }

    /// Validate that all file paths in the patch are within workspace.
    fn validate_patch_paths(&self, patch: &str) -> Result<()> {
        for line in patch.lines() {
            if let Some(path_str) = line.strip_prefix("+++ ").or_else(|| line.strip_prefix("--- ")) {
                // Strip the a/ or b/ prefix
                let clean_path = path_str
                    .trim()
                    .strip_prefix("b/")
                    .or_else(|| path_str.trim().strip_prefix("a/"))
                    .unwrap_or(path_str.trim());

                // Skip /dev/null (new files)
                if clean_path == "/dev/null" {
                    continue;
                }

                // Validate path is within workspace
                self.confiner.validate_path(Path::new(clean_path))
                    .context(format!("Patch targets file outside workspace: {}", clean_path))?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Tool for PatchTool {
    fn name(&self) -> &str {
        "apply_patch"
    }

    fn description(&self) -> &str {
        "Apply a unified diff patch to one or more files. Provide the patch content in unified diff format. Use dry_run=true to verify without applying."
    }

    fn requires_confirmation(&self) -> bool {
        true
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "patch": {
                    "type": "string",
                    "description": "Unified diff content to apply"
                },
                "dry_run": {
                    "type": "boolean",
                    "description": "If true, check patch without applying (default: false)"
                }
            },
            "required": ["patch"]
        })
    }

    async fn execute(&self, arguments: &str) -> Result<String> {
        let args: PatchArgs = serde_json::from_str(arguments)
            .context("Invalid patch arguments")?;

        // Security: validate all paths in patch
        self.validate_patch_paths(&args.patch)?;

        let workspace = self.confiner.workspace_root();
        let dry_run = args.dry_run.unwrap_or(false);

        let mut cmd_args = vec![
            "-p1".to_string(),          // Strip 1 leading path component
            "--no-backup-if-mismatch".to_string(),
        ];

        if dry_run {
            cmd_args.push("--dry-run".to_string());
        }

        let _output = tokio::process::Command::new("patch")
            .args(&cmd_args)
            .current_dir(workspace)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("Failed to spawn patch command")?
            .wait_with_output()
            .await
            .map_err(|_| {
                // If wait_with_output isn't available, fall back
                anyhow::anyhow!("Failed to run patch command")
            })?;

        // Actually pipe the patch content via stdin
        // Re-run with proper stdin piping
        let mut child = tokio::process::Command::new("patch")
            .args(&cmd_args)
            .current_dir(workspace)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("Failed to spawn patch command")?;

        // Write patch to stdin
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin.write_all(args.patch.as_bytes()).await
                .context("Failed to write patch to stdin")?;
            drop(stdin);
        }

        let output = child.wait_with_output().await
            .context("Patch command failed")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let exit_code = output.status.code().unwrap_or(-1);

        if exit_code == 0 {
            let prefix = if dry_run { "Dry run successful" } else { "Patch applied successfully" };
            Ok(format!("✅ {}:\n{}", prefix, stdout))
        } else {
            let mut msg = format!("❌ Patch failed (exit code {}):\n", exit_code);
            if !stdout.is_empty() {
                msg.push_str(&format!("stdout: {}\n", stdout));
            }
            if !stderr.is_empty() {
                msg.push_str(&format!("stderr: {}\n", stderr));
            }
            Ok(msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_validate_patch_paths_valid() {
        let tmp = tempdir().unwrap();
        let confiner = Confiner::new(tmp.path()).unwrap();
        let tool = PatchTool::new(confiner);

        let patch = "--- a/foo.txt\n+++ b/foo.txt\n@@ -1 +1 @@\n-old\n+new\n";
        assert!(tool.validate_patch_paths(patch).is_ok());
    }

    #[test]
    fn test_validate_patch_paths_devnull() {
        let tmp = tempdir().unwrap();
        let confiner = Confiner::new(tmp.path()).unwrap();
        let tool = PatchTool::new(confiner);

        let patch = "--- /dev/null\n+++ b/new_file.txt\n@@ -0,0 +1 @@\n+new content\n";
        assert!(tool.validate_patch_paths(patch).is_ok());
    }
}
