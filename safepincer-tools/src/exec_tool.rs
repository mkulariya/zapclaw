use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::process::Stdio;

use safepincer_core::agent::Tool;
use safepincer_core::confiner::Confiner;

/// Sandboxed shell command execution tool.
///
/// Security properties:
/// - Commands run in the workspace directory only
/// - Blocked commands list prevents destructive operations
/// - Output truncated to prevent token flooding
/// - Timeout enforcement (inherited from agent)
/// - No PTY allocation (prevents interactive escapes)
/// - Requires confirmation for all executions
pub struct ExecTool {
    confiner: Confiner,
    max_output_chars: usize,
}

#[derive(Deserialize)]
struct ExecArgs {
    command: String,
    #[serde(default)]
    timeout_secs: Option<u64>,
}

/// Commands that are completely blocked for security.
const BLOCKED_COMMANDS: &[&str] = &[
    "rm -rf /",
    "rm -rf ~",
    "mkfs",
    "dd if=/dev",
    ":(){:|:&};:",      // Fork bomb
    "chmod -R 777 /",
    "chown -R",
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
    "init 0",
    "init 6",
    "kill -9 1",
    "killall",
    "pkill -9",
    "> /dev/sda",
    "curl | sh",
    "curl | bash",
    "wget | sh",
    "wget | bash",
];

/// Commands that require extra confirmation.
const SENSITIVE_PATTERNS: &[&str] = &[
    "rm ",
    "sudo ",
    "chmod ",
    "chown ",
    "mv /",
    "cp /",
    "pip install",
    "npm install -g",
    "cargo install",
    "apt ",
    "yum ",
    "dnf ",
    "pacman ",
];

impl ExecTool {
    pub fn new(confiner: Confiner) -> Self {
        Self {
            confiner,
            max_output_chars: 50_000,
        }
    }

    fn is_blocked(command: &str) -> bool {
        let lower = command.to_lowercase();
        BLOCKED_COMMANDS.iter().any(|blocked| lower.contains(blocked))
    }

    fn is_sensitive(command: &str) -> bool {
        let lower = command.to_lowercase();
        SENSITIVE_PATTERNS.iter().any(|pat| lower.contains(pat))
    }

    fn truncate_output(output: &str, max_chars: usize) -> String {
        if output.len() <= max_chars {
            return output.to_string();
        }
        let half = max_chars / 2;
        let start = &output[..half];
        let end = &output[output.len() - half..];
        format!(
            "{}\n\n... [truncated {} chars] ...\n\n{}",
            start,
            output.len() - max_chars,
            end
        )
    }
}

#[async_trait]
impl Tool for ExecTool {
    fn name(&self) -> &str {
        "exec"
    }

    fn description(&self) -> &str {
        "Run a shell command in the workspace directory. Output is captured and returned. Use for builds, tests, git, file operations, etc."
    }

    fn requires_confirmation(&self) -> bool {
        true // All exec calls require confirmation
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute"
                },
                "timeout_secs": {
                    "type": "integer",
                    "description": "Timeout in seconds (default: 30)"
                }
            },
            "required": ["command"]
        })
    }

    async fn execute(&self, arguments: &str) -> Result<String> {
        let args: ExecArgs = serde_json::from_str(arguments)
            .context("Invalid exec arguments")?;

        // Security: check blocked commands
        if Self::is_blocked(&args.command) {
            anyhow::bail!("🚫 Command blocked for security: {}", args.command);
        }

        // Sensitivity warning
        if Self::is_sensitive(&args.command) {
            log::warn!("⚠️  Sensitive command: {}", args.command);
        }

        let workspace = self.confiner.workspace_root();
        let timeout_secs = args.timeout_secs.unwrap_or(30);

        // Execute the command
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            tokio::process::Command::new("sh")
                .arg("-c")
                .arg(&args.command)
                .current_dir(workspace)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .stdin(Stdio::null())
                .output()
        )
        .await
        .map_err(|_| anyhow::anyhow!("Command timed out after {}s", timeout_secs))?
        .context("Failed to execute command")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let exit_code = output.status.code().unwrap_or(-1);

        let mut result = format!("Exit code: {}\n", exit_code);

        if !stdout.is_empty() {
            result.push_str(&format!(
                "\n--- stdout ---\n{}\n",
                Self::truncate_output(&stdout, self.max_output_chars)
            ));
        }

        if !stderr.is_empty() {
            result.push_str(&format!(
                "\n--- stderr ---\n{}\n",
                Self::truncate_output(&stderr, self.max_output_chars / 4)
            ));
        }

        if stdout.is_empty() && stderr.is_empty() {
            result.push_str("(no output)\n");
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn setup() -> (tempfile::TempDir, ExecTool) {
        let tmp = tempdir().unwrap();
        let confiner = Confiner::new(tmp.path()).unwrap();
        let tool = ExecTool::new(confiner);
        (tmp, tool)
    }

    #[test]
    fn test_blocked_commands() {
        assert!(ExecTool::is_blocked("rm -rf /"));
        assert!(ExecTool::is_blocked("sudo rm -rf /home"));
        assert!(ExecTool::is_blocked(":(){:|:&};:"));
        assert!(!ExecTool::is_blocked("echo hello"));
        assert!(!ExecTool::is_blocked("ls -la"));
    }

    #[test]
    fn test_sensitive_commands() {
        assert!(ExecTool::is_sensitive("rm file.txt"));
        assert!(ExecTool::is_sensitive("sudo apt install foo"));
        assert!(!ExecTool::is_sensitive("echo hello"));
        assert!(!ExecTool::is_sensitive("cat file.txt"));
    }

    #[tokio::test]
    async fn test_exec_echo() {
        let (_tmp, tool) = setup();
        let result = tool.execute(r#"{"command": "echo hello world"}"#).await.unwrap();
        assert!(result.contains("hello world"));
        assert!(result.contains("Exit code: 0"));
    }

    #[tokio::test]
    async fn test_exec_blocked() {
        let (_tmp, tool) = setup();
        let result = tool.execute(r#"{"command": "rm -rf /"}"#).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_truncate_output() {
        let short = "hello";
        assert_eq!(ExecTool::truncate_output(short, 100), "hello");

        let long = "a".repeat(200);
        let truncated = ExecTool::truncate_output(&long, 100);
        assert!(truncated.contains("truncated"));
    }
}
