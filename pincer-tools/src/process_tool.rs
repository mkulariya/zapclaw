use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

use pincer_core::agent::Tool;
use pincer_core::confiner::Confiner;

/// Background process manager — manages long-running exec sessions.
///
/// Supports: start (background exec), list, output (read stdout/stderr),
/// send (stdin), kill.
pub struct ProcessTool {
    confiner: Confiner,
    processes: Arc<tokio::sync::Mutex<HashMap<String, ProcessEntry>>>,
}

struct ProcessEntry {
    id: String,
    command: String,
    child: tokio::process::Child,
    started_at: String,
    _output_buffer: Vec<String>,
}

#[derive(Deserialize)]
struct ProcessArgs {
    action: String,
    /// Command to run (for "start" action)
    command: Option<String>,
    /// Process ID (for "output", "send", "kill" actions)
    process_id: Option<String>,
    /// Input to send to stdin (for "send" action)
    input: Option<String>,
    /// Max output lines to return (for "output" action)
    tail: Option<usize>,
}

impl ProcessTool {
    pub fn new(confiner: Confiner) -> Self {
        Self {
            confiner,
            processes: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl Tool for ProcessTool {
    fn name(&self) -> &str {
        "process"
    }

    fn description(&self) -> &str {
        "Manage background exec sessions (start, list, output, send, kill)"
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["start", "list", "output", "send", "kill"],
                    "description": "Action: start (launch background), list (show running), output (read stdout), send (send stdin), kill (terminate)"
                },
                "command": {
                    "type": "string",
                    "description": "Shell command to run in background (for 'start' action)"
                },
                "process_id": {
                    "type": "string",
                    "description": "Process ID (for 'output', 'send', 'kill' actions)"
                },
                "input": {
                    "type": "string",
                    "description": "Input to send to stdin (for 'send' action)"
                },
                "tail": {
                    "type": "integer",
                    "description": "Number of output lines to return (default: 50)"
                }
            },
            "required": ["action"]
        })
    }



    fn requires_confirmation(&self) -> bool {
        true
    }

    async fn execute(&self, args_json: &str) -> Result<String> {
        let args: ProcessArgs = serde_json::from_str(args_json)
            .context("Invalid process arguments")?;

        match args.action.as_str() {
            "start" => {
                let command = args.command
                    .ok_or_else(|| anyhow::anyhow!("'command' required for start action"))?;

                let workspace = self.confiner.workspace_root().to_string_lossy().to_string();

                let child = tokio::process::Command::new("sh")
                    .args(["-c", &command])
                    .current_dir(&workspace)
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .stdin(std::process::Stdio::piped())
                    .spawn()
                    .with_context(|| format!("Failed to start process: {}", command))?;

                let id = format!("proc_{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("0"));
                let started_at = chrono::Utc::now().format("%H:%M:%S UTC").to_string();

                let entry = ProcessEntry {
                    id: id.clone(),
                    command: command.clone(),
                    child,
                    started_at,
                    _output_buffer: Vec::new(),
                };

                let mut procs = self.processes.lock().await;
                procs.insert(id.clone(), entry);

                Ok(format!("✅ Started background process\nID: {}\nCommand: {}", id, command))
            }

            "list" => {
                let procs = self.processes.lock().await;

                if procs.is_empty() {
                    return Ok("No background processes running.".to_string());
                }

                let mut lines = vec!["Background processes:".to_string()];
                for entry in procs.values() {
                    let status = if entry.child.id().is_some() { "running" } else { "unknown" };
                    lines.push(format!(
                        "  {} | {} | started {} | {}",
                        entry.id, status, entry.started_at, entry.command
                    ));
                }

                Ok(lines.join("\n"))
            }

            "output" => {
                let process_id = args.process_id
                    .ok_or_else(|| anyhow::anyhow!("'process_id' required for output action"))?;

                let mut procs = self.processes.lock().await;
                let entry = procs.get_mut(&process_id)
                    .ok_or_else(|| anyhow::anyhow!("Process not found: {}", process_id))?;

                // Try to read available output
                let tail = args.tail.unwrap_or(50);

                // Check if process finished
                match entry.child.try_wait() {
                    Ok(Some(status)) => {
                        let mut output = String::new();

                        if let Some(stdout) = entry.child.stdout.as_mut() {
                            use tokio::io::AsyncReadExt;
                            let mut buf = Vec::new();
                            let _ = stdout.read_to_end(&mut buf).await;
                            output.push_str(&String::from_utf8_lossy(&buf));
                        }

                        let lines: Vec<&str> = output.lines().collect();
                        let start = lines.len().saturating_sub(tail);
                        let tail_output = lines[start..].join("\n");

                        Ok(format!(
                            "Process {} exited with status: {}\n\n{}",
                            process_id, status, tail_output
                        ))
                    }
                    Ok(None) => {
                        Ok(format!("Process {} is still running. Use 'output' again later.", process_id))
                    }
                    Err(e) => {
                        Ok(format!("Error checking process {}: {}", process_id, e))
                    }
                }
            }

            "send" => {
                let process_id = args.process_id
                    .ok_or_else(|| anyhow::anyhow!("'process_id' required for send action"))?;
                let input = args.input
                    .ok_or_else(|| anyhow::anyhow!("'input' required for send action"))?;

                let mut procs = self.processes.lock().await;
                let entry = procs.get_mut(&process_id)
                    .ok_or_else(|| anyhow::anyhow!("Process not found: {}", process_id))?;

                if let Some(stdin) = entry.child.stdin.as_mut() {
                    use tokio::io::AsyncWriteExt;
                    stdin.write_all(input.as_bytes()).await?;
                    stdin.write_all(b"\n").await?;
                    Ok(format!("Sent input to process {}", process_id))
                } else {
                    anyhow::bail!("Process {} stdin not available", process_id)
                }
            }

            "kill" => {
                let process_id = args.process_id
                    .ok_or_else(|| anyhow::anyhow!("'process_id' required for kill action"))?;

                let mut procs = self.processes.lock().await;
                if let Some(mut entry) = procs.remove(&process_id) {
                    let _ = entry.child.kill().await;
                    Ok(format!("Killed process {}", process_id))
                } else {
                    anyhow::bail!("Process not found: {}", process_id)
                }
            }

            _ => anyhow::bail!("Unknown action: {}. Use: start, list, output, send, kill", args.action),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_name() {
        let confiner = Confiner::new(std::env::temp_dir().as_path()).unwrap();
        let tool = ProcessTool::new(confiner);
        assert_eq!(tool.name(), "process");
        assert!(tool.requires_confirmation());
    }
}
