use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use safepincer_core::agent::Tool;

/// Cron/reminders tool — file-based scheduler with background loop.
///
/// Stores scheduled tasks in cron.json, checked by a lightweight tokio loop.
/// Supports: schedule, list, cancel, trigger.
pub struct CronTool {
    workspace: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronJob {
    pub id: String,
    pub description: String,
    /// ISO 8601 timestamp for when the job should fire
    pub fire_at: String,
    /// Command or message to deliver when job fires
    pub payload: String,
    /// Whether this is a recurring job
    pub recurring: bool,
    /// Recurrence interval in seconds (for recurring jobs)
    pub interval_secs: Option<u64>,
    /// Whether the job has been triggered
    pub triggered: bool,
    /// Creation timestamp
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CronState {
    pub jobs: Vec<CronJob>,
}

#[derive(Deserialize)]
struct CronArgs {
    action: String,
    /// Description for scheduling (for "schedule" action)
    description: Option<String>,
    /// When to fire — ISO 8601 or relative like "in 5m", "in 1h" (for "schedule")
    fire_at: Option<String>,
    /// Payload/message to deliver (for "schedule")
    payload: Option<String>,
    /// Whether recurring (for "schedule")
    recurring: Option<bool>,
    /// Interval in seconds for recurring (for "schedule")
    interval_secs: Option<u64>,
    /// Job ID (for "cancel" action)
    job_id: Option<String>,
}

impl CronTool {
    pub fn new(workspace: &Path) -> Self {
        Self {
            workspace: workspace.to_path_buf(),
        }
    }

    fn cron_path(&self) -> PathBuf {
        self.workspace.join("cron.json")
    }

    fn load_state(&self) -> Result<CronState> {
        let path = self.cron_path();
        if !path.exists() {
            return Ok(CronState::default());
        }
        let content = std::fs::read_to_string(&path)?;
        serde_json::from_str(&content).context("Failed to parse cron.json")
    }

    fn save_state(&self, state: &CronState) -> Result<()> {
        let content = serde_json::to_string_pretty(state)?;
        std::fs::write(self.cron_path(), content)?;
        Ok(())
    }

    /// Parse relative time strings like "in 5m", "in 1h", "in 30s"
    fn parse_fire_at(input: &str) -> Result<String> {
        let trimmed = input.trim().to_lowercase();

        // Try ISO 8601 first
        if chrono::DateTime::parse_from_rfc3339(&trimmed).is_ok() {
            return Ok(trimmed);
        }

        // Parse relative: "in 5m", "in 1h", "in 30s", "in 2d"
        if let Some(relative) = trimmed.strip_prefix("in ") {
            let relative = relative.trim();
            let (num_str, unit) = if relative.ends_with('s') {
                (&relative[..relative.len()-1], "seconds")
            } else if relative.ends_with('m') {
                (&relative[..relative.len()-1], "minutes")
            } else if relative.ends_with('h') {
                (&relative[..relative.len()-1], "hours")
            } else if relative.ends_with('d') {
                (&relative[..relative.len()-1], "days")
            } else {
                anyhow::bail!("Unknown time unit in: {}", input);
            };

            let num: i64 = num_str.parse()
                .with_context(|| format!("Invalid number in: {}", input))?;

            let duration = match unit {
                "seconds" => chrono::Duration::seconds(num),
                "minutes" => chrono::Duration::minutes(num),
                "hours" => chrono::Duration::hours(num),
                "days" => chrono::Duration::days(num),
                _ => unreachable!(),
            };

            let fire_time = chrono::Utc::now() + duration;
            return Ok(fire_time.to_rfc3339());
        }

        anyhow::bail!(
            "Cannot parse fire_at '{}'. Use ISO 8601 (e.g. '2026-02-14T18:00:00Z') or relative (e.g. 'in 5m', 'in 1h')",
            input
        );
    }
}

#[async_trait]
impl Tool for CronTool {
    fn name(&self) -> &str { "cron" }

    fn description(&self) -> &str {
        "Manage cron jobs and reminders (schedule, list, cancel). Use for reminders and recurring tasks."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["schedule", "list", "cancel"],
                    "description": "Action: schedule (create new job), list (show all), cancel (remove job)"
                },
                "description": {
                    "type": "string",
                    "description": "Description of the job/reminder (for 'schedule')"
                },
                "fire_at": {
                    "type": "string",
                    "description": "When to fire — ISO 8601 or relative ('in 5m', 'in 1h', 'in 2d')"
                },
                "payload": {
                    "type": "string",
                    "description": "Message/command to deliver when job fires"
                },
                "recurring": {
                    "type": "boolean",
                    "description": "Whether this repeats (default: false)"
                },
                "interval_secs": {
                    "type": "integer",
                    "description": "Repeat interval in seconds (for recurring jobs)"
                },
                "job_id": {
                    "type": "string",
                    "description": "Job ID (for 'cancel' action)"
                }
            },
            "required": ["action"]
        })
    }



    fn requires_confirmation(&self) -> bool { false }

    async fn execute(&self, args_json: &str) -> Result<String> {
        let args: CronArgs = serde_json::from_str(args_json)
            .context("Invalid cron arguments")?;

        match args.action.as_str() {
            "schedule" => {
                let description = args.description
                    .ok_or_else(|| anyhow::anyhow!("'description' required for schedule"))?;
                let fire_at_input = args.fire_at
                    .ok_or_else(|| anyhow::anyhow!("'fire_at' required for schedule"))?;
                let payload = args.payload
                    .ok_or_else(|| anyhow::anyhow!("'payload' required for schedule"))?;

                let fire_at = Self::parse_fire_at(&fire_at_input)?;
                let id = format!("cron_{}", uuid::Uuid::new_v4().to_string().split('-').next().unwrap_or("0"));

                let job = CronJob {
                    id: id.clone(),
                    description: description.clone(),
                    fire_at: fire_at.clone(),
                    payload,
                    recurring: args.recurring.unwrap_or(false),
                    interval_secs: args.interval_secs,
                    triggered: false,
                    created_at: chrono::Utc::now().to_rfc3339(),
                };

                let mut state = self.load_state()?;
                state.jobs.push(job);
                self.save_state(&state)?;

                Ok(format!("✅ Scheduled: {}\nID: {}\nFires at: {}", description, id, fire_at))
            }

            "list" => {
                let state = self.load_state()?;

                if state.jobs.is_empty() {
                    return Ok("No scheduled jobs.".to_string());
                }

                let mut lines = vec!["Scheduled jobs:".to_string()];
                for job in &state.jobs {
                    let status = if job.triggered { "✓ triggered" } else { "⏰ pending" };
                    let recurring = if job.recurring { " (recurring)" } else { "" };
                    lines.push(format!(
                        "  {} | {} | fires: {} | {}{}",
                        job.id, status, job.fire_at, job.description, recurring
                    ));
                }

                Ok(lines.join("\n"))
            }

            "cancel" => {
                let job_id = args.job_id
                    .ok_or_else(|| anyhow::anyhow!("'job_id' required for cancel"))?;

                let mut state = self.load_state()?;
                let before = state.jobs.len();
                state.jobs.retain(|j| j.id != job_id);

                if state.jobs.len() == before {
                    anyhow::bail!("Job not found: {}", job_id);
                }

                self.save_state(&state)?;
                Ok(format!("Cancelled job: {}", job_id))
            }

            _ => anyhow::bail!("Unknown action: {}. Use: schedule, list, cancel", args.action),
        }
    }
}

/// Check for due cron jobs and return their payloads.
/// Called from the background loop in the CLI.
pub fn check_due_jobs(workspace: &Path) -> Result<Vec<CronJob>> {
    let cron_path = workspace.join("cron.json");
    if !cron_path.exists() {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(&cron_path)?;
    let mut state: CronState = serde_json::from_str(&content)?;
    let now = chrono::Utc::now();
    let mut due = Vec::new();

    for job in &mut state.jobs {
        if job.triggered && !job.recurring {
            continue;
        }

        if let Ok(fire_time) = chrono::DateTime::parse_from_rfc3339(&job.fire_at) {
            if now >= fire_time {
                due.push(job.clone());
                if job.recurring {
                    if let Some(interval) = job.interval_secs {
                        let next = fire_time + chrono::Duration::seconds(interval as i64);
                        job.fire_at = next.to_rfc3339();
                    }
                } else {
                    job.triggered = true;
                }
            }
        }
    }

    // Save updated state
    if !due.is_empty() {
        let content = serde_json::to_string_pretty(&state)?;
        std::fs::write(&cron_path, content)?;
    }

    Ok(due)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_relative_time() {
        let result = CronTool::parse_fire_at("in 5m");
        assert!(result.is_ok());

        let result = CronTool::parse_fire_at("in 1h");
        assert!(result.is_ok());

        let result = CronTool::parse_fire_at("in 30s");
        assert!(result.is_ok());

        let result = CronTool::parse_fire_at("in 2d");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_iso_time() {
        let result = CronTool::parse_fire_at("2026-02-14T18:00:00+00:00");
        assert!(result.is_ok());
    }

    #[test]
    fn test_tool_name() {
        let tmp = std::env::temp_dir();
        let tool = CronTool::new(&tmp);
        assert_eq!(tool.name(), "cron");
    }
}
