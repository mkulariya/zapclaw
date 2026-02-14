use anyhow::{Context, Result};
use clap::Parser;
use pincer_core::agent::{Agent, ToolRegistry};
use pincer_core::config::{Config, LlmMode};
use pincer_core::confiner::Confiner;
use pincer_core::llm::OpenAiCompatibleClient;
use pincer_core::memory::MemoryDb;
use pincer_core::StreamChunk;
use tokio::sync::mpsc;
use pincer_tools::browser_tool::BrowserTool;
use pincer_tools::cron_tool::{check_due_jobs, CronTool};
use pincer_tools::edit_tool::EditTool;
use pincer_tools::exec_tool::ExecTool;
use pincer_tools::file_tool::FileTool;
use pincer_tools::find_tool::FindTool;
use pincer_tools::grep_tool::GrepTool;
use pincer_tools::image_tool::ImageTool;
use pincer_tools::math_tool::MathTool;
use pincer_tools::memory_tool::{MemoryGetTool, MemorySearchTool};
use pincer_tools::patch_tool::PatchTool;
use pincer_tools::process_tool::ProcessTool;
use pincer_tools::session_tool::SessionTool;
use pincer_tools::web_search_tool::WebSearchTool;
use std::sync::Arc;
use std::path::PathBuf;

/// Pincer 🦞 — Secure, lightweight AI agent
#[derive(Parser, Debug)]
#[command(name = "pincer", version, about = "Pincer 🦞 — Secure, lightweight AI agent")]
struct Cli {
    /// Workspace directory path
    #[arg(short, long, default_value = "./pincer_workspace")]
    workspace: String,

    /// LLM mode: "local" (Ollama) or "cloud" (OpenAI-compatible)
    #[arg(short, long, default_value = "local")]
    model_mode: String,

    /// Model name (e.g., "phi3:mini" for Ollama, "gpt-4o" for OpenAI)
    #[arg(short = 'n', long, default_value = "phi3:mini")]
    model_name: String,

    /// API base URL (default: auto-detected from mode)
    #[arg(long)]
    api_url: Option<String>,

    /// API key (prefer PINCER_API_KEY env var for security)
    #[arg(long, env = "PINCER_API_KEY")]
    api_key: Option<String>,

    /// Web search API key (for Brave Search)
    #[arg(long, env = "PINCER_SEARCH_API_KEY")]
    search_api_key: Option<String>,

    /// Maximum agent steps per task
    #[arg(long, default_value = "15")]
    max_steps: usize,

    /// Run a single task and exit (non-interactive mode)
    #[arg(short, long)]
    task: Option<String>,

    /// Disable human confirmation prompts
    #[arg(long)]
    no_confirm: bool,

    /// Tool execution timeout in seconds
    #[arg(long, default_value = "30")]
    tool_timeout: u64,

    /// Self-update from GitHub releases
    #[arg(long)]
    update: bool,
}

/// Run agent with streaming output.
///
/// Creates a channel, spawns a task to print stream chunks in real-time,
/// and returns the final response when complete.
async fn run_with_streaming(agent: &Agent, session_id: &str, task: &str) -> Result<String> {
    // Create channel for streaming chunks
    let (tx, mut rx) = mpsc::channel::<StreamChunk>(100);

    // Spawn task to handle streaming output
    let print_handle = tokio::spawn(async move {
        use std::io::{self, Write};
        let mut stdout = io::stdout();

        while let Some(chunk) = rx.recv().await {
            match chunk {
                StreamChunk::TextDelta(text) => {
                    // Print token by token without newlines
                    print!("{}", text);
                    stdout.flush().ok();
                }
                StreamChunk::ToolCallDelta { .. } => {
                    // Tool calls are handled silently, final output will show results
                }
                StreamChunk::Done(_) => {
                    // Final response received, stop streaming
                    break;
                }
            }
        }
    });

    // Run agent with streaming
    let response = agent.run_stream(session_id, task, tx).await?;

    // Wait for print task to finish
    print_handle.await.ok();

    Ok(response)
}

/// Model alias resolution.
fn resolve_model_alias(name: &str) -> String {
    match name.to_lowercase().as_str() {
        "phi" | "phi3" => "phi3:mini".to_string(),
        "gpt4" | "gpt4o" => "gpt-4o".to_string(),
        "claude" | "sonnet" => "claude-3.5-sonnet".to_string(),
        "llama" | "llama3" => "llama3.1:8b".to_string(),
        "gemini" | "gemini2" => "gemini-2.0-flash".to_string(),
        "qwen" | "qwen2" => "qwen2.5:7b".to_string(),
        other => other.to_string(),
    }
}

/// Self-update from GitHub releases.
async fn self_update() -> Result<()> {
    println!("🔄 Checking for updates...");

    let client = reqwest::Client::builder()
        .user_agent("Pincer-Updater")
        .build()?;

    let resp = client
        .get("https://api.github.com/repos/pincer/pincer/releases/latest")
        .send()
        .await
        .context("Failed to check for updates")?;

    if !resp.status().is_success() {
        println!("⚠️  Could not check for updates (HTTP {})", resp.status());
        println!("You can update manually:");
        println!("  cd {} && git pull && cargo build --release", env!("CARGO_MANIFEST_DIR"));
        return Ok(());
    }

    let body: serde_json::Value = resp.json().await?;
    let latest_tag = body["tag_name"].as_str().unwrap_or("unknown");
    let current = env!("CARGO_PKG_VERSION");

    if latest_tag.trim_start_matches('v') == current {
        println!("✅ Already on latest version: v{}", current);
        return Ok(());
    }

    println!("📦 New version available: {} (current: v{})", latest_tag, current);
    println!("Updating via git...");

    let output = std::process::Command::new("sh")
        .args(["-c", "cd $(git rev-parse --show-toplevel 2>/dev/null || echo .) && git pull origin main && cargo build --release"])
        .output()
        .context("Failed to run update command")?;

    if output.status.success() {
        println!("✅ Updated successfully! Restart Pincer to use the new version.");
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("⚠️  Update had issues:\n{}", stderr);
        println!("Try manually: git pull && cargo build --release");
    }

    Ok(())
}

/// Extract final response from reasoning format.
/// If response contains <think>...</think> and <final>...</final>,
/// only display the content inside <final>.
fn extract_final_response(response: &str) -> String {
    // Check for <final>...</final> tags
    if let Some(start) = response.find("<final>") {
        if let Some(end) = response.find("</final>") {
            let final_content = &response[start + 7..end];
            return final_content.trim().to_string();
        }
    }

    // Check for <think>...</think> — strip thinking block
    if let Some(think_end) = response.find("</think>") {
        let after_think = &response[think_end + 8..];
        let cleaned = after_think.trim();
        if !cleaned.is_empty() {
            return cleaned.to_string();
        }
    }

    // No reasoning format, return as-is
    response.to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .init();

    let cli = Cli::parse();

    // Self-update mode
    if cli.update {
        return self_update().await;
    }

    // Build configuration
    let mut config = Config::from_env();
    config.workspace_path = cli.workspace.into();
    config.model_name = resolve_model_alias(&cli.model_name);
    config.max_steps = cli.max_steps;
    config.require_confirmation = !cli.no_confirm;
    config.tool_timeout_secs = cli.tool_timeout;

    config.llm_mode = match cli.model_mode.to_lowercase().as_str() {
        "cloud" => LlmMode::Cloud,
        _ => LlmMode::Local,
    };

    if let Some(url) = cli.api_url {
        config.api_base_url = url;
    } else if config.llm_mode == LlmMode::Cloud {
        config.api_base_url = "https://api.openai.com/v1".to_string();
    }

    // Resolve workspace
    let workspace = config.resolve_workspace()
        .context("Failed to initialize workspace")?;

    // Update config workspace_path with resolved canonical path
    config.workspace_path = workspace.clone();

    println!("🦞 Pincer v{}", env!("CARGO_PKG_VERSION"));
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Workspace:  {}", workspace.display());
    println!("  Model:      {} ({})", config.model_name, match config.llm_mode {
        LlmMode::Local => "Ollama local",
        LlmMode::Cloud => "Cloud API",
    });
    println!("  Max steps:  {}", config.max_steps);
    println!("  Timeout:    {}s", config.tool_timeout_secs);
    println!("  Confirm:    {}", if config.require_confirmation { "yes" } else { "no" });
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Initialize components
    let api_key = cli.api_key.or_else(Config::api_key);

    let llm: Arc<dyn pincer_core::llm::LlmClient> = Arc::new(
        OpenAiCompatibleClient::new(&config.api_base_url, &config.model_name, api_key.clone())
    );

    // File-based memory (no SQLite)
    let memory = Arc::new(
        MemoryDb::new(&workspace)
            .context("Failed to initialize memory")?
    );

    let confiner = Confiner::new(&workspace)
        .context("Failed to initialize workspace confiner")?;

    // Register all 14 tools
    let mut tools = ToolRegistry::new();

    // Core developer tools
    tools.register(Arc::new(FileTool::new(Arc::new(confiner.clone()))));
    tools.register(Arc::new(EditTool::new(confiner.clone())));
    tools.register(Arc::new(ExecTool::new(confiner.clone())));
    tools.register(Arc::new(GrepTool::new(confiner.clone())));
    tools.register(Arc::new(FindTool::new(confiner.clone())));
    tools.register(Arc::new(PatchTool::new(confiner.clone())));

    // Memory tools
    tools.register(Arc::new(MemorySearchTool::new(memory.clone())));
    tools.register(Arc::new(MemoryGetTool::new(memory.clone())));

    // Background process manager
    tools.register(Arc::new(ProcessTool::new(confiner.clone())));

    // Cron/reminders
    tools.register(Arc::new(CronTool::new(&workspace)));

    // Image analysis (uses same API)
    tools.register(Arc::new(ImageTool::new(
        &config.api_base_url,
        &config.model_name,
        api_key,
    )));

    // Session status
    tools.register(Arc::new(SessionTool::new(
        memory.clone(),
        &config.model_name,
        vec![
            ("phi".to_string(), "phi3:mini".to_string()),
            ("gpt4".to_string(), "gpt-4o".to_string()),
            ("claude".to_string(), "claude-3.5-sonnet".to_string()),
            ("llama".to_string(), "llama3.1:8b".to_string()),
        ],
    )));

    // Utility tools
    tools.register(Arc::new(MathTool::new()));
    tools.register(Arc::new(BrowserTool::new()));

    // Web search (uses Brave if key provided, else DuckDuckGo)
    let search_tool = if let Some(key) = cli.search_api_key {
        WebSearchTool::brave(key)
    } else {
        WebSearchTool::duckduckgo()
    };
    tools.register(Arc::new(search_tool));

    println!("  Tools:      {}", tools.tool_names().join(", "));
    println!();

    let agent = Agent::new(llm, memory.clone(), tools, config);

    let session_id = uuid::Uuid::new_v4().to_string();

    // Start cron background loop
    let cron_workspace = workspace.clone();
    let _cron_handle = tokio::spawn(async move {
        cron_background_loop(&cron_workspace).await;
    });

    // Single task mode
    if let Some(task) = cli.task {
        let response = run_with_streaming(&agent, &session_id, &task).await?;
        println!("\n{}", extract_final_response(&response));
        return Ok(());
    }

    // Interactive REPL mode
    println!("Type your tasks below. Use 'exit' or Ctrl+C to quit.\n");

    let mut rl = rustyline::DefaultEditor::new()
        .context("Failed to initialize line editor")?;

    loop {
        let readline = rl.readline("🦞 > ");
        match readline {
            Ok(line) => {
                let input = line.trim();

                if input.is_empty() {
                    continue;
                }

                if input == "exit" || input == "quit" || input == "q" {
                    println!("👋 Goodbye!");
                    break;
                }

                if input == "help" {
                    print_help();
                    continue;
                }

                if input == "tools" {
                    print_tools(&agent);
                    continue;
                }

                // /compact command
                if input == "/compact" || input.starts_with("/compact ") {
                    let keep_days: usize = input
                        .strip_prefix("/compact ")
                        .and_then(|s| s.trim().parse().ok())
                        .unwrap_or(7);

                    match memory.compact(keep_days) {
                        Ok(result) => {
                            if result.files_compacted == 0 {
                                println!("Nothing to compact — memory is lean.");
                            } else {
                                println!(
                                    "✅ Compacted {} files, freed ~{} chars (~{} tokens)",
                                    result.files_compacted,
                                    result.chars_freed,
                                    result.chars_freed / 4
                                );
                            }
                        }
                        Err(e) => eprintln!("❌ Compaction error: {:#}", e),
                    }
                    continue;
                }

                // /update command
                if input == "/update" {
                    match self_update().await {
                        Ok(()) => {}
                        Err(e) => eprintln!("❌ Update error: {:#}", e),
                    }
                    continue;
                }

                // /status command
                if input == "/status" {
                    let tokens = memory.total_memory_tokens().unwrap_or(0);
                    let files = memory.list_memory_files().unwrap_or_default();
                    println!("\n📊 Session Status");
                    println!("  Memory files: {}", files.len());
                    println!("  Memory tokens: ~{}", tokens);
                    println!("  Session ID: {}\n", session_id);
                    continue;
                }

                rl.add_history_entry(input).ok();

                // Run the task with streaming
                match run_with_streaming(&agent, &session_id, input).await {
                    Ok(response) => {
                        println!("\n{}\n", extract_final_response(&response));
                    }
                    Err(e) => {
                        eprintln!("\n❌ Error: {:#}\n", e);
                    }
                }
            }
            Err(rustyline::error::ReadlineError::Interrupted) => {
                println!("\n👋 Interrupted. Goodbye!");
                break;
            }
            Err(rustyline::error::ReadlineError::Eof) => {
                println!("\n👋 Goodbye!");
                break;
            }
            Err(e) => {
                eprintln!("Error reading input: {}", e);
                break;
            }
        }
    }

    Ok(())
}

/// Cron background check loop — lightweight, runs every 30s.
async fn cron_background_loop(workspace: &PathBuf) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

        match check_due_jobs(workspace) {
            Ok(due_jobs) => {
                for job in &due_jobs {
                    println!("\n🔔 Reminder: {}", job.description);
                    println!("   {}\n", job.payload);
                }
            }
            Err(_) => {
                // Silently ignore cron errors in background loop
            }
        }
    }
}

fn print_help() {
    println!("
🦞 Pincer Help
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Just type your request and Pincer will help!

  Examples:
    Calculate sqrt(144) + 3^2
    Create a file called notes.txt with today's meeting notes
    Read the file data.csv
    Find all .rs files in src/
    Search my code for \"TODO\"
    Run 'cargo test' in the workspace
    Search the web for Rust async patterns
    What's on https://example.com?
    Remember that I prefer dark mode
    Set a reminder in 30 minutes to check the build
    Show session status

  Commands:
    exit/quit/q  — Exit Pincer
    help         — Show this help
    tools        — List available tools
    /compact [N] — Compact memory (keep N days, default: 7)
    /update      — Self-update from git
    /status      — Show session info

  Skills:
    Place SKILL.md files in .skills/<name>/SKILL.md
    Pincer will auto-discover and use them.

  Persona:
    Place SOUL.md in workspace root to customize personality.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
");
}

fn print_tools(_agent: &Agent) {
    println!("
🔧 Available Tools (14)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  read/write/append    — File operations (workspace-confined)
  edit                 — Precise search/replace edits
  exec                 — Run shell commands (sandboxed)
  grep                 — Search file contents for patterns
  find                 — Find files by glob pattern
  apply_patch          — Apply unified diff patches
  process              — Background exec sessions (start, list, kill)
  memory_search        — Search memory files (MEMORY.md + memory/*.md)
  memory_get           — Read specific memory file lines
  image                — Analyze images via vision model
  cron                 — Schedule reminders and recurring tasks
  session_status       — Session info, history, and compaction
  math_eval            — Evaluate math expressions
  browse_url           — Fetch web page content (read-only)
  web_search           — Search the web
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
");
}
