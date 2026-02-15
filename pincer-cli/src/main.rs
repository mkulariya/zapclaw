use anyhow::{Context, Result};
use clap::Parser;
use pincer_core::agent::{Agent, ToolRegistry};
use pincer_core::config::{Config, LlmMode};
use pincer_core::confiner::Confiner;
use pincer_core::llm::OpenAiCompatibleClient;
use pincer_core::memory::MemoryDb;
use pincer_core::session::SessionStore;
use pincer_core::StreamChunk;
use tokio::sync::mpsc;
use pincer_tunnels::inbound::{InboundConfig, InboundMessage, InboundResponse, InboundTunnel};
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

    /// Skip bubblewrap sandbox (development only — NOT recommended for production)
    #[arg(long)]
    no_sandbox: bool,

    /// Disable network access inside sandbox (blocks Ollama + cloud APIs)
    #[arg(long)]
    sandbox_no_network: bool,

    /// Tool execution timeout in seconds
    #[arg(long, default_value = "30")]
    tool_timeout: u64,

    /// Enable remote JSON-RPC server for inbound task submission
    #[arg(long)]
    enable_inbound: bool,

    /// Inbound server port
    #[arg(long, default_value = "9876")]
    inbound_port: u16,

    /// Inbound server bind address
    #[arg(long, default_value = "127.0.0.1")]
    inbound_bind: String,

    /// API key for inbound tunnel auth
    #[arg(long, env = "PINCER_INBOUND_KEY")]
    inbound_api_key: Option<String>,

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
                StreamChunk::ToolStart { name, .. } => {
                    print!("  [Running {}...", name);
                    stdout.flush().ok();
                }
                StreamChunk::ToolEnd { is_error, .. } => {
                    if is_error {
                        println!(" ERROR]");
                    } else {
                        println!(" done]");
                    }
                }
                StreamChunk::ReasoningDelta(_) => {
                    // Internal reasoning — not displayed
                }
                StreamChunk::LifecycleEvent { .. } => {
                    // Lifecycle events — optional status display (silent for now)
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

/// Resolve workspace path for sandbox bind mount (before full Config init).
fn resolve_workspace_for_sandbox(workspace_arg: &str) -> std::path::PathBuf {
    let path = std::path::PathBuf::from(workspace_arg);
    if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join(path)
    }
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

    // Sandbox enforcement — must happen FIRST, before any other initialization.
    // If not already sandboxed and --no-sandbox is not set, re-exec inside bwrap.
    let sandbox_state = if cli.no_sandbox {
        pincer_core::sandbox::SandboxState::Disabled
    } else {
        // Resolve workspace path early for the sandbox bind mount
        let ws_path = resolve_workspace_for_sandbox(&cli.workspace);
        pincer_core::sandbox::ensure_sandboxed(&ws_path, cli.sandbox_no_network)?
        // NOTE: If bwrap is available, ensure_sandboxed() does NOT return —
        // it replaces this process via exec(). If we reach here, we're
        // either already inside the sandbox (Active) or bwrap is missing (Unavailable).
    };

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
    println!("  Sandbox:    {}", match sandbox_state {
        pincer_core::sandbox::SandboxState::Active => "active (bubblewrap)",
        pincer_core::sandbox::SandboxState::Disabled => "DISABLED (--no-sandbox)",
        pincer_core::sandbox::SandboxState::Unavailable => "UNAVAILABLE (install bwrap)",
    });
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

    let sandbox_active = sandbox_state == pincer_core::sandbox::SandboxState::Active;
    let agent = Arc::new(Agent::new(llm, memory.clone(), tools, config, sandbox_active));

    let session_store = SessionStore::new(&workspace);
    let mut session_id = uuid::Uuid::new_v4().to_string();

    // Single task mode — no cron loop needed
    if let Some(task) = cli.task {
        let response = run_with_streaming(&agent, &session_id, &task).await?;
        println!("\n{}", extract_final_response(&response));
        return Ok(());
    }

    // Shared shutdown channel for background loops
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Start inbound tunnel if enabled
    let _inbound_handle = if cli.enable_inbound {
        let api_key = cli.inbound_api_key
            .ok_or_else(|| anyhow::anyhow!(
                "--inbound-api-key is required when --enable-inbound is set.\n\
                 Generate one: openssl rand -hex 16"
            ))?;

        let inbound_config = InboundConfig {
            enabled: true,
            bind_address: cli.inbound_bind.clone(),
            rpc_port: cli.inbound_port,
            api_key: Some(api_key),
            max_concurrent: 5,
            workspace_root: Some(workspace.clone()),
        };

        let (tunnel, inbound_rx) = InboundTunnel::new(inbound_config);
        let tunnel = Arc::new(tunnel);
        let tunnel_handle = tunnel.start().await
            .context("Failed to start inbound tunnel")?;

        // Spawn the processing loop
        let inbound_agent = agent.clone();
        let inbound_shutdown = shutdown_rx.clone();
        let processing_handle = tokio::spawn(async move {
            inbound_processing_loop(inbound_agent, inbound_rx, inbound_shutdown).await;
        });

        println!("  Inbound:    {}:{} (remote access enabled)", cli.inbound_bind, cli.inbound_port);
        println!();

        Some((tunnel_handle, processing_handle))
    } else {
        None
    };

    // Start cron background loop — only in REPL mode
    let cron_shutdown_rx = shutdown_rx.clone();
    let cron_workspace = workspace.clone();
    let cron_handle = tokio::spawn(async move {
        cron_background_loop(&cron_workspace, cron_shutdown_rx).await;
    });

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

                // /compact command — LLM-driven compaction with fallback
                if input == "/compact" || input.starts_with("/compact ") {
                    let keep_days: usize = input
                        .strip_prefix("/compact ")
                        .and_then(|s| s.trim().parse().ok())
                        .unwrap_or(7);

                    // Try LLM-driven compaction first, fall back to rule-based
                    let result = memory.compact_llm(agent.llm(), keep_days).await;
                    match result {
                        Ok(result) => {
                            if result.files_compacted == 0 {
                                println!("Nothing to compact — memory is lean.");
                            } else {
                                let summary_note = if result.summary.is_some() {
                                    " (LLM-summarized)"
                                } else {
                                    " (rule-based)"
                                };
                                println!(
                                    "Compacted {} files, freed ~{} chars (~{} tokens){}",
                                    result.files_compacted,
                                    result.chars_freed,
                                    result.chars_freed / 4,
                                    summary_note,
                                );
                                if let (Some(before), Some(after)) = (result.tokens_before, result.tokens_after) {
                                    println!("  Tokens: {} -> {}", before, after);
                                }
                            }
                        }
                        Err(e) => eprintln!("Compaction error: {:#}", e),
                    }
                    continue;
                }

                // /resume command — list or resume a previous session
                if input == "/resume" || input.starts_with("/resume ") {
                    let arg = input.strip_prefix("/resume").unwrap_or("").trim();

                    if arg.is_empty() {
                        // List recent sessions
                        match session_store.list_sessions() {
                            Ok(sessions) => {
                                if sessions.is_empty() {
                                    println!("No previous sessions found.");
                                } else {
                                    println!("\nRecent sessions:");
                                    for (i, s) in sessions.iter().rev().take(10).enumerate() {
                                        println!(
                                            "  {}. {} (model: {}, messages: {}, updated: {})",
                                            i + 1, s.id, s.model, s.message_count,
                                            &s.updated_at[..s.updated_at.len().min(19)]
                                        );
                                    }
                                    println!("\nUse /resume <session_id> to continue a session.\n");
                                }
                            }
                            Err(e) => eprintln!("Error listing sessions: {:#}", e),
                        }
                    } else {
                        // Resume specific session
                        match session_store.load_session_messages(arg) {
                            Ok(messages) => {
                                session_id = arg.to_string();
                                println!(
                                    "Resumed session {} ({} messages loaded)\n",
                                    session_id,
                                    messages.len()
                                );
                            }
                            Err(e) => eprintln!("Error resuming session: {:#}", e),
                        }
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

    // Graceful shutdown: stop all background loops
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        cron_handle,
    ).await;

    Ok(())
}

/// Inbound tunnel processing loop — receives tasks from remote clients,
/// runs them through the agent, and sends responses back.
async fn inbound_processing_loop(
    agent: Arc<Agent>,
    mut rx: mpsc::Receiver<InboundMessage>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(msg) => {
                        let agent = agent.clone();
                        tokio::spawn(async move {
                            let session_id = msg.task.session_id
                                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

                            log::info!("Processing inbound task {} for session {}", msg.task.id, session_id);

                            let result = agent.run(&session_id, &msg.task.task).await;

                            if let Some(tx) = msg.response_tx {
                                let response = match result {
                                    Ok(text) => InboundResponse {
                                        response: text,
                                        session_id,
                                    },
                                    Err(e) => InboundResponse {
                                        response: format!("Error: {}", e),
                                        session_id,
                                    },
                                };
                                let _ = tx.send(response);
                            }
                        });
                    }
                    None => break, // Channel closed
                }
            }
            _ = shutdown.changed() => break,
        }
    }
}

/// Cron background check loop — lightweight, runs every 30s.
///
/// Uses `spawn_blocking` for file I/O to avoid blocking the async runtime.
/// Listens for shutdown signal to terminate cleanly.
async fn cron_background_loop(
    workspace: &PathBuf,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(30)) => {
                let ws = workspace.clone();
                let result = tokio::task::spawn_blocking(move || {
                    check_due_jobs(&ws)
                }).await;

                if let Ok(Ok(due_jobs)) = result {
                    for job in &due_jobs {
                        println!("\n🔔 Reminder: {}", job.description);
                        println!("   {}\n", job.payload);
                    }
                }
            }
            _ = shutdown.changed() => {
                // Shutdown signal received — exit cleanly
                break;
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
    /resume      — List recent sessions
    /resume <id> — Resume a previous session
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
