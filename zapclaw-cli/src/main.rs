use anyhow::{Context, Result, bail};
use clap::Parser;
use zapclaw_core::agent::{Agent, ConfirmationMode, ToolRegistry};
use zapclaw_core::config::Config;
use zapclaw_core::confiner::Confiner;
use zapclaw_core::llm::OpenAiCompatibleClient;
use zapclaw_core::memory::MemoryDb;
use zapclaw_core::session::SessionStore;
use zapclaw_core::StreamChunk;
use tokio::sync::mpsc;
use zapclaw_tunnels::inbound::{InboundConfig, InboundMessage, InboundResponse, InboundTunnel};
use zapclaw_tools::browser_tool::BrowserTool;
use zapclaw_tools::cron_tool::{check_due_jobs, CronTool};
use zapclaw_tools::edit_tool::EditTool;
use zapclaw_tools::exec_tool::ExecTool;
use zapclaw_tools::android_tool::AndroidTool;
use zapclaw_tools::file_tool::FileTool;
use zapclaw_tools::find_tool::FindTool;
use zapclaw_tools::grep_tool::GrepTool;
use zapclaw_tools::image_tool::ImageTool;
use zapclaw_tools::math_tool::MathTool;
use zapclaw_tools::memory_tool::{MemoryGetTool, MemorySearchTool};
use zapclaw_tools::patch_tool::PatchTool;
use zapclaw_tools::process_tool::ProcessTool;
use zapclaw_tools::session_tool::SessionTool;
use zapclaw_tools::web_search_tool::WebSearchTool;
use zapclaw_tunnels::telegram::TelegramListener;
use std::sync::Arc;
use std::path::PathBuf;
use std::io::IsTerminal;
use std::borrow::Cow;
use rustyline::completion::{Completer, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::Helper;

/// ZapClaw 🦞 — Secure, lightweight AI agent
#[derive(Parser, Debug)]
#[command(name = "zapclaw", version, about = "ZapClaw 🦞 — Secure, lightweight AI agent")]
struct Cli {
    /// Config file path (disables layered home+project discovery)
    #[arg(short, long)]
    config: Option<String>,

    /// Initialize a new config file template and exit
    #[arg(long)]
    init_config: bool,

    /// Print effective configuration (merged from file/env/CLI) and exit
    #[arg(long)]
    print_effective_config: bool,

    /// Workspace directory path
    #[arg(short, long)]
    workspace: Option<String>,

    /// Model name (e.g., "phi3:mini" for Ollama, "gpt-4o" for OpenAI)
    #[arg(short = 'n', long, env = "ZAPCLAW_MODEL")]
    model_name: Option<String>,

    /// API base URL (required)
    #[arg(long, env = "ZAPCLAW_API_BASE_URL")]
    api_url: Option<String>,

    /// API key (optional for loopback endpoints, required for remote endpoints)
    #[arg(long, env = "ZAPCLAW_API_KEY")]
    api_key: Option<String>,

    /// Web search API key (for Brave Search)
    #[arg(long, env = "ZAPCLAW_SEARCH_API_KEY")]
    search_api_key: Option<String>,

    /// Maximum agent steps per task
    #[arg(long)]
    max_steps: Option<usize>,

    /// Run a single task and exit (non-interactive mode)
    #[arg(short, long)]
    task: Option<String>,

    /// Disable human confirmation prompts
    #[arg(long)]
    no_confirm: bool,

    /// Disable egress guard for web_search and browse_url (DANGEROUS)
    #[arg(long)]
    no_egress_guard: bool,

    /// Skip bubblewrap sandbox (development only — NOT recommended for production)
    #[arg(long)]
    no_sandbox: bool,

    /// Disable network access inside sandbox (blocks Ollama + cloud APIs)
    #[arg(long)]
    sandbox_no_network: bool,

    /// Tool execution timeout in seconds
    #[arg(long)]
    tool_timeout: Option<u64>,

    /// Enable remote JSON-RPC server for inbound task submission
    #[arg(long)]
    enable_inbound: bool,

    /// Enable Telegram bot integration (requires ZAPCLAW_TELEGRAM_TOKEN and ZAPCLAW_TELEGRAM_ALLOWED_IDS env vars)
    #[arg(long = "enable-telegram", default_value = "false")]
    enable_telegram: bool,

    /// Enable Android device control via ADB
    #[arg(long = "enable-android", default_value = "false")]
    enable_android: bool,

    /// Inbound server port
    #[arg(long)]
    inbound_port: Option<u16>,

    /// Inbound server bind address
    #[arg(long)]
    inbound_bind: Option<String>,

    /// API key for inbound tunnel auth
    #[arg(long, env = "ZAPCLAW_INBOUND_KEY")]
    inbound_api_key: Option<String>,

    /// Self-update from GitHub releases
    #[arg(long)]
    update: bool,
}

/// Resolved LLM settings with validation
#[derive(Debug, Clone)]
struct ResolvedLlmSettings {
    api_base_url: String,
    model_name: String,
    api_key: Option<String>,
    endpoint_kind: EndpointKind,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum EndpointKind {
    Loopback,
    Remote,
}

/// Check if a URL host is strict loopback (localhost, 127.0.0.1, ::1)
/// Uses case-insensitive matching for hostname and IP-based detection for robustness.
fn is_strict_loopback(host: &str) -> bool {
    let host_lower = host.to_lowercase();

    // Check for localhost hostname (case-insensitive)
    if host_lower == "localhost" {
        return true;
    }

    // Try to parse as IP address for robust loopback detection
    if let Ok(addr) = host_lower.parse::<std::net::IpAddr>() {
        return addr.is_loopback();
    }

    false
}

/// Handle --init-config flag
fn handle_init_config(cli: &Cli) -> Result<()> {
    // Determine which path to initialize
    let config_path = if let Some(ref path_str) = cli.config {
        // Explicit path via --config
        PathBuf::from(path_str)
    } else {
        // Default: project config (./zapclaw.json)
        Config::resolve_project_config_path()
    };

    if config_path.exists() {
        bail!(
            "⛔ Config file already exists at {}\n\
             To overwrite, remove the existing file first.",
            config_path.display()
        );
    }

    // Generate template
    let template = Config::default_template_json(&config_path);

    // Write to file with restrictive permissions
    std::fs::write(&config_path, template)
        .with_context(|| format!("Failed to write config file to {}", config_path.display()))?;

    // Set restrictive permissions (0600) on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&config_path, perms)
            .with_context(|| format!("Failed to set permissions on {}", config_path.display()))?;
    }

    println!("✅ Config file created at: {}", config_path.display());
    println!();
    println!("Next steps:");
    println!("  1. Edit the config file to set your preferred values");
    println!("  2. Set API keys via environment variables:");
    println!("     export ZAPCLAW_API_KEY=\"your-key-here\"");
    println!("     export ZAPCLAW_SEARCH_API_KEY=\"your-brave-key\"  # Optional");
    println!("     export ZAPCLAW_INBOUND_KEY=\"your-inbound-key\"    # For remote access");
    println!("  3. Run zapclaw normally");
    
    if config_path == Config::resolve_project_config_path() {
        println!();
        println!("Note: This is a project-level config (./zapclaw.json).");
        println!("It will override values from your home config (~/.zapclaw/zapclaw.json).");
    }

    Ok(())
}

/// Handle --print-effective-config flag
fn handle_print_effective_config(config: &Config) -> Result<()> {
    let json = config.to_persisted_json()
        .context("Failed to serialize config")?;

    println!("{}", json);
    println!();
    println!("Note: Secret values (API keys) are not shown for security.");
    println!("They must be set via environment variables or CLI flags.");

    Ok(())
}

/// Resolve LLM settings from CLI or merged config
fn resolve_llm_settings_from_config(cli: &Cli, config: &Config) -> Result<ResolvedLlmSettings> {
    // CLI args take precedence over config file
    let api_base_url = if let Some(url) = &cli.api_url {
        url.clone()
    } else if !config.api_base_url.is_empty() {
        config.api_base_url.clone()
    } else {
        bail!(
            "⛔ Missing required field: --api-url (or ZAPCLAW_API_BASE_URL env var or api_base_url in config file)\n\
             \n\
             ZapClaw requires an explicit LLM endpoint URL. Examples:\n\
             • Ollama (local): --api-url http://localhost:11434/v1\n\
             • OpenAI (cloud): --api-url https://api.openai.com/v1\n\
             • Custom: --api-url http://your-host:port/v1"
        )
    };

    let model_name = if let Some(model) = &cli.model_name {
        model.clone()
    } else if !config.model_name.is_empty() {
        config.model_name.clone()
    } else {
        bail!(
            "⛔ Missing required field: --model-name (or ZAPCLAW_MODEL env var or model_name in config file)\n\
             \n\
             ZapClaw requires an explicit model identifier. Examples:\n\
             • Ollama: --model-name phi3:mini\n\
             • OpenAI: --model-name gpt-4o\n\
             • Custom: --model-name your-model-name"
        )
    };

    // Validate URL format
    let parsed_url: url::Url = api_base_url.parse().context("Invalid --api-url format")?;

    // Validate scheme
    if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
        bail!(
            "⛔ Invalid --api-url scheme: '{}'. Only http and https are supported.\n\
             You provided: {}",
            parsed_url.scheme(),
            api_base_url
        );
    }

    // Validate host exists
    let host = parsed_url
        .host_str()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "⛔ Invalid --api-url: missing host. You provided: {}",
                api_base_url
            )
        })?;

    // Validate model_name is not empty
    let model_name = model_name.trim().to_string();
    if model_name.is_empty() {
        bail!("⛔ --model-name cannot be empty");
    }

    // Determine endpoint kind
    let endpoint_kind = if is_strict_loopback(host) {
        EndpointKind::Loopback
    } else {
        EndpointKind::Remote
    };

    // Resolve api_key from CLI, env, or config (config keys are ignored for secrets)
    let api_key = cli.api_key
        .clone()
        .or_else(|| Config::api_key())
        .or_else(|| std::env::var("ZAPCLAW_API_KEY").ok());

    // Validate api_key requirement for remote endpoints
    if endpoint_kind == EndpointKind::Remote && api_key.is_none() {
        bail!(
            "⛔ API key is required for remote endpoints.\n\
             \n\
             Your endpoint ({}) is not localhost. Remote endpoints require authentication.\n\
             \n\
             Fix: Set --api-key (or ZAPCLAW_API_KEY env var).\n\
             Example: --api-key sk-your-api-key-here",
            host
        );
    }

    Ok(ResolvedLlmSettings {
        api_base_url,
        model_name,
        api_key,
        endpoint_kind,
    })
}

/// Resolve confirmation policy from runtime mode + terminal capabilities.
fn resolve_confirmation_mode(
    no_confirm: bool,
    enable_inbound: bool,
    stdin_is_tty: bool,
    stdout_is_tty: bool,
) -> ConfirmationMode {
    if no_confirm {
        return ConfirmationMode::Allow;
    }

    // Inbound/server mode is headless from the tool-approval standpoint.
    if enable_inbound {
        return ConfirmationMode::Deny;
    }

    // Non-interactive shell (pipe/CI/service): deny by default.
    if !stdin_is_tty || !stdout_is_tty {
        return ConfirmationMode::Deny;
    }

    ConfirmationMode::Ask
}

/// Detect image file paths in a user message and load them as base64 data URIs.
///
/// Scans `input` for words ending in image extensions, resolves them relative
/// to `workspace`, reads the file, and returns `"data:<mime>;base64,<data>"` strings.
/// Silently skips files that don't exist or can't be read.
fn detect_and_encode_images(input: &str, workspace: &std::path::Path) -> Vec<String> {
    let image_exts: &[(&str, &str)] = &[
        (".png",  "image/png"),
        (".jpg",  "image/jpeg"),
        (".jpeg", "image/jpeg"),
        (".gif",  "image/gif"),
        (".webp", "image/webp"),
    ];

    let mut data_uris = Vec::new();

    for word in input.split_whitespace() {
        let lower = word.to_lowercase();
        let Some(mime) = image_exts.iter().find_map(|(ext, mime)| {
            if lower.ends_with(ext) { Some(*mime) } else { None }
        }) else {
            continue;
        };

        let path = if std::path::Path::new(word).is_absolute() {
            std::path::PathBuf::from(word)
        } else {
            workspace.join(word)
        };

        if let Ok(data) = std::fs::read(&path) {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD.encode(&data);
            data_uris.push(format!("data:{};base64,{}", mime, encoded));
            log::info!("Attached image: {} ({} bytes)", path.display(), data.len());
        }
    }

    data_uris
}

/// Run agent with streaming output.
///
/// Creates a channel, spawns a task to print stream chunks in real-time,
/// and returns the final response when complete.
///
/// Ctrl+C pressed during the run sets the agent's cancel flag, which
/// causes the run to stop cleanly at the next safe checkpoint. The cancel
/// flag is reset after the run so future runs are not affected.
async fn run_with_streaming(
    agent: &Agent,
    session_id: &str,
    task: &str,
    images: Option<Vec<String>>,
) -> Result<String> {
    // Create channel for streaming chunks
    let (tx, mut rx) = mpsc::channel::<StreamChunk>(100);

    // Wire Ctrl+C to the agent's cancellation flag for mid-run interruption.
    let cancel = agent.cancel_token();
    cancel.store(false, std::sync::atomic::Ordering::Relaxed); // ensure clean state
    let cancel_for_handler = Arc::clone(&cancel);
    let ctrlc_handle = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancel_for_handler.store(true, std::sync::atomic::Ordering::Relaxed);
            eprintln!("\n⛔ Cancelling run...");
        }
    });

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
                StreamChunk::LifecycleEvent { phase } if phase == "cancelled" => {
                    println!("\n[Run cancelled]");
                }
                StreamChunk::LifecycleEvent { .. } => {
                    // Other lifecycle events — silent for now
                }
                StreamChunk::Done(_) => {
                    // Final response received, stop streaming
                    break;
                }
            }
        }
    });

    // Run agent with streaming
    let response = agent.run_stream(session_id, task, images, tx).await;

    // Stop the Ctrl+C handler and reset cancel flag so future runs start clean.
    ctrlc_handle.abort();
    cancel.store(false, std::sync::atomic::Ordering::Relaxed);

    // Wait for print task to finish
    print_handle.await.ok();

    response
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
        .user_agent("ZapClaw-Updater")
        .build()?;

    let resp = client
        .get("https://api.github.com/repos/mkulariya/zapclaw/releases/latest")
        .send()
        .await
        .context("Failed to check for updates")?;

    if !resp.status().is_success() {
        println!("⚠️  Could not check for updates (HTTP {})", resp.status());
        println!("You can update manually:");
        println!("  git pull && cargo install --path zapclaw-cli --force");
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
        .args(["-c", "cd $(git rev-parse --show-toplevel 2>/dev/null || echo .) && git pull origin main && cargo install --path zapclaw-cli --force"])
        .output()
        .context("Failed to run update command")?;

    if output.status.success() {
        println!("✅ Updated successfully! Restart ZapClaw to use the new version.");
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("⚠️  Update had issues:\n{}", stderr);
        println!("Try manually: git pull && cargo install --path zapclaw-cli --force");
    }

    Ok(())
}

/// Resolve workspace path for sandbox bind mount (before full Config init).
fn resolve_workspace_for_sandbox(workspace_arg: &Option<String>) -> std::path::PathBuf {
    let ws_str = workspace_arg.as_ref().map(|s| s.as_str()).unwrap_or("./zapclaw_workspace");
    let path = std::path::PathBuf::from(ws_str);
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

/// Load .env files before anything else.
///
/// Precedence (highest to lowest):
///   shell env vars  >  ./.env  >  ~/.zapclaw/.env
///
/// Neither file overrides variables already set in the shell environment.
/// Both files are optional — missing files are silently ignored.
fn load_dotenv() {
    // ./.env — project-specific, takes priority over global
    if std::path::Path::new(".env").exists() {
        if let Err(e) = dotenvy::from_filename(".env") {
            eprintln!("Warning: Failed to parse .env: {}", e);
        }
    }

    // ~/.zapclaw/.env — global fallback
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok();
    if let Some(home) = home {
        let path = std::path::PathBuf::from(home).join(".zapclaw").join(".env");
        if path.exists() {
            if let Err(e) = dotenvy::from_path(&path) {
                eprintln!("Warning: Failed to parse {}: {}", path.display(), e);
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env files first — before env_logger (RUST_LOG) and Cli::parse() (env = "...")
    load_dotenv();

    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .init();

    let cli = Cli::parse();

    // Handle --init-config flag
    if cli.init_config {
        return handle_init_config(&cli);
    }

    // Resolve config mode and paths
    let cli_config_path = cli.config.as_deref().map(PathBuf::from);
    let (config_mode, config_paths) = Config::resolve_config_paths(cli_config_path.as_deref());

    // Auto-create home config if in layered mode and home doesn't exist
    if config_mode == "layered" {
        match Config::ensure_home_config_exists() {
            Ok(created) => {
                if created {
                    log::info!("✅ Created home config: {}", Config::resolve_home_config_path().display());
                }
            }
            Err(e) => {
                // Home config creation failed - this is critical for layered mode
                log::error!("⛔ Failed to create home config: {}", e);
                log::error!("ZapClaw requires a writable home directory for configuration.");
                log::error!("Home config path: {}", Config::resolve_home_config_path().display());
                return Err(e.context("Failed to create home config. \
                    You can bypass this by using --config <path> to specify an explicit config file."));
            }
        }
    }

    // Load and merge file configs
    let explicit_mode = config_mode == "explicit";
    let file_config = Config::load_and_merge_files(&config_paths, explicit_mode)
        .with_context(|| format!("Failed to load config from {:?}", config_paths))?;

    // Load env config
    let env_config = Config::from_env();

    // Merge file and env configs (precedence: Env > File > Defaults)
    let mut config = Config::from_sources(&file_config, &env_config);

    // Apply CLI overrides (highest precedence)
    if let Some(ws) = &cli.workspace {
        config.workspace_path = PathBuf::from(ws);
    }
    if let Some(url) = &cli.api_url {
        config.api_base_url = url.clone();
    }
    if let Some(model) = &cli.model_name {
        config.model_name = model.clone();
    }
    if let Some(steps) = cli.max_steps {
        config.max_steps = steps;
    }
    if let Some(timeout) = cli.tool_timeout {
        config.tool_timeout_secs = timeout;
    }
    if cli.no_confirm {
        config.require_confirmation = false;
    }
    if cli.no_egress_guard {
        config.enable_egress_guard = false;
    }
    if cli.enable_inbound {
        config.enable_inbound = true;
    }
    if let Some(port) = cli.inbound_port {
        config.inbound_port = port;
    }
    if let Some(bind) = &cli.inbound_bind {
        config.inbound_bind = bind.clone();
    }

    // Handle --print-effective-config flag
    if cli.print_effective_config {
        return handle_print_effective_config(&config);
    }

    // Self-update mode
    if cli.update {
        return self_update().await;
    }

    // Sandbox enforcement — must happen BEFORE workspace resolution.
    //
    // IMPORTANT: ensure_sandboxed() now implements FAIL-CLOSED behavior:
    // - If sandbox is verified (env + runtime evidence), returns Active
    // - If not verified but bwrap available, re-execs into sandbox (does NOT return)
    // - If not verified AND bwrap missing, returns HARD ERROR (fails closed)
    //
    // The --no-sandbox flag bypasses this and returns Disabled explicitly.
    let sandbox_state = if cli.no_sandbox {
        zapclaw_core::sandbox::SandboxState::Disabled
    } else {
        // Use the MERGED workspace path for sandbox bind mount, not CLI only
        let ws_path = resolve_workspace_for_sandbox(&Some(config.workspace_path.to_string_lossy().to_string()));
        zapclaw_core::sandbox::ensure_sandboxed(&ws_path, cli.sandbox_no_network)?
        // NOTE: If bwrap is available, ensure_sandboxed() does NOT return —
        // it replaces this process via exec(). If we reach here, we're
        // verified as sandboxed (Active).
    };

    // Resolve and validate LLM settings (fail fast on missing/invalid config)
    let llm_settings = resolve_llm_settings_from_config(&cli, &config)?;

    // Update config with resolved model name (for alias support)
    config.model_name = resolve_model_alias(&llm_settings.model_name);
    config.api_base_url = llm_settings.api_base_url.clone();

    // Resolve workspace
    let workspace = config.resolve_workspace()
        .context("Failed to initialize workspace")?;

    // Update config workspace_path with resolved canonical path
    config.workspace_path = workspace.clone();

    // Codex-style compact header
    let dir_display = {
        let path = workspace.display().to_string();
        if let Ok(home) = std::env::var("HOME") {
            if path.starts_with(&home) {
                format!("~{}", &path[home.len()..])
            } else {
                path
            }
        } else {
            path
        }
    };
    println!();
    println!("  >_ \x1b[1mZapClaw\x1b[0m  \x1b[2m(v{})\x1b[0m", env!("CARGO_PKG_VERSION"));
    println!();
    println!("  model:      {:<34}\x1b[2m/help for commands\x1b[0m", config.model_name);
    println!("  directory:  {}", dir_display);
    // Security warnings — only shown when protections are disabled
    if sandbox_state == zapclaw_core::sandbox::SandboxState::Disabled {
        println!();
        println!("  \x1b[1;33m⚠  sandbox disabled (--no-sandbox)\x1b[0m");
    }
    if !config.enable_egress_guard {
        println!("  \x1b[1;33m⚠  egress guard disabled (UNSAFE)\x1b[0m");
    }
    println!();

    // Initialize components
    let api_key = llm_settings.api_key;

    let llm: Arc<dyn zapclaw_core::llm::LlmClient> = Arc::new(
        OpenAiCompatibleClient::new(&config.api_base_url, &config.model_name, api_key.clone())
    );

    // File-based memory with SQLite indexing
    let memory = Arc::new(
        MemoryDb::new(&workspace)
            .context("Failed to initialize memory")?
    );

    // Validate memory configuration (security check)
    config.validate_memory_config()
        .map_err(|e| anyhow::anyhow!("Memory configuration validation failed: {}", e))?;

    // Start memory daemon if enabled
    let daemon_handle = if config.memory_daemon_enabled {
        log::info!("Starting memory daemon...");
        let daemon = zapclaw_core::memory_daemon::MemoryDaemon::start(
            &workspace,
            &config,
            memory.clone(),
        ).await
        .context("Failed to start memory daemon")?;

        // Create embedding provider for memory tools
        let provider = Arc::new(zapclaw_core::memory::EmbeddingProvider::new(
            &config.memory_embedding_base_url,
            &config.memory_embedding_model,
            None, // no API key for local Ollama
            config.memory_embedding_target_dims,
        ));

        Some((daemon, provider))
    } else {
        log::info!("Memory daemon disabled by config");
        None
    };

    let confiner = Confiner::new(&workspace)
        .context("Failed to initialize workspace confiner")?;

    // Register all tools
    let mut tools = ToolRegistry::new();

    // Core developer tools
    tools.register(Arc::new(FileTool::new(Arc::new(confiner.clone()))));
    tools.register(Arc::new(EditTool::new(confiner.clone())));
    tools.register(Arc::new(ExecTool::new(confiner.clone())));
    tools.register(Arc::new(GrepTool::new(confiner.clone())));
    tools.register(Arc::new(FindTool::new(confiner.clone())));
    tools.register(Arc::new(PatchTool::new(confiner.clone())));

    // Memory tools - use hybrid search only if daemon can use embeddings
    // This respects allow_lexical_fallback: checks both existing embeddings AND Ollama reachability
    let use_hybrid_search = if let Some((ref daemon, _)) = daemon_handle {
        daemon.can_use_embeddings()
    } else {
        false
    };

    if use_hybrid_search {
        if let Some((_, ref provider)) = daemon_handle {
            tools.register(Arc::new(
                zapclaw_tools::memory_tool::MemorySearchTool::with_provider(
                    memory.clone(),
                    provider.clone(),
                    config.memory_sync_on_search,
                    config.memory_require_embeddings,
                )
            ));
        }
    } else {
        // Lexical-only mode (either daemon disabled, no embeddings, or Ollama down with fallback allowed)
        log::info!("Memory search running in lexical-only mode (hybrid search disabled)");
        tools.register(Arc::new(
            zapclaw_tools::memory_tool::MemorySearchTool::new(memory.clone())
        ));
    }
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

    // Session status tool
    tools.register(Arc::new(
        SessionTool::new(
            memory.clone(),
            &config.model_name,
            vec![
                ("phi".to_string(), "phi3:mini".to_string()),
                ("gpt4".to_string(), "gpt-4o".to_string()),
                ("claude".to_string(), "claude-3.5-sonnet".to_string()),
                ("llama".to_string(), "llama3.1:8b".to_string()),
            ],
        )
    ));

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

    // Android device control (optional)
    if cli.enable_android {
        match AndroidTool::new(&workspace) {
            Ok(android_tool) => {
                tools.register(Arc::new(android_tool));
                println!("  Android:   Enabled (ADB device control)");
            }
            Err(e) => {
                eprintln!("  WARNING: Failed to initialize Android tool: {}", e);
                eprintln!("            Android control will not be available.");
            }
        }
    }

    let sandbox_active = sandbox_state == zapclaw_core::sandbox::SandboxState::Active;

    // Determine confirmation mode from CLI flags + terminal capabilities
    let stdin_is_tty = std::io::stdin().is_terminal();
    let stdout_is_tty = std::io::stdout().is_terminal();
    let confirmation_mode = resolve_confirmation_mode(
        cli.no_confirm,
        cli.enable_inbound,
        stdin_is_tty,
        stdout_is_tty,
    );

    match confirmation_mode {
        ConfirmationMode::Allow => {
            log::warn!("⚠️  Confirmation disabled via --no-confirm. Sensitive tools will execute WITHOUT approval.");
        }
        ConfirmationMode::Deny if cli.enable_inbound => {
            log::info!("🔒 Confirmation mode set to Deny (inbound/headless safety mode).");
        }
        ConfirmationMode::Deny => {
            log::warn!(
                "🔒 Non-interactive terminal detected (stdin_tty={}, stdout_tty={}). \
                 Confirmation mode set to Deny.",
                stdin_is_tty,
                stdout_is_tty
            );
        }
        ConfirmationMode::Ask => {}
    }

    // Extract inbound config values before moving config
    let inbound_bind = config.inbound_bind.clone();
    let inbound_port = config.inbound_port;

    let agent = Arc::new(
        Agent::new(llm, memory.clone(), tools, config, sandbox_active)
            .with_confirmation_mode(confirmation_mode)
    );

    let session_store = SessionStore::new(&workspace);
    let mut session_id = uuid::Uuid::new_v4().to_string();

    // Telegram bot integration (if enabled)
    if cli.enable_telegram {
        // Read env vars directly (no CLI flags for security)
        let token = std::env::var("ZAPCLAW_TELEGRAM_TOKEN")
            .context("ZAPCLAW_TELEGRAM_TOKEN environment variable must be set for Telegram mode")?;
        
        let allowed_ids_str = std::env::var("ZAPCLAW_TELEGRAM_ALLOWED_IDS")
            .context("ZAPCLAW_TELEGRAM_ALLOWED_IDS environment variable must be set for Telegram mode")?;
        
        // Capture count before moving
        let allowed_ids: Vec<i64> = allowed_ids_str
            .split(',')
            .map(|s| s.trim().parse::<i64>())
            .collect::<Result<Vec<_>, _>>()
            .context("Invalid user IDs in ZAPCLAW_TELEGRAM_ALLOWED_IDS (must be comma-separated numbers)")?;
        
        let allowed_count = allowed_ids.len();
        
        let telegram = TelegramListener::new(
            token,
            allowed_ids,
            agent.clone(),
            &workspace,
        ).context("Failed to initialize Telegram listener")?;
        
        // Run Telegram listener in background
        tokio::spawn(async move {
            if let Err(e) = telegram.run().await {
                log::error!("Telegram listener error: {}", e);
            }
        });
        
        println!("  Telegram:  Enabled ({} whitelisted user(s))", allowed_count);
    }

    // Single task mode — no cron loop needed
    if let Some(task) = cli.task {
        let images = {
            let uris = detect_and_encode_images(&task, &workspace);
            if uris.is_empty() { None } else { Some(uris) }
        };
        let response = run_with_streaming(&agent, &session_id, &task, images).await?;
        println!("\n{}", extract_final_response(&response));

        // Shutdown memory daemon if running
        if let Some((daemon, _)) = daemon_handle {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                daemon.shutdown(),
            ).await;
        }

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
            bind_address: inbound_bind.clone(),
            rpc_port: inbound_port,
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

        println!("  Inbound:    {}:{} (remote access enabled)", inbound_bind, inbound_port);
        println!();
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
    let rl_config = rustyline::Config::builder()
        .completion_type(rustyline::CompletionType::List)
        .build();
    let mut rl = rustyline::Editor::<ZapClawHelper, rustyline::history::DefaultHistory>::with_config(rl_config)
        .context("Failed to initialize line editor")?;
    rl.set_helper(Some(ZapClawHelper));

    loop {
        let readline = rl.readline("🦞 ❯ ");
        match readline {
            Ok(line) => {
                let input = line.trim();

                if input.is_empty() {
                    continue;
                }

                if input == "exit" || input == "quit" || input == "q" || input == "/exit" {
                    println!("👋 Goodbye!");
                    break;
                }

                if input == "help" || input == "/help" {
                    print_help();
                    continue;
                }

                if input == "tools" || input == "/tools" {
                    print_tools(&agent);
                    continue;
                }

                // /compact — compact the current session's conversation history
                if input == "/compact" {
                    match agent.compact_session(&session_id).await {
                        Ok(result) => {
                            if result.files_compacted == 0 {
                                println!("Nothing to compact — conversation history is short.");
                            } else {
                                println!(
                                    "Compacted {} messages, freed ~{} chars (~{} tokens)",
                                    result.files_compacted,
                                    result.chars_freed,
                                    result.chars_freed / 4,
                                );
                                if let (Some(before), Some(after)) = (result.tokens_before, result.tokens_after) {
                                    println!("  Context: ~{} tokens → ~{} tokens", before, after);
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
                    println!("  Session ID: {}", session_id);
                    println!("  Confirmation mode: {:?}\n", agent.confirmation_mode());
                    continue;
                }

                // /confirm command — change confirmation mode mid-session
                if input == "/confirm" || input.starts_with("/confirm ") {
                    let arg = input.strip_prefix("/confirm").unwrap_or("").trim();

                    if arg.is_empty() {
                        // Show current mode
                        let current = agent.confirmation_mode();
                        println!("\n🔒 Confirmation Mode: {:?}", current);
                        println!("  /confirm ask   → Prompt for each tool (default)");
                        println!("  /confirm allow → Auto-approve all tools (⚠️  DANGEROUS)");
                        println!("  /confirm deny  → Block all tools requiring confirmation\n");
                        continue;
                    }

                    let new_mode = match arg {
                        "ask" => {
                            println!("✅ Confirmation mode changed to: Ask (prompt for each tool)");
                            ConfirmationMode::Ask
                        }
                        "allow" => {
                            println!("⚠️  WARNING: Confirmation mode changed to: ALLOW");
                            println!("⚠️  All tools will auto-approve WITHOUT prompting!");
                            println!("⚠️  This is dangerous — use with caution!");
                            ConfirmationMode::Allow
                        }
                        "deny" => {
                            println!("🚫 Confirmation mode changed to: Deny (block all tools requiring confirmation)");
                            ConfirmationMode::Deny
                        }
                        _ => {
                            eprintln!("❌ Unknown mode: '{}'. Use: ask, allow, or deny", arg);
                            continue;
                        }
                    };

                    agent.set_confirmation_mode(new_mode);
                    continue;
                }

                rl.add_history_entry(input).ok();

                // Detect images referenced in user input and encode as data URIs
                let images = {
                    let uris = detect_and_encode_images(input, &workspace);
                    if uris.is_empty() { None } else { Some(uris) }
                };

                // Run the task with streaming
                match run_with_streaming(&agent, &session_id, input, images).await {
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

    // Shutdown memory daemon if running
    if let Some((daemon, _)) = daemon_handle {
        log::info!("Shutting down memory daemon...");
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            daemon.shutdown(),
        ).await;
    }

    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        cron_handle,
    ).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_cli(
        api_url: Option<&str>,
        model_name: Option<&str>,
        api_key: Option<&str>,
    ) -> Cli {
        Cli {
            config: None,
            init_config: false,
            print_effective_config: false,
            workspace: None,
            model_name: model_name.map(|s| s.to_string()),
            api_url: api_url.map(|s| s.to_string()),
            api_key: api_key.map(|s| s.to_string()),
            search_api_key: None,
            max_steps: None,
            task: None,
            no_confirm: false,
            no_egress_guard: false,
            no_sandbox: true,
            sandbox_no_network: false,
            tool_timeout: None,
            enable_inbound: false,
            enable_telegram: false,
            enable_android: false,
            inbound_port: None,
            inbound_bind: None,
            inbound_api_key: None,
            update: false,
        }
    }

    fn make_test_config(
        api_base_url: &str,
        model_name: &str,
    ) -> Config {
        Config {
            api_base_url: api_base_url.to_string(),
            model_name: model_name.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_is_strict_loopback() {
        // Case-insensitive hostname
        assert!(is_strict_loopback("localhost"));
        assert!(is_strict_loopback("LOCALHOST"));
        assert!(is_strict_loopback("LocalHost"));

        // IPv4 loopback
        assert!(is_strict_loopback("127.0.0.1"));
        assert!(is_strict_loopback("127.0.0.2"));
        assert!(is_strict_loopback("127.1.1.1"));

        // IPv6 loopback
        assert!(is_strict_loopback("::1"));
        assert!(is_strict_loopback("0:0:0:0:0:0:0:1"));

        // NOT loopback
        assert!(!is_strict_loopback("example.com"));
        assert!(!is_strict_loopback("192.168.1.1"));
        assert!(!is_strict_loopback("api.openai.com"));
        assert!(!is_strict_loopback("10.0.0.1"));
        assert!(!is_strict_loopback("172.16.0.1"));
    }

    #[test]
    fn test_resolve_llm_settings_from_config_cli_overrides_file() {
        let cli = make_test_cli(
            Some("http://cli.com/v1"),
            Some("cli-model"),
            Some("sk-test-key"), // Add API key since cli.com is not loopback
        );

        let config = make_test_config("http://file.com/v1", "file-model");

        let result = resolve_llm_settings_from_config(&cli, &config);
        assert!(result.is_ok());
        let settings = result.unwrap();
        // CLI should override config file
        assert_eq!(settings.api_base_url, "http://cli.com/v1");
        assert_eq!(settings.model_name, "cli-model");
    }

    #[test]
    fn test_resolve_llm_settings_from_config_fallback_to_file() {
        let cli = make_test_cli(None, None, None);

        let config = make_test_config("http://localhost:11434/v1", "phi3:mini");

        let result = resolve_llm_settings_from_config(&cli, &config);
        assert!(result.is_ok());
        let settings = result.unwrap();
        // Should use config file values
        assert_eq!(settings.api_base_url, "http://localhost:11434/v1");
        assert_eq!(settings.model_name, "phi3:mini");
    }

    #[test]
    fn test_resolve_llm_settings_from_config_missing_both() {
        let cli = make_test_cli(None, None, None);

        let config = Config {
            api_base_url: String::new(),
            model_name: String::new(),
            ..Default::default()
        };

        let result = resolve_llm_settings_from_config(&cli, &config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Missing required field: --api-url"));
    }

    #[test]
    fn test_resolve_llm_settings_from_config_invalid_scheme() {
        let cli = make_test_cli(
            Some("ftp://localhost:11434/v1"),
            Some("phi3:mini"),
            None,
        );

        let config = Config::default();

        let result = resolve_llm_settings_from_config(&cli, &config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid --api-url scheme"));
    }

    #[test]
    fn test_resolve_llm_settings_from_config_invalid_url() {
        let cli = make_test_cli(
            Some("not-a-url"),
            Some("phi3:mini"),
            None,
        );

        let config = Config::default();

        let result = resolve_llm_settings_from_config(&cli, &config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid --api-url") || err.contains("format"));
    }

    #[test]
    fn test_resolve_llm_settings_from_config_loopback_without_key() {
        let cli = make_test_cli(
            Some("http://localhost:11434/v1"),
            Some("phi3:mini"),
            None,
        );

        let config = Config::default();

        let result = resolve_llm_settings_from_config(&cli, &config);
        assert!(result.is_ok());
        let settings = result.unwrap();
        assert_eq!(settings.endpoint_kind, EndpointKind::Loopback);
        assert!(settings.api_key.is_none());
    }

    #[test]
    fn test_resolve_llm_settings_from_config_remote_without_key() {
        let cli = make_test_cli(
            Some("https://api.openai.com/v1"),
            Some("gpt-4o"),
            None,
        );

        let config = Config::default();

        let result = resolve_llm_settings_from_config(&cli, &config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("API key is required for remote endpoints"));
    }

    #[test]
    fn test_resolve_llm_settings_from_config_remote_with_key() {
        let cli = make_test_cli(
            Some("https://api.openai.com/v1"),
            Some("gpt-4o"),
            Some("sk-test-key"),
        );

        let config = Config::default();

        let result = resolve_llm_settings_from_config(&cli, &config);
        assert!(result.is_ok());
        let settings = result.unwrap();
        assert_eq!(settings.endpoint_kind, EndpointKind::Remote);
        assert_eq!(settings.api_key, Some("sk-test-key".to_string()));
    }

    #[test]
    fn test_resolve_llm_settings_from_config_empty_model_name() {
        let cli = make_test_cli(
            Some("http://localhost:11434/v1"),
            Some("   "),
            None,
        );

        let config = Config::default();

        let result = resolve_llm_settings_from_config(&cli, &config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("--model-name cannot be empty"));
    }

    #[test]
    fn test_cli_parser_rejects_model_mode() {
        // Test that --model-mode is not recognized (clap default behavior)
        let result = Cli::try_parse_from(["zapclaw", "--model-mode", "cloud"]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unexpected argument") || err.contains("unknown argument"));
    }

    #[test]
    fn test_cli_parser_rejects_short_m() {
        // Test that -m is not recognized (clap default behavior)
        let result = Cli::try_parse_from(["zapclaw", "-m", "cloud"]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unexpected argument") || err.contains("unknown argument"));
    }

    #[test]
    fn test_resolve_confirmation_mode_allow() {
        let mode = resolve_confirmation_mode(true, false, true, true);
        assert_eq!(mode, ConfirmationMode::Allow);
    }

    #[test]
    fn test_resolve_confirmation_mode_deny_inbound() {
        let mode = resolve_confirmation_mode(false, true, true, true);
        assert_eq!(mode, ConfirmationMode::Deny);
    }

    #[test]
    fn test_resolve_confirmation_mode_deny_non_interactive() {
        let mode = resolve_confirmation_mode(false, false, false, true);
        assert_eq!(mode, ConfirmationMode::Deny);

        let mode = resolve_confirmation_mode(false, false, true, false);
        assert_eq!(mode, ConfirmationMode::Deny);
    }

    #[test]
    fn test_resolve_confirmation_mode_ask_interactive() {
        let mode = resolve_confirmation_mode(false, false, true, true);
        assert_eq!(mode, ConfirmationMode::Ask);
    }
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

// ---------------------------------------------------------------------------
// REPL slash-command completion
// ---------------------------------------------------------------------------

/// All slash-prefixed REPL commands exposed in the completion menu.
static SLASH_COMMANDS: &[(&str, &str)] = &[
    ("/help",        "Show help and examples"),
    ("/tools",       "List available tools"),
    ("/status",      "Show session info (memory, tokens, session ID)"),
    ("/confirm",     "Show or change confirmation mode"),
    ("/compact",     "Compact conversation history (LLM summarisation)"),
    ("/resume",      "List or resume a previous session"),
    ("/update",      "Self-update ZapClaw from git"),
    ("/exit",        "Exit ZapClaw"),
];

/// Sub-commands for `/confirm`, shown when the user types `/confirm ` + Tab.
static CONFIRM_SUBCOMMANDS: &[(&str, &str)] = &[
    ("ask",   "Prompt for each tool requiring confirmation (default)"),
    ("allow", "Auto-approve all tools — DANGEROUS"),
    ("deny",  "Block all tools requiring confirmation"),
];

struct ZapClawHelper;

impl Completer for ZapClawHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        if !line.starts_with('/') {
            return Ok((0, vec![]));
        }

        // Sub-command completion: `/confirm <tab>` or `/confirm a<tab>`
        if line.starts_with("/confirm ") {
            let sub_prefix = &line["/confirm ".len()..pos];
            let matches: Vec<Pair> = CONFIRM_SUBCOMMANDS
                .iter()
                .filter(|(sub, _)| sub.starts_with(sub_prefix))
                .map(|(sub, desc)| Pair {
                    display: format!("{:<8}  {}", sub, desc),
                    replacement: format!("/confirm {}", sub),
                })
                .collect();
            return Ok((0, matches));
        }

        // Top-level slash command completion
        let prefix = &line[..pos];
        let matches: Vec<Pair> = SLASH_COMMANDS
            .iter()
            .filter(|(cmd, _)| cmd.starts_with(prefix))
            .map(|(cmd, desc)| Pair {
                display: format!("{:<14}  {}", cmd, desc),
                replacement: cmd.to_string(),
            })
            .collect();
        Ok((0, matches))
    }
}

impl Hinter for ZapClawHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, _ctx: &rustyline::Context<'_>) -> Option<String> {
        if !line.starts_with('/') || pos != line.len() || line.len() < 2 {
            return None;
        }
        // Inline hint for `/confirm <partial>`
        if line.starts_with("/confirm ") {
            let sub = &line["/confirm ".len()..];
            return CONFIRM_SUBCOMMANDS
                .iter()
                .find(|(cmd, _)| cmd.starts_with(sub) && *cmd != sub)
                .map(|(cmd, _)| cmd[sub.len()..].to_string());
        }
        // Inline hint for top-level commands
        SLASH_COMMANDS
            .iter()
            .find(|(cmd, _)| cmd.starts_with(line) && *cmd != line)
            .map(|(cmd, _)| cmd[pos..].to_string())
    }
}

impl Highlighter for ZapClawHelper {
    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        Cow::Owned(format!("\x1b[2m{}\x1b[0m", hint))
    }

    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        if line.starts_with('/') {
            Cow::Owned(format!("\x1b[36m{}\x1b[0m", line))
        } else {
            Cow::Borrowed(line)
        }
    }

    fn highlight_char(&self, line: &str, _pos: usize, _forced: bool) -> bool {
        line.starts_with('/')
    }
}

impl Validator for ZapClawHelper {}
impl Helper for ZapClawHelper {}

// ---------------------------------------------------------------------------

fn print_help() {
    println!("
🦞 ZapClaw Help
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Just type your request and ZapClaw will help!

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

  Commands:             (type / then Tab to browse)
    /help         Show this help
    /tools        List available tools
    /status       Show session info (memory, tokens, session ID)
    /confirm      Show or change confirmation mode (ask/allow/deny)
    /compact      Compact conversation history (LLM summarisation)
    /resume       List recent sessions
    /resume <id>  Resume a specific session
    /update       Self-update from git
    /exit         Exit ZapClaw  (also: exit, quit, q)

  Skills:
    Place SKILL.md files in .skills/<name>/SKILL.md
    ZapClaw will auto-discover and use them.

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
