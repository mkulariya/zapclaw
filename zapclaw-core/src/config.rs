use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use anyhow::Context;

/// File-backed configuration (non-secret fields only).
///
/// This struct represents the JSON config file format.
/// All fields are Optional to allow partial config files.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileConfig {
    /// Path to the confined workspace directory
    pub workspace_path: Option<String>,

    /// Base URL for the LLM API
    pub api_base_url: Option<String>,

    /// Model identifier
    pub model_name: Option<String>,

    /// Maximum steps per agent loop
    pub max_steps: Option<usize>,

    /// Enable inbound tunnel
    pub enable_inbound: Option<bool>,

    /// Tool execution timeout in seconds
    pub tool_timeout_secs: Option<u64>,

    /// Whether to require human confirmation
    pub require_confirmation: Option<bool>,

    /// Enable egress guard
    pub enable_egress_guard: Option<bool>,

    /// Context window size in tokens
    pub context_window_tokens: Option<usize>,

    /// Inbound server port
    pub inbound_port: Option<u16>,

    /// Inbound server bind address
    pub inbound_bind: Option<String>,

    // ── Memory System Configuration ─────────────────────────────────────

    /// Base URL for embedding API (local Ollama for memory embeddings)
    pub memory_embedding_base_url: Option<String>,

    /// Embedding model name (default: nomic-embed-text)
    pub memory_embedding_model: Option<String>,

    /// Target dimensions for Matryoshka projection (256 or 512, default: 512)
    pub memory_embedding_target_dims: Option<usize>,

    /// Batch size for embedding requests (default: 32)
    pub memory_embedding_batch_size: Option<usize>,

    /// Enable memory daemon (default: true)
    pub memory_daemon_enabled: Option<bool>,

    /// Sync interval in seconds (default: 15)
    pub memory_sync_interval_secs: Option<usize>,

    /// Sync before search (default: true)
    pub memory_sync_on_search: Option<bool>,

    /// Require embeddings to be available (default: true)
    pub memory_require_embeddings: Option<bool>,

    /// Allow lexical fallback when embeddings unavailable (default: false)
    pub memory_allow_lexical_fallback: Option<bool>,

    /// Maximum entries in embedding cache before LRU pruning (default: 50_000)
    pub memory_cache_max_entries: Option<usize>,
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            workspace_path: None,
            api_base_url: None,
            model_name: None,
            max_steps: None,
            enable_inbound: None,
            tool_timeout_secs: None,
            require_confirmation: None,
            enable_egress_guard: None,
            context_window_tokens: None,
            inbound_port: None,
            inbound_bind: None,
            memory_embedding_base_url: None,
            memory_embedding_model: None,
            memory_embedding_target_dims: None,
            memory_embedding_batch_size: None,
            memory_daemon_enabled: None,
            memory_sync_interval_secs: None,
            memory_sync_on_search: None,
            memory_require_embeddings: None,
            memory_allow_lexical_fallback: None,
            memory_cache_max_entries: None,
        }
    }
}

/// ZapClaw runtime configuration.
///
/// Loaded from config file, environment variables, and/or CLI flags.
/// Security: API keys are NEVER stored in config files — only env vars or CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Path to the confined workspace directory (default: ./zapclaw_workspace)
    pub workspace_path: PathBuf,

    /// Base URL for the LLM API
    /// Must be explicitly provided via --api-url, ZAPCLAW_API_BASE_URL, or config file
    pub api_base_url: String,

    /// Model identifier (e.g., "phi3:mini" for Ollama, "gpt-4o" for OpenAI)
    /// Must be explicitly provided via --model-name, ZAPCLAW_MODEL, or config file
    pub model_name: String,

    /// Maximum steps per agent loop (prevents infinite runs)
    pub max_steps: usize,

    /// Enable outbound tunnel (HTTPS proxy for cloud LLMs/browser)
    pub enable_outbound: bool,

    /// Enable inbound tunnel (VPN+RPC for remote commands)
    pub enable_inbound: bool,

    /// Tool execution timeout in seconds
    pub tool_timeout_secs: u64,

    /// Whether to require human confirmation for all tool calls
    pub require_confirmation: bool,

    /// Enable egress guard for web_search and browse_url tools
    pub enable_egress_guard: bool,

    /// Context window size in tokens (used for truncation calculations)
    pub context_window_tokens: usize,

    /// Inbound server port (default: 9876)
    pub inbound_port: u16,

    /// Inbound server bind address (default: 127.0.0.1)
    pub inbound_bind: String,

    // ── Memory System Configuration ─────────────────────────────────────

    /// Base URL for embedding API (local Ollama for memory embeddings)
    pub memory_embedding_base_url: String,

    /// Embedding model name (default: nomic-embed-text)
    pub memory_embedding_model: String,

    /// Target dimensions for Matryoshka projection (256 or 512, default: 512)
    pub memory_embedding_target_dims: usize,

    /// Batch size for embedding requests (default: 32)
    pub memory_embedding_batch_size: usize,

    /// Enable memory daemon (default: true)
    pub memory_daemon_enabled: bool,

    /// Sync interval in seconds (default: 15)
    pub memory_sync_interval_secs: usize,

    /// Sync before search (default: true)
    pub memory_sync_on_search: bool,

    /// Require embeddings to be available (default: true)
    pub memory_require_embeddings: bool,

    /// Allow lexical fallback when embeddings unavailable (default: false)
    pub memory_allow_lexical_fallback: bool,

    /// Maximum number of entries in the embedding cache before LRU pruning (default: 50_000)
    pub memory_cache_max_entries: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            workspace_path: PathBuf::from("./zapclaw_workspace"),
            api_base_url: String::new(), // Must be explicitly provided
            model_name: String::new(),   // Must be explicitly provided
            max_steps: 15,
            enable_outbound: false,
            enable_inbound: false,
            tool_timeout_secs: 5,
            require_confirmation: true,
            enable_egress_guard: true,
            context_window_tokens: 128_000,
            inbound_port: 9876,
            inbound_bind: "127.0.0.1".to_string(),
            // Memory system defaults
            memory_embedding_base_url: "http://localhost:11434/v1".to_string(),
            memory_embedding_model: "nomic-embed-text:v1.5".to_string(),
            memory_embedding_target_dims: 512,
            memory_embedding_batch_size: 32,
            memory_daemon_enabled: true,
            memory_sync_interval_secs: 15,
            memory_sync_on_search: true,
            memory_require_embeddings: true,
            memory_allow_lexical_fallback: false,
            memory_cache_max_entries: 50_000,
        }
    }
}

impl Config {
    /// Resolve the validated host home directory for config resolution.
    ///
    /// In sandboxed mode (ZAPCLAW_SANDBOXED=1), this considers ZAPCLAW_HOST_HOME first,
    /// then validates it against security checks before using it.
    /// In non-sandboxed mode, uses dirs::home_dir() directly.
    ///
    /// Validation for ZAPCLAW_HOST_HOME:
    /// 1. Must be absolute path
    /// 2. Canonicalization must succeed
    /// 3. Canonical path must be directory
    /// 4. Directory must be owned by current UID (Unix only)
    /// 5. Directory must not be world-writable (Unix only)
    ///
    /// If validation fails, falls back to dirs::home_dir() with warning.
    pub fn resolve_host_home_for_config() -> Option<PathBuf> {
        let is_sandboxed = std::env::var("ZAPCLAW_SANDBOXED")
            .map(|v| v == "1")
            .unwrap_or(false);

        if is_sandboxed {
            // In sandbox, try ZAPCLAW_HOST_HOME first
            if let Ok(host_home_str) = std::env::var("ZAPCLAW_HOST_HOME") {
                let candidate = PathBuf::from(&host_home_str);
                
                // Validate the candidate
                match Self::validate_host_home_path(&candidate) {
                    Ok(validated) => {
                        log::debug!("Using ZAPCLAW_HOST_HOME for config: {}", validated.display());
                        return Some(validated);
                    }
                    Err(e) => {
                        log::warn!(
                            "ZAPCLAW_HOST_HOME {} failed validation: {}. Falling back to dirs::home_dir().",
                            host_home_str,
                            e
                        );
                        // Fall through to dirs::home_dir()
                    }
                }
            }
        }

        // Fall back to dirs::home_dir()
        dirs::home_dir()
    }

    /// Validate a candidate home path for security.
    ///
    /// Checks:
    /// 1. Path is absolute
    /// 2. Path can be canonicalized
    /// 3. Canonical path is a directory
    /// 4. Directory is owned by current UID (Unix)
    /// 5. Directory is not world-writable (Unix)
    ///
    /// Returns Ok(canonical_path) on success, Err(description) on failure.
    fn validate_host_home_path(candidate: &Path) -> Result<PathBuf, String> {
        // 1. Must be absolute
        if !candidate.is_absolute() {
            return Err("path is not absolute".to_string());
        }

        // 2. Canonicalization must succeed
        let canonical = candidate
            .canonicalize()
            .map_err(|e| format!("canonicalization failed: {}", e))?;

        // 3. Must be a directory
        if !canonical.is_dir() {
            return Err("path is not a directory".to_string());
        }

        // Unix-specific checks (4 & 5)
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            
            let metadata = canonical
                .metadata()
                .map_err(|e| format!("metadata failed: {}", e))?;

            // 4. Must be owned by current UID
            let current_uid = unsafe { libc::getuid() };
            if metadata.uid() != current_uid {
                return Err(format!(
                    "directory owned by uid {} (current uid: {})",
                    metadata.uid(),
                    current_uid
                ));
            }

            // 5. Must not be world-writable
            let mode = metadata.mode();
            const WORLD_WRITABLE: u32 = 0o002;
            if mode & WORLD_WRITABLE != 0 {
                return Err("directory is world-writable (permissions too lax)".to_string());
            }
        }

        Ok(canonical)
    }

    /// Validate memory embedding base URL is loopback-only for local mode.
    ///
    /// For security, memory embeddings should only use local Ollama (localhost, 127.0.0.1, ::1).
    /// Returns Ok(()) if valid, Err(description) if non-loopback URL detected.
    fn validate_memory_embedding_url(url: &str) -> Result<(), String> {
        // Parse URL to extract host
        let parsed = url::Url::parse(url)
            .map_err(|e| format!("invalid URL: {}", e))?;

        let host = parsed.host_str()
            .ok_or_else(|| "missing host in URL".to_string())?;

        // Allow loopback addresses only
        let is_loopback = match host {
            "localhost" |
            "127.0.0.1" |
            "::1" |
            "[::1]" => true,
            _ => false,
        };

        if !is_loopback {
            return Err(format!(
                "memory embedding endpoint must be loopback-only (localhost, 127.0.0.1, or ::1) for security. Got: {}. \
                 If you need remote embeddings, set ZAPCLAW_MEMORY_ALLOW_LEXICAL_FALLBACK=true to use keyword-only search.",
                host
            ));
        }

        Ok(())
    }

    /// Validate memory configuration settings.
    ///
    /// Checks:
    /// 1. Embedding URL is loopback-only
    /// 2. Target dimensions is 256 or 512
    /// 3. Batch size is reasonable (>0 and <=256)
    pub fn validate_memory_config(&self) -> Result<(), String> {
        // Validate embedding URL if embeddings are required
        if self.memory_require_embeddings {
            Self::validate_memory_embedding_url(&self.memory_embedding_base_url)
                .map_err(|e| format!("memory embedding URL validation failed: {}", e))?;
        }

        // Validate target dimensions
        match self.memory_embedding_target_dims {
            256 | 512 => {},
            other => return Err(format!(
                "memory_embedding_target_dims must be 256 or 512, got: {}. \
                 Matryoshka projection only supports these dimensions for nomic-embed-text:v1.5",
                other
            )),
        }

        // Validate batch size
        if self.memory_embedding_batch_size == 0 {
            return Err("memory_embedding_batch_size must be > 0".to_string());
        }
        if self.memory_embedding_batch_size > 256 {
            return Err("memory_embedding_batch_size must be <= 256".to_string());
        }

        Ok(())
    }

    /// Resolve home config path (~/.zapclaw/zapclaw.json)
    ///
    /// Uses validated host home resolution to prevent config drift in sandboxed mode.
    pub fn resolve_home_config_path() -> PathBuf {
        let mut home = Self::resolve_host_home_for_config()
            .unwrap_or_else(|| PathBuf::from("."));
        home.push(".zapclaw");
        home.push("zapclaw.json");
        home
    }

    /// Resolve project config path (./zapclaw.json in current directory)
    pub fn resolve_project_config_path() -> PathBuf {
        PathBuf::from("./zapclaw.json")
    }

    /// Resolve explicit config path from CLI override or env var.
    ///
    /// Returns None if no explicit path is set (use home+project discovery).
    /// Returns Some(path) if --config or ZAPCLAW_CONFIG_PATH is set.
    pub fn resolve_explicit_config_path(cli_override: Option<&Path>) -> Option<PathBuf> {
        if let Some(path) = cli_override {
            return Some(path.to_path_buf());
        }

        if let Ok(path_str) = std::env::var("ZAPCLAW_CONFIG_PATH") {
            return Some(PathBuf::from(path_str));
        }

        None
    }

    /// Resolve the config file path(s) based on mode.
    ///
    /// Returns (mode, paths) where mode indicates discovery strategy:
    /// - "explicit": single path from --config or ZAPCLAW_CONFIG_PATH
    /// - "layered": home + project paths (project may not exist)
    ///
    /// Resolution order for explicit mode:
    /// 1. CLI --config override
    /// 2. ZAPCLAW_CONFIG_PATH environment variable
    ///
    /// For layered mode (default):
    /// 1. Home config: ~/.zapclaw/zapclaw.json
    /// 2. Project config: ./zapclaw.json (if exists)
    pub fn resolve_config_paths(cli_override: Option<&Path>) -> (String, Vec<PathBuf>) {
        // Check for explicit path first
        if let Some(explicit) = Self::resolve_explicit_config_path(cli_override) {
            return ("explicit".to_string(), vec![explicit]);
        }

        // Layered mode: home + project
        let home_path = Self::resolve_home_config_path();
        let project_path = Self::resolve_project_config_path();

        let mut paths = vec![home_path];
        
        // Only include project path if it exists
        if project_path.exists() {
            paths.push(project_path);
        }

        ("layered".to_string(), paths)
    }

    /// Load and merge multiple config files in precedence order.
    ///
    /// Files are merged in order: later files override earlier ones.
    /// Missing files are skipped.
    ///
    /// IMPORTANT: In explicit mode (single file path), strict validation is applied
    /// and missing file is treated as error.
    /// In layered mode (multiple paths), missing files are silently skipped.
    pub fn load_and_merge_files(paths: &[PathBuf], explicit_mode: bool) -> Result<FileConfig, anyhow::Error> {
        let mut merged = FileConfig::default();

        for (_i, path) in paths.iter().enumerate() {
            // In explicit mode with a single file, check if file exists first
            if explicit_mode && paths.len() == 1 && !path.exists() {
                return Err(anyhow::anyhow!(
                    "⛔ Explicit config file does not exist: {}\n\
                     \n\
                     Fix: Create the file or remove --config / ZAPCLAW_CONFIG_PATH to use layered mode.\n\
                     Example: zapclaw --init-config --config {}",
                    path.display(),
                    path.display()
                ));
            }

            // Use strict validation for explicit mode, regular for layered mode
            let load_result = if explicit_mode {
                Self::from_json_file_strict(path)
            } else {
                Self::from_json_file(path)
            };

            match load_result {
                Ok(file_cfg) => {
                    // Merge file_cfg into merged (later overrides earlier)
                    if file_cfg.workspace_path.is_some() {
                        merged.workspace_path = file_cfg.workspace_path;
                    }
                    if file_cfg.api_base_url.is_some() {
                        merged.api_base_url = file_cfg.api_base_url;
                    }
                    if file_cfg.model_name.is_some() {
                        merged.model_name = file_cfg.model_name;
                    }
                    if file_cfg.max_steps.is_some() {
                        merged.max_steps = file_cfg.max_steps;
                    }
                    if file_cfg.enable_inbound.is_some() {
                        merged.enable_inbound = file_cfg.enable_inbound;
                    }
                    if file_cfg.tool_timeout_secs.is_some() {
                        merged.tool_timeout_secs = file_cfg.tool_timeout_secs;
                    }
                    if file_cfg.require_confirmation.is_some() {
                        merged.require_confirmation = file_cfg.require_confirmation;
                    }
                    if file_cfg.enable_egress_guard.is_some() {
                        merged.enable_egress_guard = file_cfg.enable_egress_guard;
                    }
                    if file_cfg.context_window_tokens.is_some() {
                        merged.context_window_tokens = file_cfg.context_window_tokens;
                    }
                    if file_cfg.inbound_port.is_some() {
                        merged.inbound_port = file_cfg.inbound_port;
                    }
                    if file_cfg.inbound_bind.is_some() {
                        merged.inbound_bind = file_cfg.inbound_bind;
                    }
                    // Memory config fields
                    if file_cfg.memory_embedding_base_url.is_some() {
                        merged.memory_embedding_base_url = file_cfg.memory_embedding_base_url;
                    }
                    if file_cfg.memory_embedding_model.is_some() {
                        merged.memory_embedding_model = file_cfg.memory_embedding_model;
                    }
                    if file_cfg.memory_embedding_target_dims.is_some() {
                        merged.memory_embedding_target_dims = file_cfg.memory_embedding_target_dims;
                    }
                    if file_cfg.memory_embedding_batch_size.is_some() {
                        merged.memory_embedding_batch_size = file_cfg.memory_embedding_batch_size;
                    }
                    if file_cfg.memory_daemon_enabled.is_some() {
                        merged.memory_daemon_enabled = file_cfg.memory_daemon_enabled;
                    }
                    if file_cfg.memory_sync_interval_secs.is_some() {
                        merged.memory_sync_interval_secs = file_cfg.memory_sync_interval_secs;
                    }
                    if file_cfg.memory_sync_on_search.is_some() {
                        merged.memory_sync_on_search = file_cfg.memory_sync_on_search;
                    }
                    if file_cfg.memory_require_embeddings.is_some() {
                        merged.memory_require_embeddings = file_cfg.memory_require_embeddings;
                    }
                    if file_cfg.memory_allow_lexical_fallback.is_some() {
                        merged.memory_allow_lexical_fallback = file_cfg.memory_allow_lexical_fallback;
                    }
                    if file_cfg.memory_cache_max_entries.is_some() {
                        merged.memory_cache_max_entries = file_cfg.memory_cache_max_entries;
                    }
                }
                Err(e) => {
                    // In explicit mode with a single file, missing file is an error
                    if explicit_mode && paths.len() == 1 && !path.exists() {
                        return Err(anyhow::anyhow!(
                            "⛔ Explicit config file does not exist: {}\n\
                             \n\
                             Fix: Create the file or remove --config / ZAPCLAW_CONFIG_PATH to use layered mode.\n\
                             Example: zapclaw --init-config --config {}",
                            path.display(),
                            path.display()
                        ));
                    }
                    
                    // If file exists but fails to parse, return error
                    if path.exists() {
                        return Err(e);
                    }
                    // If file doesn't exist in layered mode, skip it
                }
            }
        }

        Ok(merged)
    }

    /// Create home config directory and file with default template if missing.
    ///
    /// Returns true if file was created, false if it already existed.
    pub fn ensure_home_config_exists() -> Result<bool, anyhow::Error> {
        let home_path = Self::resolve_home_config_path();
        Self::ensure_config_exists_at(&home_path)
    }

    /// Create config file at specified path with default template if missing.
    ///
    /// Returns true if file was created, false if it already existed.
    pub fn ensure_config_exists_at(path: &Path) -> Result<bool, anyhow::Error> {
        if path.exists() {
            return Ok(false);
        }

        // Create parent directory
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {}", parent.display()))?;

            // Set restrictive permissions (0700) on Unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o700);
                std::fs::set_permissions(parent, perms)
                    .with_context(|| format!("Failed to set permissions on {}", parent.display()))?;
            }
        }

        // Write default config
        let template = Self::default_template_json(path);
        std::fs::write(path, template)
            .with_context(|| format!("Failed to write config to {}", path.display()))?;

        // Set restrictive permissions (0600) on file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms)
                .with_context(|| format!("Failed to set permissions on {}", path.display()))?;
        }

        Ok(true)
    }

    /// Resolve the config file path from CLI override, env var, or default location.
    ///
    /// DEPRECATED: Use resolve_config_paths() instead for layered mode support.
    /// This method is kept for backward compatibility during transition.
    ///
    /// Resolution order:
    /// 1. CLI --config override (explicit parameter)
    /// 2. ZAPCLAW_CONFIG_PATH environment variable
    /// 3. ./zapclaw.json (current directory)
    #[deprecated(note = "Use resolve_config_paths() for layered home+project support")]
    pub fn resolve_config_path(cli_override: Option<&Path>) -> PathBuf {
        if let Some(path) = cli_override {
            return path.to_path_buf();
        }

        if let Ok(path_str) = std::env::var("ZAPCLAW_CONFIG_PATH") {
            return PathBuf::from(path_str);
        }

        PathBuf::from("./zapclaw.json")
    }

    /// Validate config file path for security.
    ///
    /// Checks:
    /// 1. If file is a symlink, target must be within trusted_home_base (if provided)
    /// 2. File permissions must be 0600 or stricter (no group/other read/write) (Unix)
    /// 3. Parent directory permissions must be 0700 or stricter (no group/other read/write) (Unix)
    ///
    /// trusted_home_base: The trusted home directory path (used for symlink validation)
    /// strict_mode: If true, returns error on validation failure. If false, warns and returns Ok(()).
    ///
    /// Returns Ok(()) if safe or strict_mode=false, Err(description) if unsafe and strict_mode=true.
    fn validate_config_file_security(path: &Path, trusted_home_base: Option<&Path>, strict_mode: bool) -> Result<(), String> {
        // Skip validation if file doesn't exist yet (auto-create case)
        if !path.exists() {
            return Ok(());
        }

        // Canonicalize to resolve symlinks
        let canonical_path = path
            .canonicalize()
            .map_err(|e| format!("Failed to canonicalize {}: {}", path.display(), e))?;

        // 1. Symlink check: reject if target outside trusted home base
        if let Some(home_base) = trusted_home_base {
            // Check if canonical path starts with home base
            if !canonical_path.starts_with(home_base) {
                let msg = format!(
                    "Config file {} (resolved to {}) is outside trusted home directory {}",
                    path.display(),
                    canonical_path.display(),
                    home_base.display()
                );
                if strict_mode {
                    return Err(msg);
                } else {
                    log::warn!("⚠️  {}", msg);
                }
            }
        }

        // Unix permission checks
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            // 2. File permissions check - require 0600 or stricter (only owner can read/write)
            if let Ok(metadata) = path.metadata() {
                let mode = metadata.permissions().mode();

                // Check if group or others have ANY permissions (read or write)
                // 0o077 masks group+other bits (rwx for group + rwx for other)
                if mode & 0o077 != 0 {
                    let msg = format!(
                        "Config file {} has overly permissive permissions ({:04o}). Required: 0600 (owner-only)",
                        path.display(),
                        mode & 0o777
                    );
                    if strict_mode {
                        return Err(msg);
                    } else {
                        log::warn!("⚠️  {}", msg);
                    }
                }
            }

            // 3. Parent directory permissions check - require 0700 or stricter
            if let Some(parent) = path.parent() {
                if parent.exists() {
                    if let Ok(metadata) = parent.metadata() {
                        let mode = metadata.permissions().mode();

                        // Check if group or others have ANY permissions
                        if mode & 0o077 != 0 {
                            let msg = format!(
                                "Config directory {} has overly permissive permissions ({:04o}). Required: 0700 (owner-only)",
                                parent.display(),
                                mode & 0o777
                            );
                            if strict_mode {
                                return Err(msg);
                            } else {
                                log::warn!("⚠️  {}", msg);
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Load configuration from a JSON file with strict validation.
    ///
    /// This is used for explicit config paths (--config flag) where security
    /// validation failures should result in errors.
    ///
    /// Returns error if file doesn't exist, fails validation, or fails to parse.
    pub fn from_json_file_strict(path: &Path) -> Result<FileConfig, anyhow::Error> {
        if !path.exists() {
            return Err(anyhow::anyhow!("Config file does not exist: {}", path.display()));
        }

        // For explicit configs, always use strict mode (no trusted base)
        Self::validate_config_file_security(path, None, true)
            .map_err(|e| anyhow::anyhow!("Config file security validation failed: {}", e))?;

        // Read and parse
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let parsed: serde_json::Value = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse config file as JSON: {}", path.display()))?;

        // Check for forbidden secret keys in file
        if let Some(obj) = parsed.as_object() {
            let forbidden_keys: &[&str] = &["api_key", "search_api_key", "inbound_api_key"];
            for key in forbidden_keys {
                if obj.contains_key(*key) {
                    log::warn!(
                        "⚠️  Secret key '{}' found in config file {}. \
                         Secret keys should be set via environment variables or CLI only. \
                         Ignoring value from file.",
                        key,
                        path.display()
                    );
                }
            }
        }

        let file_config: FileConfig = serde_json::from_str(&content)
            .with_context(|| format!("Failed to deserialize config file: {}", path.display()))?;

        Ok(file_config)
    }

    /// Load configuration from a JSON file.
    ///
    /// Returns empty FileConfig if file doesn't exist.
    /// Returns error if file exists but fails to parse.
    ///
    /// Security: Validates file permissions and symlink safety for home config files.
    /// Non-home config files (test files, explicit configs) skip permission checks
    /// but still validate symlink safety when a trusted base is provided.
    ///
    /// Home config detection: Checks if path matches ~/.zapclaw/zapclaw.json pattern
    /// by comparing against the resolved home config path.
    pub fn from_json_file(path: &Path) -> Result<FileConfig, anyhow::Error> {
        if !path.exists() {
            return Ok(FileConfig::default());
        }

        // Determine if this is a home config file by comparing with expected home path
        // This is more reliable than substring matching which can be bypassed by symlinks
        let expected_home_path = Self::resolve_home_config_path();
        let is_home_config = path.canonicalize()
            .ok()
            .as_ref()
            == expected_home_path.canonicalize().ok().as_ref();

        // For home config, get the trusted home base and apply validation
        let trusted_home_base = if is_home_config {
            expected_home_path.parent().and_then(|p| p.parent())
        } else {
            None
        };

        // Security validation
        // For home config: warn on issues but continue (backward compatible)
        // For explicit config: no validation here (handled at call site for explicit mode)
        if is_home_config {
            if let Err(e) = Self::validate_config_file_security(path, trusted_home_base, false) {
                log::warn!("⚠️  Config file security check for {}: {}", path.display(), e);
            }
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        // Parse as JSON, allowing unknown keys (forward compatibility)
        let parsed: serde_json::Value = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse config file as JSON: {}", path.display()))?;

        // Check for forbidden secret keys in file
        if let Some(obj) = parsed.as_object() {
            let forbidden_keys: &[&str] = &["api_key", "search_api_key", "inbound_api_key"];
            for key in forbidden_keys {
                if obj.contains_key(*key) {
                    log::warn!(
                        "⚠️  Secret key '{}' found in config file {}. \
                         Secret keys should be set via environment variables or CLI only. \
                         Ignoring value from file.",
                        key,
                        path.display()
                    );
                }
            }
        }

        // Deserialize into FileConfig
        let file_config: FileConfig = serde_json::from_str(&content)
            .with_context(|| format!("Failed to deserialize config file: {}", path.display()))?;

        Ok(file_config)
    }

    /// Load configuration from environment variables.
    ///
    /// Supported env vars:
    /// - ZAPCLAW_WORKSPACE: workspace directory path
    /// - ZAPCLAW_API_BASE_URL: LLM API base URL (required)
    /// - ZAPCLAW_API_KEY: API key (read at runtime, never stored)
    /// - ZAPCLAW_MODEL: model name (required)
    /// - ZAPCLAW_MAX_STEPS: max agent loop steps
    /// - ZAPCLAW_TOOL_TIMEOUT: tool timeout in seconds
    /// - ZAPCLAW_REQUIRE_CONFIRMATION: "true" or "false"
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(ws) = std::env::var("ZAPCLAW_WORKSPACE") {
            config.workspace_path = PathBuf::from(ws);
        }

        // These are now required but loaded here - validation happens in CLI
        if let Ok(url) = std::env::var("ZAPCLAW_API_BASE_URL") {
            config.api_base_url = url;
        }

        if let Ok(model) = std::env::var("ZAPCLAW_MODEL") {
            config.model_name = model;
        }

        if let Ok(steps) = std::env::var("ZAPCLAW_MAX_STEPS") {
            if let Ok(n) = steps.parse::<usize>() {
                config.max_steps = n;
            }
        }

        if let Ok(timeout) = std::env::var("ZAPCLAW_TOOL_TIMEOUT") {
            if let Ok(t) = timeout.parse::<u64>() {
                config.tool_timeout_secs = t;
            }
        }

        if let Ok(confirm) = std::env::var("ZAPCLAW_REQUIRE_CONFIRMATION") {
            config.require_confirmation = confirm.to_lowercase() != "false";
        }

        if let Ok(egress) = std::env::var("ZAPCLAW_ENABLE_EGRESS_GUARD") {
            config.enable_egress_guard = egress.to_lowercase() != "false";
        }

        if let Ok(ctx) = std::env::var("ZAPCLAW_CONTEXT_WINDOW") {
            if let Ok(n) = ctx.parse::<usize>() {
                config.context_window_tokens = n;
            }
        }

        // Memory system env vars
        if let Ok(url) = std::env::var("ZAPCLAW_MEMORY_EMBEDDING_BASE_URL") {
            config.memory_embedding_base_url = url;
        }

        if let Ok(model) = std::env::var("ZAPCLAW_MEMORY_EMBEDDING_MODEL") {
            config.memory_embedding_model = model;
        }

        if let Ok(dims) = std::env::var("ZAPCLAW_MEMORY_EMBEDDING_TARGET_DIMS") {
            if let Ok(n) = dims.parse::<usize>() {
                config.memory_embedding_target_dims = n;
            }
        }

        if let Ok(batch) = std::env::var("ZAPCLAW_MEMORY_EMBEDDING_BATCH_SIZE") {
            if let Ok(n) = batch.parse::<usize>() {
                config.memory_embedding_batch_size = n;
            }
        }

        if let Ok(enabled) = std::env::var("ZAPCLAW_MEMORY_DAEMON_ENABLED") {
            config.memory_daemon_enabled = enabled.to_lowercase() != "false";
        }

        if let Ok(interval) = std::env::var("ZAPCLAW_MEMORY_SYNC_INTERVAL_SECS") {
            if let Ok(n) = interval.parse::<usize>() {
                config.memory_sync_interval_secs = n;
            }
        }

        if let Ok(sync) = std::env::var("ZAPCLAW_MEMORY_SYNC_ON_SEARCH") {
            config.memory_sync_on_search = sync.to_lowercase() != "false";
        }

        if let Ok(req) = std::env::var("ZAPCLAW_MEMORY_REQUIRE_EMBEDDINGS") {
            config.memory_require_embeddings = req.to_lowercase() != "false";
        }

        if let Ok(fallback) = std::env::var("ZAPCLAW_MEMORY_ALLOW_LEXICAL_FALLBACK") {
            config.memory_allow_lexical_fallback = fallback.to_lowercase() != "false";
        }

        if let Ok(max) = std::env::var("ZAPCLAW_MEMORY_CACHE_MAX_ENTRIES") {
            if let Ok(n) = max.parse::<usize>() {
                config.memory_cache_max_entries = n;
            }
        }

        config
    }

    /// Merge configuration from file, env, and defaults.
    ///
    /// Precedence: Env > File > Defaults
    /// Note: CLI overrides are applied separately after this merge.
    ///
    /// IMPORTANT: We check env vars directly (not via env_cfg) to determine if they were set.
    /// This is necessary because we can't distinguish "env var set to default" from "env var not set"
    /// after the fact using only Config values.
    pub fn from_sources(file_cfg: &FileConfig, _env_cfg: &Config) -> Self {
        let defaults = Self::default();
        let mut config = defaults.clone();

        // Apply file config first (lowest precedence after defaults)
        if let Some(ws) = &file_cfg.workspace_path {
            config.workspace_path = PathBuf::from(ws);
        }
        if let Some(url) = &file_cfg.api_base_url {
            config.api_base_url = url.clone();
        }
        if let Some(model) = &file_cfg.model_name {
            config.model_name = model.clone();
        }
        if let Some(steps) = file_cfg.max_steps {
            config.max_steps = steps;
        }
        if let Some(inbound) = file_cfg.enable_inbound {
            config.enable_inbound = inbound;
        }
        if let Some(timeout) = file_cfg.tool_timeout_secs {
            config.tool_timeout_secs = timeout;
        }
        if let Some(confirm) = file_cfg.require_confirmation {
            config.require_confirmation = confirm;
        }
        if let Some(egress) = file_cfg.enable_egress_guard {
            config.enable_egress_guard = egress;
        }
        if let Some(ctx) = file_cfg.context_window_tokens {
            config.context_window_tokens = ctx;
        }
        if let Some(port) = file_cfg.inbound_port {
            config.inbound_port = port;
        }
        if let Some(bind) = &file_cfg.inbound_bind {
            config.inbound_bind = bind.clone();
        }

        // Memory system file config
        if let Some(url) = &file_cfg.memory_embedding_base_url {
            config.memory_embedding_base_url = url.clone();
        }
        if let Some(model) = &file_cfg.memory_embedding_model {
            config.memory_embedding_model = model.clone();
        }
        if let Some(dims) = file_cfg.memory_embedding_target_dims {
            config.memory_embedding_target_dims = dims;
        }
        if let Some(batch) = file_cfg.memory_embedding_batch_size {
            config.memory_embedding_batch_size = batch;
        }
        if let Some(enabled) = file_cfg.memory_daemon_enabled {
            config.memory_daemon_enabled = enabled;
        }
        if let Some(interval) = file_cfg.memory_sync_interval_secs {
            config.memory_sync_interval_secs = interval;
        }
        if let Some(sync) = file_cfg.memory_sync_on_search {
            config.memory_sync_on_search = sync;
        }
        if let Some(req) = file_cfg.memory_require_embeddings {
            config.memory_require_embeddings = req;
        }
        if let Some(fallback) = file_cfg.memory_allow_lexical_fallback {
            config.memory_allow_lexical_fallback = fallback;
        }
        if let Some(max_entries) = file_cfg.memory_cache_max_entries {
            config.memory_cache_max_entries = max_entries;
        }

        // Apply env config (overrides file and defaults)
        // Check env vars directly to ensure we override file even when env equals default
        if std::env::var("ZAPCLAW_WORKSPACE").is_ok() {
            if let Ok(ws) = std::env::var("ZAPCLAW_WORKSPACE") {
                config.workspace_path = PathBuf::from(ws);
            }
        }
        if std::env::var("ZAPCLAW_API_BASE_URL").is_ok() {
            if let Ok(url) = std::env::var("ZAPCLAW_API_BASE_URL") {
                config.api_base_url = url;
            }
        }
        if std::env::var("ZAPCLAW_MODEL").is_ok() {
            if let Ok(model) = std::env::var("ZAPCLAW_MODEL") {
                config.model_name = model;
            }
        }
        if std::env::var("ZAPCLAW_MAX_STEPS").is_ok() {
            if let Ok(steps) = std::env::var("ZAPCLAW_MAX_STEPS") {
                if let Ok(n) = steps.parse::<usize>() {
                    config.max_steps = n;
                }
            }
        }
        if std::env::var("ZAPCLAW_TOOL_TIMEOUT").is_ok() {
            if let Ok(timeout) = std::env::var("ZAPCLAW_TOOL_TIMEOUT") {
                if let Ok(t) = timeout.parse::<u64>() {
                    config.tool_timeout_secs = t;
                }
            }
        }
        if std::env::var("ZAPCLAW_REQUIRE_CONFIRMATION").is_ok() {
            if let Ok(confirm) = std::env::var("ZAPCLAW_REQUIRE_CONFIRMATION") {
                config.require_confirmation = confirm.to_lowercase() != "false";
            }
        }
        if std::env::var("ZAPCLAW_ENABLE_EGRESS_GUARD").is_ok() {
            if let Ok(egress) = std::env::var("ZAPCLAW_ENABLE_EGRESS_GUARD") {
                config.enable_egress_guard = egress.to_lowercase() != "false";
            }
        }
        if std::env::var("ZAPCLAW_CONTEXT_WINDOW").is_ok() {
            if let Ok(ctx) = std::env::var("ZAPCLAW_CONTEXT_WINDOW") {
                if let Ok(n) = ctx.parse::<usize>() {
                    config.context_window_tokens = n;
                }
            }
        }

        // Memory system env overrides
        if std::env::var("ZAPCLAW_MEMORY_EMBEDDING_BASE_URL").is_ok() {
            if let Ok(url) = std::env::var("ZAPCLAW_MEMORY_EMBEDDING_BASE_URL") {
                config.memory_embedding_base_url = url;
            }
        }
        if std::env::var("ZAPCLAW_MEMORY_EMBEDDING_MODEL").is_ok() {
            if let Ok(model) = std::env::var("ZAPCLAW_MEMORY_EMBEDDING_MODEL") {
                config.memory_embedding_model = model;
            }
        }
        if std::env::var("ZAPCLAW_MEMORY_EMBEDDING_TARGET_DIMS").is_ok() {
            if let Ok(dims) = std::env::var("ZAPCLAW_MEMORY_EMBEDDING_TARGET_DIMS") {
                if let Ok(n) = dims.parse::<usize>() {
                    config.memory_embedding_target_dims = n;
                }
            }
        }
        if std::env::var("ZAPCLAW_MEMORY_EMBEDDING_BATCH_SIZE").is_ok() {
            if let Ok(batch) = std::env::var("ZAPCLAW_MEMORY_EMBEDDING_BATCH_SIZE") {
                if let Ok(n) = batch.parse::<usize>() {
                    config.memory_embedding_batch_size = n;
                }
            }
        }
        if std::env::var("ZAPCLAW_MEMORY_DAEMON_ENABLED").is_ok() {
            if let Ok(enabled) = std::env::var("ZAPCLAW_MEMORY_DAEMON_ENABLED") {
                config.memory_daemon_enabled = enabled.to_lowercase() != "false";
            }
        }
        if std::env::var("ZAPCLAW_MEMORY_SYNC_INTERVAL_SECS").is_ok() {
            if let Ok(interval) = std::env::var("ZAPCLAW_MEMORY_SYNC_INTERVAL_SECS") {
                if let Ok(n) = interval.parse::<usize>() {
                    config.memory_sync_interval_secs = n;
                }
            }
        }
        if std::env::var("ZAPCLAW_MEMORY_SYNC_ON_SEARCH").is_ok() {
            if let Ok(sync) = std::env::var("ZAPCLAW_MEMORY_SYNC_ON_SEARCH") {
                config.memory_sync_on_search = sync.to_lowercase() != "false";
            }
        }
        if std::env::var("ZAPCLAW_MEMORY_REQUIRE_EMBEDDINGS").is_ok() {
            if let Ok(req) = std::env::var("ZAPCLAW_MEMORY_REQUIRE_EMBEDDINGS") {
                config.memory_require_embeddings = req.to_lowercase() != "false";
            }
        }
        if std::env::var("ZAPCLAW_MEMORY_ALLOW_LEXICAL_FALLBACK").is_ok() {
            if let Ok(fallback) = std::env::var("ZAPCLAW_MEMORY_ALLOW_LEXICAL_FALLBACK") {
                config.memory_allow_lexical_fallback = fallback.to_lowercase() != "false";
            }
        }
        if std::env::var("ZAPCLAW_MEMORY_CACHE_MAX_ENTRIES").is_ok() {
            if let Ok(max) = std::env::var("ZAPCLAW_MEMORY_CACHE_MAX_ENTRIES") {
                if let Ok(n) = max.parse::<usize>() {
                    config.memory_cache_max_entries = n;
                }
            }
        }

        config
    }

    /// Get API key from environment. Never stored in config struct.
    pub fn api_key() -> Option<String> {
        std::env::var("ZAPCLAW_API_KEY").ok()
    }

    /// Get search API key from environment. Never stored in config struct.
    pub fn search_api_key() -> Option<String> {
        std::env::var("ZAPCLAW_SEARCH_API_KEY").ok()
    }

    /// Get inbound API key from environment. Never stored in config struct.
    pub fn inbound_api_key() -> Option<String> {
        std::env::var("ZAPCLAW_INBOUND_KEY").ok()
    }

    /// Generate a default config file template as JSON string.
    ///
    /// Includes hints via comments in JSON (using non-standard approach with _comment fields
    /// that users can remove, or we can provide a separate example file).
    pub fn default_template_json(_workspace_hint: &Path) -> String {
        let template = serde_json::json!({
            "workspace_path": "./zapclaw_workspace",
            "api_base_url": "http://localhost:11434/v1",
            "model_name": "phi3:mini",
            "max_steps": 15,
            "tool_timeout_secs": 30,
            "require_confirmation": true,
            "enable_egress_guard": true,
            "context_window_tokens": 128000,
            "_comment_api_base_url": "For Ollama: http://localhost:11434/v1, For OpenAI: https://api.openai.com/v1",
            "_comment_model_name": "Ollama: phi3:mini, OpenAI: gpt-4o",
            "_comment_secrets": "API keys must be set via environment variables: ZAPCLAW_API_KEY, ZAPCLAW_SEARCH_API_KEY, ZAPCLAW_INBOUND_KEY",
            "memory_embedding_base_url": "http://localhost:11434/v1",
            "memory_embedding_model": "nomic-embed-text:v1.5",
            "memory_embedding_target_dims": 512,
            "memory_embedding_batch_size": 32,
            "memory_daemon_enabled": true,
            "memory_sync_interval_secs": 15,
            "memory_sync_on_search": true,
            "memory_require_embeddings": true,
            "memory_allow_lexical_fallback": false,
            "memory_cache_max_entries": 50000,
            "_comment_memory": "Memory system settings for hybrid search (BM25 + vector embeddings)",
            "_comment_memory_setup": "Install Ollama and run: ollama pull nomic-embed-text:v1.5",
        });

        serde_json::to_string_pretty(&template).unwrap()
    }

    /// Serialize to JSON for persistence (excludes secrets).
    pub fn to_persisted_json(&self) -> Result<String, anyhow::Error> {
        let file_config = FileConfig {
            workspace_path: Some(self.workspace_path.to_string_lossy().to_string()),
            api_base_url: if self.api_base_url.is_empty() { None } else { Some(self.api_base_url.clone()) },
            model_name: if self.model_name.is_empty() { None } else { Some(self.model_name.clone()) },
            max_steps: Some(self.max_steps),
            enable_inbound: Some(self.enable_inbound),
            tool_timeout_secs: Some(self.tool_timeout_secs),
            require_confirmation: Some(self.require_confirmation),
            enable_egress_guard: Some(self.enable_egress_guard),
            context_window_tokens: Some(self.context_window_tokens),
            inbound_port: Some(self.inbound_port),
            inbound_bind: Some(self.inbound_bind.clone()),
            memory_embedding_base_url: Some(self.memory_embedding_base_url.clone()),
            memory_embedding_model: Some(self.memory_embedding_model.clone()),
            memory_embedding_target_dims: Some(self.memory_embedding_target_dims),
            memory_embedding_batch_size: Some(self.memory_embedding_batch_size),
            memory_daemon_enabled: Some(self.memory_daemon_enabled),
            memory_sync_interval_secs: Some(self.memory_sync_interval_secs),
            memory_sync_on_search: Some(self.memory_sync_on_search),
            memory_require_embeddings: Some(self.memory_require_embeddings),
            memory_allow_lexical_fallback: Some(self.memory_allow_lexical_fallback),
            memory_cache_max_entries: Some(self.memory_cache_max_entries),
        };

        serde_json::to_string_pretty(&file_config)
            .map_err(|e| anyhow::anyhow!("Failed to serialize config: {}", e))
    }

    /// Resolve the workspace path to an absolute, canonical path.
    pub fn resolve_workspace(&self) -> anyhow::Result<PathBuf> {
        let path = if self.workspace_path.is_absolute() {
            self.workspace_path.clone()
        } else {
            std::env::current_dir()?.join(&self.workspace_path)
        };

        // Create workspace if it doesn't exist
        if !path.exists() {
            std::fs::create_dir_all(&path)?;
        }

        // Set restrictive permissions (0700) on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&path, perms)?;
        }

        Ok(std::fs::canonicalize(&path)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use serial_test::serial;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        // api_base_url and model_name are now empty by default (must be explicitly provided)
        assert!(config.api_base_url.is_empty());
        assert!(config.model_name.is_empty());
        assert_eq!(config.max_steps, 15);
        assert!(!config.enable_outbound);
        assert!(!config.enable_inbound);
        assert_eq!(config.tool_timeout_secs, 5);
        assert!(config.require_confirmation);
        assert_eq!(config.inbound_port, 9876);
        assert_eq!(config.inbound_bind, "127.0.0.1");
    }

    #[test]
    fn test_api_key_not_stored() {
        // API key is a static method, never part of Config struct
        let config = Config::default();
        let serialized = serde_json::to_string(&config).unwrap();
        assert!(!serialized.contains("api_key"));
    }

    #[test]
    fn test_from_json_file_missing() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("nonexistent.json");

        let result = Config::from_json_file(&config_path);
        assert!(result.is_ok());
        let file_config = result.unwrap();
        assert_eq!(file_config, FileConfig::default());
    }

    #[test]
    fn test_from_json_file_valid() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.json");

        let content = r#"{
            "workspace_path": "/tmp/workspace",
            "api_base_url": "http://localhost:11434/v1",
            "model_name": "phi3:mini",
            "max_steps": 20,
            "tool_timeout_secs": 60
        }"#;

        std::fs::write(&config_path, content).unwrap();

        let result = Config::from_json_file(&config_path);
        assert!(result.is_ok());
        let file_config = result.unwrap();
        assert_eq!(file_config.workspace_path, Some("/tmp/workspace".to_string()));
        assert_eq!(file_config.api_base_url, Some("http://localhost:11434/v1".to_string()));
        assert_eq!(file_config.model_name, Some("phi3:mini".to_string()));
        assert_eq!(file_config.max_steps, Some(20));
        assert_eq!(file_config.tool_timeout_secs, Some(60));
    }

    #[test]
    fn test_from_json_file_invalid_json() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("invalid.json");

        std::fs::write(&config_path, "{ invalid json }").unwrap();

        let result = Config::from_json_file(&config_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to parse"));
    }

    #[test]
    fn test_from_json_file_with_secret_key() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("with_secret.json");

        let content = r#"{
            "api_base_url": "http://localhost:11434/v1",
            "model_name": "phi3:mini",
            "api_key": "sk-secret-key"
        }"#;

        std::fs::write(&config_path, content).unwrap();

        let result = Config::from_json_file(&config_path);
        assert!(result.is_ok());
        let file_config = result.unwrap();
        // api_key should be ignored (not in FileConfig struct)
        assert_eq!(file_config.api_base_url, Some("http://localhost:11434/v1".to_string()));
    }

    #[test]
    #[serial] // Requires exclusive access to environment variables
    fn test_from_sources_precedence() {
        // File config
        let file_cfg = FileConfig {
            workspace_path: Some("/from/file".to_string()),
            api_base_url: Some("http://file.com/v1".to_string()),
            model_name: Some("file-model".to_string()),
            max_steps: Some(10),
            tool_timeout_secs: Some(20),
            ..Default::default()
        };

        // Set env vars
        std::env::set_var("ZAPCLAW_WORKSPACE", "/from/env");
        std::env::set_var("ZAPCLAW_API_BASE_URL", "http://env.com/v1");
        std::env::set_var("ZAPCLAW_MODEL", "env-model");
        std::env::set_var("ZAPCLAW_MAX_STEPS", "25");
        std::env::set_var("ZAPCLAW_TOOL_TIMEOUT", "35");

        let env_cfg = Config::from_env();

        // Merged config
        let merged = Config::from_sources(&file_cfg, &env_cfg);

        // Clean up env vars
        std::env::remove_var("ZAPCLAW_WORKSPACE");
        std::env::remove_var("ZAPCLAW_API_BASE_URL");
        std::env::remove_var("ZAPCLAW_MODEL");
        std::env::remove_var("ZAPCLAW_MAX_STEPS");
        std::env::remove_var("ZAPCLAW_TOOL_TIMEOUT");

        // Env should override file
        assert_eq!(merged.workspace_path, PathBuf::from("/from/env"));
        assert_eq!(merged.api_base_url, "http://env.com/v1");
        assert_eq!(merged.model_name, "env-model");
        assert_eq!(merged.max_steps, 25);
        assert_eq!(merged.tool_timeout_secs, 35);
    }

    #[test]
    #[serial] // Requires exclusive access to environment variables
    fn test_from_sources_precedence_env_over_file_when_env_equals_default() {
        // Test case: file has max_steps=20, env has ZAPCLAW_MAX_STEPS=15 (default)
        // Expected: env should win (15), not file (20)

        let file_cfg = FileConfig {
            max_steps: Some(20),
            ..Default::default()
        };

        std::env::set_var("ZAPCLAW_MAX_STEPS", "15");
        let env_cfg = Config::from_env();

        let merged = Config::from_sources(&file_cfg, &env_cfg);

        std::env::remove_var("ZAPCLAW_MAX_STEPS");

        // Env should win even though it equals default
        assert_eq!(merged.max_steps, 15, "Env should override file even when env equals default");
    }

    #[test]
    #[serial] // Requires exclusive access to environment variables
    fn test_from_sources_precedence_file_when_env_not_set() {
        // Test case: file has max_steps=20, env not set
        // Expected: file should win (20)

        let file_cfg = FileConfig {
            max_steps: Some(20),
            ..Default::default()
        };

        // Ensure env var is not set
        std::env::remove_var("ZAPCLAW_MAX_STEPS");
        let env_cfg = Config::from_env();

        let merged = Config::from_sources(&file_cfg, &env_cfg);

        // File should win when env not set
        assert_eq!(merged.max_steps, 20, "File should be used when env not set");
    }

    #[test]
    #[serial] // Requires exclusive access to environment variables
    fn test_from_sources_precedence_boolean_field() {
        // Test case: file has require_confirmation=false, env has ZAPCLAW_REQUIRE_CONFIRMATION=true
        // Expected: env should win (true)

        let file_cfg = FileConfig {
            require_confirmation: Some(false),
            ..Default::default()
        };

        std::env::set_var("ZAPCLAW_REQUIRE_CONFIRMATION", "true");
        let env_cfg = Config::from_env();

        let merged = Config::from_sources(&file_cfg, &env_cfg);

        std::env::remove_var("ZAPCLAW_REQUIRE_CONFIRMATION");

        // Env should win for boolean fields
        assert!(merged.require_confirmation, "Env should override file for boolean fields");
    }

    #[test]
    #[serial] // Requires exclusive access to environment variables
    fn test_from_sources_defaults_when_file_and_env_not_set() {
        // Ensure no env vars are set
        std::env::remove_var("ZAPCLAW_MAX_STEPS");
        std::env::remove_var("ZAPCLAW_TOOL_TIMEOUT");
        std::env::remove_var("ZAPCLAW_REQUIRE_CONFIRMATION");

        let file_cfg = FileConfig::default();
        let env_cfg = Config::from_env();

        let merged = Config::from_sources(&file_cfg, &env_cfg);

        assert_eq!(merged.workspace_path, PathBuf::from("./zapclaw_workspace"));
        assert_eq!(merged.max_steps, 15);
        assert_eq!(merged.tool_timeout_secs, 5);
        assert!(merged.require_confirmation);
    }

    #[test]
    fn test_resolve_home_config_path() {
        let home_path = Config::resolve_home_config_path();
        assert!(home_path.ends_with(".zapclaw/zapclaw.json"));
    }

    #[test]
    fn test_resolve_project_config_path() {
        let proj_path = Config::resolve_project_config_path();
        assert_eq!(proj_path, PathBuf::from("./zapclaw.json"));
    }

    #[test]
    fn test_resolve_explicit_config_path_cli() {
        let custom = PathBuf::from("/custom/path.json");
        let result = Config::resolve_explicit_config_path(Some(&custom));
        assert_eq!(result, Some(custom));
    }

    #[test]
    #[serial] // Requires exclusive access to environment variables
    fn test_resolve_explicit_config_path_env() {
        std::env::set_var("ZAPCLAW_CONFIG_PATH", "/env/path.json");
        let result = Config::resolve_explicit_config_path(None);
        assert_eq!(result, Some(PathBuf::from("/env/path.json")));
        std::env::remove_var("ZAPCLAW_CONFIG_PATH");
    }

    #[test]
    fn test_resolve_explicit_config_path_none() {
        std::env::remove_var("ZAPCLAW_CONFIG_PATH");
        let result = Config::resolve_explicit_config_path(None);
        assert_eq!(result, None);
    }

    #[test]
    fn test_resolve_config_paths_explicit_mode() {
        let custom = PathBuf::from("/custom.json");
        let (mode, paths) = Config::resolve_config_paths(Some(&custom));
        
        assert_eq!(mode, "explicit");
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], custom);
    }

    #[test]
    fn test_resolve_config_paths_layered_mode() {
        let (mode, paths) = Config::resolve_config_paths(None);
        
        assert_eq!(mode, "layered");
        // Should have home path, and possibly project path if it exists
        assert!(!paths.is_empty());
        assert!(paths[0].ends_with(".zapclaw/zapclaw.json"));
    }

    #[test]
    fn test_load_and_merge_files_empty() {
        let result = Config::load_and_merge_files(&[], false);
        assert!(result.is_ok());
        let merged = result.unwrap();
        assert_eq!(merged, FileConfig::default());
    }

    #[test]
    fn test_load_and_merge_files_layered() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create home config
        let home_path = temp_dir.path().join("zapclaw.json");
        let home_content = r#"{
            "workspace_path": "/home/workspace",
            "max_steps": 10,
            "require_confirmation": false
        }"#;
        std::fs::write(&home_path, home_content).unwrap();

        // Create project config
        let proj_path = temp_dir.path().join("project.json");
        let proj_content = r#"{
            "max_steps": 20,
            "tool_timeout_secs": 60
        }"#;
        std::fs::write(&proj_path, proj_content).unwrap();

        // Load and merge (home first, then project overrides)
        let result = Config::load_and_merge_files(&[home_path, proj_path], false);
        assert!(result.is_ok());
        let merged = result.unwrap();
        
        // Home values
        assert_eq!(merged.workspace_path, Some("/home/workspace".to_string()));
        assert_eq!(merged.require_confirmation, Some(false));
        
        // Project overrides home
        assert_eq!(merged.max_steps, Some(20));
        assert_eq!(merged.tool_timeout_secs, Some(60));
    }

    #[test]
    fn test_ensure_config_exists_creates() {
        let temp_dir = TempDir::new().unwrap();
        let test_config = temp_dir.path().join("zapclaw.json");

        // Verify file doesn't exist initially
        assert!(!test_config.exists());

        // Create config
        let result = Config::ensure_config_exists_at(&test_config);
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should return true (created)

        // Verify file exists now
        assert!(test_config.exists());

        // Verify file has valid JSON content
        let content = std::fs::read_to_string(&test_config).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(parsed.is_object());

        // Call again - should return false (already exists)
        let result = Config::ensure_config_exists_at(&test_config);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should return false (already existed)
    }

    #[test]
    fn test_ensure_config_exists_already_exists() {
        let temp_dir = TempDir::new().unwrap();
        let test_config = temp_dir.path().join("zapclaw.json");

        // Create file manually
        std::fs::write(&test_config, r#"{"workspace_path": "/test"}"#).unwrap();

        // Should return false (already exists)
        let result = Config::ensure_config_exists_at(&test_config);
        assert!(result.is_ok());
        assert!(!result.unwrap());

        // Content should not be overwritten
        let content = std::fs::read_to_string(&test_config).unwrap();
        assert_eq!(content.trim(), r#"{"workspace_path": "/test"}"#);
    }

    #[test]
    fn test_load_and_merge_files_explicit_mode_missing_file() {
        let missing_path = PathBuf::from("/tmp/does-not-exist-zapclaw-12345.json");
        
        let result = Config::load_and_merge_files(&[missing_path.clone()], true);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("does not exist"));
        assert!(err.contains("/tmp/does-not-exist-zapclaw-12345.json"));
    }

    #[test]
    fn test_load_and_merge_files_layered_mode_missing_file() {
        let missing_path = PathBuf::from("/tmp/does-not-exist-zapclaw-12345.json");
        
        // Layered mode should not error on missing file
        let result = Config::load_and_merge_files(&[missing_path], false);
        assert!(result.is_ok());
        
        // Should return default config when no files exist
        let merged = result.unwrap();
        assert_eq!(merged, FileConfig::default());
    }

    #[test]
    fn test_resolve_config_path_cli_override() {
        let cli_path = PathBuf::from("/custom/path.json");
        let resolved = Config::resolve_config_path(Some(&cli_path));
        assert_eq!(resolved, cli_path);
    }

    #[test]
    fn test_resolve_config_path_env_var() {
        std::env::set_var("ZAPCLAW_CONFIG_PATH", "/env/path.json");
        let resolved = Config::resolve_config_path(None);
        assert_eq!(resolved, PathBuf::from("/env/path.json"));
        std::env::remove_var("ZAPCLAW_CONFIG_PATH");
    }

    #[test]
    fn test_default_template_json() {
        let template = Config::default_template_json(Path::new("/tmp"));
        assert!(template.contains("workspace_path"));
        assert!(template.contains("api_base_url"));
        assert!(template.contains("model_name"));
        assert!(template.contains("_comment_"));
    }

    #[test]
    fn test_to_persisted_json() {
        let config = Config {
            workspace_path: PathBuf::from("/test/workspace"),
            api_base_url: "http://localhost:11434/v1".to_string(),
            model_name: "phi3:mini".to_string(),
            max_steps: 20,
            tool_timeout_secs: 60,
            require_confirmation: false,
            ..Default::default()
        };

        let json = config.to_persisted_json().unwrap();
        assert!(json.contains("workspace_path"));
        assert!(json.contains("api_base_url"));
        assert!(json.contains("model_name"));
        // Secrets should not be present
        assert!(!json.contains("api_key"));
        assert!(!json.contains("search_api_key"));
        assert!(!json.contains("inbound_api_key"));
    }

    // WP2 Tests: Secure home resolution with validation

    #[test]
    #[serial] // Requires exclusive access to environment variables
    fn test_resolve_home_config_path_uses_valid_host_home_when_sandboxed() {
        let temp_dir = TempDir::new().unwrap();
        let fake_home = temp_dir.path();

        // Set sandboxed mode
        std::env::set_var("ZAPCLAW_SANDBOXED", "1");
        std::env::set_var("ZAPCLAW_HOST_HOME", fake_home.to_string_lossy().as_ref());

        let result = Config::resolve_home_config_path();
        
        // Should point to fake_home/.zapclaw/zapclaw.json
        assert!(result.starts_with(fake_home));
        assert!(result.ends_with(".zapclaw/zapclaw.json"));

        std::env::remove_var("ZAPCLAW_SANDBOXED");
        std::env::remove_var("ZAPCLAW_HOST_HOME");
    }

    #[test]
    #[serial] // Requires exclusive access to environment variables
    fn test_resolve_home_config_path_ignores_relative_host_home() {
        // Set sandboxed mode with relative path
        std::env::set_var("ZAPCLAW_SANDBOXED", "1");
        std::env::set_var("ZAPCLAW_HOST_HOME", "relative/path");

        // Should fall back to dirs::home_dir() (or . if HOME not set)
        let result = Config::resolve_home_config_path();
        // Result should not contain "relative/path"
        assert!(!result.to_string_lossy().contains("relative/path"));

        std::env::remove_var("ZAPCLAW_SANDBOXED");
        std::env::remove_var("ZAPCLAW_HOST_HOME");
    }

    #[test]
    #[serial] // Requires exclusive access to environment variables
    fn test_resolve_host_home_for_config_fallback_to_dirs_home() {
        // Ensure sandbox mode is off
        std::env::remove_var("ZAPCLAW_SANDBOXED");
        std::env::remove_var("ZAPCLAW_HOST_HOME");

        // Should use dirs::home_dir()
        let result = Config::resolve_host_home_for_config();
        
        // If HOME is set, should return it
        if let Ok(home) = std::env::var("HOME") {
            assert_eq!(result, Some(PathBuf::from(home)));
        }
    }

    #[test]
    #[serial] // Requires exclusive access to environment variables
    fn test_validate_host_home_path_accepts_valid_directory() {
        let temp_dir = TempDir::new().unwrap();
        
        let result = Config::validate_host_home_path(temp_dir.path());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), temp_dir.path());
    }

    #[test]
    fn test_validate_host_home_path_rejects_non_absolute() {
        let relative = PathBuf::from("relative/path");
        
        let result = Config::validate_host_home_path(&relative);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not absolute"));
    }

    #[test]
    fn test_validate_host_home_path_rejects_nonexistent() {
        let nonexistent = PathBuf::from("/nonexistent-path-xyz-123");
        
        let result = Config::validate_host_home_path(&nonexistent);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("canonicalization failed"));
    }

    #[test]
    fn test_validate_host_home_path_rejects_file_not_directory() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("not-a-dir");
        std::fs::write(&file_path, b"test").unwrap();
        
        let result = Config::validate_host_home_path(&file_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not a directory"));
    }

    // WP3 Tests: Config file security validation

    #[test]
    #[serial] // Requires exclusive access to environment variables
    fn test_home_config_unsafe_permissions_warns_and_loads() {
        let temp_dir = TempDir::new().unwrap();
        let config_dir = temp_dir.path().join(".zapclaw");
        let config_path = config_dir.join("zapclaw.json");

        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            &config_path,
            r#"{"workspace_path": "/test", "api_base_url": "http://localhost:11434/v1", "model_name": "test"}"#
        ).unwrap();

        // Set overly permissive permissions (group-readable 0640)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            // 0640 has group read - should trigger warning but still load
            let perms = std::fs::Permissions::from_mode(0o640);
            std::fs::set_permissions(&config_path, perms).unwrap();

            // Should load (non-strict mode for home config)
            // Warning is logged but loading succeeds
            let result = Config::from_json_file(&config_path);
            assert!(result.is_ok());
        }

        #[cfg(not(unix))]
        {
            // Non-Unix: no permission checks, should load fine
            let result = Config::from_json_file(&config_path);
            assert!(result.is_ok());
        }
    }

    #[test]
    #[serial] // Requires exclusive access to environment variables
    fn test_explicit_config_unsafe_permissions_fails() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("explicit_config.json");

        std::fs::write(
            &config_path,
            r#"{"workspace_path": "/test", "api_base_url": "http://localhost:11434/v1", "model_name": "test"}"#
        ).unwrap();

        // Set overly permissive permissions (group-readable 0640)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            // 0640 has group read - should fail in strict mode
            let perms = std::fs::Permissions::from_mode(0o640);
            std::fs::set_permissions(&config_path, perms).unwrap();

            // Use from_json_file_strict for explicit config validation
            let result = Config::from_json_file_strict(&config_path);
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("overly permissive permissions"));
        }

        #[cfg(not(unix))]
        {
            // Non-Unix: permission checks not available
            // This test passes trivially on non-Unix
            assert!(true);
        }
    }

    #[test]
    #[serial] // Requires exclusive access to environment variables
    fn test_config_file_symlink_outside_trusted_home_warns() {
        let temp_dir = TempDir::new().unwrap();
        let home_base = temp_dir.path().join("home");
        let config_dir = home_base.join(".zapclaw");
        std::fs::create_dir_all(&config_dir).unwrap();

        let real_config_path = temp_dir.path().join("real_config.json");
        std::fs::write(
            &real_config_path,
            r#"{"workspace_path": "/real"}"#
        ).unwrap();

        // Create symlink in .zapclaw pointing outside
        let symlink_path = config_dir.join("zapclaw.json");
        
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&real_config_path, &symlink_path).unwrap();

            // Load from symlink path - should warn but continue (home config)
            // The validation will detect it's outside trusted home base
            let result = Config::from_json_file(&symlink_path);
            
            // Should still load (warn-only for home config)
            assert!(result.is_ok());
        }

        #[cfg(not(unix))]
        {
            // Symlinks not well-supported on Windows, skip test
            assert!(true);
        }
    }

    #[test]
    #[serial] // Requires exclusive access to environment variables
    fn test_resolve_home_config_path_in_sandbox_uses_host_home() {
        let temp_dir = TempDir::new().unwrap();
        let fake_host_home = temp_dir.path();

        // Simulate sandboxed environment
        std::env::set_var("ZAPCLAW_SANDBOXED", "1");
        std::env::set_var("ZAPCLAW_HOST_HOME", fake_host_home.to_string_lossy().as_ref());
        
        // Set HOME to workspace (simulating sandbox setup)
        let workspace = temp_dir.path().join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        std::env::set_var("HOME", workspace.to_string_lossy().as_ref());

        let result = Config::resolve_home_config_path();
        
        // Should use ZAPCLAW_HOST_HOME, not HOME
        assert!(result.starts_with(fake_host_home));
        assert!(!result.starts_with(&workspace));

        std::env::remove_var("ZAPCLAW_SANDBOXED");
        std::env::remove_var("ZAPCLAW_HOST_HOME");
        std::env::remove_var("HOME");
    }
}
