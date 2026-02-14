use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Pincer runtime configuration.
///
/// Loaded from environment variables and/or CLI flags.
/// Security: API keys are NEVER stored in plaintext config files — only env vars.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Path to the confined workspace directory (default: ./pincer_workspace)
    pub workspace_path: PathBuf,

    /// LLM backend mode
    pub llm_mode: LlmMode,

    /// Base URL for the LLM API
    /// - Local (Ollama): http://localhost:11434/v1
    /// - Cloud (OpenAI): https://api.openai.com/v1
    pub api_base_url: String,

    /// Model identifier (e.g., "phi3:mini" for Ollama, "gpt-4o" for OpenAI)
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

    /// Context window size in tokens (used for truncation calculations)
    pub context_window_tokens: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LlmMode {
    /// Local inference via Ollama (default)
    Local,
    /// Cloud inference via OpenAI-compatible API
    Cloud,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            workspace_path: PathBuf::from("./pincer_workspace"),
            llm_mode: LlmMode::Local,
            api_base_url: "http://localhost:11434/v1".to_string(),
            model_name: "phi3:mini".to_string(),
            max_steps: 15,
            enable_outbound: false,
            enable_inbound: false,
            tool_timeout_secs: 5,
            require_confirmation: true,
            context_window_tokens: 128_000,
        }
    }
}

impl Config {
    /// Load configuration from environment variables, falling back to defaults.
    ///
    /// Supported env vars:
    /// - PINCER_WORKSPACE: workspace directory path
    /// - PINCER_LLM_MODE: "local" or "cloud"
    /// - PINCER_API_BASE_URL: LLM API base URL
    /// - PINCER_API_KEY: API key (read at runtime, never stored)
    /// - PINCER_MODEL: model name
    /// - PINCER_MAX_STEPS: max agent loop steps
    /// - PINCER_TOOL_TIMEOUT: tool timeout in seconds
    /// - PINCER_REQUIRE_CONFIRMATION: "true" or "false"
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(ws) = std::env::var("PINCER_WORKSPACE") {
            config.workspace_path = PathBuf::from(ws);
        }

        if let Ok(mode) = std::env::var("PINCER_LLM_MODE") {
            config.llm_mode = match mode.to_lowercase().as_str() {
                "cloud" => LlmMode::Cloud,
                _ => LlmMode::Local,
            };
        }

        if let Ok(url) = std::env::var("PINCER_API_BASE_URL") {
            config.api_base_url = url;
        } else if config.llm_mode == LlmMode::Cloud {
            config.api_base_url = "https://api.openai.com/v1".to_string();
        }

        if let Ok(model) = std::env::var("PINCER_MODEL") {
            config.model_name = model;
        }

        if let Ok(steps) = std::env::var("PINCER_MAX_STEPS") {
            if let Ok(n) = steps.parse::<usize>() {
                config.max_steps = n;
            }
        }

        if let Ok(timeout) = std::env::var("PINCER_TOOL_TIMEOUT") {
            if let Ok(t) = timeout.parse::<u64>() {
                config.tool_timeout_secs = t;
            }
        }

        if let Ok(confirm) = std::env::var("PINCER_REQUIRE_CONFIRMATION") {
            config.require_confirmation = confirm.to_lowercase() != "false";
        }

        if let Ok(ctx) = std::env::var("PINCER_CONTEXT_WINDOW") {
            if let Ok(n) = ctx.parse::<usize>() {
                config.context_window_tokens = n;
            }
        }

        config
    }

    /// Get API key from environment. Never stored in config struct.
    pub fn api_key() -> Option<String> {
        std::env::var("PINCER_API_KEY").ok()
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

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.llm_mode, LlmMode::Local);
        assert_eq!(config.api_base_url, "http://localhost:11434/v1");
        assert_eq!(config.model_name, "phi3:mini");
        assert_eq!(config.max_steps, 15);
        assert!(!config.enable_outbound);
        assert!(!config.enable_inbound);
        assert_eq!(config.tool_timeout_secs, 5);
        assert!(config.require_confirmation);
    }

    #[test]
    fn test_api_key_not_stored() {
        // API key is a static method, never part of Config struct
        let config = Config::default();
        let serialized = serde_json::to_string(&config).unwrap();
        assert!(!serialized.contains("api_key"));
    }
}
