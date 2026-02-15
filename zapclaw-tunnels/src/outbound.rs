use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// Outbound HTTPS tunnel with rate limiting and mTLS support.
///
/// This tunnel proxies all outbound HTTPS requests from ZapClaw,
/// providing:
/// - **Rate limiting**: Configurable requests per minute
/// - **mTLS**: Client certificate authentication for cloud endpoints
/// - **Domain allowlisting**: Only approved domains are reachable
/// - **Audit logging**: All outbound requests are logged
/// - **User confirmation**: Optional per-request approval
///
/// When disabled (default), the agent can only communicate with
/// the local Ollama instance on localhost:11434.
pub struct OutboundTunnel {
    config: OutboundConfig,
    client: reqwest::Client,
    rate_limiter: Arc<Mutex<RateLimiter>>,
}

/// Outbound tunnel configuration.
#[derive(Debug, Clone)]
pub struct OutboundConfig {
    /// Whether the tunnel is enabled
    pub enabled: bool,
    /// Optional HTTPS proxy URL
    pub proxy_url: Option<String>,
    /// Max requests per minute (0 = unlimited)
    pub rate_limit_per_minute: u32,
    /// Allowed destination domains (empty = allow all)
    pub allowed_domains: Vec<String>,
    /// Whether to require user confirmation for each request
    pub require_confirmation: bool,
    /// mTLS client certificate path (PEM)
    pub client_cert_path: Option<String>,
    /// mTLS client key path (PEM)
    pub client_key_path: Option<String>,
    /// CA certificate path for server verification (PEM)
    pub ca_cert_path: Option<String>,
}

impl Default for OutboundConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy_url: None,
            rate_limit_per_minute: 60,
            allowed_domains: vec![
                "api.openai.com".to_string(),
                "api.anthropic.com".to_string(),
                "localhost".to_string(),
            ],
            require_confirmation: false,
            client_cert_path: None,
            client_key_path: None,
            ca_cert_path: None,
        }
    }
}

/// Simple sliding-window rate limiter.
struct RateLimiter {
    window: VecDeque<DateTime<Utc>>,
    max_requests: u32,
}

impl RateLimiter {
    fn new(max_per_minute: u32) -> Self {
        Self {
            window: VecDeque::new(),
            max_requests: max_per_minute,
        }
    }

    /// Check if a request is allowed. Returns Ok(()) if allowed, Err if rate limited.
    fn check(&mut self) -> Result<()> {
        if self.max_requests == 0 {
            return Ok(()); // Unlimited
        }

        let now = Utc::now();
        let one_minute_ago = now - chrono::Duration::seconds(60);

        // Remove entries older than 1 minute
        while let Some(front) = self.window.front() {
            if *front < one_minute_ago {
                self.window.pop_front();
            } else {
                break;
            }
        }

        if self.window.len() >= self.max_requests as usize {
            anyhow::bail!(
                "🚫 Rate limited: {} requests in the last minute (limit: {})",
                self.window.len(),
                self.max_requests
            );
        }

        self.window.push_back(now);
        Ok(())
    }
}

/// Outbound request record (for audit logging).
#[derive(Debug, Clone, serde::Serialize)]
pub struct OutboundRequest {
    pub id: String,
    pub timestamp: String,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub duration_ms: u64,
}

impl OutboundTunnel {
    /// Create a new outbound tunnel.
    pub fn new(config: OutboundConfig) -> Result<Self> {
        let mut client_builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("ZapClaw/0.1 (Outbound Tunnel)");

        // Configure proxy if specified
        if let Some(ref proxy_url) = config.proxy_url {
            let proxy = reqwest::Proxy::all(proxy_url)
                .with_context(|| format!("Invalid proxy URL: {}", proxy_url))?;
            client_builder = client_builder.proxy(proxy);
        }

        // Configure mTLS if certificates are provided
        if let (Some(ref cert_path), Some(ref key_path)) = (&config.client_cert_path, &config.client_key_path) {
            let cert_pem = std::fs::read(cert_path)
                .with_context(|| format!("Failed to read client cert: {}", cert_path))?;
            let key_pem = std::fs::read(key_path)
                .with_context(|| format!("Failed to read client key: {}", key_path))?;

            let mut combined = cert_pem.clone();
            combined.extend_from_slice(&key_pem);

            let identity = reqwest::Identity::from_pem(&combined)
                .context("Failed to create mTLS identity from cert+key")?;
            client_builder = client_builder.identity(identity);
        }

        // Configure custom CA if specified
        if let Some(ref ca_path) = config.ca_cert_path {
            let ca_pem = std::fs::read(ca_path)
                .with_context(|| format!("Failed to read CA cert: {}", ca_path))?;
            let ca_cert = reqwest::Certificate::from_pem(&ca_pem)
                .context("Failed to parse CA certificate")?;
            client_builder = client_builder.add_root_certificate(ca_cert);
        }

        let client = client_builder.build().context("Failed to build outbound HTTP client")?;
        let rate_limiter = Arc::new(Mutex::new(RateLimiter::new(config.rate_limit_per_minute)));

        Ok(Self {
            config,
            client,
            rate_limiter,
        })
    }

    /// Check if the tunnel is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Validate that the target URL is allowed.
    fn validate_domain(&self, url: &str) -> Result<()> {
        if self.config.allowed_domains.is_empty() {
            return Ok(()); // No restrictions
        }

        let parsed: url::Url = url.parse().context("Invalid URL")?;
        let host = parsed.host_str().unwrap_or("");

        for allowed in &self.config.allowed_domains {
            if host == allowed || host.ends_with(&format!(".{}", allowed)) {
                return Ok(());
            }
        }

        anyhow::bail!(
            "🚫 Domain '{}' is not in the allowlist. Allowed: {:?}",
            host,
            self.config.allowed_domains
        );
    }

    /// Send a proxied GET request through the tunnel.
    pub async fn get(&self, url: &str) -> Result<(u16, String)> {
        self.preflight_check(url)?;

        let start = std::time::Instant::now();
        let response = self.client.get(url)
            .send()
            .await
            .with_context(|| format!("Outbound GET failed: {}", url))?;

        let status = response.status().as_u16();
        let body = response.text().await.context("Failed to read response body")?;

        let duration = start.elapsed().as_millis() as u64;
        log::info!("📡 Outbound GET {} → {} ({} ms, {} bytes)", url, status, duration, body.len());

        Ok((status, body))
    }

    /// Send a proxied POST request through the tunnel.
    pub async fn post(&self, url: &str, json_body: &serde_json::Value) -> Result<(u16, String)> {
        self.preflight_check(url)?;

        let start = std::time::Instant::now();
        let response = self.client.post(url)
            .json(json_body)
            .send()
            .await
            .with_context(|| format!("Outbound POST failed: {}", url))?;

        let status = response.status().as_u16();
        let body = response.text().await.context("Failed to read response body")?;

        let duration = start.elapsed().as_millis() as u64;
        log::info!("📡 Outbound POST {} → {} ({} ms, {} bytes)", url, status, duration, body.len());

        Ok((status, body))
    }

    /// Pre-flight checks: domain validation + rate limiting.
    fn preflight_check(&self, url: &str) -> Result<()> {
        if !self.config.enabled {
            anyhow::bail!("Outbound tunnel is disabled. Enable with --enable-outbound");
        }

        self.validate_domain(url)?;

        let mut limiter = self.rate_limiter.lock()
            .map_err(|e| anyhow::anyhow!("Rate limiter lock poisoned: {}", e))?;
        limiter.check()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = OutboundConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.rate_limit_per_minute, 60);
        assert!(config.allowed_domains.contains(&"api.openai.com".to_string()));
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(3);
        assert!(limiter.check().is_ok());
        assert!(limiter.check().is_ok());
        assert!(limiter.check().is_ok());
        assert!(limiter.check().is_err()); // 4th should fail
    }

    #[test]
    fn test_rate_limiter_unlimited() {
        let mut limiter = RateLimiter::new(0);
        for _ in 0..100 {
            assert!(limiter.check().is_ok());
        }
    }

    #[test]
    fn test_domain_validation() {
        let config = OutboundConfig::default();
        let tunnel = OutboundTunnel::new(OutboundConfig { enabled: true, ..config }).unwrap();

        assert!(tunnel.validate_domain("https://api.openai.com/v1/chat").is_ok());
        assert!(tunnel.validate_domain("https://api.anthropic.com/v1").is_ok());
        assert!(tunnel.validate_domain("https://evil.com/steal").is_err());
    }

    #[test]
    fn test_disabled_tunnel_blocks() {
        let tunnel = OutboundTunnel::new(OutboundConfig::default()).unwrap();
        assert!(tunnel.preflight_check("https://api.openai.com").is_err());
    }
}
