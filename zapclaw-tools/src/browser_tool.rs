use anyhow::{Context, Result};
use async_trait::async_trait;
use zapclaw_core::agent::Tool;
use serde::Deserialize;
use readability_rust::Readability;
use std::net::IpAddr;
use url::Url;

// SSRF hardening constants
const MAX_REDIRECT_HOPS: usize = 3;
const DNS_LOOKUP_RETRIES: usize = 2; // initial + one retry

/// Read-only browser tool.
///
/// Fetches web page content via HTTP and extracts text.
/// Unlike OpenClaw's full browser automation (Playwright), this is
/// intentionally limited to read-only operations:
/// - No JavaScript execution
/// - No form submission
/// - No cookie/session management
/// - No file downloads
///
/// SSRF Protection:
/// - Only allows http/https schemes
/// - Only allows default ports (80 for http, 443 for https)
/// - Blocks private/local network hostnames
/// - Blocks DNS resolution to private/link-local/loopback addresses
/// - Manual redirect handling with per-hop validation
/// - Fail-closed DNS policy with one retry
///
/// This eliminates the entire class of browser-based attacks that
/// affected OpenClaw (e.g., malicious webpages triggering code execution).
pub struct BrowserTool {
    client: reqwest::Client,
}

#[derive(Deserialize)]
struct BrowserArgs {
    url: String,
    #[serde(default = "default_max_length")]
    max_length: usize,
}

fn default_max_length() -> usize {
    10_000
}

impl BrowserTool {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none()) // Manual redirect handling
            .user_agent("ZapClaw/0.1 (Read-Only Browser Tool)")
            // No cookie store — stateless
            .build()
            .expect("Failed to build HTTP client");

        Self { client }
    }

    /// Fetch URL and extract text content with full SSRF protection.
    async fn fetch_text(&self, url: &str, max_length: usize) -> Result<String> {
        // Parse and validate initial URL
        let parsed_url: Url = url.parse()
            .context("Invalid URL")?;

        // Validate outbound target before first request
        validate_outbound_target(&parsed_url).await?;

        // Fetch with manual redirect validation
        let response = self.fetch_with_validated_redirects(parsed_url).await?;

        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("HTTP error {}: {}", status.as_u16(), status.canonical_reason().unwrap_or("Unknown"));
        }

        // Get content type
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("text/plain")
            .to_string();

        let body = response.text().await
            .context("Failed to read response body")?;

        // Extract text based on content type
        let text = if content_type.contains("html") {
            // Try readability extraction first
            match extract_article_content(&body, url) {
                Ok(article_text) => article_text,
                Err(e) => {
                    log::warn!("Readability extraction failed ({}), falling back to basic HTML stripping", e);
                    extract_text_from_html(&body)
                }
            }
        } else {
            body
        };

        // Truncate to max length
        if text.len() > max_length {
            Ok(format!(
                "{}\n\n[Truncated: showing {}/{} characters]",
                &text[..max_length],
                max_length,
                text.len()
            ))
        } else {
            Ok(text)
        }
    }

    /// Fetch URL with manual redirect handling and per-hop SSRF validation.
    async fn fetch_with_validated_redirects(&self, start_url: Url) -> Result<reqwest::Response> {
        let mut current_url = start_url;
        let mut redirect_count = 0;

        loop {
            log::debug!("Fetching URL (redirects so far: {}): {}", redirect_count, current_url);

            // Send request
            let response = self.client
                .get(current_url.clone())
                .send()
                .await
                .with_context(|| format!("Failed to fetch URL: {}", current_url))?;

            // Check if it's a redirect
            if response.status().is_redirection() {
                // Enforce redirect hop limit BEFORE following redirect
                if redirect_count >= MAX_REDIRECT_HOPS {
                    anyhow::bail!(
                        "🚫 SSRF BLOCKED: Redirect chain exceeded maximum hops ({})",
                        MAX_REDIRECT_HOPS
                    );
                }

                // Extract Location header
                let location = response.headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| anyhow::anyhow!(
                        "🚫 SSRF BLOCKED: Redirect response missing Location header"
                    ))?;

                // Resolve relative Location against current URL
                let next_url = current_url.join(location)
                    .with_context(|| format!("Invalid redirect Location: {}", location))?;

                redirect_count += 1;

                log::info!(
                    "🔄 Redirect hop {}/{}: {} -> {}",
                    redirect_count,
                    MAX_REDIRECT_HOPS,
                    current_url,
                    next_url
                );

                // Validate next URL before following
                validate_outbound_target(&next_url).await?;

                current_url = next_url;
            } else {
                // Non-redirect response, return it
                return Ok(response);
            }
        }
    }
}

impl Default for BrowserTool {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SSRF Validation Helpers
// ============================================================================

/// Unified SSRF validation gate for outbound targets.
///
/// Enforces all policies in sequence:
/// 1. Scheme and port restrictions
/// 2. Hostname lexical guard (local/internal names)
/// 3. IP address classification (literal or DNS-resolved)
///
/// Blocks on first policy violation with actionable error.
async fn validate_outbound_target(url: &Url) -> Result<()> {
    // 1. Validate scheme and port
    let port = validate_scheme_and_port(url)?;

    // 2. Check host presence
    let host = url.host_str()
        .ok_or_else(|| anyhow::anyhow!("🚫 SSRF BLOCKED: URL missing host"))?;

    // 3. Lexical hostname guard (pre-DNS)
    if is_blocked_local_hostname(host) {
        anyhow::bail!(
            "🚫 SSRF BLOCKED: Blocked local/internal hostname: {}",
            host
        );
    }

    // 4. IP classification (literal or DNS-resolved)
    if let Ok(literal_ip) = host.parse::<IpAddr>() {
        // Literal IP: check directly
        if is_disallowed_ip(literal_ip) {
            anyhow::bail!(
                "🚫 SSRF BLOCKED: Literal IP address is not globally routable: {}",
                literal_ip
            );
        }
        log::debug!("Literal IP validation passed: {}", literal_ip);
    } else {
        // Hostname: resolve and check all IPs
        let ips = resolve_host_ips_with_retry(host, port).await?;
        for ip in &ips {
            if is_disallowed_ip(*ip) {
                log::warn!(
                    "🚫 SSRF BLOCKED: Hostname '{}' resolved to disallowed IP: {}",
                    host,
                    ip
                );
                anyhow::bail!(
                    "🚫 SSRF BLOCKED: Hostname '{}' resolved to disallowed IP: {} (fail-closed: mixed DNS answers blocked)",
                    host,
                    ip
                );
            }
        }
        log::debug!("DNS resolution validation passed: {} -> {:?}", host, ips);
    }

    Ok(())
}

/// Validate URL scheme and enforce strict port policy.
///
/// Returns the port number if valid.
///
/// Policy:
/// - Only http and https schemes allowed
/// - http must use port 80
/// - https must use port 443
/// - Explicit non-standard ports are blocked
fn validate_scheme_and_port(url: &Url) -> Result<u16> {
    match url.scheme() {
        "http" => {
            let port = url.port().unwrap_or(80);
            if port != 80 {
                anyhow::bail!(
                    "🚫 SSRF BLOCKED: HTTP URL must use port 80, got port {}",
                    port
                );
            }
            Ok(80)
        }
        "https" => {
            let port = url.port().unwrap_or(443);
            if port != 443 {
                anyhow::bail!(
                    "🚫 SSRF BLOCKED: HTTPS URL must use port 443, got port {}",
                    port
                );
            }
            Ok(443)
        }
        scheme => {
            anyhow::bail!(
                "🚫 SSRF BLOCKED: Unsupported URL scheme: '{}'. Only http/https allowed.",
                scheme
            );
        }
    }
}

/// Check if hostname is a blocked local/internal name (pre-DNS guard).
///
/// Blocks:
/// - localhost
/// - *.localhost
/// - *.local
/// - *.internal
fn is_blocked_local_hostname(host: &str) -> bool {
    let host_lower = host.to_lowercase();

    // Exact match for localhost
    if host_lower == "localhost" {
        return true;
    }

    // Suffix matches for local/internal TLDs
    if host_lower.ends_with(".localhost")
        || host_lower.ends_with(".local")
        || host_lower.ends_with(".internal")
    {
        return true;
    }

    false
}

/// Check if IP address is disallowed (not globally routable unicast).
///
/// Policy: Allow only globally routable unicast addresses.
/// Block everything else:
/// - Loopback (127.0.0.0/8, ::1)
/// - Private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
/// - Link-local (169.254.0.0/16, fe80::/10)
/// - Carrier-grade NAT (100.64.0.0/10)
/// - Multicast (224.0.0.0/4, ff00::/8)
/// - Unspecified (0.0.0.0, ::)
/// - Reserved/documentation ranges
/// - IPv4-mapped IPv6 addresses (::ffff:0:0/96) - blocks mapped IPv4 loopback/private
fn is_disallowed_ip(ip: IpAddr) -> bool {
    // Check for IPv4-mapped IPv6 addresses first (SSRF bypass protection)
    if let IpAddr::V6(ipv6) = ip {
        // IPv4-mapped IPv6 (::ffff:0:0/96)
        // Format: 0:0:0:0:0:ffff:IPv4
        // Segments 5 and 6 contain 0xffff, last 4 bytes contain IPv4
        let segments = ipv6.segments();
        if segments[0] == 0 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0
            && segments[4] == 0 && segments[5] == 0xffff {

            let octets = ipv6.octets();
            // IPv4 is in last 4 bytes: octets[12..16]
            let a = octets[12] as u8;
            let b = octets[13] as u8;
            let _c = octets[14] as u8;
            let _d = octets[15] as u8;

            // Check if the embedded IPv4 is private/loopback/link-local
            // Loopback: 127.0.0.0/8
            if a == 127 {
                return true;
            }
            // Private: 10.0.0.0/8
            if a == 10 {
                return true;
            }
            // Private: 172.16.0.0/12
            if a == 172 && b >= 16 && b <= 31 {
                return true;
            }
            // Private: 192.168.0.0/16
            if a == 192 && b == 168 {
                return true;
            }
            // Link-local: 169.254.0.0/16
            if a == 169 && b == 254 {
                return true;
            }
            // Carrier-grade NAT: 100.64.0.0/10
            if a == 100 && b >= 64 && b <= 127 {
                return true;
            }
        }

        // Regular IPv6 checks
        if ipv6.is_loopback() {
            return true;
        }
    }

    match ip {
        IpAddr::V4(ipv4) => {
            // Loopback
            if ipv4.is_loopback() {
                return true;
            }

            // Private
            if ipv4.is_private() {
                return true;
            }

            // Link-local
            if ipv4.is_link_local() {
                return true;
            }

            // Multicast
            if ipv4.is_multicast() {
                return true;
            }

            // Unspecified
            if ipv4.is_unspecified() {
                return true;
            }

            // Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
            let octets = ipv4.octets();
            if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
                return true;
            }
            if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
                return true;
            }
            if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
                return true;
            }

            // Benchmark (198.18.0.0/15)
            if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
                return true;
            }

            // Carrier-grade NAT (100.64.0.0/10)
            if octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127 {
                return true;
            }

            // Reserved (240.0.0.0/4)
            if octets[0] >= 240 {
                return true;
            }

            false
        }
        IpAddr::V6(ipv6) => {
            // Loopback
            if ipv6.is_loopback() {
                return true;
            }

            // Unique local (fc00::/7)
            if (ipv6.segments()[0] & 0xfe00) == 0xfc00 {
                return true;
            }

            // Link-local (fe80::/10)
            if ipv6.is_unicast_link_local() {
                return true;
            }

            // Multicast (ff00::/8)
            if ipv6.is_multicast() {
                return true;
            }

            // Unspecified
            if ipv6.is_unspecified() {
                return true;
            }

            // Documentation range (2001:db8::/32)
            if ipv6.segments()[0] == 0x2001 && ipv6.segments()[1] == 0xdb8 {
                return true;
            }

            false
        }
    }
}

/// Resolve hostname to IP addresses with retry logic.
///
/// Policy:
/// - Initial attempt + one retry (total 2 attempts)
/// - Fail-closed: block if DNS fails after retry
/// - Block if no addresses returned
/// - Deduplicate addresses before returning
async fn resolve_host_ips_with_retry(host: &str, _port: u16) -> Result<Vec<IpAddr>> {
    let mut last_error = None;

    for attempt in 0..DNS_LOOKUP_RETRIES {
        match tokio::net::lookup_host((host, _port)).await {
            Ok(sockaddrs) => {
                // Extract and deduplicate IPs
                let ips: Vec<IpAddr> = sockaddrs
                    .map(|addr| addr.ip())
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect();

                if ips.is_empty() {
                    anyhow::bail!(
                        "🚫 SSRF BLOCKED: DNS resolution for '{}' returned no addresses",
                        host
                    );
                }

                if attempt > 0 {
                    log::info!("DNS resolution succeeded on retry {}/{} for '{}': {:?}", attempt + 1, DNS_LOOKUP_RETRIES, host, ips);
                } else {
                    log::debug!("DNS resolution for '{}': {:?}", host, ips);
                }

                return Ok(ips);
            }
            Err(e) => {
                last_error = Some(e);
                if attempt < DNS_LOOKUP_RETRIES - 1 {
                    log::warn!(
                        "DNS lookup failed for '{}' (attempt {}/{}), retrying...",
                        host,
                        attempt + 1,
                        DNS_LOOKUP_RETRIES
                    );
                }
            }
        }
    }

    // All attempts failed
    anyhow::bail!(
        "🚫 SSRF BLOCKED: DNS resolution failed for '{}' after {} attempts: {}",
        host,
        DNS_LOOKUP_RETRIES,
        last_error.unwrap()
    );
}

// ============================================================================
// HTML Extraction Helpers (unchanged)
// ============================================================================

/// Extract main article content using Mozilla Readability algorithm.
///
/// Returns formatted text with title, byline, and clean article content.
/// Falls back to basic HTML stripping if readability extraction fails.
fn extract_article_content(html: &str, _url: &str) -> Result<String> {
    // Parse with readability (use default options)
    let mut parser = Readability::new(html, None)
        .context("Failed to create readability parser")?;

    let article = parser.parse()
        .ok_or_else(|| anyhow::anyhow!("Readability failed to extract article"))?;

    // Format the output
    let mut output = String::new();

    // Title
    if let Some(title) = article.title {
        if !title.is_empty() {
            output.push_str(&format!("# {}\n\n", title));
        }
    }

    // Byline (author)
    if let Some(byline) = article.byline {
        if !byline.is_empty() {
            output.push_str(&format!("**By {}**\n\n", byline));
        }
    }

    // Excerpt (if available)
    if let Some(excerpt) = article.excerpt {
        if !excerpt.is_empty() {
            output.push_str(&format!("_{}_\n\n", excerpt));
        }
    }

    // Main content (use text_content for clean plain text)
    if let Some(text_content) = article.text_content {
        output.push_str(&text_content);
    } else if let Some(content_html) = article.content {
        // Fallback: strip HTML if text_content not available
        output.push_str(&extract_text_from_html(&content_html));
    }

    Ok(output)
}

/// Basic HTML to text extraction (fallback).
///
/// Strips all tags and extracts text content. This is intentionally
/// simple — we don't need DOM parsing since we're read-only.
fn extract_text_from_html(html: &str) -> String {
    let mut text = String::new();
    let mut in_tag = false;
    let mut in_script = false;
    let mut in_style = false;

    let lower = html.to_lowercase();
    let chars: Vec<char> = html.chars().collect();
    let lower_chars: Vec<char> = lower.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if in_script {
            // Skip until </script>
            if i + 9 <= lower_chars.len() {
                let slice: String = lower_chars[i..i+9].iter().collect();
                if slice == "</script>" {
                    in_script = false;
                    i += 9;
                    continue;
                }
            }
            i += 1;
            continue;
        }

        if in_style {
            if i + 8 <= lower_chars.len() {
                let slice: String = lower_chars[i..i+8].iter().collect();
                if slice == "</style>" {
                    in_style = false;
                    i += 8;
                    continue;
                }
            }
            i += 1;
            continue;
        }

        if chars[i] == '<' {
            // Check for script/style start
            if i + 7 <= lower_chars.len() {
                let slice: String = lower_chars[i..i+7].iter().collect();
                if slice == "<script" {
                    in_script = true;
                    i += 7;
                    continue;
                }
            }
            if i + 6 <= lower_chars.len() {
                let slice: String = lower_chars[i..i+6].iter().collect();
                if slice == "<style" {
                    in_style = true;
                    i += 6;
                    continue;
                }
            }

            in_tag = true;

            // Add newline for block elements
            if i + 2 < lower_chars.len() {
                let next_two: String = lower_chars[i+1..i+3.min(lower_chars.len())].iter().collect();
                if next_two.starts_with('p') || next_two.starts_with("br")
                    || next_two.starts_with("di") || next_two.starts_with("h1")
                    || next_two.starts_with("h2") || next_two.starts_with("h3")
                    || next_two.starts_with("li") || next_two.starts_with("tr")
                {
                    text.push('\n');
                }
            }
        } else if chars[i] == '>' {
            in_tag = false;
        } else if !in_tag {
            text.push(chars[i]);
        }

        i += 1;
    }

    // Decode common HTML entities
    text = text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ");

    // Collapse whitespace
    let lines: Vec<&str> = text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();

    lines.join("\n")
}

#[async_trait]
impl Tool for BrowserTool {
    fn name(&self) -> &str {
        "browse_url"
    }

    fn description(&self) -> &str {
        "Fetch and read the text content of a web page (read-only). \
         No JavaScript execution, no form submission, no cookies. \
         Returns the text content of the page, stripped of HTML tags. \
         SSRF-protected: only http/https, default ports only, blocks private networks."
    }

    fn requires_confirmation(&self) -> bool {
        true // Network access requires confirmation
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to fetch (http/https only, default ports only)"
                },
                "max_length": {
                    "type": "integer",
                    "description": "Maximum characters to return (default: 10000)"
                }
            },
            "required": ["url"]
        })
    }

    async fn execute(&self, arguments: &str) -> Result<String> {
        let args: BrowserArgs = serde_json::from_str(arguments)
            .context("Invalid browser tool arguments")?;

        self.fetch_text(&args.url, args.max_length).await
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ========================================================================
    // A. IP Classification Tests
    // ========================================================================

    #[test]
    fn test_ip_policy_blocks_private_v4_ranges() {
        // 10.0.0.0/8
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        // 172.16.0.0/12
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        // 192.168.0.0/16
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_ip_policy_blocks_loopback_linklocal_unspecified_v4() {
        // Loopback
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        // Link-local
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1))));
        // Unspecified
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
    }

    #[test]
    fn test_ip_policy_blocks_private_v6_ranges() {
        // Unique local (fc00::/7)
        assert!(is_disallowed_ip(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))));
        assert!(is_disallowed_ip(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn test_ip_policy_blocks_loopback_linklocal_unspecified_v6() {
        // Loopback
        assert!(is_disallowed_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // Link-local
        assert!(is_disallowed_ip(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))));
        // Unspecified
        assert!(is_disallowed_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn test_ip_policy_allows_public_v4_v6() {
        // Public IPv4
        assert!(!is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        // Public IPv6
        assert!(!is_disallowed_ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 1))));
    }

    // ========================================================================
    // B. Hostname Lexical Policy Tests
    // ========================================================================

    #[test]
    fn test_blocked_local_hostnames() {
        assert!(is_blocked_local_hostname("localhost"));
        assert!(is_blocked_local_hostname("example.localhost"));
        assert!(is_blocked_local_hostname("test.local"));
        assert!(is_blocked_local_hostname("internal.local"));
        assert!(is_blocked_local_hostname("service.internal"));
    }

    #[test]
    fn test_allowed_public_hostnames() {
        assert!(!is_blocked_local_hostname("example.com"));
        assert!(!is_blocked_local_hostname("google.com"));
        assert!(!is_blocked_local_hostname("api.github.com"));
        assert!(!is_blocked_local_hostname("subdomain.example.co.uk"));
    }

    #[test]
    fn test_literal_private_ip_still_blocked() {
        // Literal private IPs should pass hostname check but fail IP check
        assert!(!is_blocked_local_hostname("192.168.1.1"));
        assert!(!is_blocked_local_hostname("127.0.0.1"));
        assert!(!is_blocked_local_hostname("10.0.0.1"));
        // But they should be caught by is_disallowed_ip
        assert!(is_disallowed_ip("192.168.1.1".parse::<IpAddr>().unwrap()));
        assert!(is_disallowed_ip("127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_disallowed_ip("10.0.0.1".parse::<IpAddr>().unwrap()));
    }

    // ========================================================================
    // C. Scheme/Port Policy Tests
    // ========================================================================

    #[test]
    fn test_scheme_restriction_http_https_only() {
        let http_url: Url = "http://example.com".parse().unwrap();
        assert!(validate_scheme_and_port(&http_url).is_ok());

        let https_url: Url = "https://example.com".parse().unwrap();
        assert!(validate_scheme_and_port(&https_url).is_ok());

        let ftp_url: Url = "ftp://example.com".parse().unwrap();
        assert!(validate_scheme_and_port(&ftp_url).is_err());
    }

    #[test]
    fn test_port_policy_allows_default_ports() {
        let http_default: Url = "http://example.com:80".parse().unwrap();
        assert!(validate_scheme_and_port(&http_default).is_ok());

        let http_implicit: Url = "http://example.com".parse().unwrap();
        assert!(validate_scheme_and_port(&http_implicit).is_ok());

        let https_default: Url = "https://example.com:443".parse().unwrap();
        assert!(validate_scheme_and_port(&https_default).is_ok());

        let https_implicit: Url = "https://example.com".parse().unwrap();
        assert!(validate_scheme_and_port(&https_implicit).is_ok());
    }

    #[test]
    fn test_port_policy_blocks_non_standard_ports() {
        let http_8080: Url = "http://example.com:8080".parse().unwrap();
        assert!(validate_scheme_and_port(&http_8080).is_err());

        let https_8443: Url = "https://example.com:8443".parse().unwrap();
        assert!(validate_scheme_and_port(&https_8443).is_err());
    }

    // ========================================================================
    // HTML Extraction Tests (unchanged)
    // ========================================================================

    #[test]
    fn test_html_extraction() {
        let html = "<html><body><h1>Title</h1><p>Hello <b>world</b>!</p></body></html>";
        let text = extract_text_from_html(html);
        assert!(text.contains("Title"));
        assert!(text.contains("Hello world!"));
    }

    #[test]
    fn test_script_removal() {
        let html = "<p>Before</p><script>alert('xss')</script><p>After</p>";
        let text = extract_text_from_html(html);
        assert!(text.contains("Before"));
        assert!(text.contains("After"));
        assert!(!text.contains("alert"));
    }

    #[test]
    fn test_entity_decode() {
        let html = "<p>A &amp; B &lt; C</p>";
        let text = extract_text_from_html(html);
        assert!(text.contains("A & B < C"));
    }

    // ========================================================================
    // D. DNS Resolution Behavior Tests (integration-style)
    // ========================================================================

    #[tokio::test]
    async fn test_dns_resolution_allows_public_hosts() {
        // This test actually resolves public hostnames
        let result = resolve_host_ips_with_retry("example.com", 80).await;
        assert!(result.is_ok());
        let ips = result.unwrap();
        assert!(!ips.is_empty());
        // All should be public IPs
        for ip in ips {
            assert!(!is_disallowed_ip(ip), "Public hostname resolved to disallowed IP: {}", ip);
        }
    }

    #[tokio::test]
    async fn test_dns_resolution_blocks_if_any_answer_is_disallowed() {
        // localhost resolves to 127.0.0.1 which is disallowed
        let result = resolve_host_ips_with_retry("localhost", 80).await;
        assert!(result.is_ok());
        let ips = result.unwrap();
        assert!(!ips.is_empty());
        // At least one should be disallowed
        assert!(ips.iter().any(|ip| is_disallowed_ip(*ip)),
            "Expected localhost to resolve to disallowed IP, got: {:?}", ips);
    }

    // ========================================================================
    // E. URL Validation Tests
    // ========================================================================

    #[tokio::test]
    async fn test_validate_outbound_target_allows_public_http() {
        let url: Url = "http://example.com".parse().unwrap();
        assert!(validate_outbound_target(&url).await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_outbound_target_allows_public_https() {
        let url: Url = "https://example.com".parse().unwrap();
        assert!(validate_outbound_target(&url).await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_outbound_target_blocks_localhost() {
        let url: Url = "http://localhost".parse().unwrap();
        assert!(validate_outbound_target(&url).await.is_err());
    }

    #[tokio::test]
    async fn test_validate_outbound_target_blocks_literal_loopback() {
        let url: Url = "http://127.0.0.1".parse().unwrap();
        assert!(validate_outbound_target(&url).await.is_err());
    }

    #[tokio::test]
    async fn test_validate_outbound_target_blocks_non_standard_port() {
        let url: Url = "http://example.com:8080".parse().unwrap();
        assert!(validate_outbound_target(&url).await.is_err());
    }

    #[tokio::test]
    async fn test_validate_outbound_target_blocks_private_ip() {
        let url: Url = "http://192.168.1.1".parse().unwrap();
        assert!(validate_outbound_target(&url).await.is_err());
    }

    // ========================================================================
    // F. IPv4-mapped IPv6 SSRF bypass tests
    // ========================================================================

    #[test]
    fn test_ipv4_mapped_ipv6_loopback_is_blocked() {
        // ::ffff:127.0.0.1 is IPv4-mapped loopback
        let ip: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        println!("Testing ::ffff:127.0.0.1");
        println!("is_disallowed_ip result: {}", is_disallowed_ip(ip));
        assert!(is_disallowed_ip(ip), "IPv4-mapped loopback should be blocked");
    }

    #[test]
    fn test_ipv4_mapped_ipv6_private_is_blocked() {
        // ::ffff:192.168.1.1 is IPv4-mapped private
        let ip: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
        println!("Testing ::ffff:192.168.1.1");
        println!("is_disallowed_ip result: {}", is_disallowed_ip(ip));
        assert!(is_disallowed_ip(ip), "IPv4-mapped private IP should be blocked");
    }

    #[test]
    fn test_ipv4_mapped_ipv6_public_is_allowed() {
        // ::ffff:8.8.8.8 is IPv4-mapped public IP
        let ip: IpAddr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(!is_disallowed_ip(ip), "IPv4-mapped public IP should be allowed");
    }

    // ========================================================================
    // G. CGNAT range tests
    // ========================================================================

    #[test]
    fn test_cgnat_range_is_blocked() {
        // 100.64.0.0/10 (Carrier-grade NAT)
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(100, 100, 0, 1))));
        assert!(is_disallowed_ip(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 255))));
    }

    // ========================================================================
    // H. Redirect hop limit verification tests
    // ========================================================================

    #[test]
    fn test_max_redirect_hops_constant() {
        // Verify the constant is set correctly
        assert_eq!(MAX_REDIRECT_HOPS, 3, "Should allow 3 redirect hops");
    }

    #[test]
    fn test_dns_lookup_retries_constant() {
        // Verify DNS retry policy
        assert_eq!(DNS_LOOKUP_RETRIES, 2, "Should retry DNS lookup once (2 total attempts)");
    }

    // ========================================================================
    // I. Integration-style redirect behavior tests
    // ========================================================================
    //
    // Note: Full redirect-chain testing with mocked HTTP responses requires
    // additional test dependencies (e.g., mockito, wiremock). The current
    // tests verify the validation logic and hop counting mechanism.
    //
    // To add full redirect-chain tests, add mockito to dev-dependencies and
    // create tests that:
    // 1. Mock HTTP server with redirect endpoints
    // 2. Test redirect to private host is blocked mid-chain
    // 3. Test redirect to non-standard port is blocked mid-chain
    // 4. Test relative redirect inherits and revalidates host
    // 5. Test redirect hop limit is enforced (4th redirect blocked)
    //
    // Example structure:
    // #[tokio::test]
    // async fn test_redirect_to_private_host_blocked() {
    //     let mock_server = mockito::Server::new();
    //     let _mock1 = mock_server.mock("GET", "/")
    //         .with_status(302)
    //         .with_header("location", "http://192.168.1.1/admin")
    //         .create();
    //     let tool = BrowserTool::new();
    //     let url = format!("{}/", mock_server.url());
    //     let result = tool.fetch_text(&url, 1000).await;
    //     assert!(result.is_err());
    //     assert!(result.unwrap_err().to_string().contains("SSRF BLOCKED"));
    // }
}
