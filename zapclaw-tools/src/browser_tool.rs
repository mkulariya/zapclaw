use anyhow::{Context, Result};
use async_trait::async_trait;
use zapclaw_core::agent::Tool;
use serde::Deserialize;
use readability_rust::Readability;

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
            .redirect(reqwest::redirect::Policy::limited(3))
            .user_agent("ZapClaw/0.1 (Read-Only Browser Tool)")
            // No cookie store — stateless
            .build()
            .expect("Failed to build HTTP client");

        Self { client }
    }

    /// Fetch URL and extract text content.
    async fn fetch_text(&self, url: &str, max_length: usize) -> Result<String> {
        // Validate URL
        let parsed: url::Url = url.parse()
            .context("Invalid URL")?;

        // Security: Only allow http/https
        match parsed.scheme() {
            "http" | "https" => {}
            scheme => anyhow::bail!("Unsupported URL scheme: '{}'. Only http/https allowed.", scheme),
        }

        // Security: Block private/local network access
        if let Some(host) = parsed.host_str() {
            if is_private_host(host) {
                anyhow::bail!(
                    "🚫 Blocked access to private/local network address: {}",
                    host
                );
            }
        }

        // Fetch the page
        let response = self.client.get(url)
            .send()
            .await
            .with_context(|| format!("Failed to fetch URL: {}", url))?;

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
}

impl Default for BrowserTool {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a hostname points to a private/local network.
fn is_private_host(host: &str) -> bool {
    let host_lower = host.to_lowercase();

    // Block localhost and common local names
    if host_lower == "localhost"
        || host_lower == "127.0.0.1"
        || host_lower == "::1"
        || host_lower == "0.0.0.0"
        || host_lower.ends_with(".local")
        || host_lower.ends_with(".internal")
    {
        return true;
    }

    // Block private IP ranges
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                return ipv4.is_loopback()
                    || ipv4.is_private()
                    || ipv4.is_link_local()
                    || ipv4.octets()[0] == 0;
            }
            std::net::IpAddr::V6(ipv6) => {
                return ipv6.is_loopback();
            }
        }
    }

    false
}

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
         Returns the text content of the page, stripped of HTML tags."
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
                    "description": "The URL to fetch (http/https only)"
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_private_host_detection() {
        assert!(is_private_host("localhost"));
        assert!(is_private_host("127.0.0.1"));
        assert!(is_private_host("::1"));
        assert!(is_private_host("192.168.1.1"));
        assert!(is_private_host("10.0.0.1"));
        assert!(is_private_host("172.16.0.1"));
        assert!(!is_private_host("google.com"));
        assert!(!is_private_host("8.8.8.8"));
    }
}
