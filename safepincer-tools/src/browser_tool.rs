use anyhow::{Context, Result};
use async_trait::async_trait;
use safepincer_core::agent::Tool;
use serde::Deserialize;

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
            .user_agent("SafePincer/0.1 (Read-Only Browser Tool)")
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
            extract_text_from_html(&body)
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

/// Robust HTML to Markdown converter.
///
/// Converts HTML structure into clean Markdown for better LLM readability:
/// - Headers (h1-h6) -> # Header
/// - Lists (ul/ol/li) -> - Item
/// - Links (a) -> [text](href)
/// - Images (img) -> ![alt](src)
/// - Code blocks (pre/code) -> ```\n...\n```
/// - Blockquotes (blockquote) -> > text
/// - Bold/Italic (b, strong, i, em) -> **text**, *text*
/// - Paragraphs/Divs -> \n\n
fn extract_text_from_html(html: &str) -> String {
    let mut output = String::with_capacity(html.len());
    let mut in_tag = false;
    let mut tag_name = String::new();
    let mut attributes = std::collections::HashMap::new();
    let mut tag_stack: Vec<String> = Vec::new();
    
    // Simple state machine for parsing
    let chars: Vec<char> = html.chars().collect();
    let mut i = 0;
    
    // Helper to check if we are inside specific tags
    let in_code_block = |stack: &[String]| stack.iter().any(|t| t == "pre" || t == "code");
    let in_script_style = |stack: &[String]| stack.iter().any(|t| t == "script" || t == "style");

    while i < chars.len() {
        if chars[i] == '<' && i + 1 < chars.len() {
            // Check for comments
            if i + 4 <= chars.len() && &html[i..i+4] == "<!--" {
                if let Some(end) = html[i..].find("-->") {
                    i += end + 3;
                    continue;
                }
            }

            // Start of tag
            in_tag = true;
            let closing = chars[i+1] == '/';
            let start = i + 1 + (if closing { 1 } else { 0 });
            
            // Find end of tag name
            let mut end = start;
            while end < chars.len() && (chars[end].is_alphanumeric() || chars[end] == '-') {
                end += 1;
            }
            
            tag_name = html[start..end].to_lowercase();
            
            // Parse attributes if opening tag
            attributes.clear();
            if !closing {
                let mut attr_start = end;
                while attr_start < chars.len() && chars[attr_start] != '>' {
                    // Skip whitespace
                    while attr_start < chars.len() && chars[attr_start].is_whitespace() {
                        attr_start += 1;
                    }
                    if attr_start >= chars.len() || chars[attr_start] == '>' { break; }
                    
                    // Parse attr name
                    let mut name_end = attr_start;
                    while name_end < chars.len() && chars[name_end] != '=' && !chars[name_end].is_whitespace() && chars[name_end] != '>' {
                        name_end += 1;
                    }
                    let attr_name = html[attr_start..name_end].to_lowercase();
                    
                    // Parse attr value
                    let mut val_start = name_end;
                    while val_start < chars.len() && chars[val_start].is_whitespace() {
                        val_start += 1;
                    }
                    
                    if val_start < chars.len() && chars[val_start] == '=' {
                        val_start += 1;
                        while val_start < chars.len() && chars[val_start].is_whitespace() {
                            val_start += 1;
                        }
                        
                        if val_start < chars.len() {
                            let quote = chars[val_start];
                            if quote == '"' || quote == '\'' {
                                let mut val_end = val_start + 1;
                                while val_end < chars.len() && chars[val_end] != quote {
                                    val_end += 1;
                                }
                                if val_end < chars.len() {
                                    attributes.insert(attr_name, html[val_start+1..val_end].to_string());
                                    attr_start = val_end + 1;
                                    continue;
                                }
                            }
                        }
                    }
                    attr_start = name_end + 1;
                }
            }

            // Find end of tag bracket
            while i < chars.len() && chars[i] != '>' {
                i += 1;
            }
            
            if !in_script_style(&tag_stack) {
                match (closing, tag_name.as_str()) {
                    // Block elements
                    (false, "p") | (false, "div") | (false, "article") | (false, "section") => output.push_str("\n\n"),
                    (true, "p") | (true, "div") | (true, "article") | (true, "section") => output.push_str("\n\n"),
                    
                    (false, "br") => output.push('\n'),
                    (false, "hr") => output.push_str("\n---\n"),
                    
                    // Headers
                    (false, "h1") => output.push_str("\n\n# "),
                    (false, "h2") => output.push_str("\n\n## "),
                    (false, "h3") => output.push_str("\n\n### "),
                    (false, "h4") => output.push_str("\n\n#### "),
                    (true, h) if h.starts_with("h") => output.push_str("\n\n"),
                    
                    // Lists
                    (false, "ul") | (false, "ol") => output.push_str("\n\n"),
                    (true, "ul") | (true, "ol") => output.push_str("\n\n"),
                    (false, "li") => output.push_str("\n- "),
                    
                    // Formatting
                    (false, "b") | (false, "strong") => output.push_str("**"),
                    (true, "b") | (true, "strong") => output.push_str("**"),
                    (false, "i") | (false, "em") => output.push('*'),
                    (true, "i") | (true, "em") => output.push('*'),
                    
                    // Code
                    (false, "pre") => output.push_str("\n```\n"),
                    (true, "pre") => output.push_str("\n```\n"),
                    (false, "code") if !tag_stack.contains(&"pre".to_string()) => output.push('`'),
                    (true, "code") if !tag_stack.contains(&"pre".to_string()) => output.push('`'),
                    
                    // Links
                    (false, "a") => {
                        output.push('[');
                        // Store href for closing tag
                        if let Some(href) = attributes.get("href") {
                            tag_stack.push(format!("a:{}", href));
                            i += 1; // skip >
                            continue; // avoid pushing to stack below
                        }
                    },
                    (true, "a") => {
                        if let Some(last) = tag_stack.last() {
                            if last.starts_with("a:") {
                                let href = &last[2..];
                                if !href.starts_with("javascript:") && !href.starts_with('#') {
                                    output.push_str(&format!("]({})", href));
                                } else {
                                    output.push(']');
                                }
                            }
                        }
                    },
                    
                    // Images
                    (false, "img") => {
                        let alt = attributes.get("alt").map(|s| s.as_str()).unwrap_or("image");
                        if let Some(src) = attributes.get("src") {
                            output.push_str(&format!("![{}]({})", alt, src));
                        }
                    },
                    
                    // Blockquote
                    (false, "blockquote") => output.push_str("\n> "),
                    (true, "blockquote") => output.push_str("\n\n"),
                    
                    _ => {}
                }
            }
            
            if closing {
                if let Some(pos) = tag_stack.iter().rposition(|t| t == &tag_name || (t.starts_with("a:") && tag_name == "a")) {
                    tag_stack.truncate(pos);
                }
            } else if !html[start..i].ends_with('/') { // not self-closing
                if tag_name == "a" && attributes.contains_key("href") {
                   // handled above
                } else {
                    tag_stack.push(tag_name);
                }
            }
            
            in_tag = false;
        } else {
            // Text content
            if !in_tag && !in_script_style(&tag_stack) {
                // Decode entities
                let c = chars[i];
                if c == '&' {
                    let end = (i+10).min(chars.len());
                    let slice = &html[i..end];
                    if let Some(sc) = slice.find(';') {
                        let entity = &slice[1..sc];
                        let decoded = match entity {
                            "nbsp" => ' ',
                            "amp" => '&',
                            "lt" => '<',
                            "gt" => '>',
                            "quot" => '"',
                            "apos" => '\'',
                            "copy" => '©',
                            "reg" => '®',
                            _ => if entity.starts_with('#') {
                                // numeric
                                let num = if entity.starts_with("#x") {
                                    u32::from_str_radix(&entity[2..], 16)
                                } else {
                                    entity[1..].parse::<u32>()
                                };
                                num.ok().and_then(std::char::from_u32).unwrap_or('&')
                            } else {
                                '&'
                            }
                        };
                        if decoded != '&' {
                            output.push(decoded);
                            i += sc + 1;
                            continue;
                        }
                    }
                }
                
                // Collapse whitespace unless in code block
                if !in_code_block(&tag_stack) {
                    if c.is_whitespace() {
                        if output.ends_with(' ') || output.ends_with('\n') {
                            // skip
                        } else {
                            output.push(' ');
                        }
                    } else {
                        output.push(c);
                    }
                } else {
                    output.push(c);
                }
            }
        }
        i += 1;
    }

    // Post-processing cleanup
    let mut clean_lines = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            clean_lines.push(trimmed);
        }
    }
    
    clean_lines.join("\n")
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
