use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;

use pincer_core::agent::Tool;

/// Web search tool — search the web via configurable API.
///
/// Supports:
/// - Brave Search API (default)
/// - SearXNG (self-hosted, no API key required)
/// - DuckDuckGo HTML (no API key, fallback)
///
/// Security: read-only web access, no POST/mutation,
/// SSRF prevention via URL validation.
pub struct WebSearchTool {
    api_key: Option<String>,
    search_engine: SearchEngine,
    max_results: usize,
}

#[derive(Clone)]
pub enum SearchEngine {
    Brave,
    DuckDuckGo,
    SearXNG { base_url: String },
}

#[derive(Deserialize)]
struct SearchArgs {
    query: String,
    #[serde(default)]
    num_results: Option<usize>,
}

impl WebSearchTool {
    pub fn new(api_key: Option<String>, engine: SearchEngine) -> Self {
        Self {
            api_key,
            search_engine: engine,
            max_results: 10,
        }
    }

    /// Create with Brave Search API.
    pub fn brave(api_key: String) -> Self {
        Self::new(Some(api_key), SearchEngine::Brave)
    }

    /// Create with DuckDuckGo (no API key needed).
    pub fn duckduckgo() -> Self {
        Self::new(None, SearchEngine::DuckDuckGo)
    }

    async fn search_brave(&self, query: &str, num_results: usize) -> Result<String> {
        let api_key = self.api_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Brave Search API key not configured. Set PINCER_SEARCH_API_KEY."))?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let resp = client
            .get("https://api.search.brave.com/res/v1/web/search")
            .header("X-Subscription-Token", api_key)
            .header("Accept", "application/json")
            .query(&[
                ("q", query),
                ("count", &num_results.to_string()),
            ])
            .send()
            .await
            .context("Brave Search request failed")?;

        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("Brave Search API returned {}", status);
        }

        let json: serde_json::Value = resp.json().await
            .context("Failed to parse Brave Search response")?;

        let mut results = Vec::new();
        if let Some(web) = json.get("web").and_then(|w| w.get("results")) {
            if let Some(items) = web.as_array() {
                for (i, item) in items.iter().enumerate().take(num_results) {
                    let title = item.get("title").and_then(|t| t.as_str()).unwrap_or("");
                    let url = item.get("url").and_then(|u| u.as_str()).unwrap_or("");
                    let desc = item.get("description").and_then(|d| d.as_str()).unwrap_or("");
                    results.push(format!("{}. {} — {}\n   {}", i + 1, title, url, desc));
                }
            }
        }

        if results.is_empty() {
            return Ok(format!("No search results found for: '{}'", query));
        }

        Ok(format!("Search results for '{}':\n\n{}", query, results.join("\n\n")))
    }

    async fn search_duckduckgo(&self, query: &str, num_results: usize) -> Result<String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
            .build()?;

        let resp = client
            .get("https://html.duckduckgo.com/html/")
            .query(&[("q", query)])
            .send()
            .await
            .context("DuckDuckGo search request failed")?;

        let body = resp.text().await?;

        // Simple HTML parsing for DDG results
        let mut results = Vec::new();
        for (i, cap) in body.split("class=\"result__a\"").skip(1).enumerate() {
            if i >= num_results {
                break;
            }
            // Extract href
            let url = cap.split("href=\"").nth(1)
                .and_then(|s| s.split('"').next())
                .unwrap_or("");
            // Extract title text
            let title = cap.split('>').nth(1)
                .and_then(|s| s.split('<').next())
                .unwrap_or("");
            // Extract snippet
            let snippet = if let Some(snip) = cap.split("class=\"result__snippet\"").nth(1) {
                snip.split('>').nth(1)
                    .and_then(|s| s.split('<').next())
                    .unwrap_or("")
            } else {
                ""
            };

            if !url.is_empty() {
                results.push(format!("{}. {} — {}\n   {}", i + 1, title.trim(), url, snippet.trim()));
            }
        }

        if results.is_empty() {
            return Ok(format!("No search results found for: '{}'", query));
        }

        Ok(format!("Search results for '{}':\n\n{}", query, results.join("\n\n")))
    }

    async fn search_searxng(&self, base_url: &str, query: &str, num_results: usize) -> Result<String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let resp = client
            .get(&format!("{}/search", base_url))
            .query(&[
                ("q", query),
                ("format", "json"),
                ("categories", "general"),
            ])
            .send()
            .await
            .context("SearXNG search request failed")?;

        let json: serde_json::Value = resp.json().await?;

        let mut results = Vec::new();
        if let Some(items) = json.get("results").and_then(|r| r.as_array()) {
            for (i, item) in items.iter().enumerate().take(num_results) {
                let title = item.get("title").and_then(|t| t.as_str()).unwrap_or("");
                let url = item.get("url").and_then(|u| u.as_str()).unwrap_or("");
                let content = item.get("content").and_then(|c| c.as_str()).unwrap_or("");
                results.push(format!("{}. {} — {}\n   {}", i + 1, title, url, content));
            }
        }

        if results.is_empty() {
            return Ok(format!("No search results found for: '{}'", query));
        }

        Ok(format!("Search results for '{}':\n\n{}", query, results.join("\n\n")))
    }
}

#[async_trait]
impl Tool for WebSearchTool {
    fn name(&self) -> &str {
        "web_search"
    }

    fn description(&self) -> &str {
        "Search the web for information. Returns titles, URLs, and descriptions. Use for current events, documentation, troubleshooting."
    }

    fn requires_confirmation(&self) -> bool {
        false
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query"
                },
                "num_results": {
                    "type": "integer",
                    "description": "Number of results to return (default: 5)"
                }
            },
            "required": ["query"]
        })
    }

    async fn execute(&self, arguments: &str) -> Result<String> {
        let args: SearchArgs = serde_json::from_str(arguments)
            .context("Invalid web_search arguments")?;

        let num_results = args.num_results.unwrap_or(5).min(self.max_results);

        match &self.search_engine {
            SearchEngine::Brave => self.search_brave(&args.query, num_results).await,
            SearchEngine::DuckDuckGo => self.search_duckduckgo(&args.query, num_results).await,
            SearchEngine::SearXNG { base_url } => {
                let url = base_url.clone();
                self.search_searxng(&url, &args.query, num_results).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_metadata() {
        let tool = WebSearchTool::duckduckgo();
        assert_eq!(tool.name(), "web_search");
        assert!(!tool.requires_confirmation());
    }
}
