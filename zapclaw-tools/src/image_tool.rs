use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;

use zapclaw_core::agent::Tool;

/// Image analysis tool — analyze images via multimodal LLM.
///
/// Sends image (base64 or URL) to a vision-capable model for analysis.
pub struct ImageTool {
    api_base_url: String,
    model: String,
    api_key: Option<String>,
}

#[derive(Deserialize)]
struct ImageArgs {
    /// Image path (local file in workspace) or URL
    image: String,
    /// Analysis prompt/question about the image
    prompt: Option<String>,
}

impl ImageTool {
    pub fn new(api_base_url: &str, model: &str, api_key: Option<String>) -> Self {
        Self {
            api_base_url: api_base_url.trim_end_matches('/').to_string(),
            model: model.to_string(),
            api_key,
        }
    }
}

#[async_trait]
impl Tool for ImageTool {
    fn name(&self) -> &str { "image" }

    fn description(&self) -> &str {
        "Analyze an image with the configured vision model. Accepts a local file path or URL."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "image": {
                    "type": "string",
                    "description": "Local file path (in workspace) or URL of the image"
                },
                "prompt": {
                    "type": "string",
                    "description": "Question or prompt about the image (default: 'Describe this image')"
                }
            },
            "required": ["image"]
        })
    }



    fn requires_confirmation(&self) -> bool { false }

    async fn execute(&self, args_json: &str) -> Result<String> {
        let args: ImageArgs = serde_json::from_str(args_json)
            .context("Invalid image arguments")?;

        let prompt = args.prompt.unwrap_or_else(|| "Describe this image in detail.".to_string());

        // Build the image content part
        let image_content = if args.image.starts_with("http://") || args.image.starts_with("https://") {
            // URL-based image
            serde_json::json!({
                "type": "image_url",
                "image_url": { "url": args.image }
            })
        } else {
            // Local file — read and base64 encode
            let path = std::path::Path::new(&args.image);
            if !path.exists() {
                anyhow::bail!("Image file not found: {}", args.image);
            }

            let data = std::fs::read(path)
                .with_context(|| format!("Failed to read image: {}", args.image))?;
            let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &data);

            // Detect MIME type from extension
            let mime = match path.extension().and_then(|e| e.to_str()) {
                Some("png") => "image/png",
                Some("gif") => "image/gif",
                Some("webp") => "image/webp",
                _ => "image/jpeg",
            };

            serde_json::json!({
                "type": "image_url",
                "image_url": { "url": format!("data:{};base64,{}", mime, b64) }
            })
        };

        // Build multi-modal message
        let request = serde_json::json!({
            "model": self.model,
            "messages": [{
                "role": "user",
                "content": [
                    { "type": "text", "text": prompt },
                    image_content
                ]
            }],
            "max_tokens": 1024
        });

        let url = format!("{}/chat/completions", self.api_base_url);

        let client = reqwest::Client::new();
        let mut req = client.post(&url)
            .header("Content-Type", "application/json");

        if let Some(ref key) = self.api_key {
            req = req.header("Authorization", format!("Bearer {}", key));
        }

        let response = req.json(&request).send().await
            .context("Failed to send image analysis request")?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Image analysis API error: {}", body);
        }

        let body: serde_json::Value = response.json().await
            .context("Failed to parse image analysis response")?;

        let content = body["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("No analysis returned.");

        Ok(content.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_name() {
        let tool = ImageTool::new("http://localhost:11434/v1", "llava", None);
        assert_eq!(tool.name(), "image");
        assert!(!tool.requires_confirmation());
    }
}
