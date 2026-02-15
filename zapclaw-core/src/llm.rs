use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

/// Messages for LLM conversations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
    /// Tool call ID (for tool results)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// Tool calls requested by the assistant
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    #[serde(rename = "type")]
    pub call_type: String,
    pub function: FunctionCall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCall {
    pub name: String,
    pub arguments: String,
}

/// Tool definition for LLM function calling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    #[serde(rename = "type")]
    pub tool_type: String,
    pub function: FunctionDefinition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

/// Response from the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmResponse {
    /// Text content of the response
    pub content: Option<String>,
    /// Tool calls requested by the model
    pub tool_calls: Vec<ToolCall>,
    /// Whether the model thinks the task is complete
    pub finish_reason: String,
    /// Token usage
    pub usage: Option<TokenUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// Streaming chunk — emitted token-by-token during SSE streaming.
/// Matches OpenClaw's streaming architecture with full event types.
#[derive(Debug, Clone)]
pub enum StreamChunk {
    /// Text content delta
    TextDelta(String),
    /// Reasoning/thinking content delta (content inside <think> tags)
    ReasoningDelta(String),
    /// Tool call delta (index, id, function name, argument fragment)
    ToolCallDelta {
        index: usize,
        id: Option<String>,
        name: Option<String>,
        arguments: Option<String>,
    },
    /// Tool execution started
    ToolStart {
        name: String,
        tool_call_id: String,
    },
    /// Tool execution ended with result
    ToolEnd {
        name: String,
        tool_call_id: String,
        result: String,
        is_error: bool,
    },
    /// Agent lifecycle event
    LifecycleEvent {
        phase: String, // "start", "end", "error", "step"
    },
    /// Stream is complete; final accumulated response
    Done(LlmResponse),
}

/// Detect context length exceeded errors from LLM API responses.
pub fn is_context_overflow_error(error: &anyhow::Error) -> bool {
    let msg = error.to_string().to_lowercase();
    msg.contains("context_length_exceeded")
        || msg.contains("context window")
        || msg.contains("maximum context length")
        || msg.contains("too many tokens")
        || (msg.contains("400") && (msg.contains("token") || msg.contains("length")))
}

/// LLM client trait — abstraction over any OpenAI-compatible API.
///
/// Both Ollama (local) and cloud providers (OpenAI, Anthropic) expose
/// OpenAI-compatible REST APIs, so a single implementation handles both.
#[async_trait]
pub trait LlmClient: Send + Sync {
    /// Send a chat completion request with optional tool definitions.
    async fn complete(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolDefinition],
    ) -> Result<LlmResponse>;

    /// Stream a chat completion, emitting chunks via the sender.
    /// Default implementation falls back to non-streaming complete().
    async fn complete_stream(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolDefinition],
        tx: mpsc::Sender<StreamChunk>,
    ) -> Result<LlmResponse> {
        let response = self.complete(messages, tools).await?;
        if let Some(ref content) = response.content {
            let _ = tx.send(StreamChunk::TextDelta(content.clone())).await;
        }
        let _ = tx.send(StreamChunk::Done(response.clone())).await;
        Ok(response)
    }

    /// Whether this client supports true streaming.
    fn supports_streaming(&self) -> bool {
        false
    }

    /// Get the model name this client is configured for.
    fn model_name(&self) -> &str;
}

/// OpenAI-compatible API client.
///
/// Works with:
/// - Ollama (local): http://localhost:11434/v1
/// - OpenAI: https://api.openai.com/v1
/// - Any OpenAI-compatible endpoint
pub struct OpenAiCompatibleClient {
    client: reqwest::Client,
    base_url: String,
    model: String,
    api_key: Option<String>,
}

impl OpenAiCompatibleClient {
    /// Create a new client.
    ///
    /// - `base_url`: API base URL (e.g., "http://localhost:11434/v1")
    /// - `model`: Model identifier (e.g., "phi3:mini")
    /// - `api_key`: Optional API key (required for cloud, not for local Ollama)
    pub fn new(base_url: &str, model: &str, api_key: Option<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            model: model.to_string(),
            api_key,
        }
    }

    /// Create a client configured for local Ollama.
    pub fn ollama(model: &str) -> Self {
        Self::new("http://localhost:11434/v1", model, None)
    }

    /// Create a client configured for OpenAI.
    pub fn openai(model: &str, api_key: String) -> Self {
        Self::new("https://api.openai.com/v1", model, Some(api_key))
    }
}

/// OpenAI API request/response types
#[derive(Serialize)]
struct ChatCompletionRequest {
    model: String,
    messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<ToolDefinition>,
    temperature: f32,
}

#[derive(Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<Choice>,
    usage: Option<ApiUsage>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChoiceMessage,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct ChoiceMessage {
    content: Option<String>,
    tool_calls: Option<Vec<ToolCall>>,
}

#[derive(Deserialize)]
struct ApiUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
    total_tokens: u32,
}

#[derive(Deserialize)]
struct ApiError {
    error: ApiErrorDetail,
}

#[derive(Deserialize)]
struct ApiErrorDetail {
    message: String,
}

#[async_trait]
impl LlmClient for OpenAiCompatibleClient {
    async fn complete(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolDefinition],
    ) -> Result<LlmResponse> {
        let url = format!("{}/chat/completions", self.base_url);

        let request = ChatCompletionRequest {
            model: self.model.clone(),
            messages: messages.to_vec(),
            tools: tools.to_vec(),
            temperature: 0.7,
        };

        let mut req_builder = self.client.post(&url)
            .header("Content-Type", "application/json");

        if let Some(ref key) = self.api_key {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", key));
        }

        let response = req_builder
            .json(&request)
            .send()
            .await
            .context("Failed to send request to LLM API")?;

        let status = response.status();
        let body = response.text().await.context("Failed to read LLM API response body")?;

        if !status.is_success() {
            // Try to parse error message
            if let Ok(api_error) = serde_json::from_str::<ApiError>(&body) {
                anyhow::bail!("LLM API error ({}): {}", status, api_error.error.message);
            }
            anyhow::bail!("LLM API error ({}): {}", status, body);
        }

        let completion: ChatCompletionResponse = serde_json::from_str(&body)
            .with_context(|| format!("Failed to parse LLM API response: {}", &body[..body.len().min(200)]))?;

        let choice = completion
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("LLM API returned no choices"))?;

        Ok(LlmResponse {
            content: choice.message.content,
            tool_calls: choice.message.tool_calls.unwrap_or_default(),
            finish_reason: choice.finish_reason.unwrap_or_else(|| "stop".to_string()),
            usage: completion.usage.map(|u| TokenUsage {
                prompt_tokens: u.prompt_tokens,
                completion_tokens: u.completion_tokens,
                total_tokens: u.total_tokens,
            }),
        })
    }

    async fn complete_stream(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolDefinition],
        tx: mpsc::Sender<StreamChunk>,
    ) -> Result<LlmResponse> {
        let url = format!("{}/chat/completions", self.base_url);

        let body = serde_json::json!({
            "model": self.model,
            "messages": messages,
            "tools": if tools.is_empty() { serde_json::Value::Null } else { serde_json::to_value(tools)? },
            "temperature": 0.7,
            "stream": true,
        });

        let mut req_builder = self.client.post(&url)
            .header("Content-Type", "application/json");
        if let Some(ref key) = self.api_key {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", key));
        }

        let response = req_builder
            .json(&body)
            .send()
            .await
            .context("Failed to send streaming request to LLM API")?;

        let status = response.status();
        if !status.is_success() {
            let body_text = response.text().await?;
            if let Ok(api_error) = serde_json::from_str::<ApiError>(&body_text) {
                anyhow::bail!("LLM API streaming error ({}): {}", status, api_error.error.message);
            }
            anyhow::bail!("LLM API streaming error ({}): {}", status, body_text);
        }

        // Parse SSE stream
        let mut full_content = String::new();
        let mut tool_calls_acc: Vec<ToolCall> = Vec::new();
        let mut finish_reason = "stop".to_string();
        let mut usage: Option<TokenUsage> = None;

        use tokio_stream::StreamExt;
        let mut byte_stream = response.bytes_stream();
        let mut buffer = String::new();

        while let Some(chunk_result) = byte_stream.next().await {
            let bytes = chunk_result.context("Failed to read SSE chunk")?;
            buffer.push_str(&String::from_utf8_lossy(&bytes));

            // Process complete SSE lines
            while let Some(newline_pos) = buffer.find('\n') {
                let line = buffer[..newline_pos].trim_end_matches('\r').to_string();
                buffer = buffer[newline_pos + 1..].to_string();

                if line.is_empty() || line.starts_with(':') {
                    continue;
                }

                if !line.starts_with("data: ") {
                    continue;
                }
                let data = &line[6..];

                if data == "[DONE]" {
                    break;
                }

                // Parse SSE delta
                #[derive(Deserialize)]
                struct StreamDelta {
                    choices: Option<Vec<StreamChoice>>,
                    usage: Option<ApiUsage>,
                }
                #[derive(Deserialize)]
                struct StreamChoice {
                    delta: Option<StreamDeltaContent>,
                    finish_reason: Option<String>,
                }
                #[derive(Deserialize)]
                struct StreamDeltaContent {
                    content: Option<String>,
                    tool_calls: Option<Vec<StreamToolCallDelta>>,
                }
                #[derive(Deserialize)]
                struct StreamToolCallDelta {
                    index: Option<usize>,
                    id: Option<String>,
                    function: Option<StreamFunctionDelta>,
                }
                #[derive(Deserialize)]
                struct StreamFunctionDelta {
                    name: Option<String>,
                    arguments: Option<String>,
                }

                if let Ok(delta) = serde_json::from_str::<StreamDelta>(data) {
                    if let Some(u) = delta.usage {
                        usage = Some(TokenUsage {
                            prompt_tokens: u.prompt_tokens,
                            completion_tokens: u.completion_tokens,
                            total_tokens: u.total_tokens,
                        });
                    }
                    if let Some(choices) = delta.choices {
                        for choice in choices {
                            if let Some(fr) = choice.finish_reason {
                                finish_reason = fr;
                            }
                            if let Some(d) = choice.delta {
                                // Text delta
                                if let Some(ref text) = d.content {
                                    if !text.is_empty() {
                                        full_content.push_str(text);
                                        let _ = tx.send(StreamChunk::TextDelta(text.clone())).await;
                                    }
                                }
                                // Tool call deltas
                                if let Some(tc_deltas) = d.tool_calls {
                                    for tc in tc_deltas {
                                        let idx = tc.index.unwrap_or(0);
                                        let func = tc.function.as_ref();
                                        let name = func.and_then(|f| f.name.clone());
                                        let args = func.and_then(|f| f.arguments.clone());

                                        // Accumulate tool call
                                        while tool_calls_acc.len() <= idx {
                                            tool_calls_acc.push(ToolCall {
                                                id: String::new(),
                                                call_type: "function".to_string(),
                                                function: FunctionCall {
                                                    name: String::new(),
                                                    arguments: String::new(),
                                                },
                                            });
                                        }
                                        if let Some(ref id) = tc.id {
                                            tool_calls_acc[idx].id = id.clone();
                                        }
                                        if let Some(ref n) = name {
                                            tool_calls_acc[idx].function.name = n.clone();
                                        }
                                        if let Some(ref a) = args {
                                            tool_calls_acc[idx].function.arguments.push_str(a);
                                        }

                                        let _ = tx.send(StreamChunk::ToolCallDelta {
                                            index: idx,
                                            id: tc.id,
                                            name,
                                            arguments: args,
                                        }).await;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let response = LlmResponse {
            content: if full_content.is_empty() { None } else { Some(full_content) },
            tool_calls: tool_calls_acc,
            finish_reason,
            usage,
        };

        let _ = tx.send(StreamChunk::Done(response.clone())).await;
        Ok(response)
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn model_name(&self) -> &str {
        &self.model
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chat_message_serialization() {
        let msg = ChatMessage {
            role: "user".to_string(),
            content: "Hello".to_string(),
            tool_call_id: None,
            tool_calls: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("user"));
        assert!(json.contains("Hello"));
        // tool_call_id and tool_calls should be omitted when None
        assert!(!json.contains("tool_call_id"));
        assert!(!json.contains("tool_calls"));
    }

    #[test]
    fn test_tool_definition_serialization() {
        let tool = ToolDefinition {
            tool_type: "function".to_string(),
            function: FunctionDefinition {
                name: "math_eval".to_string(),
                description: "Evaluate a math expression".to_string(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "expression": {
                            "type": "string",
                            "description": "The math expression to evaluate"
                        }
                    },
                    "required": ["expression"]
                }),
            },
        };
        let json = serde_json::to_string(&tool).unwrap();
        assert!(json.contains("math_eval"));
        assert!(json.contains("function"));
    }

    #[test]
    fn test_ollama_client_creation() {
        let client = OpenAiCompatibleClient::ollama("phi3:mini");
        assert_eq!(client.model_name(), "phi3:mini");
        assert_eq!(client.base_url, "http://localhost:11434/v1");
        assert!(client.api_key.is_none());
    }

    #[test]
    fn test_openai_client_creation() {
        let client = OpenAiCompatibleClient::openai("gpt-4o", "sk-test123".to_string());
        assert_eq!(client.model_name(), "gpt-4o");
        assert_eq!(client.base_url, "https://api.openai.com/v1");
        assert!(client.api_key.is_some());
    }
}
