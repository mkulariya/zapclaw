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
    /// Attached images as base64 data URIs (e.g. "data:image/png;base64,...").
    /// Not stored in JSONL session transcripts — transient per-message only.
    #[serde(skip)]
    pub images: Option<Vec<String>>,
    /// Raw Anthropic content blocks for this assistant message (thinking + tool_use blocks).
    /// Required to preserve interleaved thinking context when sending tool results back.
    /// Must be echoed verbatim in the next API request. Not stored in JSONL transcripts.
    #[serde(skip)]
    pub anthropic_blocks: Option<Vec<serde_json::Value>>,
}

/// Build a JSON value for a single message, expanding `images` into a
/// multimodal content array when present.
///
/// Without images: `{"role": "user", "content": "hello"}`
/// With images:    `{"role": "user", "content": [{"type":"text","text":"hello"}, {"type":"image_url",...}]}`
fn build_message_value(msg: &ChatMessage) -> serde_json::Value {
    let content: serde_json::Value = match &msg.images {
        Some(images) if !images.is_empty() => {
            let mut blocks = vec![serde_json::json!({"type": "text", "text": msg.content})];
            for img in images {
                blocks.push(serde_json::json!({
                    "type": "image_url",
                    "image_url": {"url": img}
                }));
            }
            serde_json::Value::Array(blocks)
        }
        _ => serde_json::Value::String(msg.content.clone()),
    };

    let mut obj = serde_json::json!({
        "role": msg.role,
        "content": content,
    });

    if let Some(ref id) = msg.tool_call_id {
        obj["tool_call_id"] = serde_json::json!(id);
    }
    if let Some(ref calls) = msg.tool_calls {
        obj["tool_calls"] = serde_json::to_value(calls).unwrap_or_default();
    }

    obj
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
    /// Raw Anthropic content blocks (thinking + tool_use), ordered by block index.
    /// Non-empty only when the Anthropic API returned thinking blocks.
    /// Must be preserved in conversation history and echoed back on the next request.
    #[serde(skip)]
    pub anthropic_blocks: Vec<serde_json::Value>,
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

// ---------------------------------------------------------------------------
// API style detection
// ---------------------------------------------------------------------------

/// Which wire protocol the endpoint speaks.
#[derive(Debug, Clone, PartialEq)]
enum ApiStyle {
    /// Standard OpenAI-compatible API (/chat/completions, Bearer token auth).
    OpenAi,
    /// Anthropic Messages API (/v1/messages, x-api-key auth, different request/response format).
    Anthropic,
}

fn detect_api_style(base_url: &str) -> ApiStyle {
    if base_url.to_lowercase().contains("anthropic") {
        ApiStyle::Anthropic
    } else {
        ApiStyle::OpenAi
    }
}

// ---------------------------------------------------------------------------
// Anthropic message/tool conversion helpers
// ---------------------------------------------------------------------------

/// Convert ZapClaw's flat ChatMessage list to Anthropic Messages API format.
/// Returns (system_prompt, messages_array).
///
/// Conversion rules:
/// - role=system  → extracted as separate `system` string
/// - role=user    → {"role":"user","content":"..."}
/// - role=assistant with tool_calls → {"role":"assistant","content":[tool_use blocks]}
/// - role=tool    → merged into {"role":"user","content":[tool_result blocks]}
fn to_anthropic_messages(messages: &[ChatMessage]) -> (Option<String>, Vec<serde_json::Value>) {
    let mut system: Option<String> = None;
    let mut result: Vec<serde_json::Value> = Vec::new();

    for msg in messages {
        match msg.role.as_str() {
            "system" => {
                system = Some(msg.content.clone());
            }
            "user" => {
                result.push(serde_json::json!({"role": "user", "content": msg.content}));
            }
            "assistant" => {
                // If raw Anthropic blocks were captured (thinking + tool_use), echo them
                // verbatim. This is required for interleaved thinking continuity.
                if let Some(ref blocks) = msg.anthropic_blocks {
                    result.push(serde_json::json!({"role": "assistant", "content": blocks}));
                } else if let Some(ref calls) = msg.tool_calls {
                    let mut blocks: Vec<serde_json::Value> = Vec::new();
                    if !msg.content.trim().is_empty() {
                        blocks.push(serde_json::json!({"type": "text", "text": msg.content}));
                    }
                    for call in calls {
                        let input: serde_json::Value =
                            serde_json::from_str(&call.function.arguments)
                                .unwrap_or(serde_json::json!({}));
                        blocks.push(serde_json::json!({
                            "type": "tool_use",
                            "id": call.id,
                            "name": call.function.name,
                            "input": input,
                        }));
                    }
                    result.push(serde_json::json!({"role": "assistant", "content": blocks}));
                } else {
                    result.push(serde_json::json!({"role": "assistant", "content": msg.content}));
                }
            }
            "tool" => {
                // Anthropic expects tool results as user messages with tool_result content blocks.
                // Consecutive tool results must be merged into a single user message.
                let block = serde_json::json!({
                    "type": "tool_result",
                    "tool_use_id": msg.tool_call_id.as_deref().unwrap_or(""),
                    "content": msg.content,
                });
                let can_merge = result.last().map(|last| {
                    last["role"] == "user" && last["content"].is_array()
                }).unwrap_or(false);
                if can_merge {
                    result.last_mut().unwrap()["content"]
                        .as_array_mut()
                        .unwrap()
                        .push(block);
                } else {
                    result.push(serde_json::json!({"role": "user", "content": [block]}));
                }
            }
            _ => {}
        }
    }

    (system, result)
}

/// Convert ZapClaw's OpenAI-style ToolDefinition list to Anthropic format.
/// OpenAI: {"type":"function","function":{"name":...,"description":...,"parameters":{...}}}
/// Anthropic: {"name":...,"description":...,"input_schema":{...}}
fn to_anthropic_tools(tools: &[ToolDefinition]) -> Vec<serde_json::Value> {
    tools
        .iter()
        .map(|t| {
            serde_json::json!({
                "name": t.function.name,
                "description": t.function.description,
                "input_schema": t.function.parameters,
            })
        })
        .collect()
}

/// Parse a complete Anthropic non-streaming response body into LlmResponse.
fn parse_anthropic_response(body: &str) -> Result<LlmResponse> {
    let val: serde_json::Value = serde_json::from_str(body).with_context(|| {
        format!(
            "Failed to parse Anthropic response: {}",
            &body[..body.len().min(300)]
        )
    })?;

    let stop_reason = val["stop_reason"].as_str().unwrap_or("end_turn").to_string();
    let usage = {
        let input = val["usage"]["input_tokens"].as_u64().unwrap_or(0) as u32;
        let output = val["usage"]["output_tokens"].as_u64().unwrap_or(0) as u32;
        if input > 0 || output > 0 {
            Some(TokenUsage { prompt_tokens: input, completion_tokens: output, total_tokens: input + output })
        } else {
            None
        }
    };

    let mut text_content = String::new();
    let mut tool_calls: Vec<ToolCall> = Vec::new();
    let mut anthropic_blocks: Vec<serde_json::Value> = Vec::new();
    let mut has_thinking = false;

    if let Some(blocks) = val["content"].as_array() {
        for block in blocks {
            let kind = block["type"].as_str().unwrap_or("");
            match kind {
                "thinking" => {
                    has_thinking = true;
                    // Preserve complete block (thinking text + signature) for history replay
                    anthropic_blocks.push(block.clone());
                }
                "redacted_thinking" => {
                    has_thinking = true;
                    anthropic_blocks.push(block.clone());
                }
                "text" => {
                    if let Some(t) = block["text"].as_str() {
                        text_content.push_str(t);
                    }
                    anthropic_blocks.push(block.clone());
                }
                "tool_use" => {
                    let id = block["id"].as_str().unwrap_or("").to_string();
                    let name = block["name"].as_str().unwrap_or("").to_string();
                    let arguments = serde_json::to_string(&block["input"])
                        .unwrap_or_else(|_| "{}".to_string());
                    tool_calls.push(ToolCall {
                        id,
                        call_type: "function".to_string(),
                        function: FunctionCall { name, arguments },
                    });
                    anthropic_blocks.push(block.clone());
                }
                _ => {}
            }
        }
    }

    Ok(LlmResponse {
        content: if text_content.is_empty() { None } else { Some(text_content) },
        tool_calls,
        finish_reason: stop_reason,
        usage,
        // Only populate anthropic_blocks when thinking was present — tool_use-only
        // responses don't need special handling (we can reconstruct them from tool_calls).
        anthropic_blocks: if has_thinking { anthropic_blocks } else { Vec::new() },
    })
}

// ---------------------------------------------------------------------------
// OpenAI API request/response types (private)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ChatCompletionRequest {
    model: String,
    messages: Vec<serde_json::Value>,
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

// ---------------------------------------------------------------------------
// Client implementation
// ---------------------------------------------------------------------------

/// OpenAI-compatible (and Anthropic) API client.
///
/// Auto-detects API style from base_url:
/// - URL contains "anthropic" → uses Anthropic Messages API format
/// - Otherwise → uses OpenAI Chat Completions format
///
/// Works with:
/// - Ollama (local): http://localhost:11434/v1
/// - OpenAI: https://api.openai.com/v1
/// - Anthropic proxies: https://api.z.ai/api/anthropic
/// - Any OpenAI-compatible endpoint
pub struct OpenAiCompatibleClient {
    client: reqwest::Client,
    base_url: String,
    model: String,
    api_key: Option<String>,
    api_style: ApiStyle,
    /// Anthropic adaptive thinking effort level ("low" | "medium" | "high").
    /// Shared via Arc<Mutex> so the REPL can update it mid-session without
    /// rebuilding the client. None = thinking disabled.
    thinking_effort: std::sync::Arc<std::sync::Mutex<Option<String>>>,
}

impl OpenAiCompatibleClient {
    /// Create a new client. API style is auto-detected from `base_url`.
    pub fn new(base_url: &str, model: &str, api_key: Option<String>) -> Self {
        let trimmed = base_url.trim_end_matches('/').to_string();
        let api_style = detect_api_style(&trimmed);
        if api_style == ApiStyle::Anthropic {
            log::info!("Detected Anthropic API endpoint: {}", trimmed);
        }
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .expect("Failed to build HTTP client");
        Self {
            client,
            base_url: trimmed,
            model: model.to_string(),
            api_key,
            api_style,
            thinking_effort: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Set the initial thinking effort level ("low" | "medium" | "high" | None to disable).
    /// Only takes effect for Anthropic API endpoints; ignored for OpenAI-style.
    pub fn with_thinking_effort(self, effort: Option<String>) -> Self {
        *self.thinking_effort.lock().unwrap() = effort;
        self
    }

    /// Return a shared handle to the thinking effort so the REPL can update it mid-session.
    pub fn thinking_effort_handle(&self) -> std::sync::Arc<std::sync::Mutex<Option<String>>> {
        std::sync::Arc::clone(&self.thinking_effort)
    }

    /// Create a client configured for local Ollama.
    pub fn ollama(model: &str) -> Self {
        Self::new("http://localhost:11434/v1", model, None)
    }

    /// Create a client configured for OpenAI.
    pub fn openai(model: &str, api_key: String) -> Self {
        Self::new("https://api.openai.com/v1", model, Some(api_key))
    }

    // --- Anthropic request helpers ---

    fn anthropic_messages_url(&self) -> String {
        format!("{}/v1/messages", self.base_url)
    }

    fn build_anthropic_body(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolDefinition],
        stream: bool,
    ) -> serde_json::Value {
        let (system, anth_messages) = to_anthropic_messages(messages);
        let anth_tools = to_anthropic_tools(tools);

        // Anthropic requires max_tokens (mandatory field, unlike OpenAI).
        // 32768 is safe for all current Claude 4 models without extended output beta.
        let mut body = serde_json::json!({
            "model": self.model,
            "max_tokens": 32768_u32,
            "messages": anth_messages,
            "stream": stream,
        });

        if let Some(sys) = system {
            body["system"] = serde_json::Value::String(sys);
        }
        if !anth_tools.is_empty() {
            body["tools"] = serde_json::Value::Array(anth_tools);
        }
        if let Some(ref effort) = *self.thinking_effort.lock().unwrap() {
            body["thinking"] = serde_json::json!({"type": "adaptive"});
            body["output_config"] = serde_json::json!({"effort": effort});
        }

        body
    }

    /// Build an authenticated POST request builder for Anthropic API.
    /// Uses x-api-key header + anthropic-version, not Bearer token.
    fn anthropic_req(&self, url: &str) -> reqwest::RequestBuilder {
        let mut req = self
            .client
            .post(url)
            .header("content-type", "application/json")
            .header("anthropic-version", "2023-06-01");
        if let Some(ref key) = self.api_key {
            req = req.header("x-api-key", key);
        }
        // Enable interleaved thinking beta when thinking is requested.
        // Kept even with the adaptive effort API — it's a no-op if not needed
        // and ensures thinking between tool calls works on models that require it.
        if self.thinking_effort.lock().unwrap().is_some() {
            req = req.header("anthropic-beta", "interleaved-thinking-2025-05-14");
        }
        req
    }
}

#[async_trait]
impl LlmClient for OpenAiCompatibleClient {
    async fn complete(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolDefinition],
    ) -> Result<LlmResponse> {
        match self.api_style {
            // ------------------------------------------------------------------
            // Anthropic Messages API
            // ------------------------------------------------------------------
            ApiStyle::Anthropic => {
                let url = self.anthropic_messages_url();
                let body = self.build_anthropic_body(messages, tools, false);

                let response = self
                    .anthropic_req(&url)
                    .json(&body)
                    .send()
                    .await
                    .context("Failed to send request to Anthropic API")?;

                let status = response.status();
                let text = response
                    .text()
                    .await
                    .context("Failed to read Anthropic API response body")?;

                if !status.is_success() {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                        if let Some(msg) = val["error"]["message"].as_str() {
                            anyhow::bail!("Anthropic API error ({}): {}", status, msg);
                        }
                    }
                    anyhow::bail!("Anthropic API error ({}): {}", status, text);
                }

                parse_anthropic_response(&text)
            }

            // ------------------------------------------------------------------
            // OpenAI-compatible API
            // ------------------------------------------------------------------
            ApiStyle::OpenAi => {
                let url = format!("{}/chat/completions", self.base_url);

                let request = ChatCompletionRequest {
                    model: self.model.clone(),
                    messages: messages.iter().map(build_message_value).collect(),
                    tools: tools.to_vec(),
                    temperature: 0.7,
                };

                let mut req_builder = self
                    .client
                    .post(&url)
                    .header("Content-Type", "application/json");

                if let Some(ref key) = self.api_key {
                    req_builder =
                        req_builder.header("Authorization", format!("Bearer {}", key));
                }

                let response = req_builder
                    .json(&request)
                    .send()
                    .await
                    .context("Failed to send request to LLM API")?;

                let status = response.status();
                let body = response
                    .text()
                    .await
                    .context("Failed to read LLM API response body")?;

                if !status.is_success() {
                    if let Ok(api_error) = serde_json::from_str::<ApiError>(&body) {
                        anyhow::bail!(
                            "LLM API error ({}): {}",
                            status,
                            api_error.error.message
                        );
                    }
                    anyhow::bail!("LLM API error ({}): {}", status, body);
                }

                let completion: ChatCompletionResponse = serde_json::from_str(&body)
                    .with_context(|| {
                        format!(
                            "Failed to parse LLM API response: {}",
                            &body[..body.len().min(200)]
                        )
                    })?;

                let choice = completion
                    .choices
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("LLM API returned no choices"))?;

                Ok(LlmResponse {
                    content: choice.message.content,
                    tool_calls: choice.message.tool_calls.unwrap_or_default(),
                    finish_reason: choice
                        .finish_reason
                        .unwrap_or_else(|| "stop".to_string()),
                    usage: completion.usage.map(|u| TokenUsage {
                        prompt_tokens: u.prompt_tokens,
                        completion_tokens: u.completion_tokens,
                        total_tokens: u.total_tokens,
                    }),
                    anthropic_blocks: Vec::new(),
                })
            }
        }
    }

    async fn complete_stream(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolDefinition],
        tx: mpsc::Sender<StreamChunk>,
    ) -> Result<LlmResponse> {
        match self.api_style {
            // ------------------------------------------------------------------
            // Anthropic streaming SSE
            // Event format: "event: TYPE\ndata: JSON\n\n"
            // Key events: message_start, content_block_start, content_block_delta,
            //             content_block_stop, message_delta, message_stop, ping, error
            // ------------------------------------------------------------------
            ApiStyle::Anthropic => {
                let url = self.anthropic_messages_url();
                let body = self.build_anthropic_body(messages, tools, true);

                let response = self
                    .anthropic_req(&url)
                    .json(&body)
                    .send()
                    .await
                    .context("Failed to send streaming request to Anthropic API")?;

                let status = response.status();
                if !status.is_success() {
                    let body_text = response.text().await?;
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body_text) {
                        if let Some(msg) = val["error"]["message"].as_str() {
                            anyhow::bail!(
                                "Anthropic API streaming error ({}): {}",
                                status,
                                msg
                            );
                        }
                    }
                    anyhow::bail!(
                        "Anthropic API streaming error ({}): {}",
                        status,
                        body_text
                    );
                }

                let mut full_content = String::new();
                let mut tool_calls_acc: Vec<ToolCall> = Vec::new();
                let mut finish_reason = "end_turn".to_string();
                let mut usage: Option<TokenUsage> = None;

                // Per-block tracking for tool use accumulation: index → (id, name, partial_args)
                let mut tool_blocks: std::collections::HashMap<
                    usize,
                    (String, String, String),
                > = Default::default();

                // Per-block tracking for thinking accumulation: index → (content, signature)
                let mut thinking_blocks: std::collections::HashMap<
                    usize,
                    (String, String),
                > = Default::default();

                // Per-block tracking for text accumulation: index → accumulated_text
                // Required so text blocks can be finalized into content_blocks_ordered
                // when thinking is active (the full content array must be echoed verbatim).
                let mut text_blocks: std::collections::HashMap<usize, String> =
                    Default::default();

                // Ordered content blocks for history replay (thinking + tool_use + text)
                // BTreeMap keeps blocks in index order.
                let mut content_blocks_ordered: std::collections::BTreeMap<
                    usize,
                    serde_json::Value,
                > = Default::default();
                let mut has_thinking = false;

                use tokio_stream::StreamExt;
                let mut byte_stream = response.bytes_stream();
                let mut buffer = String::new();
                let mut current_event = String::new();

                while let Some(chunk_result) = byte_stream.next().await {
                    let bytes =
                        chunk_result.context("Failed to read Anthropic SSE chunk")?;
                    buffer.push_str(&String::from_utf8_lossy(&bytes));

                    while let Some(newline_pos) = buffer.find('\n') {
                        let line =
                            buffer[..newline_pos].trim_end_matches('\r').to_string();
                        buffer = buffer[newline_pos + 1..].to_string();

                        if line.is_empty() {
                            // Blank line = end of SSE event block; reset event name
                            current_event.clear();
                            continue;
                        }

                        if line.starts_with(':') {
                            continue; // SSE comment
                        }

                        if let Some(event_type) = line.strip_prefix("event: ") {
                            current_event = event_type.trim().to_string();
                            continue;
                        }

                        if let Some(data) = line.strip_prefix("data: ") {
                            log::debug!(
                                "Anthropic SSE [{}]: {}",
                                current_event,
                                &data[..data.len().min(300)]
                            );

                            let val: serde_json::Value =
                                match serde_json::from_str(data) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        log::warn!(
                                            "Failed to parse Anthropic SSE data ({}): {}",
                                            e,
                                            &data[..data.len().min(200)]
                                        );
                                        continue;
                                    }
                                };

                            match current_event.as_str() {
                                "message_start" => {
                                    let input_tokens = val["message"]["usage"]
                                        ["input_tokens"]
                                        .as_u64()
                                        .unwrap_or(0)
                                        as u32;
                                    usage = Some(TokenUsage {
                                        prompt_tokens: input_tokens,
                                        completion_tokens: 0,
                                        total_tokens: input_tokens,
                                    });
                                }
                                "content_block_start" => {
                                    let idx =
                                        val["index"].as_u64().unwrap_or(0) as usize;
                                    let block_type = val["content_block"]["type"]
                                        .as_str()
                                        .unwrap_or("");
                                    match block_type {
                                        "tool_use" => {
                                            let id = val["content_block"]["id"]
                                                .as_str()
                                                .unwrap_or("")
                                                .to_string();
                                            let name = val["content_block"]["name"]
                                                .as_str()
                                                .unwrap_or("")
                                                .to_string();
                                            tool_blocks
                                                .insert(idx, (id, name, String::new()));
                                        }
                                        "thinking" => {
                                            has_thinking = true;
                                            thinking_blocks.insert(idx, (String::new(), String::new()));
                                        }
                                        "redacted_thinking" => {
                                            // redacted_thinking has no deltas — the encrypted
                                            // data blob is entirely in the start event itself.
                                            // Capture it directly into content_blocks_ordered.
                                            has_thinking = true;
                                            let data = val["content_block"]["data"]
                                                .as_str()
                                                .unwrap_or("")
                                                .to_string();
                                            content_blocks_ordered.insert(idx, serde_json::json!({
                                                "type": "redacted_thinking",
                                                "data": data,
                                            }));
                                        }
                                        "text" => {
                                            // Track text blocks so they can be included in the
                                            // echoed content array when thinking is active.
                                            text_blocks.insert(idx, String::new());
                                        }
                                        _ => {}
                                    }
                                }
                                "content_block_delta" => {
                                    let idx =
                                        val["index"].as_u64().unwrap_or(0) as usize;
                                    let delta_type =
                                        val["delta"]["type"].as_str().unwrap_or("");
                                    match delta_type {
                                        "text_delta" => {
                                            if let Some(text) =
                                                val["delta"]["text"].as_str()
                                            {
                                                if !text.is_empty() {
                                                    full_content.push_str(text);
                                                    // Also accumulate into text_blocks so we
                                                    // can include this block in the echoed
                                                    // content array when thinking is active.
                                                    if let Some(entry) = text_blocks.get_mut(&idx) {
                                                        entry.push_str(text);
                                                    }
                                                    let _ = tx
                                                        .send(StreamChunk::TextDelta(
                                                            text.to_string(),
                                                        ))
                                                        .await;
                                                }
                                            }
                                        }
                                        "thinking_delta" => {
                                            if let Some(thinking) =
                                                val["delta"]["thinking"].as_str()
                                            {
                                                if !thinking.is_empty() {
                                                    // Accumulate for history preservation
                                                    if let Some(entry) = thinking_blocks.get_mut(&idx) {
                                                        entry.0.push_str(thinking);
                                                    }
                                                    let _ = tx
                                                        .send(
                                                            StreamChunk::ReasoningDelta(
                                                                thinking.to_string(),
                                                            ),
                                                        )
                                                        .await;
                                                }
                                            }
                                        }
                                        "signature_delta" => {
                                            // Signature authenticates the thinking block;
                                            // must be included verbatim when echoing back.
                                            if let Some(sig) = val["delta"]["signature"].as_str() {
                                                if let Some(entry) = thinking_blocks.get_mut(&idx) {
                                                    entry.1 = sig.to_string();
                                                }
                                            }
                                        }
                                        "input_json_delta" => {
                                            if let Some(partial) =
                                                val["delta"]["partial_json"].as_str()
                                            {
                                                if let Some(entry) =
                                                    tool_blocks.get_mut(&idx)
                                                {
                                                    entry.2.push_str(partial);
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                "content_block_stop" => {
                                    let idx =
                                        val["index"].as_u64().unwrap_or(0) as usize;
                                    if let Some((id, name, args)) =
                                        tool_blocks.remove(&idx)
                                    {
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
                                        // Parse args JSON for the Anthropic block
                                        let input: serde_json::Value =
                                            serde_json::from_str(&args)
                                                .unwrap_or(serde_json::json!({}));
                                        content_blocks_ordered.insert(idx, serde_json::json!({
                                            "type": "tool_use",
                                            "id": id,
                                            "name": name,
                                            "input": input,
                                        }));
                                        tool_calls_acc[idx] = ToolCall {
                                            id: id.clone(),
                                            call_type: "function".to_string(),
                                            function: FunctionCall {
                                                name: name.clone(),
                                                arguments: args.clone(),
                                            },
                                        };
                                        let _ = tx
                                            .send(StreamChunk::ToolCallDelta {
                                                index: idx,
                                                id: Some(id),
                                                name: Some(name),
                                                arguments: Some(args),
                                            })
                                            .await;
                                    } else if let Some((content, signature)) =
                                        thinking_blocks.remove(&idx)
                                    {
                                        // Store complete thinking block for history replay
                                        content_blocks_ordered.insert(idx, serde_json::json!({
                                            "type": "thinking",
                                            "thinking": content,
                                            "signature": signature,
                                        }));
                                    } else if let Some(text) = text_blocks.remove(&idx) {
                                        // Store completed text block so the full content array
                                        // [thinking, text, tool_use] can be echoed verbatim.
                                        content_blocks_ordered.insert(idx, serde_json::json!({
                                            "type": "text",
                                            "text": text,
                                        }));
                                    }
                                }
                                "message_delta" => {
                                    if let Some(stop) =
                                        val["delta"]["stop_reason"].as_str()
                                    {
                                        finish_reason = stop.to_string();
                                    }
                                    if let Some(out) =
                                        val["usage"]["output_tokens"].as_u64()
                                    {
                                        if let Some(ref mut u) = usage {
                                            u.completion_tokens = out as u32;
                                            u.total_tokens =
                                                u.prompt_tokens + u.completion_tokens;
                                        }
                                    }
                                }
                                "message_stop" => {
                                    break;
                                }
                                "error" => {
                                    let msg = val["error"]["message"]
                                        .as_str()
                                        .unwrap_or("unknown Anthropic stream error");
                                    anyhow::bail!(
                                        "Anthropic API stream error: {}",
                                        msg
                                    );
                                }
                                _ => {} // ping and unknown events — ignore
                            }
                        }
                    }
                }

                let anthropic_blocks: Vec<serde_json::Value> = if has_thinking {
                    content_blocks_ordered.into_values().collect()
                } else {
                    Vec::new()
                };

                let response = LlmResponse {
                    content: if full_content.is_empty() {
                        None
                    } else {
                        Some(full_content)
                    },
                    tool_calls: tool_calls_acc,
                    finish_reason,
                    usage,
                    anthropic_blocks,
                };
                let _ = tx.send(StreamChunk::Done(response.clone())).await;
                Ok(response)
            }

            // ------------------------------------------------------------------
            // OpenAI-compatible streaming SSE
            // Format: "data: JSON\n\n" with choices[].delta.content
            // ------------------------------------------------------------------
            ApiStyle::OpenAi => {
                let url = format!("{}/chat/completions", self.base_url);

                let body = serde_json::json!({
                    "model": self.model,
                    "messages": messages.iter().map(build_message_value).collect::<Vec<_>>(),
                    "tools": if tools.is_empty() { serde_json::Value::Null } else { serde_json::to_value(tools)? },
                    "temperature": 0.7,
                    "stream": true,
                });

                let mut req_builder = self
                    .client
                    .post(&url)
                    .header("Content-Type", "application/json");
                if let Some(ref key) = self.api_key {
                    req_builder =
                        req_builder.header("Authorization", format!("Bearer {}", key));
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
                        anyhow::bail!(
                            "LLM API streaming error ({}): {}",
                            status,
                            api_error.error.message
                        );
                    }
                    anyhow::bail!("LLM API streaming error ({}): {}", status, body_text);
                }

                let mut full_content = String::new();
                let mut tool_calls_acc: Vec<ToolCall> = Vec::new();
                let mut finish_reason = "stop".to_string();
                let mut usage: Option<TokenUsage> = None;

                use tokio_stream::StreamExt;
                let mut byte_stream = response.bytes_stream();
                let mut buffer = String::new();

                while let Some(chunk_result) = byte_stream.next().await {
                    let bytes =
                        chunk_result.context("Failed to read SSE chunk")?;
                    buffer.push_str(&String::from_utf8_lossy(&bytes));

                    while let Some(newline_pos) = buffer.find('\n') {
                        let line =
                            buffer[..newline_pos].trim_end_matches('\r').to_string();
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

                        log::debug!("SSE raw: {}", &data[..data.len().min(500)]);

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

                        match serde_json::from_str::<StreamDelta>(data) {
                            Err(parse_err) => {
                                log::warn!(
                                    "Failed to parse SSE chunk ({}): {}",
                                    parse_err,
                                    &data[..data.len().min(200)]
                                );
                            }
                            Ok(delta) => {
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
                                            if let Some(ref text) = d.content {
                                                if !text.is_empty() {
                                                    full_content.push_str(text);
                                                    let _ = tx
                                                        .send(StreamChunk::TextDelta(
                                                            text.clone(),
                                                        ))
                                                        .await;
                                                }
                                            }
                                            if let Some(tc_deltas) = d.tool_calls {
                                                for tc in tc_deltas {
                                                    let idx = tc.index.unwrap_or(0);
                                                    let func = tc.function.as_ref();
                                                    let name = func.and_then(|f| f.name.clone());
                                                    let args = func.and_then(|f| f.arguments.clone());

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

                                                    let _ = tx
                                                        .send(StreamChunk::ToolCallDelta {
                                                            index: idx,
                                                            id: tc.id,
                                                            name,
                                                            arguments: args,
                                                        })
                                                        .await;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                let response = LlmResponse {
                    content: if full_content.is_empty() {
                        None
                    } else {
                        Some(full_content)
                    },
                    tool_calls: tool_calls_acc,
                    finish_reason,
                    usage,
                    anthropic_blocks: vec![],
                };
                let _ = tx.send(StreamChunk::Done(response.clone())).await;
                Ok(response)
            }
        }
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
            images: None,
            anthropic_blocks: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("user"));
        assert!(json.contains("Hello"));
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
        assert_eq!(client.api_style, ApiStyle::OpenAi);
    }

    #[test]
    fn test_openai_client_creation() {
        let client = OpenAiCompatibleClient::openai("gpt-4o", "sk-test123".to_string());
        assert_eq!(client.model_name(), "gpt-4o");
        assert_eq!(client.base_url, "https://api.openai.com/v1");
        assert!(client.api_key.is_some());
        assert_eq!(client.api_style, ApiStyle::OpenAi);
    }

    #[test]
    fn test_anthropic_client_detection() {
        let client = OpenAiCompatibleClient::new(
            "https://api.z.ai/api/anthropic",
            "claude-sonnet-4-6",
            Some("key".to_string()),
        );
        assert_eq!(client.api_style, ApiStyle::Anthropic);
        assert_eq!(
            client.anthropic_messages_url(),
            "https://api.z.ai/api/anthropic/v1/messages"
        );
    }

    #[test]
    fn test_to_anthropic_tools() {
        let tools = vec![ToolDefinition {
            tool_type: "function".to_string(),
            function: FunctionDefinition {
                name: "get_weather".to_string(),
                description: "Get weather".to_string(),
                parameters: serde_json::json!({"type": "object", "properties": {}}),
            },
        }];
        let anth = to_anthropic_tools(&tools);
        assert_eq!(anth[0]["name"], "get_weather");
        assert!(anth[0].get("input_schema").is_some());
        assert!(anth[0].get("parameters").is_none());
    }

    #[test]
    fn test_to_anthropic_messages_tool_result_merging() {
        let messages = vec![
            ChatMessage {
                role: "assistant".to_string(),
                content: "".to_string(),
                tool_call_id: None,
                tool_calls: Some(vec![
                    ToolCall {
                        id: "id1".to_string(),
                        call_type: "function".to_string(),
                        function: FunctionCall { name: "tool_a".to_string(), arguments: "{}".to_string() },
                    },
                    ToolCall {
                        id: "id2".to_string(),
                        call_type: "function".to_string(),
                        function: FunctionCall { name: "tool_b".to_string(), arguments: "{}".to_string() },
                    },
                ]),
                images: None,
                anthropic_blocks: None,
            },
            ChatMessage {
                role: "tool".to_string(),
                content: "result A".to_string(),
                tool_call_id: Some("id1".to_string()),
                tool_calls: None,
                images: None,
                anthropic_blocks: None,
            },
            ChatMessage {
                role: "tool".to_string(),
                content: "result B".to_string(),
                tool_call_id: Some("id2".to_string()),
                tool_calls: None,
                images: None,
                anthropic_blocks: None,
            },
        ];
        let (_, anth_msgs) = to_anthropic_messages(&messages);
        // Two tool results should be merged into a single user message
        assert_eq!(anth_msgs.len(), 2); // assistant + one merged user
        let last = &anth_msgs[1];
        assert_eq!(last["role"], "user");
        assert_eq!(last["content"].as_array().unwrap().len(), 2);
    }
}
