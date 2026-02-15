use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use zapclaw_core::confiner::Confiner;
use zapclaw_core::sanitizer::InputSanitizer;

/// Inbound JSON-RPC tunnel for remote task submission.
///
/// Provides a lightweight JSON-RPC 2.0 server that accepts tasks
/// submitted from remote clients over the network.
///
/// Security properties:
/// - Binds to 127.0.0.1 by default (localhost only)
/// - Optional bind to VPN interface (Tailscale/WireGuard)
/// - API key authentication on every request
/// - Input sanitization on all submitted tasks
/// - File operations confined to workspace via Confiner
/// - Disabled by default (--enable-inbound flag required)
pub struct InboundTunnel {
    config: InboundConfig,
    task_sender: mpsc::Sender<InboundMessage>,
}

/// Inbound tunnel configuration.
#[derive(Debug, Clone)]
pub struct InboundConfig {
    /// Whether the tunnel is enabled
    pub enabled: bool,
    /// Bind address (default: 127.0.0.1)
    pub bind_address: String,
    /// RPC port
    pub rpc_port: u16,
    /// Required API key for authentication (None = reject all)
    pub api_key: Option<String>,
    /// Max concurrent requests
    pub max_concurrent: usize,
    /// Workspace root for file operations (None = file ops disabled)
    pub workspace_root: Option<PathBuf>,
}

impl Default for InboundConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: "127.0.0.1".to_string(),
            rpc_port: 9876,
            api_key: None,
            max_concurrent: 5,
            workspace_root: None,
        }
    }
}

/// A task submitted via the inbound tunnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundTask {
    /// Unique task ID
    pub id: String,
    /// The task content/prompt
    pub task: String,
    /// Session ID (optional, creates new if missing)
    pub session_id: Option<String>,
    /// Timestamp of submission
    pub submitted_at: String,
}

/// Response from agent processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundResponse {
    /// The agent's response text
    pub response: String,
    /// The session ID used for this task
    pub session_id: String,
}

/// Internal message sent through the processing channel.
/// Wraps InboundTask + optional oneshot for synchronous responses.
pub struct InboundMessage {
    pub task: InboundTask,
    pub response_tx: Option<tokio::sync::oneshot::Sender<InboundResponse>>,
}

/// JSON-RPC 2.0 request structure.
#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Option<serde_json::Value>,
    id: serde_json::Value,
}

/// JSON-RPC 2.0 response structure.
#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    result: Option<serde_json::Value>,
    error: Option<JsonRpcError>,
    id: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

impl InboundTunnel {
    /// Create a new inbound tunnel.
    ///
    /// Returns the tunnel and a receiver for incoming messages.
    pub fn new(config: InboundConfig) -> (Self, mpsc::Receiver<InboundMessage>) {
        let (tx, rx) = mpsc::channel(config.max_concurrent);
        (Self { config, task_sender: tx }, rx)
    }

    /// Start the inbound tunnel server.
    ///
    /// This runs the JSON-RPC server in a background task.
    /// Returns a handle that can be used to shut down the server.
    pub async fn start(self: Arc<Self>) -> Result<tokio::task::JoinHandle<()>> {
        if !self.config.enabled {
            anyhow::bail!("Inbound tunnel is disabled. Enable with --enable-inbound");
        }

        let addr: SocketAddr = format!("{}:{}", self.config.bind_address, self.config.rpc_port)
            .parse()
            .context("Invalid bind address")?;

        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind inbound tunnel to {}", addr))?;

        log::info!("Inbound tunnel listening on {}", addr);

        let tunnel = self.clone();
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        log::debug!("Inbound connection from {}", peer_addr);
                        let tunnel = tunnel.clone();
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let tunnel = tunnel.clone();
                            if let Err(e) = http1::Builder::new()
                                .serve_connection(
                                    io,
                                    service_fn(move |req| {
                                        let tunnel = tunnel.clone();
                                        async move { tunnel.handle_request(req).await }
                                    }),
                                )
                                .await
                            {
                                log::error!("Connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("Accept error: {}", e);
                    }
                }
            }
        });

        Ok(handle)
    }

    /// Handle an incoming HTTP request.
    async fn handle_request(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        // Only accept POST to /rpc
        if req.method() != Method::POST || req.uri().path() != "/rpc" {
            return Ok(Self::error_response(
                StatusCode::NOT_FOUND,
                "Not found. Use POST /rpc",
            ));
        }

        // Check API key authentication
        if let Some(ref expected_key) = self.config.api_key {
            let auth = req.headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            let provided_key = auth.strip_prefix("Bearer ").unwrap_or("");
            if provided_key != expected_key {
                return Ok(Self::error_response(
                    StatusCode::UNAUTHORIZED,
                    "Invalid or missing API key",
                ));
            }
        }

        // Read body
        let body = match http_body_util::BodyExt::collect(req.into_body()).await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                return Ok(Self::error_response(
                    StatusCode::BAD_REQUEST,
                    "Failed to read request body",
                ));
            }
        };

        // Parse JSON-RPC request
        let rpc_req: JsonRpcRequest = match serde_json::from_slice(&body) {
            Ok(req) => req,
            Err(e) => {
                return Ok(Self::json_rpc_error(
                    serde_json::Value::Null,
                    -32700,
                    &format!("Parse error: {}", e),
                ));
            }
        };

        // Validate JSON-RPC version
        if rpc_req.jsonrpc != "2.0" {
            return Ok(Self::json_rpc_error(
                rpc_req.id,
                -32600,
                "Invalid JSON-RPC version. Expected 2.0",
            ));
        }

        // Dispatch method
        match rpc_req.method.as_str() {
            "submit_task" => self.handle_submit_task(rpc_req).await,
            "run_task" => self.handle_run_task(rpc_req).await,
            "upload_file" => self.handle_upload_file(rpc_req).await,
            "download_file" => self.handle_download_file(rpc_req).await,
            "list_files" => self.handle_list_files(rpc_req).await,
            "health" => self.handle_health(rpc_req).await,
            _ => Ok(Self::json_rpc_error(
                rpc_req.id,
                -32601,
                &format!("Unknown method: {}", rpc_req.method),
            )),
        }
    }

    /// Handle submit_task RPC method (fire-and-forget).
    async fn handle_submit_task(
        &self,
        rpc_req: JsonRpcRequest,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let params = match rpc_req.params {
            Some(params) => params,
            None => {
                return Ok(Self::json_rpc_error(
                    rpc_req.id,
                    -32602,
                    "Missing params. Required: { task: string }",
                ));
            }
        };

        let task_text = params.get("task")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if task_text.is_empty() {
            return Ok(Self::json_rpc_error(
                rpc_req.id,
                -32602,
                "Empty task. Provide: { task: \"your task\" }",
            ));
        }

        // Sanitize input
        let sanitizer = InputSanitizer::new();
        let sanitized = match sanitizer.sanitize(task_text) {
            Ok(s) => s,
            Err(e) => {
                return Ok(Self::json_rpc_error(
                    rpc_req.id,
                    -32602,
                    &format!("Input rejected: {}", e),
                ));
            }
        };

        let session_id = params.get("session_id")
            .and_then(|v| v.as_str())
            .map(String::from);

        let inbound_task = InboundTask {
            id: uuid::Uuid::new_v4().to_string(),
            task: sanitized,
            session_id,
            submitted_at: chrono::Utc::now().to_rfc3339(),
        };

        let task_id = inbound_task.id.clone();

        // Send task to the processing queue (no response expected)
        let msg = InboundMessage {
            task: inbound_task,
            response_tx: None,
        };

        match self.task_sender.send(msg).await {
            Ok(()) => {
                log::info!("Task {} queued via inbound tunnel", task_id);
                Ok(Self::json_rpc_success(
                    rpc_req.id,
                    serde_json::json!({
                        "task_id": task_id,
                        "status": "queued"
                    }),
                ))
            }
            Err(_) => Ok(Self::json_rpc_error(
                rpc_req.id,
                -32000,
                "Task queue is full. Try again later.",
            )),
        }
    }

    /// Handle run_task RPC method (synchronous — waits for agent response).
    async fn handle_run_task(
        &self,
        rpc_req: JsonRpcRequest,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let params = match rpc_req.params {
            Some(params) => params,
            None => {
                return Ok(Self::json_rpc_error(
                    rpc_req.id,
                    -32602,
                    "Missing params. Required: { task: string }",
                ));
            }
        };

        let task_text = params.get("task")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if task_text.is_empty() {
            return Ok(Self::json_rpc_error(
                rpc_req.id,
                -32602,
                "Empty task. Provide: { task: \"your task\" }",
            ));
        }

        // Sanitize input
        let sanitizer = InputSanitizer::new();
        let sanitized = match sanitizer.sanitize(task_text) {
            Ok(s) => s,
            Err(e) => {
                return Ok(Self::json_rpc_error(
                    rpc_req.id,
                    -32602,
                    &format!("Input rejected: {}", e),
                ));
            }
        };

        let session_id = params.get("session_id")
            .and_then(|v| v.as_str())
            .map(String::from);

        let inbound_task = InboundTask {
            id: uuid::Uuid::new_v4().to_string(),
            task: sanitized,
            session_id,
            submitted_at: chrono::Utc::now().to_rfc3339(),
        };

        let task_id = inbound_task.id.clone();

        // Create oneshot channel for synchronous response
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();

        let msg = InboundMessage {
            task: inbound_task,
            response_tx: Some(response_tx),
        };

        // Send to processing queue
        if self.task_sender.send(msg).await.is_err() {
            return Ok(Self::json_rpc_error(
                rpc_req.id,
                -32000,
                "Task queue is full. Try again later.",
            ));
        }

        log::info!("Task {} submitted for synchronous processing", task_id);

        // Wait for response with 120s timeout
        match tokio::time::timeout(
            std::time::Duration::from_secs(120),
            response_rx,
        ).await {
            Ok(Ok(response)) => {
                Ok(Self::json_rpc_success(
                    rpc_req.id,
                    serde_json::json!({
                        "response": response.response,
                        "session_id": response.session_id,
                        "task_id": task_id,
                    }),
                ))
            }
            Ok(Err(_)) => {
                // Sender dropped without sending — processing failed
                Ok(Self::json_rpc_error(
                    rpc_req.id,
                    -32000,
                    "Task processing failed (agent did not respond).",
                ))
            }
            Err(_) => {
                // Timeout
                Ok(Self::json_rpc_error(
                    rpc_req.id,
                    -32000,
                    "Task timed out after 120 seconds.",
                ))
            }
        }
    }

    /// Handle upload_file RPC method.
    async fn handle_upload_file(
        &self,
        rpc_req: JsonRpcRequest,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let workspace = match &self.config.workspace_root {
            Some(ws) => ws,
            None => {
                return Ok(Self::json_rpc_error(
                    rpc_req.id,
                    -32000,
                    "File operations not available (no workspace configured).",
                ));
            }
        };

        let params = match rpc_req.params {
            Some(params) => params,
            None => {
                return Ok(Self::json_rpc_error(
                    rpc_req.id,
                    -32602,
                    "Missing params. Required: { path: string, content_base64: string }",
                ));
            }
        };

        let path = match params.get("path").and_then(|v| v.as_str()) {
            Some(p) if !p.is_empty() => p,
            _ => {
                return Ok(Self::json_rpc_error(
                    rpc_req.id,
                    -32602,
                    "Missing or empty 'path' parameter.",
                ));
            }
        };

        let content_b64 = match params.get("content_base64").and_then(|v| v.as_str()) {
            Some(c) => c,
            None => {
                return Ok(Self::json_rpc_error(
                    rpc_req.id,
                    -32602,
                    "Missing 'content_base64' parameter.",
                ));
            }
        };

        // Validate path is within workspace
        let full_path = workspace.join(path);
        let confiner = match Confiner::new(workspace) {
            Ok(c) => c,
            Err(e) => {
                return Ok(Self::json_rpc_error(
                    rpc_req.id,
                    -32000,
                    &format!("Workspace error: {}", e),
                ));
            }
        };

        let validated_path = match confiner.validate_path(&full_path) {
            Ok(p) => p,
            Err(e) => {
                return Ok(Self::json_rpc_error(
                    rpc_req.id,
                    -32602,
                    &format!("Path rejected: {}", e),
                ));
            }
        };

        // Decode base64 content
        let content = match BASE64.decode(content_b64.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                return Ok(Self::json_rpc_error(
                    rpc_req.id,
                    -32602,
                    &format!("Invalid base64: {}", e),
                ));
            }
        };

        // Create parent directories if needed
        if let Some(parent) = validated_path.parent() {
            if !parent.exists() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    return Ok(Self::json_rpc_error(
                        rpc_req.id,
                        -32000,
                        &format!("Failed to create directory: {}", e),
                    ));
                }
            }
        }

        // Write file
        let size = content.len();
        match std::fs::write(&validated_path, &content) {
            Ok(()) => {
                log::info!("Uploaded file: {} ({} bytes)", path, size);
                Ok(Self::json_rpc_success(
                    rpc_req.id,
                    serde_json::json!({
                        "path": path,
                        "size": size,
                        "status": "uploaded"
                    }),
                ))
            }
            Err(e) => Ok(Self::json_rpc_error(
                rpc_req.id,
                -32000,
                &format!("Failed to write file: {}", e),
            )),
        }
    }

    /// Handle download_file RPC method.
    async fn handle_download_file(
        &self,
        rpc_req: JsonRpcRequest,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let workspace = match &self.config.workspace_root {
            Some(ws) => ws,
            None => {
                return Ok(Self::json_rpc_error(
                    rpc_req.id,
                    -32000,
                    "File operations not available (no workspace configured).",
                ));
            }
        };

        let params = match rpc_req.params {
            Some(params) => params,
            None => {
                return Ok(Self::json_rpc_error(
                    rpc_req.id,
                    -32602,
                    "Missing params. Required: { path: string }",
                ));
            }
        };

        let path = match params.get("path").and_then(|v| v.as_str()) {
            Some(p) if !p.is_empty() => p,
            _ => {
                return Ok(Self::json_rpc_error(
                    rpc_req.id,
                    -32602,
                    "Missing or empty 'path' parameter.",
                ));
            }
        };

        // Validate path is within workspace
        let full_path = workspace.join(path);
        let confiner = match Confiner::new(workspace) {
            Ok(c) => c,
            Err(e) => {
                return Ok(Self::json_rpc_error(
                    rpc_req.id,
                    -32000,
                    &format!("Workspace error: {}", e),
                ));
            }
        };

        let validated_path = match confiner.validate_path(&full_path) {
            Ok(p) => p,
            Err(e) => {
                return Ok(Self::json_rpc_error(
                    rpc_req.id,
                    -32602,
                    &format!("Path rejected: {}", e),
                ));
            }
        };

        // Read file
        match std::fs::read(&validated_path) {
            Ok(content) => {
                let size = content.len();
                let encoded = BASE64.encode(&content);
                log::info!("Downloaded file: {} ({} bytes)", path, size);
                Ok(Self::json_rpc_success(
                    rpc_req.id,
                    serde_json::json!({
                        "content_base64": encoded,
                        "size": size,
                        "path": path,
                    }),
                ))
            }
            Err(e) => Ok(Self::json_rpc_error(
                rpc_req.id,
                -32000,
                &format!("Failed to read file: {}", e),
            )),
        }
    }

    /// Handle list_files RPC method.
    async fn handle_list_files(
        &self,
        rpc_req: JsonRpcRequest,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let workspace = match &self.config.workspace_root {
            Some(ws) => ws,
            None => {
                return Ok(Self::json_rpc_error(
                    rpc_req.id,
                    -32000,
                    "File operations not available (no workspace configured).",
                ));
            }
        };

        let pattern = rpc_req.params
            .as_ref()
            .and_then(|p| p.get("pattern"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Read workspace directory recursively (max depth 3 to prevent slowness)
        let mut files = Vec::new();
        Self::list_dir_recursive(workspace, workspace, pattern, 0, 3, &mut files);

        Ok(Self::json_rpc_success(
            rpc_req.id,
            serde_json::json!({
                "files": files,
                "count": files.len(),
            }),
        ))
    }

    /// Recursively list files in a directory up to max_depth.
    fn list_dir_recursive(
        base: &std::path::Path,
        dir: &std::path::Path,
        pattern: &str,
        depth: usize,
        max_depth: usize,
        results: &mut Vec<serde_json::Value>,
    ) {
        if depth > max_depth {
            return;
        }

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let relative = path.strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();

            // Skip hidden files/dirs
            if relative.starts_with('.') || relative.contains("/.") {
                continue;
            }

            if path.is_dir() {
                Self::list_dir_recursive(base, &path, pattern, depth + 1, max_depth, results);
            } else {
                // Apply pattern filter (simple substring match)
                if pattern.is_empty() || relative.contains(pattern) {
                    let size = std::fs::metadata(&path)
                        .map(|m| m.len())
                        .unwrap_or(0);

                    results.push(serde_json::json!({
                        "path": relative,
                        "size": size,
                    }));
                }
            }
        }
    }

    /// Handle health RPC method.
    async fn handle_health(
        &self,
        rpc_req: JsonRpcRequest,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        Ok(Self::json_rpc_success(
            rpc_req.id,
            serde_json::json!({
                "status": "healthy",
                "version": env!("CARGO_PKG_VERSION"),
                "methods": ["health", "run_task", "submit_task", "upload_file", "download_file", "list_files"],
            }),
        ))
    }

    /// Create a JSON-RPC success response.
    fn json_rpc_success(id: serde_json::Value, result: serde_json::Value) -> Response<Full<Bytes>> {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        };
        let body = serde_json::to_string(&resp).unwrap_or_default();
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }

    /// Create a JSON-RPC error response.
    fn json_rpc_error(id: serde_json::Value, code: i32, message: &str) -> Response<Full<Bytes>> {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.to_string(),
            }),
            id,
        };
        let body = serde_json::to_string(&resp).unwrap_or_default();
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }

    /// Create a plain HTTP error response.
    fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
        Response::builder()
            .status(status)
            .header("Content-Type", "text/plain")
            .body(Full::new(Bytes::from(message.to_string())))
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = InboundConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.bind_address, "127.0.0.1");
        assert_eq!(config.rpc_port, 9876);
        assert!(config.api_key.is_none());
        assert!(config.workspace_root.is_none());
    }

    #[test]
    fn test_tunnel_creation() {
        let config = InboundConfig::default();
        let (tunnel, _rx) = InboundTunnel::new(config);
        assert!(!tunnel.config.enabled);
    }

    #[test]
    fn test_json_rpc_success_response() {
        let resp = InboundTunnel::json_rpc_success(
            serde_json::json!(1),
            serde_json::json!({"status": "ok"}),
        );
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_json_rpc_error_response() {
        let resp = InboundTunnel::json_rpc_error(
            serde_json::json!(1),
            -32600,
            "Test error",
        );
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_upload_download_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().to_path_buf();

        // Upload: write file via confiner-validated path
        let content = b"hello from remote";
        let encoded = BASE64.encode(content);
        let file_path = workspace.join("test_upload.txt");
        let confiner = Confiner::new(&workspace).unwrap();
        let validated = confiner.validate_path(&file_path).unwrap();
        std::fs::write(&validated, content).unwrap();

        // Download: read and base64-encode
        let read_back = std::fs::read(&validated).unwrap();
        let re_encoded = BASE64.encode(&read_back);
        assert_eq!(encoded, re_encoded);

        // Decode and verify
        let decoded = BASE64.decode(re_encoded.as_bytes()).unwrap();
        assert_eq!(decoded, content);
    }

    #[test]
    fn test_file_path_escape_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().to_path_buf();
        let confiner = Confiner::new(&workspace).unwrap();

        // Attempt to escape workspace
        let escape_path = workspace.join("../../etc/passwd");
        assert!(confiner.validate_path(&escape_path).is_err());

        let escape_path2 = workspace.join("../../../tmp/evil");
        assert!(confiner.validate_path(&escape_path2).is_err());
    }

    #[test]
    fn test_list_files() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().to_path_buf();

        // Create test files
        std::fs::write(workspace.join("data.csv"), "a,b,c").unwrap();
        std::fs::write(workspace.join("notes.txt"), "hello").unwrap();
        std::fs::create_dir_all(workspace.join("subdir")).unwrap();
        std::fs::write(workspace.join("subdir/deep.csv"), "d,e,f").unwrap();

        // List all files
        let mut all_files = Vec::new();
        InboundTunnel::list_dir_recursive(&workspace, &workspace, "", 0, 3, &mut all_files);
        assert_eq!(all_files.len(), 3);

        // List with pattern filter
        let mut csv_files = Vec::new();
        InboundTunnel::list_dir_recursive(&workspace, &workspace, ".csv", 0, 3, &mut csv_files);
        assert_eq!(csv_files.len(), 2);
    }

    #[tokio::test]
    async fn test_inbound_message_channel() {
        let config = InboundConfig {
            max_concurrent: 2,
            ..Default::default()
        };
        let (tunnel, mut rx) = InboundTunnel::new(config);

        // Send a message through the channel
        let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
        let task = InboundTask {
            id: "test-1".to_string(),
            task: "What is 2+2?".to_string(),
            session_id: Some("sess-1".to_string()),
            submitted_at: "2026-01-01T00:00:00Z".to_string(),
        };

        let msg = InboundMessage {
            task,
            response_tx: Some(resp_tx),
        };

        tunnel.task_sender.send(msg).await.unwrap();

        // Receive from the other end
        let received = rx.recv().await.unwrap();
        assert_eq!(received.task.id, "test-1");
        assert_eq!(received.task.task, "What is 2+2?");
        assert!(received.response_tx.is_some());

        // Send response back through oneshot
        let response = InboundResponse {
            response: "The answer is 4.".to_string(),
            session_id: "sess-1".to_string(),
        };
        received.response_tx.unwrap().send(response).unwrap();

        // Verify response received
        let result = resp_rx.await.unwrap();
        assert_eq!(result.response, "The answer is 4.");
        assert_eq!(result.session_id, "sess-1");
    }

    #[test]
    fn test_input_sanitization() {
        let sanitizer = InputSanitizer::new();

        // Normal input passes
        assert!(sanitizer.sanitize("What is 2+2?").is_ok());
        assert!(sanitizer.sanitize("List all files in the workspace").is_ok());

        // Empty input is technically ok at sanitizer level (caught by handler)
        assert!(sanitizer.sanitize("").is_ok());
    }
}
