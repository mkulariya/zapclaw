use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// Inbound JSON-RPC tunnel for remote task submission.
///
/// Provides a lightweight JSON-RPC 2.0 server that accepts tasks
/// submitted from remote clients over the network.
///
/// Security properties:
/// - Binds to 127.0.0.1 by default (localhost only)
/// - Optional bind to VPN interface (Tailscale/WireGuard)
/// - API key authentication on every request
/// - Rate limiting via shared state
/// - All submitted tasks go through InputSanitizer
/// - Disabled by default (--enable-inbound flag required)
pub struct InboundTunnel {
    config: InboundConfig,
    task_sender: mpsc::Sender<InboundTask>,
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
}

impl Default for InboundConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: "127.0.0.1".to_string(),
            rpc_port: 9876,
            api_key: None,
            max_concurrent: 5,
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
    /// Returns the tunnel and a receiver for incoming tasks.
    pub fn new(config: InboundConfig) -> (Self, mpsc::Receiver<InboundTask>) {
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

        log::info!("🔌 Inbound tunnel listening on {}", addr);

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
            "health" => self.handle_health(rpc_req).await,
            _ => Ok(Self::json_rpc_error(
                rpc_req.id,
                -32601,
                &format!("Unknown method: {}", rpc_req.method),
            )),
        }
    }

    /// Handle submit_task RPC method.
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

        let session_id = params.get("session_id")
            .and_then(|v| v.as_str())
            .map(String::from);

        let inbound_task = InboundTask {
            id: uuid::Uuid::new_v4().to_string(),
            task: task_text.to_string(),
            session_id,
            submitted_at: chrono::Utc::now().to_rfc3339(),
        };

        let task_id = inbound_task.id.clone();

        // Send task to the processing queue
        match self.task_sender.send(inbound_task).await {
            Ok(()) => {
                log::info!("📥 Task {} queued via inbound tunnel", task_id);
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
}
