//! IPC module for watcher daemon communication.
//!
//! Provides Unix domain socket communication between CLI commands and the
//! watcher daemon. Used primarily for delivering user-var events from
//! shell hooks to the running watcher.
//!
//! # Protocol
//!
//! The protocol uses JSON lines (newline-delimited JSON):
//! - Client sends: `{"type":"user_var","pane_id":1,"name":"WA_EVENT","value":"base64..."}\n`
//! - Server responds: `{"ok":true}\n` or `{"ok":false,"error":"..."}\n`

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use crate::events::{Event, EventBus, UserVarError, UserVarPayload};

/// Default IPC socket filename relative to workspace .wa directory.
pub const IPC_SOCKET_NAME: &str = "ipc.sock";

/// Maximum message size in bytes (64KB).
pub const MAX_MESSAGE_SIZE: usize = 65536;

/// Request message from client to server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcRequest {
    /// User-var event from shell hook
    UserVar {
        /// Pane ID that emitted the user-var
        pane_id: u64,
        /// Variable name (e.g., "WA_EVENT")
        name: String,
        /// Raw value (typically base64-encoded JSON)
        value: String,
    },
    /// Ping to check if watcher is alive
    Ping,
    /// Request current watcher status
    Status,
}

/// Response message from server to client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    /// Whether the request succeeded
    pub ok: bool,
    /// Error message if failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Additional data (for status requests)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl IpcResponse {
    /// Create a success response.
    #[must_use]
    pub fn ok() -> Self {
        Self {
            ok: true,
            error: None,
            data: None,
        }
    }

    /// Create a success response with data.
    #[must_use]
    pub fn ok_with_data(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            error: None,
            data: Some(data),
        }
    }

    /// Create an error response.
    #[must_use]
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(message.into()),
            data: None,
        }
    }
}

/// IPC server that runs in the watcher daemon.
pub struct IpcServer {
    socket_path: PathBuf,
    listener: UnixListener,
}

impl IpcServer {
    /// Create and bind a new IPC server.
    ///
    /// # Arguments
    /// * `socket_path` - Path to the Unix socket file
    ///
    /// # Errors
    /// Returns error if socket binding fails.
    pub async fn bind(socket_path: impl AsRef<Path>) -> std::io::Result<Self> {
        let socket_path = socket_path.as_ref().to_path_buf();

        // Remove stale socket file if it exists
        if socket_path.exists() {
            std::fs::remove_file(&socket_path)?;
        }

        // Create parent directory if needed
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(&socket_path)?;
        tracing::info!(path = %socket_path.display(), "IPC server listening");

        Ok(Self {
            socket_path,
            listener,
        })
    }

    /// Get the socket path.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Run the IPC server, forwarding events to the event bus.
    ///
    /// This spawns a task for each connection. Returns when the shutdown
    /// signal is received.
    ///
    /// # Arguments
    /// * `event_bus` - Event bus to publish received events
    /// * `shutdown_rx` - Channel to receive shutdown signal
    pub async fn run(
        self,
        event_bus: std::sync::Arc<EventBus>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                result = self.listener.accept() => {
                    match result {
                        Ok((stream, _addr)) => {
                            let bus = event_bus.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_client(stream, bus).await {
                                    tracing::warn!(error = %e, "IPC client error");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "Failed to accept IPC connection");
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("IPC server shutting down");
                    break;
                }
            }
        }

        // Clean up socket file
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Handle a single client connection.
async fn handle_client(
    stream: UnixStream,
    event_bus: std::sync::Arc<EventBus>,
) -> std::io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Read one request per connection (simple request-response)
    let bytes_read = reader.read_line(&mut line).await?;
    if bytes_read == 0 {
        return Ok(()); // Client disconnected
    }

    // Check message size
    if line.len() > MAX_MESSAGE_SIZE {
        let response = IpcResponse::error("message too large");
        let response_json = serde_json::to_string(&response).unwrap_or_default();
        writer.write_all(response_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        return Ok(());
    }

    // Parse and handle request
    let response = match serde_json::from_str::<IpcRequest>(&line) {
        Ok(request) => handle_request(request, &event_bus).await,
        Err(e) => IpcResponse::error(format!("invalid request: {e}")),
    };

    // Send response
    let response_json = serde_json::to_string(&response).unwrap_or_default();
    writer.write_all(response_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    Ok(())
}

/// Handle a parsed IPC request.
async fn handle_request(request: IpcRequest, event_bus: &EventBus) -> IpcResponse {
    match request {
        IpcRequest::UserVar {
            pane_id,
            name,
            value,
        } => {
            // Decode and validate the user-var payload
            match UserVarPayload::decode(&value, true) {
                Ok(payload) => {
                    // Publish event to the bus
                    let event = Event::UserVarReceived {
                        pane_id,
                        name,
                        payload,
                    };
                    let subscribers = event_bus.publish(event);
                    tracing::debug!(pane_id, subscribers, "Published user-var event");
                    IpcResponse::ok()
                }
                Err(e) => IpcResponse::error(e.to_string()),
            }
        }
        IpcRequest::Ping => IpcResponse::ok_with_data(serde_json::json!({
            "pong": true,
            "uptime_ms": event_bus.uptime().as_millis() as u64,
        })),
        IpcRequest::Status => {
            let stats = event_bus.stats();
            let total_queued = stats.delta_queued + stats.detection_queued + stats.signal_queued;
            let total_subscribers =
                stats.delta_subscribers + stats.detection_subscribers + stats.signal_subscribers;
            IpcResponse::ok_with_data(serde_json::json!({
                "uptime_ms": event_bus.uptime().as_millis() as u64,
                "events_queued": total_queued,
                "subscriber_count": total_subscribers,
            }))
        }
    }
}

/// IPC client for sending requests to the watcher daemon.
pub struct IpcClient {
    socket_path: PathBuf,
}

impl IpcClient {
    /// Create a new IPC client.
    #[must_use]
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }

    /// Check if the watcher socket exists.
    #[must_use]
    pub fn socket_exists(&self) -> bool {
        self.socket_path.exists()
    }

    /// Send a user-var event to the watcher daemon.
    ///
    /// # Arguments
    /// * `pane_id` - Pane that emitted the user-var
    /// * `name` - Variable name (e.g., "WA_EVENT")
    /// * `value` - Raw value (typically base64-encoded JSON)
    ///
    /// # Errors
    /// Returns error if connection or send fails.
    pub async fn send_user_var(
        &self,
        pane_id: u64,
        name: String,
        value: String,
    ) -> Result<IpcResponse, UserVarError> {
        let request = IpcRequest::UserVar {
            pane_id,
            name,
            value,
        };
        self.send_request(request).await
    }

    /// Ping the watcher daemon.
    ///
    /// # Errors
    /// Returns error if connection fails.
    pub async fn ping(&self) -> Result<IpcResponse, UserVarError> {
        self.send_request(IpcRequest::Ping).await
    }

    /// Get watcher status.
    ///
    /// # Errors
    /// Returns error if connection fails.
    pub async fn status(&self) -> Result<IpcResponse, UserVarError> {
        self.send_request(IpcRequest::Status).await
    }

    /// Send a request and receive a response.
    async fn send_request(&self, request: IpcRequest) -> Result<IpcResponse, UserVarError> {
        // Check if socket exists
        if !self.socket_path.exists() {
            return Err(UserVarError::WatcherNotRunning {
                socket_path: self.socket_path.display().to_string(),
            });
        }

        // Connect to socket
        let stream = UnixStream::connect(&self.socket_path).await.map_err(|e| {
            UserVarError::IpcSendFailed {
                message: format!("failed to connect: {e}"),
            }
        })?;

        let (reader, mut writer) = stream.into_split();

        // Send request
        let request_json =
            serde_json::to_string(&request).map_err(|e| UserVarError::IpcSendFailed {
                message: format!("failed to serialize request: {e}"),
            })?;

        writer
            .write_all(request_json.as_bytes())
            .await
            .map_err(|e| UserVarError::IpcSendFailed {
                message: format!("failed to send: {e}"),
            })?;
        writer
            .write_all(b"\n")
            .await
            .map_err(|e| UserVarError::IpcSendFailed {
                message: format!("failed to send newline: {e}"),
            })?;
        writer
            .flush()
            .await
            .map_err(|e| UserVarError::IpcSendFailed {
                message: format!("failed to flush: {e}"),
            })?;

        // Read response
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .await
            .map_err(|e| UserVarError::IpcSendFailed {
                message: format!("failed to read response: {e}"),
            })?;

        // Parse response
        let response: IpcResponse =
            serde_json::from_str(&line).map_err(|e| UserVarError::IpcSendFailed {
                message: format!("invalid response: {e}"),
            })?;

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::TempDir;

    #[test]
    fn ipc_response_ok_serializes() {
        let response = IpcResponse::ok();
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"ok\":true"));
        assert!(!json.contains("error"));
    }

    #[test]
    fn ipc_response_error_serializes() {
        let response = IpcResponse::error("test error");
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"ok\":false"));
        assert!(json.contains("test error"));
    }

    #[test]
    fn ipc_request_user_var_serializes() {
        let request = IpcRequest::UserVar {
            pane_id: 42,
            name: "WA_EVENT".to_string(),
            value: "eyJraW5kIjoidGVzdCJ9".to_string(),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"type\":\"user_var\""));
        assert!(json.contains("\"pane_id\":42"));
    }

    #[test]
    fn ipc_request_ping_serializes() {
        let request = IpcRequest::Ping;
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"type\":\"ping\""));
    }

    #[test]
    fn ipc_client_detects_missing_socket() {
        let client = IpcClient::new("/nonexistent/path/ipc.sock");
        assert!(!client.socket_exists());
    }

    #[tokio::test]
    async fn ipc_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let socket_path = temp_dir.path().join("test.sock");

        // Start server
        let server = IpcServer::bind(&socket_path).await.unwrap();
        let event_bus = Arc::new(EventBus::new(100));
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let server_bus = event_bus.clone();
        let server_handle = tokio::spawn(async move {
            server.run(server_bus, shutdown_rx).await;
        });

        // Give server time to start
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Create client and send ping
        let client = IpcClient::new(&socket_path);
        let response = client.ping().await.unwrap();
        assert!(response.ok);
        assert!(response.data.is_some());

        // Send user-var event
        let response = client
            .send_user_var(
                1,
                "WA_EVENT".to_string(),
                "eyJraW5kIjoidGVzdCJ9".to_string(), // {"kind":"test"}
            )
            .await
            .unwrap();
        assert!(response.ok);

        // Shutdown
        let _ = shutdown_tx.send(()).await;
        let _ = server_handle.await;
    }
}
