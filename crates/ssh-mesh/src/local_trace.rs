//! Local trace functionality including in-memory log buffering and WebSocket streaming.
//!
//! This module provides:
//! - Dynamic trace level configuration via REST API
//! - In-memory circular buffer for recent log entries
//! - Real-time log streaming via WebSocket

use axum::{
    Router,
    extract::{State, ws::WebSocket, ws::WebSocketUpgrade},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, put},
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::broadcast;
use tracing_subscriber::layer::{Context, Layer};

/// Maximum number of log entries to keep in the circular buffer (default)
const DEFAULT_BUFFER_SIZE: usize = 1000;

/// A single log entry in the buffer
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LogEntry {
    /// Timestamp in RFC3339 format
    pub timestamp: String,
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
    /// Target module/crate
    pub target: String,
    /// Log message
    pub message: String,
    /// Optional fields (key-value pairs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<serde_json::Value>,
}

/// Request body for setting trace level
#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
pub struct TraceLevelRequest {
    /// The new trace level filter directive (e.g., "info", "debug", "trace", "ssh_mesh=debug,info")
    pub level: String,
}

/// Response for getting/setting trace level
#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
pub struct TraceLevelResponse {
    /// The current trace level filter directive
    pub level: String,
    /// Optional message indicating the result of the operation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Circular buffer for storing recent log entries
#[derive(Clone)]
pub struct LogBuffer {
    inner: Arc<RwLock<LogBufferInner>>,
}

struct LogBufferInner {
    buffer: VecDeque<LogEntry>,
    max_size: usize,
    tx: broadcast::Sender<LogEntry>,
}

impl LogBuffer {
    /// Create a new log buffer with the specified maximum size
    pub fn new(max_size: usize) -> Self {
        let (tx, _) = broadcast::channel(100);
        Self {
            inner: Arc::new(RwLock::new(LogBufferInner {
                buffer: VecDeque::with_capacity(max_size),
                max_size,
                tx,
            })),
        }
    }

    /// Add a log entry to the buffer
    pub fn push(&self, entry: LogEntry) {
        let mut inner = self.inner.write().unwrap();

        // Add to circular buffer
        if inner.buffer.len() >= inner.max_size {
            inner.buffer.pop_front();
        }
        inner.buffer.push_back(entry.clone());

        // Broadcast to WebSocket clients (ignore if no receivers)
        let _ = inner.tx.send(entry);
    }

    /// Get all current log entries
    pub fn get_all(&self) -> Vec<LogEntry> {
        let inner = self.inner.read().unwrap();
        inner.buffer.iter().cloned().collect()
    }

    /// Subscribe to new log entries
    pub fn subscribe(&self) -> broadcast::Receiver<LogEntry> {
        let inner = self.inner.read().unwrap();
        inner.tx.subscribe()
    }

    /// Get the current buffer size
    pub fn len(&self) -> usize {
        let inner = self.inner.read().unwrap();
        inner.buffer.len()
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Custom tracing layer that captures log events and stores them in the buffer
pub struct LogBufferLayer {
    buffer: LogBuffer,
}

impl LogBufferLayer {
    pub fn new(buffer: LogBuffer) -> Self {
        Self { buffer }
    }
}

impl<S> Layer<S> for LogBufferLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();

        // Create a visitor to extract the message and fields
        let mut visitor = LogVisitor::default();
        event.record(&mut visitor);

        let entry = LogEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            level: metadata.level().to_string().to_lowercase(),
            target: metadata.target().to_string(),
            message: visitor.message,
            fields: if visitor.fields.is_empty() {
                None
            } else {
                Some(serde_json::to_value(&visitor.fields).unwrap_or(serde_json::Value::Null))
            },
        };

        self.buffer.push(entry);
    }
}

/// Visitor to extract message and fields from tracing events
#[derive(Default)]
struct LogVisitor {
    message: String,
    fields: std::collections::HashMap<String, serde_json::Value>,
}

impl tracing::field::Visit for LogVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
            // Remove quotes if present
            if self.message.starts_with('"') && self.message.ends_with('"') {
                self.message = self.message[1..self.message.len() - 1].to_string();
            }
        } else {
            self.fields.insert(
                field.name().to_string(),
                serde_json::Value::String(format!("{:?}", value)),
            );
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.fields.insert(
                field.name().to_string(),
                serde_json::Value::String(value.to_string()),
            );
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), serde_json::Value::Bool(value));
    }
}

/// Get the current tracing level
#[utoipa::path(
    get,
    path = "/_m/trace/level",
    tag = "tracing",
    responses(
        (status = 200, description = "Current trace level", body = TraceLevelResponse),
        (status = 500, description = "Failed to get trace level")
    )
)]
pub async fn get_trace_level() -> impl IntoResponse {
    // Note: EnvFilter doesn't provide an easy way to get the current filter as a string,
    // so we return a placeholder. The actual filter is managed by tracing-subscriber.
    // In a production system, you might want to store the filter string separately.
    (
        StatusCode::OK,
        Json(TraceLevelResponse {
            level: "See logs for current level (configured via RUST_LOG or set via PUT)"
                .to_string(),
            message: Some("Use PUT to update the trace level".to_string()),
        }),
    )
}

/// Set a new tracing level dynamically
#[utoipa::path(
    put,
    path = "/_m/trace/level",
    tag = "tracing",
    request_body = TraceLevelRequest,
    responses(
        (status = 200, description = "Trace level updated successfully", body = TraceLevelResponse),
        (status = 400, description = "Invalid trace level format"),
        (status = 500, description = "Failed to update trace level")
    )
)]
pub async fn set_trace_level(Json(req): Json<TraceLevelRequest>) -> impl IntoResponse {
    use tracing_subscriber::EnvFilter;

    // Parse the new filter
    let new_filter = match req.level.parse::<EnvFilter>() {
        Ok(filter) => filter,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(TraceLevelResponse {
                    level: req.level.clone(),
                    message: Some(format!("Invalid filter format: {}", e)),
                }),
            )
                .into_response();
        }
    };

    // Get the reload handle and update the filter
    match crate::TRACING_RELOAD_HANDLE.get() {
        Some(handle) => match handle.reload(new_filter) {
            Ok(()) => {
                tracing::info!("Tracing level updated to: {}", req.level);
                (
                    StatusCode::OK,
                    Json(TraceLevelResponse {
                        level: req.level,
                        message: Some("Trace level updated successfully".to_string()),
                    }),
                )
                    .into_response()
            }
            Err(e) => {
                tracing::error!("Failed to reload tracing filter: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(TraceLevelResponse {
                        level: req.level,
                        message: Some(format!("Failed to reload filter: {:?}", e)),
                    }),
                )
                    .into_response()
            }
        },
        None => {
            tracing::error!("Tracing reload handle not initialized");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TraceLevelResponse {
                    level: req.level,
                    message: Some("Tracing reload handle not initialized".to_string()),
                }),
            )
                .into_response()
        }
    }
}

/// WebSocket handler for streaming logs
async fn handle_trace_view_ws(
    ws: WebSocketUpgrade,
    State(buffer): State<LogBuffer>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_trace_socket(socket, buffer))
}

/// Handle WebSocket connection for trace viewing
pub async fn handle_trace_socket(mut socket: WebSocket, buffer: LogBuffer) {
    use axum::extract::ws::Message;

    tracing::info!("New trace view WebSocket connection");

    // Send all existing log entries
    let existing_logs = buffer.get_all();
    tracing::info!("Sending {} existing log entries", existing_logs.len());

    for entry in existing_logs {
        if let Ok(json) = serde_json::to_string(&entry) {
            if socket.send(Message::Text(json)).await.is_err() {
                tracing::warn!("Failed to send existing log entry");
                return;
            }
        }
    }

    // Subscribe to new log entries
    let mut rx = buffer.subscribe();

    // Stream new log entries
    loop {
        tokio::select! {
            // Receive new log entries from broadcast channel
            Ok(entry) = rx.recv() => {
                if let Ok(json) = serde_json::to_string(&entry) {
                    if socket.send(Message::Text(json)).await.is_err() {
                        tracing::info!("Trace view WebSocket client disconnected");
                        break;
                    }
                }
            }
            // Handle incoming WebSocket messages (typically pings/close)
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => {
                        tracing::info!("Trace view WebSocket client closed connection");
                        break;
                    }
                    Some(Ok(Message::Ping(_))) => {
                        // Axum handles pongs automatically
                    }
                    Some(Err(e)) => {
                        tracing::warn!("WebSocket error: {:?}", e);
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}

/// JSON-based tracing configuration
///
/// This provides a structured alternative to RUST_LOG environment variable.
///
/// Example:
/// ```json
/// {
///   "global_level": "info",
///   "modules": {
///     "ssh_mesh::handlers": "debug",
///     "russh": "trace"
///   },
///   "targets": ["ssh_mesh", "russh"],
///   "min_level": "debug"
/// }
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TraceConfig {
    /// Global default trace level
    #[serde(default = "default_global_level")]
    pub global_level: String,

    /// Per-module trace levels
    #[serde(default)]
    pub modules: HashMap<String, String>,

    /// List of target prefixes to include (if empty, include all)
    #[serde(default)]
    pub targets: Vec<String>,

    /// Minimum level to capture (acts as a floor)
    #[serde(default)]
    pub min_level: Option<String>,

    /// Maximum level to capture (acts as a ceiling)
    #[serde(default)]
    pub max_level: Option<String>,

    /// Field filters - only include events with these fields
    #[serde(default)]
    pub fields: HashMap<String, String>,
}

fn default_global_level() -> String {
    "info".to_string()
}

impl TraceConfig {
    /// Convert to EnvFilter compatible string
    pub fn to_filter_string(&self) -> String {
        let mut parts = Vec::new();

        // Add module-specific levels
        for (module, level) in &self.modules {
            parts.push(format!("{}={}", module, level));
        }

        // Add global level
        parts.push(self.global_level.clone());

        parts.join(",")
    }

    /// Check if a log entry matches this configuration
    pub fn matches(&self, entry: &LogEntry) -> bool {
        // Check target filter
        if !self.targets.is_empty() {
            let matches_target = self.targets.iter().any(|t| entry.target.starts_with(t));
            if !matches_target {
                return false;
            }
        }

        // Check level bounds
        if let Some(ref min_level) = self.min_level {
            if !level_gte(&entry.level, min_level) {
                return false;
            }
        }

        if let Some(ref max_level) = self.max_level {
            if !level_lte(&entry.level, max_level) {
                return false;
            }
        }

        // Check field filters
        if !self.fields.is_empty() {
            if let Some(ref entry_fields) = entry.fields {
                for (key, value) in &self.fields {
                    if let Some(field_value) = entry_fields.get(key) {
                        let field_str = field_value.as_str().unwrap_or("");
                        if field_str != value {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            } else {
                return false;
            }
        }

        true
    }
}

/// Compare log levels (greater than or equal)
fn level_gte(level: &str, threshold: &str) -> bool {
    let levels = ["trace", "debug", "info", "warn", "error"];
    let level_idx = levels.iter().position(|&l| l == level).unwrap_or(2);
    let threshold_idx = levels.iter().position(|&l| l == threshold).unwrap_or(2);
    level_idx >= threshold_idx
}

/// Compare log levels (less than or equal)
fn level_lte(level: &str, threshold: &str) -> bool {
    let levels = ["trace", "debug", "info", "warn", "error"];
    let level_idx = levels.iter().position(|&l| l == level).unwrap_or(2);
    let threshold_idx = levels.iter().position(|&l| l == threshold).unwrap_or(2);
    level_idx <= threshold_idx
}

/// Start listening on a Unix Domain Socket for trace connections
///
/// Each connection:
/// 1. Expects a JSON config on the first line
/// 2. Sends all buffered entries that match the config
/// 3. Streams new entries that match the config
///
/// Example usage:
/// ```bash
/// echo '{"global_level":"debug","modules":{"ssh_mesh":"trace"}}' | nc -U /tmp/trace.sock
/// ```
pub async fn start_uds_listener(
    socket_path: impl AsRef<Path>,
    buffer: LogBuffer,
) -> std::io::Result<()> {
    let socket_path = socket_path.as_ref();

    // Remove existing socket if it exists
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    tracing::info!("UDS trace listener started at: {:?}", socket_path);

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let buffer = buffer.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_uds_connection(stream, buffer).await {
                        tracing::warn!("UDS trace connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                tracing::error!("UDS accept error: {}", e);
            }
        }
    }
}

/// Handle a single UDS connection
async fn handle_uds_connection(
    stream: tokio::net::UnixStream,
    buffer: LogBuffer,
) -> std::io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // Read first line as JSON config
    let mut config_line = String::new();
    reader.read_line(&mut config_line).await?;

    let config: TraceConfig = match serde_json::from_str(config_line.trim()) {
        Ok(cfg) => {
            tracing::info!("UDS trace connection with config: {:?}", cfg);
            cfg
        }
        Err(e) => {
            let error_msg = format!("{{\"error\":\"Invalid config JSON: {}\"}}\n", e);
            writer.write_all(error_msg.as_bytes()).await?;
            return Ok(());
        }
    };

    // Send all existing buffered entries that match the config
    let existing_logs = buffer.get_all();
    tracing::debug!(
        "Sending {} buffered entries to UDS client",
        existing_logs.len()
    );

    for entry in existing_logs {
        if config.matches(&entry) {
            if let Ok(json) = serde_json::to_string(&entry) {
                let line = format!("{}\n", json);
                if writer.write_all(line.as_bytes()).await.is_err() {
                    return Ok(());
                }
            }
        }
    }

    // Subscribe to new entries
    let mut rx = buffer.subscribe();

    // Stream new entries that match the config
    loop {
        match rx.recv().await {
            Ok(entry) => {
                if config.matches(&entry) {
                    if let Ok(json) = serde_json::to_string(&entry) {
                        let line = format!("{}\n", json);
                        if writer.write_all(line.as_bytes()).await.is_err() {
                            tracing::debug!("UDS trace client disconnected");
                            break;
                        }
                    }
                }
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                tracing::warn!("UDS trace client lagged, skipped {} entries", skipped);
                continue;
            }
            Err(broadcast::error::RecvError::Closed) => {
                tracing::info!("UDS trace broadcast channel closed");
                break;
            }
        }
    }

    Ok(())
}

/// Create the router with all trace-related routes
pub fn routes(buffer: LogBuffer) -> Router {
    Router::new()
        .route("/_m/trace/level", get(get_trace_level))
        .route("/_m/trace/level", put(set_trace_level))
        .route("/_m/trace/view", get(handle_trace_view_ws))
        .with_state(buffer)
}

/// Create a log buffer with default size
pub fn create_log_buffer() -> LogBuffer {
    LogBuffer::new(DEFAULT_BUFFER_SIZE)
}

/// Create a log buffer with custom size
pub fn create_log_buffer_with_size(size: usize) -> LogBuffer {
    LogBuffer::new(size)
}
