//! Trace server: HTTP server for observability hub.
//!
//! Discovers UDS trace sockets in a base directory, aggregates logs,
//! and serves a rich trace viewer UI.

use axum::{
    Router,
    extract::{
        Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    response::{
        Html, IntoResponse, Json,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use futures_util::stream::{Stream, StreamExt};
use mesh::local_trace::{LogEntry, TraceConfig, TraceLevelRequest};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, broadcast};

/// Embedded web assets for the trace viewer
#[derive(RustEmbed)]
#[folder = "web/"]
pub struct TraceAssets;

/// State for the trace server
#[derive(Clone)]
pub struct TraceServerState {
    /// Base directory where UDS trace sockets are located.
    /// Each producer creates a socket named `<app_name>.sock` here.
    pub base_dir: PathBuf,

    /// Broadcast sender for aggregated log entries from all connected sources
    pub aggregated_tx: broadcast::Sender<SourcedLogEntry>,

    /// Track which sources are currently connected
    pub connected_sources: Arc<Mutex<HashMap<String, SourceInfo>>>,
}

/// A log entry tagged with its source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourcedLogEntry {
    /// Source name (derived from socket filename)
    pub source: String,
    /// The original log entry
    #[serde(flatten)]
    pub entry: LogEntry,
}

/// Info about a connected source
#[derive(Debug, Clone, Serialize)]
pub struct SourceInfo {
    pub name: String,
    pub socket_path: String,
    pub connected: bool,
}

/// Query parameter for SSE stream
#[derive(Debug, Deserialize)]
pub struct StreamQuery {
    /// Comma-separated list of source names to stream from.
    /// If empty, streams from all sources.
    pub sources: Option<String>,
}

/// API response for discovered sockets
#[derive(Debug, Serialize)]
pub struct DiscoveredSocket {
    pub name: String,
    pub path: String,
    pub connected: bool,
}

impl TraceServerState {
    pub fn new(base_dir: PathBuf) -> Self {
        let (aggregated_tx, _) = broadcast::channel(1000);
        Self {
            base_dir,
            aggregated_tx,
            connected_sources: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

/// Build the axum Router for the trace server
pub fn trace_router(state: TraceServerState) -> Router {
    Router::new()
        .route("/", get(serve_trace_viewer))
        .route("/api/sources", get(list_sources))
        .route("/api/sources/connect", get(connect_source))
        .route("/api/sources/disconnect", get(disconnect_source))
        .route("/api/sources/:name/level", post(set_source_level))
        .route("/api/stream", get(stream_aggregated_sse))
        .route("/api/stream/ws", get(stream_aggregated_ws))
        .route("/api/discover", get(discover_sockets))
        .route("/assets/*path", get(serve_asset))
        .with_state(state)
}

/// Serve the trace viewer HTML
async fn serve_trace_viewer() -> impl IntoResponse {
    match TraceAssets::get("trace_viewer.html") {
        Some(content) => Html(std::str::from_utf8(&content.data).unwrap().to_string()),
        None => Html("<h1>Error: trace_viewer.html not found</h1>".to_string()),
    }
}

/// Serve embedded static assets
async fn serve_asset(axum::extract::Path(path): axum::extract::Path<String>) -> impl IntoResponse {
    match TraceAssets::get(&path) {
        Some(content) => {
            let mime = mime_guess::from_path(&path)
                .first_or_octet_stream()
                .to_string();
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, mime)],
                content.data.to_vec(),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

/// Discover UDS sockets in the base directory
async fn discover_sockets(State(state): State<TraceServerState>) -> impl IntoResponse {
    let sockets = scan_sockets(&state.base_dir).await;
    let connected = state.connected_sources.lock().await;

    let discovered: Vec<DiscoveredSocket> = sockets
        .into_iter()
        .map(|(name, path)| DiscoveredSocket {
            connected: connected.contains_key(&name),
            name,
            path,
        })
        .collect();

    (StatusCode::OK, Json(discovered))
}

/// List currently connected sources
async fn list_sources(State(state): State<TraceServerState>) -> impl IntoResponse {
    let sources = state.connected_sources.lock().await;
    let list: Vec<SourceInfo> = sources.values().cloned().collect();
    (StatusCode::OK, Json(list))
}

/// Connect to a UDS source by name
#[derive(Debug, Deserialize)]
pub struct ConnectQuery {
    pub name: String,
    /// Optional custom socket path. If not provided, uses base_dir/<name>.sock.
    pub path: Option<String>,
}

async fn connect_source(
    State(state): State<TraceServerState>,
    Query(query): Query<ConnectQuery>,
) -> impl IntoResponse {
    let socket_path = query.path.unwrap_or_else(|| {
        state
            .base_dir
            .join(format!("{}.sock", query.name))
            .to_string_lossy()
            .to_string()
    });

    // Check if already connected
    {
        let sources = state.connected_sources.lock().await;
        if sources.contains_key(&query.name) {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "Source already connected"})),
            )
                .into_response();
        }
    }

    // Try to connect to the UDS socket
    let stream = match UnixStream::connect(&socket_path).await {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("Failed to connect to {}: {}", socket_path, e)})),
            )
                .into_response();
        }
    };

    // Register source
    let source_name = query.name.clone();
    {
        let mut sources = state.connected_sources.lock().await;
        sources.insert(
            source_name.clone(),
            SourceInfo {
                name: source_name.clone(),
                socket_path: socket_path.clone(),
                connected: true,
            },
        );
    }

    // Spawn a task to read from the UDS and broadcast entries
    let tx = state.aggregated_tx.clone();
    let connected_sources = state.connected_sources.clone();
    let name = source_name.clone();

    tokio::spawn(async move {
        read_uds_source(stream, &name, tx).await;
        // Mark as disconnected when done
        let mut sources = connected_sources.lock().await;
        sources.remove(&name);
        tracing::info!("Source '{}' disconnected", name);
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({"connected": source_name})),
    )
        .into_response()
}

/// Disconnect from a UDS source by name
async fn disconnect_source(
    State(state): State<TraceServerState>,
    Query(query): Query<ConnectQuery>,
) -> impl IntoResponse {
    let mut sources = state.connected_sources.lock().await;
    if sources.remove(&query.name).is_some() {
        (
            StatusCode::OK,
            Json(serde_json::json!({"disconnected": query.name})),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Source not found"})),
        )
    }
}

/// Build the shared aggregated stream: subscribe to the broadcast, optionally
/// filter by source name, and yield `SourcedLogEntry` values. Used by both
/// the SSE endpoint and the WebSocket endpoint so transport differences are
/// the only per-handler concern. Returns a `Unpin` stream so both
/// `Stream::map` (SSE) and `Stream::next().await` (WS) work directly.
fn aggregated_stream(
    rx: broadcast::Receiver<SourcedLogEntry>,
    source_filter: Option<Vec<String>>,
) -> impl Stream<Item = SourcedLogEntry> + Send + 'static {
    use tokio_stream::wrappers::BroadcastStream;
    BroadcastStream::new(rx)
        .filter_map(|r| async move { r.ok() })
        .filter(move |entry| {
            let keep = match &source_filter {
                Some(s) => s.contains(&entry.source),
                None => true,
            };
            std::future::ready(keep)
        })
}

fn parse_source_filter(raw: Option<String>) -> Option<Vec<String>> {
    raw.map(|s| {
        s.split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect()
    })
    .filter(|v: &Vec<String>| !v.is_empty())
}

/// SSE endpoint that streams aggregated log entries from all connected sources
async fn stream_aggregated_sse(
    State(state): State<TraceServerState>,
    Query(query): Query<StreamQuery>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.aggregated_tx.subscribe();
    let source_filter = parse_source_filter(query.sources);

    let stream = aggregated_stream(rx, source_filter)
        .map(|entry| Ok(Event::default().data(serde_json::to_string(&entry).unwrap_or_default())));

    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// WebSocket endpoint mirroring `/api/stream` (SSE). Sends each
/// `SourcedLogEntry` as a text frame. Useful for clients that prefer
/// WebSocket over EventSource.
async fn stream_aggregated_ws(
    ws: WebSocketUpgrade,
    State(state): State<TraceServerState>,
    Query(query): Query<StreamQuery>,
) -> impl IntoResponse {
    let rx = state.aggregated_tx.subscribe();
    let source_filter = parse_source_filter(query.sources);
    ws.on_upgrade(move |socket| ws_stream_loop(socket, rx, source_filter))
}

async fn ws_stream_loop(
    mut socket: WebSocket,
    rx: broadcast::Receiver<SourcedLogEntry>,
    source_filter: Option<Vec<String>>,
) {
    // The aggregated stream is not Unpin, so pin it on the heap to drive it
    // with `Stream::next().await` from a select/cancellation-safe loop.
    let mut stream = Box::pin(aggregated_stream(rx, source_filter));
    while let Some(entry) = stream.next().await {
        let text = serde_json::to_string(&entry).unwrap_or_default();
        if socket.send(Message::Text(text)).await.is_err() {
            break;
        }
    }
    let _ = socket.close().await;
}

/// Set the trace level on a connected source.
///
/// Opens a one-shot UDS connection to `<base_dir>/<name>.sock`, sends a
/// `TraceConfig` with `control: true` and the requested level, reads the
/// producer's ack, and returns it. This is the supported way to change a
/// producer's `RUST_LOG` at runtime; apps expose only a UDS trace socket
/// (no HTTP).
async fn set_source_level(
    State(state): State<TraceServerState>,
    axum::extract::Path(name): axum::extract::Path<String>,
    Json(req): Json<TraceLevelRequest>,
) -> impl IntoResponse {
    let socket_path = state.base_dir.join(format!("{}.sock", name));

    let config = TraceConfig {
        global_level: req.level.clone(),
        modules: HashMap::new(),
        targets: Vec::new(),
        min_level: None,
        max_level: None,
        fields: HashMap::new(),
        control: Some(true),
    };
    let config_line = match serde_json::to_string(&config) {
        Ok(s) => format!("{}\n", s),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    let stream = match UnixStream::connect(&socket_path).await {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": format!("connect {}: {}", socket_path.display(), e)
                })),
            )
                .into_response();
        }
    };

    let (reader, mut writer) = stream.into_split();
    if writer.write_all(config_line.as_bytes()).await.is_err() {
        return (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": "failed to send config to source" })),
        )
            .into_response();
    }
    let _ = writer.shutdown().await;

    // Read the single ack line from the producer.
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    match reader.read_line(&mut line).await {
        Ok(0) | Err(_) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": "source closed before ack" })),
        )
            .into_response(),
        Ok(_) => {
            let value: serde_json::Value = serde_json::from_str(line.trim())
                .unwrap_or_else(|_| json!({ "ok": true, "raw": line.trim() }));
            (StatusCode::OK, Json(value)).into_response()
        }
    }
}

/// Read log entries from a UDS source and broadcast them
async fn read_uds_source(
    stream: UnixStream,
    source_name: &str,
    tx: broadcast::Sender<SourcedLogEntry>,
) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // Send a default config to the producer. `global_level: "trace"` raises
    // the producer to trace so the buffer/stream actually carries every
    // event. This is the #3 mechanism: collectors can request a level and
    // the producer applies it via the global reload handle.
    let config = TraceConfig {
        global_level: "trace".to_string(),
        modules: HashMap::new(),
        targets: Vec::new(),
        min_level: None,
        max_level: None,
        fields: HashMap::new(),
        control: None,
    };

    if let Ok(config_json) = serde_json::to_string(&config) {
        let config_line = format!("{}\n", config_json);
        if writer.write_all(config_line.as_bytes()).await.is_err() {
            tracing::warn!("Failed to send config to source '{}'", source_name);
            return;
        }
    }

    // Read log entries line by line
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                tracing::info!("Source '{}' EOF", source_name);
                break;
            }
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                match serde_json::from_str::<LogEntry>(trimmed) {
                    Ok(entry) => {
                        let sourced = SourcedLogEntry {
                            source: source_name.to_string(),
                            entry,
                        };
                        let _ = tx.send(sourced);
                    }
                    Err(e) => {
                        tracing::debug!(
                            "Failed to parse log entry from '{}': {} (line: {})",
                            source_name,
                            e,
                            trimmed
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Read error from source '{}': {}", source_name, e);
                break;
            }
        }
    }
}

/// Scan a directory for UDS socket files
async fn scan_sockets(base_dir: &Path) -> Vec<(String, String)> {
    let mut sockets = Vec::new();

    if let Ok(mut entries) = tokio::fs::read_dir(base_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "sock") {
                if let Some(stem) = path.file_stem() {
                    sockets.push((
                        stem.to_string_lossy().to_string(),
                        path.to_string_lossy().to_string(),
                    ));
                }
            }
        }
    }

    sockets
}

/// Start the trace HTTP server
pub async fn run_trace_server(
    base_dir: PathBuf,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    // Ensure base dir exists
    tokio::fs::create_dir_all(&base_dir).await?;

    let state = TraceServerState::new(base_dir.clone());

    // Auto-discover and connect to existing sockets
    let existing = scan_sockets(&base_dir).await;
    for (name, path) in &existing {
        tracing::info!("Auto-discovered trace socket: {} ({})", name, path);
        // Auto-connect to each discovered socket
        if let Ok(stream) = UnixStream::connect(path).await {
            let source_name = name.clone();
            {
                let mut sources = state.connected_sources.lock().await;
                sources.insert(
                    source_name.clone(),
                    SourceInfo {
                        name: source_name.clone(),
                        socket_path: path.clone(),
                        connected: true,
                    },
                );
            }
            let tx = state.aggregated_tx.clone();
            let connected_sources = state.connected_sources.clone();
            let name_clone = source_name.clone();
            tokio::spawn(async move {
                read_uds_source(stream, &name_clone, tx).await;
                let mut sources = connected_sources.lock().await;
                sources.remove(&name_clone);
                tracing::info!("Auto-connected source '{}' disconnected", name_clone);
            });
            tracing::info!("Auto-connected to trace source: {}", source_name);
        } else {
            tracing::warn!(
                "Failed to auto-connect to trace socket: {} ({})",
                name,
                path
            );
        }
    }

    let app = trace_router(state);

    let addr = format!("127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Trace server listening on http://{}", addr);

    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}
