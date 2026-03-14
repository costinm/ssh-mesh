//! Trace server: HTTP server for observability hub.
//!
//! Discovers UDS trace sockets in a base directory, aggregates logs,
//! and serves a rich trace viewer UI. Also provides controls for
//! Perfetto tracer and OTEL push.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        Html, IntoResponse, Json,
    },
    routing::{get, post},
    Router,
};
use futures_util::stream::{self, Stream};
use mesh::local_trace::{LogEntry, TraceConfig};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{broadcast, Mutex};

/// Embedded web assets for the otel trace viewer
#[derive(RustEmbed)]
#[folder = "web/"]
pub struct OtelAssets;

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

    /// Perfetto consumer socket path (configurable)
    pub perfetto_socket: Arc<Mutex<String>>,

    /// Whether OTEL push is currently active
    pub otel_push_active: Arc<Mutex<bool>>,
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

/// Perfetto config request/response
#[derive(Debug, Serialize, Deserialize)]
pub struct PerfettoConfig {
    pub socket: String,
    pub connected: bool,
}

/// OTEL push status
#[derive(Debug, Serialize, Deserialize)]
pub struct OtelPushStatus {
    pub active: bool,
    pub endpoint: Option<String>,
}

impl TraceServerState {
    pub fn new(base_dir: PathBuf) -> Self {
        let (aggregated_tx, _) = broadcast::channel(1000);
        Self {
            base_dir,
            aggregated_tx,
            connected_sources: Arc::new(Mutex::new(HashMap::new())),
            perfetto_socket: Arc::new(Mutex::new("/tmp/perfetto-consumer".to_string())),
            otel_push_active: Arc::new(Mutex::new(false)),
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
        .route("/api/stream", get(stream_aggregated_sse))
        .route("/api/discover", get(discover_sockets))
        .route("/api/perfetto", get(get_perfetto_config))
        .route("/api/perfetto/pull", post(perfetto_pull_handler))
        .route("/api/otel", get(get_otel_status))
        .route("/api/otel/toggle", post(otel_toggle_handler))
        .route("/assets/*path", get(serve_asset))
        .with_state(state)
}

/// Serve the trace viewer HTML
async fn serve_trace_viewer() -> impl IntoResponse {
    match OtelAssets::get("trace_viewer.html") {
        Some(content) => Html(std::str::from_utf8(&content.data).unwrap().to_string()),
        None => Html("<h1>Error: trace_viewer.html not found</h1>".to_string()),
    }
}

/// Serve embedded static assets
async fn serve_asset(axum::extract::Path(path): axum::extract::Path<String>) -> impl IntoResponse {
    match OtelAssets::get(&path) {
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

/// SSE endpoint that streams aggregated log entries from all connected sources
async fn stream_aggregated_sse(
    State(state): State<TraceServerState>,
    Query(query): Query<StreamQuery>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.aggregated_tx.subscribe();
    let source_filter: Option<Vec<String>> = query
        .sources
        .map(|s| s.split(',').map(|s| s.trim().to_string()).collect());

    let stream = stream::unfold((rx, source_filter), |(mut rx, filter)| async move {
        loop {
            match rx.recv().await {
                Ok(entry) => {
                    // Apply source filter if provided
                    if let Some(ref sources) = filter {
                        if !sources.contains(&entry.source) {
                            continue;
                        }
                    }
                    if let Ok(json) = serde_json::to_string(&entry) {
                        return Some((Ok(Event::default().data(json)), (rx, filter)));
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// Get current Perfetto configuration
async fn get_perfetto_config(State(state): State<TraceServerState>) -> impl IntoResponse {
    let socket = state.perfetto_socket.lock().await.clone();
    (
        StatusCode::OK,
        Json(PerfettoConfig {
            socket,
            connected: false, // TODO: track actual connection status
        }),
    )
}

/// Query parameters for the Perfetto pull request
#[derive(Debug, Deserialize)]
pub struct PerfettoPullQuery {
    pub socket: Option<String>,
    pub duration: Option<u64>,
}

/// Handler for POST /api/perfetto/pull
///
/// Starts a Perfetto pull session for the specified duration.
async fn perfetto_pull_handler(
    State(state): State<TraceServerState>,
    Query(query): Query<PerfettoPullQuery>,
) -> impl IntoResponse {
    let socket = match query.socket {
        Some(s) => s,
        None => state.perfetto_socket.lock().await.clone(),
    };
    let duration = query.duration.unwrap_or(10);

    // Spawn the pull in a background task so we don't block the HTTP response
    tokio::task::spawn_blocking(move || {
        match crate::perfetto_pull::PerfettoPull::new_system(&socket) {
            Ok(mut pull) => {
                pull.start();
                std::thread::sleep(std::time::Duration::from_secs(duration));
                if let Err(e) = pull.stop() {
                    tracing::error!("Perfetto pull stop error: {}", e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to create Perfetto pull session: {}", e);
            }
        }
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "pulling", "duration": duration})),
    )
}

/// Get OTEL push status
async fn get_otel_status(State(state): State<TraceServerState>) -> impl IntoResponse {
    let active = *state.otel_push_active.lock().await;
    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();
    (StatusCode::OK, Json(OtelPushStatus { active, endpoint }))
}

/// Handler for POST /api/otel/toggle
///
/// Toggles the OTEL push active flag.
async fn otel_toggle_handler(State(state): State<TraceServerState>) -> impl IntoResponse {
    let mut active = state.otel_push_active.lock().await;
    *active = !*active;
    let new_state = *active;
    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();
    (
        StatusCode::OK,
        Json(OtelPushStatus {
            active: new_state,
            endpoint,
        }),
    )
}

/// Read log entries from a UDS source and broadcast them
async fn read_uds_source(
    stream: UnixStream,
    source_name: &str,
    tx: broadcast::Sender<SourcedLogEntry>,
) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // Send a default config to the producer (request all logs)
    let config = TraceConfig {
        global_level: "trace".to_string(),
        modules: HashMap::new(),
        targets: Vec::new(),
        min_level: None,
        max_level: None,
        fields: HashMap::new(),
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
            if path.extension().map_or(false, |ext| ext == "sock") {
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
