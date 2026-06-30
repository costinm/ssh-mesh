//! Trace hub JSON-lines service.
//!
//! The service discovers producer trace sockets, connects to selected
//! producers, aggregates log entries, and exposes request/response commands
//! plus streaming notifications over the mesh JSONL protocol.

use mesh::local_trace::{LogEntry, TraceConfig, TraceLevelRequest};
use mesh::protocol::Response;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, broadcast};
use tracing::{debug, info, warn};

/// State for the trace hub.
#[derive(Clone)]
pub struct TraceServerState {
    /// Base directory where producer UDS trace sockets are located.
    pub base_dir: PathBuf,
    /// Broadcast sender for aggregated log entries from all connected sources.
    pub aggregated_tx: broadcast::Sender<SourcedLogEntry>,
    /// Track which sources are currently connected.
    pub connected_sources: Arc<Mutex<HashMap<String, SourceInfo>>>,
}

/// A log entry tagged with its source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourcedLogEntry {
    /// Source name derived from socket filename.
    pub source: String,
    /// The original log entry fields.
    #[serde(flatten)]
    pub entry: LogEntry,
}

/// Info about a connected source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceInfo {
    pub name: String,
    pub socket_path: String,
    pub connected: bool,
}

/// API response for discovered sockets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredSocket {
    pub name: String,
    pub path: String,
    pub connected: bool,
}

/// JSON-lines request methods for traceweb.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method")]
pub enum Request {
    /// Discover producer sockets under the trace base directory.
    #[serde(rename = "discover", alias = "discover_sockets")]
    Discover,
    /// List connected producer sources.
    #[serde(rename = "sources", alias = "list_sources")]
    Sources,
    /// Connect to a producer source by name and optional explicit socket path.
    #[serde(rename = "connect_source")]
    ConnectSource { name: String, path: Option<String> },
    /// Forget a connected source. Existing reader tasks exit when the source closes.
    #[serde(rename = "disconnect_source")]
    DisconnectSource { name: String },
    /// Set the producer EnvFilter level on one source.
    #[serde(rename = "set_source_level")]
    SetSourceLevel { name: String, level: String },
    /// Subscribe to aggregated log notifications on the current JSONL connection.
    #[serde(rename = "subscribe")]
    Subscribe {
        /// Optional list of source names. Empty means all connected sources.
        #[serde(default)]
        sources: Option<Vec<String>>,
    },
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

/// Reusable trace hub command service.
#[derive(Clone)]
pub struct TraceService {
    state: TraceServerState,
}

impl TraceService {
    /// Create a trace service for a socket base directory.
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            state: TraceServerState::new(base_dir),
        }
    }

    /// Auto-connect to producer sockets that already exist.
    pub async fn auto_connect_existing(&self) {
        for (name, path) in scan_sockets(&self.state.base_dir).await {
            match self.connect_source(name.clone(), Some(path.clone())).await {
                Ok(_) => info!(source = %name, path = %path, "traceweb source autoconnected"),
                Err(e) => {
                    warn!(source = %name, path = %path, error = %e, "traceweb source autoconnect failed")
                }
            }
        }
    }

    /// Handle a request/response JSONL method.
    pub async fn handle_request(&self, request: Request) -> Response {
        match request {
            Request::Discover => Response::ok_with_data(json!(self.discover().await)),
            Request::Sources => Response::ok_with_data(json!(self.sources().await)),
            Request::ConnectSource { name, path } => match self.connect_source(name, path).await {
                Ok(source) => Response::ok_with_data(json!({ "connected": source })),
                Err(e) => Response::err(e),
            },
            Request::DisconnectSource { name } => match self.disconnect_source(&name).await {
                true => Response::ok_with_data(json!({ "disconnected": name })),
                false => Response::err(format!("source {name} not found")),
            },
            Request::SetSourceLevel { name, level } => {
                match self.set_source_level(&name, &level).await {
                    Ok(value) => Response::ok_with_data(value),
                    Err(e) => Response::err(e),
                }
            }
            Request::Subscribe { .. } => {
                Response::err("subscribe is a streaming method and is handled before dispatch")
            }
        }
    }

    async fn discover(&self) -> Vec<DiscoveredSocket> {
        let sockets = scan_sockets(&self.state.base_dir).await;
        let connected = self.state.connected_sources.lock().await;
        sockets
            .into_iter()
            .map(|(name, path)| DiscoveredSocket {
                connected: connected.contains_key(&name),
                name,
                path,
            })
            .collect()
    }

    async fn sources(&self) -> Vec<SourceInfo> {
        let sources = self.state.connected_sources.lock().await;
        sources.values().cloned().collect()
    }

    async fn connect_source(&self, name: String, path: Option<String>) -> Result<String, String> {
        let socket_path = path.unwrap_or_else(|| {
            self.state
                .base_dir
                .join(format!("{name}.sock"))
                .to_string_lossy()
                .to_string()
        });

        {
            let sources = self.state.connected_sources.lock().await;
            if sources.contains_key(&name) {
                return Err(format!("source {name} already connected"));
            }
        }

        let stream = UnixStream::connect(&socket_path)
            .await
            .map_err(|e| format!("connect {socket_path}: {e}"))?;

        {
            let mut sources = self.state.connected_sources.lock().await;
            sources.insert(
                name.clone(),
                SourceInfo {
                    name: name.clone(),
                    socket_path: socket_path.clone(),
                    connected: true,
                },
            );
        }

        let tx = self.state.aggregated_tx.clone();
        let connected_sources = self.state.connected_sources.clone();
        let source_name = name.clone();
        tokio::spawn(async move {
            read_uds_source(stream, &source_name, tx).await;
            let mut sources = connected_sources.lock().await;
            sources.remove(&source_name);
            info!(source = %source_name, "traceweb source disconnected");
        });

        Ok(name)
    }

    async fn disconnect_source(&self, name: &str) -> bool {
        let mut sources = self.state.connected_sources.lock().await;
        sources.remove(name).is_some()
    }

    async fn set_source_level(&self, name: &str, level: &str) -> Result<Value, String> {
        let socket_path = self.state.base_dir.join(format!("{name}.sock"));

        let config = TraceConfig {
            global_level: level.to_string(),
            modules: HashMap::new(),
            targets: Vec::new(),
            min_level: None,
            max_level: None,
            fields: HashMap::new(),
            control: Some(true),
        };
        let config_line = serde_json::to_string(&config)
            .map_err(|e| e.to_string())
            .map(|s| format!("{s}\n"))?;

        let stream = UnixStream::connect(&socket_path)
            .await
            .map_err(|e| format!("connect {}: {e}", socket_path.display()))?;
        let (reader, mut writer) = stream.into_split();
        writer
            .write_all(config_line.as_bytes())
            .await
            .map_err(|e| format!("send config to source: {e}"))?;
        writer
            .shutdown()
            .await
            .map_err(|e| format!("shutdown source config writer: {e}"))?;

        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        match reader.read_line(&mut line).await {
            Ok(0) => Err("source closed before ack".to_string()),
            Ok(_) => Ok(serde_json::from_str(line.trim())
                .unwrap_or_else(|_| json!({ "ok": true, "raw": line.trim() }))),
            Err(e) => Err(format!("read ack from source: {e}")),
        }
    }

    fn subscribe(&self) -> broadcast::Receiver<SourcedLogEntry> {
        self.state.aggregated_tx.subscribe()
    }
}

/// Run the traceweb JSON-lines service on an activated UDS socket or stdio.
pub async fn run_trace_server(base_dir: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    tokio::fs::create_dir_all(&base_dir).await?;
    let service = Arc::new(TraceService::new(base_dir));
    service.auto_connect_existing().await;
    let mcp = Arc::new(mesh::jsonl::McpRegistry::new("traceweb"));

    let mut listener = mesh::server::MeshListener::new("traceweb", None)?;
    while let Some(stream) = listener.accept().await? {
        let service = service.clone();
        let mcp = mcp.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_jsonl_connection(stream, service, mcp).await {
                warn!(error = %e, "traceweb JSONL connection error");
            }
        });
    }

    Ok(())
}

async fn handle_jsonl_connection(
    stream: mesh::server::MeshStream,
    service: Arc<TraceService>,
    mcp: Arc<mesh::jsonl::McpRegistry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;
        if bytes_read == 0 {
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (raw_format, raw) = mesh::jsonl::parse_raw_request(trimmed);
        if matches!(raw.as_ref().map(|r| r.method.as_str()), Ok("subscribe")) {
            let request = match mesh::jsonl::parse_request::<Request>(trimmed).1 {
                Ok(request) => request,
                Err(e) => {
                    let response = mesh::jsonl::format_response(Response::err(e), &raw_format)?;
                    write_jsonl(reader.get_mut(), &response).await?;
                    continue;
                }
            };
            if let Request::Subscribe { sources } = request {
                stream_notifications(reader.get_mut(), service.subscribe(), sources).await?;
                break;
            }
        }

        let service = service.clone();
        let (format, response) = mesh::jsonl::dispatch_request(trimmed, &mcp, move |request| {
            let service = service.clone();
            async move {
                debug!(?request, "traceweb JSONL request");
                service.handle_request(request).await
            }
        })
        .await;
        let Some(response) = response else {
            continue;
        };
        let response = mesh::jsonl::format_response(response, &format)?;
        write_jsonl(reader.get_mut(), &response).await?;
    }

    Ok(())
}

async fn write_jsonl(
    stream: &mut mesh::server::MeshStream,
    line: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    stream.write_all(line.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;
    Ok(())
}

async fn stream_notifications(
    stream: &mut mesh::server::MeshStream,
    mut rx: broadcast::Receiver<SourcedLogEntry>,
    sources: Option<Vec<String>>,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let entry = match rx.recv().await {
            Ok(entry) => entry,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        };
        if let Some(filter) = &sources
            && !filter.is_empty()
            && !filter.contains(&entry.source)
        {
            continue;
        }

        let notification = json!({
            "jsonrpc": "2.0",
            "method": "trace_entry",
            "params": entry,
        });
        let line = serde_json::to_string(&notification)?;
        write_jsonl(stream, &line).await?;
    }
    Ok(())
}

/// Read log entries from a producer UDS source and broadcast them.
async fn read_uds_source(
    stream: UnixStream,
    source_name: &str,
    tx: broadcast::Sender<SourcedLogEntry>,
) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

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
        let config_line = format!("{config_json}\n");
        if writer.write_all(config_line.as_bytes()).await.is_err() {
            warn!(source = %source_name, "failed to send trace config to source");
            return;
        }
    }

    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                match serde_json::from_str::<LogEntry>(trimmed) {
                    Ok(entry) => {
                        let _ = tx.send(SourcedLogEntry {
                            source: source_name.to_string(),
                            entry,
                        });
                    }
                    Err(e) => debug!(
                        source = %source_name,
                        error = %e,
                        line = %trimmed,
                        "failed to parse trace source log entry"
                    ),
                }
            }
            Err(e) => {
                warn!(source = %source_name, error = %e, "trace source read error");
                break;
            }
        }
    }
}

/// Scan a directory for UDS socket files.
async fn scan_sockets(base_dir: &Path) -> Vec<(String, String)> {
    let mut sockets = Vec::new();

    if let Ok(mut entries) = tokio::fs::read_dir(base_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "sock")
                && let Some(stem) = path.file_stem()
            {
                sockets.push((
                    stem.to_string_lossy().to_string(),
                    path.to_string_lossy().to_string(),
                ));
            }
        }
    }

    sockets
}

#[allow(dead_code)]
fn _trace_level_request_for_docs(level: String) -> TraceLevelRequest {
    TraceLevelRequest { level }
}
