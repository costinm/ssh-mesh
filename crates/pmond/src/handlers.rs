use crate::{ProcMemInfo, ProcMon};
use axum::{
    extract::{State, Path as AxumPath},
    response::{Html, IntoResponse, Json},
    routing::{delete, get, post},
    Router,
};
use hyper::StatusCode;
use log::debug;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;
use ws::WSServer;
use tower_http::cors::CorsLayer;

// MCP Imports
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use rmcp::{
    handler::server::ServerHandler,
    model::{
        Annotated, CallToolResult, ErrorCode, ErrorData, Implementation, InitializeRequestParam,
        InitializeResult, ListResourcesResult, ListToolsResult, PaginatedRequestParam,
        ProtocolVersion, RawContent, RawResource, RawTextContent, ReadResourceRequestParam,
        ReadResourceResult, Resource, ResourceContents, ResourcesCapability, ServerCapabilities,
        Tool, ToolsCapability,
    },
    service::RequestContext,
    RoleServer, ServiceExt,
};
use schemars::{schema_for, JsonSchema};
use tokio::net::UnixListener;
use tracing::{error, info};

// TODO: find a way to reduce duplication and auto-generate 
// the MCP and REST boilerplate. Each public method should
// be exposed with a rust macro.


#[derive(RustEmbed)]
#[folder = "web/"]
pub struct Assets;

#[derive(Clone)]
pub struct AppState {
    pub proc_mon: Arc<ProcMon>,
    pub ws_server: Arc<WSServer>,
}

pub async fn handle_ps_request(
    State(app_state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    debug!("Received PS request");
    let processes = app_state.proc_mon.get_all_processes();
    (StatusCode::OK, Json(json!(processes)))
}

pub async fn handle_cgroups_request(
    State(app_state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    debug!("Received CGroups request");
    let cgroups = app_state.proc_mon.get_all_cgroups();
    (StatusCode::OK, Json(json!(cgroups)))
}

#[derive(Deserialize, Debug)]
pub struct CgroupHighPayload {
    pub path: String,
    pub percentage: f64,
    pub interval: u64,
}

pub async fn handle_cgroup_high_request(
    State(app_state): State<AppState>,
    Json(payload): Json<CgroupHighPayload>,
) -> (StatusCode, Json<serde_json::Value>) {
    debug!("Received CGroup High request for {}", payload.path);
    match app_state.proc_mon.adjust_cgroup_memory_high(
        payload.path,
        payload.percentage,
        payload.interval,
    ) {
        Ok(_) => (StatusCode::OK, Json(json!({"status": "ok"}))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

#[derive(Deserialize, Debug)]
pub struct CgroupProcsPayload {
    pub path: String,
}

pub async fn handle_cgroup_procs_request(
    State(app_state): State<AppState>,
    Json(payload): Json<CgroupProcsPayload>,
) -> (StatusCode, Json<serde_json::Value>) {
    debug!("Received CGroup Procs request for {}", payload.path);
    let processes = app_state.proc_mon.get_processes_in_cgroup(&payload.path);
    (StatusCode::OK, Json(json!(processes)))
}

pub async fn handle_root_request() -> Html<&'static str> {
    Html(
        r#"
        <!DOCTYPE html>
        <html>
        <head><title>PMOND</title></head>
        <body>
            <h1>PMOND - Process Monitor</h1>
            <p><a href='/web/pmon.html'>Process Monitor</a></p>
            <p><a href='/web/cgmon.html'>CGroup Monitor</a></p>
            <p><a href='/web/chat.html'>Chat</a></p>
            <p><a href='/_ps'>Process API</a></p>
            <p><a href='/_cgroups'>CGroups API</a></p>
            <p><a href='/_psi'>PSI Watches API</a></p>
            <p><a href='/ws'>WebSocket</a></p>
        </body>
        </html>
    "#,
    )
}

pub async fn get_psi_watches(
    State(app_state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    debug!("Received PSI watches request");
    let watches = app_state.proc_mon.get_psi_watches();
    (StatusCode::OK, Json(json!(watches)))
}

pub async fn handle_web_request(
    AxumPath(path): AxumPath<String>,
) -> impl axum::response::IntoResponse {
    let path = path.trim_start_matches('/');
    let local_path = Path::new("web").join(path);

    if local_path.exists() && local_path.is_file() {
        match std::fs::read(&local_path) {
            Ok(content) => {
                let mime = mime_guess::from_path(&local_path).first_or_octet_stream();
                return (
                    StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, mime.to_string())],
                    content,
                )
                    .into_response();
            }
            Err(_) => {}
        }
    }

    match Assets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, mime.to_string())],
                content.data.to_owned(),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

pub fn app(proc_mon: Arc<ProcMon>, ws_server: Arc<WSServer>) -> Router {
    let app_state = AppState {
        proc_mon: proc_mon.clone(),
        ws_server,
    };

    Router::new()
        .route("/", get(handle_root_request))
        .route("/_ps", get(handle_ps_request))
        .route("/_cgroups", get(handle_cgroups_request))
        .route("/_cgroup_high", post(handle_cgroup_high_request))
        .route("/_cgroup_procs", post(handle_cgroup_procs_request))
        .route("/_psi", get(get_psi_watches))
        .route(
            "/ws",
            get(move |State(app_state): State<AppState>, req| {
                ws::handle_websocket_upgrade(State(app_state.ws_server), req)
            }),
        )
        .route(
            "/api/clients",
            get(move |State(app_state): State<AppState>| {
                ws::handle_list_clients(State(app_state.ws_server))
            }),
        )
        .route(
            "/api/clients/:id",
            delete(move |State(app_state): State<AppState>, path| {
                ws::handle_remove_client(State(app_state.ws_server), path)
            }),
        )
        .route(
            "/api/clients/:id/message",
            post(move |State(app_state): State<AppState>, path, json| {
                ws::handle_send_message(State(app_state.ws_server), path, json)
            }),
        )
        .route(
            "/api/broadcast",
            post(move |State(app_state): State<AppState>, json| {
                ws::handle_broadcast(State(app_state.ws_server), json)
            }),
        )
        .route("/web/*path", get(handle_web_request))
        .nest_service("/mcp", mcp_service(proc_mon))
        .layer(CorsLayer::permissive())
        .with_state(app_state)
}

// ================= MCP IMPLEMENTATION =================

#[derive(Clone)]
pub struct PmonMcpHandler {
    proc_mon: Arc<ProcMon>,
}

impl PmonMcpHandler {
    pub fn new(proc_mon: Arc<ProcMon>) -> Self {
        Self { proc_mon }
    }
}

pub fn mcp_service(proc_mon: Arc<ProcMon>) -> StreamableHttpService<PmonMcpHandler> {
    let config = StreamableHttpServerConfig::default();
    let session_manager = Arc::new(LocalSessionManager::default());

    StreamableHttpService::new(
        move || Ok(PmonMcpHandler::new(proc_mon.clone())),
        session_manager,
        config,
    )
}

#[derive(Deserialize, JsonSchema)]
struct GetProcessArgs {
    process: String,
}

#[derive(Deserialize, JsonSchema)]
struct GetCgroupArgs {
    path: String,
}

#[derive(Serialize, Deserialize)]
pub struct SimplifiedProcess {
    pid: u32,
    ppid: u32,
    name: String,
    cgroup_path: Option<String>,
    cmdline: Option<String>,
    rss: u64,
    mem_info: Option<ProcMemInfo>,
    user: Option<u32>,
}

// Helper to convert Value to input_schema type (Arc<Map<String, Value>>)
fn to_schema(v: Value) -> Arc<serde_json::Map<String, Value>> {
    if let Value::Object(map) = v {
        Arc::new(map)
    } else {
        Arc::new(serde_json::Map::new())
    }
}

impl ServerHandler for PmonMcpHandler {
    async fn initialize(
        &self,
        _params: InitializeRequestParam,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        tracing::info!("MCP Initialize called");
        Ok(InitializeResult {
            protocol_version: ProtocolVersion::default(),
            server_info: Implementation {
                name: "pmond".to_string().into(),
                version: "0.1.0".to_string().into(),
                icons: None,
                title: None,
                website_url: None,
            },
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability {
                    list_changed: Some(false),
                }),
                resources: Some(ResourcesCapability {
                    list_changed: Some(false),
                    subscribe: Some(false),
                }),
                ..Default::default()
            },
            instructions: None,
        })
    }

    async fn list_tools(
        &self,
        _params: Option<PaginatedRequestParam>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        tracing::info!("list_tools called");
        let tools = vec![
            Tool {
                name: "list_processes".to_string().into(),
                description: Some("List all running processes".to_string().into()),
                input_schema: to_schema(json!({
                    "type": "object",
                    "properties": {},
                })),
                annotations: None,
                icons: None,
                meta: None,
                title: None,
                output_schema: None,
            },
            Tool {
                name: "get_process".to_string().into(),
                description: Some(
                    "Get details of a specific process by PID"
                        .to_string()
                        .into(),
                ),
                input_schema: to_schema(serde_json::to_value(schema_for!(GetProcessArgs)).unwrap()),
                annotations: None,
                icons: None,
                meta: None,
                title: None,
                output_schema: None,
            },
            Tool {
                name: "list_cgroups".to_string().into(),
                description: Some("List all cgroups used by processes".to_string().into()),
                input_schema: to_schema(json!({
                    "type": "object",
                    "properties": {},
                })),
                annotations: None,
                icons: None,
                meta: None,
                title: None,
                output_schema: None,
            },
            Tool {
                name: "get_cgroup".to_string().into(),
                description: Some(
                    "Get memory info for a specific cgroup path"
                        .to_string()
                        .into(),
                ),
                input_schema: to_schema(serde_json::to_value(schema_for!(GetCgroupArgs)).unwrap()),
                annotations: None,
                icons: None,
                meta: None,
                title: None,
                output_schema: None,
            },
        ];

        Ok(ListToolsResult {
            tools,
            next_cursor: None,
            meta: None,
        })
    }

    async fn call_tool(
        &self,
        params: rmcp::model::CallToolRequestParam,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        match params.name.as_ref() {
            "list_processes" => {
                let processes = self.proc_mon.get_all_processes();
                // Convert to a simplified list for display
                let process_list: Vec<SimplifiedProcess> = processes
                    .values()
                    .map(|p| SimplifiedProcess {
                        pid: p.pid,
                        ppid: p.ppid,
                        name: p.comm.clone(),
                        cgroup_path: p.cgroup_path.clone(),
                        cmdline: p.cmdline.clone(),
                        rss: p.mem_info.as_ref().map(|m| m.anon).unwrap_or(0),
                        mem_info: p.mem_info.clone(),
                        user: p.uid,
                    })
                    .collect();

                Ok(CallToolResult {
                    content: vec![Annotated {
                        raw: RawContent::Text(RawTextContent {
                            text: serde_json::to_string_pretty(&process_list).unwrap().into(),
                            meta: None,
                        }),
                        annotations: None,
                    }],
                    is_error: None,
                    meta: None,
                    structured_content: None,
                })
            }
            "get_process" => {
                let args_val = serde_json::Value::Object(params.arguments.unwrap_or_default());
                let args: GetProcessArgs =
                    serde_json::from_value(args_val).map_err(|e| ErrorData {
                        code: ErrorCode(-32602),
                        message: format!("Invalid arguments: {}", e).into(),
                        data: None,
                    })?;

                let pid = args.process.parse::<u32>().map_err(|_| ErrorData {
                    code: ErrorCode(-32602),
                    message: format!("Invalid PID: {}", args.process).into(),
                    data: None,
                })?;

                match self.proc_mon.get_process(pid) {
                    Some(process) => Ok(CallToolResult {
                        content: vec![Annotated {
                            raw: RawContent::Text(RawTextContent {
                                text: serde_json::to_string_pretty(&process).unwrap().into(),
                                meta: None,
                            }),
                            annotations: None,
                        }],
                        is_error: None,
                        meta: None,
                        structured_content: None,
                    }),
                    None => Err(ErrorData {
                        code: ErrorCode(-32001),
                        message: format!("Process {} not found", pid).into(),
                        data: None,
                    }),
                }
            }
            "list_cgroups" => {
                let cgroups = self.proc_mon.get_all_cgroups();
                Ok(CallToolResult {
                    content: vec![Annotated {
                        raw: RawContent::Text(RawTextContent {
                            text: serde_json::to_string_pretty(&cgroups).unwrap().into(),
                            meta: None,
                        }),
                        annotations: None,
                    }],
                    is_error: None,
                    meta: None,
                    structured_content: None,
                })
            }
            "get_cgroup" => {
                let args_val = serde_json::Value::Object(params.arguments.unwrap_or_default());
                let args: GetCgroupArgs =
                    serde_json::from_value(args_val).map_err(|e| ErrorData {
                        code: ErrorCode(-32602),
                        message: format!("Invalid arguments: {}", e).into(),
                        data: None,
                    })?;

                match self.proc_mon.read_cgroup(&args.path) {
                    Some(cgroup) => Ok(CallToolResult {
                        content: vec![Annotated {
                            raw: RawContent::Text(RawTextContent {
                                text: serde_json::to_string_pretty(&cgroup).unwrap().into(),
                                meta: None,
                            }),
                            annotations: None,
                        }],
                        is_error: None,
                        meta: None,
                        structured_content: None,
                    }),
                    None => Err(ErrorData {
                        code: ErrorCode(-32002),
                        message: format!("Cgroup {} not found or failed to read", args.path).into(),
                        data: None,
                    }),
                }
            }
            _ => Err(ErrorData {
                code: ErrorCode(-32601),
                message: format!("Tool not found: {}", params.name).into(),
                data: None,
            }),
        }
    }

    async fn list_resources(
        &self,
        _params: Option<PaginatedRequestParam>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let resources = vec![
            Resource {
                annotations: None,
                raw: RawResource {
                    uri: "process://list".to_string().into(),
                    name: "Process List".to_string().into(),
                    description: Some("List of all processes".to_string().into()),
                    mime_type: Some("application/json".to_string().into()),
                    size: None,
                    meta: None,
                    icons: None,
                    title: None,
                },
            },
            Resource {
                annotations: None,
                raw: RawResource {
                    uri: "cgroup://list".to_string().into(),
                    name: "CGroup List".to_string().into(),
                    description: Some(
                        "List of all cgroups and their memory info"
                            .to_string()
                            .into(),
                    ),
                    mime_type: Some("application/json".to_string().into()),
                    size: None,
                    meta: None,
                    icons: None,
                    title: None,
                },
            },
        ];

        Ok(ListResourcesResult {
            resources,
            next_cursor: None,
            meta: None,
        })
    }

    async fn read_resource(
        &self,
        params: ReadResourceRequestParam,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        if params.uri == "process://list" {
            let processes = self.proc_mon.get_all_processes();
            Ok(ReadResourceResult {
                contents: vec![ResourceContents::TextResourceContents {
                    uri: params.uri,
                    mime_type: Some("application/json".to_string().into()),
                    text: serde_json::to_string(&processes).unwrap().into(),
                    meta: None,
                }],
            })
        } else if params.uri == "cgroup://list" {
            let cgroups = self.proc_mon.get_all_cgroups();
            Ok(ReadResourceResult {
                contents: vec![ResourceContents::TextResourceContents {
                    uri: params.uri,
                    mime_type: Some("application/json".to_string().into()),
                    text: serde_json::to_string(&cgroups).unwrap().into(),
                    meta: None,
                }],
            })
        } else {
            Err(ErrorData {
                code: ErrorCode(-32602),
                message: format!("Resource not found: {}", params.uri).into(),
                data: None,
            })
        }
    }
}

pub async fn run_stdio_server(proc_mon: Arc<ProcMon>) -> Result<(), Box<dyn std::error::Error>> {
    let handler = PmonMcpHandler::new(proc_mon);
    let transport = rmcp::transport::stdio();
    let service = handler.serve(transport).await?;
    service.waiting().await?;
    Ok(())
}

pub async fn run_uds_server(
    proc_mon: Arc<ProcMon>,
    path: &str,
    authorized_uid: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    info!("MCP UDS server listening on {}", path);

    // Set permissions to 0666 so other users can connect (we will verify UID anyway)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o666);
        std::fs::set_permissions(path, perms)?;
    }

    let current_uid = unsafe { libc::getuid() };

    loop {
        let (stream, _) = listener.accept().await?;
        let proc_mon_clone = proc_mon.clone();

        // Verify credentials
        let peer_cred = stream.peer_cred()?;
        let peer_uid = peer_cred.uid();

        let is_authorized = peer_uid == 0
            || peer_uid == current_uid
            || (authorized_uid.is_some() && authorized_uid == Some(peer_uid));

        if !is_authorized {
            error!("Unauthorized UDS connection from UID {}", peer_uid);
            continue;
        }

        tokio::spawn(async move {
            let handler = PmonMcpHandler::new(proc_mon_clone);
            let (read, write) = tokio::io::split(stream);
            match handler.serve((read, write)).await {
                Ok(service) => {
                    if let Err(e) = service.waiting().await {
                        error!("MCP UDS session error: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to start MCP UDS service: {}", e);
                }
            }
        });
    }
}
