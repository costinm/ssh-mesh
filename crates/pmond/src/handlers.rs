use crate::methods::{call_method, METHODS};
use crate::ProcMon;
use axum::{
    extract::{Path as AxumPath, State},
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use hyper::StatusCode;
use log::debug;
use rust_embed::RustEmbed;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;
// MCP Imports
use crate::psi::{PressureData, PressureEvent, PressureInfo, PressureType};
use crate::{
    CgroupHighArgs, ClearRefsArgs, GetCgroupArgs, GetProcessArgs, ListCgroupsArgs,
    ListProcessesArgs, MoveProcessArgs, CGroupInfo, ProcMemInfo, ProcessDetailedInfo, ProcessInfo, PsiWatchesArgs,
};
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
use tokio::net::UnixListener;
use tracing::{error, info};
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

#[derive(RustEmbed)]
#[folder = "web/"]
pub struct Assets;

#[derive(Clone)]
pub struct AppState {
    pub proc_mon: Arc<ProcMon>,
}

// ============================================================================
// HTTP Handlers (delegating to unified methods)
// ============================================================================

/// HTTP response helper that wraps method results
fn method_response(
    result: Result<Value, crate::methods::MethodError>,
) -> (StatusCode, Json<Value>) {
    match result {
        Ok(v) => (StatusCode::OK, Json(v)),
        Err(e) => {
            let status = match e.code {
                -32602 => StatusCode::BAD_REQUEST,     // Invalid params
                -32601 => StatusCode::NOT_FOUND,       // Method not found
                -32001 => StatusCode::NOT_FOUND,       // Resource not found
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            info!("Method error: {} (code: {}, status: {})", e.message, e.code, status);
            (
                status,
                Json(json!({"error": e.message, "code": e.code})),
            )
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        handle_ps_request,
        handle_get_process_request,
        handle_cgroups_request,
        handle_psi_request,
        handle_cgroup_high_request,
        handle_cgroup_procs_request,
        handle_move_process_request,
        handle_clear_refs_request
    ),
    components(
        schemas(
            ProcessInfo, ProcessDetailedInfo, CGroupInfo, ProcMemInfo, CgroupProcsPayload,
            ListProcessesArgs, GetProcessArgs, ListCgroupsArgs, GetCgroupArgs,
            MoveProcessArgs, ClearRefsArgs, CgroupHighArgs, PsiWatchesArgs,
            PressureInfo, PressureData, PressureEvent, PressureType
        )
    ),
    tags(
        (name = "pmond", description = "Process Memory Monitor API")
    )
)]
pub struct ApiDoc;

#[utoipa::path(
    get,
    path = "/_m/pmon/_ps",
    tag = "pmond",
    responses(
        (status = 200, 
        description = "List processes and return detailed memory info", 
        body = Vec<ProcessInfo>)
    )
)]
pub async fn handle_ps_request(
    State(app_state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    info!("Received list_processes request");
    method_response(call_method(
        &app_state.proc_mon,
        "list_processes",
        json!({}),
    ))
}

#[utoipa::path(
    get,
    path = "/_m/pmon/_process/{pid}",
    tag = "pmond",
    params(
        ("pid" = String, Path, description = "Process ID")
    ),
    responses(
        (status = 200, description = "Get detailed process info with cgroup hierarchy", body = ProcessDetailedInfo),
        (status = 404, description = "Process not found")
    )
)]
pub async fn handle_get_process_request(
    State(app_state): State<AppState>,
    AxumPath(pid): AxumPath<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    debug!("Received get_process request for PID: {}", pid);
    method_response(call_method(
        &app_state.proc_mon,
        "get_process",
        json!({"process": pid}),
    ))
}

#[utoipa::path(
    get,
    path = "/_m/pmon/_cgroups",
    tag = "pmond",
    responses(
        (status = 200, description = "List all cgroups", body = HashMap<String, ProcMemInfo>)
    )
)]
pub async fn handle_cgroups_request(
    State(app_state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    method_response(call_method(&app_state.proc_mon, "list_cgroups", json!({})))
}

#[utoipa::path(
    get,
    path = "/_m/pmon/_psi",
    tag = "pmond",
    responses(
        (status = 200, description = "Get PSI watches", body = HashMap<String, PressureInfo>)
    )
)]
pub async fn handle_psi_request(
    State(app_state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    method_response(call_method(&app_state.proc_mon, "psi_watches", json!({})))
}

#[utoipa::path(
    post,
    path = "/_m/pmon/_cgroup_high",
    tag = "pmond",
    request_body = CgroupHighArgs,
    responses(
        (status = 200, description = "Adjust memory.high")
    )
)]
pub async fn handle_cgroup_high_request(
    State(app_state): State<AppState>,
    Json(payload): Json<Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    info!("Received CGroup High request: {}", payload);
    method_response(call_method(&app_state.proc_mon, "cgroup_high", payload))
}

#[derive(Deserialize, Debug, ToSchema)]
pub struct CgroupProcsPayload {
    pub path: String,
}

#[utoipa::path(
    post,
    path = "/_m/pmon/_cgroup_procs",
    tag = "pmond",
    request_body = CgroupProcsPayload,
    responses(
        (status = 200, description = "Get processes in cgroup", body = Vec<ProcessInfo>)
    )
)]
pub async fn handle_cgroup_procs_request(
    State(app_state): State<AppState>,
    Json(payload): Json<CgroupProcsPayload>,
) -> (StatusCode, Json<serde_json::Value>) {
    debug!("Received CGroup Procs request for {}", payload.path);
    // This one isn't in the methods registry - it's a specialized query
    let processes = app_state.proc_mon.get_processes_in_cgroup(&payload.path);
    (StatusCode::OK, Json(json!(processes)))
}

#[utoipa::path(
    post,
    path = "/_m/pmon/_move_process",
    tag = "pmond",
    request_body = MoveProcessArgs,
    responses(
        (status = 200, description = "Move process to cgroup")
    )
)]
pub async fn handle_move_process_request(
    State(app_state): State<AppState>,
    Json(payload): Json<Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    debug!("Received Move Process request: {:?}", payload);
    method_response(call_method(&app_state.proc_mon, "move_process", payload))
}

#[utoipa::path(
    post,
    path = "/_m/pmon/_clear_refs",
    tag = "pmond",
    request_body = ClearRefsArgs,
    responses(
        (status = 200, description = "Clear process refs")
    )
)]
pub async fn handle_clear_refs_request(
    State(app_state): State<AppState>,
    Json(payload): Json<Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    debug!("Received Clear Refs request: {:?}", payload);
    method_response(call_method(&app_state.proc_mon, "clear_refs", payload))
}

// ============================================================================
// Static Pages
// ============================================================================

pub async fn handle_root_request(_state: State<AppState>) -> Html<String> {
    Html(format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head><title>PMOND</title></head>
        <body>
            <h1>PMOND - Process Monitor</h1>
            <p><a href='/_m/pmon/web/pmon.html'>Process Monitor</a></p>
            <p><a href='/_m/pmon/web/cgmon.html'>CGroup Monitor</a></p>
            <p><a href='/_m/pmon/_ps'>Process API</a></p>
            <p><a href='/_m/pmon/_cgroups'>CGroups API</a></p>
        <p><a href='/_m/pmon/_psi'>PSI Watches API</a></p>
            <p><a href='/_m/pmon/swagger-ui/'>Swagger UI</a></p>
        </body>
        </html>
    "#
    ))
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

// ============================================================================
// Router Setup
// ============================================================================

pub fn app(proc_mon: Arc<ProcMon>) -> Router {
    let app_state = AppState {
        proc_mon: proc_mon.clone(),
    };

    Router::new()
        .route("/_m/pmon/", get(handle_root_request))
        .route("/_m/pmon/_ps", get(handle_ps_request))
        .route("/_m/pmon/_process/:pid", get(handle_get_process_request))
        .route("/_m/pmon/_cgroups", get(handle_cgroups_request))
        .route("/_m/pmon/_psi", get(handle_psi_request))
        .route("/_m/pmon/_cgroup_high", post(handle_cgroup_high_request))
        .route("/_m/pmon/_cgroup_procs", post(handle_cgroup_procs_request))
        .route("/_m/pmon/_move_process", post(handle_move_process_request))
        .route("/_m/pmon/_clear_refs", post(handle_clear_refs_request))
        .route(
            "/_m/pmon/api-docs/openapi.json",
            get(|| async { Json(ApiDoc::openapi()) }),
        )
        .route("/_m/pmon/web/*path", get(handle_web_request))
        .nest_service("/_m/pmon/mcp", mcp_service(proc_mon))
        .with_state(app_state)
        .merge(
            SwaggerUi::new("/_m/pmon/swagger-ui").config(utoipa_swagger_ui::Config::new([
                utoipa_swagger_ui::Url::with_primary(
                    "pmond",
                    "/_m/pmon/api-docs/openapi.json",
                    true,
                ),
            ])),
        )
}

// ============================================================================
// MCP Implementation (using unified methods)
// ============================================================================

/// MCP handler for the Process Memory monitor.
#[derive(Clone)]
pub struct PmonMcpHandler {
    proc_mon: Arc<ProcMon>,
}

impl PmonMcpHandler {
    pub fn new(proc_mon: Arc<ProcMon>) -> Self {
        Self { proc_mon }
    }
}

/// Handles the MCP streamable protocol - streaming events and json-rpc 
/// calls. This is backed by a local session manager - will not work well
/// with a load balancer without sticky sessions or some other routing to
/// a specific host, which makes sense since the process is specific to a host.
///
/// It is likely better to use a H2 stream using the stdio protocol - and have the
/// load balancers and some external box handle the strange MCP HTTP/1.1 protocol.
/// 
/// Even better to use a local stdio server that tunnels over SSH or H2 to
/// the server-stdio server.
pub fn mcp_service(proc_mon: Arc<ProcMon>) -> StreamableHttpService<PmonMcpHandler> {
    let config = StreamableHttpServerConfig::default();
    let session_manager = Arc::new(LocalSessionManager::default());

    StreamableHttpService::new(
        move || Ok(PmonMcpHandler::new(proc_mon.clone())),
        session_manager,
        config,
    )
}

/// Handles the MCP STDIO protocol.
pub async fn run_stdio_server(proc_mon: Arc<ProcMon>) -> Result<(), Box<dyn std::error::Error>> {
    let handler = PmonMcpHandler::new(proc_mon);
    let transport = rmcp::transport::stdio();
    let service = handler.serve(transport).await?;
    service.waiting().await?;
    Ok(())
}


/// Helper to convert Value to input_schema type (Arc<Map<String, Value>>)
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
        // Generate tool list from unified METHODS registry
        let tools: Vec<Tool> = METHODS
            .iter()
            .map(|m| Tool {
                name: m.name.to_string().into(),
                description: Some(m.description.to_string().into()),
                input_schema: to_schema((m.schema_fn)()),
                annotations: None,
                icons: None,
                meta: None,
                title: None,
                output_schema: None,
            })
            .collect();

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
        // Dispatch to unified method registry
        let args = Value::Object(params.arguments.unwrap_or_default());
        match call_method(&self.proc_mon, params.name.as_ref(), args) {
            Ok(result) => {
                let text = serde_json::to_string_pretty(&result).unwrap_or_default();
                Ok(CallToolResult {
                    content: vec![Annotated {
                        raw: RawContent::Text(RawTextContent {
                            text: text.into(),
                            meta: None,
                        }),
                        annotations: None,
                    }],
                    is_error: None,
                    meta: None,
                    structured_content: None,
                })
            }
            Err(e) => Err(ErrorData {
                code: ErrorCode(e.code),
                message: e.message.into(),
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
        // Use method registry for resource reads too
        let method_name = if params.uri == "process://list" {
            "list_processes"
        } else if params.uri == "cgroup://list" {
            "list_cgroups"
        } else {
            return Err(ErrorData {
                code: ErrorCode(-32602),
                message: format!("Resource not found: {}", params.uri).into(),
                data: None,
            });
        };

        match call_method(&self.proc_mon, method_name, json!({})) {
            Ok(result) => Ok(ReadResourceResult {
                contents: vec![ResourceContents::TextResourceContents {
                    uri: params.uri,
                    mime_type: Some("application/json".to_string().into()),
                    text: serde_json::to_string(&result).unwrap().into(),
                    meta: None,
                }],
            }),
            Err(e) => Err(ErrorData {
                code: ErrorCode(e.code),
                message: e.message.into(),
                data: None,
            }),
        }
    }
}

// ============================================================================
// Server Functions
// ============================================================================

/// Run a HTTP server over UDS - to avoid opening a port (security).
/// 
/// The SSH server can forard local ports to UDS, safer and simpler.
pub async fn run_uds_http_server(
    proc_mon: Arc<ProcMon>,
    path: &str,
    authorized_uid: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    info!("HTTP UDS server listening on {}", path);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o666);
        std::fs::set_permissions(path, perms)?;
    }

    let current_uid = unsafe { libc::getuid() };
    let app = app(proc_mon);

    loop {
        let (stream, _) = listener.accept().await?;
        let peer_cred = stream.peer_cred()?;
        let peer_uid = peer_cred.uid();

        let is_authorized = peer_uid == 0
            || peer_uid == current_uid
            || (authorized_uid.is_some() && authorized_uid == Some(peer_uid));

        if !is_authorized {
            error!("Unauthorized UDS HTTP connection from UID {}", peer_uid);
            continue;
        }

        let app_clone = app.clone();
        tokio::spawn(async move {
            use hyper_util::rt::TokioIo;
            use hyper_util::service::TowerToHyperService;
            let io = TokioIo::new(stream);
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, TowerToHyperService::new(app_clone))
                .with_upgrades()
                .await
            {
                error!("Error serving UDS HTTP connection: {:?}", err);
            }
        });
    }
}

pub async fn run_uds_mcp_server(
    proc_mon: Arc<ProcMon>,
    path: &str,
    authorized_uid: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    info!("MCP Stream UDS server listening on {}", path);

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
        let peer_cred = stream.peer_cred()?;
        let peer_uid = peer_cred.uid();

        let is_authorized = peer_uid == 0
            || peer_uid == current_uid
            || (authorized_uid.is_some() && authorized_uid == Some(peer_uid));

        if !is_authorized {
            error!("Unauthorized UDS MCP connection from UID {}", peer_uid);
            continue;
        }

        tokio::spawn(async move {
            let handler = PmonMcpHandler::new(proc_mon_clone);
            let (read, write) = tokio::io::split(stream);
            if let Err(e) = handler.serve((read, write)).await {
                error!("Failed to start MCP UDS service: {}", e);
            } else {
                info!("MCP session started for UID {}", peer_uid);
            }
        });
    }
}
