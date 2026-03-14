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
use serde_json::json;
use std::path::Path;
use std::sync::Arc;
use tokio::net::UnixListener;
use tracing::{error, info};
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

use crate::psi::{PressureData, PressureEvent, PressureInfo, PressureType};
use crate::{
    CGroupInfo, CgroupHighArgs, ClearRefsArgs, FreezeCgroupArgs, FreezeProcessArgs,
    GetCgroupArgs, GetProcessArgs, ListCgroupsArgs, ListProcessesArgs, MoveProcessArgs,
    ProcMemInfo, ProcessDetailedInfo, ProcessInfo, PsiWatchesArgs,
};

#[derive(RustEmbed)]
#[folder = "web/"]
pub struct Assets;

#[derive(Clone)]
pub struct AppState {
    pub proc_mon: Arc<ProcMon>,
}

// ============================================================================
// HTTP Handlers (with inline method logic)
// ============================================================================

#[derive(OpenApi)]
#[openapi(
    paths(
        handle_ps_request,
        handle_get_process_request,
        handle_get_process_only_request,
        handle_get_cgroup_detailed_request,
        handle_cgroups_request,
        handle_psi_request,
        handle_cgroup_high_request,
        handle_cgroup_procs_request,
        handle_move_process_request,
        handle_clear_refs_request,
        handle_freeze_process_request,
        handle_freeze_cgroup_request
    ),
    components(
        schemas(
            ProcessInfo, ProcessDetailedInfo, CGroupInfo, ProcMemInfo, CgroupProcsPayload,
            ListProcessesArgs, GetProcessArgs, ListCgroupsArgs, GetCgroupArgs,
            MoveProcessArgs, ClearRefsArgs, CgroupHighArgs, PsiWatchesArgs,
            PressureInfo, PressureData, PressureEvent, PressureType,
            FreezeProcessArgs, FreezeCgroupArgs
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
    let processes = app_state.proc_mon.get_all_processes(1);
    let process_list: Vec<&ProcessInfo> = processes.values().collect();
    (StatusCode::OK, Json(json!(process_list)))
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

    let pid: u32 = match pid.parse() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("Invalid PID: {}", pid)})),
            )
        }
    };

    match app_state.proc_mon.get_process(pid) {
        Some(process) => {
            let cgroup = process
                .cgroup_path
                .as_ref()
                .and_then(|p| crate::read_cgroup_detailed(p));

            let parent_cgroups = process
                .cgroup_path
                .as_ref()
                .map(|p| crate::get_parent_cgroups(p))
                .unwrap_or_default();

            let detailed_info = ProcessDetailedInfo {
                process,
                cgroup,
                parent_cgroups,
            };

            (StatusCode::OK, Json(json!(detailed_info)))
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("Process {} not found", pid)})),
        ),
    }
}

#[utoipa::path(
    get,
    path = "/_m/pmon/_ps/{pid}",
    tag = "pmond",
    params(
        ("pid" = u32, Path, description = "Process ID")
    ),
    responses(
        (status = 200, description = "Get process info only", body = ProcessInfo),
        (status = 404, description = "Process not found")
    )
)]
pub async fn handle_get_process_only_request(
    State(app_state): State<AppState>,
    AxumPath(pid): AxumPath<u32>,
) -> (StatusCode, Json<serde_json::Value>) {
    match app_state.proc_mon.get_process(pid) {
        Some(process) => (StatusCode::OK, Json(json!(process))),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("Process {} not found", pid)})),
        ),
    }
}

#[derive(Deserialize)]
pub struct GetCgroupQuery {
    pub path: String,
}

#[utoipa::path(
    get,
    path = "/_m/pmon/_cg",
    tag = "pmond",
    params(
        ("path" = String, Query, description = "Full cgroup path")
    ),
    responses(
        (status = 200, description = "Get detailed cgroup info", body = CGroupInfo),
        (status = 404, description = "Cgroup not found")
    )
)]
pub async fn handle_get_cgroup_detailed_request(
    State(_app_state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<GetCgroupQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    match crate::read_cgroup_detailed(&query.path) {
        Some(cgroup) => (StatusCode::OK, Json(json!(cgroup))),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("Cgroup {} not found", query.path)})),
        ),
    }
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
    let cgroups = app_state.proc_mon.get_all_cgroups();
    (StatusCode::OK, Json(json!(cgroups)))
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
    let watches = app_state.proc_mon.get_psi_watches();
    (StatusCode::OK, Json(json!(watches)))
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
    Json(payload): Json<CgroupHighArgs>,
) -> (StatusCode, Json<serde_json::Value>) {
    info!(
        "Received CGroup High request: path={} percentage={} interval={}",
        payload.path, payload.percentage, payload.interval
    );

    match app_state
        .proc_mon
        .adjust_cgroup_memory_high(payload.path, payload.percentage, payload.interval)
    {
        Ok(()) => (StatusCode::OK, Json(json!({"status": "ok"}))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ),
    }
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
    Json(payload): Json<MoveProcessArgs>,
) -> (StatusCode, Json<serde_json::Value>) {
    debug!(
        "Received Move Process request: pid={} cgroup={:?}",
        payload.pid, payload.cgroup_name
    );

    match app_state
        .proc_mon
        .move_process_to_cgroup(payload.pid, payload.cgroup_name)
    {
        Ok(()) => (StatusCode::OK, Json(json!({"status": "ok"}))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ),
    }
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
    Json(payload): Json<ClearRefsArgs>,
) -> (StatusCode, Json<serde_json::Value>) {
    debug!(
        "Received Clear Refs request: pid={} value={}",
        payload.pid, payload.value
    );

    match app_state.proc_mon.clear_refs(payload.pid, &payload.value) {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "message": format!("Cleared refs for process {} with value {}", payload.pid, payload.value)
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

#[utoipa::path(
    post,
    path = "/_m/pmon/_freeze_process",
    tag = "pmond",
    request_body = FreezeProcessArgs,
    responses(
        (status = 200, description = "Freeze or unfreeze a process by sending SIGSTOP/SIGCONT")
    )
)]
pub async fn handle_freeze_process_request(
    State(app_state): State<AppState>,
    Json(payload): Json<FreezeProcessArgs>,
) -> (StatusCode, Json<serde_json::Value>) {
    let action = if payload.freeze { "freeze" } else { "unfreeze" };
    info!("Received {} request for PID: {}", action, payload.pid);

    match app_state.proc_mon.freeze_process(payload.pid, payload.freeze) {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "message": format!("Successfully {}d process {}", action, payload.pid)
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ),
    }
}

#[utoipa::path(
    post,
    path = "/_m/pmon/_freeze_cgroup",
    tag = "pmond",
    request_body = FreezeCgroupArgs,
    responses(
        (status = 200, description = "Freeze or unfreeze all processes in a cgroup via cgroup.freeze")
    )
)]
pub async fn handle_freeze_cgroup_request(
    State(app_state): State<AppState>,
    Json(payload): Json<FreezeCgroupArgs>,
) -> (StatusCode, Json<serde_json::Value>) {
    let action = if payload.freeze { "freeze" } else { "unfreeze" };
    info!("Received {} request for cgroup: {}", action, payload.path);

    match app_state.proc_mon.freeze_cgroup(&payload.path, payload.freeze) {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "message": format!("Successfully {}d cgroup {}", action, payload.path)
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        ),
    }
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
        .route("/_m/pmon/_ps/:pid", get(handle_get_process_only_request))
        .route("/_m/pmon/_process/:pid", get(handle_get_process_request))
        .route("/_m/pmon/_cg", get(handle_get_cgroup_detailed_request))
        .route("/_m/pmon/_cgroups", get(handle_cgroups_request))
        .route("/_m/pmon/_psi", get(handle_psi_request))
        .route("/_m/pmon/_cgroup_high", post(handle_cgroup_high_request))
        .route("/_m/pmon/_cgroup_procs", post(handle_cgroup_procs_request))
        .route("/_m/pmon/_move_process", post(handle_move_process_request))
        .route("/_m/pmon/_clear_refs", post(handle_clear_refs_request))
        .route("/_m/pmon/_freeze_process", post(handle_freeze_process_request))
        .route("/_m/pmon/_freeze_cgroup", post(handle_freeze_cgroup_request))
        .route(
            "/_m/pmon/api-docs/openapi.json",
            get(|| async { Json(ApiDoc::openapi()) }),
        )
        .route("/_m/pmon/web/*path", get(handle_web_request))
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
