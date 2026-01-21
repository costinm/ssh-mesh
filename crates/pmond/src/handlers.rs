use crate::ProcMon;
use axum::{
    extract::State,
    response::{Html, IntoResponse, Json},
    routing::{delete, get, post},
    Router,
};
use hyper::StatusCode;
use log::debug;
use rust_embed::RustEmbed;
use serde_json::json;
use std::path::Path;
use std::sync::Arc;
use ws::WSServer;

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

pub async fn handle_root_request() -> Html<&'static str> {
    Html(
        r#"
        <!DOCTYPE html>
        <html>
        <head><title>PMOND</title></head>
        <body>
            <h1>PMOND - Process Monitor</h1>
            <p><a href='/web/pmon.html'>Process Monitor</a></p>
            <p><a href='/web/chat.html'>Chat</a></p>
            <p><a href='/_ps'>Process API</a></p>
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
    axum::extract::Path(path): axum::extract::Path<String>,
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
        .nest_service("/mcp", crate::mcp::mcp_service(proc_mon))
        .with_state(app_state)
}
