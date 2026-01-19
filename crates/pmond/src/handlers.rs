use crate::ProcMon;
use axum::{
    extract::State,
    response::{Html, Json},
    routing::{delete, get, post},
    Router,
};
use hyper::StatusCode;
use log::debug;
use serde_json::json;
use std::sync::Arc;
use tower_http::services::ServeDir;
use ws::WSServer;

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

pub fn app(proc_mon: Arc<ProcMon>, ws_server: Arc<WSServer>) -> Router {
    let app_state = AppState {
        proc_mon,
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
        .nest_service("/web", ServeDir::new("web"))
        .with_state(app_state)
}
