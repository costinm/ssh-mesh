use axum::{
    Json, Router,
    extract::{Path, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{AppState, handlers::Assets};

fn pmond_socket_path() -> String {
    std::env::var("PMOND_UDS").unwrap_or_else(|_| {
        mesh::paths::AppPaths::for_app("pmond")
            .control_socket("pmond")
            .to_string_lossy()
            .into_owned()
    })
}

async fn call(method: &str, params: Value) -> impl IntoResponse {
    match crate::jsonl_proxy::call_jsonl(&pmond_socket_path(), method, params)
        .await
        .and_then(crate::jsonl_proxy::jsonl_response_payload)
    {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn serve_web(Path(path): Path<String>) -> impl IntoResponse {
    let path = format!("pmon/{}", path.trim_start_matches('/'));
    match Assets::get(&path) {
        Some(content) => {
            let mime = mime_guess::from_path(&path)
                .first_or_octet_stream()
                .to_string();
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, mime)],
                content.data.clone(),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

#[derive(Deserialize)]
struct CgroupQuery {
    path: String,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(|| async { Json(json!({"service": "pmond"})) }))
        .route("/web/*path", get(serve_web))
        .route("/_ps", get(|| call("ps", json!({}))))
        .route(
            "/_ps/:pid",
            get(|Path(pid): Path<u32>| call("process_only", json!({ "pid": pid }))),
        )
        .route(
            "/_process/:pid",
            get(|Path(pid): Path<u32>| call("process", json!({ "pid": pid }))),
        )
        .route(
            "/_cg",
            get(|Query(query): Query<CgroupQuery>| call("cgroup", json!({"path": query.path}))),
        )
        .route("/_cgroups", get(|| call("cgroups", json!({}))))
        .route("/_psi", get(|| call("psi", json!({}))))
        .route(
            "/_cgroup_high",
            post(|Json(payload): Json<Value>| call("cgroup_high", payload)),
        )
        .route(
            "/_cgroup_procs",
            post(|Json(payload): Json<Value>| call("cgroup_procs", payload)),
        )
        .route(
            "/_move_process",
            post(|Json(payload): Json<Value>| call("move_process", payload)),
        )
        .route(
            "/_clear_refs",
            post(|Json(payload): Json<Value>| call("clear_refs", payload)),
        )
        .route(
            "/_freeze_process",
            post(|Json(payload): Json<Value>| call("freeze_process", payload)),
        )
        .route(
            "/_freeze_cgroup",
            post(|Json(payload): Json<Value>| call("freeze_cgroup", payload)),
        )
}
