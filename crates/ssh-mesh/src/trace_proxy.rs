use axum::{
    Json, Router,
    extract::Path,
    http::StatusCode,
    response::{
        Html, IntoResponse,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use mesh::local_trace::{
    TraceLevelRequest, get_trace_level, global_buffer, set_trace_event_info, set_trace_level,
    trace_event_stats,
};
use serde::Deserialize;
use serde_json::json;
use std::convert::Infallible;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::{AppState, handlers::Assets};

async fn serve_index() -> impl IntoResponse {
    match Assets::get("trace/trace_viewer.html") {
        Some(content) => Html(String::from_utf8_lossy(&content.data).into_owned()).into_response(),
        None => (StatusCode::NOT_FOUND, "trace viewer not found").into_response(),
    }
}

async fn serve_web(Path(path): Path<String>) -> impl IntoResponse {
    let path = format!("trace/{}", path.trim_start_matches('/'));
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
struct TraceLevelBody {
    level: String,
}

#[derive(Deserialize)]
struct TraceEventBody {
    enabled: bool,
}

async fn handle_get_level() -> impl IntoResponse {
    let resp = get_trace_level();
    (StatusCode::OK, Json(json!(resp)))
}

async fn handle_set_level(Json(body): Json<TraceLevelBody>) -> impl IntoResponse {
    let req = TraceLevelRequest { level: body.level };
    match set_trace_level(&req) {
        Ok(resp) => (StatusCode::OK, Json(json!(resp))).into_response(),
        Err(resp) => (StatusCode::BAD_REQUEST, Json(json!(resp))).into_response(),
    }
}

async fn handle_get_events() -> impl IntoResponse {
    Json(json!({ "events": trace_event_stats() }))
}

/// Bounded snapshot for clients which cannot keep an SSE connection alive
/// through a reverse proxy or an SSH forward.
async fn handle_get_entries() -> impl IntoResponse {
    let entries = global_buffer()
        .map(|buffer| buffer.get_all())
        .unwrap_or_default();
    Json(json!({ "entries": entries }))
}

async fn handle_set_event(
    Path(name): Path<String>,
    Json(body): Json<TraceEventBody>,
) -> impl IntoResponse {
    match set_trace_event_info(&name, body.enabled) {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({ "name": name, "enabled": body.enabled })),
        )
            .into_response(),
        Err(message) => {
            (StatusCode::BAD_REQUEST, Json(json!({ "message": message }))).into_response()
        }
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(serve_index))
        .route("/web/*path", get(serve_web))
        .route(
            "/level",
            get(handle_get_level)
                .put(handle_set_level)
                .post(handle_set_level),
        )
        .route(
            "/api/level",
            get(handle_get_level)
                .put(handle_set_level)
                .post(handle_set_level),
        )
        .route(
            "/api/sources/:name/level",
            post(|Json(body): Json<TraceLevelBody>| handle_set_level(Json(body))),
        )
        .route("/api/events", get(handle_get_events))
        .route("/api/events/:name", post(handle_set_event))
        .route("/api/entries", get(handle_get_entries))
        .route("/api/stream", get(stream_sse))
}

async fn stream_sse() -> Sse<ReceiverStream<Result<Event, Infallible>>> {
    let (tx, rx) = mpsc::channel(64);
    tokio::spawn(async move {
        if let Some(buffer) = global_buffer() {
            let existing = buffer.get_all();
            for entry in existing {
                if let Ok(data) = serde_json::to_string(&entry) {
                    if tx.send(Ok(Event::default().data(data))).await.is_err() {
                        return;
                    }
                }
            }
            let mut rx = buffer.subscribe();
            while let Ok(entry) = rx.recv().await {
                if let Ok(data) = serde_json::to_string(&entry) {
                    if tx.send(Ok(Event::default().data(data))).await.is_err() {
                        break;
                    }
                }
            }
        } else {
            let _ = tx
                .send(Ok(Event::default()
                    .event("error")
                    .data("global log buffer not initialized")))
                .await;
        }
    });

    Sse::new(ReceiverStream::new(rx)).keep_alive(KeepAlive::default())
}
