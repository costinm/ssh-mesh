use axum::{
    Json, Router,
    extract::{Path, Query},
    http::StatusCode,
    response::{
        Html, IntoResponse,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::convert::Infallible;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::{AppState, handlers::Assets};

fn traceweb_socket_path() -> String {
    std::env::var("TRACEWEB_UDS").unwrap_or_else(|_| {
        mesh::paths::AppPaths::for_app("traceweb")
            .control_socket("traceweb")
            .to_string_lossy()
            .into_owned()
    })
}

async fn call(method: &str, params: Value) -> impl IntoResponse {
    match crate::jsonl_proxy::call_json_rpc(&traceweb_socket_path(), method, params)
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
struct ConnectQuery {
    name: String,
    path: Option<String>,
}

#[derive(Deserialize)]
struct StreamQuery {
    sources: Option<String>,
}

#[derive(Deserialize)]
struct TraceLevelBody {
    level: String,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(serve_index))
        .route("/web/*path", get(serve_web))
        .route("/api/discover", get(|| call("discover", json!({}))))
        .route("/api/sources", get(|| call("sources", json!({}))))
        .route(
            "/api/sources/connect",
            get(|Query(query): Query<ConnectQuery>| {
                call(
                    "connect_source",
                    json!({ "name": query.name, "path": query.path }),
                )
            }),
        )
        .route(
            "/api/sources/disconnect",
            get(|Query(query): Query<ConnectQuery>| {
                call("disconnect_source", json!({ "name": query.name }))
            }),
        )
        .route(
            "/api/sources/:name/level",
            post(
                |Path(name): Path<String>, Json(body): Json<TraceLevelBody>| {
                    call(
                        "set_source_level",
                        json!({ "name": name, "level": body.level }),
                    )
                },
            ),
        )
        .route("/api/stream", get(stream_sse))
}

async fn stream_sse(
    Query(query): Query<StreamQuery>,
) -> Sse<ReceiverStream<Result<Event, Infallible>>> {
    let (tx, rx) = mpsc::channel(64);
    tokio::spawn(async move {
        if let Err(e) = forward_trace_notifications(query.sources, tx.clone()).await {
            let _ = tx
                .send(Ok(Event::default().event("error").data(e.to_string())))
                .await;
        }
    });

    Sse::new(ReceiverStream::new(rx)).keep_alive(KeepAlive::default())
}

async fn forward_trace_notifications(
    sources: Option<String>,
    tx: mpsc::Sender<Result<Event, Infallible>>,
) -> anyhow::Result<()> {
    let stream = UnixStream::connect(traceweb_socket_path()).await?;
    let mut stream = BufReader::new(stream);
    let sources = sources
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|sources| !sources.is_empty());
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "subscribe",
        "params": { "sources": sources },
    });
    let line = serde_json::to_vec(&request)?;
    stream.get_mut().write_all(&line).await?;
    stream.get_mut().write_all(b"\n").await?;
    stream.get_mut().flush().await?;

    let mut line = String::new();
    loop {
        line.clear();
        let read = stream.read_line(&mut line).await?;
        if read == 0 {
            break;
        }
        let value: Value = match serde_json::from_str(line.trim()) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if value.get("method").and_then(Value::as_str) != Some("trace_entry") {
            continue;
        }
        let payload = value.get("params").cloned().unwrap_or(Value::Null);
        let data = serde_json::to_string(&payload)?;
        if tx.send(Ok(Event::default().data(data))).await.is_err() {
            break;
        }
    }

    Ok(())
}
