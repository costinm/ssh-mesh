//! Re-export core trace types from mesh crate, plus HTTP-specific handlers.
//!
//! The core trace infrastructure (LogBuffer, LogEntry, TraceConfig, UDS listener, etc.)
//! now lives in the `mesh::local_trace` module. This module re-exports those types
//! for backward compatibility and adds HTTP/axum-specific handlers.

pub use mesh::local_trace::*;

use axum::{
    http::StatusCode,
    response::{
        IntoResponse, Json,
        sse::{Event, KeepAlive, Sse},
    },
};
use futures_util::stream::{self, Stream};
use std::convert::Infallible;

/// HTTP handler: GET trace level
pub async fn trace_get_level() -> impl IntoResponse {
    let resp = mesh::local_trace::get_trace_level();
    (StatusCode::OK, Json(resp))
}

/// HTTP handler: PUT trace level
pub async fn trace_set_level(Json(req): Json<TraceLevelRequest>) -> impl IntoResponse {
    match mesh::local_trace::set_trace_level(&req) {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(resp) => {
            // Determine status code based on the error message
            let status = if resp
                .message
                .as_deref()
                .map_or(false, |m| m.starts_with("Invalid"))
            {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, Json(resp)).into_response()
        }
    }
}

/// HTTP handler: SSE stream of log entries
pub async fn stream_logs_sse(
    buffer: LogBuffer,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = buffer.subscribe();

    // Get existing logs
    let existing = buffer.get_all();

    let stream = stream::unfold(
        (existing.into_iter(), rx),
        |(mut existing, mut rx)| async move {
            if let Some(entry) = existing.next() {
                if let Ok(json) = serde_json::to_string(&entry) {
                    return Some((Ok(Event::default().data(json)), (existing, rx)));
                }
            }

            match rx.recv().await {
                Ok(entry) => {
                    if let Ok(json) = serde_json::to_string(&entry) {
                        Some((Ok(Event::default().data(json)), (existing, rx)))
                    } else {
                        None
                    }
                }
                Err(_) => None,
            }
        },
    );

    Sse::new(stream).keep_alive(KeepAlive::default())
}
