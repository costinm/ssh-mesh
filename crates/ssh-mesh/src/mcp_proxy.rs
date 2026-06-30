use axum::{Json, Router, http::StatusCode, response::IntoResponse, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method")]
enum SshMeshMcpRequest {
    #[serde(rename = "jsonl_call")]
    JsonlCall {
        socket_path: String,
        method_name: String,
        #[serde(default)]
        params: Value,
    },
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/", post(handle_mcp_json_rpc))
}

async fn handle_mcp_json_rpc(Json(payload): Json<Value>) -> impl IntoResponse {
    let line = match serde_json::to_string(&payload) {
        Ok(line) => line,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid JSON-RPC payload: {e}")})),
            )
                .into_response();
        }
    };
    let registry = mesh::jsonl::McpRegistry::new("ssh-mesh");
    let (format, response) = mesh::jsonl::dispatch_request::<SshMeshMcpRequest, _, _>(
        &line,
        &registry,
        |request| async {
            match request {
                SshMeshMcpRequest::JsonlCall {
                    socket_path,
                    method_name,
                    params,
                } => match crate::jsonl_proxy::call_json_rpc(&socket_path, &method_name, params)
                    .await
                    .and_then(crate::jsonl_proxy::jsonl_response_payload)
                {
                    Ok(value) => mesh::protocol::Response::ok_with_data(value),
                    Err(e) => mesh::protocol::Response::err(e.to_string()),
                },
            }
        },
    )
    .await;

    let Some(response) = response else {
        return StatusCode::NO_CONTENT.into_response();
    };
    match mesh::jsonl::format_response(response, &format)
        .ok()
        .and_then(|line| serde_json::from_str::<Value>(&line).ok())
    {
        Some(value) => (StatusCode::OK, Json(value)).into_response(),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to format JSON-RPC response"})),
        )
            .into_response(),
    }
}
