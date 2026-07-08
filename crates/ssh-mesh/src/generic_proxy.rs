use axum::{
    Json, Router,
    extract::{Path, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{AppState, handlers::Assets};

#[derive(Debug, Deserialize)]
struct ProxyQuery {
    socket: Option<String>,
    tools: Option<String>,
}

fn app_socket_path(app: &str, explicit: Option<&str>) -> String {
    if let Some(socket) = explicit
        && !socket.is_empty()
    {
        return socket.to_string();
    }

    let env_name = format!("{}_UDS", app.to_uppercase().replace('-', "_"));
    if let Ok(socket) = std::env::var(env_name) {
        return socket;
    }

    if app == "mesh-init" {
        return mesh::paths::AppPaths::for_app("mesh-init")
            .mesh_socket()
            .to_string_lossy()
            .into_owned();
    }

    mesh::paths::AppPaths::for_app(app)
        .mesh_socket()
        .to_string_lossy()
        .into_owned()
}

async fn proxy_jsonl(
    Path(app): Path<String>,
    Query(query): Query<ProxyQuery>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    let socket = app_socket_path(&app, query.socket.as_deref());
    match crate::jsonl_proxy::call_jsonl_value(&socket, payload)
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

async fn proxy_json_rpc(
    Path(app): Path<String>,
    Query(query): Query<ProxyQuery>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    let Some(method) = payload.get("method").and_then(Value::as_str) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "JSON-RPC payload requires method"})),
        )
            .into_response();
    };
    let params = payload.get("params").cloned().unwrap_or_else(|| json!({}));
    let socket = app_socket_path(&app, query.socket.as_deref());
    match crate::jsonl_proxy::call_json_rpc(&socket, method, params)
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

async fn proxy_mcp(
    Path(app): Path<String>,
    Query(query): Query<ProxyQuery>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
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

    let mut registry = mesh::jsonl::McpRegistry::new(&app);
    if let Some(tools_path) = query.tools.as_deref()
        && let Some(asset) = Assets::get(tools_path.trim_start_matches('/'))
        && let Ok(tools) = serde_json::from_slice::<Value>(&asset.data)
    {
        registry = registry.with_tools_json(tools);
    }

    let socket = app_socket_path(&app, query.socket.as_deref());
    if payload
        .get("method")
        .and_then(Value::as_str)
        .map(mesh::message::canonical_method_name)
        .as_deref()
        == Some("tools/call")
    {
        let params = payload.get("params").cloned().unwrap_or_else(|| json!({}));
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "tools/call requires name"})),
            )
                .into_response();
        };
        let name = mesh::message::canonical_method_name(name);
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        return match crate::jsonl_proxy::call_json_rpc(&socket, &name, arguments)
            .await
            .and_then(crate::jsonl_proxy::jsonl_response_payload)
        {
            Ok(value) => (
                StatusCode::OK,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": payload.get("id").cloned().unwrap_or(Value::Null),
                    "result": {
                        "content": [{ "type": "text", "text": value.to_string() }],
                        "structuredContent": value,
                        "isError": false
                    }
                })),
            )
                .into_response(),
            Err(e) => (
                StatusCode::OK,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": payload.get("id").cloned().unwrap_or(Value::Null),
                    "result": {
                        "content": [{ "type": "text", "text": e.to_string() }],
                        "isError": true
                    }
                })),
            )
                .into_response(),
        };
    }

    let (format, response) = mesh::jsonl::dispatch_request::<GenericMcpRequest, _, _>(
        &line,
        &registry,
        move |request| {
            let socket = socket.clone();
            async move {
                match request {
                    GenericMcpRequest::JsonlCall {
                        method_name,
                        params,
                    } => {
                        let method_name = mesh::message::canonical_method_name(&method_name);
                        match crate::jsonl_proxy::call_json_rpc(&socket, &method_name, params)
                            .await
                            .and_then(crate::jsonl_proxy::jsonl_response_payload)
                        {
                            Ok(value) => mesh::protocol::Response::ok_with_data(value),
                            Err(e) => mesh::protocol::Response::err(e.to_string()),
                        }
                    }
                }
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "method")]
enum GenericMcpRequest {
    #[serde(rename = "jsonl_call")]
    JsonlCall {
        method_name: String,
        #[serde(default)]
        params: Value,
    },
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/jsonl/:app", post(proxy_jsonl))
        .route("/jsonrpc/:app", post(proxy_json_rpc))
        .route("/mcp/:app", post(proxy_mcp))
}
