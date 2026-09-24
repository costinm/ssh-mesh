//! Optional MCP adapter over the protocol-neutral mesh service registry.

use std::future::Future;

use mesh::jsonl::ProtocolFormat;
use mesh::protocol::Response;
use mesh::registry::ServiceRegistry;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Dispatch MCP methods, translating `tools/call` into the worker's ordinary
/// typed handler. Non-MCP methods fall through to the common mesh dispatcher.
pub async fn dispatch_request<T, F, Fut>(
    trimmed: &str,
    registry: &ServiceRegistry,
    handler: F,
) -> (ProtocolFormat, Option<Response>)
where
    T: DeserializeOwned,
    F: Fn(T) -> Fut,
    Fut: Future<Output = Response>,
{
    let (format, raw) = mesh::jsonl::parse_raw_request(trimmed);
    let raw = match raw {
        Ok(raw) => raw,
        Err(error) => return (format, Some(Response::err(error))),
    };

    let response = match raw.method.as_str() {
        "initialize" => initialize(registry, &raw.params),
        "notifications/initialized" => return (format, None),
        "tools/list" => registry.tools().await,
        "resources/list" => registry.resources().await,
        "resources/read" => match raw.params.get("uri").and_then(Value::as_str) {
            Some(uri) => registry.read_resource(uri).await,
            None => Response::err("resources/read requires uri"),
        },
        "tools/call" => {
            let Some(name) = raw.params.get("name").and_then(Value::as_str) else {
                return (format, Some(Response::err("tools/call requires name")));
            };
            let service_prefix = format!("{}.", registry.name());
            let name = name.strip_prefix(&service_prefix).unwrap_or(name);
            let arguments = raw
                .params
                .get("arguments")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let mut direct = serde_json::Map::new();
            direct.insert("method".to_string(), json!(name));
            direct.extend(arguments);
            match serde_json::from_value::<T>(Value::Object(direct)) {
                Ok(request) => tool_response(handler(request).await),
                Err(error) => Response::err(format!("tools/call request mapping failed: {error}")),
            }
        }
        _ => return mesh::jsonl::dispatch_request(trimmed, registry, handler).await,
    };
    (format, Some(response))
}

fn initialize(registry: &ServiceRegistry, params: &serde_json::Map<String, Value>) -> Response {
    let requested = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or(PROTOCOL_VERSION);
    let protocol_version = if requested == PROTOCOL_VERSION {
        requested
    } else {
        PROTOCOL_VERSION
    };
    let mut result = json!({
        "protocolVersion": protocol_version,
        "capabilities": {
            "resources": { "listChanged": false },
            "tools": { "listChanged": false }
        },
        "serverInfo": {
            "name": registry.name(),
            "version": registry.version()
        }
    });
    if let Some(title) = registry.title() {
        result["serverInfo"]["title"] = json!(title);
    }
    if let Some(instructions) = registry.instructions() {
        result["instructions"] = json!(instructions);
    }
    Response::ok_with_data(result)
}

fn tool_response(response: Response) -> Response {
    if response.success {
        let structured = response.data.unwrap_or(Value::Null);
        Response::ok_with_data(json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string(&structured).unwrap_or_else(|_| "null".to_string())
            }],
            "structuredContent": structured,
            "isError": false
        }))
    } else {
        let error = response
            .error
            .unwrap_or_else(|| "tool call failed".to_string());
        Response::ok_with_data(json!({
            "content": [{ "type": "text", "text": error }],
            "isError": true
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(tag = "method")]
    enum Request {
        #[serde(rename = "echo")]
        Echo { value: String },
    }

    #[tokio::test]
    async fn initializes_as_mcp_only_when_adapter_is_used() {
        let registry = ServiceRegistry::new("worker");
        let (format, response) = dispatch_request::<Request, _, _>(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
            &registry,
            |_| async { Response::err("native handler called") },
        )
        .await;
        let encoded = mesh::jsonl::format_response(response.unwrap(), &format).unwrap();
        let value: Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(value["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(value["result"]["serverInfo"]["name"], "worker");
    }

    #[tokio::test]
    async fn maps_mcp_tool_call_to_native_handler() {
        let registry = ServiceRegistry::new("worker");
        let (_, response) = dispatch_request::<Request, _, _>(
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"worker.echo","arguments":{"value":"hello"}}}"#,
            &registry,
            |request| async move {
                match request {
                    Request::Echo { value } => Response::ok_with_data(json!({"echo": value})),
                }
            },
        )
        .await;
        let data = response.unwrap().data.unwrap();
        assert_eq!(data["structuredContent"]["echo"], "hello");
        assert_eq!(data["isError"], false);
    }
}
