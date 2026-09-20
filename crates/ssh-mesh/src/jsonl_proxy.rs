use anyhow::{Context, Result};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Send one JSONL object to a Unix socket and return the parsed response.
pub async fn call_jsonl_value(socket_path: &str, request: Value) -> Result<Value> {
    let stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("connect JSONL UDS {}", socket_path))?;
    let mut stream = BufReader::new(stream);

    let line = serde_json::to_vec(&request)?;
    stream.get_mut().write_all(&line).await?;
    stream.get_mut().write_all(b"\n").await?;
    stream.get_mut().flush().await?;

    let mut response = String::new();
    stream.read_line(&mut response).await?;
    if response.trim().is_empty() {
        anyhow::bail!("empty JSONL response from {}", socket_path);
    }

    Ok(serde_json::from_str(response.trim())?)
}

/// Send a JSON-RPC 2.0 request over JSONL and return the parsed response.
pub async fn call_json_rpc(socket_path: &str, method: &str, params: Value) -> Result<Value> {
    call_jsonl_value(
        socket_path,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }),
    )
    .await
}

/// Convert a mesh JSONL response into an HTTP-friendly JSON payload.
pub fn jsonl_response_payload(response: Value) -> Result<Value> {
    if response.get("jsonrpc").is_some() {
        if let Some(error) = response.get("error") {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or_else(|| error.as_str().unwrap_or("JSON-RPC request failed"));
            anyhow::bail!("{}", message);
        }
        return Ok(response.get("result").cloned().unwrap_or(Value::Null));
    }

    anyhow::bail!("JSONL response is not JSON-RPC")
}

#[cfg(test)]
mod tests {
    use super::jsonl_response_payload;
    use serde_json::json;

    #[test]
    fn unwraps_json_rpc_result() {
        let payload = jsonl_response_payload(json!({
            "jsonrpc": "2.0",
            "id": "request-1",
            "result": {"pid": 42},
        }))
        .unwrap();

        assert_eq!(payload, json!({"pid": 42}));
    }

    #[test]
    fn unwraps_array_json_rpc_result_without_a_mesh_wrapper() {
        let payload = jsonl_response_payload(json!({
            "jsonrpc": "2.0",
            "id": "request-1",
            "result": [{"pid": 42}],
        }))
        .unwrap();

        assert_eq!(payload, json!([{"pid": 42}]));
    }

    #[test]
    fn json_rpc_error_remains_an_error() {
        let error = jsonl_response_payload(json!({
            "jsonrpc": "2.0",
            "id": "request-2",
            "error": {"code": -32603, "message": "not available"},
        }))
        .unwrap_err();

        assert_eq!(error.to_string(), "not available");
    }
}
