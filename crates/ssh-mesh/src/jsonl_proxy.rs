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

/// Send a single flat JSONL request to a Unix socket and return the parsed response.
pub async fn call_jsonl(socket_path: &str, method: &str, params: Value) -> Result<Value> {
    let mut request = serde_json::Map::new();
    request.insert("method".to_string(), json!(method));
    if let Some(params) = params.as_object() {
        for (k, v) in params {
            request.insert(k.clone(), v.clone());
        }
    }

    call_jsonl_value(socket_path, Value::Object(request)).await
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
            anyhow::bail!("{}", error);
        }
        return Ok(response.get("result").cloned().unwrap_or(Value::Null));
    }

    if response
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Ok(response
            .get("data")
            .cloned()
            .unwrap_or_else(|| json!({"status": "ok"})));
    }

    let error = response
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("JSONL request failed");
    anyhow::bail!("{}", error)
}
