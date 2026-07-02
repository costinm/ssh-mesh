//! Shared JSON-lines request/response helpers.
//!
//! Each message is a single JSON object terminated by `\n`. Requests may use
//! the workspace's flat form (`{"method":"status", ...}`) or JSON-RPC 2.0
//! shape (`{"jsonrpc":"2.0","method":"status","params":{...},"id":1}`).

use std::future::Future;
use std::io::{IoSlice, IoSliceMut, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use nix::cmsg_space;
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::paths::AppPaths;
use crate::protocol::Response;

/// Wire format detected for an incoming JSON-lines request.
#[derive(Debug, Clone)]
pub enum ProtocolFormat {
    /// Workspace-native flat JSON request/response.
    FlatJson { id: Option<serde_json::Value> },
    /// JSON-RPC-shaped request/response.
    JsonRpc { id: Option<serde_json::Value> },
}

/// A parsed JSON-lines request before deserializing into a component request enum.
#[derive(Debug, Clone)]
pub struct RawRequest {
    pub method: String,
    pub params: serde_json::Map<String, Value>,
}

/// Static or file-backed JSON payload used by built-in MCP-style methods.
#[derive(Debug, Clone)]
pub enum JsonSource {
    File(PathBuf),
    Static(Value),
}

/// A resource exposed through the lightweight MCP-compatible JSONL methods.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSpec {
    pub uri: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip)]
    source: Option<ResourceSource>,
}

#[derive(Debug, Clone)]
enum ResourceSource {
    File(PathBuf),
    StaticText(String),
    StaticJson(Value),
}

/// Lightweight MCP registry for JSONL/JSON-RPC services.
#[derive(Debug, Clone)]
pub struct McpRegistry {
    server_name: String,
    server_title: Option<String>,
    server_version: String,
    protocol_version: String,
    instructions: Option<String>,
    res_dirs: Vec<PathBuf>,
    tools: JsonSource,
    resources: Vec<ResourceSpec>,
}

impl McpRegistry {
    /// Create a registry using `MESH_RES_DIR` or the standard per-app overlay.
    pub fn new(server_name: impl Into<String>) -> Self {
        let server_name = server_name.into();
        let res_dirs = AppPaths::for_app(&server_name).resource_dirs();
        let tools = JsonSource::File(first_resource_dir(&res_dirs).join("tools.json"));
        Self {
            server_name,
            server_title: None,
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: "2025-06-18".to_string(),
            instructions: None,
            res_dirs,
            tools,
            resources: Vec::new(),
        }
    }

    /// Set the base directory for file-backed resources.
    pub fn with_res_dir(mut self, res_dir: impl Into<PathBuf>) -> Self {
        self.res_dirs = vec![res_dir.into()];
        if matches!(self.tools, JsonSource::File(_)) {
            self.tools = JsonSource::File(first_resource_dir(&self.res_dirs).join("tools.json"));
        }
        self
    }

    /// Set a non-default `tools.json` path.
    pub fn with_tools_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.tools = JsonSource::File(path.into());
        self
    }

    /// Set static `tools/list` content.
    pub fn with_tools_json(mut self, tools: Value) -> Self {
        self.tools = JsonSource::Static(tools);
        self
    }

    /// Set optional display title.
    pub fn with_server_title(mut self, title: impl Into<String>) -> Self {
        self.server_title = Some(title.into());
        self
    }

    /// Set server version reported by `initialize`.
    pub fn with_server_version(mut self, version: impl Into<String>) -> Self {
        self.server_version = version.into();
        self
    }

    /// Set optional instructions reported by `initialize`.
    pub fn with_instructions(mut self, instructions: impl Into<String>) -> Self {
        self.instructions = Some(instructions.into());
        self
    }

    /// Register a file-backed resource.
    pub fn add_file_resource(
        mut self,
        uri: impl Into<String>,
        path: impl Into<PathBuf>,
        mime_type: Option<String>,
    ) -> Self {
        let uri = uri.into();
        let path = path.into();
        let name = Path::new(&uri)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("resource")
            .to_string();
        self.resources.push(ResourceSpec {
            uri,
            name,
            title: None,
            description: None,
            mime_type,
            size: std::fs::metadata(&path).ok().map(|m| m.len()),
            source: Some(ResourceSource::File(path)),
        });
        self
    }

    /// Register a static text resource.
    pub fn add_static_text_resource(
        mut self,
        uri: impl Into<String>,
        name: impl Into<String>,
        text: impl Into<String>,
        mime_type: Option<String>,
    ) -> Self {
        self.resources.push(ResourceSpec {
            uri: uri.into(),
            name: name.into(),
            title: None,
            description: None,
            mime_type,
            size: None,
            source: Some(ResourceSource::StaticText(text.into())),
        });
        self
    }

    /// Register a static JSON resource.
    pub fn add_static_json_resource(
        mut self,
        uri: impl Into<String>,
        name: impl Into<String>,
        value: Value,
    ) -> Self {
        self.resources.push(ResourceSpec {
            uri: uri.into(),
            name: name.into(),
            title: None,
            description: None,
            mime_type: Some("application/json".to_string()),
            size: None,
            source: Some(ResourceSource::StaticJson(value)),
        });
        self
    }

    async fn initialize(&self, params: &serde_json::Map<String, Value>) -> Response {
        let requested = params
            .get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or(&self.protocol_version);
        let protocol_version = if requested == self.protocol_version {
            requested
        } else {
            &self.protocol_version
        };
        let mut result = json!({
            "protocolVersion": protocol_version,
            "capabilities": {
                "resources": { "listChanged": false },
                "tools": { "listChanged": false }
            },
            "serverInfo": {
                "name": self.server_name,
                "version": self.server_version
            }
        });
        if let Some(title) = &self.server_title {
            result["serverInfo"]["title"] = json!(title);
        }
        if let Some(instructions) = &self.instructions {
            result["instructions"] = json!(instructions);
        }
        Response::ok_with_data(result)
    }

    async fn tools_list(&self) -> Response {
        match self.read_json_source(&self.tools).await {
            Ok(value) => {
                if value.get("tools").is_some() {
                    Response::ok_with_data(value)
                } else {
                    Response::ok_with_data(json!({ "tools": value }))
                }
            }
            Err(e) => Response::err(e),
        }
    }

    async fn resources_list(&self) -> Response {
        let mut resources = Vec::new();
        for resource in &self.resources {
            resources.push(resource_public_json(resource));
        }
        for resource in self.scan_resource_dir().await {
            resources.push(resource_public_json(&resource));
        }
        Response::ok_with_data(json!({ "resources": resources }))
    }

    async fn resources_read(&self, uri: &str) -> Response {
        for resource in &self.resources {
            if resource.uri == uri {
                return match read_registered_resource(resource).await {
                    Ok(content) => Response::ok_with_data(json!({ "contents": [content] })),
                    Err(e) => Response::err(e),
                };
            }
        }

        let Some(path) = uri.strip_prefix("file://").map(PathBuf::from) else {
            return Response::err("unsupported resource uri");
        };
        if !self.res_dirs.iter().any(|dir| path_is_under(&path, dir)) {
            return Response::err("resource is outside resource directories");
        }
        match read_file_resource(uri.to_string(), &path).await {
            Ok(content) => Response::ok_with_data(json!({ "contents": [content] })),
            Err(e) => Response::err(e),
        }
    }

    async fn read_json_source(&self, source: &JsonSource) -> Result<Value, String> {
        match source {
            JsonSource::Static(value) => Ok(value.clone()),
            JsonSource::File(path) => {
                let mut last_error = None;
                for candidate in self.json_source_candidates(path) {
                    match tokio::fs::read(&candidate).await {
                        Ok(bytes) => {
                            return serde_json::from_slice(&bytes)
                                .map_err(|e| format!("parse {}: {}", candidate.display(), e));
                        }
                        Err(e) => {
                            last_error = Some(format!("read {}: {}", candidate.display(), e));
                        }
                    }
                }
                Err(last_error.unwrap_or_else(|| "no JSON source candidates".to_string()))
            }
        }
    }

    fn json_source_candidates(&self, path: &Path) -> Vec<PathBuf> {
        if path.file_name().and_then(|s| s.to_str()) == Some("tools.json")
            && self
                .res_dirs
                .iter()
                .any(|dir| path == dir.join("tools.json"))
        {
            return self
                .res_dirs
                .iter()
                .map(|dir| dir.join("tools.json"))
                .collect();
        }
        vec![path.to_path_buf()]
    }

    async fn scan_resource_dir(&self) -> Vec<ResourceSpec> {
        let mut resources = Vec::new();
        let mut seen_names = std::collections::HashSet::new();
        for dir in &self.res_dirs {
            let mut entries = match tokio::fs::read_dir(dir).await {
                Ok(entries) => entries,
                Err(_) => continue,
            };
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                let Ok(meta) = entry.metadata().await else {
                    continue;
                };
                if !meta.is_file() {
                    continue;
                }
                let Some(name) = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .map(str::to_string)
                else {
                    continue;
                };
                if !seen_names.insert(name.clone()) {
                    continue;
                }
                resources.push(ResourceSpec {
                    uri: file_uri(&path),
                    name,
                    title: None,
                    description: None,
                    mime_type: Some(mime_for_path(&path)),
                    size: Some(meta.len()),
                    source: Some(ResourceSource::File(path)),
                });
            }
        }
        resources
    }
}

/// Parse a flat or JSON-RPC request without binding it to a component enum.
pub fn parse_raw_request(trimmed: &str) -> (ProtocolFormat, Result<RawRequest, String>) {
    let val: Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(e) => {
            return (
                ProtocolFormat::FlatJson { id: None },
                Err(format!("Invalid JSON: {}", e)),
            );
        }
    };

    raw_from_value(val)
}

fn raw_from_value(val: Value) -> (ProtocolFormat, Result<RawRequest, String>) {
    let Some(obj) = val.as_object() else {
        return (
            ProtocolFormat::FlatJson { id: None },
            Err("JSON payload is not an object".to_string()),
        );
    };

    let id = obj.get("id").cloned();
    if obj.contains_key("jsonrpc") {
        let format = ProtocolFormat::JsonRpc { id };
        let Some(method) = obj.get("method").and_then(Value::as_str) else {
            return (
                format,
                Err("Missing or invalid 'method' in JSON-RPC request".to_string()),
            );
        };
        let params = match obj.get("params") {
            Some(Value::Object(params)) => params.clone(),
            Some(Value::Null) | None => serde_json::Map::new(),
            Some(_) => {
                return (
                    format,
                    Err("JSON-RPC 'params' must be an object".to_string()),
                );
            }
        };
        return (
            format,
            Ok(RawRequest {
                method: method.to_string(),
                params,
            }),
        );
    }

    let format = ProtocolFormat::FlatJson { id };
    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        return (
            format,
            Err("Missing or invalid 'method' in JSON request".to_string()),
        );
    };
    let mut params = obj.clone();
    params.remove("method");
    params.remove("id");
    (
        format,
        Ok(RawRequest {
            method: method.to_string(),
            params,
        }),
    )
}

/// Dispatch built-in MCP-style methods or a component-specific request.
pub async fn dispatch_request<T, F, Fut>(
    trimmed: &str,
    registry: &McpRegistry,
    handler: F,
) -> (ProtocolFormat, Option<Response>)
where
    T: DeserializeOwned,
    F: Fn(T) -> Fut,
    Fut: Future<Output = Response>,
{
    let (format, raw) = parse_raw_request(trimmed);
    let raw = match raw {
        Ok(raw) => raw,
        Err(e) => return (format, Some(Response::err(e))),
    };

    let response = match raw.method.as_str() {
        "initialize" => registry.initialize(&raw.params).await,
        "notifications/initialized" => return (format, None),
        "tools/list" => registry.tools_list().await,
        "resources/list" => registry.resources_list().await,
        "resources/read" => match raw.params.get("uri").and_then(Value::as_str) {
            Some(uri) => registry.resources_read(uri).await,
            None => Response::err("resources/read requires uri"),
        },
        "tools/call" => {
            let Some(name) = raw.params.get("name").and_then(Value::as_str) else {
                return (format, Some(Response::err("tools/call requires name")));
            };
            let arguments = raw
                .params
                .get("arguments")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let mut direct = serde_json::Map::new();
            direct.insert("method".to_string(), json!(name));
            for (key, value) in arguments {
                direct.insert(key, value);
            }
            match serde_json::from_value::<T>(Value::Object(direct)) {
                Ok(request) => tool_response(handler(request).await),
                Err(e) => Response::err(format!("tools/call request mapping failed: {e}")),
            }
        }
        _ => {
            let mut direct = raw.params;
            direct.insert("method".to_string(), json!(raw.method));
            match serde_json::from_value::<T>(Value::Object(direct)) {
                Ok(request) => handler(request).await,
                Err(e) => Response::err(format!("Failed to deserialize request: {e}")),
            }
        }
    };

    (format, Some(response))
}

fn first_resource_dir(res_dirs: &[PathBuf]) -> PathBuf {
    res_dirs
        .first()
        .cloned()
        .unwrap_or_else(|| PathBuf::from("/opt/mesh/resources"))
}

fn tool_response(response: Response) -> Response {
    if response.success {
        let structured = response.data.unwrap_or(Value::Null);
        Response::ok_with_data(json!({
            "content": [
                {
                    "type": "text",
                    "text": serde_json::to_string(&structured).unwrap_or_else(|_| "null".to_string())
                }
            ],
            "structuredContent": structured,
            "isError": false
        }))
    } else {
        let error = response
            .error
            .unwrap_or_else(|| "tool call failed".to_string());
        Response::ok_with_data(json!({
            "content": [
                {
                    "type": "text",
                    "text": error
                }
            ],
            "isError": true
        }))
    }
}

fn resource_public_json(resource: &ResourceSpec) -> Value {
    let mut value = serde_json::to_value(resource).unwrap_or_else(|_| json!({}));
    if let Some(obj) = value.as_object_mut() {
        obj.remove("source");
    }
    value
}

async fn read_registered_resource(resource: &ResourceSpec) -> Result<Value, String> {
    match resource.source.as_ref() {
        Some(ResourceSource::StaticText(text)) => Ok(json!({
            "uri": resource.uri,
            "mimeType": resource.mime_type.clone().unwrap_or_else(|| "text/plain".to_string()),
            "text": text
        })),
        Some(ResourceSource::StaticJson(value)) => Ok(json!({
            "uri": resource.uri,
            "mimeType": resource.mime_type.clone().unwrap_or_else(|| "application/json".to_string()),
            "text": serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
        })),
        Some(ResourceSource::File(path)) => read_file_resource(resource.uri.clone(), path).await,
        None => Err("resource has no content source".to_string()),
    }
}

async fn read_file_resource(uri: String, path: &Path) -> Result<Value, String> {
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| format!("read {}: {}", path.display(), e))?;
    let mime_type = mime_for_path(path);
    if is_text_mime(&mime_type) {
        let text = String::from_utf8(bytes)
            .map_err(|e| format!("{} is not valid UTF-8: {}", path.display(), e))?;
        Ok(json!({
            "uri": uri,
            "mimeType": mime_type,
            "text": text
        }))
    } else {
        Ok(json!({
            "uri": uri,
            "mimeType": mime_type,
            "blob": base64_encode(&bytes)
        }))
    }
}

fn path_is_under(path: &Path, base: &Path) -> bool {
    let Ok(path) = std::fs::canonicalize(path) else {
        return false;
    };
    let Ok(base) = std::fs::canonicalize(base) else {
        return false;
    };
    path.starts_with(base)
}

fn file_uri(path: &Path) -> String {
    format!("file://{}", path.to_string_lossy())
}

fn mime_for_path(path: &Path) -> String {
    match path.extension().and_then(|s| s.to_str()).unwrap_or("") {
        "json" => "application/json",
        "md" => "text/markdown",
        "txt" | "log" => "text/plain",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "toml" => "application/toml",
        "yaml" | "yml" => "application/yaml",
        "rs" => "text/x-rust",
        _ => "application/octet-stream",
    }
    .to_string()
}

fn is_text_mime(mime_type: &str) -> bool {
    mime_type.starts_with("text/")
        || matches!(
            mime_type,
            "application/json" | "application/javascript" | "application/toml" | "application/yaml"
        )
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Parse a flat or JSON-RPC-shaped JSON-lines request.
pub fn parse_request<T>(trimmed: &str) -> (ProtocolFormat, Result<T, String>)
where
    T: DeserializeOwned,
{
    let val: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(e) => {
            return (
                ProtocolFormat::FlatJson { id: None },
                Err(format!("Invalid JSON: {}", e)),
            );
        }
    };

    let Some(obj) = val.as_object() else {
        return (
            ProtocolFormat::FlatJson { id: None },
            Err("JSON payload is not an object".to_string()),
        );
    };

    let id = obj.get("id").cloned();
    if obj.contains_key("jsonrpc") {
        let format = ProtocolFormat::JsonRpc { id };
        let method = match obj.get("method").and_then(|m| m.as_str()) {
            Some(m) => m,
            None => {
                return (
                    format,
                    Err("Missing or invalid 'method' in JSON-RPC request".to_string()),
                );
            }
        };

        let mut flat = serde_json::Map::new();
        flat.insert("method".to_string(), serde_json::json!(method));
        if let Some(params) = obj.get("params") {
            if let Some(params_obj) = params.as_object() {
                for (k, v) in params_obj {
                    flat.insert(k.clone(), v.clone());
                }
            } else if !params.is_null() {
                return (
                    format,
                    Err("JSON-RPC 'params' must be an object".to_string()),
                );
            }
        }

        match serde_json::from_value::<T>(serde_json::Value::Object(flat)) {
            Ok(req) => (format, Ok(req)),
            Err(e) => (format, Err(format!("Failed to deserialize request: {}", e))),
        }
    } else {
        let format = ProtocolFormat::FlatJson { id };
        match serde_json::from_value::<T>(val) {
            Ok(req) => (format, Ok(req)),
            Err(e) => (format, Err(format!("Failed to deserialize request: {}", e))),
        }
    }
}

/// Format a protocol response in the same shape as the incoming request.
pub fn format_response(response: Response, format: &ProtocolFormat) -> anyhow::Result<String> {
    match format {
        ProtocolFormat::FlatJson { id } => {
            let mut val = serde_json::to_value(&response)?;
            if let Some(obj) = val.as_object_mut()
                && let Some(id_val) = id
            {
                obj.insert("id".to_string(), id_val.clone());
            }
            Ok(serde_json::to_string(&val)?)
        }
        ProtocolFormat::JsonRpc { id } => {
            let mut map = serde_json::Map::new();
            map.insert("jsonrpc".to_string(), serde_json::json!("2.0"));
            if response.success {
                map.insert(
                    "result".to_string(),
                    response.data.clone().unwrap_or(serde_json::Value::Null),
                );
            } else {
                let mut err_map = serde_json::Map::new();
                err_map.insert("code".to_string(), serde_json::json!(-32603));
                err_map.insert(
                    "message".to_string(),
                    serde_json::json!(
                        response
                            .error
                            .clone()
                            .unwrap_or_else(|| "Unknown error".to_string())
                    ),
                );
                map.insert("error".to_string(), serde_json::Value::Object(err_map));
            }
            map.insert(
                "id".to_string(),
                id.clone().unwrap_or(serde_json::Value::Null),
            );
            Ok(serde_json::to_string(&serde_json::Value::Object(map))?)
        }
    }
}

/// Send one JSON-lines message with one attached file descriptor.
pub fn send_json_with_fd(
    stream: &mut std::os::unix::net::UnixStream,
    message: &serde_json::Value,
    fd: &OwnedFd,
) -> anyhow::Result<()> {
    let line = serde_json::to_vec(message)?;
    stream.write_all(&line)?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let iov = [IoSlice::new(b"F")];
    let fds = [fd.as_raw_fd()];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    sendmsg::<()>(stream.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)?;
    Ok(())
}

/// Receive one file descriptor from a Unix stream using SCM_RIGHTS.
pub fn recv_one_fd(stream: &std::os::unix::net::UnixStream) -> anyhow::Result<OwnedFd> {
    recv_one_fd_raw(stream.as_raw_fd())
}

/// Receive one file descriptor from a raw Unix stream fd using SCM_RIGHTS.
pub fn recv_one_fd_raw(raw_fd: i32) -> anyhow::Result<OwnedFd> {
    let mut buf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsgspace = cmsg_space!([std::os::fd::RawFd; 1]);
    let msg = recvmsg::<()>(raw_fd, &mut iov, Some(&mut cmsgspace), MsgFlags::empty())?;

    for cmsg in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg
            && let Some(fd) = fds.first()
        {
            // SAFETY: recvmsg transferred ownership of this descriptor.
            let owned = unsafe { OwnedFd::from_raw_fd(*fd) };
            set_fd_cloexec(owned.as_raw_fd());
            return Ok(owned);
        }
    }

    anyhow::bail!("missing passed file descriptor")
}

fn set_fd_cloexec(fd: i32) {
    // SAFETY: fd is a valid open file descriptor; F_GETFD/F_SETFD are safe.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return;
    }
    if flags & libc::FD_CLOEXEC == 0 {
        // SAFETY: as above.
        let _ = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(tag = "method")]
    enum TestRequest {
        #[serde(rename = "status")]
        Status { name: Option<String> },
        #[serde(rename = "echo")]
        Echo { value: String },
    }

    #[test]
    fn parses_flat_json() {
        let (format, parsed) =
            parse_request::<TestRequest>(r#"{"method":"status","name":"x","id":"req-id"}"#);
        assert!(
            matches!(format, ProtocolFormat::FlatJson { id: Some(serde_json::Value::String(ref s)) } if s == "req-id")
        );
        match parsed.unwrap() {
            TestRequest::Status { name } => assert_eq!(name.as_deref(), Some("x")),
            TestRequest::Echo { .. } => panic!("unexpected request"),
        }
    }

    #[test]
    fn parses_json_rpc() {
        let (format, parsed) = parse_request::<TestRequest>(
            r#"{"jsonrpc":"2.0","method":"status","params":{"name":"x"},"id":100}"#,
        );
        assert!(
            matches!(format, ProtocolFormat::JsonRpc { id: Some(serde_json::Value::Number(ref n)) } if n.as_i64() == Some(100))
        );
        match parsed.unwrap() {
            TestRequest::Status { name } => assert_eq!(name.as_deref(), Some("x")),
            TestRequest::Echo { .. } => panic!("unexpected request"),
        }
    }

    #[test]
    fn formats_json_rpc_response() {
        let response = Response::ok_with_data(serde_json::json!({"pid": 42}));
        let formatted = format_response(
            response,
            &ProtocolFormat::JsonRpc {
                id: Some(serde_json::json!(100)),
            },
        )
        .unwrap();
        let val: serde_json::Value = serde_json::from_str(&formatted).unwrap();
        assert_eq!(val["jsonrpc"], "2.0");
        assert_eq!(val["result"]["pid"], 42);
        assert_eq!(val["id"], 100);
    }

    #[tokio::test]
    async fn dispatches_initialize() {
        let registry = McpRegistry::new("test-service");
        let (format, response) = dispatch_request::<TestRequest, _, _>(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
            &registry,
            |_| async { Response::err("should not call direct handler") },
        )
        .await;
        let response = response.unwrap();
        let formatted = format_response(response, &format).unwrap();
        let val: serde_json::Value = serde_json::from_str(&formatted).unwrap();
        assert_eq!(val["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(val["result"]["capabilities"]["tools"]["listChanged"], false);
        assert_eq!(val["result"]["serverInfo"]["name"], "test-service");
    }

    #[tokio::test]
    async fn dispatches_tools_list_from_static_json() {
        let registry = McpRegistry::new("test-service").with_tools_json(serde_json::json!([
            {
                "name": "echo",
                "description": "Echo a value",
                "inputSchema": {"type": "object"}
            }
        ]));
        let (_format, response) = dispatch_request::<TestRequest, _, _>(
            r#"{"method":"tools/list"}"#,
            &registry,
            |_| async { Response::err("should not call direct handler") },
        )
        .await;
        let data = response.unwrap().data.unwrap();
        assert_eq!(data["tools"][0]["name"], "echo");
    }

    #[tokio::test]
    async fn dispatches_tools_call_to_native_handler() {
        let registry = McpRegistry::new("test-service");
        let (_format, response) = dispatch_request::<TestRequest, _, _>(
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo","arguments":{"value":"hello"}}}"#,
            &registry,
            |request| async move {
                match request {
                    TestRequest::Echo { value } => {
                        Response::ok_with_data(serde_json::json!({"echo": value}))
                    }
                    TestRequest::Status { .. } => Response::err("unexpected request"),
                }
            },
        )
        .await;
        let data = response.unwrap().data.unwrap();
        assert_eq!(data["structuredContent"]["echo"], "hello");
        assert_eq!(data["isError"], false);
    }

    fn write(path: &Path, content: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    fn env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    #[tokio::test]
    async fn tools_json_prefers_explicit_resource_dir() {
        let temp = tempfile::tempdir().unwrap();
        let explicit = temp.path().join("explicit");
        let home_base = temp.path().join("home");
        let opt_base = temp.path().join("opt");
        write(
            &explicit.join("tools.json"),
            r#"{"tools":[{"name":"explicit"}]}"#,
        );
        write(
            &home_base.join("demo/etc/resources/tools.json"),
            r#"{"tools":[{"name":"home"}]}"#,
        );
        write(
            &opt_base.join("demo/resources/tools.json"),
            r#"{"tools":[{"name":"opt"}]}"#,
        );

        let registry = {
            let _guard = env_lock().lock().unwrap();
            unsafe {
                std::env::set_var("MESH_RES_DIR", &explicit);
                std::env::set_var("MESH_HOME_BASE", &home_base);
                std::env::set_var("MESH_OPT_BASE", &opt_base);
            }
            let registry = McpRegistry::new("demo");
            unsafe {
                std::env::remove_var("MESH_RES_DIR");
                std::env::remove_var("MESH_HOME_BASE");
                std::env::remove_var("MESH_OPT_BASE");
            }
            registry
        };
        let response = registry.tools_list().await;

        assert!(response.success);
        let data = response.data.unwrap();
        assert_eq!(data["tools"][0]["name"], "explicit");
    }

    #[tokio::test]
    async fn tools_json_prefers_home_overlay_before_package() {
        let temp = tempfile::tempdir().unwrap();
        let home_base = temp.path().join("home");
        let opt_base = temp.path().join("opt");
        write(
            &home_base.join("traceweb/etc/resources/tools.json"),
            r#"{"tools":[{"name":"home"}]}"#,
        );
        write(
            &opt_base.join("traceweb/resources/tools.json"),
            r#"{"tools":[{"name":"opt"}]}"#,
        );

        let registry = {
            let _guard = env_lock().lock().unwrap();
            unsafe {
                std::env::remove_var("MESH_RES_DIR");
                std::env::set_var("MESH_HOME_BASE", &home_base);
                std::env::set_var("MESH_OPT_BASE", &opt_base);
            }
            let registry = McpRegistry::new("traceweb");
            unsafe {
                std::env::remove_var("MESH_HOME_BASE");
                std::env::remove_var("MESH_OPT_BASE");
            }
            registry
        };
        let response = registry.tools_list().await;

        assert!(response.success);
        let data = response.data.unwrap();
        assert_eq!(data["tools"][0]["name"], "home");
    }

    #[tokio::test]
    async fn resources_list_overlays_home_over_package_by_name() {
        let temp = tempfile::tempdir().unwrap();
        let home_base = temp.path().join("home");
        let opt_base = temp.path().join("opt");
        write(&home_base.join("lmesh/etc/resources/readme.md"), "home");
        write(&opt_base.join("lmesh/resources/readme.md"), "opt");
        write(&opt_base.join("lmesh/resources/other.md"), "other");

        let registry = {
            let _guard = env_lock().lock().unwrap();
            unsafe {
                std::env::remove_var("MESH_RES_DIR");
                std::env::set_var("MESH_HOME_BASE", &home_base);
                std::env::set_var("MESH_OPT_BASE", &opt_base);
            }
            let registry = McpRegistry::new("lmesh");
            unsafe {
                std::env::remove_var("MESH_HOME_BASE");
                std::env::remove_var("MESH_OPT_BASE");
            }
            registry
        };
        let response = registry.resources_list().await;

        assert!(response.success);
        let data = response.data.unwrap();
        let resources = data["resources"].as_array().unwrap();
        let names: Vec<_> = resources
            .iter()
            .map(|r| r["name"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["readme.md".to_string(), "other.md".to_string()]);
        assert!(
            resources[0]["uri"].as_str().unwrap().contains(
                &home_base
                    .join("lmesh/etc/resources/readme.md")
                    .to_string_lossy()
                    .to_string()
            )
        );
    }
}
