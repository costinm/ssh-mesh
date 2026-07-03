//! UDS control server for the mesh-init daemon.
//!
//! Accepts JSON-lines requests over a Unix domain socket with peer credential
//! verification. Only root (UID 0) or the daemon's own UID may connect.

use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;

use anyhow::{Context, Result};
use nix::cmsg_space;
use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
use std::io::IoSliceMut;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::daemon::Daemon;
use crate::protocol::{Request, Response};

// ============================================================================
// Control Server
// ============================================================================

/// Default maximum number of concurrent control-socket connections.
const DEFAULT_MAX_CONTROL_CONNECTIONS: usize = 32;

/// Resolve the configured maximum number of concurrent control-socket
/// connections from the `MESH_INIT_MAX_CONTROL_CONNECTIONS` env var.
fn max_control_connections() -> usize {
    std::env::var("MESH_INIT_MAX_CONTROL_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n: &usize| n > 0)
        .unwrap_or(DEFAULT_MAX_CONTROL_CONNECTIONS)
}

/// UDS control server that dispatches JSON-lines protocol requests to the daemon.
pub struct ControlServer {
    socket_path: String,
    daemon: Arc<Daemon>,
    connection_slots: Arc<Semaphore>,
}

impl ControlServer {
    /// Create a new control server.
    pub fn new(socket_path: String, daemon: Arc<Daemon>) -> Self {
        Self {
            socket_path,
            daemon,
            connection_slots: Arc::new(Semaphore::new(max_control_connections())),
        }
    }

    /// Run the control server accept loop.
    ///
    /// Removes any stale socket file, binds, and accepts connections in a loop.
    /// Each connection is handled in a separate task.
    pub async fn run(&self) -> Result<()> {
        // Clean up stale socket
        if let Err(error) = std::fs::remove_file(&self.socket_path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(error).with_context(|| {
                format!("remove stale mesh-init control socket {}", self.socket_path)
            });
        }

        // Ensure parent directory exists
        if let Some(parent) = std::path::Path::new(&self.socket_path).parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "create mesh-init control socket directory {}",
                    parent.display()
                )
            })?;
            if unsafe { libc::getuid() } == 0
                && let Ok(path) = std::ffi::CString::new(parent.as_os_str().as_encoded_bytes())
            {
                let _ = unsafe {
                    libc::chown(
                        path.as_ptr(),
                        u32::MAX,
                        mesh::auth::DEFAULT_TRUSTED_SSHD_UID,
                    )
                };
            }
            if let Ok(metadata) = std::fs::metadata(parent) {
                let mut perms = metadata.permissions();
                std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o770);
                std::fs::set_permissions(parent, perms).with_context(|| {
                    format!(
                        "set permissions on mesh-init control socket directory {}",
                        parent.display()
                    )
                })?;
            }
        }

        let listener = UnixListener::bind(&self.socket_path)
            .with_context(|| format!("bind mesh-init control socket {}", self.socket_path))?;
        if unsafe { libc::getuid() } == 0
            && let Ok(path) = std::ffi::CString::new(self.socket_path.as_str())
        {
            let _ = unsafe {
                libc::chown(
                    path.as_ptr(),
                    u32::MAX,
                    mesh::auth::DEFAULT_TRUSTED_SSHD_UID,
                )
            };
        }

        // Set permissions so root/owner/group can connect
        let mut perms = std::fs::metadata(&self.socket_path)
            .with_context(|| format!("stat mesh-init control socket {}", self.socket_path))?
            .permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o660);
        std::fs::set_permissions(&self.socket_path, perms).with_context(|| {
            format!(
                "set permissions on mesh-init control socket {}",
                self.socket_path
            )
        })?;

        info!("Control server listening on {}", self.socket_path);

        let current_uid = unsafe { libc::getuid() };

        let mut shutdown_rx = self.daemon.shutdown_tx.subscribe();

        loop {
            let stream = tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok((stream, _)) => stream,
                        Err(e) => {
                            error!("Accept error: {}", e);
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            continue;
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Control server stopping due to shutdown");
                        break;
                    }
                    continue;
                }
            };

            // Verify peer credentials
            let peer_cred = match stream.peer_cred() {
                Ok(cred) => cred,
                Err(e) => {
                    warn!("Failed to get peer credentials: {}", e);
                    continue;
                }
            };

            let peer_uid = peer_cred.uid();
            let peer_gid = peer_cred.gid();

            // Use daemon's auth config if available, otherwise fallback to root+self
            let is_authorized = {
                let configs = self.daemon.configs.lock();
                // Check if default config has auth rules
                let auth = configs.get("default").and_then(|c| c.auth.as_ref());
                match auth {
                    Some(auth_config) => auth_config.is_uid_authorized(peer_uid, current_uid),
                    None => {
                        mesh::auth::AuthConfig::is_builtin_uid_authorized(peer_uid, current_uid)
                    }
                }
            };
            if !is_authorized {
                error!(
                    "Rejected connection from UID {} (expected 0, {}, or {})",
                    peer_uid,
                    current_uid,
                    mesh::auth::DEFAULT_TRUSTED_SSHD_UID
                );
                continue;
            }

            debug!("Accepted control connection from UID {}", peer_uid);

            let daemon = self.daemon.clone();
            let slots = self.connection_slots.clone();
            // Acquire a connection-slot permit; if the daemon is at capacity,
            // wait for a slot to free up rather than spawning unbounded tasks.
            let permit = match slots.clone().acquire_owned().await {
                Ok(p) => p,
                Err(e) => {
                    error!("Control connection semaphore closed: {}", e);
                    continue;
                }
            };
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, daemon, peer_uid, peer_gid).await {
                    error!("Control connection error: {}", e);
                }
                drop(permit);
            });
        }
        Ok(())
    }
}

/// Handle a single control connection.
///
/// Reads JSON lines from the stream, dispatches each to the daemon,
/// and writes back JSON responses.
enum ProtocolFormat {
    Json(mesh::jsonl::ProtocolFormat),
    TextCommand,
}

fn parse_incoming(trimmed: &str) -> (ProtocolFormat, Result<Request, String>) {
    if !trimmed.starts_with('{') {
        let parsed = parse_text_command(trimmed);
        (
            ProtocolFormat::TextCommand,
            parsed.map_err(|e| e.to_string()),
        )
    } else {
        let (format, parsed) = mesh::jsonl::parse_request::<Request>(trimmed);
        (ProtocolFormat::Json(format), parsed)
    }
}

fn parse_text_command(line: &str) -> Result<Request> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.is_empty() {
        anyhow::bail!("Empty command");
    }

    match tokens[0] {
        "status" => Ok(Request::Status {
            name: tokens.get(1).map(|s| s.to_string()),
        }),
        "start" => {
            let name = tokens
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("Missing service name"))?;
            Ok(Request::Start {
                name: name.to_string(),
                args: tokens[2..].iter().map(|s| s.to_string()).collect(),
                env: std::collections::HashMap::new(),
                context: None,
            })
        }
        "stop" => {
            let name = tokens
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("Missing service name"))?;
            let mut signal = None;
            let mut i = 2;
            while i < tokens.len() {
                if tokens[i] == "--signal" && i + 1 < tokens.len() {
                    signal = Some(tokens[i + 1].parse()?);
                    break;
                }
                i += 1;
            }
            Ok(Request::Stop {
                name: name.to_string(),
                signal,
            })
        }
        "freeze" => {
            let name = tokens
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("Missing service name"))?;
            Ok(Request::Freeze {
                name: name.to_string(),
            })
        }
        "unfreeze" => {
            let name = tokens
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("Missing service name"))?;
            Ok(Request::Unfreeze {
                name: name.to_string(),
            })
        }
        "reload" => Ok(Request::Reload),
        "shutdown" => Ok(Request::Shutdown),
        cmd => anyhow::bail!("Unsupported CLI command: {}", cmd),
    }
}

fn format_text_success(data: &Option<serde_json::Value>) -> String {
    let Some(data) = data else {
        return "OK".to_string();
    };

    if let Some(obj) = data.as_object() {
        let mut lines = Vec::new();
        for (k, v) in obj {
            let v_str = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                other => other.to_string(),
            };
            lines.push(format!("{}: {}", k, v_str));
        }
        lines.join("\n")
    } else if let Some(arr) = data.as_array() {
        let mut lines = Vec::new();
        for item in arr {
            if let Some(obj) = item.as_object() {
                let name = obj
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("unknown");
                let state = obj
                    .get("state")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");
                if let Some(pid) = obj.get("pid").and_then(|p| p.as_u64()) {
                    lines.push(format!("{}: {} (PID {})", name, state, pid));
                } else {
                    lines.push(format!("{}: {}", name, state));
                }
            } else {
                lines.push(item.to_string());
            }
        }
        lines.join("\n")
    } else {
        data.to_string()
    }
}

fn format_response(response: Response, format: &ProtocolFormat) -> Result<String> {
    match format {
        ProtocolFormat::Json(format) => mesh::jsonl::format_response(response, format),
        ProtocolFormat::TextCommand => {
            if response.success {
                Ok(format_text_success(&response.data))
            } else {
                Ok(format!(
                    "Error: {}",
                    response.error.as_deref().unwrap_or("Unknown error")
                ))
            }
        }
    }
}

/// Handle a single control connection.
///
/// Reads JSON or text command lines from the stream, dispatches each to the daemon,
/// and writes back formatted responses.
async fn handle_connection(
    stream: tokio::net::UnixStream,
    daemon: Arc<Daemon>,
    peer_uid: u32,
    peer_gid: u32,
) -> Result<()> {
    let mut stream = stream;
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = read_json_line(&mut stream, &mut line).await?;
        if bytes_read == 0 {
            break; // Client disconnected
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (format, parsed_result) = parse_incoming(trimmed);

        let response = match parsed_result {
            Ok(request) => {
                debug!("Received request: {:?}", request);
                match request {
                    request @ (Request::StartTerminal { .. }
                    | Request::RegisterNamespace { .. }) => {
                        let mut std_stream = stream.into_std()?;
                        std_stream.set_nonblocking(false)?;
                        let fds = recv_fds(&std_stream)?;
                        if fds.len() > 1 {
                            debug!("Received {} FDs with request; using the first", fds.len());
                        }
                        let fd = fds.into_iter().next().expect("at least one FD");
                        let response = daemon
                            .handle_request_with_fd(request, fd, peer_uid, peer_gid)
                            .await;
                        let response_str = format_response(response, &format)?;
                        std_stream.write_all(response_str.as_bytes())?;
                        std_stream.write_all(b"\n")?;
                        std_stream.flush()?;
                        std_stream.set_nonblocking(true)?;
                        stream = tokio::net::UnixStream::from_std(std_stream)?;
                        continue;
                    }
                    Request::Shutdown => {
                        let response = Response::ok();
                        let response_str = format_response(response, &format)?;
                        stream.write_all(response_str.as_bytes()).await?;
                        stream.write_all(b"\n").await?;
                        stream.flush().await?;

                        let daemon_clone = daemon.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            daemon_clone.shutdown().await;
                        });
                        break;
                    }
                    request => daemon.handle_request(request, peer_uid, peer_gid).await,
                }
            }
            Err(e) => {
                warn!("Invalid request: {}", e);
                Response::err(format!("invalid request: {}", e))
            }
        };

        let response_str = format_response(response, &format)?;
        stream.write_all(response_str.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;
    }

    debug!("Control connection closed");
    Ok(())
}

async fn read_json_line(stream: &mut tokio::net::UnixStream, line: &mut String) -> Result<usize> {
    // Read raw bytes into a Vec, then convert to a String. Reading one byte
    // at a time and casting u8→char corrupts multibyte UTF-8 sequences (each
    // byte becomes a separate Unicode scalar, doubling/tripling their size).
    // Also cap the line at 1 MiB to prevent unbounded reads from OOM-ing.
    const MAX_LINE_LEN: usize = 1024 * 1024;
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Ok(buf.len());
        }
        let b = byte[0];
        buf.push(b);
        if b == b'\n' {
            break;
        }
        if buf.len() > MAX_LINE_LEN {
            anyhow::bail!("control line exceeds {} bytes", MAX_LINE_LEN);
        }
    }
    let len = buf.len();
    // Strip a trailing newline for the String conversion.
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    *line = String::from_utf8(buf)
        .map_err(|e| anyhow::anyhow!("control line is not valid UTF-8: {}", e))?;
    Ok(len)
}

/// Receive any number of file descriptors from a single `recvmsg`.
///
/// Returns all FDs from all `SCM_RIGHTS` cmsgs. Each FD has `FD_CLOEXEC` set
/// to prevent it from leaking into child processes the daemon may spawn
/// later. FDs received via `SCM_RIGHTS` do not inherit the sender's
/// `FD_CLOEXEC` flag, so we set it explicitly.
fn recv_fds(stream: &std::os::unix::net::UnixStream) -> Result<Vec<OwnedFd>> {
    let mut buf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut buf)];
    // Accept up to 4 FDs in a single message; the kernel itself limits the
    // number of FDs that can be passed in a single `SCM_RIGHTS` cmsg.
    let mut cmsgspace = cmsg_space!([std::os::fd::RawFd; 4]);
    let msg = recvmsg::<()>(
        stream.as_raw_fd(),
        &mut iov,
        Some(&mut cmsgspace),
        MsgFlags::empty(),
    )?;

    let mut fds = Vec::new();
    for cmsg in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(raw_fds) = cmsg {
            for raw in raw_fds {
                // SAFETY: recvmsg transferred ownership of this descriptor.
                let owned = unsafe { OwnedFd::from_raw_fd(raw) };
                set_fd_cloexec(owned.as_raw_fd());
                fds.push(owned);
            }
        }
    }

    if fds.is_empty() {
        anyhow::bail!("missing passed file descriptor");
    }
    Ok(fds)
}

/// Set `FD_CLOEXEC` on a file descriptor. Best-effort.
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

// ============================================================================
// Client
// ============================================================================

/// Send a single request to a running daemon and return the response.
pub async fn send_request(socket_path: &str, request: &Request) -> Result<Response> {
    let stream = tokio::net::UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("connect to mesh-init daemon at {}", socket_path))?;
    let (reader, mut writer) = stream.into_split();

    let request_json = serde_json::to_string(request)?;
    writer.write_all(request_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    // Shutdown the write side to signal we're done sending
    drop(writer);

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    let response: Response = serde_json::from_str(line.trim())?;
    Ok(response)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_protocol_roundtrip() {
        // Test serialization/deserialization round-trip
        let request = Request::Start {
            name: "test".to_string(),
            args: vec![],
            env: std::collections::HashMap::new(),
            context: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();
        match parsed {
            Request::Start { name, .. } => assert_eq!(name, "test"),
            _ => panic!("expected Start"),
        }

        let response = Response::ok_with_data(serde_json::json!({"pid": 42}));
        let json = serde_json::to_string(&response).unwrap();
        let parsed: Response = serde_json::from_str(&json).unwrap();
        assert!(parsed.success);
    }

    #[test]
    fn test_parse_incoming_flat_json() {
        let trimmed = r#"{"method":"status","name":"x","id":"req-id"}"#;
        let (format, parsed) = parse_incoming(trimmed);
        assert!(
            matches!(format, ProtocolFormat::Json(mesh::jsonl::ProtocolFormat::FlatJson { id: Some(serde_json::Value::String(ref s)) }) if s == "req-id")
        );
        let req = parsed.unwrap();
        match req {
            Request::Status { name } => assert_eq!(name, Some("x".to_string())),
            _ => panic!("Expected status request"),
        }
    }

    #[test]
    fn test_parse_incoming_jsonrpc() {
        let trimmed = r#"{"jsonrpc":"2.0","method":"status","params":{"name":"x"},"id":100}"#;
        let (format, parsed) = parse_incoming(trimmed);
        assert!(
            matches!(format, ProtocolFormat::Json(mesh::jsonl::ProtocolFormat::JsonRpc { id: Some(serde_json::Value::Number(ref n)) }) if n.as_i64() == Some(100))
        );
        let req = parsed.unwrap();
        match req {
            Request::Status { name } => assert_eq!(name, Some("x".to_string())),
            _ => panic!("Expected status request"),
        }
    }

    #[test]
    fn test_parse_incoming_text() {
        let trimmed = "status x";
        let (format, parsed) = parse_incoming(trimmed);
        assert!(matches!(format, ProtocolFormat::TextCommand));
        let req = parsed.unwrap();
        match req {
            Request::Status { name } => assert_eq!(name, Some("x".to_string())),
            _ => panic!("Expected status request"),
        }
    }

    #[test]
    fn test_format_response_jsonrpc() {
        let response = Response::ok_with_data(serde_json::json!({"pid": 42}));
        let format = ProtocolFormat::Json(mesh::jsonl::ProtocolFormat::JsonRpc {
            id: Some(serde_json::json!(100)),
        });
        let formatted = format_response(response, &format).unwrap();
        let val: serde_json::Value = serde_json::from_str(&formatted).unwrap();
        assert_eq!(val["jsonrpc"], "2.0");
        assert_eq!(val["result"]["pid"], 42);
        assert_eq!(val["id"], 100);
    }

    #[test]
    fn test_format_response_text() {
        let response = Response::ok_with_data(serde_json::json!({"pid": 42, "state": "running"}));
        let format = ProtocolFormat::TextCommand;
        let formatted = format_response(response, &format).unwrap();
        assert!(formatted.contains("pid: 42"));
        assert!(formatted.contains("state: running"));
    }
}
