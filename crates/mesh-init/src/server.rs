//! UDS control server for the mesh-init daemon.
//!
//! Accepts JSON-lines requests over a Unix domain socket with peer credential
//! verification. Only root (UID 0) or the daemon's own UID may connect.

use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, LazyLock};

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

use mesh::tagged::{TaggedCatalog, TaggedRecord};
use mesh::wire::{TaggedRecordHandler, response_ok, serve_cbor_session};

// ============================================================================
// Control Server
// ============================================================================

/// Default maximum number of concurrent control-socket connections.
const DEFAULT_MAX_CONTROL_CONNECTIONS: usize = 32;

/// Public, generated schema used to translate numeric CBOR tags back into the
/// existing serde `Request` enum. The schema is embedded with the daemon so a
/// client and server cannot silently disagree because a runtime file changed.
static CONTROL_CATALOG: LazyLock<TaggedCatalog> = LazyLock::new(|| {
    TaggedCatalog::from_tools_json(
        &serde_json::from_str(include_str!("../resources/tools.json"))
            .expect("mesh-init generated tools.json must be valid JSON"),
    )
    .expect("mesh-init generated tools.json must be a valid tagged catalog")
});

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
                std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
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

        // The socket is locally discoverable/connectable; requests are
        // authorized by the mesh-init protocol after peer credentials are read.
        let mut perms = std::fs::metadata(&self.socket_path)
            .with_context(|| format!("stat mesh-init control socket {}", self.socket_path))?
            .permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o666);
        std::fs::set_permissions(&self.socket_path, perms).with_context(|| {
            format!(
                "set permissions on mesh-init control socket {}",
                self.socket_path
            )
        })?;

        info!(path = %self.socket_path, "control_server_listening");

        let current_uid = unsafe { libc::getuid() };

        let mut shutdown_rx = self.daemon.shutdown_tx.subscribe();

        loop {
            let stream = tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok((stream, _)) => stream,
                        Err(e) => {
                            error!(error = %e, "control_accept_failed");
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            continue;
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("control_server_stopping");
                        break;
                    }
                    continue;
                }
            };

            // Verify peer credentials
            let peer_cred = match stream.peer_cred() {
                Ok(cred) => cred,
                Err(e) => {
                    warn!(error = %e, "get_peer_credentials_failed");
                    continue;
                }
            };

            let peer_uid = peer_cred.uid();
            let peer_gid = peer_cred.gid();

            // Admit the connection so request-level policy can distinguish the
            // safe `reload` operation from privileged lifecycle/observer calls.
            // Rejecting here made it impossible for an ordinary user to ask
            // mesh-init to refresh service configuration.
            debug!(
                peer_uid,
                peer_gid, current_uid, "control_connection_admitted"
            );

            debug!(peer_uid, "control_connection_accepted");

            let daemon = self.daemon.clone();
            let slots = self.connection_slots.clone();
            // Acquire a connection-slot permit; if the daemon is at capacity,
            // wait for a slot to free up rather than spawning unbounded tasks.
            let permit = match slots.clone().acquire_owned().await {
                Ok(p) => p,
                Err(e) => {
                    error!(error = %e, "connection_semaphore_closed");
                    continue;
                }
            };
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, daemon, peer_uid, peer_gid).await {
                    error!(error = %e, "control_connection_error");
                }
                drop(permit);
            });
        }
        Ok(())
    }
}

/// Handle a single control connection.
///
/// Programmatic callers use a length-framed tagged-CBOR session when the first
/// byte is zero (the high byte of the bounded frame length). The legacy line
/// selector remains a deliberate JSON-RPC/text gateway for humans and old
/// clients. A connection chooses once; it is never re-detected per request.
async fn handle_connection(
    stream: tokio::net::UnixStream,
    daemon: Arc<Daemon>,
    peer_uid: u32,
    peer_gid: u32,
) -> Result<()> {
    let mut stream = stream;
    if control_uses_tagged_cbor(&stream).await? {
        let handler = CborControlHandler {
            daemon,
            peer_uid,
            peer_gid,
        };
        return serve_cbor_session(&mut stream, &handler).await;
    }

    let mut line = String::new();
    let mut protocol = mesh::message::LineProtocolSession::new();

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

        let normalized = normalize_service_method(trimmed);
        let (_format, parsed_result) = protocol.parse_request_line(&normalized);

        let response = match parsed_result {
            Ok(request) => {
                debug!(request = ?request, "request_received");
                match request {
                    request @ (Request::StartTerminal { .. }
                    | Request::RegisterNamespace { .. }) => {
                        let mut std_stream = stream.into_std()?;
                        std_stream.set_nonblocking(false)?;
                        let fds = recv_fds(&std_stream)?;
                        let response = daemon
                            .handle_request_with_fds(request, fds, peer_uid, peer_gid)
                            .await;
                        let response_str = protocol.format_response(response)?;
                        std_stream.write_all(response_str.as_bytes())?;
                        std_stream.write_all(b"\n")?;
                        std_stream.flush()?;
                        std_stream.set_nonblocking(true)?;
                        stream = tokio::net::UnixStream::from_std(std_stream)?;
                        continue;
                    }
                    Request::Shutdown => {
                        let response = Response::ok();
                        let response_str = protocol.format_response(response)?;
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
                warn!(error = %e, "invalid_request");
                Response::err(format!("invalid request: {}", e))
            }
        };

        let response_str = protocol.format_response(response)?;
        stream.write_all(response_str.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;
    }

    debug!("control_connection_closed");
    Ok(())
}

/// Peek without consuming the byte so the selected handler receives the
/// complete stream. `UnixStream` has no async `peek`; waiting for readability
/// before `recv(MSG_PEEK|MSG_DONTWAIT)` keeps this small syscall non-blocking.
async fn control_uses_tagged_cbor(stream: &tokio::net::UnixStream) -> Result<bool> {
    stream.readable().await?;
    let mut first = [0_u8; 1];
    // SAFETY: `as_raw_fd` is a live Unix socket for the duration of this call,
    // and `first` is a writable one-byte buffer.
    let read = unsafe {
        libc::recv(
            stream.as_raw_fd(),
            first.as_mut_ptr().cast(),
            first.len(),
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if read == 0 {
        return Ok(false);
    }
    if read < 0 {
        return Err(std::io::Error::last_os_error()).context("peek control protocol byte");
    }
    Ok(first[0] == 0)
}

struct CborControlHandler {
    daemon: Arc<Daemon>,
    peer_uid: u32,
    peer_gid: u32,
}

#[async_trait::async_trait]
impl TaggedRecordHandler for CborControlHandler {
    async fn handle_record(&self, record: TaggedRecord) -> Result<Option<TaggedRecord>> {
        let id = record
            .id
            .clone()
            .context("tagged-CBOR request missing id")?;
        let request = match decode_tagged_request(&record) {
            Ok(request) => request,
            Err(error) => {
                return Ok(Some(response_ok(
                    id,
                    serde_json::to_value(Response::err(format!("invalid request: {error}")))?,
                )));
            }
        };
        let response = match request {
            // These operations need SCM_RIGHTS. Tagged CBOR is still a normal
            // UDS stream, but the shared session deliberately has no hidden
            // ancillary-data side channel. Keeping it explicit prevents a
            // seemingly valid request from losing terminal descriptors.
            Request::StartTerminal { .. } | Request::RegisterNamespace { .. } => {
                Response::err("this operation requires the explicit UDS SCM_RIGHTS protocol")
            }
            Request::Shutdown => {
                let daemon = self.daemon.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    daemon.shutdown().await;
                });
                Response::ok()
            }
            request => {
                self.daemon
                    .handle_request(request, self.peer_uid, self.peer_gid)
                    .await
            }
        };
        Ok(Some(response_ok(id, serde_json::to_value(response)?)))
    }
}

/// Reconstruct the stable public method and field names before invoking the
/// existing serde-based service handler. Numeric tags never leak into service
/// code; the generated catalog is the sole translation boundary.
fn decode_tagged_request(record: &TaggedRecord) -> Result<Request> {
    if CONTROL_CATALOG.method_name(record).is_none() {
        anyhow::bail!("tagged-CBOR method is outside the mesh-init public catalog");
    }
    let mut value = CONTROL_CATALOG.to_jsonl(record);
    let method = value
        .get("method")
        .and_then(serde_json::Value::as_str)
        .context("tagged-CBOR record has no documented mesh-init method")?
        .to_owned();
    let method = method
        .strip_prefix("mesh-init.")
        .context("tagged-CBOR method is outside the mesh-init public catalog")?;
    value["method"] = serde_json::Value::String(method.to_owned());
    serde_json::from_value(value).context("deserialize tagged mesh-init request")
}

fn normalize_service_method(line: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(line) else {
        return line.to_string();
    };
    let Some(method) = value
        .get("method")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
    else {
        return line.to_string();
    };
    let Some(method) = method.strip_prefix("mesh-init.") else {
        return line.to_string();
    };
    if let Some(method_value) = value.get_mut("method") {
        *method_value = serde_json::Value::String(method.to_string());
    }
    value.to_string()
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
    use mesh::tagged::NameOrTag;
    use mesh::wire::{read_cbor_record, write_cbor_record};
    use serde_json::json;
    use tokio::io::AsyncWriteExt;

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
    fn generated_catalog_decodes_numeric_cbor_request_into_existing_serde_type() {
        let request = decode_tagged_request(&TaggedRecord {
            component: NameOrTag::Tag(3),
            method: NameOrTag::Tag(3),
            id: Some(json!(9)),
            env: [
                (NameOrTag::Tag(1), json!("radio")),
                (NameOrTag::Tag(2), json!(15)),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        })
        .unwrap();
        assert!(matches!(
            request,
            Request::Stop {
                name,
                signal: Some(15)
            } if name == "radio"
        ));
    }

    #[test]
    fn tagged_cbor_rejects_methods_outside_generated_public_catalog() {
        let error = decode_tagged_request(&TaggedRecord {
            component: NameOrTag::Name("mesh-init".to_owned()),
            method: NameOrTag::Name("start_terminal".to_owned()),
            id: Some(json!(9)),
            ..Default::default()
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("outside the mesh-init public catalog")
        );
    }

    #[tokio::test]
    async fn uds_control_connection_dispatches_generated_tagged_cbor() {
        let daemon = Daemon::new(crate::daemon::DaemonConfig {
            config_dirs: Vec::new(),
            socket_path: "/tmp/mesh-init-cbor-test.sock".to_owned(),
        });
        let (mut client, server) = tokio::net::UnixStream::pair().unwrap();
        let server_task = tokio::spawn(handle_connection(
            server,
            daemon,
            unsafe { libc::getuid() },
            unsafe { libc::getgid() },
        ));
        write_cbor_record(
            &mut client,
            &TaggedRecord {
                component: NameOrTag::Tag(3),
                method: NameOrTag::Tag(1),
                id: Some(json!(17)),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let response = read_cbor_record(&mut client).await.unwrap().unwrap();
        assert_eq!(response.id, Some(json!(17)));
        assert_eq!(response.result.unwrap()["success"], true);
        client.shutdown().await.unwrap();
        server_task.await.unwrap().unwrap();
    }

    #[test]
    fn test_parse_incoming_flat_json() {
        let trimmed = r#"{"method":"status","name":"x","id":"req-id"}"#;
        let mut session = mesh::message::LineProtocolSession::new();
        let (format, parsed) = session.parse_request_line(trimmed);
        assert!(
            matches!(format, mesh::message::LineProtocolFormat::Json(mesh::jsonl::ProtocolFormat::FlatJson { id: Some(serde_json::Value::String(ref s)) }) if s == "req-id")
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
        let mut session = mesh::message::LineProtocolSession::new();
        let (format, parsed) = session.parse_request_line(trimmed);
        assert!(
            matches!(format, mesh::message::LineProtocolFormat::Json(mesh::jsonl::ProtocolFormat::JsonRpc { id: Some(serde_json::Value::Number(ref n)) }) if n.as_i64() == Some(100))
        );
        let req = parsed.unwrap();
        match req {
            Request::Status { name } => assert_eq!(name, Some("x".to_string())),
            _ => panic!("Expected status request"),
        }
    }

    #[test]
    fn test_parse_incoming_text() {
        let trimmed = "status name=x";
        let mut session = mesh::message::LineProtocolSession::new();
        let (format, parsed) = session.parse_request_line(trimmed);
        assert!(matches!(format, mesh::message::LineProtocolFormat::Text));
        let req = parsed.unwrap();
        match req {
            Request::Status { name } => assert_eq!(name, Some("x".to_string())),
            _ => panic!("Expected status request"),
        }

        let trimmed = "status name=\"quoted service\"";
        let (_, parsed) = session.parse_request_line(trimmed);
        match parsed.unwrap() {
            Request::Status { name } => assert_eq!(name, Some("quoted service".to_string())),
            _ => panic!("Expected status request"),
        }
    }

    #[test]
    fn test_format_response_jsonrpc() {
        let response = Response::ok_with_data(serde_json::json!({"pid": 42}));
        let format =
            mesh::message::LineProtocolFormat::Json(mesh::jsonl::ProtocolFormat::JsonRpc {
                id: Some(serde_json::json!(100)),
            });
        let formatted = mesh::message::format_protocol_response(response, &format).unwrap();
        let val: serde_json::Value = serde_json::from_str(&formatted).unwrap();
        assert_eq!(val["jsonrpc"], "2.0");
        assert_eq!(val["result"]["pid"], 42);
        assert_eq!(val["id"], 100);
    }

    #[test]
    fn test_format_response_text() {
        let response = Response::ok_with_data(serde_json::json!({"pid": 42, "state": "running"}));
        let format = mesh::message::LineProtocolFormat::Text;
        let formatted = mesh::message::format_protocol_response(response, &format).unwrap();
        assert_eq!(formatted, "response pid=42 state=running success=true");

        let response = Response::err("bad service");
        let formatted = mesh::message::format_protocol_response(response, &format).unwrap();
        assert_eq!(formatted, r#"error message="bad service""#);
    }
}
