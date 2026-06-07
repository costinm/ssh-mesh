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
use tracing::{debug, error, info, warn};

use crate::daemon::Daemon;
use crate::protocol::{Request, Response};

// ============================================================================
// Control Server
// ============================================================================

/// UDS control server that dispatches JSON-lines protocol requests to the daemon.
pub struct ControlServer {
    socket_path: String,
    daemon: Arc<Daemon>,
}

impl ControlServer {
    /// Create a new control server.
    pub fn new(socket_path: String, daemon: Arc<Daemon>) -> Self {
        Self {
            socket_path,
            daemon,
        }
    }

    /// Run the control server accept loop.
    ///
    /// Removes any stale socket file, binds, and accepts connections in a loop.
    /// Each connection is handled in a separate task.
    pub async fn run(&self) -> Result<()> {
        // Clean up stale socket
        let _ = std::fs::remove_file(&self.socket_path);

        // Ensure parent directory exists
        if let Some(parent) = std::path::Path::new(&self.socket_path).parent() {
            let _ = std::fs::create_dir_all(parent);
            if let Ok(metadata) = std::fs::metadata(parent) {
                let mut perms = metadata.permissions();
                std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o770);
                let _ = std::fs::set_permissions(parent, perms);
            }
        }

        let listener = UnixListener::bind(&self.socket_path)?;

        // Set permissions so root/owner/group can connect
        let mut perms = std::fs::metadata(&self.socket_path)?.permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o660);
        std::fs::set_permissions(&self.socket_path, perms)?;

        info!("Control server listening on {}", self.socket_path);

        let current_uid = unsafe { libc::getuid() };

        loop {
            let (stream, _) = listener.accept().await?;

            // Verify peer credentials
            let peer_cred = match stream.peer_cred() {
                Ok(cred) => cred,
                Err(e) => {
                    warn!("Failed to get peer credentials: {}", e);
                    continue;
                }
            };

            let peer_uid = peer_cred.uid();

            // Use daemon's auth config if available, otherwise fallback to root+self
            let is_authorized = {
                let configs = self.daemon.configs.lock();
                // Check if any loaded config has auth rules
                let auth = configs.values().find_map(|c| c.auth.as_ref());
                match auth {
                    Some(auth_config) => auth_config.is_uid_authorized(peer_uid, current_uid),
                    None => peer_uid == 0 || peer_uid == current_uid,
                }
            };
            if !is_authorized {
                error!(
                    "Rejected connection from UID {} (expected 0 or {})",
                    peer_uid, current_uid
                );
                continue;
            }

            debug!("Accepted control connection from UID {}", peer_uid);

            let daemon = self.daemon.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, daemon).await {
                    error!("Control connection error: {}", e);
                }
            });
        }
    }
}

/// Handle a single control connection.
///
/// Reads JSON lines from the stream, dispatches each to the daemon,
/// and writes back JSON responses.
async fn handle_connection(stream: tokio::net::UnixStream, daemon: Arc<Daemon>) -> Result<()> {
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

        let response = match serde_json::from_str::<Request>(trimmed) {
            Ok(request) => {
                debug!("Received request: {:?}", request);
                match request {
                    request @ Request::StartTerminal { .. } => {
                        let mut std_stream = stream.into_std()?;
                        std_stream.set_nonblocking(false)?;
                        let fd = recv_one_fd(&std_stream)?;
                        let response = daemon.handle_request_with_fd(request, fd).await;
                        let response_json = serde_json::to_string(&response)?;
                        std_stream.write_all(response_json.as_bytes())?;
                        std_stream.write_all(b"\n")?;
                        std_stream.flush()?;
                        return Ok(());
                    }
                    request => daemon.handle_request(request).await,
                }
            }
            Err(e) => {
                warn!("Invalid request: {}", e);
                Response::err(format!("invalid request: {}", e))
            }
        };

        let response_json = serde_json::to_string(&response)?;
        stream.write_all(response_json.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;
    }

    debug!("Control connection closed");
    Ok(())
}

async fn read_json_line(stream: &mut tokio::net::UnixStream, line: &mut String) -> Result<usize> {
    let mut bytes_read = 0;
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Ok(bytes_read);
        }
        bytes_read += n;
        line.push(byte[0] as char);
        if byte[0] == b'\n' {
            return Ok(bytes_read);
        }
    }
}

fn recv_one_fd(stream: &std::os::unix::net::UnixStream) -> Result<OwnedFd> {
    let mut buf = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsgspace = cmsg_space!([std::os::fd::RawFd; 1]);
    let msg = recvmsg::<()>(
        stream.as_raw_fd(),
        &mut iov,
        Some(&mut cmsgspace),
        MsgFlags::empty(),
    )?;

    for cmsg in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg
            && let Some(fd) = fds.first()
        {
            // SAFETY: recvmsg transferred ownership of this descriptor.
            return Ok(unsafe { OwnedFd::from_raw_fd(*fd) });
        }
    }

    anyhow::bail!("missing passed file descriptor")
}

// ============================================================================
// Client
// ============================================================================

/// Send a single request to a running daemon and return the response.
pub async fn send_request(socket_path: &str, request: &Request) -> Result<Response> {
    let stream = tokio::net::UnixStream::connect(socket_path)
        .await
        .context("failed to connect to mesh-init daemon")?;
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
}
