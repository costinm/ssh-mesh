use crate::auth::{AuthConfig, DelegationEnvelope};
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufStream, ReadBuf};
use tokio::net::{UnixListener, UnixStream};
use tracing::{error, info, warn};

/// Set `FD_CLOEXEC` on an existing file descriptor.
///
/// Best-effort: logs a warning on failure. This prevents the FD from being
/// inherited by child processes spawned via `execve()`.
fn set_cloexec(fd: i32) {
    // SAFETY: fd is a valid open file descriptor. F_GETFD/F_SETFD do not
    // have undefined behavior on valid fds.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return;
    }
    if flags & libc::FD_CLOEXEC == 0 {
        // SAFETY: as above.
        let _ = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    }
}

pub enum MeshStream {
    Uds(UnixStream),
    /// A UDS stream that has had its read side buffered (e.g. after consuming a
    /// leading delegation envelope line). Buffered bytes are preserved for
    /// subsequent reads.
    UdsBuf(BufStream<UnixStream>),
    Stdio {
        stdin: tokio::io::Stdin,
        stdout: tokio::io::Stdout,
    },
}

impl AsyncRead for MeshStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            MeshStream::Uds(s) => Pin::new(s).poll_read(cx, buf),
            MeshStream::UdsBuf(s) => Pin::new(s).poll_read(cx, buf),
            MeshStream::Stdio { stdin, .. } => Pin::new(stdin).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MeshStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            MeshStream::Uds(s) => Pin::new(s).poll_write(cx, buf),
            MeshStream::UdsBuf(s) => Pin::new(s).poll_write(cx, buf),
            MeshStream::Stdio { stdout, .. } => Pin::new(stdout).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            MeshStream::Uds(s) => Pin::new(s).poll_flush(cx),
            MeshStream::UdsBuf(s) => Pin::new(s).poll_flush(cx),
            MeshStream::Stdio { stdout, .. } => Pin::new(stdout).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            MeshStream::Uds(s) => Pin::new(s).poll_shutdown(cx),
            MeshStream::UdsBuf(s) => Pin::new(s).poll_shutdown(cx),
            MeshStream::Stdio { stdout, .. } => Pin::new(stdout).poll_shutdown(cx),
        }
    }
}

enum ListenerMode {
    Uds(UnixListener),
    Stdio(bool), // bool is `has_yielded`
}

pub struct MeshListener {
    mode: ListenerMode,
    auth: Option<AuthConfig>,
    current_uid: u32,
    /// When true, peer UIDs configured as delegates must send a validated
    /// `DelegationEnvelope` as the first line of the connection. Opt-in via the
    /// `MESH_ENFORCE_DELEGATION` env var. Defaults to `false` for backward
    /// compatibility.
    enforce_delegation: bool,
}

impl MeshListener {
    pub fn new(
        app_name: &str,
        listen_path: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let auth = AuthConfig::load_for_app(app_name);
        let current_uid = unsafe { libc::getuid() };
        let enforce_delegation = std::env::var("MESH_ENFORCE_DELEGATION")
            .map(|v| {
                let v = v.trim();
                v.eq_ignore_ascii_case("1") || v.eq_ignore_ascii_case("true") || v == "yes"
            })
            .unwrap_or(false);

        let mode = if let Ok(fd_str) = std::env::var("LISTEN_FD") {
            if let Ok(fd) = fd_str.parse::<i32>() {
                info!("MeshListener: Using activated listener FD {}", fd);
                // SAFETY: the FD was passed by the parent (systemd-style socket
                // activation) and is a valid UnixListener fd owned by us.
                let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
                std_listener.set_nonblocking(true)?;
                // Ensure close-on-exec so the listener does not leak into child
                // processes spawned by handlers (e.g. exec, terminal).
                set_cloexec(std_listener.as_raw_fd());
                ListenerMode::Uds(UnixListener::from_std(std_listener)?)
            } else {
                return Err("Invalid LISTEN_FD".into());
            }
        } else if let Some(path_str) = listen_path {
            let actual_path = if path_str.starts_with('_') {
                path_str.replacen('_', "\0", 1)
            } else if path_str.starts_with('/') {
                path_str.to_string()
            } else {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                let dir = format!("{}/.run/{}", home, app_name);
                let _ = std::fs::create_dir_all(&dir);
                format!("{}/{}", dir, path_str)
            };

            if !actual_path.starts_with('\0') {
                let path = std::path::Path::new(&actual_path);
                if path.exists() {
                    let _ = std::fs::remove_file(path);
                }
            }
            let listener = UnixListener::bind(&actual_path)?;
            info!("MeshListener: Listening on UDS {:?}", actual_path);

            if !actual_path.starts_with('\0') {
                // Set permissions to 0660
                let mut perms = std::fs::metadata(&actual_path)?.permissions();
                perms.set_mode(0o660);
                std::fs::set_permissions(&actual_path, perms)?;
            }

            ListenerMode::Uds(listener)
        } else {
            info!("MeshListener: Serving over stdin/stdout");
            ListenerMode::Stdio(false)
        };

        Ok(Self {
            mode,
            auth,
            current_uid,
            enforce_delegation,
        })
    }

    pub async fn accept(&mut self) -> Result<Option<MeshStream>, Box<dyn std::error::Error>> {
        match &mut self.mode {
            ListenerMode::Uds(listener) => loop {
                let (stream, _) = listener.accept().await?;
                let peer_uid = stream.peer_cred()?.uid();

                let auth = self.auth.as_ref();
                let is_authorized = match auth {
                    Some(a) => a.is_uid_authorized(peer_uid, self.current_uid),
                    None => crate::auth::AuthConfig::is_builtin_uid_authorized(
                        peer_uid,
                        self.current_uid,
                    ),
                };

                if !is_authorized {
                    error!(
                        "MeshListener: Unauthorized UDS connection from UID {}",
                        peer_uid
                    );
                    continue;
                }

                // Delegation enforcement: if the peer UID is configured as a
                // trusted delegate, require a DelegationEnvelope as the first
                // line and validate it before serving any HTTP. This prevents a
                // delegate (e.g. sshd) from asserting arbitrary identities.
                if self.enforce_delegation
                    && let Some(a) = auth
                    && a.get_delegate(peer_uid).is_some()
                {
                    match Self::read_and_validate_delegation(stream, a, peer_uid).await {
                        Ok(buf_stream) => return Ok(Some(MeshStream::UdsBuf(buf_stream))),
                        Err(reason) => {
                            warn!(
                                "MeshListener: rejecting delegated connection from UID {}: {}",
                                peer_uid, reason
                            );
                            continue;
                        }
                    }
                }

                return Ok(Some(MeshStream::Uds(stream)));
            },
            ListenerMode::Stdio(yielded) => {
                if *yielded {
                    return Ok(None);
                }
                *yielded = true;

                // For stdio mode, mesh-init handles auth checking prior to activation
                // No need to check X_PEER_UID here.
                Ok(Some(MeshStream::Stdio {
                    stdin: tokio::io::stdin(),
                    stdout: tokio::io::stdout(),
                }))
            }
        }
    }

    /// Read the leading `DelegationEnvelope` line from a delegate connection
    /// and validate it against the auth config. On success returns the
    /// buffered stream (preserving any HTTP bytes already read).
    async fn read_and_validate_delegation(
        stream: UnixStream,
        auth: &AuthConfig,
        delegate_uid: u32,
    ) -> Result<BufStream<UnixStream>, String> {
        let mut buf_stream = BufStream::new(stream);
        // Cap the envelope line at 8 KiB to prevent unbounded reads.
        const MAX_ENVELOPE_LEN: usize = 8 * 1024;
        let mut line = Vec::with_capacity(256);
        loop {
            let buffered = buf_stream
                .fill_buf()
                .await
                .map_err(|e| format!("read error: {e}"))?;
            if buffered.is_empty() {
                return Err("connection closed before delegation envelope".to_string());
            }
            if let Some(pos) = buffered.iter().position(|&b| b == b'\n') {
                line.extend_from_slice(&buffered[..pos]);
                // Consume only up to and including the newline; bytes after it
                // remain in BufStream's buffer for subsequent HTTP reads.
                buf_stream.consume(pos + 1);
                break;
            }
            // No newline yet: accumulate the whole buffer and keep filling.
            line.extend_from_slice(buffered);
            let n = buffered.len();
            buf_stream.consume(n);
            if line.len() > MAX_ENVELOPE_LEN {
                return Err("delegation envelope exceeds 8 KiB".to_string());
            }
        }

        let envelope: DelegationEnvelope = serde_json::from_slice(&line)
            .map_err(|e| format!("invalid delegation envelope JSON: {e}"))?;

        auth.validate_delegation(delegate_uid, &envelope.peer)
            .map_err(|e| format!("delegation rejected: {e}"))?;

        if !auth.is_peer_allowed(&envelope.peer) {
            return Err(format!(
                "delegated identity {:?} not permitted by peer allowlist",
                envelope.peer
            ));
        }

        Ok(buf_stream)
    }
}

pub async fn run_axum_server(
    app_name: &str,
    listen_path: Option<&str>,
    app: axum::Router,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut listener = MeshListener::new(app_name, listen_path)?;

    while let Some(stream) = listener.accept().await? {
        let app_clone = app.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, TowerToHyperService::new(app_clone))
                .with_upgrades()
                .await
            {
                let err_str = err.to_string();
                if !err_str.contains("connection error: not connected")
                    && !err_str.contains("early eof")
                {
                    error!("Error serving HTTP connection: {:?}", err);
                }
            }
        });
    }

    Ok(())
}
