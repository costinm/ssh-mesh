/// OpenSSH Control Master mux protocol server.
///
/// Implements the server side of the multiplexing protocol described in
/// PROTOCOL.mux. When a `mux_dir` is configured, each SSH connection
/// creates a Unix domain socket that external mux clients can connect to.
///
/// Socket naming: `ssh-<user>@<host>` (mirrors OpenSSH `%r@%n`).
use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use russh::{ChannelMsg, client};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::{Mutex, watch};

use super::sshc::ClientHandler;
pub use mesh::mux::*;

// ---------------------------------------------------------------------------
// MuxServer — listens on a UDS and serves mux clients
// ---------------------------------------------------------------------------

/// Mux server for a single SSH connection.
pub struct MuxServer {
    pub socket_path: PathBuf,
    #[allow(dead_code)]
    session: Arc<Mutex<client::Handle<ClientHandler>>>,
    cancel_tx: watch::Sender<bool>,
    _task: Option<tokio::task::JoinHandle<()>>,
}

impl MuxServer {
    /// Create and start a mux server.
    ///
    /// * `socket_path` — path for the Unix domain socket
    /// * `session` — the russh client session handle to multiplex over
    pub fn start(
        socket_path: PathBuf,
        session: Arc<Mutex<client::Handle<ClientHandler>>>,
    ) -> Result<Arc<Self>> {
        // Remove stale socket if present
        if socket_path.exists() {
            let _ = std::fs::remove_file(&socket_path);
        }

        // Ensure parent directory exists
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent).context("create mux socket directory")?;
        }

        let listener =
            std::os::unix::net::UnixListener::bind(&socket_path).context("bind mux socket")?;
        listener.set_nonblocking(true)?;
        let listener = UnixListener::from_std(listener)?;

        info!("Mux server listening on {:?}", socket_path);

        let (cancel_tx, cancel_rx) = watch::channel(false);
        let session_clone = session.clone();
        let path_clone = socket_path.clone();

        let task = tokio::spawn(async move {
            Self::accept_loop(listener, session_clone, cancel_rx, &path_clone).await;
        });

        Ok(Arc::new(Self {
            socket_path,
            session,
            cancel_tx,
            _task: Some(task),
        }))
    }

    /// Stop listening and clean up the socket file.
    pub fn stop(&self) {
        let _ = self.cancel_tx.send(true);
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
            info!("Removed mux socket {:?}", self.socket_path);
        }
    }

    async fn accept_loop(
        listener: UnixListener,
        session: Arc<Mutex<client::Handle<ClientHandler>>>,
        mut cancel_rx: watch::Receiver<bool>,
        _path: &Path,
    ) {
        loop {
            tokio::select! {
                _ = cancel_rx.changed() => {
                    debug!("Mux accept loop cancelled");
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((stream, _addr)) => {
                            let session = session.clone();
                            let cancel_rx = cancel_rx.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_mux_client(stream, session, cancel_rx).await {
                                    debug!("Mux client session ended: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Mux accept error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    }
}

impl Drop for MuxServer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Construct the mux socket path for a connection.
pub fn mux_socket_path(mux_dir: &Path, user: &str, host: &str) -> PathBuf {
    mux_dir.join(format!("ssh-{}@{}", user, host))
}

// ---------------------------------------------------------------------------
// Per-client mux session handler
// ---------------------------------------------------------------------------

async fn handle_mux_client(
    mut stream: tokio::net::UnixStream,
    session: Arc<Mutex<client::Handle<ClientHandler>>>,
    mut cancel_rx: watch::Receiver<bool>,
) -> Result<()> {
    // 1. Send our hello
    let mut hello = payload_with_type(MUX_MSG_HELLO);
    push_u32(&mut hello, MUX_PROTOCOL_VERSION);
    stream
        .write_all(&build_packet(&hello))
        .await
        .context("send hello")?;

    // 2. Read client hello
    let (msg_type, payload) = read_packet(&mut stream)
        .await
        .context("read client hello")?;
    if msg_type != MUX_MSG_HELLO {
        anyhow::bail!("expected MUX_MSG_HELLO, got 0x{:08x}", msg_type);
    }
    if payload.len() < 4 {
        anyhow::bail!("client hello too short");
    }
    let client_version = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if client_version != MUX_PROTOCOL_VERSION {
        warn!(
            "Mux client version {} != our version {}",
            client_version, MUX_PROTOCOL_VERSION
        );
    }
    debug!("Mux client hello: version {}", client_version);

    // 3. Message loop
    let mut next_session_id: u32 = 1;
    loop {
        tokio::select! {
            _ = cancel_rx.changed() => {
                debug!("Mux client handler cancelled");
                break;
            }
            result = read_packet(&mut stream) => {
                let (msg_type, payload) = match result {
                    Ok(v) => v,
                    Err(_) => {
                        debug!("Mux client disconnected");
                        break;
                    }
                };
                match msg_type {
                    MUX_C_ALIVE_CHECK => {
                        handle_alive_check(&mut stream, &payload).await?;
                    }
                    MUX_C_NEW_SESSION => {
                        let sid = next_session_id;
                        next_session_id += 1;
                        handle_new_session(&mut stream, &payload, &session, sid).await?;
                    }
                    MUX_C_OPEN_FWD => {
                        handle_open_fwd(&mut stream, &payload, &session, cancel_rx.clone()).await?;
                    }
                    MUX_C_CLOSE_FWD => {
                        handle_close_fwd(&mut stream, &payload).await?;
                    }
                    MUX_C_TERMINATE => {
                        handle_terminate(&mut stream, &payload).await?;
                        break;
                    }
                    MUX_C_STOP_LISTENING => {
                        handle_stop_listening(&mut stream, &payload).await?;
                    }
                    _ => {
                        warn!("Unknown mux message type: 0x{:08x}", msg_type);
                        // Send failure
                        if payload.len() >= 4 {
                            let req_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                            let mut resp = payload_with_type(MUX_S_FAILURE);
                            push_u32(&mut resp, req_id);
                            push_string(&mut resp, "unsupported message type");
                            stream.write_all(&build_packet(&resp)).await?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Individual message handlers
// ---------------------------------------------------------------------------

async fn handle_alive_check(stream: &mut tokio::net::UnixStream, payload: &[u8]) -> Result<()> {
    let (req_id, _) = parse_u32(payload, 0)?;
    let pid = std::process::id();
    debug!(
        "Mux alive check: req_id={}, responding with pid={}",
        req_id, pid
    );

    let mut resp = payload_with_type(MUX_S_ALIVE);
    push_u32(&mut resp, req_id);
    push_u32(&mut resp, pid);
    stream.write_all(&build_packet(&resp)).await?;
    Ok(())
}

async fn handle_new_session(
    stream: &mut tokio::net::UnixStream,
    payload: &[u8],
    session: &Arc<Mutex<client::Handle<ClientHandler>>>,
    session_id: u32,
) -> Result<()> {
    // Parse request:
    //   u32 request_id
    //   string reserved
    //   bool want_tty
    //   bool want_x11
    //   bool want_agent
    //   bool subsystem
    //   u32 escape_char
    //   string terminal_type
    //   string command
    let (req_id, off) = parse_u32(payload, 0)?;
    let (_reserved, off) = parse_string(payload, off)?;
    let (want_tty, off) = parse_u32(payload, off)?;
    let (_want_x11, off) = parse_u32(payload, off)?;
    let (_want_agent, off) = parse_u32(payload, off)?;
    let (subsystem, off) = parse_u32(payload, off)?;
    let (_escape_char, off) = parse_u32(payload, off)?;
    let (_term, off) = parse_string(payload, off)?;
    let (command, _off) = parse_string(payload, off)?;

    info!(
        "Mux new session: req_id={}, want_tty={}, subsystem={}, cmd={:?}",
        req_id,
        want_tty != 0,
        subsystem != 0,
        command
    );

    // Open a channel on the SSH connection
    let mut channel = {
        let handle = session.lock().await;
        handle.channel_open_session().await?
    };

    // Request PTY if wanted
    if want_tty != 0 {
        channel
            .request_pty(false, "xterm", 80, 24, 0, 0, &[])
            .await?;
    }

    // Execute command or shell
    if !command.is_empty() {
        if subsystem != 0 {
            channel.request_subsystem(true, command.as_str()).await?;
        } else {
            channel.exec(true, command.as_str()).await?;
        }
    } else {
        channel.request_shell(true).await?;
    }

    // Send SESSION_OPENED
    let mut resp = payload_with_type(MUX_S_SESSION_OPENED);
    push_u32(&mut resp, req_id);
    push_u32(&mut resp, session_id);
    stream.write_all(&build_packet(&resp)).await?;

    // Try to receive FDs (stdin, stdout, stderr)
    // We expect 3 messages, each with 1 FD.
    let stdin_fd = recv_fd(stream).await.context("recv stdin fd")?;
    let stdout_fd = recv_fd(stream).await.context("recv stdout fd")?;
    let stderr_fd = recv_fd(stream).await.context("recv stderr fd")?;

    let mut stdin_file = tokio::fs::File::from_std(std::fs::File::from(stdin_fd));
    let mut stdout_file = tokio::fs::File::from_std(std::fs::File::from(stdout_fd));
    let mut stderr_file = tokio::fs::File::from_std(std::fs::File::from(stderr_fd));

    let mut buf = [0u8; 32768];
    let mut stdin_closed = false;
    let mut exit_code = 0;

    loop {
        tokio::select! {
            r = stdin_file.read(&mut buf), if !stdin_closed => {
                match r {
                    Ok(0) => {
                        stdin_closed = true;
                        channel.eof().await?;
                    }
                    Ok(n) => {
                        channel.data(&buf[..n]).await?;
                    }
                    Err(e) => {
                        warn!("Error reading stdin: {}", e);
                        stdin_closed = true;
                    }
                }
            }
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        stdout_file.write_all(&data).await?;
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        stderr_file.write_all(&data).await?;
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        exit_code = exit_status;
                    }
                    Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    // Send exit message
    let mut exit_msg = payload_with_type(MUX_S_EXIT_MESSAGE);
    push_u32(&mut exit_msg, session_id);
    push_u32(&mut exit_msg, exit_code);
    stream.write_all(&build_packet(&exit_msg)).await?;

    debug!("Mux session {} exited with code {}", session_id, exit_code);
    Ok(())
}

async fn handle_open_fwd(
    stream: &mut tokio::net::UnixStream,
    payload: &[u8],
    session: &Arc<Mutex<client::Handle<ClientHandler>>>,
    cancel_rx: watch::Receiver<bool>,
) -> Result<()> {
    // Parse:
    //   u32 request_id
    //   u32 fwd_type
    //   string listen_host
    //   u32 listen_port
    //   string connect_host
    //   u32 connect_port
    let (req_id, off) = parse_u32(payload, 0)?;
    let (fwd_type, off) = parse_u32(payload, off)?;
    let (listen_host, off) = parse_string(payload, off)?;
    let (listen_port, off) = parse_u32(payload, off)?;
    let (connect_host, off) = parse_string(payload, off)?;
    let (connect_port, _) = parse_u32(payload, off)?;

    info!(
        "Mux open fwd: type={}, {}:{} -> {}:{}",
        fwd_type, listen_host, listen_port, connect_host, connect_port
    );

    match fwd_type {
        MUX_FWD_REMOTE => {
            // Ask SSH server to listen on remote side
            let handle = session.lock().await;

            if listen_port == super::sshd::UDS_FORWARD_PORT
                || connect_port == super::sshd::UDS_FORWARD_PORT
            {
                // Streamlocal forwarding (UDS)
                info!("Requesting remote streamlocal forward for {}", listen_host);

                match handle.streamlocal_forward(&listen_host).await {
                    Ok(()) => {
                        let mut resp = payload_with_type(MUX_S_OK);
                        push_u32(&mut resp, req_id);
                        stream.write_all(&build_packet(&resp)).await?;
                    }
                    Err(e) => {
                        let msg = format!("{}", e);
                        let mut resp = payload_with_type(MUX_S_FAILURE);
                        push_u32(&mut resp, req_id);
                        push_string(&mut resp, &msg);
                        stream.write_all(&build_packet(&resp)).await?;
                    }
                }
            } else {
                match handle.tcpip_forward(&listen_host, listen_port).await {
                    Ok(actual_port) => {
                        if listen_port == 0 {
                            // Dynamic port — send REMOTE_PORT
                            let mut resp = payload_with_type(MUX_S_REMOTE_PORT);
                            push_u32(&mut resp, req_id);
                            push_u32(&mut resp, actual_port);
                            stream.write_all(&build_packet(&resp)).await?;
                        } else {
                            let mut resp = payload_with_type(MUX_S_OK);
                            push_u32(&mut resp, req_id);
                            stream.write_all(&build_packet(&resp)).await?;
                        }
                    }
                    Err(e) => {
                        let mut resp = payload_with_type(MUX_S_FAILURE);
                        push_u32(&mut resp, req_id);
                        push_string(&mut resp, &e.to_string());
                        stream.write_all(&build_packet(&resp)).await?;
                    }
                }
            }
        }
        MUX_FWD_LOCAL | MUX_FWD_DYNAMIC => {
            // Local/dynamic forwarding — start a local TCP listener
            let bind_addr = format!("{}:{}", listen_host, listen_port);
            match tokio::net::TcpListener::bind(&bind_addr).await {
                Ok(listener) => {
                    let actual_port = listener.local_addr()?.port();
                    let session = session.clone();
                    let connect_host = connect_host.clone();

                    let mut cancel_rx_clone = cancel_rx.clone();
                    tokio::spawn(async move {
                        loop {
                            tokio::select! {
                                _ = cancel_rx_clone.changed() => {
                                    debug!("Mux local fwd listener cancelled");
                                    break;
                                }
                                result = listener.accept() => {
                                    match result {
                                        Ok((tcp_stream, _)) => {
                                            let session = session.clone();
                                            let ch = connect_host.clone();
                                            let cp = connect_port as u16;
                                            if listen_port == super::sshd::UDS_FORWARD_PORT
                                                || connect_port == super::sshd::UDS_FORWARD_PORT
                                            {
                                                warn!("Local UDS forwarding not implemented in mux server yet");
                                                return;
                                            }
                                            tokio::spawn(async move {
                                                if let Err(e) = super::sshc::handle_local_forward(
                                                    tcp_stream, session, &ch, cp,
                                                )
                                                .await
                                                {
                                                    debug!("Mux local forward error: {}", e);
                                                }
                                            });
                                        }
                                        Err(e) => {
                                            error!("Mux local fwd accept error: {}", e);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    });

                    if listen_port == 0 {
                        let mut resp = payload_with_type(MUX_S_REMOTE_PORT);
                        push_u32(&mut resp, req_id);
                        push_u32(&mut resp, actual_port as u32);
                        stream.write_all(&build_packet(&resp)).await?;
                    } else {
                        let mut resp = payload_with_type(MUX_S_OK);
                        push_u32(&mut resp, req_id);
                        stream.write_all(&build_packet(&resp)).await?;
                    }
                }
                Err(e) => {
                    let mut resp = payload_with_type(MUX_S_FAILURE);
                    push_u32(&mut resp, req_id);
                    push_string(&mut resp, &e.to_string());
                    stream.write_all(&build_packet(&resp)).await?;
                }
            }
        }
        _ => {
            let mut resp = payload_with_type(MUX_S_FAILURE);
            push_u32(&mut resp, req_id);
            push_string(&mut resp, "unknown forwarding type");
            stream.write_all(&build_packet(&resp)).await?;
        }
    }

    Ok(())
}

async fn handle_close_fwd(stream: &mut tokio::net::UnixStream, payload: &[u8]) -> Result<()> {
    let (req_id, _off) = parse_u32(payload, 0)?;
    // TODO: actually track and close the forward
    info!("Mux close fwd: req_id={} (not fully implemented)", req_id);
    let mut resp = payload_with_type(MUX_S_OK);
    push_u32(&mut resp, req_id);
    stream.write_all(&build_packet(&resp)).await?;
    Ok(())
}

async fn handle_terminate(stream: &mut tokio::net::UnixStream, payload: &[u8]) -> Result<()> {
    let (req_id, _) = parse_u32(payload, 0)?;
    info!("Mux terminate request: req_id={}", req_id);
    let mut resp = payload_with_type(MUX_S_OK);
    push_u32(&mut resp, req_id);
    stream.write_all(&build_packet(&resp)).await?;
    Ok(())
}

async fn handle_stop_listening(stream: &mut tokio::net::UnixStream, payload: &[u8]) -> Result<()> {
    let (req_id, _) = parse_u32(payload, 0)?;
    info!("Mux stop listening: req_id={}", req_id);
    let mut resp = payload_with_type(MUX_S_OK);
    push_u32(&mut resp, req_id);
    stream.write_all(&build_packet(&resp)).await?;
    Ok(())
}

// Make handle_local_forward accessible for the mux module
// (it's already pub(crate) in sshc.rs — we call it via super::sshc::handle_local_forward)
