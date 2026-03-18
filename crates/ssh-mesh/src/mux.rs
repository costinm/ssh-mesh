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

// ---------------------------------------------------------------------------
// Protocol constants (from PROTOCOL.mux §11)
// ---------------------------------------------------------------------------

pub const MUX_MSG_HELLO: u32 = 0x0000_0001;
pub const MUX_C_NEW_SESSION: u32 = 0x1000_0002;
pub const MUX_C_ALIVE_CHECK: u32 = 0x1000_0004;
pub const MUX_C_TERMINATE: u32 = 0x1000_0005;
pub const MUX_C_OPEN_FWD: u32 = 0x1000_0006;
pub const MUX_C_CLOSE_FWD: u32 = 0x1000_0007;
pub const MUX_C_NEW_STDIO_FWD: u32 = 0x1000_0008;
pub const MUX_C_STOP_LISTENING: u32 = 0x1000_0009;

pub const MUX_S_OK: u32 = 0x8000_0001;
pub const MUX_S_PERMISSION_DENIED: u32 = 0x8000_0002;
pub const MUX_S_FAILURE: u32 = 0x8000_0003;
pub const MUX_S_EXIT_MESSAGE: u32 = 0x8000_0004;
pub const MUX_S_ALIVE: u32 = 0x8000_0005;
pub const MUX_S_SESSION_OPENED: u32 = 0x8000_0006;
pub const MUX_S_REMOTE_PORT: u32 = 0x8000_0007;
#[allow(dead_code)]
pub const MUX_S_TTY_ALLOC_FAIL: u32 = 0x8000_0008;

pub const MUX_FWD_LOCAL: u32 = 1;
pub const MUX_FWD_REMOTE: u32 = 2;
#[allow(dead_code)]
pub const MUX_FWD_DYNAMIC: u32 = 3;

pub const MUX_PROTOCOL_VERSION: u32 = 4;

// ---------------------------------------------------------------------------
// Wire format helpers
// ---------------------------------------------------------------------------

/// Read a big-endian u32 from async reader.
pub async fn read_u32<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf).await.context("read u32")?;
    Ok(u32::from_be_bytes(buf))
}

/// Write a big-endian u32 to async writer.
pub async fn write_u32<W: AsyncWriteExt + Unpin>(w: &mut W, v: u32) -> Result<()> {
    w.write_all(&v.to_be_bytes()).await.context("write u32")
}

/// Read an SSH-style string (u32 length + bytes).
pub async fn read_string<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<String> {
    let len = read_u32(r).await? as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await.context("read string body")?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Write an SSH-style string (u32 length + bytes).
pub async fn write_string<W: AsyncWriteExt + Unpin>(w: &mut W, s: &str) -> Result<()> {
    write_u32(w, s.len() as u32).await?;
    w.write_all(s.as_bytes()).await.context("write string body")
}

/// Read a bool (u32: 0 = false, non-zero = true).
pub async fn read_bool<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<bool> {
    Ok(read_u32(r).await? != 0)
}

/// Read an entire mux packet, returning (msg_type, payload_bytes).
pub async fn read_packet<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<(u32, Vec<u8>)> {
    let pkt_len = read_u32(r).await.context("read packet length")?;
    if pkt_len < 4 {
        anyhow::bail!("mux packet too short: {}", pkt_len);
    }
    let mut buf = vec![0u8; pkt_len as usize];
    r.read_exact(&mut buf).await.context("read packet body")?;
    let msg_type = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    Ok((msg_type, buf[4..].to_vec()))
}

/// Build a complete mux packet from payload bytes (prepends length).
pub fn build_packet(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut pkt = Vec::with_capacity(4 + payload.len());
    pkt.extend_from_slice(&len.to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

/// Build a packet payload starting with msg_type, followed by fields.
/// Fields are appended by the caller before wrapping with `build_packet`.
pub fn payload_with_type(msg_type: u32) -> Vec<u8> {
    msg_type.to_be_bytes().to_vec()
}

/// Append a u32 to a payload buffer.
pub fn push_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Append an SSH string to a payload buffer.
pub fn push_string(buf: &mut Vec<u8>, s: &str) {
    push_u32(buf, s.len() as u32);
    buf.extend_from_slice(s.as_bytes());
}

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
                        handle_open_fwd(&mut stream, &payload, &session).await?;
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

async fn recv_fd_blocking(stream: &tokio::net::UnixStream) -> Result<std::os::unix::io::RawFd> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
    use std::io::IoSliceMut;
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();

    loop {
        stream.readable().await?;

        // Peek to see if we have data/errors
        let mut buf = [0u8; 1];
        let mut iov = [IoSliceMut::new(&mut buf)];
        let mut cmsg_space = nix::cmsg_space!(std::os::unix::io::RawFd);

        match recvmsg::<nix::sys::socket::UnixAddr>(
            fd,
            &mut iov,
            Some(&mut cmsg_space),
            MsgFlags::empty(),
        ) {
            Ok(msg) => {
                let mut received_fd = None;
                let mut cmsg_iter = msg.cmsgs()?;
                while let Some(cmsg_item) = cmsg_iter.next() {
                    match cmsg_item {
                        ControlMessageOwned::ScmRights(fds) => {
                            if !fds.is_empty() {
                                received_fd = Some(fds[0]);
                            }
                        }
                        _ => {}
                    }
                }

                if let Some(f) = received_fd {
                    return Ok(f);
                } else {
                    // We read bytes but no FD? This is unexpected for the 1-byte dummy + FD protocol.
                    // But if we just got the dummy byte without FD (shouldn't happen with SCM_RIGHTS if sent together),
                    // or maybe we got some other traffic?
                    // For now, retry? Or error?
                    // If we consumed the dummy byte but didn't get FD, we might be desyncing.
                    // However, standard behavior is atomic.
                    anyhow::bail!("received message without file descriptor");
                }
            }
            Err(nix::errno::Errno::EAGAIN) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Individual message handlers
// ---------------------------------------------------------------------------

/// Parse a u32 from the start of a payload slice.
fn parse_u32(data: &[u8], offset: usize) -> Result<(u32, usize)> {
    if offset + 4 > data.len() {
        anyhow::bail!("payload too short for u32 at offset {}", offset);
    }
    let v = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    Ok((v, offset + 4))
}

/// Parse an SSH string from a payload slice, returning (string, new_offset).
fn parse_string(data: &[u8], offset: usize) -> Result<(String, usize)> {
    let (len, off) = parse_u32(data, offset)?;
    let end = off + len as usize;
    if end > data.len() {
        anyhow::bail!(
            "payload too short for string of len {} at offset {}",
            len,
            offset
        );
    }
    let s = String::from_utf8_lossy(&data[off..end]).into_owned();
    Ok((s, end))
}

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
    let stdin_fd = recv_fd_blocking(stream).await.context("recv stdin fd")?;
    let stdout_fd = recv_fd_blocking(stream).await.context("recv stdout fd")?;
    let stderr_fd = recv_fd_blocking(stream).await.context("recv stderr fd")?;

    use std::os::unix::io::FromRawFd;
    let mut stdin_file = tokio::fs::File::from_std(unsafe { std::fs::File::from_raw_fd(stdin_fd) });
    let mut stdout_file =
        tokio::fs::File::from_std(unsafe { std::fs::File::from_raw_fd(stdout_fd) });
    let mut stderr_file =
        tokio::fs::File::from_std(unsafe { std::fs::File::from_raw_fd(stderr_fd) });

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
            let mut handle = session.lock().await;

            if listen_port == 0xFFFF_FFFE || connect_port == 0xFFFF_FFFE {
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

                    tokio::spawn(async move {
                        loop {
                            match listener.accept().await {
                                Ok((tcp_stream, _)) => {
                                    let session = session.clone();
                                    let ch = connect_host.clone();
                                     let cp = connect_port as u16;
                                     if listen_port == 0xFFFF_FFFE || connect_port == 0xFFFF_FFFE {
                                         // TODO: handle local UDS forwarding
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
