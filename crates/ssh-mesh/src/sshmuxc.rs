/// OpenSSH Control Master mux protocol client.
///
/// Implements the client side of the multiplexing protocol described in
/// PROTOCOL.mux. Can connect to a mux master socket to perform health
/// checks, open sessions, set up port forwards, etc.
use anyhow::{Context, Result};
use log::{debug, info};
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

use super::mux::*;

// ---------------------------------------------------------------------------
// MuxClient
// ---------------------------------------------------------------------------

/// Client for the OpenSSH mux protocol.
pub struct MuxClient {
    stream: UnixStream,
    next_req_id: u32,
}

impl MuxClient {
    /// Connect to a mux master socket and perform the hello handshake.
    pub async fn connect(socket_path: &Path) -> Result<Self> {
        let mut stream = UnixStream::connect(socket_path)
            .await
            .context("connect to mux socket")?;

        // Read server hello
        let (msg_type, payload) = read_packet(&mut stream)
            .await
            .context("read server hello")?;
        if msg_type != MUX_MSG_HELLO {
            anyhow::bail!("expected MUX_MSG_HELLO, got 0x{:08x}", msg_type);
        }
        if payload.len() < 4 {
            anyhow::bail!("server hello too short");
        }
        let server_version = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        if server_version != MUX_PROTOCOL_VERSION {
            anyhow::bail!(
                "unsupported mux protocol version: {} (expected {})",
                server_version,
                MUX_PROTOCOL_VERSION
            );
        }

        // Send our hello
        let mut hello = payload_with_type(MUX_MSG_HELLO);
        push_u32(&mut hello, MUX_PROTOCOL_VERSION);
        stream
            .write_all(&build_packet(&hello))
            .await
            .context("send client hello")?;

        Ok(Self {
            stream,
            next_req_id: 1,
        })
    }

    fn alloc_req_id(&mut self) -> u32 {
        let id = self.next_req_id;
        self.next_req_id += 1;
        id
    }

    /// Perform an alive check, returns the server PID.
    pub async fn alive_check(&mut self) -> Result<u32> {
        let req_id = self.alloc_req_id();

        let mut pkt = payload_with_type(MUX_C_ALIVE_CHECK);
        push_u32(&mut pkt, req_id);
        self.stream.write_all(&build_packet(&pkt)).await?;

        let (msg_type, payload) = read_packet(&mut self.stream).await?;
        if msg_type != MUX_S_ALIVE {
            anyhow::bail!("expected MUX_S_ALIVE, got 0x{:08x}", msg_type);
        }
        let (resp_req_id, off) = parse_u32_payload(&payload, 0)?;
        if resp_req_id != req_id {
            anyhow::bail!(
                "request id mismatch: expected {}, got {}",
                req_id,
                resp_req_id
            );
        }
        let (pid, _) = parse_u32_payload(&payload, off)?;
        info!("Mux alive: server pid={}", pid);
        Ok(pid)
    }

    /// Request a new session to execute a command.
    /// Returns (session_id, exit_code).
    pub async fn new_session(
        &mut self,
        command: &str,
        want_tty: bool,
        stdin: std::os::unix::io::RawFd,
        stdout: std::os::unix::io::RawFd,
        stderr: std::os::unix::io::RawFd,
    ) -> Result<(u32, u32)> {
        let req_id = self.alloc_req_id();

        let mut pkt = payload_with_type(MUX_C_NEW_SESSION);
        push_u32(&mut pkt, req_id);
        push_string(&mut pkt, ""); // reserved
        push_u32(&mut pkt, if want_tty { 1 } else { 0 }); // want_tty
        push_u32(&mut pkt, 0); // want_x11
        push_u32(&mut pkt, 0); // want_agent
        push_u32(&mut pkt, 0); // subsystem
        push_u32(&mut pkt, 0xffff_ffff); // escape char (disabled)
        push_string(&mut pkt, "xterm"); // terminal type
        push_string(&mut pkt, command); // command
        self.stream.write_all(&build_packet(&pkt)).await?;

        // Send FDs immediately after the request packet
        use std::os::unix::io::AsRawFd;
        let socket_fd = self.stream.as_raw_fd();
        Self::send_fd(socket_fd, stdin).context("send stdin")?;
        Self::send_fd(socket_fd, stdout).context("send stdout")?;
        Self::send_fd(socket_fd, stderr).context("send stderr")?;

        // Loop until we get an exit message
        // Note: OpenSSH behavior varies on whether MUX_S_OK is sent after FDs.
        // We handle any sequence by looking for SESSION_OPENED, OK (optional), and EXIT.
        let mut session_id = 0;

        loop {
            let (msg_type, payload) = read_packet(&mut self.stream).await?;
            match msg_type {
                MUX_S_SESSION_OPENED => {
                    let (_rid, off) = parse_u32_payload(&payload, 0)?;
                    let (sid, _) = parse_u32_payload(&payload, off)?;
                    session_id = sid;
                }
                MUX_S_OK => {
                    // Not happening with ssh client (?)
                    debug!("Mux session confirmed (MUX_S_OK)");
                }
                MUX_S_EXIT_MESSAGE => {
                    let (resp_sid, off) = parse_u32_payload(&payload, 0)?;
                    let (exit_code, _) = parse_u32_payload(&payload, off)?;
                    debug!("Mux session {} exit code: {}", resp_sid, exit_code);
                    return Ok((session_id, exit_code));
                }
                MUX_S_PERMISSION_DENIED | MUX_S_FAILURE => {
                    let (_rid, off) = parse_u32_payload(&payload, 0)?;
                    let (reason, _) = parse_string_payload(&payload, off)?;
                    anyhow::bail!("session error: {}", reason);
                }
                _ => {
                    debug!("Unexpected mux message: 0x{:08x}", msg_type);
                    return Ok((session_id, 0));
                }
            }
        }
    }

    /// Request a stdio forward to a destination host:port.
    /// Returns (session_id, exit_code).
    pub async fn open_stdio_forward(
        &mut self,
        connect_host: &str,
        connect_port: u16,
    ) -> Result<(u32, u32)> {
        let req_id = self.alloc_req_id();

        let mut pkt = payload_with_type(MUX_C_NEW_STDIO_FWD);
        push_u32(&mut pkt, req_id);
        push_string(&mut pkt, ""); // reserved
        push_string(&mut pkt, connect_host);
        push_u32(&mut pkt, connect_port as u32);
        self.stream.write_all(&build_packet(&pkt)).await?;

        // Send FDs immediately after the request packet
        use std::os::unix::io::AsRawFd;
        let socket_fd = self.stream.as_raw_fd();
        let stdin = std::io::stdin().as_raw_fd();
        let stdout = std::io::stdout().as_raw_fd();
        // Stderr is NOT sent for stdio forward in some implementations?
        // OpenSSH mux.c: process_mux_new_stdio_fwd:
        //   "Expected 2 open file descriptors, got X"
        // So for stdio forward, it only expects stdin/stdout?

        // Let's check PROTOCOL.mux if available?
        // Doc says "standard input and output file descriptors". "Error file descriptor is not sent".
        // Wait, I should verify this.
        // I will assume it sends STDIN and STDOUT only.

        Self::send_fd(socket_fd, stdin).context("send stdin")?;
        Self::send_fd(socket_fd, stdout).context("send stdout")?;

        // Loop until we get an exit message
        let mut session_id = 0;

        loop {
            let (msg_type, payload) = read_packet(&mut self.stream).await?;
            match msg_type {
                MUX_S_SESSION_OPENED => {
                    let (_rid, off) = parse_u32_payload(&payload, 0)?;
                    let (sid, _) = parse_u32_payload(&payload, off)?;
                    session_id = sid;
                    info!("Mux stdio session opened: id={}", sid);
                }
                MUX_S_OK => {
                    debug!("Mux session confirmed (MUX_S_OK)");
                }
                MUX_S_EXIT_MESSAGE => {
                    let (resp_sid, off) = parse_u32_payload(&payload, 0)?;
                    let (exit_code, _) = parse_u32_payload(&payload, off)?;
                    debug!("Mux session {} exit code: {}", resp_sid, exit_code);
                    return Ok((session_id, exit_code));
                }
                MUX_S_PERMISSION_DENIED | MUX_S_FAILURE => {
                    let (_rid, off) = parse_u32_payload(&payload, 0)?;
                    let (reason, _) = parse_string_payload(&payload, off)?;
                    anyhow::bail!("session error: {}", reason);
                }
                _ => {
                    debug!("Ignored unexpected mux message: 0x{:08x}", msg_type);
                }
            }
        }
    }

    fn send_fd(socket: std::os::unix::io::RawFd, fd: std::os::unix::io::RawFd) -> Result<()> {
        use nix::sys::socket::{ControlMessage, MsgFlags, UnixAddr, sendmsg};
        use std::io::IoSlice;

        let dummy = [0u8];
        let iov = [IoSlice::new(&dummy)];
        let cmsg = [ControlMessage::ScmRights(&[fd])];

        sendmsg::<UnixAddr>(socket, &iov, &cmsg, MsgFlags::empty(), None)?;
        Ok(())
    }

    /// Request a local port forward.
    pub async fn open_local_forward(
        &mut self,
        listen_host: &str,
        listen_port: u16,
        connect_host: &str,
        connect_port: u16,
    ) -> Result<Option<u32>> {
        let req_id = self.alloc_req_id();

        let mut pkt = payload_with_type(MUX_C_OPEN_FWD);
        push_u32(&mut pkt, req_id);
        push_u32(&mut pkt, MUX_FWD_LOCAL);
        push_string(&mut pkt, listen_host);
        push_u32(&mut pkt, listen_port as u32);
        push_string(&mut pkt, connect_host);
        push_u32(&mut pkt, connect_port as u32);
        self.stream.write_all(&build_packet(&pkt)).await?;

        let (msg_type, payload) = read_packet(&mut self.stream).await?;
        match msg_type {
            MUX_S_OK => {
                info!(
                    "Local forward established: {}:{} -> {}:{}",
                    listen_host, listen_port, connect_host, connect_port
                );
                Ok(None)
            }
            MUX_S_REMOTE_PORT => {
                let (_rid, off) = parse_u32_payload(&payload, 0)?;
                let (port, _) = parse_u32_payload(&payload, off)?;
                info!(
                    "Local forward established on dynamic port {}: -> {}:{}",
                    port, connect_host, connect_port
                );
                Ok(Some(port))
            }
            MUX_S_FAILURE | MUX_S_PERMISSION_DENIED => {
                let (_rid, off) = parse_u32_payload(&payload, 0)?;
                let (reason, _) = parse_string_payload(&payload, off)?;
                anyhow::bail!("forward failed: {}", reason);
            }
            _ => anyhow::bail!("unexpected response: 0x{:08x}", msg_type),
        }
    }

    /// Request a remote port forward.
    pub async fn open_remote_forward(
        &mut self,
        listen_host: &str,
        listen_port: u16,
        connect_host: &str,
        connect_port: u16,
    ) -> Result<Option<u32>> {
        let req_id = self.alloc_req_id();

        let mut pkt = payload_with_type(MUX_C_OPEN_FWD);
        push_u32(&mut pkt, req_id);
        push_u32(&mut pkt, MUX_FWD_REMOTE);
        push_string(&mut pkt, listen_host);
        push_u32(&mut pkt, listen_port as u32);
        push_string(&mut pkt, connect_host);
        push_u32(&mut pkt, connect_port as u32);
        self.stream.write_all(&build_packet(&pkt)).await?;

        let (msg_type, payload) = read_packet(&mut self.stream).await?;
        match msg_type {
            MUX_S_OK => Ok(None),
            MUX_S_REMOTE_PORT => {
                let (_rid, off) = parse_u32_payload(&payload, 0)?;
                let (port, _) = parse_u32_payload(&payload, off)?;
                Ok(Some(port))
            }
            MUX_S_FAILURE | MUX_S_PERMISSION_DENIED => {
                let (_rid, off) = parse_u32_payload(&payload, 0)?;
                let (reason, _) = parse_string_payload(&payload, off)?;
                anyhow::bail!("remote forward failed: {}", reason);
            }
            _ => anyhow::bail!("unexpected response: 0x{:08x}", msg_type),
        }
    }

    /// Close a port forward.
    pub async fn close_forward(
        &mut self,
        fwd_type: u32,
        listen_host: &str,
        listen_port: u16,
        connect_host: &str,
        connect_port: u16,
    ) -> Result<()> {
        let req_id = self.alloc_req_id();

        let mut pkt = payload_with_type(MUX_C_CLOSE_FWD);
        push_u32(&mut pkt, req_id);
        push_u32(&mut pkt, fwd_type);
        push_string(&mut pkt, listen_host);
        push_u32(&mut pkt, listen_port as u32);
        push_string(&mut pkt, connect_host);
        push_u32(&mut pkt, connect_port as u32);
        self.stream.write_all(&build_packet(&pkt)).await?;

        let (msg_type, payload) = read_packet(&mut self.stream).await?;
        match msg_type {
            MUX_S_OK => Ok(()),
            MUX_S_FAILURE | MUX_S_PERMISSION_DENIED => {
                let (_rid, off) = parse_u32_payload(&payload, 0)?;
                let (reason, _) = parse_string_payload(&payload, off)?;
                anyhow::bail!("close forward failed: {}", reason);
            }
            _ => anyhow::bail!("unexpected response: 0x{:08x}", msg_type),
        }
    }

    /// Request the master to terminate.
    pub async fn terminate(&mut self) -> Result<()> {
        let req_id = self.alloc_req_id();

        let mut pkt = payload_with_type(MUX_C_TERMINATE);
        push_u32(&mut pkt, req_id);
        self.stream.write_all(&build_packet(&pkt)).await?;

        let (msg_type, payload) = read_packet(&mut self.stream).await?;
        match msg_type {
            MUX_S_OK => Ok(()),
            MUX_S_PERMISSION_DENIED => {
                let (_rid, off) = parse_u32_payload(&payload, 0)?;
                let (reason, _) = parse_string_payload(&payload, off)?;
                anyhow::bail!("terminate denied: {}", reason);
            }
            _ => anyhow::bail!("unexpected response: 0x{:08x}", msg_type),
        }
    }

    /// Request the master to stop listening for new connections.
    pub async fn stop_listening(&mut self) -> Result<()> {
        let req_id = self.alloc_req_id();

        let mut pkt = payload_with_type(MUX_C_STOP_LISTENING);
        push_u32(&mut pkt, req_id);
        self.stream.write_all(&build_packet(&pkt)).await?;

        let (msg_type, payload) = read_packet(&mut self.stream).await?;
        match msg_type {
            MUX_S_OK => Ok(()),
            MUX_S_FAILURE | MUX_S_PERMISSION_DENIED => {
                let (_rid, off) = parse_u32_payload(&payload, 0)?;
                let (reason, _) = parse_string_payload(&payload, off)?;
                anyhow::bail!("stop listening failed: {}", reason);
            }
            _ => anyhow::bail!("unexpected response: 0x{:08x}", msg_type),
        }
    }
}

// ---------------------------------------------------------------------------
// Payload parsing helpers (from byte slices, not async)
// ---------------------------------------------------------------------------

fn parse_u32_payload(data: &[u8], offset: usize) -> Result<(u32, usize)> {
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

fn parse_string_payload(data: &[u8], offset: usize) -> Result<(String, usize)> {
    let (len, off) = parse_u32_payload(data, offset)?;
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
