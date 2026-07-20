//! Transport-neutral OpenSSH ControlMaster client.
//!
//! This client deliberately lives in `mesh`: it speaks only the local mux
//! framing and SCM_RIGHTS conventions, not SSH encryption or `russh` types.

use std::os::fd::AsRawFd;
use std::path::Path;

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tracing::{debug, info};

use crate::mux::*;

/// Client for an OpenSSH ControlMaster socket.
pub struct MuxClient {
    stream: UnixStream,
    next_req_id: u32,
}

impl MuxClient {
    /// Connect and perform the OpenSSH mux version handshake.
    pub async fn connect(socket_path: &Path) -> Result<Self> {
        let mut stream = UnixStream::connect(socket_path)
            .await
            .context("connect to mux socket")?;
        let (msg_type, payload) = read_packet(&mut stream).await.context("read mux hello")?;
        if msg_type != MUX_MSG_HELLO {
            anyhow::bail!("expected MUX_MSG_HELLO, got 0x{msg_type:08x}");
        }
        let (version, _) = parse_u32(&payload, 0).context("read mux hello version")?;
        if version != MUX_PROTOCOL_VERSION {
            anyhow::bail!(
                "unsupported mux protocol version {version}; expected {MUX_PROTOCOL_VERSION}"
            );
        }
        let mut hello = payload_with_type(MUX_MSG_HELLO);
        push_u32(&mut hello, MUX_PROTOCOL_VERSION);
        stream.write_all(&build_packet(&hello)).await?;
        Ok(Self {
            stream,
            next_req_id: 1,
        })
    }

    fn request_id(&mut self) -> u32 {
        let id = self.next_req_id;
        self.next_req_id = self.next_req_id.wrapping_add(1).max(1);
        id
    }

    async fn send(&mut self, packet: &[u8]) -> Result<()> {
        self.stream.write_all(&build_packet(packet)).await?;
        self.stream.flush().await?;
        Ok(())
    }

    async fn response(&mut self) -> Result<(u32, Vec<u8>)> {
        read_packet(&mut self.stream).await
    }

    fn failure(payload: &[u8], operation: &str) -> Result<()> {
        let (_, offset) = parse_u32(payload, 0).context("read mux failure request id")?;
        let (reason, _) = parse_string(payload, offset).context("read mux failure reason")?;
        anyhow::bail!("{operation}: {reason}")
    }

    /// Check that the master is alive and return its process ID.
    pub async fn alive_check(&mut self) -> Result<u32> {
        let request_id = self.request_id();
        let mut packet = payload_with_type(MUX_C_ALIVE_CHECK);
        push_u32(&mut packet, request_id);
        self.send(&packet).await?;
        let (msg_type, payload) = self.response().await?;
        if msg_type != MUX_S_ALIVE {
            anyhow::bail!("expected MUX_S_ALIVE, got 0x{msg_type:08x}");
        }
        let (response_id, offset) = parse_u32(&payload, 0)?;
        if response_id != request_id {
            anyhow::bail!("mux alive response request id mismatch");
        }
        let (pid, _) = parse_u32(&payload, offset)?;
        info!(pid, "mux alive");
        Ok(pid)
    }

    /// Open a session and attach stdin, stdout, and stderr descriptors.
    pub async fn new_session(
        &mut self,
        command: &str,
        want_tty: bool,
        stdin: std::os::fd::RawFd,
        stdout: std::os::fd::RawFd,
        stderr: std::os::fd::RawFd,
    ) -> Result<(u32, u32)> {
        let request_id = self.request_id();
        let mut packet = payload_with_type(MUX_C_NEW_SESSION);
        push_u32(&mut packet, request_id);
        push_string(&mut packet, "");
        push_u32(&mut packet, u32::from(want_tty));
        push_u32(&mut packet, 0);
        push_u32(&mut packet, 0);
        push_u32(&mut packet, 0);
        push_u32(&mut packet, u32::MAX);
        push_string(&mut packet, "xterm");
        push_string(&mut packet, command);
        self.send(&packet).await?;
        let socket_fd = self.stream.as_raw_fd();
        send_fd(socket_fd, stdin).context("send mux stdin")?;
        send_fd(socket_fd, stdout).context("send mux stdout")?;
        send_fd(socket_fd, stderr).context("send mux stderr")?;
        self.wait_for_session().await
    }

    /// Open a stdio forward and attach this process's stdin/stdout descriptors.
    pub async fn open_stdio_forward(
        &mut self,
        connect_host: &str,
        connect_port: u16,
    ) -> Result<(u32, u32)> {
        let request_id = self.request_id();
        let mut packet = payload_with_type(MUX_C_NEW_STDIO_FWD);
        push_u32(&mut packet, request_id);
        push_string(&mut packet, "");
        push_string(&mut packet, connect_host);
        push_u32(&mut packet, u32::from(connect_port));
        self.send(&packet).await?;
        let socket_fd = self.stream.as_raw_fd();
        send_fd(socket_fd, std::io::stdin().as_raw_fd()).context("send mux stdin")?;
        send_fd(socket_fd, std::io::stdout().as_raw_fd()).context("send mux stdout")?;
        self.wait_for_session().await
    }

    async fn wait_for_session(&mut self) -> Result<(u32, u32)> {
        let mut session_id = 0;
        loop {
            let (msg_type, payload) = self.response().await?;
            match msg_type {
                MUX_S_SESSION_OPENED => {
                    let (_, offset) = parse_u32(&payload, 0)?;
                    (session_id, _) = parse_u32(&payload, offset)?;
                }
                MUX_S_OK => debug!("mux session confirmed"),
                MUX_S_EXIT_MESSAGE => {
                    let (_, offset) = parse_u32(&payload, 0)?;
                    let (exit_code, _) = parse_u32(&payload, offset)?;
                    return Ok((session_id, exit_code));
                }
                MUX_S_PERMISSION_DENIED | MUX_S_FAILURE => {
                    Self::failure(&payload, "mux session failed")?;
                }
                _ => debug!(
                    message = format_args!("0x{msg_type:08x}"),
                    "ignored mux message"
                ),
            }
        }
    }

    /// Request a local listener through the mux master.
    pub async fn open_local_forward(
        &mut self,
        listen_host: &str,
        listen_port: u32,
        connect_host: &str,
        connect_port: u32,
    ) -> Result<Option<u32>> {
        self.open_forward(
            MUX_FWD_LOCAL,
            listen_host,
            listen_port,
            connect_host,
            connect_port,
        )
        .await
    }

    /// Request a remote listener through the mux master.
    pub async fn open_remote_forward(
        &mut self,
        listen_host: &str,
        listen_port: u32,
        connect_host: &str,
        connect_port: u32,
    ) -> Result<Option<u32>> {
        self.open_forward(
            MUX_FWD_REMOTE,
            listen_host,
            listen_port,
            connect_host,
            connect_port,
        )
        .await
    }

    async fn open_forward(
        &mut self,
        kind: u32,
        listen_host: &str,
        listen_port: u32,
        connect_host: &str,
        connect_port: u32,
    ) -> Result<Option<u32>> {
        let request_id = self.request_id();
        let mut packet = payload_with_type(MUX_C_OPEN_FWD);
        push_u32(&mut packet, request_id);
        push_u32(&mut packet, kind);
        push_string(&mut packet, listen_host);
        push_u32(&mut packet, listen_port);
        push_string(&mut packet, connect_host);
        push_u32(&mut packet, connect_port);
        self.send(&packet).await?;
        let (msg_type, payload) = self.response().await?;
        match msg_type {
            MUX_S_OK => Ok(None),
            MUX_S_REMOTE_PORT => {
                let (_, offset) = parse_u32(&payload, 0)?;
                Ok(Some(parse_u32(&payload, offset)?.0))
            }
            MUX_S_FAILURE | MUX_S_PERMISSION_DENIED => {
                Self::failure(&payload, "mux forward failed")?;
                unreachable!()
            }
            _ => anyhow::bail!("unexpected mux forward response 0x{msg_type:08x}"),
        }
    }

    /// Close a listener through the mux master.
    pub async fn close_forward(
        &mut self,
        kind: u32,
        listen_host: &str,
        listen_port: u32,
        connect_host: &str,
        connect_port: u32,
    ) -> Result<()> {
        let request_id = self.request_id();
        let mut packet = payload_with_type(MUX_C_CLOSE_FWD);
        push_u32(&mut packet, request_id);
        push_u32(&mut packet, kind);
        push_string(&mut packet, listen_host);
        push_u32(&mut packet, listen_port);
        push_string(&mut packet, connect_host);
        push_u32(&mut packet, connect_port);
        self.send(&packet).await?;
        let (msg_type, payload) = self.response().await?;
        match msg_type {
            MUX_S_OK => Ok(()),
            MUX_S_FAILURE | MUX_S_PERMISSION_DENIED => Self::failure(&payload, "close mux forward"),
            _ => anyhow::bail!("unexpected mux close-forward response 0x{msg_type:08x}"),
        }
    }

    /// Ask the mux master to terminate.
    pub async fn terminate(&mut self) -> Result<()> {
        self.simple_request(MUX_C_TERMINATE, "terminate mux master")
            .await
    }

    /// Ask the mux master to stop accepting new clients.
    pub async fn stop_listening(&mut self) -> Result<()> {
        self.simple_request(MUX_C_STOP_LISTENING, "stop mux listener")
            .await
    }

    async fn simple_request(&mut self, message_type: u32, operation: &str) -> Result<()> {
        let request_id = self.request_id();
        let mut packet = payload_with_type(message_type);
        push_u32(&mut packet, request_id);
        self.send(&packet).await?;
        let (response_type, payload) = self.response().await?;
        match response_type {
            MUX_S_OK => Ok(()),
            MUX_S_FAILURE | MUX_S_PERMISSION_DENIED => Self::failure(&payload, operation),
            _ => anyhow::bail!("unexpected mux response 0x{response_type:08x}"),
        }
    }
}
