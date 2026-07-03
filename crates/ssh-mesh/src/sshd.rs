use log::{error, info};
use tracing::{debug, instrument, trace};

use openpty::openpty;

use russh::keys::{Certificate, HashAlg, PublicKey, PublicKeyBase64};
use russh::{ChannelId, MethodKind, server};

use std::collections::HashMap;
use std::io::{IoSlice, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::io::AsRawFd;
use std::process::Stdio;
use std::sync::Arc;
use std::time::SystemTime;

use hyper::body::Bytes;
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::process::Command;
use tokio::sync::{Mutex, mpsc};

use crate::{ConnectedClientInfo, MeshNode, SshRouteConfig};

/// SshHandler is responsible for one server multiplexed connection.
///
/// Connections may use TCP - or H2 tunnel, websockets, virtio.
#[allow(unused)]
#[derive(Clone)]
pub struct SshHandler {
    pub(crate) id: u64,
    pub(crate) server: MeshNode,

    // streams multiplexed on the client TCP connection
    // TODO: rename to streams, including (exec/shell) session and forwards.
    sessions: Arc<Mutex<HashMap<ChannelId, ChannelSession>>>,

    /// Channel writers, handling incoming data from client for opened
    /// channels.
    channel_writers: Arc<Mutex<HashMap<ChannelId, mpsc::UnboundedSender<Bytes>>>>,

    // Listeners for remote forwarding ((address, port) -> shutdown_sender)
    #[allow(clippy::type_complexity)]
    remote_forward_listeners: Arc<Mutex<HashMap<(String, u32), mpsc::UnboundedSender<()>>>>,

    user: String,

    comment: String,
    options: Option<String>,

    /// SHA-256 fingerprint of the authenticated peer's public key,
    /// stored as a filesystem-safe hex string (e.g. "SHA256:abc..."
    /// with non-alphanum replaced). Empty until auth succeeds.
    peer_key_sha: String,

    authenticated_with_certificate: bool,
    cert_user: Option<String>,
    terminal_user: Option<String>,
    trusted_transport: bool,
}

const DEBUG_PTY: bool = false;
/// Sentinel direct-tcpip port used to request Unix-domain socket forwarding.
pub const UDS_FORWARD_PORT: u32 = 0xFFFF_FFFE;

#[derive(Debug, Clone)]
struct PtyInfo {
    term: String,
    col_width: u32,
    row_height: u32,
    pix_width: u32,
    pix_height: u32,
}

/// Exec/Shell stream, with optional PTY support,
struct ChannelSession {
    pty: Option<PtyInfo>,
    shell: bool,
    env: HashMap<String, String>,
    // Process handling for PTY/shell sessions
    process: Option<tokio::process::Child>,
    pty_master: Option<std::fs::File>,
    mesh_init_terminal: Option<MeshInitTerminalControl>,
}

#[derive(Clone)]
struct MeshInitTerminalControl {
    terminal_id: String,
    stream: Arc<std::sync::Mutex<std::os::unix::net::UnixStream>>,
}

impl MeshInitTerminalControl {
    async fn resize(
        &self,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    ) -> Result<(), anyhow::Error> {
        self.send_request(mesh::protocol::Request::TerminalResize {
            terminal_id: self.terminal_id.clone(),
            col_width,
            row_height,
            pix_width,
            pix_height,
        })
        .await
    }

    async fn command(
        &self,
        command: impl Into<String>,
        data: serde_json::Value,
    ) -> Result<(), anyhow::Error> {
        self.send_request(mesh::protocol::Request::TerminalCommand {
            terminal_id: self.terminal_id.clone(),
            command: command.into(),
            data,
        })
        .await
    }

    async fn send_request(&self, request: mesh::protocol::Request) -> Result<(), anyhow::Error> {
        let stream = self.stream.clone();
        tokio::task::spawn_blocking(move || {
            let mut stream = stream
                .lock()
                .map_err(|_| anyhow::anyhow!("mesh-init terminal control lock poisoned"))?;
            send_mesh_init_control_request_blocking(&mut stream, &request).map(|_| ())
        })
        .await
        .map_err(|e| anyhow::anyhow!("mesh-init terminal control task failed: {}", e))?
    }
}

#[derive(Clone, Debug)]
struct MeshInitTerminal {
    socket_path: String,
    user: String,
    home: String,
    uid: u32,
    gid: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jump_route_matches_direct_tcpip_host_and_port() {
        let route = SshRouteConfig {
            name: "bwrap-nonet".to_string(),
            jump_host: Some("bwrap-nonet.example.m".to_string()),
            jump_port: Some(22),
            target_host: Some("127.0.0.1".to_string()),
            target_port: Some(22),
            activation_service: Some("activate-bwrap-nonet".to_string()),
            ..Default::default()
        };

        assert!(jump_route_matches(&route, "bwrap-nonet.example.m", 22));
        assert!(!jump_route_matches(&route, "vm-nonet.example.m", 22));
        assert!(!jump_route_matches(&route, "bwrap-nonet.example.m", 2222));
    }
}

impl SshHandler {
    pub(crate) fn new(id: u64, server: MeshNode) -> Self {
        SshHandler {
            id,
            server,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            channel_writers: Arc::new(Mutex::new(HashMap::new())),
            remote_forward_listeners: Arc::new(Mutex::new(HashMap::new())),
            user: String::new(),
            comment: String::new(),
            options: None,
            peer_key_sha: String::new(),
            authenticated_with_certificate: false,
            cert_user: None,
            terminal_user: None,
            trusted_transport: false,
        }
    }

    pub(crate) fn set_trusted_transport(&mut self, trusted_transport: bool) {
        self.trusted_transport = trusted_transport;
    }

    fn matching_ssh_route(&self, command: Option<&str>) -> Option<SshRouteConfig> {
        self.server
            .cfg
            .ssh_routes
            .iter()
            .find(|route| route_matches(route, &self.user, command))
            .cloned()
    }

    fn matching_jump_route(&self, host: &str, port: u16) -> Option<SshRouteConfig> {
        self.server
            .cfg
            .ssh_routes
            .iter()
            .find(|route| jump_route_matches(route, host, port))
            .cloned()
    }

    fn activation_context(&self, command: Option<String>) -> mesh::protocol::ActivationContext {
        mesh::protocol::ActivationContext {
            kind: "ssh".to_string(),
            user: self.user.clone(),
            command,
            certificate_user: self.cert_user.clone(),
            peer_key_sha: if self.peer_key_sha.is_empty() {
                None
            } else {
                Some(self.peer_key_sha.clone())
            },
            client_id: Some(self.id),
            env: HashMap::new(),
        }
    }

    fn jump_activation_context(
        &self,
        host: &str,
        port: u16,
        originator_ip: &str,
        originator_port: u32,
    ) -> mesh::protocol::ActivationContext {
        mesh::protocol::ActivationContext {
            kind: "ssh-direct-tcpip".to_string(),
            user: self.user.clone(),
            command: None,
            certificate_user: self.cert_user.clone(),
            peer_key_sha: if self.peer_key_sha.is_empty() {
                None
            } else {
                Some(self.peer_key_sha.clone())
            },
            client_id: Some(self.id),
            env: HashMap::from([
                ("SSH_MESH_JUMP_HOST".to_string(), host.to_string()),
                ("SSH_MESH_JUMP_PORT".to_string(), port.to_string()),
                (
                    "SSH_MESH_JUMP_ORIGINATOR_IP".to_string(),
                    originator_ip.to_string(),
                ),
                (
                    "SSH_MESH_JUMP_ORIGINATOR_PORT".to_string(),
                    originator_port.to_string(),
                ),
            ]),
        }
    }

    async fn prepare_route_activation(
        activation_service: &str,
        context: mesh::protocol::ActivationContext,
    ) -> Result<(), anyhow::Error> {
        let stream = UnixStream::connect(mesh_init_socket_path()).await?;
        let mut stream = BufReader::new(stream);
        let request = mesh::protocol::Request::PrepareActivation {
            name: activation_service.to_string(),
            context,
        };
        let mut line = serde_json::to_vec(&request)?;
        line.push(b'\n');
        stream.get_mut().write_all(&line).await?;
        stream.get_mut().flush().await?;

        let mut response = String::new();
        stream.read_line(&mut response).await?;
        let response: mesh::protocol::Response = serde_json::from_str(response.trim())?;
        if response.success {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "mesh-init rejected activation prepare: {}",
                response
                    .error
                    .unwrap_or_else(|| "unknown error".to_string())
            ))
        }
    }

    fn route_activation_uds_path(route: &SshRouteConfig) -> Option<&std::path::Path> {
        route.activation_uds_path.as_deref().or_else(|| {
            if route.client.transport.eq_ignore_ascii_case("uds") {
                None
            } else {
                route.client.uds_path.as_deref()
            }
        })
    }

    async fn trigger_route_activation_uds(
        route: &SshRouteConfig,
        service: &str,
    ) -> Result<(), anyhow::Error> {
        let Some(socket_path) = Self::route_activation_uds_path(route) else {
            return Ok(());
        };
        let required = route.activation_uds_path.is_some();
        let attempts = if required { 20 } else { 1 };
        let mut last_error = None;
        for attempt in 0..attempts {
            match UnixStream::connect(socket_path).await {
                Ok(_) => {
                    debug!(
                        "triggered activation service '{}' via {}",
                        service,
                        socket_path.display()
                    );
                    return Ok(());
                }
                Err(e) => {
                    last_error = Some(e);
                    if attempt + 1 < attempts {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }

        let error = last_error
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".to_string());
        if required {
            Err(anyhow::anyhow!(
                "activation trigger connect to {} failed for '{}': {}",
                socket_path.display(),
                service,
                error
            ))
        } else {
            debug!(
                "activation trigger connect to {} failed for '{}': {}",
                socket_path.display(),
                service,
                error
            );
            Ok(())
        }
    }

    async fn routed_connection_id(
        server: &MeshNode,
        route: &SshRouteConfig,
        context: mesh::protocol::ActivationContext,
    ) -> Result<u64, anyhow::Error> {
        if let Some(id) = server
            .route_connections
            .lock()
            .await
            .get(&route.name)
            .copied()
        {
            return Ok(id);
        }

        if let Some(service) = route.activation_service.as_deref() {
            Self::prepare_route_activation(service, context).await?;
            Self::trigger_route_activation_uds(route, service).await?;
        }

        let attempts = if route.activation_service.is_some() {
            30
        } else {
            1
        };
        let mut last_error = None;
        for attempt in 0..attempts {
            match server
                .route_client_manager
                .connect_with_config(&route.name, &route.client)
                .await
            {
                Ok(id) => {
                    server
                        .route_connections
                        .lock()
                        .await
                        .insert(route.name.clone(), id);
                    return Ok(id);
                }
                Err(e) => {
                    last_error = Some(e);
                    if attempt + 1 < attempts {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("route connection failed")))
    }

    async fn routed_exec(
        server: MeshNode,
        route: SshRouteConfig,
        context: mesh::protocol::ActivationContext,
        command: String,
        channel_id: ChannelId,
        session_handle: server::Handle,
    ) -> Result<(), anyhow::Error> {
        let id = Self::routed_connection_id(&server, &route, context.clone()).await?;
        let result = match server.route_client_manager.exec(id, &command).await {
            Ok(result) => result,
            Err(first_error) => {
                let _ = server.route_client_manager.disconnect(id).await;
                server.route_connections.lock().await.remove(&route.name);
                let id = Self::routed_connection_id(&server, &route, context).await?;
                server
                    .route_client_manager
                    .exec(id, &command)
                    .await
                    .map_err(|retry_error| {
                        anyhow::anyhow!(
                            "route '{}' exec failed after reconnect: {}; first error: {}",
                            route.name,
                            retry_error,
                            first_error
                        )
                    })?
            }
        };

        let _ = session_handle.channel_success(channel_id).await;
        if !result.stdout.is_empty() {
            let _ = session_handle
                .data(channel_id, Bytes::from(result.stdout))
                .await;
        }
        if !result.stderr.is_empty() {
            let _ = session_handle
                .extended_data(channel_id, 1, Bytes::from(result.stderr))
                .await;
        }
        let _ = session_handle
            .exit_status_request(channel_id, result.exit_code)
            .await;
        let _ = session_handle.eof(channel_id).await;
        let _ = session_handle.close(channel_id).await;
        Ok(())
    }

    async fn routed_stream(
        server: MeshNode,
        route: SshRouteConfig,
        context: mesh::protocol::ActivationContext,
        host: String,
        port: u16,
    ) -> Result<tokio::io::DuplexStream, anyhow::Error> {
        let id = Self::routed_connection_id(&server, &route, context.clone()).await?;
        match server
            .route_client_manager
            .open_stream(id, &host, port)
            .await
        {
            Ok(stream) => Ok(stream),
            Err(first_error) => {
                let _ = server.route_client_manager.disconnect(id).await;
                server.route_connections.lock().await.remove(&route.name);
                let id = Self::routed_connection_id(&server, &route, context).await?;
                server
                    .route_client_manager
                    .open_stream(id, &host, port)
                    .await
                    .map_err(|retry_error| {
                        anyhow::anyhow!(
                            "route '{}' stream failed after reconnect: {}; first error: {}",
                            route.name,
                            retry_error,
                            first_error
                        )
                    })
            }
        }
    }

    async fn routed_streamlocal(
        server: MeshNode,
        route: SshRouteConfig,
        context: mesh::protocol::ActivationContext,
        socket_path: &str,
    ) -> Result<tokio::io::DuplexStream, anyhow::Error> {
        let id = Self::routed_connection_id(&server, &route, context.clone()).await?;
        match server
            .route_client_manager
            .open_streamlocal(id, socket_path)
            .await
        {
            Ok(stream) => Ok(stream),
            Err(first_error) => {
                let _ = server.route_client_manager.disconnect(id).await;
                server.route_connections.lock().await.remove(&route.name);
                let id = Self::routed_connection_id(&server, &route, context).await?;
                server
                    .route_client_manager
                    .open_streamlocal(id, socket_path)
                    .await
                    .map_err(|retry_error| {
                        anyhow::anyhow!(
                            "route '{}' streamlocal failed after reconnect: {}; first error: {}",
                            route.name,
                            retry_error,
                            first_error
                        )
                    })
            }
        }
    }

    async fn routed_shell_stream(
        server: MeshNode,
        route: SshRouteConfig,
        context: mesh::protocol::ActivationContext,
        pty: Option<PtyInfo>,
    ) -> Result<tokio::io::DuplexStream, anyhow::Error> {
        let id = Self::routed_connection_id(&server, &route, context.clone()).await?;
        let pty = pty.map(|pty| crate::sshc::ShellPty {
            term: pty.term,
            col_width: pty.col_width,
            row_height: pty.row_height,
            pix_width: pty.pix_width,
            pix_height: pty.pix_height,
        });
        match server
            .route_client_manager
            .open_shell_with_pty(id, pty.clone())
            .await
        {
            Ok(stream) => Ok(stream),
            Err(first_error) => {
                let _ = server.route_client_manager.disconnect(id).await;
                server.route_connections.lock().await.remove(&route.name);
                let id = Self::routed_connection_id(&server, &route, context).await?;
                server
                    .route_client_manager
                    .open_shell_with_pty(id, pty)
                    .await
                    .map_err(|retry_error| {
                        anyhow::anyhow!(
                            "route '{}' shell failed after reconnect: {}; first error: {}",
                            route.name,
                            retry_error,
                            first_error
                        )
                    })
            }
        }
    }

    async fn routed_trusted_uds_stream(
        route: &SshRouteConfig,
        context: mesh::protocol::ActivationContext,
    ) -> Result<UnixStream, anyhow::Error> {
        if let Some(service) = route.activation_service.as_deref() {
            Self::prepare_route_activation(service, context).await?;
            Self::trigger_route_activation_uds(route, service).await?;
        }
        let socket_path = route.client.uds_path.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "route '{}' uses trusted UDS routing without uds_path",
                route.name
            )
        })?;
        let attempts = if route.activation_service.is_some() {
            30
        } else {
            1
        };
        let mut last_error = None;
        for attempt in 0..attempts {
            match crate::trusted_transport::connect_trusted_uds(socket_path).await {
                Ok(mut stream) => {
                    let user = if route.client.user.is_empty() {
                        route.user.as_deref().unwrap_or_default()
                    } else {
                        route.client.user.as_str()
                    };
                    let port = route
                        .target_port
                        .or(route.jump_port)
                        .unwrap_or(route.client.port);
                    crate::trusted_transport::apply_client_line_handshake(
                        &mut stream,
                        &route.client,
                        user,
                        port,
                        &route.name,
                    )
                    .await?;
                    return Ok(stream);
                }
                Err(e) => {
                    last_error = Some(e);
                    if attempt + 1 < attempts {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("trusted UDS route connect failed")))
    }

    async fn bridge_stream_to_channel<S>(
        stream: S,
        channel_id: ChannelId,
        channel_writers: Arc<Mutex<HashMap<ChannelId, mpsc::UnboundedSender<Bytes>>>>,
        session_handle: server::Handle,
        label: String,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (reader, writer) = tokio::io::split(stream);
        let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
        {
            let mut writers = channel_writers.lock().await;
            writers.insert(channel_id, tx);
        }

        let channel_writers_clone = channel_writers.clone();
        let label_to_ssh = format!("{} to SSH", label);
        tokio::spawn(async move {
            crate::utils::pipe_read_to_ssh(reader, session_handle, channel_id, &label_to_ssh).await;
            let mut writers = channel_writers_clone.lock().await;
            writers.remove(&channel_id);
        });

        let channel_writers_clone = channel_writers.clone();
        let label_from_ssh = format!("SSH to {}", label);
        tokio::spawn(async move {
            crate::utils::pipe_rx_to_write(rx, writer, &label_from_ssh).await;
            let mut writers = channel_writers_clone.lock().await;
            writers.remove(&channel_id);
        });
    }

    async fn bridge_command_streams_to_channel(
        stdin_stream: tokio::net::UnixStream,
        stdout_stream: tokio::net::UnixStream,
        stderr_stream: tokio::net::UnixStream,
        channel_id: ChannelId,
        channel_writers: Arc<Mutex<HashMap<ChannelId, mpsc::UnboundedSender<Bytes>>>>,
        session_handle: server::Handle,
        label: String,
    ) {
        let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
        {
            let mut writers = channel_writers.lock().await;
            writers.insert(channel_id, tx);
        }

        let channel_writers_clone = channel_writers.clone();
        let label_from_ssh = format!("SSH to {} (stdin)", label);
        tokio::spawn(async move {
            crate::utils::pipe_rx_to_write(rx, stdin_stream, &label_from_ssh).await;
            let mut writers = channel_writers_clone.lock().await;
            writers.remove(&channel_id);
        });

        let channel_writers_clone = channel_writers.clone();
        tokio::spawn(async move {
            let label_stdout_to_ssh = format!("{} stdout to SSH", label);
            let label_stderr_to_ssh = format!("{} stderr to SSH", label);

            let stdout_fut = crate::utils::pipe_read_to_ssh_no_close(
                stdout_stream,
                session_handle.clone(),
                channel_id,
                &label_stdout_to_ssh,
            );

            let stderr_fut = crate::utils::pipe_read_to_ssh_extended(
                stderr_stream,
                session_handle.clone(),
                channel_id,
                1,
                &label_stderr_to_ssh,
            );

            tokio::join!(stdout_fut, stderr_fut);

            let _ = session_handle.exit_status_request(channel_id, 0).await;
            let _ = session_handle.eof(channel_id).await;
            let _ = session_handle.close(channel_id).await;

            let mut writers = channel_writers_clone.lock().await;
            writers.remove(&channel_id);
        });
    }

    async fn bridge_shell_stream_to_channel<S>(
        stream: S,
        channel_id: ChannelId,
        channel_writers: Arc<Mutex<HashMap<ChannelId, mpsc::UnboundedSender<Bytes>>>>,
        session_handle: server::Handle,
        label: String,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut reader, writer) = tokio::io::split(stream);
        let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
        {
            let mut writers = channel_writers.lock().await;
            writers.insert(channel_id, tx);
        }

        let channel_writers_clone = channel_writers.clone();
        let label_to_ssh = format!("{} to SSH", label);
        tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => {
                        debug!("{} EOF", label_to_ssh);
                        break;
                    }
                    Ok(n) => {
                        if session_handle
                            .data(channel_id, Bytes::copy_from_slice(&buf[..n]))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::Other || e.raw_os_error() == Some(5) =>
                    {
                        debug!("{} closed cleanly: {}", label_to_ssh, e);
                        break;
                    }
                    Err(e) => {
                        error!("{} read error: {}", label_to_ssh, e);
                        break;
                    }
                }
            }
            let _ = session_handle.exit_status_request(channel_id, 0).await;
            let _ = session_handle.eof(channel_id).await;
            let _ = session_handle.close(channel_id).await;
            let mut writers = channel_writers_clone.lock().await;
            writers.remove(&channel_id);
        });

        let channel_writers_clone = channel_writers.clone();
        let label_from_ssh = format!("SSH to {}", label);
        tokio::spawn(async move {
            crate::utils::pipe_rx_to_write(rx, writer, &label_from_ssh).await;
            let mut writers = channel_writers_clone.lock().await;
            writers.remove(&channel_id);
        });
    }

    /// Shared implementation for both exec_request and shell_request.
    ///
    /// When `command` is None, starts an interactive shell through mesh-init.
    /// When `command` is Some, asks mesh-init to execute it with its shell
    /// policy. ssh-mesh only bridges SSH channel bytes and terminal controls.
    fn spawn_command(
        command: Option<String>,
        channel_id: ChannelId,
        sessions: Arc<Mutex<HashMap<ChannelId, ChannelSession>>>,
        channel_writers: Arc<Mutex<HashMap<ChannelId, mpsc::UnboundedSender<Bytes>>>>,
        session: &mut server::Session,
        mesh_init_terminal: Option<MeshInitTerminal>,
        activation_context: Option<mesh::protocol::ActivationContext>,
    ) -> impl std::future::Future<Output = Result<(), anyhow::Error>> + Send {
        let session_handle = session.handle();
        let label = match &command {
            None => "shell".to_string(),
            Some(c) => format!("exec({})", c),
        };

        async move {
            let mut sessions_lock = sessions.lock().await;
            let channel_session = match sessions_lock.get_mut(&channel_id) {
                Some(cs) => cs,
                None => {
                    trace!(
                        "No session found for channel {:?} when processing {} request",
                        channel_id, label
                    );
                    return Ok(());
                }
            };
            channel_session.shell = true;

            let has_pty = channel_session.pty.is_some();

            if has_pty {
                // ---- PTY mode ----
                let winsize = channel_session
                    .pty
                    .as_ref()
                    .map(|pty_info| nix::libc::winsize {
                        ws_row: pty_info.row_height as u16,
                        ws_col: pty_info.col_width as u16,
                        ws_xpixel: pty_info.pix_width as u16,
                        ws_ypixel: pty_info.pix_height as u16,
                    });

                let pty = openpty(None, winsize.as_ref(), None)
                    .map_err(|e| anyhow::Error::msg(format!("{:?}", e)))?;
                channel_session.pty_master = Some(pty.0);

                let slave_file = &pty.1;

                let delegated = if let Some(terminal) = mesh_init_terminal {
                    let slave_for_mesh_init = slave_file
                        .try_clone()
                        .map_err(|e| anyhow::Error::msg(format!("{:?}", e)))?;
                    let term = channel_session
                        .pty
                        .as_ref()
                        .map(|pty| pty.term.clone())
                        .unwrap_or_else(|| "xterm-256color".to_string());
                    let control = send_terminal_to_mesh_init_with_term(
                        terminal,
                        slave_for_mesh_init,
                        term,
                        command.clone(),
                        activation_context,
                    )
                    .await?;
                    channel_session.mesh_init_terminal = Some(control);
                    true
                } else {
                    return Err(anyhow::anyhow!(
                        "{} requires mesh-init terminal delegation",
                        label
                    ));
                };

                // Set up PTY I/O forwarding
                let master = channel_session.pty_master.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("{label} requested PTY but no PTY master exists")
                })?;
                let master_fd = master.as_raw_fd();
                trace!("PTY created with master fd {}", master_fd);

                use std::os::unix::io::FromRawFd;
                let master_fd_read = unsafe { nix::libc::dup(master_fd) };
                if master_fd_read < 0 {
                    return Err(anyhow::Error::msg(
                        "Failed to duplicate master FD for reading",
                    ));
                }
                let master_fd_write = unsafe { nix::libc::dup(master_fd) };
                if master_fd_write < 0 {
                    unsafe {
                        nix::libc::close(master_fd_read);
                    }
                    return Err(anyhow::Error::msg(
                        "Failed to duplicate master FD for writing",
                    ));
                }

                let master_read_file = unsafe { std::fs::File::from_raw_fd(master_fd_read) };
                let master_write_file = unsafe { std::fs::File::from_raw_fd(master_fd_write) };
                let master_read = tokio::fs::File::from_std(master_read_file);
                let master_write = tokio::fs::File::from_std(master_write_file);
                drop(sessions_lock);
                drop(pty.1); // drop slave

                // PTY master -> SSH channel
                let sh = session_handle.clone();
                let ch = channel_id;
                let close_on_pty_eof = delegated;
                tokio::spawn(async move {
                    if close_on_pty_eof {
                        crate::utils::pipe_read_to_ssh_with_exit_status(
                            master_read,
                            sh,
                            ch,
                            "PTY to SSH",
                            0,
                        )
                        .await;
                    } else {
                        crate::utils::pipe_read_to_ssh_no_close(master_read, sh, ch, "PTY to SSH")
                            .await;
                    }
                });

                // SSH channel -> PTY master
                let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
                {
                    let mut writers = channel_writers.lock().await;
                    writers.insert(channel_id, tx);
                }
                let tw = channel_writers.clone();
                tokio::spawn(async move {
                    crate::utils::pipe_rx_to_write(rx, master_write, "SSH to PTY").await;
                    let mut writers = tw.lock().await;
                    writers.remove(&ch);
                });
                let _ = session_handle.channel_success(channel_id).await;
            } else {
                let terminal = mesh_init_terminal.ok_or_else(|| {
                    anyhow::anyhow!("{} requires mesh-init terminal delegation", label)
                })?;
                let env = channel_session.env.clone();
                let (stdin_stream, stdout_stream, stderr_stream, control) =
                    send_stdio_to_mesh_init(terminal, command.clone(), env, activation_context)
                        .await?;
                channel_session.mesh_init_terminal = Some(control);
                drop(sessions_lock);

                Self::bridge_command_streams_to_channel(
                    stdin_stream,
                    stdout_stream,
                    stderr_stream,
                    channel_id,
                    channel_writers.clone(),
                    session_handle.clone(),
                    label.clone(),
                )
                .await;
                let _ = session_handle.channel_success(channel_id).await;
            }

            // Monitor child process for exit status. Delegated mesh-init PTYs do
            // not have a local child handle; EOF on the PTY closes the channel.
            let sessions_for_exit = sessions.clone();
            let tw_exit = channel_writers.clone();
            let sh_exit = session_handle.clone();
            tokio::spawn(async move {
                // Take ownership of the child from the session
                let mut child = {
                    let mut sl = sessions_for_exit.lock().await;
                    match sl.get_mut(&channel_id) {
                        Some(cs) => match cs.process.take() {
                            Some(c) => c,
                            None => return,
                        },
                        None => return,
                    }
                };

                match child.wait().await {
                    Ok(status) => {
                        let exit_code = status.code().unwrap_or(0) as u32;
                        debug!(
                            "{} exited with status {} (code {})",
                            label, status, exit_code
                        );
                        let _ = sh_exit.exit_status_request(channel_id, exit_code).await;
                    }
                    Err(e) => {
                        error!("Error waiting for {} process: {}", label, e);
                    }
                }
                let _ = sh_exit.eof(channel_id).await;
                let _ = sh_exit.close(channel_id).await;

                // Cleanup writer
                let mut writers = tw_exit.lock().await;
                writers.remove(&channel_id);
            });

            Ok(())
        }
    }

    /// Helper to connect to a Unix Domain Socket (UDS).
    /// Handles abstract namespace if path starts with '_'.
    async fn connect_uds(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        socket_path: &str,
        session_handle: russh::server::Handle,
    ) -> Result<bool, anyhow::Error> {
        let channel_id = channel.id();
        let sessions = self.sessions.clone();
        let channel_writers = self.channel_writers.clone();
        let handler_id = self.id;
        let socket_path_str = socket_path.to_string();

        // Security: refuse to connect to arbitrary UDS paths by default. UDS
        // paths like `/var/run/docker.sock` or dbus sockets would let an
        // authenticated SSH user escalate to host/container control. Only
        // allow when the operator explicitly opts in via
        // `allow_direct_tcpip` (the same flag governs direct-tcpip and UDS
        // relay behavior), or the path matches a configured route.
        if !self.server.cfg.allow_direct_tcpip {
            error!(
                "Refusing direct-streamlocal UDS connection to '{}' — \
                 allow_direct_tcpip is false",
                socket_path_str
            );
            return Ok(false);
        }

        trace!(
            "Processing UDS connection for: {} (handler ID: {})",
            socket_path_str, handler_id
        );

        // Handle abstract namespace: replace leading '_' with '\0'
        let path_bytes = if let Some(stripped) = socket_path_str.strip_prefix('_') {
            let mut bytes = Vec::with_capacity(socket_path_str.len());
            bytes.push(0);
            bytes.extend_from_slice(stripped.as_bytes());
            bytes
        } else {
            socket_path_str.clone().into_bytes()
        };

        // Create a new session entry for this channel
        let channel_session = ChannelSession {
            pty: None,
            shell: false,
            env: HashMap::new(),
            process: None,
            pty_master: None,
            mesh_init_terminal: None,
        };

        // Store the session in our sessions map
        {
            let mut sessions_lock = sessions.lock().await;
            sessions_lock.insert(channel_id, channel_session);
        }

        trace!(
            "Created new UDS session for channel {:?} in handler {}",
            channel_id, handler_id
        );

        // Establish connection to the UDS
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        use std::path::Path;

        let os_str = OsStr::from_bytes(&path_bytes);
        let path = Path::new(os_str);

        match UnixStream::connect(path).await {
            Ok(stream) => {
                trace!("Successfully connected to UDS {}", socket_path_str);

                // Set up bidirectional data forwarding
                let (uds_reader, uds_writer) = stream.into_split();

                // Store the writer for SSH to UDS forwarding
                let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
                {
                    let mut writers = channel_writers.lock().await;
                    writers.insert(channel_id, tx);
                }

                // Spawn task to forward data from UDS -> SSH channel
                let session_handle_clone = session_handle.clone();
                let channel_writers_clone = channel_writers.clone();
                tokio::spawn(async move {
                    crate::utils::pipe_read_to_ssh(
                        uds_reader,
                        session_handle_clone,
                        channel_id,
                        "UDS to SSH",
                    )
                    .await;
                    let mut writers = channel_writers_clone.lock().await;
                    writers.remove(&channel_id);
                });

                // Spawn task to forward data from SSH channel -> UDS
                let channel_writers_clone2 = channel_writers.clone();
                tokio::spawn(async move {
                    crate::utils::pipe_rx_to_write(rx, uds_writer, "SSH to UDS").await;
                    let mut writers = channel_writers_clone2.lock().await;
                    writers.remove(&channel_id);
                });

                info!("UDS forwarding established for {}", socket_path_str);
                Ok(true)
            }
            Err(e) => {
                error!(
                    "Failed to connect to UDS {}: {} (handler ID: {})",
                    socket_path_str, e, handler_id
                );
                Ok(false) // Reject the channel if we can't connect
            }
        }
    }
}

fn mesh_init_socket_path() -> String {
    if let Ok(path) = std::env::var("MESH_INIT_SOCK") {
        return path;
    }
    mesh::paths::AppPaths::for_app("system")
        .control_socket("mesh-init")
        .to_string_lossy()
        .into_owned()
}

fn user_part(identity: &str) -> String {
    identity
        .split_once('@')
        .map(|(user, _)| user)
        .unwrap_or(identity)
        .to_string()
}

fn safe_user_part(identity: &str) -> Option<String> {
    let user = user_part(identity);
    if user.is_empty()
        || user == "."
        || user == ".."
        || user.contains('/')
        || user.contains('\\')
        || user.contains('\0')
    {
        None
    } else {
        Some(user)
    }
}

fn cert_terminal_for_user(user: &str) -> Option<MeshInitTerminal> {
    let home_root = std::env::var("SSH_MESH_HOME_ROOT")
        .or_else(|_| std::env::var("MESH_HOME_BASE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| mesh::paths::default_home_base());
    let home_path = home_root.join(user);
    let metadata = std::fs::metadata(&home_path).ok()?;
    if !metadata.is_dir() {
        return None;
    }

    use std::os::unix::fs::MetadataExt;
    Some(MeshInitTerminal {
        socket_path: mesh_init_socket_path(),
        user: user.to_string(),
        home: home_path.to_string_lossy().into_owned(),
        uid: metadata.uid(),
        gid: Some(metadata.gid()),
    })
}

fn route_matches(route: &SshRouteConfig, user: &str, command: Option<&str>) -> bool {
    if route.name.is_empty() {
        return false;
    }

    let user_matches = match (&route.user, &route.user_prefix) {
        (Some(expected), _) if user != expected => false,
        (_, Some(prefix)) if !user.starts_with(prefix) => false,
        (None, None) => false,
        _ => true,
    };
    if !user_matches {
        return false;
    }

    if let Some(expected) = &route.command
        && command != Some(expected.as_str())
    {
        return false;
    }
    if let Some(prefix) = &route.command_prefix
        && !command.is_some_and(|cmd| cmd.starts_with(prefix))
    {
        return false;
    }
    if let Some(needle) = &route.command_contains
        && !command.is_some_and(|cmd| cmd.contains(needle))
    {
        return false;
    }

    true
}

fn jump_route_matches(route: &SshRouteConfig, host: &str, port: u16) -> bool {
    let Some(jump_host) = &route.jump_host else {
        return false;
    };
    if route.name.is_empty() || jump_host != host {
        return false;
    }
    if let Some(jump_port) = route.jump_port
        && jump_port != port
    {
        return false;
    }
    true
}

async fn send_terminal_to_mesh_init_with_term(
    terminal: MeshInitTerminal,
    slave: std::fs::File,
    term: String,
    command: Option<String>,
    context: Option<mesh::protocol::ActivationContext>,
) -> Result<MeshInitTerminalControl, anyhow::Error> {
    use std::os::fd::AsRawFd;
    let slave_fd = OwnedFd::from(slave);
    tokio::task::spawn_blocking(move || {
        send_start_terminal_to_mesh_init_blocking(
            terminal,
            &[slave_fd.as_raw_fd()],
            true,
            term,
            command,
            std::collections::HashMap::new(),
            context,
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!("mesh-init terminal task failed: {}", e))?
}

async fn send_stdio_to_mesh_init(
    terminal: MeshInitTerminal,
    command: Option<String>,
    env: std::collections::HashMap<String, String>,
    context: Option<mesh::protocol::ActivationContext>,
) -> Result<
    (
        tokio::net::UnixStream,
        tokio::net::UnixStream,
        tokio::net::UnixStream,
        MeshInitTerminalControl,
    ),
    anyhow::Error,
> {
    let (stdin_child, stdin_parent) = std::os::unix::net::UnixStream::pair()?;
    let (stdout_child, stdout_parent) = std::os::unix::net::UnixStream::pair()?;
    let (stderr_child, stderr_parent) = std::os::unix::net::UnixStream::pair()?;

    use std::os::fd::{AsRawFd, OwnedFd};
    let stdin_child_fd = OwnedFd::from(stdin_child);
    let stdout_child_fd = OwnedFd::from(stdout_child);
    let stderr_child_fd = OwnedFd::from(stderr_child);

    let fds = [
        stdin_child_fd.as_raw_fd(),
        stdout_child_fd.as_raw_fd(),
        stderr_child_fd.as_raw_fd(),
    ];

    let control = tokio::task::spawn_blocking(move || {
        send_start_terminal_to_mesh_init_blocking(
            terminal,
            &fds,
            false,
            "xterm-256color".to_string(),
            command,
            env,
            context,
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!("mesh-init stdio task failed: {}", e))??;

    drop(stdin_child_fd);
    drop(stdout_child_fd);
    drop(stderr_child_fd);

    stdin_parent.set_nonblocking(true)?;
    stdout_parent.set_nonblocking(true)?;
    stderr_parent.set_nonblocking(true)?;

    let stdin_stream = tokio::net::UnixStream::from_std(stdin_parent)?;
    let stdout_stream = tokio::net::UnixStream::from_std(stdout_parent)?;
    let stderr_stream = tokio::net::UnixStream::from_std(stderr_parent)?;

    Ok((stdin_stream, stdout_stream, stderr_stream, control))
}

fn send_start_terminal_to_mesh_init_blocking(
    terminal: MeshInitTerminal,
    fds: &[std::os::unix::io::RawFd],
    pty: bool,
    term: String,
    command: Option<String>,
    extra_env: std::collections::HashMap<String, String>,
    context: Option<mesh::protocol::ActivationContext>,
) -> Result<MeshInitTerminalControl, anyhow::Error> {
    let mut stream = std::os::unix::net::UnixStream::connect(&terminal.socket_path)?;
    let home = terminal.home.clone();
    let user = terminal.user.clone();
    let mut env = std::collections::HashMap::from([
        ("HOME".to_string(), home.clone()),
        ("USER".to_string(), user.clone()),
        ("LOGNAME".to_string(), user.clone()),
        ("TERM".to_string(), term),
    ]);
    env.extend(extra_env);
    let request = mesh::protocol::Request::StartTerminal {
        name: user.clone(),
        home: home.clone(),
        uid: terminal.uid,
        gid: terminal.gid,
        pty,
        env,
        context,
        command,
        fd_count: Some(fds.len() as u32),
    };
    let line = serde_json::to_string(&request)?;
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let iov = [IoSlice::new(b"F")];
    let cmsg = [ControlMessage::ScmRights(fds)];
    sendmsg::<()>(stream.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)?;

    let response = read_mesh_init_response_blocking(&mut stream)?;
    if !response.success {
        Err(anyhow::anyhow!(
            "mesh-init rejected terminal: {}",
            response
                .error
                .unwrap_or_else(|| "unknown error".to_string())
        ))
    } else {
        let terminal_id = response
            .data
            .as_ref()
            .and_then(|data| data.get("terminal_id"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("mesh-init terminal start omitted terminal_id"))?
            .to_string();
        Ok(MeshInitTerminalControl {
            terminal_id,
            stream: Arc::new(std::sync::Mutex::new(stream)),
        })
    }
}

fn send_mesh_init_control_request_blocking(
    stream: &mut std::os::unix::net::UnixStream,
    request: &mesh::protocol::Request,
) -> Result<mesh::protocol::Response, anyhow::Error> {
    let line = serde_json::to_string(request)?;
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let response = read_mesh_init_response_blocking(stream)?;
    if response.success {
        Ok(response)
    } else {
        Err(anyhow::anyhow!(
            "mesh-init control request failed: {}",
            response
                .error
                .unwrap_or_else(|| "unknown error".to_string())
        ))
    }
}

fn read_mesh_init_response_blocking(
    stream: &mut std::os::unix::net::UnixStream,
) -> Result<mesh::protocol::Response, anyhow::Error> {
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            break;
        }
        response.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    if response.is_empty() {
        anyhow::bail!("empty response from mesh-init");
    }
    let response = String::from_utf8(response)?;
    Ok(serde_json::from_str(response.trim())?)
}

/// Handler deals with one SSH connection, after crypto and
/// low level networking.
impl server::Handler for SshHandler {
    type Error = anyhow::Error;

    fn auth_password(
        &mut self,
        user: &str,
        _password: &str,
    ) -> impl std::future::Future<Output = Result<server::Auth, Self::Error>> + Send {
        info!(
            "Password auth attempt for user: {} {}- REJECTED",
            user, self.id
        );
        async move {
            Ok(server::Auth::Reject {
                proceed_with_methods: Some((&[MethodKind::PublicKey][..]).into()),
                partial_success: false,
            })
        }
    }

    #[instrument(skip(self), fields(user = %user))]
    fn auth_none(
        &mut self,
        user: &str,
    ) -> impl std::future::Future<Output = Result<server::Auth, Self::Error>> + Send {
        let allow = self.trusted_transport;
        let user_part = safe_user_part(user);
        let user_str = user.to_string();
        let connected_clients = self.server.connected_clients.clone();
        let handler_id = self.id;
        let comment = self.comment.clone();
        let options = self.options.clone();
        // B15: Auth state mutation is deferred until the async block confirms
        // `Auth::Accept`. Mutating `self` synchronously before the auth result
        // is known would leave partially-populated identity fields if russh
        // invokes this method speculatively during a multi-step handshake.

        async move {
            if !allow {
                return Ok(server::Auth::Reject {
                    proceed_with_methods: Some((&[MethodKind::PublicKey][..]).into()),
                    partial_success: false,
                });
            }

            if user_part.is_some() {
                self.user = user_str.clone();
                self.authenticated_with_certificate = false;
                self.cert_user = None;
                self.terminal_user = user_part.clone();
                let mut clients = connected_clients.lock().await;
                clients.insert(
                    handler_id,
                    ConnectedClientInfo {
                        id: handler_id,
                        user: user_str,
                        comment,
                        options,
                        remote_forward_listeners: Vec::new(),
                        connected_at: SystemTime::now(),
                    },
                );
                Ok(server::Auth::Accept)
            } else {
                Ok(server::Auth::Reject {
                    proceed_with_methods: Some((&[MethodKind::None][..]).into()),
                    partial_success: false,
                })
            }
        }
    }

    #[instrument(skip(self, public_key), fields(user = %user))]
    fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> impl std::future::Future<Output = Result<server::Auth, Self::Error>> + Send {
        let authorized_keys = self.server.authorized_keys.clone();
        let ca_keys = self.server.ca_keys.clone();
        let config_dir = self.server.config_dir();
        let authz = self.server.cfg.auth.clone();

        let user_str = user.to_string();
        let user_part = safe_user_part(&user_str);

        let connected_clients = self.server.connected_clients.clone();
        let handler_id = self.id;

        // B15: Do not mutate `self.user` synchronously before the auth result
        // is known; defer it to the `Auth::Accept` branch in the async block.

        let keyfp = public_key.fingerprint(HashAlg::Sha256).to_string();

        // Serialize russh key to OpenSSH format for ssh-key crate
        let key_base64 = public_key.public_key_base64();
        let algorithm = public_key.algorithm();
        let key_type_name = algorithm.as_str();

        let key_openssh = format!("{} {}", key_type_name, key_base64);
        let is_certificate = key_openssh.contains("-cert-v01@openssh.com");

        async move {
            // Detect if this is a certificate or regular key
            let auth_result = if is_certificate {
                info!(
                    "Certificate auth attempt for user: {} {} {}",
                    user, self.id, &key_openssh
                );

                crate::auth::validate_certificate_with_authz(
                    &key_openssh,
                    &user_str,
                    &ca_keys,
                    authz.as_ref(),
                )
                .await
            } else {
                info!(
                    "Public key auth attempt for user: {} {} {} {}",
                    user, self.id, &key_openssh, &keyfp,
                );

                let mut result =
                    crate::auth::validate_public_key(&user_str, &key_openssh, &authorized_keys)
                        .await?;
                if !matches!(result.status, server::Auth::Accept)
                    && let Some(ref safe_user) = user_part
                {
                    let user_keys_path = config_dir
                        .join("users")
                        .join(safe_user)
                        .join("authorized_keys");
                    result = crate::auth::validate_public_key_file(
                        &user_str,
                        &key_openssh,
                        &user_keys_path,
                    )
                    .await?;
                }
                Ok(result)
            };

            if let Ok(ref auth_res) = auth_result {
                if let server::Auth::Accept = auth_res.status {
                    // B15: Apply identity only after auth is confirmed.
                    self.user = user_str.clone();
                    let mut clients = connected_clients.lock().await;
                    let client_info = ConnectedClientInfo {
                        id: handler_id,
                        user: user_str.clone(),
                        comment: auth_res.comment.clone(),
                        options: auth_res.options.clone(),
                        remote_forward_listeners: Vec::new(),
                        connected_at: SystemTime::now(),
                    };
                    clients.insert(handler_id, client_info);
                    self.comment = auth_res.comment.clone();
                    self.options = auth_res.options.clone();

                    // Notify listeners about the authenticated connection
                    let listeners = self.server.listeners.clone();
                    let id_val = handler_id;
                    let u_str = user_str.clone();
                    tokio::spawn(async move {
                        let listeners = listeners.lock().await;
                        for l in listeners.iter() {
                            l.on_ssh_connection(id_val, &u_str);
                        }
                    });

                    // Store a filesystem-safe version of the key fingerprint.
                    // keyfp is like "SHA256:abc+/def="; keep only alphanumerics.
                    self.peer_key_sha = keyfp
                        .chars()
                        .filter(|c| c.is_ascii_alphanumeric())
                        .collect();
                    self.authenticated_with_certificate = is_certificate;
                    if is_certificate {
                        self.cert_user = if auth_res.user.is_empty() {
                            user_part.clone()
                        } else {
                            Some(auth_res.user.clone())
                        };
                    }
                    self.terminal_user = user_part.clone();
                }
            } else {
                error!("Auth failed {}", self.id)
            }

            auth_result.map(|r| r.status)
        }
    }

    #[instrument(skip(self, certificate), fields(user = %user, key_id = %certificate.key_id()))]
    fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &Certificate,
    ) -> impl std::future::Future<Output = Result<server::Auth, Self::Error>> + Send {
        let ca_keys = self.server.ca_keys.clone();
        let authz = self.server.cfg.auth.clone();
        let user_str = user.to_string();
        let user_part = safe_user_part(&user_str);
        let connected_clients = self.server.connected_clients.clone();
        let handler_id = self.id;
        // B15: defer self.user mutation until Accept.
        let cert_openssh = certificate.to_openssh();

        async move {
            let auth_result = match cert_openssh {
                Ok(cert_openssh) => {
                    info!(
                        "Certificate auth attempt for user: {} {} {}",
                        user, self.id, cert_openssh
                    );
                    crate::auth::validate_certificate_with_authz(
                        &cert_openssh,
                        &user_str,
                        &ca_keys,
                        authz.as_ref(),
                    )
                    .await
                }
                Err(e) => Err(anyhow::anyhow!(
                    "failed to serialize SSH certificate: {}",
                    e
                )),
            };

            if let Ok(ref auth_res) = auth_result {
                if let server::Auth::Accept = auth_res.status {
                    // B15: Apply identity only after auth is confirmed.
                    self.user = user_str.clone();
                    let mut clients = connected_clients.lock().await;
                    clients.insert(
                        handler_id,
                        ConnectedClientInfo {
                            id: handler_id,
                            user: user_str.clone(),
                            comment: auth_res.comment.clone(),
                            options: auth_res.options.clone(),
                            remote_forward_listeners: Vec::new(),
                            connected_at: SystemTime::now(),
                        },
                    );
                    self.comment = auth_res.comment.clone();
                    self.options = auth_res.options.clone();
                    self.authenticated_with_certificate = true;
                    self.cert_user = if auth_res.user.is_empty() {
                        user_part.clone()
                    } else {
                        Some(auth_res.user.clone())
                    };
                    self.terminal_user = user_part.clone();

                    let listeners = self.server.listeners.clone();
                    let id_val = handler_id;
                    let u_str = user_str.clone();
                    tokio::spawn(async move {
                        let listeners = listeners.lock().await;
                        for l in listeners.iter() {
                            l.on_ssh_connection(id_val, &u_str);
                        }
                    });
                }
            } else {
                error!("Certificate auth failed {}", self.id)
            }

            auth_result.map(|r| r.status)
        }
    }

    /// This is called when a new stream (called channel) is opened on a client connection
    ///
    /// This is usually a shell - message followed by env, pty - and ending
    /// with the actual shell or exec command, than data and close.
    #[instrument(skip(self, _session), fields(channel_id = ?channel.id()))]
    fn channel_open_session(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        _session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        let channel_id = channel.id();
        let sessions = self.sessions.clone();
        let handler_id = self.id;

        async move {
            // Create a new session entry for this channel
            let channel_session = ChannelSession {
                pty: None,
                shell: false,
                env: HashMap::new(),
                process: None,
                pty_master: None,
                mesh_init_terminal: None,
            };

            // Store the session in our sessions map
            let mut sessions_lock = sessions.lock().await;
            sessions_lock.insert(channel_id, channel_session);
            drop(sessions_lock);

            trace!(
                "Created new session for channel {:?} in handler {}",
                channel_id, handler_id
            );
            Ok(true)
        }
    }

    /// Connection forward from client.
    ///
    /// If port is [`UDS_FORWARD_PORT`], treat host as a UDS path.
    #[instrument(skip(self, session), fields(channel_id = ?channel.id(), host_to_connect = %host_to_connect, port_to_connect = %port_to_connect, originator_ip = %originator_ip_address, originator_port = %originator_port))]
    fn channel_open_direct_tcpip(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_ip_address: &str,
        originator_port: u32,
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        info!(
            "Direct TCP/IP connection request: {}:{} from {}:{} (handler ID: {})",
            host_to_connect, port_to_connect, originator_ip_address, originator_port, self.id
        );

        // TODO: apply the rules to map host and port to 'special'
        // internal channels.

        let channel_id = channel.id();
        let sessions = self.sessions.clone();
        let handler_id = self.id;
        let host = host_to_connect.to_string();
        let port = port_to_connect;
        let originator_ip = originator_ip_address.to_string();
        let jump_route = u16::try_from(port)
            .ok()
            .and_then(|port| self.matching_jump_route(&host, port));
        let jump_context = u16::try_from(port).ok().map(|port| {
            self.jump_activation_context(&host, port, originator_ip_address, originator_port)
        });

        let session_handle = session.handle();

        let mut me = self.clone();
        let channel = channel;

        async move {
            // UDS support: the host field carries the socket path.
            if port == UDS_FORWARD_PORT {
                return me.connect_uds(channel, &host, session_handle).await;
            }

            trace!(
                "Processing direct TCP/IP connection for: {}:{} from {}:{}",
                host, port, originator_ip, originator_port
            );

            // Create a new session entry for this channel
            let channel_session = ChannelSession {
                pty: None,
                shell: false,
                env: HashMap::new(),
                process: None,
                pty_master: None,
                mesh_init_terminal: None,
            };

            // Store the session in our sessions map
            let mut sessions_lock = sessions.lock().await;
            sessions_lock.insert(channel_id, channel_session);
            drop(sessions_lock);

            if let (Some(route), Some(context), Ok(incoming_port)) =
                (jump_route, jump_context, u16::try_from(port))
            {
                let target_host = route.target_host.clone().unwrap_or_else(|| host.clone());
                let target_port = route.target_port.unwrap_or(incoming_port);
                if route.activation_service.is_some()
                    && route.client.transport.eq_ignore_ascii_case("uds")
                    && route.client.uds_path.is_some()
                {
                    match Self::routed_trusted_uds_stream(&route, context).await {
                        Ok(stream) => {
                            Self::bridge_stream_to_channel(
                                stream,
                                channel_id,
                                me.channel_writers.clone(),
                                session_handle,
                                format!("activated trusted UDS route {}", route.name),
                            )
                            .await;
                            info!(
                                "Routed jump established for {}:{} via activated trusted UDS route {}",
                                host, incoming_port, route.name
                            );
                            return Ok(true);
                        }
                        Err(e) => {
                            error!(
                                "Failed routed jump for {}:{} via route '{}': {}",
                                host, incoming_port, route.name, e
                            );
                            return Ok(false);
                        }
                    }
                }

                match Self::routed_stream(
                    me.server.clone(),
                    route.clone(),
                    context,
                    target_host.clone(),
                    target_port,
                )
                .await
                {
                    Ok(stream) => {
                        Self::bridge_stream_to_channel(
                            stream,
                            channel_id,
                            me.channel_writers.clone(),
                            session_handle,
                            format!(
                                "routed jump {}:{} via {}",
                                target_host, target_port, route.name
                            ),
                        )
                        .await;
                        info!(
                            "Routed jump established for {}:{} via {} to {}:{}",
                            host, incoming_port, route.name, target_host, target_port
                        );
                        return Ok(true);
                    }
                    Err(e) => {
                        error!(
                            "Failed routed jump for {}:{} via route '{}': {}",
                            host, incoming_port, route.name, e
                        );
                        return Ok(false);
                    }
                }
            }

            // Handle internal stream hosts - trigger callback.
            if host == "local" || host == "dmesh-msg" {
                let (s1, s2) = tokio::io::duplex(64 * 1024);

                // Notify listeners
                let listeners = me.server.listeners.clone();
                let client_id = handler_id;
                let port_val = port as u16;
                let stream_host = host.clone();
                tokio::spawn(async move {
                    let listeners = listeners.lock().await;
                    if let Some(l) = listeners.first() {
                        l.on_stream(client_id, &stream_host, port_val, s1);
                    }
                });

                // Bridge s2 to SSH channel
                let (reader, writer) = tokio::io::split(s2);
                let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
                {
                    let mut writers = me.channel_writers.lock().await;
                    writers.insert(channel_id, tx);
                }

                let session_handle_clone = session_handle.clone();
                let channel_writers_clone = me.channel_writers.clone();
                tokio::spawn(async move {
                    crate::utils::pipe_read_to_ssh(
                        reader,
                        session_handle_clone,
                        channel_id,
                        "Local Stream to SSH",
                    )
                    .await;
                    let mut writers = channel_writers_clone.lock().await;
                    writers.remove(&channel_id);
                });

                let channel_writers_clone2 = me.channel_writers.clone();
                tokio::spawn(async move {
                    crate::utils::pipe_rx_to_write(rx, writer, "SSH to Local Stream").await;
                    let mut writers = channel_writers_clone2.lock().await;
                    writers.remove(&channel_id);
                });

                return Ok(true);
            }

            // Establish a TCP connection to the target host:port
            //
            // Security: by default, refuse to connect to arbitrary hosts to
            // avoid acting as an open SSH relay / SSRF pivot. Only the
            // `local` host (handled above) and configured routes (handled
            // above) are permitted. Operators can opt into open-relay mode by
            // setting `allow_direct_tcpip = true` in the mesh config.
            if !me.server.cfg.allow_direct_tcpip {
                error!(
                    "Refusing direct-tcpip to {}:{} — no matching route and \
                     allow_direct_tcpip is false",
                    host, port
                );
                return Ok(false);
            }
            let target_addr = format!("{}:{}", host, port);
            match TcpStream::connect(&target_addr).await {
                Ok(tcp_stream) => {
                    trace!("Successfully connected to target {}:{}", host, port);

                    // Set up bidirectional data forwarding between SSH channel and TCP connection
                    let (tcp_reader, tcp_writer) = tcp_stream.into_split();
                    let channel_id = channel_id;

                    // Store the TCP writer for SSH to TCP forwarding
                    let tcp_writers = me.channel_writers.clone();
                    let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
                    {
                        let mut writers = tcp_writers.lock().await;
                        writers.insert(channel_id, tx);
                    }

                    let session_handle_clone = session_handle.clone();
                    let channel_writers_clone = me.channel_writers.clone();
                    tokio::spawn(async move {
                        crate::utils::pipe_read_to_ssh(
                            tcp_reader,
                            session_handle_clone,
                            channel_id,
                            "TCP to SSH",
                        )
                        .await;
                        let mut writers = channel_writers_clone.lock().await;
                        writers.remove(&channel_id);
                    });

                    // Bridge SSH channel to TCP
                    let channel_writers_clone2 = me.channel_writers.clone();
                    tokio::spawn(async move {
                        crate::utils::pipe_rx_to_write(rx, tcp_writer, "SSH to TCP").await;
                        let mut writers = channel_writers_clone2.lock().await;
                        writers.remove(&channel_id);
                    });

                    Ok(true)
                }
                Err(e) => {
                    error!("Failed to connect to {}:{}: {}", host, port, e);
                    Ok(false)
                }
            }
        }
    }

    fn channel_open_direct_streamlocal(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        socket_path: &str,
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        info!(
            "Direct streamlocal connection request: {} (handler ID: {})",
            socket_path, self.id
        );
        let mut me = self.clone();
        let channel = channel;
        let socket_path = socket_path.to_string();
        let handle = session.handle();

        async move {
            if let Some(route) = me.matching_ssh_route(None) {
                let channel_id = channel.id();
                let context = me.activation_context(None);
                match Self::routed_streamlocal(
                    me.server.clone(),
                    route.clone(),
                    context,
                    &socket_path,
                )
                .await
                {
                    Ok(stream) => {
                        Self::bridge_stream_to_channel(
                            stream,
                            channel_id,
                            me.channel_writers.clone(),
                            handle,
                            format!("routed streamlocal {} via {}", socket_path, route.name),
                        )
                        .await;
                        info!(
                            "Routed streamlocal established for {} via {}",
                            socket_path, route.name
                        );
                        return Ok(true);
                    }
                    Err(e) => {
                        error!(
                            "Failed routed streamlocal for {} via route '{}': {}",
                            socket_path, route.name, e
                        );
                        return Ok(false);
                    }
                }
            }

            me.connect_uds(channel, &socket_path, handle).await
        }
    }

    /// This is the message used by server to accept new streams on behalf of
    /// clients - not supported from clients (open_direct_tcpip does the same).
    #[instrument(skip(self, _session), fields(channel_id = ?_channel.id(), host_to_connect = %_host_to_connect, port_to_connect = %_port_to_connect, originator_ip = %_originator_ip_address, originator_port = %_originator_port))]
    fn channel_open_forwarded_tcpip(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_ip_address: &str,
        _originator_port: u32,
        _session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        error!("Client-initiated forwarded-tcpip channel is not supported.");
        async { Ok(false) }
    }

    #[instrument(skip(self, session), fields(channel_id = ?channel, data_len = data.len()))]
    fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        // Check if this is a direct TCP/IP channel and forward data to the TCP connection
        let tcp_writers = self.channel_writers.clone();
        let data_vec = data.to_vec();
        let channel_id = channel;
        let session_handle = session.handle();

        async move {
            // B16: Clone the sender out and drop the lock guard *before* sending,
            // so concurrent data() calls for different channels don't serialize
            // on the channel_writers mutex. `mpsc::UnboundedSender::send` is
            // synchronous (never blocks), but holding the lock across it still
            // serializes lookups.
            let tx_opt = {
                let writers = tcp_writers.lock().await;
                writers.get(&channel_id).cloned()
            };
            if let Some(tx) = tx_opt {
                trace!(
                    "Forwarding {} bytes from SSH channel {:?}",
                    data_vec.len(),
                    channel_id
                );
                if let Err(e) = tx.send(Bytes::from(data_vec)) {
                    error!("Failed to send data for channel {:?}: {}", channel_id, e);
                }
            } else {
                trace!(
                    "Echoing data back ({} bytes) for non-TCP channel {:?}",
                    data_vec.len(),
                    channel_id
                );
                let _ = session_handle
                    .data(channel_id, bytes::Bytes::from(data_vec))
                    .await;
            }
            Ok(())
        }
    }

    /// Tcpip_forward requests that the ssh server accepts connections
    /// on an address, and forwards them to the client
    #[instrument(skip(self, session), fields(address = %address, port = %*port))]
    fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        let session_handle = session.handle();
        let tcp_writers = self.channel_writers.clone();
        let remote_forward_listeners = self.remote_forward_listeners.clone();
        let bind_addr = address.to_string();
        let bind_port = *port;

        let fut = async move {
            let listen_addr = format!("{}:{}", bind_addr, bind_port);
            let listener = match tokio::net::TcpListener::bind(&listen_addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind to {}: {}", listen_addr, e);
                    return (Err(anyhow::Error::new(e)), 0);
                }
            };

            // TODO:

            let actual_port = match listener.local_addr() {
                Ok(addr) => addr.port(),
                Err(error) => {
                    error!(
                        "Failed to read local address for {}: {}",
                        listen_addr, error
                    );
                    return (Err(anyhow::Error::new(error)), 0);
                }
            };
            info!("Started listening on {}:{}", bind_addr, actual_port);

            // Channel to signal shutdown
            let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();

            {
                let mut listeners = remote_forward_listeners.lock().await;
                // B12: Key the listener map on the *actual* bound port (not the
                // requested `bind_port`, which is 0 for ephemeral). The client
                // receives `actual_port` from the reply and uses it to cancel,
                // so the lookup key must match.
                listeners.insert((bind_addr.clone(), actual_port as u32), shutdown_tx);
            }

            let remote_forward_listeners_weak = Arc::downgrade(&remote_forward_listeners);

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            match accepted {
                                Ok((tcp_stream, originator_addr)) => {
                                    info!("Accepted connection from {}", originator_addr);
                                    let session_handle_clone = session_handle.clone();
                                    let tcp_writers_clone = tcp_writers.clone();
                                    let bind_addr_clone = bind_addr.clone();

                                    tokio::spawn(async move {
                                        // Open a forwarded-tcpip channel to the client
                                        let channel = match session_handle_clone.channel_open_forwarded_tcpip(
                                            &bind_addr_clone,
                                            actual_port as u32,
                                            &originator_addr.ip().to_string(),
                                            originator_addr.port() as u32,
                                        ).await {
                                            Ok(channel) => channel,
                                            Err(e) => {
                                                error!("Failed to open forwarded-tcpip channel: {}", e);
                                                return;
                                            }
                                        };
                                        let channel_id = channel.id();
                                        info!("Opened forwarded-tcpip channel {:?}", channel_id);

                                        // Set up bidirectional data forwarding
                                        let (tcp_reader, tcp_writer) = tcp_stream.into_split();

                                        // Store the TCP writer for SSH→TCP forwarding
                                        let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
                                        {
                                            let mut writers = tcp_writers_clone.lock().await;
                                            writers.insert(channel_id, tx);
                                        }

                                        // Spawn task to forward data from TCP -> SSH channel
                                        let session_handle_clone2 = session_handle_clone.clone();
                                        let tcp_writers_clone2 = tcp_writers_clone.clone();
                                        tokio::spawn(async move {
                                            crate::utils::pipe_read_to_ssh(tcp_reader, session_handle_clone2, channel_id, "TCP forwarder to SSH").await;
                                            let mut writers = tcp_writers_clone2.lock().await;
                                            writers.remove(&channel_id);
                                        });

                                        // Spawn task to forward data from SSH channel -> TCP connection
                                        let tcp_writers_clone3 = tcp_writers_clone.clone();
                                        tokio::spawn(async move {
                                            crate::utils::pipe_rx_to_write(rx, tcp_writer, "SSH to TCP forwarder").await;
                                            let mut writers = tcp_writers_clone3.lock().await;
                                            writers.remove(&channel_id);
                                        });
                                    });
                                }
                                Err(e) => error!("Failed to accept connection: {}", e),
                            }
                        }
                        _ = shutdown_rx.recv() => {
                            info!("Shutting down remote forward listener on {}:{}", bind_addr, bind_port);
                            break;
                        }
                        else => {
                            break;
                        }
                    }
                }
                // Cleanup
                if let Some(listeners_arc) = remote_forward_listeners_weak.upgrade() {
                    let mut listeners = listeners_arc.lock().await;
                    listeners.remove(&(bind_addr, bind_port));
                }
            });

            (Ok(()), actual_port)
        };

        async move {
            let (result, actual_port) = fut.await;
            if result.is_ok() {
                *port = actual_port as u32;
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }

    /// Close the listening port.
    #[instrument(skip(self, _session), fields(address = %address, port = %port))]
    fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        info!(
            "Request to cancel TCP/IP forwarding for {}:{}",
            address, port
        );
        let remote_forward_listeners = self.remote_forward_listeners.clone();
        let address = address.to_string();

        async move {
            let mut listeners = remote_forward_listeners.lock().await;
            if let Some(shutdown_tx) = listeners.remove(&(address.clone(), port)) {
                // Sending a message will cause the listening task to break its loop and exit.
                let _ = shutdown_tx.send(());
                info!("Cancelled TCP/IP forwarding for {}:{}", address, port);
                Ok(true)
            } else {
                log::warn!(
                    "No active forwarding found for {}:{} to cancel",
                    address,
                    port
                );
                Ok(false)
            }
        }
    }

    /// Handle streamlocal-forward@openssh.com — remote UDS forwarding.
    ///
    /// The client asks us to listen on a Unix domain socket path on the
    /// server side. When a connection arrives we open a
    /// `forwarded-streamlocal@openssh.com` channel back to the client so
    /// it can pipe data to its local socket.
    #[instrument(skip(self, session), fields(socket_path = %socket_path))]
    fn streamlocal_forward(
        &mut self,
        socket_path: &str,
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        info!("streamlocal_forward request for {}", socket_path);

        let session_handle = session.handle();
        let channel_writers = self.channel_writers.clone();
        let remote_forward_listeners = self.remote_forward_listeners.clone();
        let socket_path_owned = socket_path.to_string();
        let peer_key_sha = self.peer_key_sha.clone();

        async move {
            // If the path is /tmp/<name>.sock where <name> is a 9p socket,
            // rewrite it into a per-peer directory and auto-mount.
            let (actual_socket_path, mount_dir) = if socket_path_owned.starts_with("/tmp/")
                && socket_path_owned.ends_with("/9p.sock")
            {
                if peer_key_sha.is_empty() {
                    error!("Cannot create per-peer 9p directory: peer key not available");
                    return Ok(false);
                }
                let peer_dir = format!("/tmp/{}", peer_key_sha);
                let sock = format!("{}/9p.sock", peer_dir);
                let rootfs = format!("{}/rootfs", peer_dir);
                (sock, Some(rootfs))
            } else {
                (socket_path_owned.clone(), None)
            };

            // Remove stale socket if present
            let _ = tokio::fs::remove_file(&actual_socket_path).await;

            // Ensure parent directory exists
            if let Some(parent) = std::path::Path::new(&actual_socket_path).parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }

            // Create the rootfs mount-point directory if needed
            if let Some(ref rootfs_dir) = mount_dir {
                if let Err(e) = tokio::fs::create_dir_all(rootfs_dir).await {
                    error!("Failed to create rootfs directory {}: {}", rootfs_dir, e);
                    return Ok(false);
                }
                info!("Created rootfs directory {}", rootfs_dir);
            }

            let listener = match UnixListener::bind(&actual_socket_path) {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind UDS {}: {}", actual_socket_path, e);
                    return Ok(false);
                }
            };

            info!(
                "Listening on UDS {} for streamlocal forward",
                actual_socket_path
            );

            // Auto-mount 9p filesystem if rootfs directory was created
            if let Some(ref rootfs_dir) = mount_dir {
                let is_root = nix::unistd::getuid().is_root();
                if is_root {
                    // Unmount any previous mount, ignoring errors
                    let _ = tokio::process::Command::new("umount")
                        .arg(rootfs_dir)
                        .output()
                        .await;

                    info!(
                        "Mounting 9p filesystem: {} -> {}",
                        actual_socket_path, rootfs_dir
                    );
                    match tokio::process::Command::new("mount")
                        .args([
                            "-t",
                            "9p",
                            "-o",
                            "trans=unix,version=9p2000.L",
                            &actual_socket_path,
                            rootfs_dir,
                        ])
                        .output()
                        .await
                    {
                        Ok(output) if output.status.success() => {
                            info!("Successfully mounted 9p at {}", rootfs_dir);
                        }
                        Ok(output) => {
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            error!("Failed to mount 9p at {}: {}", rootfs_dir, stderr.trim());
                        }
                        Err(e) => {
                            error!("Failed to run mount command: {}", e);
                        }
                    }
                } else {
                    info!("Not running as root, skipping 9p mount for {}", rootfs_dir);
                }
            }

            // Channel to signal shutdown
            let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();

            {
                let mut listeners = remote_forward_listeners.lock().await;
                // Use port 0 as the key component for UDS forwards.
                // Key under the *original* path so cancel_streamlocal_forward
                // still matches the path the client sends.
                listeners.insert((socket_path_owned.clone(), 0), shutdown_tx);
            }

            let sp = actual_socket_path.clone();
            let sp_original = socket_path_owned.clone();
            let remote_forward_listeners_weak = Arc::downgrade(&remote_forward_listeners);
            let mount_dir_cleanup = mount_dir.clone();

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            match accepted {
                                Ok((uds_stream, _addr)) => {
                                    info!("Accepted connection on UDS {}", sp);
                                    let session_handle_clone = session_handle.clone();
                                    let channel_writers_clone = channel_writers.clone();
                                    let sp_clone = sp_original.clone();

                                    tokio::spawn(async move {
                                        // Open a forwarded-streamlocal channel
                                        // back to the client using the *original*
                                        // path so the client recognises it.
                                        let channel = match session_handle_clone
                                            .channel_open_forwarded_streamlocal(&sp_clone)
                                            .await
                                        {
                                            Ok(channel) => channel,
                                            Err(e) => {
                                                error!(
                                                    "Failed to open forwarded-streamlocal channel for {}: {}",
                                                    sp_clone, e
                                                );
                                                return;
                                            }
                                        };
                                        let channel_id = channel.id();
                                        info!(
                                            "Opened forwarded-streamlocal channel {:?} for {}",
                                            channel_id, sp_clone
                                        );

                                        // Set up bidirectional data forwarding
                                        let (uds_reader, uds_writer) = uds_stream.into_split();

                                        // Store the UDS writer for SSH→UDS forwarding
                                        let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
                                        {
                                            let mut writers = channel_writers_clone.lock().await;
                                            writers.insert(channel_id, tx);
                                        }

                                        // UDS → SSH channel
                                        let session_handle_clone2 = session_handle_clone.clone();
                                        let cw2 = channel_writers_clone.clone();
                                        tokio::spawn(async move {
                                            crate::utils::pipe_read_to_ssh(
                                                uds_reader,
                                                session_handle_clone2,
                                                channel_id,
                                                "streamlocal UDS to SSH",
                                            )
                                            .await;
                                            let mut writers = cw2.lock().await;
                                            writers.remove(&channel_id);
                                        });

                                        // SSH channel → UDS
                                        let cw3 = channel_writers_clone.clone();
                                        tokio::spawn(async move {
                                            crate::utils::pipe_rx_to_write(
                                                rx,
                                                uds_writer,
                                                "SSH to streamlocal UDS",
                                            )
                                            .await;
                                            let mut writers = cw3.lock().await;
                                            writers.remove(&channel_id);
                                        });
                                    });
                                }
                                Err(e) => {
                                    error!("Failed to accept on UDS {}: {}", sp, e);
                                }
                            }
                        }
                        _ = shutdown_rx.recv() => {
                            info!("Shutting down streamlocal forward listener on {}", sp);
                            break;
                        }
                        else => {
                            // If shutdown channel is closed (sender dropped) or
                            // both branches are unreachable, stop the loop.
                            break;
                        }
                    }
                }
                // Cleanup: unmount 9p if we mounted it
                if let (Some(rootfs_dir), true) =
                    (mount_dir_cleanup.as_ref(), nix::unistd::getuid().is_root())
                {
                    info!("Unmounting 9p at {}", rootfs_dir);
                    let _ = tokio::process::Command::new("umount")
                        .arg(rootfs_dir)
                        .output()
                        .await;
                }
                // Cleanup socket file
                let _ = tokio::fs::remove_file(&sp).await;
                // Only attempt to remove from listener map if SshHandler still exists
                if let Some(listeners_arc) = remote_forward_listeners_weak.upgrade() {
                    let mut listeners = listeners_arc.lock().await;
                    listeners.remove(&(sp_original, 0));
                }
            });

            Ok(true)
        }
    }

    /// Cancel a streamlocal forward — stop listening on the UDS path.
    #[instrument(skip(self, _session), fields(socket_path = %socket_path))]
    fn cancel_streamlocal_forward(
        &mut self,
        socket_path: &str,
        _session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        info!("cancel_streamlocal_forward for {}", socket_path);
        let remote_forward_listeners = self.remote_forward_listeners.clone();
        let socket_path_owned = socket_path.to_string();

        async move {
            let mut listeners = remote_forward_listeners.lock().await;
            if let Some(shutdown_tx) = listeners.remove(&(socket_path_owned.clone(), 0)) {
                let _ = shutdown_tx.send(());
                info!("Cancelled streamlocal forward for {}", socket_path_owned);
                Ok(true)
            } else {
                log::warn!(
                    "No active streamlocal forward found for {} to cancel",
                    socket_path_owned
                );
                Ok(false)
            }
        }
    }

    #[instrument(skip(self, _session), fields(channel_id = ?channel))]
    fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        debug!("Channel EOF: stream: {:?} client: {}", channel, self.id);
        let tcp_writers = self.channel_writers.clone();
        let channel_id = channel;
        async move {
            let mut writers = tcp_writers.lock().await;
            if writers.remove(&channel_id).is_some() {
                debug!("Removed writer for channel {:?} after EOF", channel_id);
            }
            Ok(())
        }
    }

    #[instrument(skip(self, _session), fields(channel_id = ?channel))]
    fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        debug!("Channel closed: stream {:?} client {}", channel, self.id);

        let sessions = self.sessions.clone();
        let tcp_writers = self.channel_writers.clone();
        let _connected_clients = self.server.connected_clients.clone();
        let handler_id = self.id;
        let channel_id = channel;

        async move {
            // Remove the session from our sessions map and clean up PTY process if any
            let mut sessions_lock = sessions.lock().await;
            let mut mesh_init_terminal = None;
            if let Some(mut removed_session) = sessions_lock.remove(&channel_id) {
                trace!(
                    "Removed session for channel {:?} from handler {}",
                    channel_id, handler_id
                );
                mesh_init_terminal = removed_session.mesh_init_terminal.take();
                // If a PTY process was spawned, kill it.
                if let Some(mut child) = removed_session.process.take() {
                    // Attempt graceful termination, then force kill if needed.
                    let _ = child.kill().await;
                }
            } else {
                info!(
                    "No session found for channel {:?} in handler {}",
                    channel_id, handler_id
                );
            }
            drop(sessions_lock);

            // Remove the writer (PTY or TCP) for this channel if it exists
            let mut writers_lock = tcp_writers.lock().await;
            if let Some(_removed_writer) = writers_lock.remove(&channel_id) {
                trace!("Removed writer for channel {:?}", channel_id);
            } else {
                trace!("No writer found for channel {:?}", channel_id);
            }
            drop(writers_lock);

            if let Some(control) = mesh_init_terminal {
                tokio::spawn(async move {
                    if let Err(e) = control.command("close", serde_json::json!({})).await {
                        debug!(
                            "Failed to close mesh-init terminal '{}': {}",
                            control.terminal_id, e
                        );
                    }
                });
            }

            Ok(())
        }
    }

    // ---------- Exec and FTP ----------
    // This functionality is mainly for the admin, when user as a regular
    // user.

    // TODO: change the code to allow other users (authenticated with cert)
    // to run - in isolated containers.

    /// Exec_request is the last message in a 'session', after pty is setup and
    /// env variables are sent. May have a pty (if -t is used on client).
    #[instrument(skip(self, session), fields(channel_id = ?channel, data_len = data.len()))]
    fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let command = String::from_utf8_lossy(data).to_string();
        info!("Exec request: {} {}", command, self.id);

        let route = self.matching_ssh_route(Some(&command));
        let session_handle = session.handle();
        let local_future = if route.is_none() {
            let mesh_init_terminal = self
                .terminal_user
                .as_deref()
                .and_then(cert_terminal_for_user);
            Some(Self::spawn_command(
                Some(command.clone()),
                channel,
                self.sessions.clone(),
                self.channel_writers.clone(),
                session,
                mesh_init_terminal,
                Some(self.activation_context(Some(command.clone()))),
            ))
        } else {
            None
        };
        let context = self.activation_context(Some(command.clone()));
        let server = self.server.clone();

        async move {
            if let Some(future) = local_future {
                return future.await;
            }

            if let Some(route) = route {
                if let Err(e) = Self::routed_exec(
                    server,
                    route,
                    context,
                    command,
                    channel,
                    session_handle.clone(),
                )
                .await
                {
                    error!("Routed exec failed: {}", e);
                    let _ = session_handle
                        .extended_data(channel, 1, Bytes::from(format!("{}\n", e)))
                        .await;
                    let _ = session_handle.exit_status_request(channel, 255).await;
                    let _ = session_handle.eof(channel).await;
                    let _ = session_handle.close(channel).await;
                }
            }
            Ok(())
        }
    }

    #[instrument(skip(self, session), fields(channel_id = ?channel))]
    fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        info!("Shell request for channel {:?}", channel);
        debug!("SSH handler ID: {}", self.id);
        let route = self.matching_ssh_route(None);
        let session_handle = session.handle();
        let local_future = if route.is_none() {
            let mesh_init_terminal = self
                .terminal_user
                .as_deref()
                .and_then(cert_terminal_for_user);

            Some(Self::spawn_command(
                None,
                channel,
                self.sessions.clone(),
                self.channel_writers.clone(),
                session,
                mesh_init_terminal,
                Some(self.activation_context(None)),
            ))
        } else {
            None
        };
        let context = self.activation_context(None);
        let server = self.server.clone();
        let channel_writers = self.channel_writers.clone();
        let sessions = self.sessions.clone();

        async move {
            if let Some(future) = local_future {
                return future.await;
            }

            if let Some(route) = route {
                let route_name = route.name.clone();
                let pty = {
                    let sessions = sessions.lock().await;
                    sessions
                        .get(&channel)
                        .and_then(|channel_session| channel_session.pty.clone())
                };
                match Self::routed_shell_stream(server, route, context, pty).await {
                    Ok(stream) => {
                        let _ = session_handle.channel_success(channel).await;
                        Self::bridge_shell_stream_to_channel(
                            stream,
                            channel,
                            channel_writers,
                            session_handle.clone(),
                            format!("shell:{}", route_name),
                        )
                        .await;
                        return Ok(());
                    }
                    Err(e) => {
                        error!("Routed shell failed: {}", e);
                        let _ = session_handle
                            .extended_data(channel, 1, Bytes::from(format!("{}\n", e)))
                            .await;
                        let _ = session_handle.eof(channel).await;
                        let _ = session_handle.close(channel).await;
                    }
                }
            }
            Ok(())
        }
    }

    #[instrument(skip(self, session), fields(channel_id = ?channel, term = %term))]
    fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(russh::Pty, u32)],
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        info!(
            "PTY request for channel {:?}: term={}, {}x{} ({}x{} px), modes: {} entries",
            channel,
            term,
            col_width,
            row_height,
            pix_width,
            pix_height,
            modes.len()
        );

        let sessions = self.sessions.clone();
        let channel_id = channel;
        let session_handle = session.handle();
        let term = term.to_string();

        if DEBUG_PTY {
            // Log PTY modes for debugging
            for (mode, value) in modes {
                trace!("PTY mode: {:?} = {}", mode, value);
            }
        }

        async move {
            // Update the session with PTY information
            let mut sessions_lock = sessions.lock().await;
            if let Some(channel_session) = sessions_lock.get_mut(&channel_id) {
                channel_session.pty = Some(PtyInfo {
                    term,
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                });
                if DEBUG_PTY {
                    trace!("Updated PTY info for channel {:?}", channel_id);
                }
                // If PTY is already open, update its size.
                if let Some(master) = &channel_session.pty_master {
                    let mut winsize = nix::libc::winsize {
                        ws_row: row_height as u16,
                        ws_col: col_width as u16,
                        ws_xpixel: pix_width as u16,
                        ws_ypixel: pix_height as u16,
                    };
                    unsafe {
                        nix::libc::ioctl(master.as_raw_fd(), nix::libc::TIOCSWINSZ, &mut winsize);
                    }
                }
            } else {
                trace!(
                    "No session found for channel {:?} when processing PTY request",
                    channel_id
                );
            }
            drop(sessions_lock);

            let _ = session_handle.channel_success(channel_id).await;
            Ok(())
        }
    }

    #[instrument(skip(self, _session), fields(channel_id = ?channel))]
    fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        _session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        trace!(
            "Env request for channel {:?}: {}={}",
            channel, variable_name, variable_value
        );

        let sessions = self.sessions.clone();
        let channel_id = channel;
        let variable_name = variable_name.to_string();
        let variable_value = variable_value.to_string();

        async move {
            let mut sessions_lock = sessions.lock().await;
            if let Some(channel_session) = sessions_lock.get_mut(&channel_id) {
                channel_session.env.insert(variable_name, variable_value);
            }
            drop(sessions_lock);
            Ok(())
        }
    }

    #[instrument(skip(self, _session), fields(channel_id = ?channel))]
    fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        trace!(
            "Window change request for channel {:?}: {}x{} ({}x{} px)",
            channel, col_width, row_height, pix_width, pix_height
        );

        let sessions = self.sessions.clone();
        let channel_id = channel;

        async move {
            // Update the session with the new window size
            let mut mesh_init_terminal = None;
            let mut sessions_lock = sessions.lock().await;
            if let Some(channel_session) = sessions_lock.get_mut(&channel_id) {
                if let Some(pty) = &mut channel_session.pty {
                    pty.col_width = col_width;
                    pty.row_height = row_height;
                    pty.pix_width = pix_width;
                    pty.pix_height = pix_height;
                }
                mesh_init_terminal = channel_session.mesh_init_terminal.clone();
                if let Some(master) = &channel_session.pty_master {
                    trace!("Updating window size for channel {:?}", channel_id);
                    let mut winsize = nix::libc::winsize {
                        ws_row: row_height as u16,
                        ws_col: col_width as u16,
                        ws_xpixel: pix_width as u16,
                        ws_ypixel: pix_height as u16,
                    };
                    unsafe {
                        nix::libc::ioctl(master.as_raw_fd(), nix::libc::TIOCSWINSZ, &mut winsize);
                    }
                }
            }
            drop(sessions_lock);

            if let Some(control) = mesh_init_terminal
                && let Err(e) = control
                    .resize(col_width, row_height, pix_width, pix_height)
                    .await
            {
                log::warn!(
                    "Failed to forward window size to mesh-init terminal '{}': {}",
                    control.terminal_id,
                    e
                );
            }

            trace!("Processing PTY request with terminal info");
            Ok(())
        }
    }

    /// This handles the original sftp, the only subsystem in broad use.
    /// It is equivalent to a port forward or shell execution for the binary
    /// sftp, all comms are via stdin/stderr.
    #[instrument(skip(self, session), fields(channel_id = ?channel, name = %name))]
    fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut server::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let channel_id = channel;
        let subsystem_name = name.to_string();
        let tcp_writers = self.channel_writers.clone();
        let session_handle = session.handle();

        async move {
            if subsystem_name == "sftp" {
                #[cfg(feature = "sftp")]
                if self.server.cfg.sftp_server_path.is_none() {
                    info!("Starting built-in SFTP server for channel");
                    // Create input channel (SSH -> SFTP)
                    let (tx_in, rx_in) = mpsc::unbounded_channel::<Bytes>();
                    {
                        let mut writers = tcp_writers.lock().await;
                        writers.insert(channel_id, tx_in);
                    }
                    // Create output channel (SFTP -> SSH)
                    let (tx_out, mut rx_out) = mpsc::unbounded_channel::<Bytes>();
                    // Create the stream adapter
                    let stream = crate::utils::ChannelBytesStream {
                        reader: rx_in,
                        writer: tx_out,
                        read_buf: bytes::BytesMut::new(),
                    };
                    // Spawn task to forward SFTP output to SSH channel
                    let session_handle_clone = session_handle.clone();
                    tokio::spawn(async move {
                        while let Some(data) = rx_out.recv().await {
                            if session_handle_clone
                                .data(channel_id, bytes::Bytes::copy_from_slice(data.as_ref()))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        let _ = session_handle_clone.eof(channel_id).await;
                        let _ = session_handle_clone.close(channel_id).await;
                    });
                    // Start SFTP server
                    let sftp_root = self.server.sftp_root();
                    tokio::spawn(async move {
                        let handler = sftp_server::FileSystemHandler::new(sftp_root);
                        russh_sftp::server::run(stream, handler).await;
                    });
                    let _ = session_handle.channel_success(channel_id).await;
                    return Ok(());
                }

                {
                    let default_path = "/usr/lib/openssh/sftp-server";
                    let sftp_server_path = self
                        .server
                        .cfg
                        .sftp_server_path
                        .as_deref()
                        .unwrap_or(default_path);

                    if !std::path::Path::new(sftp_server_path).exists() {
                        error!("SFTP server binary not found at {}", sftp_server_path);
                        let _ = session_handle.channel_failure(channel_id).await;
                        return Ok(());
                    }

                    info!(
                        "Spawning SFTP server: {} in {:?}",
                        sftp_server_path,
                        self.server.base_dir()
                    );
                    let mut cmd = Command::new(sftp_server_path);
                    cmd.current_dir(self.server.base_dir())
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped());

                    let mut child = cmd.spawn().map_err(|e| anyhow::anyhow!(e))?;
                    let stdin = child
                        .stdin
                        .take()
                        .ok_or_else(|| anyhow::anyhow!("SFTP child stdin was not piped"))?;
                    let stdout = child
                        .stdout
                        .take()
                        .ok_or_else(|| anyhow::anyhow!("SFTP child stdout was not piped"))?;
                    let stderr = child
                        .stderr
                        .take()
                        .ok_or_else(|| anyhow::anyhow!("SFTP child stderr was not piped"))?;

                    // Forward SFTP stdout -> SSH data
                    let session_handle_clone = session_handle.clone();
                    tokio::spawn(async move {
                        crate::utils::pipe_read_to_ssh(
                            stdout,
                            session_handle_clone,
                            channel_id,
                            "SFTP stdout to SSH",
                        )
                        .await;
                    });

                    // Forward SFTP stderr -> SSH extended data
                    let session_handle_clone2 = session_handle.clone();
                    tokio::spawn(async move {
                        crate::utils::pipe_read_to_ssh_extended(
                            stderr,
                            session_handle_clone2,
                            channel_id,
                            1,
                            "SFTP stderr to SSH",
                        )
                        .await;
                    });

                    // Forward SSH data -> SFTP stdin
                    let (tx, rx) = mpsc::unbounded_channel::<Bytes>();
                    {
                        let mut writers = tcp_writers.lock().await;
                        writers.insert(channel_id, tx);
                    }

                    let tcp_writers_clone = tcp_writers.clone();
                    tokio::spawn(async move {
                        crate::utils::pipe_rx_to_write(rx, stdin, "SSH to SFTP stdin").await;
                        let mut writers = tcp_writers_clone.lock().await;
                        writers.remove(&channel_id);
                    });

                    // Monitor child process exit
                    let session_handle_clone3 = session_handle.clone();
                    let tcp_writers_clone2 = tcp_writers.clone();
                    tokio::spawn(async move {
                        debug!("SFTP process monitor task started");
                        match child.wait().await {
                            Ok(status) => {
                                debug!("SFTP server exited with status: {}", status);
                                let exit_code = status.code().unwrap_or(0) as u32;
                                let _ = session_handle_clone3
                                    .exit_status_request(channel_id, exit_code)
                                    .await;
                            }
                            Err(e) => {
                                error!("Error waiting for SFTP server: {}", e);
                            }
                        }
                        let _ = session_handle_clone3.close(channel_id).await;

                        // Ensure cleanup
                        let mut writers = tcp_writers_clone2.lock().await;
                        writers.remove(&channel_id);
                        debug!("SFTP process monitor task ended");
                    });
                    info!("SFTP subsystem request accepted and handlers spawned");
                    let _ = session_handle.channel_success(channel_id).await;
                    Ok(())
                }
            } else {
                error!("Unsupported subsystem: {}", subsystem_name);
                let _ = session_handle.channel_failure(channel_id).await;
                Ok(())
            }
        }
    }
}
