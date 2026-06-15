use std::borrow::Cow;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use russh::client;
use russh::{ChannelMsg, Disconnect};
#[cfg(target_os = "linux")]
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info};

use crate::MeshNode;

#[cfg(target_os = "linux")]
pub const VMADDR_CID_ANY: u32 = 0xffff_ffff;

#[cfg(target_os = "linux")]
pub const VMADDR_CID_HOST: u32 = 2;

pub fn trusted_preferred() -> russh::Preferred {
    russh::Preferred {
        kex: russh::Preferred::DEFAULT.kex,
        key: russh::Preferred::DEFAULT.key,
        cipher: Cow::Borrowed(&[russh::cipher::NONE]),
        mac: Cow::Borrowed(&[russh::mac::NONE]),
        compression: Cow::Borrowed(&[russh::compression::NONE]),
    }
}

pub fn trusted_client_config() -> client::Config {
    client::Config {
        preferred: trusted_preferred(),
        anonymous: false,
        limits: russh::Limits::new(
            1 << 30,
            1 << 30,
            std::time::Duration::from_secs(365 * 24 * 60 * 60),
        ),
        nodelay: true,
        ..Default::default()
    }
}

pub async fn run_trusted_server_stdio(server: MeshNode) -> Result<()> {
    set_stdio_raw_mode();
    let config = Arc::new(server.get_trusted_transport_config());
    let stream = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());
    run_trusted_server_stream(config, stream, server, "stdio").await
}

#[cfg(unix)]
fn set_stdio_raw_mode() {
    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO] {
        let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
        let rc = unsafe { libc::tcgetattr(fd, termios.as_mut_ptr()) };
        if rc != 0 {
            debug!(
                "failed to read terminal mode for trusted stdio fd {}: {}",
                fd,
                std::io::Error::last_os_error()
            );
            continue;
        }

        let mut termios = unsafe { termios.assume_init() };
        unsafe {
            libc::cfmakeraw(&mut termios);
        }
        let rc = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) };
        if rc != 0 {
            debug!(
                "failed to set raw terminal mode for trusted stdio fd {}: {}",
                fd,
                std::io::Error::last_os_error()
            );
        }
    }
}

#[cfg(not(unix))]
fn set_stdio_raw_mode() {}

pub async fn run_trusted_uds_server(server: MeshNode, socket_path: impl AsRef<Path>) -> Result<()> {
    let socket_path = socket_path.as_ref();
    if socket_path.exists() {
        std::fs::remove_file(socket_path).with_context(|| {
            format!(
                "remove stale trusted SSH UDS socket {}",
                socket_path.display()
            )
        })?;
    }
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create trusted SSH UDS dir {}", parent.display()))?;
    }

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("bind trusted SSH UDS socket {}", socket_path.display()))?;
    let config = Arc::new(server.get_trusted_transport_config());
    info!("trusted SSH UDS listener on {}", socket_path.display());

    loop {
        let (stream, _) = listener.accept().await?;
        let config = config.clone();
        let server = server.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::run_ssh_stream(config, stream, server, None, "uds", true).await {
                error!("trusted UDS SSH stream failed: {}", e);
            }
        });
    }
}

pub async fn connect_trusted_uds(socket_path: impl AsRef<Path>) -> Result<UnixStream> {
    UnixStream::connect(socket_path.as_ref())
        .await
        .with_context(|| format!("connect trusted SSH UDS {}", socket_path.as_ref().display()))
}

pub fn render_client_line_handshake(
    template: &str,
    cfg: &crate::SshClientConfig,
    user: &str,
    port: u16,
) -> String {
    let port = port.to_string();
    let vsock_port = cfg
        .vsock_port
        .map(|port| port.to_string())
        .unwrap_or_else(|| port.clone());
    let vsock_cid = cfg.vsock_cid.map(|cid| cid.to_string()).unwrap_or_default();
    let uds_path = cfg
        .uds_path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_default();

    template
        .replace("{user}", user)
        .replace("{port}", &port)
        .replace("{vsock_port}", &vsock_port)
        .replace("{vsock_cid}", &vsock_cid)
        .replace("{uds_path}", &uds_path)
}

pub async fn apply_client_line_handshake<S>(
    stream: &mut S,
    cfg: &crate::SshClientConfig,
    user: &str,
    port: u16,
    label: &str,
) -> Result<Option<String>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(handshake) = cfg.line_handshake.as_ref() else {
        return Ok(None);
    };
    if handshake.send.is_empty() {
        anyhow::bail!("line handshake for '{}' has an empty send line", label);
    }

    let mut send = render_client_line_handshake(&handshake.send, cfg, user, port).into_bytes();
    if !send.ends_with(b"\n") {
        send.push(b'\n');
    }
    stream
        .write_all(&send)
        .await
        .with_context(|| format!("write line handshake for '{}'", label))?;
    stream
        .flush()
        .await
        .with_context(|| format!("flush line handshake for '{}'", label))?;

    let response = read_handshake_line(stream, handshake.max_response_bytes)
        .await
        .with_context(|| format!("read line handshake response for '{}'", label))?;
    if let Some(expected) = handshake.expect.as_deref()
        && response != expected
    {
        anyhow::bail!(
            "line handshake for '{}' returned {:?}, expected {:?}",
            label,
            response,
            expected
        );
    }
    if let Some(prefix) = handshake.expect_prefix.as_deref()
        && !response.starts_with(prefix)
    {
        anyhow::bail!(
            "line handshake for '{}' returned {:?}, expected prefix {:?}",
            label,
            response,
            prefix
        );
    }

    debug!("line handshake for '{}' returned {:?}", label, response);
    Ok(Some(response))
}

async fn read_handshake_line<S>(stream: &mut S, max_response_bytes: usize) -> Result<String>
where
    S: AsyncRead + Unpin,
{
    let limit = max_response_bytes.max(1);
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while response.len() < limit {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            anyhow::bail!("line handshake stream closed before response line");
        }
        if byte[0] == b'\n' {
            if response.last() == Some(&b'\r') {
                response.pop();
            }
            return String::from_utf8(response).context("line handshake response is not UTF-8");
        }
        response.push(byte[0]);
    }

    anyhow::bail!(
        "line handshake response exceeded {} bytes without newline",
        limit
    );
}

pub async fn run_trusted_server_stream<S>(
    config: Arc<russh::server::Config>,
    stream: S,
    server: MeshNode,
    label: &'static str,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    crate::run_ssh_stream(config, stream, server, None, label, true).await
}

pub async fn run_trusted_vsock_server(server: MeshNode, cid: u32, port: u32) -> Result<()> {
    let listener = VsockListener::bind(cid, port)?;
    let config = Arc::new(server.get_trusted_transport_config());
    info!("trusted SSH vsock listener on cid={} port={}", cid, port);

    loop {
        let stream = listener.accept().await?;
        let config = config.clone();
        let server = server.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::run_ssh_stream(config, stream, server, None, "vsock", true).await
            {
                error!("trusted vsock SSH stream failed: {}", e);
            }
        });
    }
}

pub async fn run_trusted_vsock_exec(cid: u32, port: u32, user: &str, command: &str) -> Result<i32> {
    let stream = VsockStream::connect(cid, port).await?;
    run_trusted_client_exec(stream, user, command).await
}

pub async fn run_trusted_client_exec<S>(stream: S, user: &str, command: &str) -> Result<i32>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let result = run_trusted_client_exec_collect(stream, user, command).await?;
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    stdout.write_all(&result.stdout).await?;
    stdout.flush().await?;
    stderr.write_all(&result.stderr).await?;
    stderr.flush().await?;
    Ok(result.exit_status)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedExecResult {
    pub exit_status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub async fn run_trusted_client_exec_collect<S>(
    stream: S,
    user: &str,
    command: &str,
) -> Result<TrustedExecResult>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = Arc::new(trusted_client_config());
    let handler = TrustedClientHandler;
    let mut session = client::connect_stream(config, stream, handler)
        .await
        .context("connect trusted SSH stream")?;
    let auth = session
        .authenticate_none(user)
        .await
        .context("trusted none authentication")?;
    if auth != client::AuthResult::Success {
        anyhow::bail!("trusted SSH none authentication failed");
    }

    let mut channel = session
        .channel_open_session()
        .await
        .context("open trusted SSH session channel")?;
    channel
        .exec(true, command.as_bytes())
        .await
        .context("execute trusted SSH command")?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_status = 0;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => {
                stdout.extend_from_slice(&data);
            }
            ChannelMsg::ExtendedData { data, .. } => {
                stderr.extend_from_slice(&data);
            }
            ChannelMsg::ExitStatus {
                exit_status: status,
            } => {
                exit_status = status as i32;
            }
            ChannelMsg::Eof | ChannelMsg::Close => break,
            _ => {}
        }
    }

    session
        .disconnect(Disconnect::ByApplication, "trusted exec complete", "en")
        .await
        .ok();

    Ok(TrustedExecResult {
        exit_status,
        stdout,
        stderr,
    })
}

#[derive(Clone, Debug)]
struct TrustedClientHandler;

impl client::Handler for TrustedClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[cfg(target_os = "linux")]
pub struct VsockListener {
    fd: AsyncFd<OwnedFd>,
}

#[cfg(target_os = "linux")]
impl VsockListener {
    pub fn bind(cid: u32, port: u32) -> Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("create AF_VSOCK socket");
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        set_nonblocking(fd.as_raw_fd())?;

        let addr = sockaddr_vm(cid, port);
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error()).context("bind AF_VSOCK socket");
        }

        let rc = unsafe { libc::listen(fd.as_raw_fd(), 128) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error()).context("listen AF_VSOCK socket");
        }

        Ok(Self {
            fd: AsyncFd::new(fd).context("register AF_VSOCK listener")?,
        })
    }

    pub async fn accept(&self) -> Result<VsockStream> {
        loop {
            let mut guard = self.fd.readable().await?;
            let result = guard.try_io(|inner| {
                let fd = unsafe {
                    libc::accept4(
                        inner.get_ref().as_raw_fd(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    )
                };
                if fd >= 0 {
                    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });

            match result {
                Ok(Ok(fd)) => {
                    debug!("accepted AF_VSOCK stream fd={}", fd.as_raw_fd());
                    return VsockStream::from_owned_fd(fd);
                }
                Ok(Err(e)) => return Err(e).context("accept AF_VSOCK socket"),
                Err(_would_block) => continue,
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub struct VsockListener;

#[cfg(not(target_os = "linux"))]
impl VsockListener {
    pub fn bind(_cid: u32, _port: u32) -> Result<Self> {
        anyhow::bail!("virtio-vsock is only supported on Linux")
    }
}

pub struct VsockStream {
    #[cfg(target_os = "linux")]
    fd: AsyncFd<OwnedFd>,
}

impl VsockStream {
    #[cfg(target_os = "linux")]
    fn from_owned_fd(fd: OwnedFd) -> Result<Self> {
        Ok(Self {
            fd: AsyncFd::new(fd).context("register AF_VSOCK stream")?,
        })
    }

    #[cfg(target_os = "linux")]
    pub async fn connect(cid: u32, port: u32) -> Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("create AF_VSOCK socket");
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        set_nonblocking(fd.as_raw_fd())?;

        let addr = sockaddr_vm(cid, port);
        let rc = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(err).context("connect AF_VSOCK socket");
            }
        }

        let async_fd = AsyncFd::new(fd).context("register AF_VSOCK socket")?;
        if rc < 0 {
            let _ = async_fd
                .writable()
                .await
                .context("wait for AF_VSOCK connect")?;
        }

        let mut so_error = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                async_fd.get_ref().as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut so_error as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error()).context("getsockopt SO_ERROR");
        }
        if so_error != 0 {
            return Err(std::io::Error::from_raw_os_error(so_error)).context("connect AF_VSOCK");
        }

        Self::from_owned_fd(async_fd.into_inner())
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn connect(_cid: u32, _port: u32) -> Result<Self> {
        anyhow::bail!("virtio-vsock is only supported on Linux")
    }
}

impl AsyncRead for VsockStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        #[cfg(target_os = "linux")]
        {
            if buf.remaining() == 0 {
                return std::task::Poll::Ready(Ok(()));
            }

            let mut tmp = vec![0_u8; buf.remaining().min(64 * 1024)];
            loop {
                let mut guard = std::task::ready!(self.fd.poll_read_ready_mut(cx))?;
                let result = guard.try_io(|inner| {
                    let rc = unsafe {
                        libc::read(
                            inner.get_ref().as_raw_fd(),
                            tmp.as_mut_ptr() as *mut libc::c_void,
                            tmp.len(),
                        )
                    };
                    if rc >= 0 {
                        Ok(rc as usize)
                    } else {
                        Err(std::io::Error::last_os_error())
                    }
                });

                match result {
                    Ok(Ok(n)) => {
                        buf.put_slice(&tmp[..n]);
                        return std::task::Poll::Ready(Ok(()));
                    }
                    Ok(Err(e)) => return std::task::Poll::Ready(Err(e)),
                    Err(_would_block) => continue,
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (cx, buf);
            std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "virtio-vsock is only supported on Linux",
            )))
        }
    }
}

impl AsyncWrite for VsockStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        #[cfg(target_os = "linux")]
        {
            loop {
                let mut guard = std::task::ready!(self.fd.poll_write_ready_mut(cx))?;
                let result = guard.try_io(|inner| {
                    let rc = unsafe {
                        libc::write(
                            inner.get_ref().as_raw_fd(),
                            buf.as_ptr() as *const libc::c_void,
                            buf.len(),
                        )
                    };
                    if rc >= 0 {
                        Ok(rc as usize)
                    } else {
                        Err(std::io::Error::last_os_error())
                    }
                });

                match result {
                    Ok(result) => return std::task::Poll::Ready(result),
                    Err(_would_block) => continue,
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (cx, buf);
            std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "virtio-vsock is only supported on Linux",
            )))
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        #[cfg(target_os = "linux")]
        {
            let rc = unsafe { libc::shutdown(self.fd.get_ref().as_raw_fd(), libc::SHUT_WR) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::NotConnected {
                    return std::task::Poll::Ready(Err(err));
                }
            }
        }
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(target_os = "linux")]
fn sockaddr_vm(cid: u32, port: u32) -> libc::sockaddr_vm {
    libc::sockaddr_vm {
        svm_family: libc::AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: cid,
        svm_zero: [0; 4],
    }
}

#[cfg(target_os = "linux")]
fn set_nonblocking(fd: std::os::fd::RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error()).context("fcntl F_GETFL");
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error()).context("fcntl F_SETFL O_NONBLOCK");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{MeshNode, MeshNodeConfig};

    use super::*;

    #[tokio::test]
    async fn line_handshake_sends_rendered_line_and_preserves_stream_tail() {
        let (mut client_io, mut server_io) = tokio::io::duplex(1024);
        let server_task = tokio::spawn(async move {
            let mut line = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                server_io.read_exact(&mut byte).await.unwrap();
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            assert_eq!(String::from_utf8(line).unwrap(), "connect 18522\n");
            server_io
                .write_all(b"OK 9\nSSH-2.0-test\r\n")
                .await
                .unwrap();
        });

        let cfg = crate::SshClientConfig {
            user: "app4".to_string(),
            uds_path: Some(std::path::PathBuf::from("/tmp/ch.vsock")),
            vsock_port: Some(18522),
            line_handshake: Some(crate::LineHandshakeConfig {
                send: "connect {vsock_port}".to_string(),
                expect_prefix: Some("OK ".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let response = apply_client_line_handshake(&mut client_io, &cfg, "app4", 22, "ch-test")
            .await
            .unwrap();
        assert_eq!(response.as_deref(), Some("OK 9"));

        let mut tail = [0u8; 7];
        client_io.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"SSH-2.0");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn trusted_duplex_exec_uses_none_auth_and_none_crypto() {
        let _guard = crate::test_utils::TEST_MUTEX.lock().await;
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base_dir = std::env::temp_dir().join(format!(
            "ssh-mesh-trusted-duplex-{}-{}",
            std::process::id(),
            unique
        ));
        std::fs::create_dir_all(&base_dir).unwrap();

        let mock_socket = base_dir.join("mesh-init-control.sock");
        let _mock_handle = crate::test_utils::start_mock_mesh_init(mock_socket, base_dir.clone());

        let server = MeshNode::new(
            Some(base_dir.clone()),
            Some(MeshNodeConfig {
                base_dir: Some(base_dir),
                ..Default::default()
            }),
        );

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_config = Arc::new(server.get_trusted_transport_config());
        let server_task = tokio::spawn(run_trusted_server_stream(
            server_config,
            server_io,
            server,
            "duplex-test",
        ));

        let result = run_trusted_client_exec_collect(client_io, "alice", "printf trusted-ok")
            .await
            .unwrap();

        assert_eq!(result.exit_status, 0);
        assert_eq!(result.stdout, b"trusted-ok");
        assert!(result.stderr.is_empty());

        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;
    }

    #[tokio::test]
    async fn configured_client_can_maintain_trusted_uds_connection() {
        let _guard = crate::test_utils::TEST_MUTEX.lock().await;
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base_dir = std::env::temp_dir().join(format!(
            "ssh-mesh-trusted-uds-{}-{}",
            std::process::id(),
            unique
        ));
        std::fs::create_dir_all(&base_dir).unwrap();
        let socket_path = base_dir.join("trusted.sock");

        let mock_socket = base_dir.join("mesh-init-control.sock");
        let _mock_handle = crate::test_utils::start_mock_mesh_init(mock_socket, base_dir.clone());

        let server = MeshNode::new(
            Some(base_dir.join("server")),
            Some(MeshNodeConfig {
                base_dir: Some(base_dir.join("server")),
                trusted_uds_path: Some(socket_path.clone()),
                ..Default::default()
            }),
        );
        let client_key = server.private_key().clone();
        let server_task = tokio::spawn(run_trusted_uds_server(server, socket_path.clone()));

        for _ in 0..100 {
            if socket_path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let manager = crate::sshc::SshClientManager::new(client_key, Vec::new(), None, None);
        let cfg = crate::SshClientConfig {
            transport: "uds".to_string(),
            user: "alice".to_string(),
            uds_path: Some(socket_path),
            keep_alive: true,
            ..Default::default()
        };
        let id = match manager.connect_with_config("local-uds", &cfg).await {
            Ok(id) => id,
            Err(e) if format!("{e:?}").contains("Operation not permitted") => {
                server_task.abort();
                return;
            }
            Err(e) => panic!("configured trusted UDS client failed: {e:?}"),
        };
        let result = manager.exec(id, "printf client-uds-ok").await.unwrap();

        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, "client-uds-ok");
        assert!(result.stderr.is_empty());

        server_task.abort();
    }
}
