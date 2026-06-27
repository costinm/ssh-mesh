use crate::policy::FlowContext;
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, copy_bidirectional};
use tokio::net::TcpStream;

pub trait TunByteStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T> TunByteStream for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

pub type BoxTunByteStream = Box<dyn TunByteStream>;

/// Bridge an already-accepted byte stream into a guest TCP listener.
///
/// The source tuple is the original peer address that should be visible to the
/// guest. The stream may be a native TCP accept, SSH channel, HBONE stream, or
/// any other bidirectional transport.
pub async fn bridge_accepted_tcp_to_guest<S>(
    injector: Arc<dyn mesh::tun::TunInjector>,
    src: SocketAddr,
    dst: SocketAddr,
    mut stream: S,
) -> Result<(u64, u64), anyhow::Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut guest = injector
        .connect_tcp(src.ip(), src.port(), dst.ip(), dst.port())
        .await?;
    Ok(copy_bidirectional(&mut stream, &mut guest).await?)
}

#[async_trait::async_trait]
pub trait TcpConnector: Send + Sync + 'static {
    async fn connect(&self, ctx: &FlowContext) -> Result<BoxTunByteStream, anyhow::Error>;
}

#[derive(Debug, Default)]
pub struct NativeTcpConnector;

#[async_trait::async_trait]
impl TcpConnector for NativeTcpConnector {
    async fn connect(&self, ctx: &FlowContext) -> Result<BoxTunByteStream, anyhow::Error> {
        let stream = TcpStream::connect(ctx.dst).await?;
        stream.set_nodelay(true)?;
        tune_backend_socket(&stream);
        Ok(Box::new(stream))
    }
}

#[cfg(target_os = "linux")]
fn tune_backend_socket(stream: &TcpStream) {
    // Bulk proxy traffic benefits from kernel buffers that match the synthetic
    // TCP window, while TCP_NOTSENT_LOWAT reduces wakeups when the kernel send
    // queue is already full. All knobs are best-effort: policy-selected streams
    // may not always be ordinary Linux TCP sockets.
    set_sockopt_int(
        stream,
        libc::IPPROTO_TCP,
        libc::TCP_QUICKACK,
        1,
        "TCP_QUICKACK",
    );
    set_sockopt_int(
        stream,
        libc::IPPROTO_TCP,
        libc::TCP_NOTSENT_LOWAT,
        16 * 1024,
        "TCP_NOTSENT_LOWAT",
    );
    set_sockopt_int(
        stream,
        libc::SOL_SOCKET,
        libc::SO_SNDBUF,
        4 * 1024 * 1024,
        "SO_SNDBUF",
    );
    set_sockopt_int(
        stream,
        libc::SOL_SOCKET,
        libc::SO_RCVBUF,
        4 * 1024 * 1024,
        "SO_RCVBUF",
    );
}

#[cfg(target_os = "linux")]
fn set_sockopt_int(
    stream: &TcpStream,
    level: libc::c_int,
    optname: libc::c_int,
    value: libc::c_int,
    label: &'static str,
) {
    // Best-effort: TCP_QUICKACK is Linux-specific and advisory. Failure should
    // not break non-performance-critical connectors or unusual socket types.
    let rc = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            level,
            optname,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if rc != 0 {
        tracing::debug!(
            error = %std::io::Error::last_os_error(),
            "failed to set {label} on mesh-tun backend socket"
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn tune_backend_socket(_stream: &TcpStream) {}

pub struct FixedTcpConnectorPolicy {
    connector: Arc<dyn TcpConnector>,
}

impl FixedTcpConnectorPolicy {
    pub fn new(connector: Arc<dyn TcpConnector>) -> Self {
        Self { connector }
    }
}

#[async_trait::async_trait]
impl crate::policy::MeshTunPolicy for FixedTcpConnectorPolicy {
    async fn check(&self, _ctx: &FlowContext) -> crate::policy::PolicyDecision {
        crate::policy::PolicyDecision::Allow
    }

    async fn route_tcp(&self, _ctx: &FlowContext) -> crate::policy::TcpRouteDecision {
        crate::policy::TcpRouteDecision::Connect {
            connector: self.connector.clone(),
        }
    }
}
