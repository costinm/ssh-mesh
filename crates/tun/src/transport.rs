use crate::policy::FlowContext;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

pub trait TunByteStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T> TunByteStream for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

pub type BoxTunByteStream = Box<dyn TunByteStream>;

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
        set_tcp_quickack(&stream);
        Ok(Box::new(stream))
    }
}

#[cfg(target_os = "linux")]
fn set_tcp_quickack(stream: &TcpStream) {
    let value: libc::c_int = 1;
    // Best-effort: TCP_QUICKACK is Linux-specific and advisory. Failure should
    // not break non-performance-critical connectors or unusual socket types.
    let rc = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_QUICKACK,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if rc != 0 {
        tracing::debug!(
            error = %std::io::Error::last_os_error(),
            "failed to set TCP_QUICKACK on mesh-tun backend socket"
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn set_tcp_quickack(_stream: &TcpStream) {}

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
