use crate::policy::FlowContext;
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
        Ok(Box::new(stream))
    }
}

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
