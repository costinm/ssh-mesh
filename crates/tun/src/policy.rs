use std::net::{IpAddr, SocketAddr};

pub type VmId = String;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FlowProtocol {
    Tcp,
    Udp,
    Dns,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FlowContext {
    pub vm_id: VmId,
    pub protocol: FlowProtocol,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PolicyDecision {
    Allow,
    Deny { reason: String },
}

impl PolicyDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

#[async_trait::async_trait]
pub trait MeshTunPolicy: Send + Sync + 'static {
    async fn check(&self, ctx: &FlowContext) -> PolicyDecision;
}

#[derive(Debug, Default)]
pub struct AllowAllPolicy;

#[async_trait::async_trait]
impl MeshTunPolicy for AllowAllPolicy {
    async fn check(&self, _ctx: &FlowContext) -> PolicyDecision {
        PolicyDecision::Allow
    }
}

#[derive(Debug, Clone)]
pub struct DenyPortPolicy {
    pub dst_addr: Option<IpAddr>,
    pub dst_port: u16,
    pub reason: String,
}

#[async_trait::async_trait]
impl MeshTunPolicy for DenyPortPolicy {
    async fn check(&self, ctx: &FlowContext) -> PolicyDecision {
        if ctx.dst.port() == self.dst_port
            && self
                .dst_addr
                .map(|addr| addr == ctx.dst.ip())
                .unwrap_or(true)
        {
            return PolicyDecision::Deny {
                reason: self.reason.clone(),
            };
        }
        PolicyDecision::Allow
    }
}
