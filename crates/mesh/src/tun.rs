use async_trait::async_trait;

/// Metadata for an inbound TCP connection captured from the TUN.
pub struct TunTcpMeta {
    pub src_addr: std::net::IpAddr,
    pub src_port: u16,
    pub dst_addr: std::net::IpAddr,
    pub dst_port: u16,
}

/// Handler for TCP connections arriving from the TUN device.
///
/// Called when an application behind the TUN initiates a TCP connection.
/// The implementor receives a bidirectional `DuplexStream` representing
/// the TCP flow and the connection metadata.
#[async_trait]
pub trait TunTcpHandler: Send + Sync + 'static {
    async fn handle_tcp(&self, meta: TunTcpMeta, stream: tokio::io::DuplexStream);
}

/// A received UDP datagram from the TUN device.
pub struct TunUdpPacket {
    pub src_addr: std::net::IpAddr,
    pub src_port: u16,
    pub dst_addr: std::net::IpAddr,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

/// Handler for generic UDP packets arriving from the TUN device.
#[async_trait]
pub trait TunUdpHandler: Send + Sync + 'static {
    async fn handle_udp(&self, packet: TunUdpPacket);
}

/// Handler for DNS queries (UDP port 53) arriving from the TUN device.
#[async_trait]
pub trait TunDnsHandler: Send + Sync + 'static {
    async fn handle_dns(&self, packet: TunUdpPacket);
}

/// Sender for injecting TCP connections and UDP packets back into the TUN.
///
/// Obtained from `MeshTun` after initialization. Trait-based so that
/// consumers in other crates can hold a reference without depending on
/// the `tun` crate.
#[async_trait]
pub trait TunInjector: Send + Sync + 'static {
    /// Create a TCP connection into the guest that appears to originate from
    /// the given source tuple. The caller may back this with a local TCP
    /// accept, SSH channel, HBONE stream, or another byte-stream transport.
    async fn connect_tcp(
        &self,
        src_addr: std::net::IpAddr,
        src_port: u16,
        dst_addr: std::net::IpAddr,
        dst_port: u16,
    ) -> Result<tokio::io::DuplexStream, anyhow::Error>;

    /// Inject a UDP packet into the TUN device.
    async fn inject_udp(
        &self,
        src_addr: std::net::IpAddr,
        src_port: u16,
        dst_addr: std::net::IpAddr,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<(), anyhow::Error>;
}
