use crate::packet::build_ipv4_udp_packet;
use mesh::tun::TunInjector;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use tokio::sync::mpsc;

pub struct MeshTunInjector {
    tx: mpsc::Sender<Vec<u8>>,
}

impl MeshTunInjector {
    pub fn new(tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self { tx }
    }
}

#[async_trait::async_trait]
impl TunInjector for MeshTunInjector {
    async fn connect_tcp(
        &self,
        _src_addr: IpAddr,
        _src_port: u16,
        _dst_addr: IpAddr,
        _dst_port: u16,
    ) -> Result<tokio::io::DuplexStream, anyhow::Error> {
        anyhow::bail!("TCP stream injection is not implemented without the embedded TCP/IP stack")
    }

    async fn inject_udp(
        &self,
        src_addr: IpAddr,
        src_port: u16,
        dst_addr: IpAddr,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<(), anyhow::Error> {
        let packet = match (src_addr, dst_addr) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                build_ipv4_udp_packet(src, src_port, dst, dst_port, payload)?
            }
            (IpAddr::V6(_), IpAddr::V6(_)) => {
                anyhow::bail!("IPv6 UDP injection is not implemented yet")
            }
            _ => anyhow::bail!("source and destination IP versions differ"),
        };

        self.tx.send(packet).await.map_err(|_| {
            crate::stats::stats()
                .tun_output_queue_full
                .fetch_add(1, Ordering::Relaxed);
            anyhow::anyhow!("TUN output queue closed")
        })?;
        Ok(())
    }
}
