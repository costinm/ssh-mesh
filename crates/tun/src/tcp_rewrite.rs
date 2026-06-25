use crate::packet::{parse_ip_packet, rewrite_ipv4_tcp, TunPacket};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TcpRewriteConfig {
    pub proxy_addr: Ipv4Addr,
    pub first_port: u16,
    pub last_port: u16,
}

impl Default for TcpRewriteConfig {
    fn default() -> Self {
        Self {
            proxy_addr: Ipv4Addr::new(169, 254, 0, 1),
            first_port: 40_000,
            last_port: 60_000,
        }
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct TcpFlowKey {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TcpRewriteEntry {
    pub original: TcpFlowKey,
    pub translated_src: SocketAddr,
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct TcpRewriteStats {
    pub active_flows: usize,
    pub translated_packets: u64,
    pub reverse_packets: u64,
    pub dropped_packets: u64,
}

#[derive(Debug)]
pub struct TcpRewriter {
    config: TcpRewriteConfig,
    next_port: u16,
    forward: HashMap<TcpFlowKey, TcpRewriteEntry>,
    reverse: HashMap<TcpFlowKey, TcpFlowKey>,
    stats: TcpRewriteStats,
}

impl TcpRewriter {
    pub fn new(config: TcpRewriteConfig) -> Result<Self, anyhow::Error> {
        if config.first_port == 0 || config.first_port > config.last_port {
            anyhow::bail!(
                "invalid TCP rewrite port range {}..={}",
                config.first_port,
                config.last_port
            );
        }
        Ok(Self {
            next_port: config.first_port,
            config,
            forward: HashMap::new(),
            reverse: HashMap::new(),
            stats: TcpRewriteStats::default(),
        })
    }

    pub fn stats(&self) -> TcpRewriteStats {
        let mut stats = self.stats.clone();
        stats.active_flows = self.forward.len();
        stats
    }

    pub fn config(&self) -> &TcpRewriteConfig {
        &self.config
    }

    pub fn lookup_forward(&self, key: &TcpFlowKey) -> Option<&TcpRewriteEntry> {
        self.forward.get(key)
    }

    pub fn translate_outbound(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>, anyhow::Error> {
        let TunPacket::Tcp(tcp) = parse_ip_packet(packet) else {
            self.stats.dropped_packets += 1;
            return Ok(None);
        };
        let (IpAddr::V4(src_addr), IpAddr::V4(dst_addr)) = (tcp.src_addr, tcp.dst_addr) else {
            self.stats.dropped_packets += 1;
            return Ok(None);
        };

        let original = TcpFlowKey {
            src: SocketAddr::new(IpAddr::V4(src_addr), tcp.src_port),
            dst: SocketAddr::new(IpAddr::V4(dst_addr), tcp.dst_port),
        };
        let entry = if let Some(entry) = self.forward.get(&original) {
            entry.clone()
        } else if tcp.syn && !tcp.ack {
            self.create_entry(original.clone(), dst_addr, tcp.dst_port)?
        } else {
            self.stats.dropped_packets += 1;
            return Ok(None);
        };

        let translated_src = match entry.translated_src {
            SocketAddr::V4(addr) => *addr.ip(),
            SocketAddr::V6(_) => unreachable!("IPv4 rewriter allocated IPv6 address"),
        };
        self.stats.translated_packets += 1;
        Ok(Some(rewrite_ipv4_tcp(
            packet,
            translated_src,
            entry.translated_src.port(),
            dst_addr,
            tcp.dst_port,
        )?))
    }

    pub fn translate_inbound(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>, anyhow::Error> {
        let TunPacket::Tcp(tcp) = parse_ip_packet(packet) else {
            self.stats.dropped_packets += 1;
            return Ok(None);
        };
        let (IpAddr::V4(src_addr), IpAddr::V4(dst_addr)) = (tcp.src_addr, tcp.dst_addr) else {
            self.stats.dropped_packets += 1;
            return Ok(None);
        };

        let reverse_key = TcpFlowKey {
            src: SocketAddr::new(IpAddr::V4(src_addr), tcp.src_port),
            dst: SocketAddr::new(IpAddr::V4(dst_addr), tcp.dst_port),
        };
        let Some(original) = self.reverse.get(&reverse_key).cloned() else {
            self.stats.dropped_packets += 1;
            return Ok(None);
        };
        let original_src = match original.src {
            SocketAddr::V4(addr) => *addr.ip(),
            SocketAddr::V6(_) => unreachable!("IPv4 rewriter tracked IPv6 client"),
        };
        let original_dst = match original.dst {
            SocketAddr::V4(addr) => *addr.ip(),
            SocketAddr::V6(_) => unreachable!("IPv4 rewriter tracked IPv6 remote"),
        };

        self.stats.reverse_packets += 1;
        Ok(Some(rewrite_ipv4_tcp(
            packet,
            original_dst,
            original.dst.port(),
            original_src,
            original.src.port(),
        )?))
    }

    fn create_entry(
        &mut self,
        original: TcpFlowKey,
        dst_addr: Ipv4Addr,
        dst_port: u16,
    ) -> Result<TcpRewriteEntry, anyhow::Error> {
        let port = self.allocate_port()?;
        let translated_src = SocketAddr::new(IpAddr::V4(self.config.proxy_addr), port);
        let entry = TcpRewriteEntry {
            original: original.clone(),
            translated_src,
        };
        let reverse_key = TcpFlowKey {
            src: SocketAddr::new(IpAddr::V4(dst_addr), dst_port),
            dst: translated_src,
        };
        self.forward.insert(original.clone(), entry.clone());
        self.reverse.insert(reverse_key, original);
        Ok(entry)
    }

    fn allocate_port(&mut self) -> Result<u16, anyhow::Error> {
        let total = u32::from(self.config.last_port) - u32::from(self.config.first_port) + 1;
        for _ in 0..total {
            let port = self.next_port;
            self.next_port = if self.next_port == self.config.last_port {
                self.config.first_port
            } else {
                self.next_port + 1
            };
            let in_use = self
                .forward
                .values()
                .any(|entry| entry.translated_src.port() == port);
            if !in_use {
                return Ok(port);
            }
        }
        anyhow::bail!("TCP rewrite port range exhausted")
    }
}
