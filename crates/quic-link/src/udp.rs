//! Host-only Tokio UDP socket adapter (`TokioUdpLink`) for `quic-link` (`feature = "tokio"`).
//!
//! Provides:
//! - IPv4 and scoped IPv6 peer parsing ([`parse_udp_peer`], [`wildcard_bind`]),
//! - Kernel receive/send buffer and DSCP (`IP_TOS` / `IPV6_TCLASS`) configuration ([`UdpSocketConfig`]),
//! - Zero-copy UDP receive directly into a [`quic_base::PacketPool`] slot (`recv_into_pool`), and
//! - Non-blocking/async UDP transmit from [`OutboundLinkPacket`](crate::OutboundLinkPacket) (`try_send_packet`, `send_packet`).

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use tokio::net::UdpSocket;

use crate::assoc::{AssocConfig, QuicLinkAssoc};
use crate::congestion::{LinkId, LinkProfile, LinkTxOutcome};
use crate::wire::ConnectionId;
use quic_base::{
    AssociationEgress, DEFAULT_HEADROOM, DEFAULT_MAX_PAYLOAD, PacketPool, PoolPacket,
    StreamPriority, TxPacketMeta, XipLazyPacket, XipLazyPool,
};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Default host kernel UDP socket receive/send buffer request (`4 MiB`).
pub const HOST_UDP_SOCKET_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// Parse a UDP peer endpoint string using `default_port` when no port is specified.
///
/// Accepts `udp://192.0.2.1:4433`, `192.0.2.1`, `[2001:db8::1]`, `[fe80::1%wlan0]:4433`,
/// and `[fe80::1%3]`.
pub fn parse_udp_peer(name: &str, default_port: u16) -> io::Result<SocketAddr> {
    let name = name.strip_prefix("udp://").unwrap_or(name);
    if let Ok(address) = name.parse::<SocketAddr>() {
        return Ok(address);
    }
    if let Ok(address) = name.parse::<IpAddr>() {
        return Ok(SocketAddr::new(address, default_port));
    }
    if let Some(address) = name
        .strip_prefix('[')
        .and_then(|name| name.strip_suffix(']'))
        .and_then(|address| address.parse::<Ipv6Addr>().ok())
    {
        return Ok(SocketAddr::new(IpAddr::V6(address), default_port));
    }
    let (address_scope, port) = name
        .strip_prefix('[')
        .and_then(|name| {
            name.rsplit_once("]:")
                .map(|(address, port)| (address, Some(port)))
                .or_else(|| name.strip_suffix(']').map(|address| (address, None)))
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid UDP peer"))?;
    let (address, scope) = address_scope.rsplit_once('%').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "scoped IPv6 peer needs %INTERFACE",
        )
    })?;
    let address = address
        .parse::<Ipv6Addr>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let port = port
        .map(str::parse::<u16>)
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
        .unwrap_or(default_port);
    let scope_id = scope.parse::<u32>().ok().or_else(|| {
        std::fs::read_to_string(std::format!("/sys/class/net/{scope}/ifindex"))
            .ok()
            .and_then(|index| index.trim().parse::<u32>().ok())
    });
    let scope_id = scope_id.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            std::format!("unknown IPv6 scope interface {scope:?}"),
        )
    })?;
    Ok(SocketAddr::V6(SocketAddrV6::new(
        address, port, 0, scope_id,
    )))
}

/// Wildcard bind address in `peer`'s address family.
pub const fn wildcard_bind(peer: SocketAddr, port: u16) -> SocketAddr {
    match peer {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
    }
}

/// Kernel socket buffer and DSCP configuration for [`TokioUdpLink`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpSocketConfig {
    /// Six-bit Differentiated Services Code Point (`0..=63`).
    pub dscp: Option<u8>,
    /// Requested kernel receive queue size in bytes.
    pub receive_buffer_bytes: Option<usize>,
    /// Requested kernel send queue size in bytes.
    pub send_buffer_bytes: Option<usize>,
}

impl Default for UdpSocketConfig {
    fn default() -> Self {
        Self {
            dscp: None,
            receive_buffer_bytes: Some(HOST_UDP_SOCKET_BUFFER_BYTES),
            send_buffer_bytes: Some(HOST_UDP_SOCKET_BUFFER_BYTES),
        }
    }
}

impl UdpSocketConfig {
    fn validate(self) -> io::Result<Self> {
        if self.dscp.is_some_and(|dscp| dscp > 63) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP DSCP must fit in six bits",
            ));
        }
        for bytes in [self.receive_buffer_bytes, self.send_buffer_bytes]
            .into_iter()
            .flatten()
        {
            if bytes == 0 || i32::try_from(bytes).is_err() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP socket buffer size must be in 1..=i32::MAX",
                ));
            }
        }
        Ok(self)
    }
}

#[cfg(unix)]
fn set_socket_option(
    socket: &impl std::os::fd::AsRawFd,
    level: libc::c_int,
    option: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&value as *const libc::c_int).cast(),
            core::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn configure_socket(
    socket: &impl std::os::fd::AsRawFd,
    address: SocketAddr,
    config: UdpSocketConfig,
) -> io::Result<()> {
    let config = config.validate()?;
    if let Some(bytes) = config.receive_buffer_bytes {
        set_socket_option(
            socket,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            bytes as libc::c_int,
        )?;
    }
    if let Some(bytes) = config.send_buffer_bytes {
        set_socket_option(
            socket,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            bytes as libc::c_int,
        )?;
    }
    if let Some(dscp) = config.dscp {
        let traffic_class = libc::c_int::from(dscp << 2);
        match address {
            SocketAddr::V4(_) => {
                set_socket_option(socket, libc::IPPROTO_IP, libc::IP_TOS, traffic_class)?;
            }
            SocketAddr::V6(_) => {
                set_socket_option(socket, libc::IPPROTO_IPV6, libc::IPV6_TCLASS, traffic_class)?;
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn configure_socket(
    _socket: &std::net::UdpSocket,
    _address: SocketAddr,
    config: UdpSocketConfig,
) -> io::Result<()> {
    let config = config.validate()?;
    if config.dscp.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "UDP DSCP configuration is unsupported on this platform",
        ));
    }
    Ok(())
}

/// Host Tokio UDP socket adapter that reads UDP datagrams directly into [`PacketPool`] slots and
/// transmits [`PoolPacket`] slices without extra heap copies.
#[derive(Clone)]
pub struct TokioUdpLink {
    socket: Arc<UdpSocket>,
    max_packet_size: usize,
}

impl TokioUdpLink {
    /// Bind a new host UDP socket with [`UdpSocketConfig::default()`].
    pub async fn bind(address: SocketAddr) -> io::Result<Self> {
        Self::bind_with_config(address, UdpSocketConfig::default()).await
    }

    /// Bind and configure a new host UDP socket.
    pub async fn bind_with_config(
        address: SocketAddr,
        config: UdpSocketConfig,
    ) -> io::Result<Self> {
        config.validate()?;
        let socket = std::net::UdpSocket::bind(address)?;
        configure_socket(&socket, socket.local_addr()?, config)?;
        Self::from_configured_std(socket)
    }

    /// Adopt an existing [`std::net::UdpSocket`] and apply [`UdpSocketConfig::default()`].
    pub fn from_std(socket: std::net::UdpSocket) -> io::Result<Self> {
        Self::from_std_with_config(socket, UdpSocketConfig::default())
    }

    /// Adopt an existing [`std::net::UdpSocket`] and apply `config`.
    pub fn from_std_with_config(
        socket: std::net::UdpSocket,
        config: UdpSocketConfig,
    ) -> io::Result<Self> {
        config.validate()?;
        configure_socket(&socket, socket.local_addr()?, config)?;
        Self::from_configured_std(socket)
    }

    fn from_configured_std(socket: std::net::UdpSocket) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket: Arc::new(UdpSocket::from_std(socket)?),
            max_packet_size: DEFAULT_MAX_PAYLOAD,
        })
    }

    /// Configure the maximum UDP datagram payload size read into a pool packet (`DEFAULT_MAX_PAYLOAD = 1500` by default).
    pub fn set_max_packet_size(&mut self, max_packet_size: usize) {
        self.max_packet_size = max_packet_size.max(64);
    }

    /// Local socket address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Borrow the underlying [`tokio::net::UdpSocket`].
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Receive one UDP datagram directly into a freshly allocated packet from `pool` at its
    /// configured headroom (`alloc_with_headroom(headroom)`), returning `(packet, peer_addr)`.
    pub async fn recv_into_pool<Pool: PacketPool>(
        &self,
        pool: &Pool,
        headroom: usize,
    ) -> io::Result<(Pool::Packet, SocketAddr)> {
        let mut pkt = pool
            .alloc_with_headroom(headroom)
            .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "packet pool exhausted"))?;
        let start = pkt.range().start;
        let max_len = pkt.tailroom().min(self.max_packet_size);
        if max_len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "insufficient packet tailroom",
            ));
        }
        let slot = pkt
            .slot_slice_mut()
            .map_err(|_| io::Error::other("fresh pool packet is shared"))?;
        let (len, peer) = self
            .socket
            .recv_from(&mut slot[start..start + max_len])
            .await?;
        pkt.set_range(start..start + len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid packet range"))?;
        Ok((pkt, peer))
    }

    /// Non-blocking transmit of `packet` to `peer`.
    ///
    /// Returns `Ok(LinkTxOutcome::Sent)` when the datagram was accepted by the kernel,
    /// `Err(io::ErrorKind::WouldBlock)` when the kernel send queue is full, or
    /// `Ok(LinkTxOutcome::Failed)` on immediate send error.
    pub fn try_send_packet<P: PoolPacket>(
        &self,
        packet: &P,
        peer: SocketAddr,
    ) -> io::Result<LinkTxOutcome> {
        let bytes = packet.bytes();
        match self.socket.try_send_to(bytes, peer) {
            Ok(sent) if sent == bytes.len() => Ok(LinkTxOutcome::Sent),
            Ok(_) => Ok(LinkTxOutcome::Failed),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
            Err(_) => Ok(LinkTxOutcome::Failed),
        }
    }

    /// Async transmit of `packet` to `peer`, awaiting socket writability if needed.
    pub async fn send_packet<P: PoolPacket>(
        &self,
        packet: &P,
        peer: SocketAddr,
    ) -> io::Result<LinkTxOutcome> {
        let bytes = packet.bytes();
        match self.socket.send_to(bytes, peer).await {
            Ok(sent) if sent == bytes.len() => Ok(LinkTxOutcome::Sent),
            Ok(_) => Ok(LinkTxOutcome::Failed),
            Err(e) => Err(e),
        }
    }

    /// Spawn a background [`QuicLinkAssoc`] UDP packet-link task for `peer`, returning
    /// `(tx, rx)` channels ready to pass directly to `quic_mux::TokioMux::add_packet_link`.
    ///
    /// Outbound `quic-mux` frames sent on `tx` are wrapped with a [`ShortHeader`](crate::ShortHeader),
    /// tracked in [`QuicLinkAssoc`] for Selective ACK (`0x02`) loss recovery and PTO retransmission,
    /// and transmitted to `peer` over this UDP socket. Incoming UDP datagrams from `peer` are
    /// demultiplexed by [`QuicLinkAssoc::receive_packet`] and their inner `quic-mux` frames are
    /// delivered on `rx`.
    pub fn spawn_packet_link(
        &self,
        peer: SocketAddr,
        assoc_config: AssocConfig,
        channel_capacity: usize,
    ) -> (
        mpsc::Sender<std::vec::Vec<u8>>,
        mpsc::Receiver<std::vec::Vec<u8>>,
        JoinHandle<()>,
    ) {
        spawn_udp_assoc_packet_link(
            self.clone(),
            peer,
            assoc_config,
            LinkProfile::udp_datagram(0, 1200, assoc_config.default_peer_cid),
            channel_capacity,
        )
    }
}

/// Spawn a background [`QuicLinkAssoc`] driver over `udp_link` to `peer` with an explicit
/// [`LinkProfile`], returning `(tx, rx, task)` where `(tx, rx)` plug directly into
/// `quic_mux::TokioMux::add_packet_link`.
pub fn spawn_udp_assoc_packet_link(
    udp_link: TokioUdpLink,
    peer: SocketAddr,
    assoc_config: AssocConfig,
    mut profile: LinkProfile,
    channel_capacity: usize,
) -> (
    mpsc::Sender<std::vec::Vec<u8>>,
    mpsc::Receiver<std::vec::Vec<u8>>,
    JoinHandle<()>,
) {
    let cap = channel_capacity.max(16);
    let (mux_to_link_tx, mut mux_to_link_rx) = mpsc::channel::<std::vec::Vec<u8>>(cap);
    let (link_to_mux_tx, link_to_mux_rx) = mpsc::channel::<std::vec::Vec<u8>>(cap);

    // Ensure pacing does not stall burst frames from `TokioMux` on localhost / LAN unless configured.
    if let crate::congestion::CongestionMode::NewRenoPaced {
        initial_window_bytes,
        ..
    } = profile.congestion_mode
    {
        profile.congestion_mode = crate::congestion::CongestionMode::NewRenoPaced {
            initial_window_bytes: initial_window_bytes.max(64 * 1024),
            pacing: crate::congestion::PacingConfig::disabled(profile.mtu),
        };
    }

    let task = tokio::spawn(async move {
        let pool = XipLazyPool::with_default_geometry(256);
        let mut assoc = QuicLinkAssoc::<XipLazyPacket>::new(assoc_config);
        let link_id = LinkId(1);
        assoc.upsert_link(link_id, profile);
        let start = Instant::now();
        let mut pending_mux_frames: std::collections::VecDeque<std::vec::Vec<u8>> =
            std::collections::VecDeque::new();

        loop {
            let now_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
            assoc.set_now_us(now_us);

            // Try to admit any pending mux frames into `QuicLinkAssoc`.
            while let Some(raw) = pending_mux_frames.pop_front() {
                let Ok(mut pkt) = pool.alloc() else {
                    pending_mux_frames.push_front(raw);
                    break;
                };
                if pkt.append(&raw).is_err() {
                    continue;
                }
                let meta = TxPacketMeta {
                    association: assoc.config().assoc_id,
                    stream_id: None,
                    priority: StreamPriority::NORMAL,
                    retransmittable: true,
                };
                if assoc.send_packet(meta, pkt).is_err() {
                    pending_mux_frames.push_front(raw);
                    break;
                }
            }

            let mut pool_clone = pool.clone();
            assoc.poll_timers(&mut pool_clone, now_us);

            while let Some(out) = assoc.pop_outbound_packet() {
                let outcome = loop {
                    match udp_link.try_send_packet(&out.packet, peer) {
                        Ok(o) => break o,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            if udp_link.socket().writable().await.is_err() {
                                break LinkTxOutcome::Failed;
                            }
                        }
                        Err(_) => break LinkTxOutcome::Failed,
                    }
                };
                let done_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
                assoc.on_driver_complete(out.link_id, out.packet_number, outcome, done_us);
            }

            let now_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
            let sleep_dur = match assoc.next_deadline_us() {
                Some(dl) => Duration::from_micros(dl.saturating_sub(now_us).max(500)),
                None if !pending_mux_frames.is_empty() => Duration::from_millis(2),
                None => Duration::from_millis(25),
            };

            tokio::select! {
                biased;
                recv_res = udp_link.recv_into_pool(&pool, DEFAULT_HEADROOM) => {
                    if let Ok((pkt, from)) = recv_res {
                        if from == peer {
                            let rx_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
                            if let Ok(outcome) = assoc.receive_packet(link_id, pkt, rx_us) {
                                if let Some(mux_pkt) = outcome.mux_packet {
                                    let bytes = mux_pkt.bytes().to_vec();
                                    drop(mux_pkt);
                                    if link_to_mux_tx.send(bytes).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                maybe_raw = mux_to_link_rx.recv(), if pending_mux_frames.len() < cap => {
                    match maybe_raw {
                        Some(raw) => {
                            pending_mux_frames.push_back(raw);
                            while pending_mux_frames.len() < cap {
                                match mux_to_link_rx.try_recv() {
                                    Ok(next) => pending_mux_frames.push_back(next),
                                    Err(_) => break,
                                }
                            }
                        }
                        None => {
                            if pending_mux_frames.is_empty() {
                                break;
                            }
                        }
                    }
                }
                _ = tokio::time::sleep(sleep_dur) => {}
            }
        }
    });

    (mux_to_link_tx, link_to_mux_rx, task)
}

/// Convenience helper returning `(tx, rx, task)` for a `TokioUdpLink` connected to `peer` with
/// default [`AssocConfig`] (`local_cid` and `default_peer_cid` both set to `cid`).
pub fn spawn_udp_packet_link(
    udp_link: TokioUdpLink,
    peer: SocketAddr,
    cid: ConnectionId,
) -> (
    mpsc::Sender<std::vec::Vec<u8>>,
    mpsc::Receiver<std::vec::Vec<u8>>,
    JoinHandle<()>,
) {
    let cfg = AssocConfig {
        local_cid: Some(cid),
        default_peer_cid: cid,
        ..AssocConfig::default()
    };
    udp_link.spawn_packet_link(peer, cfg, 128)
}
