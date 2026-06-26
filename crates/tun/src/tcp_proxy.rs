use crate::packet::{TunTcpPacket, build_ipv4_tcp_packet, build_ipv4_tcp_packet_with_options};
use crate::policy::{FlowContext, FlowProtocol, MeshTunPolicy, TcpRouteDecision};
use mesh::config::DEFAULT_MESH_TUN_MTU;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, mpsc};

const TCP_REORDER_BUFFER_MAX_BYTES: usize = 256 * 1024;
const TCP_SYNTHETIC_WINDOW_BYTES: u32 = 4 * 1024 * 1024;
const IPV4_TCP_HEADER_BYTES: u32 = 40;
const TCP_WINDOW_SCALE_SHIFT: u8 = 7;

fn default_tcp_mss() -> u16 {
    DEFAULT_MESH_TUN_MTU
        .saturating_sub(IPV4_TCP_HEADER_BYTES)
        .min(u16::MAX as u32) as u16
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TcpProxyConfig {
    pub max_flows: usize,
    pub per_flow_queue_capacity: usize,
    pub handshake_timeout: std::time::Duration,
    pub connect_timeout: std::time::Duration,
}

impl Default for TcpProxyConfig {
    fn default() -> Self {
        Self {
            max_flows: 4096,
            per_flow_queue_capacity: 256,
            handshake_timeout: std::time::Duration::from_secs(10),
            connect_timeout: std::time::Duration::from_secs(10),
        }
    }
}

#[derive(Clone)]
pub struct TcpProxyManager {
    config: TcpProxyConfig,
    flows: Arc<Mutex<HashMap<TcpFlowKey, mpsc::Sender<TunTcpPacket>>>>,
    outgoing_tx: mpsc::Sender<Vec<u8>>,
    policy: Arc<dyn MeshTunPolicy>,
    vm_id: String,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct TcpFlowKey {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

fn tcp_seq_after(seq: u32, other: u32) -> bool {
    (seq.wrapping_sub(other) as i32) > 0
}

fn tcp_seq_before_or_equal(seq: u32, other: u32) -> bool {
    (seq.wrapping_sub(other) as i32) <= 0
}

impl TcpProxyManager {
    pub fn new(
        vm_id: String,
        outgoing_tx: mpsc::Sender<Vec<u8>>,
        policy: Arc<dyn MeshTunPolicy>,
        config: TcpProxyConfig,
    ) -> Self {
        Self {
            config,
            flows: Arc::new(Mutex::new(HashMap::new())),
            outgoing_tx,
            policy,
            vm_id,
        }
    }

    pub async fn handle_packet(&self, pkt: TunTcpPacket) {
        crate::stats::stats()
            .tcp_packet
            .fetch_add(1, Ordering::Relaxed);
        if !pkt.payload.is_empty() {
            crate::stats::stats()
                .tcp_packet_payload_bytes
                .fetch_add(pkt.payload.len() as u64, Ordering::Relaxed);
        }
        let key = TcpFlowKey {
            src: SocketAddr::new(pkt.src_addr, pkt.src_port),
            dst: SocketAddr::new(pkt.dst_addr, pkt.dst_port),
        };

        let mut flows_guard = self.flows.lock().await;
        if let Some(tx) = flows_guard.get(&key) {
            crate::stats::stats()
                .tcp_flow_packet
                .fetch_add(1, Ordering::Relaxed);
            if tx.try_send(pkt).is_err() {
                crate::stats::stats()
                    .tcp_flow_queue_full
                    .fetch_add(1, Ordering::Relaxed);
            }
        } else if pkt.syn && !pkt.ack {
            if flows_guard.len() >= self.config.max_flows {
                crate::stats::stats()
                    .tcp_flow_rejected
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            crate::stats::stats()
                .tcp_syn
                .fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = mpsc::channel(self.config.per_flow_queue_capacity);
            flows_guard.insert(key.clone(), tx.clone());

            let flows_clone = self.flows.clone();
            let outgoing_tx = self.outgoing_tx.clone();
            let policy = self.policy.clone();
            let config = self.config.clone();
            let vm_id = self.vm_id.clone();

            tokio::spawn(async move {
                if tx.try_send(pkt).is_err() {
                    crate::stats::stats()
                        .tcp_flow_queue_full
                        .fetch_add(1, Ordering::Relaxed);
                }
                handle_tcp_flow(key.src, key.dst, rx, outgoing_tx, policy, config, vm_id).await;
                flows_clone.lock().await.remove(&key);
            });
        }
    }
}

async fn handle_tcp_flow(
    src: SocketAddr,
    dst: SocketAddr,
    mut rx: mpsc::Receiver<TunTcpPacket>,
    outgoing_tx: mpsc::Sender<Vec<u8>>,
    policy: Arc<dyn MeshTunPolicy>,
    config: TcpProxyConfig,
    vm_id: String,
) {
    let syn_pkt = match rx.recv().await {
        Some(pkt) if pkt.syn && !pkt.ack => pkt,
        _ => return,
    };
    crate::stats::stats()
        .tcp_flow_open
        .fetch_add(1, Ordering::Relaxed);

    let src_ip_v4 = match src.ip() {
        IpAddr::V4(ip) => ip,
        _ => return,
    };
    let dst_ip_v4 = match dst.ip() {
        IpAddr::V4(ip) => ip,
        _ => return,
    };

    let context = FlowContext {
        vm_id,
        protocol: FlowProtocol::Tcp,
        src,
        dst,
    };

    let connect_result = match policy.route_tcp(&context).await {
        TcpRouteDecision::Connect { connector } => {
            tokio::time::timeout(config.connect_timeout, connector.connect(&context)).await
        }
        TcpRouteDecision::Deny { reason } => {
            tracing::debug!(?src, ?dst, %reason, "TCP flow denied before SYN-ACK");
            crate::stats::stats()
                .tcp_flow_rejected
                .fetch_add(1, Ordering::Relaxed);
            send_tcp_reset(
                src_ip_v4,
                src.port(),
                dst_ip_v4,
                dst.port(),
                &syn_pkt,
                &outgoing_tx,
            )
            .await;
            return;
        }
    };

    let backend_stream = match connect_result {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            tracing::debug!(?src, ?dst, %error, "TCP backend connect failed before SYN-ACK");
            crate::stats::stats()
                .tcp_flow_error
                .fetch_add(1, Ordering::Relaxed);
            send_tcp_reset(
                src_ip_v4,
                src.port(),
                dst_ip_v4,
                dst.port(),
                &syn_pkt,
                &outgoing_tx,
            )
            .await;
            return;
        }
        Err(_) => {
            tracing::debug!(?src, ?dst, "TCP backend connect timed out before SYN-ACK");
            crate::stats::stats()
                .tcp_flow_error
                .fetch_add(1, Ordering::Relaxed);
            send_tcp_reset(
                src_ip_v4,
                src.port(),
                dst_ip_v4,
                dst.port(),
                &syn_pkt,
                &outgoing_tx,
            )
            .await;
            return;
        }
    };

    let (mut reader, mut writer) = tokio::io::split(backend_stream);

    let initial_server_seq = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u32)
        .unwrap_or(0);
    let server_seq_shared = Arc::new(AtomicU32::new(initial_server_seq.wrapping_add(1)));
    let client_seq_shared = Arc::new(AtomicU32::new(syn_pkt.seq.wrapping_add(1)));
    let client_acked_shared = Arc::new(AtomicU32::new(initial_server_seq));

    // Send SYN-ACK
    let syn_ack_options = tcp_syn_ack_options();
    let syn_ack = match build_ipv4_tcp_packet_with_options(
        dst_ip_v4,
        dst.port(),
        src_ip_v4,
        src.port(),
        0x12, // SYN | ACK
        initial_server_seq,
        syn_pkt.seq.wrapping_add(1),
        &syn_ack_options,
        &[],
    ) {
        Ok(pkt) => pkt,
        Err(e) => {
            tracing::error!("Failed to build SYN-ACK: {}", e);
            return;
        }
    };
    if outgoing_tx.send(syn_ack.clone()).await.is_err() {
        crate::stats::stats()
            .tcp_flow_error
            .fetch_add(1, Ordering::Relaxed);
        return;
    }
    crate::stats::stats()
        .tcp_syn_ack_sent
        .fetch_add(1, Ordering::Relaxed);

    let expected_ack = initial_server_seq.wrapping_add(1);
    let ack_pkt = loop {
        let recv = tokio::time::timeout(config.handshake_timeout, rx.recv()).await;
        let Some(pkt) = (match recv {
            Ok(pkt) => pkt,
            Err(_) => {
                crate::stats::stats()
                    .tcp_handshake_timeout
                    .fetch_add(1, Ordering::Relaxed);
                crate::stats::stats()
                    .tcp_flow_error
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
        }) else {
            crate::stats::stats()
                .tcp_flow_error
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        if pkt.ack && pkt.ack_num == expected_ack {
            break pkt;
        }
        if pkt.rst || pkt.fin {
            crate::stats::stats()
                .tcp_flow_error
                .fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                ?src,
                ?dst,
                rst = pkt.rst,
                fin = pkt.fin,
                "TCP flow closed during handshake"
            );
            return;
        }
        if pkt.syn && !pkt.ack {
            if outgoing_tx.send(syn_ack.clone()).await.is_err() {
                crate::stats::stats()
                    .tcp_flow_error
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            crate::stats::stats()
                .tcp_syn_ack_sent
                .fetch_add(1, Ordering::Relaxed);
        }
        crate::stats::stats()
            .tcp_handshake_skip
            .fetch_add(1, Ordering::Relaxed);
        crate::stats::stats()
            .tcp_last_handshake_flags
            .store(tcp_flags(&pkt) as u64, Ordering::Relaxed);
        crate::stats::stats()
            .tcp_last_handshake_seq
            .store(pkt.seq as u64, Ordering::Relaxed);
        crate::stats::stats()
            .tcp_last_handshake_ack
            .store(pkt.ack_num as u64, Ordering::Relaxed);
        crate::stats::stats()
            .tcp_last_handshake_expected_ack
            .store(expected_ack as u64, Ordering::Relaxed);
        crate::stats::stats()
            .tcp_last_handshake_payload_len
            .store(pkt.payload.len() as u64, Ordering::Relaxed);
        tracing::debug!(
            ?src,
            ?dst,
            syn = pkt.syn,
            ack = pkt.ack,
            seq = pkt.seq,
            ack_num = pkt.ack_num,
            expected_ack,
            payload_len = pkt.payload.len(),
            "skipping TCP packet while waiting for handshake ACK"
        );
    };

    client_acked_shared.store(ack_pkt.ack_num, Ordering::Relaxed);
    crate::stats::stats()
        .tcp_ack_after_syn
        .fetch_add(1, Ordering::Relaxed);

    let server_seq_a = server_seq_shared.clone();
    let client_seq_a = client_seq_shared.clone();
    let client_acked_a = client_acked_shared.clone();
    let outgoing_tx_a = outgoing_tx.clone();

    // B2: Notify the tx_task (host→guest) when an ACK advances the window,
    // instead of the old 5ms busy-poll that burned CPU and could deadlock.
    let ack_notify = Arc::new(tokio::sync::Notify::new());
    let ack_notify_rx = ack_notify.clone();
    let ack_notify_tx = ack_notify.clone();

    // Task A: Guest to Host (Read rx -> Write writer)
    let mut rx_task = tokio::spawn(async move {
        let mut client_seq = client_seq_a.load(Ordering::Acquire);
        // B3: Reorder buffer for out-of-order segments, keyed by seq.
        let mut ooo_buf: std::collections::BTreeMap<u32, bytes::Bytes> =
            std::collections::BTreeMap::new();
        let mut ooo_bytes = 0usize;

        while let Some(pkt) = rx.recv().await {
            if pkt.rst {
                break;
            }

            if pkt.ack {
                client_acked_a.store(pkt.ack_num, Ordering::Release);
                // B2: Wake the tx_task so it can re-check the window.
                ack_notify_tx.notify_one();
            }

            if !pkt.payload.is_empty() {
                // B3: Handle in-order, out-of-order, and retransmitted data.
                let segment_end = pkt.seq.wrapping_add(pkt.payload.len() as u32);
                if tcp_seq_after(segment_end, client_seq)
                    && tcp_seq_before_or_equal(pkt.seq, client_seq)
                {
                    // In-order or overlapping: extract the new portion.
                    let offset = client_seq.wrapping_sub(pkt.seq) as usize;
                    let new_data = &pkt.payload[offset..];
                    if !new_data.is_empty() {
                        if writer.write_all(new_data).await.is_err() {
                            crate::stats::stats()
                                .tcp_flow_error
                                .fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        crate::stats::stats()
                            .tcp_payload_guest_to_host
                            .fetch_add(new_data.len() as u64, Ordering::Relaxed);
                        crate::stats::stats()
                            .tcp_guest_write_calls
                            .fetch_add(1, Ordering::Relaxed);
                        client_seq = client_seq.wrapping_add(new_data.len() as u32);
                        client_seq_a.store(client_seq, Ordering::Release);

                        // Drain the reorder buffer for any now-in-order segments.
                        while let Some(seg) = ooo_buf.remove(&client_seq) {
                            ooo_bytes = ooo_bytes.saturating_sub(seg.len());
                            if writer.write_all(&seg).await.is_err() {
                                crate::stats::stats()
                                    .tcp_flow_error
                                    .fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                            crate::stats::stats()
                                .tcp_payload_guest_to_host
                                .fetch_add(seg.len() as u64, Ordering::Relaxed);
                            crate::stats::stats()
                                .tcp_guest_write_calls
                                .fetch_add(1, Ordering::Relaxed);
                            client_seq = client_seq.wrapping_add(seg.len() as u32);
                            client_seq_a.store(client_seq, Ordering::Release);
                        }
                    }
                } else if tcp_seq_after(pkt.seq, client_seq) {
                    // B3: Out-of-order — buffer for later delivery.
                    if let Some(previous) = ooo_buf.insert(pkt.seq, pkt.payload.clone()) {
                        ooo_bytes = ooo_bytes.saturating_sub(previous.len());
                    }
                    ooo_bytes = ooo_bytes.saturating_add(pkt.payload.len());
                    // Avoid delivering gaps if the out-of-order queue grows beyond
                    // its bounded budget. Close the flow and reset the guest side.
                    if ooo_bytes > TCP_REORDER_BUFFER_MAX_BYTES {
                        crate::stats::stats()
                            .tcp_flow_error
                            .fetch_add(1, Ordering::Relaxed);
                        let s_seq = server_seq_a.load(Ordering::Relaxed);
                        if let Ok(rst) = build_ipv4_tcp_packet(
                            dst_ip_v4,
                            dst.port(),
                            src_ip_v4,
                            src.port(),
                            0x14, // RST | ACK
                            s_seq,
                            client_seq,
                            &[],
                        ) {
                            let _ = outgoing_tx_a.send(rst).await;
                        }
                        break;
                    }
                }
                // If pkt.seq + len <= client_seq, it's a pure retransmit of
                // already-received data — ack but don't re-deliver.

                let s_seq = server_seq_a.load(Ordering::Relaxed);
                if let Ok(ack_pkt) = build_ipv4_tcp_packet(
                    dst_ip_v4,
                    dst.port(),
                    src_ip_v4,
                    src.port(),
                    0x10, // ACK
                    s_seq,
                    client_seq,
                    &[],
                ) {
                    if outgoing_tx_a.send(ack_pkt).await.is_err() {
                        crate::stats::stats()
                            .tun_output_queue_full
                            .fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    crate::stats::stats()
                        .tcp_ack_sent
                        .fetch_add(1, Ordering::Relaxed);
                }
            }

            if pkt.fin {
                let s_seq = server_seq_a.load(Ordering::Relaxed);
                let final_client_seq = client_seq.wrapping_add(1);
                client_seq_a.store(final_client_seq, Ordering::Release);
                // B3: Reply with FIN|ACK (0x11) instead of bare ACK (0x10) for
                // a cleaner close per RFC 793.
                if let Ok(fin_ack) = build_ipv4_tcp_packet(
                    dst_ip_v4,
                    dst.port(),
                    src_ip_v4,
                    src.port(),
                    0x11, // FIN | ACK
                    s_seq,
                    final_client_seq,
                    &[],
                ) {
                    let _ = outgoing_tx_a.send(fin_ack).await;
                    crate::stats::stats()
                        .tcp_fin_sent
                        .fetch_add(1, Ordering::Relaxed);
                }
                let _ = writer.shutdown().await;
                break;
            }
        }
    });

    // Task B: Host to Guest (Read reader -> Send outgoing_tx)
    let mut tx_task = tokio::spawn(async move {
        // Match the advertised default MSS so host-to-guest traffic also uses
        // near-MTU packets on the default mesh-tun TAP path.
        let mut buf = vec![0u8; usize::from(default_tcp_mss())];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    let s_seq = server_seq_shared.fetch_add(1, Ordering::Relaxed);
                    let c_seq = client_seq_shared.load(Ordering::Relaxed);
                    if let Ok(fin_pkt) = build_ipv4_tcp_packet(
                        dst_ip_v4,
                        dst.port(),
                        src_ip_v4,
                        src.port(),
                        0x11, // FIN | ACK
                        s_seq,
                        c_seq,
                        &[],
                    ) {
                        let _ = outgoing_tx.send(fin_pkt).await;
                        crate::stats::stats()
                            .tcp_fin_sent
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    crate::stats::stats()
                        .tcp_flow_close
                        .fetch_add(1, Ordering::Relaxed);
                    break;
                }
                Ok(n) => {
                    crate::stats::stats()
                        .tcp_payload_host_to_guest
                        .fetch_add(n as u64, Ordering::Relaxed);
                    crate::stats::stats()
                        .tcp_host_read_calls
                        .fetch_add(1, Ordering::Relaxed);
                    let s_seq = server_seq_shared.load(Ordering::Relaxed);
                    // B2: Wait for send window to open, woken by the rx_task's
                    // notify on ACK. Use a 60s overall timeout to avoid an
                    // unbounded hang if the client never ACKs.
                    let window = TCP_SYNTHETIC_WINDOW_BYTES;
                    let deadline =
                        tokio::time::Instant::now() + tokio::time::Duration::from_secs(60);
                    loop {
                        let acked = client_acked_shared.load(Ordering::Acquire);
                        let in_flight = s_seq.wrapping_add(n as u32).wrapping_sub(acked);
                        if in_flight <= window {
                            break;
                        }
                        // Window full: wait for an ACK notification.
                        let timeout = tokio::time::sleep_until(deadline);
                        tokio::pin!(timeout);
                        tokio::select! {
                            _ = ack_notify_rx.notified() => {}
                                            _ = &mut timeout => {
                                tracing::warn!(
                                    "TCP flow {:?}->{:?} timed out waiting for ACK window",
                                    src, dst
                                );
                                crate::stats::stats()
                                    .tcp_flow_error
                                    .fetch_add(1, Ordering::Relaxed);
                                return;
                            }
                        }
                    }

                    server_seq_shared.fetch_add(n as u32, Ordering::Release);
                    let c_seq = client_seq_shared.load(Ordering::Relaxed);
                    if let Ok(data_pkt) = build_ipv4_tcp_packet(
                        dst_ip_v4,
                        dst.port(),
                        src_ip_v4,
                        src.port(),
                        0x10, // ACK
                        s_seq,
                        c_seq,
                        &buf[..n],
                    ) {
                        if outgoing_tx.send(data_pkt).await.is_err() {
                            crate::stats::stats()
                                .tun_output_queue_full
                                .fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        crate::stats::stats()
                            .tcp_data_sent
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    crate::stats::stats()
                        .tcp_flow_error
                        .fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
        }
    });

    // B2: Abort the loser task to prevent task/FD leaks. Previously the select!
    // returned the winner's result and leaked the loser (which could keep
    // touching outgoing_tx and atomics).
    let _ = tokio::select! {
        res = &mut rx_task => {
            tx_task.abort();
            res
        }
        res = &mut tx_task => {
            rx_task.abort();
            res
        }
    };
}

fn tcp_syn_ack_options() -> [u8; 8] {
    // Kind=2, Len=4, MSS=default MTU minus IPv4/TCP headers. Kind=3, Len=3,
    // Shift=7 advertises an
    // ~8 MiB receive window instead of the unscaled ~64 KiB TCP header field.
    // Without MSS, Linux falls back to ~536-byte segments; without window
    // scaling, large-MSS uploads keep only one segment in flight.
    let mss = default_tcp_mss().to_be_bytes();
    [2, 4, mss[0], mss[1], 1, 3, 3, TCP_WINDOW_SCALE_SHIFT]
}

fn tcp_flags(pkt: &TunTcpPacket) -> u8 {
    (if pkt.fin { 0x01 } else { 0 })
        | (if pkt.syn { 0x02 } else { 0 })
        | (if pkt.rst { 0x04 } else { 0 })
        | (if pkt.ack { 0x10 } else { 0 })
}

async fn send_tcp_reset(
    src_ip_v4: std::net::Ipv4Addr,
    src_port: u16,
    dst_ip_v4: std::net::Ipv4Addr,
    dst_port: u16,
    syn_pkt: &TunTcpPacket,
    outgoing_tx: &mpsc::Sender<Vec<u8>>,
) {
    if let Ok(rst) = build_ipv4_tcp_packet(
        dst_ip_v4,
        dst_port,
        src_ip_v4,
        src_port,
        0x14, // RST | ACK
        0,
        syn_pkt.seq.wrapping_add(1),
        &[],
    ) {
        let _ = outgoing_tx.send(rst).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{TunPacket, build_ipv4_tcp_packet, parse_ip_packet};
    use crate::policy::{PolicyDecision, TcpRouteDecision};
    use crate::transport::{BoxTunByteStream, TcpConnector};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    struct DuplexConnector;

    #[async_trait::async_trait]
    impl TcpConnector for DuplexConnector {
        async fn connect(&self, _ctx: &FlowContext) -> Result<BoxTunByteStream, anyhow::Error> {
            let (stream, _peer) = tokio::io::duplex(1024);
            Ok(Box::new(stream))
        }
    }

    struct DuplexPolicy;

    #[async_trait::async_trait]
    impl MeshTunPolicy for DuplexPolicy {
        async fn check(&self, _ctx: &FlowContext) -> PolicyDecision {
            PolicyDecision::Allow
        }

        async fn route_tcp(&self, _ctx: &FlowContext) -> TcpRouteDecision {
            TcpRouteDecision::Connect {
                connector: Arc::new(DuplexConnector),
            }
        }
    }

    struct DenyTcpPolicy;

    #[async_trait::async_trait]
    impl MeshTunPolicy for DenyTcpPolicy {
        async fn check(&self, _ctx: &FlowContext) -> PolicyDecision {
            PolicyDecision::Deny {
                reason: "blocked".to_string(),
            }
        }
    }

    struct FailingConnector;

    #[async_trait::async_trait]
    impl TcpConnector for FailingConnector {
        async fn connect(&self, _ctx: &FlowContext) -> Result<BoxTunByteStream, anyhow::Error> {
            anyhow::bail!("backend unavailable")
        }
    }

    struct FailingTcpPolicy;

    #[async_trait::async_trait]
    impl MeshTunPolicy for FailingTcpPolicy {
        async fn check(&self, _ctx: &FlowContext) -> PolicyDecision {
            PolicyDecision::Allow
        }

        async fn route_tcp(&self, _ctx: &FlowContext) -> TcpRouteDecision {
            TcpRouteDecision::Connect {
                connector: Arc::new(FailingConnector),
            }
        }
    }

    fn tcp_packet(src_port: u16) -> TunTcpPacket {
        let packet = build_ipv4_tcp_packet(
            Ipv4Addr::new(10, 5, 0, 2),
            src_port,
            Ipv4Addr::new(198, 51, 100, 10),
            80,
            0x02,
            1,
            0,
            &[],
        )
        .unwrap();
        let TunPacket::Tcp(tcp) = parse_ip_packet(&packet) else {
            panic!("expected TCP packet");
        };
        tcp
    }

    #[test]
    fn tcp_sequence_order_handles_wraparound() {
        assert!(tcp_seq_after(1, u32::MAX));
        assert!(tcp_seq_after(0, u32::MAX - 1));
        assert!(!tcp_seq_after(u32::MAX, 1));
        assert!(tcp_seq_before_or_equal(u32::MAX, 1));
        assert!(tcp_seq_before_or_equal(7, 7));
        assert!(!tcp_seq_before_or_equal(9, 7));
    }

    #[tokio::test]
    async fn rejects_new_flows_after_limit() {
        crate::stats::stats().reset();
        let (outgoing_tx, _outgoing_rx) = mpsc::channel(16);
        let manager = TcpProxyManager::new(
            "vm-a".to_string(),
            outgoing_tx,
            Arc::new(DuplexPolicy),
            TcpProxyConfig {
                max_flows: 1,
                per_flow_queue_capacity: 4,
                handshake_timeout: Duration::from_secs(30),
                connect_timeout: Duration::from_secs(30),
            },
        );

        manager.handle_packet(tcp_packet(40000)).await;
        manager.handle_packet(tcp_packet(40001)).await;

        assert!(
            crate::stats::stats()
                .tcp_flow_rejected
                .load(Ordering::Relaxed)
                >= 1
        );
    }

    #[tokio::test]
    async fn handshake_timeout_removes_half_open_flow() {
        crate::stats::stats().reset();
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(16);
        let manager = TcpProxyManager::new(
            "vm-a".to_string(),
            outgoing_tx,
            Arc::new(DuplexPolicy),
            TcpProxyConfig {
                max_flows: 16,
                per_flow_queue_capacity: 4,
                handshake_timeout: Duration::from_millis(20),
                connect_timeout: Duration::from_secs(30),
            },
        );

        manager.handle_packet(tcp_packet(40000)).await;
        let _ = outgoing_rx.recv().await.expect("SYN-ACK");
        tokio::time::sleep(Duration::from_millis(80)).await;

        assert_eq!(
            crate::stats::stats()
                .tcp_handshake_timeout
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(manager.flows.lock().await.len(), 0);
    }

    #[tokio::test]
    async fn denied_syn_returns_reset_without_syn_ack() {
        crate::stats::stats().reset();
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(16);
        let manager = TcpProxyManager::new(
            "vm-a".to_string(),
            outgoing_tx,
            Arc::new(DenyTcpPolicy),
            TcpProxyConfig {
                max_flows: 16,
                per_flow_queue_capacity: 4,
                handshake_timeout: Duration::from_secs(30),
                connect_timeout: Duration::from_secs(30),
            },
        );

        manager.handle_packet(tcp_packet(40000)).await;
        let packet = outgoing_rx.recv().await.expect("RST");
        let TunPacket::Tcp(tcp) = parse_ip_packet(&packet) else {
            panic!("expected TCP packet");
        };
        assert!(tcp.rst);
        assert!(tcp.ack);
        assert!(!tcp.syn);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(manager.flows.lock().await.len(), 0);
    }

    #[tokio::test]
    async fn backend_connect_failure_returns_reset_without_syn_ack() {
        crate::stats::stats().reset();
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel(16);
        let manager = TcpProxyManager::new(
            "vm-a".to_string(),
            outgoing_tx,
            Arc::new(FailingTcpPolicy),
            TcpProxyConfig {
                max_flows: 16,
                per_flow_queue_capacity: 4,
                handshake_timeout: Duration::from_secs(30),
                connect_timeout: Duration::from_secs(30),
            },
        );

        manager.handle_packet(tcp_packet(40000)).await;
        let packet = outgoing_rx.recv().await.expect("RST");
        let TunPacket::Tcp(tcp) = parse_ip_packet(&packet) else {
            panic!("expected TCP packet");
        };
        assert!(tcp.rst);
        assert!(tcp.ack);
        assert!(!tcp.syn);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(manager.flows.lock().await.len(), 0);
    }
}
