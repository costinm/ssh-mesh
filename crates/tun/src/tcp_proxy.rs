use crate::packet::{build_ipv4_tcp_packet, TunTcpPacket};
use mesh::tun::{TunTcpHandler, TunTcpMeta};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

#[derive(Clone)]
pub struct TcpProxyManager {
    flows: Arc<Mutex<HashMap<TcpFlowKey, mpsc::UnboundedSender<TunTcpPacket>>>>,
    outgoing_tx: mpsc::UnboundedSender<Vec<u8>>,
    tcp_handler: Arc<dyn TunTcpHandler>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct TcpFlowKey {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

impl TcpProxyManager {
    pub fn new(
        outgoing_tx: mpsc::UnboundedSender<Vec<u8>>,
        tcp_handler: Arc<dyn TunTcpHandler>,
    ) -> Self {
        Self {
            flows: Arc::new(Mutex::new(HashMap::new())),
            outgoing_tx,
            tcp_handler,
        }
    }

    pub async fn handle_packet(&self, pkt: TunTcpPacket) {
        crate::stats::stats()
            .tcp_packet
            .fetch_add(1, Ordering::Relaxed);
        let key = TcpFlowKey {
            src: SocketAddr::new(pkt.src_addr, pkt.src_port),
            dst: SocketAddr::new(pkt.dst_addr, pkt.dst_port),
        };

        let mut flows_guard = self.flows.lock().await;
        if let Some(tx) = flows_guard.get(&key) {
            crate::stats::stats()
                .tcp_flow_packet
                .fetch_add(1, Ordering::Relaxed);
            let _ = tx.send(pkt);
        } else if pkt.syn && !pkt.ack {
            crate::stats::stats()
                .tcp_syn
                .fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = mpsc::unbounded_channel();
            flows_guard.insert(key.clone(), tx.clone());

            let flows_clone = self.flows.clone();
            let outgoing_tx = self.outgoing_tx.clone();
            let tcp_handler = self.tcp_handler.clone();

            tokio::spawn(async move {
                let _ = tx.send(pkt);
                handle_tcp_flow(key.src, key.dst, rx, outgoing_tx, tcp_handler).await;
                flows_clone.lock().await.remove(&key);
            });
        }
    }
}

async fn handle_tcp_flow(
    src: SocketAddr,
    dst: SocketAddr,
    mut rx: mpsc::UnboundedReceiver<TunTcpPacket>,
    outgoing_tx: mpsc::UnboundedSender<Vec<u8>>,
    tcp_handler: Arc<dyn TunTcpHandler>,
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

    let (guest_stream, host_stream) = tokio::io::duplex(65536);

    let handler = tcp_handler.clone();
    let meta = TunTcpMeta {
        src_addr: src.ip(),
        src_port: src.port(),
        dst_addr: dst.ip(),
        dst_port: dst.port(),
    };
    tokio::spawn(async move {
        handler.handle_tcp(meta, host_stream).await;
    });

    let (mut reader, mut writer) = tokio::io::split(guest_stream);

    let initial_server_seq = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u32)
        .unwrap_or(0);
    let server_seq_shared = Arc::new(AtomicU32::new(initial_server_seq.wrapping_add(1)));
    let client_seq_shared = Arc::new(AtomicU32::new(syn_pkt.seq.wrapping_add(1)));
    let client_acked_shared = Arc::new(AtomicU32::new(initial_server_seq));

    // Send SYN-ACK
    let syn_ack = match build_ipv4_tcp_packet(
        dst_ip_v4,
        dst.port(),
        src_ip_v4,
        src.port(),
        0x12, // SYN | ACK
        initial_server_seq,
        syn_pkt.seq.wrapping_add(1),
        &[],
    ) {
        Ok(pkt) => pkt,
        Err(e) => {
            tracing::error!("Failed to build SYN-ACK: {}", e);
            return;
        }
    };
    if outgoing_tx.send(syn_ack.clone()).is_err() {
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
        let Some(pkt) = rx.recv().await else {
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
            if outgoing_tx.send(syn_ack.clone()).is_err() {
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

    // Task A: Guest to Host (Read rx -> Write writer)
    let rx_task = tokio::spawn(async move {
        let mut client_seq = client_seq_a.load(Ordering::Relaxed);
        while let Some(pkt) = rx.recv().await {
            if pkt.rst {
                break;
            }

            if pkt.ack {
                client_acked_a.store(pkt.ack_num, Ordering::Relaxed);
            }

            if !pkt.payload.is_empty() {
                if pkt.seq == client_seq {
                    if writer.write_all(&pkt.payload).await.is_err() {
                        crate::stats::stats()
                            .tcp_flow_error
                            .fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    crate::stats::stats()
                        .tcp_payload_guest_to_host
                        .fetch_add(pkt.payload.len() as u64, Ordering::Relaxed);
                    client_seq = client_seq.wrapping_add(pkt.payload.len() as u32);
                    client_seq_a.store(client_seq, Ordering::Relaxed);
                }

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
                    let _ = outgoing_tx_a.send(ack_pkt);
                    crate::stats::stats()
                        .tcp_ack_sent
                        .fetch_add(1, Ordering::Relaxed);
                }
            }

            if pkt.fin {
                let s_seq = server_seq_a.load(Ordering::Relaxed);
                let final_client_seq = client_seq.wrapping_add(1);
                client_seq_a.store(final_client_seq, Ordering::Relaxed);
                if let Ok(fin_ack) = build_ipv4_tcp_packet(
                    dst_ip_v4,
                    dst.port(),
                    src_ip_v4,
                    src.port(),
                    0x10, // ACK
                    s_seq,
                    final_client_seq,
                    &[],
                ) {
                    let _ = outgoing_tx_a.send(fin_ack);
                    crate::stats::stats()
                        .tcp_ack_sent
                        .fetch_add(1, Ordering::Relaxed);
                }
                let _ = writer.shutdown().await;
                break;
            }
        }
    });

    // Task B: Host to Guest (Read reader -> Send outgoing_tx)
    let tx_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 1400];
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
                        let _ = outgoing_tx.send(fin_pkt);
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
                    let s_seq = server_seq_shared.load(Ordering::Relaxed);
                    while s_seq
                        .wrapping_add(n as u32)
                        .wrapping_sub(client_acked_shared.load(Ordering::Relaxed))
                        > 65535
                    {
                        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
                    }

                    server_seq_shared.fetch_add(n as u32, Ordering::Relaxed);
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
                        let _ = outgoing_tx.send(data_pkt);
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

    let _ = tokio::select! {
        res = rx_task => res,
        res = tx_task => res,
    };
}

fn tcp_flags(pkt: &TunTcpPacket) -> u8 {
    (if pkt.fin { 0x01 } else { 0 })
        | (if pkt.syn { 0x02 } else { 0 })
        | (if pkt.rst { 0x04 } else { 0 })
        | (if pkt.ack { 0x10 } else { 0 })
}
