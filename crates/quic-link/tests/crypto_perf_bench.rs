#![cfg(feature = "rust-crypto")]

use std::hint::black_box;
use std::net::UdpSocket;
use std::time::Instant;

use quic_base::flow::RxOutcome;
use quic_base::pool::{DEFAULT_HEADROOM, PacketPool, PoolPacket, XipLazyPacket, XipLazyPool};
use quic_base::streams::{RxStreamChunk, TxStreamData};
use quic_link::congestion::{CongestionMode, LinkId, LinkProfile, LinkTxOutcome, PacingConfig};
use quic_link::{
    AssocConfig, AssocCryptoConfig, ConnectionId, CryptoProvider, CryptoRole, HandshakeMode,
    PUBLIC_KEY_COMPRESSED_LEN, SingleStreamCallbacks, SingleStreamConfig, SingleStreamEndpoint,
    TransportParameters, derive_device_secret, derive_peer_api_key,
};

#[cfg(target_os = "linux")]
#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[cfg(target_os = "linux")]
fn thread_cpu_ns() -> u64 {
    const CLOCK_THREAD_CPUTIME_ID: i32 = 3;
    unsafe extern "C" {
        fn clock_gettime(clk_id: i32, tp: *mut Timespec) -> i32;
    }
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { clock_gettime(CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    if rc == 0 {
        (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
    } else {
        0
    }
}

#[cfg(not(target_os = "linux"))]
fn thread_cpu_ns() -> u64 {
    0
}

struct BenchReceiver {
    received: Vec<u8>,
    fin: bool,
    zero_copy_chunks: usize,
    verify_seed: bool,
}

impl BenchReceiver {
    fn new(expected_len: usize, verify_seed: bool) -> Self {
        Self {
            received: Vec::with_capacity(expected_len),
            fin: false,
            zero_copy_chunks: 0,
            verify_seed,
        }
    }
}

impl SingleStreamCallbacks<XipLazyPacket> for BenchReceiver {
    fn on_stream_data(
        &mut self,
        mut chunk: RxStreamChunk<'_, XipLazyPacket>,
        fin: bool,
    ) -> RxOutcome<XipLazyPacket> {
        let len = chunk.len();
        if let Some(pkt) = chunk.take_packet() {
            self.zero_copy_chunks += 1;
            if self.verify_seed {
                self.received.extend_from_slice(pkt.bytes());
            } else {
                self.received.resize(self.received.len() + pkt.bytes().len(), 0);
            }
        } else if self.verify_seed {
            self.received.extend_from_slice(chunk.bytes());
        } else {
            self.received.resize(self.received.len() + chunk.bytes().len(), 0);
        }
        if fin {
            self.fin = true;
        }
        RxOutcome::Consumed(len)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BenchCryptoMode {
    Off,
    PrekeyedOn,
    InitialHandshakeOn,
}

impl BenchCryptoMode {
    fn label(self) -> &'static str {
        match self {
            Self::Off => "crypto=OFF",
            Self::PrekeyedOn => "crypto=ON(prekey)",
            Self::InitialHandshakeOn => "crypto=ON(initial)",
        }
    }
}

struct TransferStats {
    wall_ns: f64,
    cpu_ns: f64,
    tx_packets: usize,
    tx_wire_bytes: usize,
    rx_packets: usize,
    rx_wire_bytes: usize,
    max_payload: usize,
}

fn make_payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) & 0xff) as u8).collect()
}

fn build_endpoints(
    mode: BenchCryptoMode,
    mtu: usize,
    pool_slots: usize,
) -> (
    SingleStreamEndpoint<XipLazyPool>,
    SingleStreamEndpoint<XipLazyPool>,
    LinkId,
) {
    let pool_a = XipLazyPool::with_default_geometry(pool_slots);
    let pool_b = XipLazyPool::with_default_geometry(pool_slots);
    let cid = ConnectionId::new(1).unwrap();
    let link_id = LinkId(1);

    let (hs_a, hs_b) = match mode {
        BenchCryptoMode::InitialHandshakeOn => (HandshakeMode::Client, HandshakeMode::Server),
        BenchCryptoMode::Off | BenchCryptoMode::PrekeyedOn => {
            (HandshakeMode::None, HandshakeMode::None)
        }
    };

    let mut cfg_a = SingleStreamConfig::default();
    cfg_a.initial_recv_window = 256 * 1024;
    cfg_a.initial_send_window = 256 * 1024;
    cfg_a.max_reassembly_chunks = 128;
    cfg_a.assoc = AssocConfig {
        local_cid: Some(cid),
        default_peer_cid: cid,
        max_retained_tx_packets: 128,
        ack_eliciting_threshold: 8,
        handshake_mode: hs_a,
        local_params: TransportParameters {
            initial_max_data: Some(256 * 1024),
            ..Default::default()
        },
        ..AssocConfig::default()
    };

    let mut cfg_b = cfg_a;
    cfg_b.assoc.handshake_mode = hs_b;
    if mode == BenchCryptoMode::InitialHandshakeOn {
        cfg_a.assoc.local_cid = ConnectionId::new(11);
        cfg_b.assoc.local_cid = ConnectionId::new(77);
    }

    let mut ep_a = SingleStreamEndpoint::new(pool_a, cfg_a);
    let mut ep_b = SingleStreamEndpoint::new(pool_b, cfg_b);

    let encrypt = mode != BenchCryptoMode::Off;
    let mut prof = LinkProfile::udp_datagram(0, mtu, cid).with_encryption(encrypt);
    prof.congestion_mode = CongestionMode::NewRenoPaced {
        initial_window_bytes: 128 * 1024,
        pacing: PacingConfig::disabled(mtu),
    };
    ep_a.assoc_mut().upsert_link(link_id, prof);
    ep_b.assoc_mut().upsert_link(link_id, prof);

    if encrypt {
        let client_pub = [0x02u8; PUBLIC_KEY_COMPRESSED_LEN];
        let server_pub = [0x03u8; PUBLIC_KEY_COMPRESSED_LEN];
        let node_secret =
            derive_device_secret(b"bench-root-secret-material", &server_pub).unwrap();
        let client_api_key = match mode {
            BenchCryptoMode::PrekeyedOn => derive_peer_api_key(&node_secret, &[]).unwrap(),
            BenchCryptoMode::InitialHandshakeOn => {
                derive_peer_api_key(&node_secret, &client_pub).unwrap()
            }
            BenchCryptoMode::Off => unreachable!(),
        };

        ep_a.assoc_mut()
            .set_crypto_config(AssocCryptoConfig {
                provider: CryptoProvider::rust_crypto(),
                role: CryptoRole::Client,
                local_public_key: (mode == BenchCryptoMode::InitialHandshakeOn)
                    .then_some(client_pub),
                local_random: [0x1a; 32],
                send_api_key: Some(client_api_key),
                node_secret: None,
            })
            .unwrap();
        ep_b.assoc_mut()
            .set_crypto_config(AssocCryptoConfig {
                provider: CryptoProvider::rust_crypto(),
                role: CryptoRole::Server,
                local_public_key: (mode == BenchCryptoMode::InitialHandshakeOn)
                    .then_some(server_pub),
                local_random: [0x2b; 32],
                send_api_key: None,
                node_secret: Some(node_secret),
            })
            .unwrap();
    }

    (ep_a, ep_b, link_id)
}

fn run_sync_stream_transfer(
    mode: BenchCryptoMode,
    mtu: usize,
    total_bytes: usize,
    write_chunk_cap: usize,
    verify: bool,
) -> TransferStats {
    let payload = make_payload(total_bytes);
    let (mut ep_a, mut ep_b, _) = build_endpoints(mode, mtu, 256);
    let mut max_payload = ep_a.max_writable_payload_len();
    let mut cb_a = BenchReceiver::new(0, false);
    let mut cb_b = BenchReceiver::new(total_bytes, verify);

    let mut tx_packets = 0usize;
    let mut tx_wire_bytes = 0usize;
    let mut rx_packets = 0usize;
    let mut rx_wire_bytes = 0usize;
    let mut sent_offset = 0usize;
    let mut now_us = 1_000u64;

    let c0 = thread_cpu_ns();
    let t0 = Instant::now();

    if mode == BenchCryptoMode::InitialHandshakeOn {
        let mut p = ep_a.pool().clone();
        ep_a.assoc_mut().enqueue_initial(&mut p).unwrap();
    }

    loop {
        if mode != BenchCryptoMode::InitialHandshakeOn || ep_a.assoc().is_handshake_complete() {
            max_payload = ep_a.max_writable_payload_len();
            let chunk_cap = write_chunk_cap.min(max_payload).max(1);
            while sent_offset < total_bytes {
                let n = (total_bytes - sent_offset).min(chunk_cap);
                let fin = sent_offset + n == total_bytes;
                match ep_a.write_stream(
                    TxStreamData::Bytes(&payload[sent_offset..sent_offset + n]),
                    fin,
                    now_us,
                ) {
                    Ok(written) if written > 0 => sent_offset += written,
                    _ => break,
                }
            }
        }

        let mut progressed = false;

        while let Some(out) = ep_a.assoc_mut().pop_outbound_packet() {
            progressed = true;
            let raw_len = out.packet.bytes().len();
            tx_packets += 1;
            tx_wire_bytes += raw_len;

            let mut rx_pkt = ep_b.pool().alloc_with_headroom(DEFAULT_HEADROOM).unwrap();
            rx_pkt.append(out.packet.bytes()).unwrap();
            ep_a.assoc_mut()
                .on_driver_complete(out.link_id, out.packet_number, LinkTxOutcome::Sent, now_us);
            ep_b.receive_packet(out.link_id, rx_pkt, now_us, &mut cb_b)
                .unwrap();
        }

        ep_b.poll_timers(now_us);
        while let Some(out) = ep_b.assoc_mut().pop_outbound_packet() {
            progressed = true;
            let raw_len = out.packet.bytes().len();
            rx_packets += 1;
            rx_wire_bytes += raw_len;

            let mut rx_pkt = ep_a.pool().alloc_with_headroom(DEFAULT_HEADROOM).unwrap();
            rx_pkt.append(out.packet.bytes()).unwrap();
            ep_b.assoc_mut()
                .on_driver_complete(out.link_id, out.packet_number, LinkTxOutcome::Sent, now_us);
            ep_a.receive_packet(out.link_id, rx_pkt, now_us, &mut cb_a)
                .unwrap();
        }

        if cb_b.fin && cb_b.received.len() == total_bytes {
            break;
        }

        if !progressed {
            now_us += 30_000;
            ep_a.poll_timers(now_us);
            ep_b.poll_timers(now_us);
        } else {
            now_us += 100;
        }
    }

    let wall_ns = t0.elapsed().as_nanos() as f64;
    let cpu_ns = thread_cpu_ns().saturating_sub(c0) as f64;
    if verify {
        assert_eq!(cb_b.received, payload);
    }

    TransferStats {
        wall_ns,
        cpu_ns,
        tx_packets,
        tx_wire_bytes,
        rx_packets,
        rx_wire_bytes,
        max_payload,
    }
}

#[test]
#[ignore]
fn bench_quic_link_crypto_matrix() {
    println!("=== quic-link SingleStreamEndpoint Crypto OFF vs ON (host loopback, no artificial sleep) ===");
    println!(
        "{:<8} {:<6} {:<19} {:>10} {:>10} {:>9} {:>9} {:>7} {:>9} {:>8}",
        "Size", "MTU", "Mode", "Wall us", "CPU us", "MiB/s", "Mbps", "TX pkts", "TX wire", "Goodput%"
    );

    for &sz in &[64usize, 256, 1024, 1200, 1400, 64 * 1024, 1024 * 1024, 2 * 1024 * 1024] {
        let iters = match sz {
            0..=1400 => 200usize,
            65536 => 20,
            _ => 5,
        };
        for &mtu in &[1472usize, 1200, 244] {
            if sz > 64 * 1024 && mtu == 244 {
                continue;
            }
            for &mode in &[
                BenchCryptoMode::Off,
                BenchCryptoMode::PrekeyedOn,
                BenchCryptoMode::InitialHandshakeOn,
            ] {
                if sz > 1400 && mode == BenchCryptoMode::InitialHandshakeOn && mtu == 1200 {
                    continue;
                }
                // Warmup once with verification
                let _ = run_sync_stream_transfer(mode, mtu, sz, usize::MAX, true);
                let mut sum_wall = 0.0;
                let mut sum_cpu = 0.0;
                let mut last = TransferStats {
                    wall_ns: 0.0,
                    cpu_ns: 0.0,
                    tx_packets: 0,
                    tx_wire_bytes: 0,
                    rx_packets: 0,
                    rx_wire_bytes: 0,
                    max_payload: 0,
                };
                for _ in 0..iters {
                    last = run_sync_stream_transfer(mode, mtu, sz, usize::MAX, false);
                    sum_wall += last.wall_ns;
                    sum_cpu += last.cpu_ns;
                }
                let wall_us = (sum_wall / iters as f64) / 1_000.0;
                let cpu_us = (sum_cpu / iters as f64) / 1_000.0;
                let mibs = (sz as f64 * 1e6) / (wall_us * 1024.0 * 1024.0);
                let mbps = (sz as f64 * 8.0) / wall_us;
                let total_wire = last.tx_wire_bytes + last.rx_wire_bytes;
                let goodput = 100.0 * sz as f64 / (last.tx_wire_bytes.max(1) as f64);
                println!(
                    "{:<8} {:<6} {:<19} {:>10.1} {:>10.1} {:>9.2} {:>9.2} {:>7} {:>9} {:>7.2}% (rx={}/{}B, max_pay={})",
                    sz,
                    mtu,
                    mode.label(),
                    wall_us,
                    cpu_us,
                    mibs,
                    mbps,
                    last.tx_packets,
                    last.tx_wire_bytes,
                    goodput,
                    last.rx_packets,
                    total_wire,
                    last.max_payload
                );
            }
        }
    }

    // Small-write coalescing comparison: 512 x 64B and 512 x 256B writes on 1472 MTU
    println!("\n=== Small-write Coalescing Impact (try_coalesce_onto_pending disabled when encrypt=true) ===");
    for &chunk_sz in &[64usize, 256] {
        let total = chunk_sz * 512;
        for &mode in &[BenchCryptoMode::Off, BenchCryptoMode::PrekeyedOn] {
            let st = run_sync_stream_transfer(mode, 1472, total, chunk_sz, true);
            let wall_us = st.wall_ns / 1_000.0;
            let cpu_us = st.cpu_ns / 1_000.0;
            println!(
                "512x{}B ({}B) {:<19} wall={:>8.1}us cpu={:>8.1}us TX={} pkts ({} wire B) goodput={:.2}%",
                chunk_sz,
                total,
                mode.label(),
                wall_us,
                cpu_us,
                st.tx_packets,
                st.tx_wire_bytes,
                100.0 * total as f64 / st.tx_wire_bytes as f64
            );
        }
    }

    // Handshake setup only (Initial client<->server 1-RTT without bulk payload) vs Pre-keyed ShortHeader 64B
    println!("\n=== Real Localhost UdpSocket Loopback (1 MiB stream & 64B RPC, MTU=1472) ===");
    for &(sz, iters) in &[(64usize, 100usize), (256, 100), (1024, 50), (1024 * 1024, 3)] {
        for &mode in &[
            BenchCryptoMode::Off,
            BenchCryptoMode::PrekeyedOn,
            BenchCryptoMode::InitialHandshakeOn,
        ] {
            if sz == 1024 * 1024 && mode == BenchCryptoMode::InitialHandshakeOn {
                continue;
            }
            let payload = make_payload(sz);
            let mut sum_wall = 0.0;
            let mut sum_cpu = 0.0;
            let mut last_tx = 0usize;
            let mut last_wire = 0usize;
            for iter in 0..iters {
                let sock_a = UdpSocket::bind("127.0.0.1:0").unwrap();
                let sock_b = UdpSocket::bind("127.0.0.1:0").unwrap();
                sock_a.set_nonblocking(true).unwrap();
                sock_b.set_nonblocking(true).unwrap();
                let addr_a = sock_a.local_addr().unwrap();
                let addr_b = sock_b.local_addr().unwrap();

                let (mut ep_a, mut ep_b, link_id) = build_endpoints(mode, 1472, 256);
                let max_payload = ep_a.max_writable_payload_len();
                let mut cb_a = BenchReceiver::new(0, false);
                let mut cb_b = BenchReceiver::new(sz, iter == 0);
                let mut sent = 0usize;
                let mut now_us = 1_000u64;
                let mut rx_buf = [0u8; 2048];
                let mut tx_pkts = 0usize;
                let mut tx_wire = 0usize;

                let c0 = thread_cpu_ns();
                let t0 = Instant::now();
                if mode == BenchCryptoMode::InitialHandshakeOn {
                    let mut p = ep_a.pool().clone();
                    ep_a.assoc_mut().enqueue_initial(&mut p).unwrap();
                }

                loop {
                    if mode != BenchCryptoMode::InitialHandshakeOn
                        || ep_a.assoc().is_handshake_complete()
                    {
                        while sent < sz {
                            let n = (sz - sent).min(max_payload);
                            let fin = sent + n == sz;
                            match ep_a.write_stream(
                                TxStreamData::Bytes(&payload[sent..sent + n]),
                                fin,
                                now_us,
                            ) {
                                Ok(w) if w > 0 => sent += w,
                                _ => break,
                            }
                        }
                    }

                    let mut did_io = false;
                    while let Some(out) = ep_a.assoc_mut().pop_outbound_packet() {
                        did_io = true;
                        let n = sock_a.send_to(out.packet.bytes(), addr_b).unwrap();
                        tx_pkts += 1;
                        tx_wire += n;
                        ep_a.assoc_mut().on_driver_complete(
                            out.link_id,
                            out.packet_number,
                            LinkTxOutcome::Sent,
                            now_us,
                        );
                    }
                    while let Ok((n, _)) = sock_b.recv_from(&mut rx_buf) {
                        did_io = true;
                        let mut rx_pkt = ep_b.pool().alloc_with_headroom(DEFAULT_HEADROOM).unwrap();
                        rx_pkt.append(&rx_buf[..n]).unwrap();
                        ep_b.receive_packet(link_id, rx_pkt, now_us, &mut cb_b)
                            .unwrap();
                    }
                    ep_b.poll_timers(now_us);
                    while let Some(out) = ep_b.assoc_mut().pop_outbound_packet() {
                        did_io = true;
                        sock_b.send_to(out.packet.bytes(), addr_a).unwrap();
                        ep_b.assoc_mut().on_driver_complete(
                            out.link_id,
                            out.packet_number,
                            LinkTxOutcome::Sent,
                            now_us,
                        );
                    }
                    while let Ok((n, _)) = sock_a.recv_from(&mut rx_buf) {
                        did_io = true;
                        let mut rx_pkt = ep_a.pool().alloc_with_headroom(DEFAULT_HEADROOM).unwrap();
                        rx_pkt.append(&rx_buf[..n]).unwrap();
                        ep_a.receive_packet(link_id, rx_pkt, now_us, &mut cb_a)
                            .unwrap();
                    }
                    if cb_b.fin && cb_b.received.len() == sz {
                        break;
                    }
                    if !did_io {
                        now_us += 25_000;
                        ep_a.poll_timers(now_us);
                        ep_b.poll_timers(now_us);
                    } else {
                        now_us += 50;
                    }
                }
                sum_wall += t0.elapsed().as_nanos() as f64;
                sum_cpu += thread_cpu_ns().saturating_sub(c0) as f64;
                last_tx = tx_pkts;
                last_wire = tx_wire;
                if iter == 0 {
                    assert_eq!(cb_b.received, payload);
                }
                black_box(&cb_b.received);
            }
            let wall_us = (sum_wall / iters as f64) / 1_000.0;
            let cpu_us = (sum_cpu / iters as f64) / 1_000.0;
            let mibs = (sz as f64 * 1e6) / (wall_us * 1024.0 * 1024.0);
            let mbps = (sz as f64 * 8.0) / wall_us;
            println!(
                "UDP {:<8} {:<19} wall={:>9.1}us cpu={:>9.1}us {:>7.2} MiB/s {:>8.2} Mbps TX={} wire={}B",
                sz,
                mode.label(),
                wall_us,
                cpu_us,
                mibs,
                mbps,
                last_tx,
                last_wire
            );
        }
    }
}
