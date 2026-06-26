use mesh::tun::{TunDnsHandler, TunUdpHandler, TunUdpPacket};
use mesh_tun::packet::{
    TunPacket, build_ipv4_tcp_packet, ipv4_checksum_valid, ipv4_tcp_checksum_valid, parse_ip_packet,
};
use mesh_tun::policy::AllowAllPolicy;
use mesh_tun::tcp_rewrite::{TcpFlowKey, TcpRewriteConfig, TcpRewriter};
use mesh_tun::{MeshTun, MeshTunConfig};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;
const ACK: u8 = 0x10;

fn tcp_tuple(packet: &[u8]) -> (Ipv4Addr, u16, Ipv4Addr, u16) {
    let TunPacket::Tcp(tcp) = parse_ip_packet(packet) else {
        panic!("expected TCP packet");
    };
    let IpAddr::V4(src) = tcp.src_addr else {
        panic!("expected IPv4 source");
    };
    let IpAddr::V4(dst) = tcp.dst_addr else {
        panic!("expected IPv4 destination");
    };
    (src, tcp.src_port, dst, tcp.dst_port)
}

struct NoopUdpHandler;

#[async_trait::async_trait]
impl TunUdpHandler for NoopUdpHandler {
    async fn handle_udp(&self, _packet: TunUdpPacket) {}
}

struct NoopDnsHandler;

#[async_trait::async_trait]
impl TunDnsHandler for NoopDnsHandler {
    async fn handle_dns(&self, _packet: TunUdpPacket) {}
}

#[test]
fn rewrites_outbound_syn_and_reverse_syn_ack() {
    let mut rewriter = TcpRewriter::new(TcpRewriteConfig {
        proxy_addr: Ipv4Addr::new(169, 254, 0, 10),
        first_port: 41000,
        last_port: 41010,
    })
    .unwrap();
    let client = Ipv4Addr::new(10, 10, 0, 2);
    let remote = Ipv4Addr::new(203, 0, 113, 9);
    let syn = build_ipv4_tcp_packet(client, 50000, remote, 7, SYN, 100, 0, b"").unwrap();

    let outbound = rewriter.translate_outbound(&syn).unwrap().unwrap();
    assert_eq!(
        tcp_tuple(&outbound),
        (Ipv4Addr::new(169, 254, 0, 10), 41000, remote, 7)
    );
    assert!(ipv4_checksum_valid(&outbound));
    assert!(ipv4_tcp_checksum_valid(&outbound));

    let syn_ack = build_ipv4_tcp_packet(
        remote,
        7,
        Ipv4Addr::new(169, 254, 0, 10),
        41000,
        SYN_ACK,
        900,
        101,
        b"",
    )
    .unwrap();
    let inbound = rewriter.translate_inbound(&syn_ack).unwrap().unwrap();
    assert_eq!(tcp_tuple(&inbound), (remote, 7, client, 50000));
    assert!(ipv4_checksum_valid(&inbound));
    assert!(ipv4_tcp_checksum_valid(&inbound));

    let stats = rewriter.stats();
    assert_eq!(stats.active_flows, 1);
    assert_eq!(stats.translated_packets, 1);
    assert_eq!(stats.reverse_packets, 1);
}

#[test]
fn two_clients_with_same_source_port_get_distinct_translated_ports() {
    let mut rewriter = TcpRewriter::new(TcpRewriteConfig {
        proxy_addr: Ipv4Addr::new(169, 254, 0, 10),
        first_port: 42000,
        last_port: 42002,
    })
    .unwrap();
    let remote = Ipv4Addr::new(203, 0, 113, 9);
    let client_a = Ipv4Addr::new(10, 10, 0, 2);
    let client_b = Ipv4Addr::new(10, 20, 0, 2);
    let syn_a = build_ipv4_tcp_packet(client_a, 50000, remote, 7, SYN, 100, 0, b"").unwrap();
    let syn_b = build_ipv4_tcp_packet(client_b, 50000, remote, 7, SYN, 200, 0, b"").unwrap();

    let outbound_a = rewriter.translate_outbound(&syn_a).unwrap().unwrap();
    let outbound_b = rewriter.translate_outbound(&syn_b).unwrap().unwrap();

    assert_eq!(
        tcp_tuple(&outbound_a),
        (Ipv4Addr::new(169, 254, 0, 10), 42000, remote, 7)
    );
    assert_eq!(
        tcp_tuple(&outbound_b),
        (Ipv4Addr::new(169, 254, 0, 10), 42001, remote, 7)
    );
    assert_ne!(tcp_tuple(&outbound_a).1, tcp_tuple(&outbound_b).1);

    let key_a = TcpFlowKey {
        src: SocketAddr::new(IpAddr::V4(client_a), 50000),
        dst: SocketAddr::new(IpAddr::V4(remote), 7),
    };
    let key_b = TcpFlowKey {
        src: SocketAddr::new(IpAddr::V4(client_b), 50000),
        dst: SocketAddr::new(IpAddr::V4(remote), 7),
    };
    assert_eq!(
        rewriter
            .lookup_forward(&key_a)
            .unwrap()
            .translated_src
            .port(),
        42000
    );
    assert_eq!(
        rewriter
            .lookup_forward(&key_b)
            .unwrap()
            .translated_src
            .port(),
        42001
    );
}

#[test]
fn non_syn_without_state_is_dropped() {
    let mut rewriter = TcpRewriter::new(TcpRewriteConfig::default()).unwrap();
    let packet = build_ipv4_tcp_packet(
        Ipv4Addr::new(10, 10, 0, 2),
        50000,
        Ipv4Addr::new(203, 0, 113, 9),
        7,
        ACK,
        100,
        900,
        b"hello",
    )
    .unwrap();

    assert!(rewriter.translate_outbound(&packet).unwrap().is_none());
    assert_eq!(rewriter.stats().dropped_packets, 1);
}

#[tokio::test]
async fn mesh_tun_channel_router_rewrites_two_client_syns() {
    let config = MeshTunConfig {
        // B1: tcp_rewrite now defaults to false; this test exercises the
        // rewrite path, so opt in explicitly.
        tcp_rewrite: true,
        tcp_rewrite_config: TcpRewriteConfig {
            proxy_addr: Ipv4Addr::new(169, 254, 0, 10),
            first_port: 43000,
            last_port: 43010,
        },
        ..MeshTunConfig::default()
    };
    let tun = MeshTun::new(config).unwrap();
    let (_injector, incoming, mut outgoing) = tun
        .run_with_channels_and_policy(
            Arc::new(AllowAllPolicy),
            Arc::new(NoopUdpHandler),
            Arc::new(NoopDnsHandler),
        )
        .await
        .unwrap();

    let remote = Ipv4Addr::new(203, 0, 113, 9);
    incoming
        .send(
            build_ipv4_tcp_packet(
                Ipv4Addr::new(10, 10, 0, 2),
                50000,
                remote,
                7,
                SYN,
                1,
                0,
                b"",
            )
            .unwrap(),
        )
        .await
        .unwrap();
    incoming
        .send(
            build_ipv4_tcp_packet(
                Ipv4Addr::new(10, 20, 0, 2),
                50000,
                remote,
                7,
                SYN,
                2,
                0,
                b"",
            )
            .unwrap(),
        )
        .await
        .unwrap();

    let first = tokio::time::timeout(Duration::from_secs(1), outgoing.recv())
        .await
        .unwrap()
        .unwrap();
    let second = tokio::time::timeout(Duration::from_secs(1), outgoing.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        tcp_tuple(&first),
        (Ipv4Addr::new(169, 254, 0, 10), 43000, remote, 7)
    );
    assert_eq!(
        tcp_tuple(&second),
        (Ipv4Addr::new(169, 254, 0, 10), 43001, remote, 7)
    );
    assert!(ipv4_tcp_checksum_valid(&first));
    assert!(ipv4_tcp_checksum_valid(&second));
}

#[tokio::test]
async fn mesh_tun_channel_router_counts_full_output_queue() {
    mesh_tun::stats::stats().reset();
    let config = MeshTunConfig {
        tcp_rewrite: true,
        packet_queue_capacity: 1,
        tcp_rewrite_config: TcpRewriteConfig {
            proxy_addr: Ipv4Addr::new(169, 254, 0, 11),
            first_port: 44000,
            last_port: 44010,
        },
        ..MeshTunConfig::default()
    };
    let tun = MeshTun::new(config).unwrap();
    let (_injector, incoming, _outgoing) = tun
        .run_with_channels_and_policy(
            Arc::new(AllowAllPolicy),
            Arc::new(NoopUdpHandler),
            Arc::new(NoopDnsHandler),
        )
        .await
        .unwrap();

    let remote = Ipv4Addr::new(203, 0, 113, 10);
    incoming
        .send(
            build_ipv4_tcp_packet(
                Ipv4Addr::new(10, 30, 0, 2),
                50000,
                remote,
                7,
                SYN,
                1,
                0,
                b"",
            )
            .unwrap(),
        )
        .await
        .unwrap();
    incoming
        .send(
            build_ipv4_tcp_packet(
                Ipv4Addr::new(10, 40, 0, 2),
                50000,
                remote,
                7,
                SYN,
                2,
                0,
                b"",
            )
            .unwrap(),
        )
        .await
        .unwrap();

    for _ in 0..50 {
        if mesh_tun::stats::stats()
            .tun_output_queue_full
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("expected tun_output_queue_full to increase");
}

#[test]
fn test_invalid_port_range_zero() {
    assert!(
        TcpRewriter::new(TcpRewriteConfig {
            proxy_addr: Ipv4Addr::new(169, 254, 0, 1),
            first_port: 0,
            last_port: 1000,
        })
        .is_err()
    );
}

#[test]
fn test_invalid_port_range_inverted() {
    assert!(
        TcpRewriter::new(TcpRewriteConfig {
            proxy_addr: Ipv4Addr::new(169, 254, 0, 1),
            first_port: 2000,
            last_port: 1000,
        })
        .is_err()
    );
}

#[test]
fn test_port_range_single_port() {
    let mut rewriter = TcpRewriter::new(TcpRewriteConfig {
        proxy_addr: Ipv4Addr::new(169, 254, 0, 1),
        first_port: 4000,
        last_port: 4000,
    })
    .unwrap();

    let client = Ipv4Addr::new(10, 0, 0, 2);
    let remote = Ipv4Addr::new(203, 0, 113, 9);
    let syn1 = build_ipv4_tcp_packet(client, 50001, remote, 80, SYN, 1, 0, b"").unwrap();
    let syn2 = build_ipv4_tcp_packet(client, 50002, remote, 80, SYN, 1, 0, b"").unwrap();

    assert!(rewriter.translate_outbound(&syn1).unwrap().is_some());
    assert!(rewriter.translate_outbound(&syn2).is_err());
}

#[test]
fn test_port_wrap_around() {
    let mut rewriter = TcpRewriter::new(TcpRewriteConfig {
        proxy_addr: Ipv4Addr::new(169, 254, 0, 1),
        first_port: 4000,
        last_port: 4001,
    })
    .unwrap();

    let client = Ipv4Addr::new(10, 0, 0, 2);
    let remote = Ipv4Addr::new(203, 0, 113, 9);
    let syn1 = build_ipv4_tcp_packet(client, 50001, remote, 80, SYN, 1, 0, b"").unwrap();
    let syn2 = build_ipv4_tcp_packet(client, 50002, remote, 80, SYN, 1, 0, b"").unwrap();

    let out1 = rewriter.translate_outbound(&syn1).unwrap().unwrap();
    let out2 = rewriter.translate_outbound(&syn2).unwrap().unwrap();
    assert_eq!(tcp_tuple(&out1).1, 4000);
    assert_eq!(tcp_tuple(&out2).1, 4001);

    rewriter.prune_expired(Duration::from_secs(0));
    let rst = build_ipv4_tcp_packet(client, 50001, remote, 80, 0x04, 2, 0, b"").unwrap();
    rewriter.translate_outbound(&rst).unwrap();
}

#[test]
fn test_translate_inbound_unknown_flow() {
    let mut rewriter = TcpRewriter::new(TcpRewriteConfig::default()).unwrap();
    let remote = Ipv4Addr::new(203, 0, 113, 9);
    let client = Ipv4Addr::new(169, 254, 0, 1);
    let syn_ack = build_ipv4_tcp_packet(remote, 80, client, 40000, SYN_ACK, 1, 2, b"").unwrap();
    assert!(rewriter.translate_inbound(&syn_ack).unwrap().is_none());
    assert_eq!(rewriter.stats().dropped_packets, 1);
}

#[test]
fn test_retransmitted_syn_reuses_entry() {
    let mut rewriter = TcpRewriter::new(TcpRewriteConfig::default()).unwrap();
    let client = Ipv4Addr::new(10, 0, 0, 2);
    let remote = Ipv4Addr::new(203, 0, 113, 9);
    let syn = build_ipv4_tcp_packet(client, 50001, remote, 80, SYN, 1, 0, b"").unwrap();
    let out1 = rewriter.translate_outbound(&syn).unwrap().unwrap();
    let out2 = rewriter.translate_outbound(&syn).unwrap().unwrap();
    assert_eq!(tcp_tuple(&out1), tcp_tuple(&out2));
}

#[test]
fn test_ack_on_existing_flow() {
    let mut rewriter = TcpRewriter::new(TcpRewriteConfig::default()).unwrap();
    let client = Ipv4Addr::new(10, 0, 0, 2);
    let remote = Ipv4Addr::new(203, 0, 113, 9);
    let syn = build_ipv4_tcp_packet(client, 50001, remote, 80, SYN, 1, 0, b"").unwrap();
    rewriter.translate_outbound(&syn).unwrap().unwrap();

    let ack = build_ipv4_tcp_packet(client, 50001, remote, 80, ACK, 2, 1, b"").unwrap();
    let out_ack = rewriter.translate_outbound(&ack).unwrap().unwrap();
    assert_eq!(tcp_tuple(&out_ack).1, 40000);
}

#[test]
fn test_flow_closure_on_both_fins() {
    let mut rewriter = TcpRewriter::new(TcpRewriteConfig::default()).unwrap();
    let client = Ipv4Addr::new(10, 0, 0, 2);
    let remote = Ipv4Addr::new(203, 0, 113, 9);
    let syn = build_ipv4_tcp_packet(client, 50001, remote, 80, SYN, 1, 0, b"").unwrap();
    rewriter.translate_outbound(&syn).unwrap().unwrap();

    let client_fin = build_ipv4_tcp_packet(client, 50001, remote, 80, 0x01, 2, 1, b"").unwrap();
    rewriter.translate_outbound(&client_fin).unwrap().unwrap();

    let server_fin = build_ipv4_tcp_packet(
        remote,
        80,
        Ipv4Addr::new(169, 254, 0, 1),
        40000,
        0x01,
        1,
        3,
        b"",
    )
    .unwrap();
    rewriter.translate_inbound(&server_fin).unwrap().unwrap();

    let flow_key = TcpFlowKey {
        src: SocketAddr::new(IpAddr::V4(client), 50001),
        dst: SocketAddr::new(IpAddr::V4(remote), 80),
    };
    let entry = rewriter.lookup_forward(&flow_key).unwrap();
    assert!(entry.client_fin);
    assert!(entry.server_fin);
    assert!(entry.closed);
}
