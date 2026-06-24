use mesh::tun::{TunDnsHandler, TunTcpHandler, TunTcpMeta, TunUdpHandler, TunUdpPacket};
use mesh_tun::flow::MeshPassthrough;
use mesh_tun::policy::{DenyPortPolicy, FlowProtocol};
use mesh_tun::telemetry::{MeshTunEvent, MeshTunTelemetry};
use mesh_tun::{MeshTun, MeshTunConfig};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct MockTcpHandler {
    count: Arc<AtomicUsize>,
}
#[async_trait::async_trait]
impl TunTcpHandler for MockTcpHandler {
    async fn handle_tcp(&self, _meta: TunTcpMeta, mut stream: tokio::io::DuplexStream) {
        println!("MockTcpHandler got a connection!");
        self.count.fetch_add(1, Ordering::SeqCst);
        let mut buf = [0u8; 1024];
        if let Ok(n) = stream.read(&mut buf).await {
            let _ = stream.write_all(&buf[..n]).await;
        }
    }
}

struct MockUdpHandler;
#[async_trait::async_trait]
impl TunUdpHandler for MockUdpHandler {
    async fn handle_udp(&self, _packet: TunUdpPacket) {}
}

struct MockDnsHandler;
#[async_trait::async_trait]
impl TunDnsHandler for MockDnsHandler {
    async fn handle_dns(&self, _packet: TunUdpPacket) {}
}

struct RecordingUdpHandler {
    packets: Arc<Mutex<Vec<TunUdpPacket>>>,
}

#[async_trait::async_trait]
impl TunUdpHandler for RecordingUdpHandler {
    async fn handle_udp(&self, packet: TunUdpPacket) {
        self.packets.lock().unwrap().push(packet);
    }
}

#[derive(Default)]
struct RecordingTelemetry {
    events: Mutex<Vec<MeshTunEvent>>,
}

#[async_trait::async_trait]
impl MeshTunTelemetry for RecordingTelemetry {
    async fn record(&self, event: MeshTunEvent) {
        self.events.lock().unwrap().push(event);
    }
}

fn ipv4_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum += u16::from_be_bytes([byte, 0]) as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn raw_ipv4_udp(
    src: Ipv4Addr,
    src_port: u16,
    dst: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    let checksum = ipv4_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    let udp = &mut packet[20..];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[8..].copy_from_slice(payload);
    packet
}

#[tokio::test]
async fn test_pipe_tun() {
    let mut config1 = MeshTunConfig::default();
    config1.address = "10.5.0.1".parse().unwrap();

    let mut config2 = MeshTunConfig::default();
    config2.address = "10.5.0.2".parse().unwrap();

    let tun1 = MeshTun::new(config1).unwrap();
    let tun2 = MeshTun::new(config2).unwrap();

    let count = Arc::new(AtomicUsize::new(0));

    let tcp1 = Arc::new(MockTcpHandler {
        count: count.clone(),
    });
    let tcp2 = Arc::new(MockTcpHandler {
        count: count.clone(),
    });

    let udp = Arc::new(MockUdpHandler);
    let dns = Arc::new(MockDnsHandler);

    let (tx1, rx1) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (tx2, rx2) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    let (inj1, tun1_tx, mut stack1_rx) = tun1
        .run_with_channels(tcp1, udp.clone(), dns.clone(), tx1, rx1)
        .await
        .unwrap();
    let (_inj2, tun2_tx, mut stack2_rx) = tun2
        .run_with_channels(tcp2, udp.clone(), dns.clone(), tx2, rx2)
        .await
        .unwrap();

    // Bridge the two stacks
    tokio::spawn(async move {
        while let Some(pkt) = stack1_rx.recv().await {
            let _ = tun2_tx.send(pkt);
        }
    });

    tokio::spawn(async move {
        while let Some(pkt) = stack2_rx.recv().await {
            let _ = tun1_tx.send(pkt);
        }
    });

    // Now let's try to connect from tun1 to tun2
    let mut stream = inj1
        .connect_tcp(
            "10.5.0.1".parse().unwrap(),
            12345,
            "10.5.0.2".parse().unwrap(),
            80,
        )
        .await
        .expect("Failed to connect");

    stream.write_all(b"hello").await.unwrap();

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello");
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn passthrough_proxies_tcp_and_records_telemetry() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 32];
        let n = socket.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
        socket.write_all(b"pong").await.unwrap();
    });

    let telemetry = Arc::new(RecordingTelemetry::default());
    let passthrough = MeshPassthrough::new("vm-a")
        .with_telemetry(telemetry.clone())
        .with_udp_response_timeout(Duration::from_millis(10));
    let (mut guest, handler_side) = tokio::io::duplex(1024);
    let meta = TunTcpMeta {
        src_addr: "10.5.0.2".parse().unwrap(),
        src_port: 40000,
        dst_addr: target.ip(),
        dst_port: target.port(),
    };

    let handler = passthrough.clone();
    tokio::spawn(async move {
        handler.handle_tcp(meta, handler_side).await;
    });

    guest.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 16];
    let n = guest.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"pong");
    guest.shutdown().await.unwrap();

    for _ in 0..50 {
        if telemetry.events.lock().unwrap().iter().any(|event| {
            matches!(
                event,
                MeshTunEvent::FlowBytes {
                    guest_to_remote: 4,
                    remote_to_guest: 4,
                    ..
                }
            )
        }) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let events = telemetry.events.lock().unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        MeshTunEvent::FlowOpen(ctx)
            if ctx.vm_id == "vm-a" && ctx.protocol == FlowProtocol::Tcp && ctx.dst == target
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        MeshTunEvent::FlowBytes {
            guest_to_remote: 4,
            remote_to_guest: 4,
            ..
        }
    )));
}

#[tokio::test]
async fn passthrough_denies_tcp_by_policy() {
    let telemetry = Arc::new(RecordingTelemetry::default());
    let policy = Arc::new(DenyPortPolicy {
        dst_addr: None,
        dst_port: 443,
        reason: "blocked".to_string(),
    });
    let passthrough = MeshPassthrough::new("vm-b")
        .with_policy(policy)
        .with_telemetry(telemetry.clone());
    let (_guest, handler_side) = tokio::io::duplex(1024);
    let meta = TunTcpMeta {
        src_addr: "10.5.0.2".parse().unwrap(),
        src_port: 40000,
        dst_addr: "203.0.113.10".parse().unwrap(),
        dst_port: 443,
    };

    passthrough.handle_tcp(meta, handler_side).await;

    let events = telemetry.events.lock().unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        MeshTunEvent::FlowDeny { context, reason }
            if context.vm_id == "vm-b" && context.dst.port() == 443 && reason == "blocked"
    )));
}

#[tokio::test]
async fn channel_stack_captures_udp_destination_metadata() {
    let config = MeshTunConfig::default();
    let tun = MeshTun::new(config).unwrap();
    let udp_packets = Arc::new(Mutex::new(Vec::new()));
    let udp = Arc::new(RecordingUdpHandler {
        packets: udp_packets.clone(),
    });
    let dns = Arc::new(MockDnsHandler);
    let tcp = Arc::new(MockTcpHandler {
        count: Arc::new(AtomicUsize::new(0)),
    });
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (_injector, tun_tx, _stack_rx) =
        tun.run_with_channels(tcp, udp, dns, tx, rx).await.unwrap();

    tun_tx
        .send(raw_ipv4_udp(
            "10.5.0.2".parse().unwrap(),
            49152,
            "198.51.100.7".parse().unwrap(),
            8080,
            b"payload",
        ))
        .unwrap();

    for _ in 0..50 {
        if !udp_packets.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let packets = udp_packets.lock().unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].src_addr, "10.5.0.2".parse::<IpAddr>().unwrap());
    assert_eq!(packets[0].src_port, 49152);
    assert_eq!(
        packets[0].dst_addr,
        "198.51.100.7".parse::<IpAddr>().unwrap()
    );
    assert_eq!(packets[0].dst_port, 8080);
    assert_eq!(packets[0].payload, b"payload");
}

#[tokio::test]
async fn injector_emits_raw_udp_packet() {
    let config = MeshTunConfig::default();
    let tun = MeshTun::new(config).unwrap();
    let udp = Arc::new(MockUdpHandler);
    let dns = Arc::new(MockDnsHandler);
    let tcp = Arc::new(MockTcpHandler {
        count: Arc::new(AtomicUsize::new(0)),
    });
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (injector, _tun_tx, mut stack_rx) =
        tun.run_with_channels(tcp, udp, dns, tx, rx).await.unwrap();

    injector
        .inject_udp(
            "198.51.100.7".parse().unwrap(),
            8080,
            "10.5.0.2".parse().unwrap(),
            49152,
            b"reply",
        )
        .await
        .unwrap();

    let packet = tokio::time::timeout(Duration::from_secs(1), stack_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        packet,
        raw_ipv4_udp(
            "198.51.100.7".parse().unwrap(),
            8080,
            "10.5.0.2".parse().unwrap(),
            49152,
            b"reply",
        )
    );
}
