use mesh::tun::{TunDnsHandler, TunInjector, TunTcpHandler, TunTcpMeta, TunUdpHandler, TunUdpPacket};
use mesh_tun::{MeshTun, MeshTunConfig};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

#[tokio::test]
async fn test_pipe_tun() {
    let mut config1 = MeshTunConfig::default();
    config1.address = "10.5.0.1".parse().unwrap();

    let mut config2 = MeshTunConfig::default();
    config2.address = "10.5.0.2".parse().unwrap();

    let tun1 = MeshTun::new(config1).unwrap();
    let tun2 = MeshTun::new(config2).unwrap();

    let count = Arc::new(AtomicUsize::new(0));

    let tcp1 = Arc::new(MockTcpHandler { count: count.clone() });
    let tcp2 = Arc::new(MockTcpHandler { count: count.clone() });

    let udp = Arc::new(MockUdpHandler);
    let dns = Arc::new(MockDnsHandler);

    let (tx1, rx1) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (tx2, rx2) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    let (inj1, tun1_tx, mut stack1_rx) = tun1.run_with_channels(tcp1, udp.clone(), dns.clone(), tx1, rx1).await.unwrap();
    let (_inj2, tun2_tx, mut stack2_rx) = tun2.run_with_channels(tcp2, udp.clone(), dns.clone(), tx2, rx2).await.unwrap();

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
