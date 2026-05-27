use std::net::IpAddr;
use std::sync::Arc;

pub mod device;
pub mod injector;
pub mod stack;

/// Configuration for MeshTun
#[derive(Debug, Clone)]
pub struct MeshTunConfig {
    /// TUN interface name (e.g., "tun0"). Ignored if `fd` is set.
    pub name: Option<String>,
    /// Pre-opened TUN file descriptor (Android VPN).
    pub fd: Option<i32>,
    /// Local IP address for the smoltcp interface.
    pub address: IpAddr,
    /// Network prefix length.
    pub prefix_len: u8,
    /// MTU for the interface.
    pub mtu: usize,
    /// Pre-allocated TCP socket count (can grow since we use std Vec).
    pub tcp_sockets: usize,
    /// Pre-allocated UDP socket count.
    pub udp_sockets: usize,
}

impl Default for MeshTunConfig {
    fn default() -> Self {
        Self {
            name: None,
            fd: None,
            address: "10.5.0.1".parse().unwrap(),
            prefix_len: 16,
            mtu: 1500,
            tcp_sockets: 64,
            udp_sockets: 64,
        }
    }
}

pub struct MeshTun {
    config: MeshTunConfig,
}

impl MeshTun {
    pub fn new(config: MeshTunConfig) -> Result<Self, anyhow::Error> {
        Ok(Self { config })
    }

    /// Create from an Android VPN file descriptor.
    pub unsafe fn from_fd(fd: i32) -> Result<Self, anyhow::Error> {
        let mut config = MeshTunConfig::default();
        config.fd = Some(fd);
        Ok(Self { config })
    }

    /// Access the config
    /// Start the smoltcp event loop and return the injector.
    pub async fn run(
        self,
        tcp_handler: Arc<dyn mesh::tun::TunTcpHandler>,
        udp_handler: Arc<dyn mesh::tun::TunUdpHandler>,
        dns_handler: Arc<dyn mesh::tun::TunDnsHandler>,
    ) -> Result<Arc<dyn mesh::tun::TunInjector>, anyhow::Error> {
        let (tun_tx, tun_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (stack_tx, mut stack_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

        // Create the stack state
        let stack_state = stack::StackState::new(
            self.config.address,
            self.config.prefix_len,
            self.config.mtu,
            self.config.tcp_sockets,
            self.config.udp_sockets,
            stack_tx,
        );

        let stack_arc = stack_state.stack.clone();
        let waker = stack_state.poll_waker.clone();
        let injector = Arc::new(injector::MeshTunInjector::new(stack_arc, waker));

        if let Some(fd) = self.config.fd {
            // Android VPN Mode (or pre-opened TUN fd)
            let tun = unsafe { tun_rs::AsyncDevice::from_fd(fd) }.map_err(|e| anyhow::anyhow!("TUN FD error: {}", e))?;
            let tun_arc = Arc::new(tun);
            let tun_read = tun_arc.clone();
            let tun_write = tun_arc;

            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    match tun_read.recv(&mut buf).await {
                        Ok(n) => {
                            let _ = tun_tx.send(buf[..n].to_vec());
                        }
                        Err(e) => {
                            tracing::error!("TUN read error: {}", e);
                            break;
                        }
                    }
                }
            });

            tokio::spawn(async move {
                while let Some(pkt) = stack_rx.recv().await {
                    let _ = tun_write.send(&pkt).await;
                }
            });
        } else {
            // Test Mode: We leave the queues open. Tests can push/pull to them if we exposed them, 
            // but for a pipe test, we can just use the config fd or we expose a method to inject.
            // Wait, tun-rs also supports creating a real TUN by name.
            let mut builder = tun_rs::DeviceBuilder::new();
            if let Some(name) = &self.config.name {
                builder = builder.name(name);
            }
            let tun = builder.mtu(self.config.mtu as u16).build_async().map_err(|e| anyhow::anyhow!("TUN create error: {}", e))?;
            let tun_arc = Arc::new(tun);
            let tun_read = tun_arc.clone();
            let tun_write = tun_arc;

            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    match tun_read.recv(&mut buf).await {
                        Ok(n) => {
                            let _ = tun_tx.send(buf[..n].to_vec());
                        }
                        Err(e) => {
                            tracing::error!("TUN read error: {}", e);
                            break;
                        }
                    }
                }
            });

            tokio::spawn(async move {
                while let Some(pkt) = stack_rx.recv().await {
                    let _ = tun_write.send(&pkt).await;
                }
            });
        }

        tokio::spawn(async move {
            stack_state.run_loop(tcp_handler, udp_handler, dns_handler, tun_rx).await;
        });

        Ok(injector)
    }

    /// Internal method for test environments to inject a pair of channels instead of a real TUN device
    pub async fn run_with_channels(
        self,
        tcp_handler: Arc<dyn mesh::tun::TunTcpHandler>,
        udp_handler: Arc<dyn mesh::tun::TunUdpHandler>,
        dns_handler: Arc<dyn mesh::tun::TunDnsHandler>,
        _tun_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        _stack_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    ) -> Result<(Arc<dyn mesh::tun::TunInjector>, tokio::sync::mpsc::UnboundedSender<Vec<u8>>, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>), anyhow::Error> {
        let (inner_tun_tx, tun_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (stack_tx, inner_stack_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

        let stack_state = stack::StackState::new(
            self.config.address,
            self.config.prefix_len,
            self.config.mtu,
            self.config.tcp_sockets,
            self.config.udp_sockets,
            stack_tx,
        );

        let stack_arc = stack_state.stack.clone();
        let waker = stack_state.poll_waker.clone();
        let injector = Arc::new(injector::MeshTunInjector::new(stack_arc, waker));

        tokio::spawn(async move {
            stack_state.run_loop(tcp_handler, udp_handler, dns_handler, tun_rx).await;
        });

        Ok((injector, inner_tun_tx, inner_stack_rx))
    }
}
