use crate::device::QueueDevice;
use mesh::tun::{TunDnsHandler, TunTcpHandler, TunTcpMeta, TunUdpHandler, TunUdpPacket};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{self, Socket as TcpSocket};
use smoltcp::socket::udp::{self, Socket as UdpSocket};
use smoltcp::wire::{IpAddress, IpCidr};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::sync::Notify;

pub struct TunStack {
    pub interface: Interface,
    pub sockets: SocketSet<'static>,
    pub device: QueueDevice,
    pub active_tcp_sockets: HashSet<SocketHandle>,
    pub vm_id: String,
}

fn parse_packet_and_add_socket(stack: &mut TunStack, p: &[u8]) {
    let mut dst_port = None;
    if p.len() >= 20 {
        let version = p[0] >> 4;
        if version == 4 {
            if let Ok(ipv4) = smoltcp::wire::Ipv4Packet::new_checked(p) {
                if ipv4.next_header() == smoltcp::wire::IpProtocol::Tcp {
                    if let Ok(tcp) = smoltcp::wire::TcpPacket::new_checked(ipv4.payload()) {
                        if tcp.syn() && !tcp.ack() {
                            dst_port = Some(tcp.dst_port());
                        }
                    }
                }
            }
        } else if version == 6 {
            if let Ok(ipv6) = smoltcp::wire::Ipv6Packet::new_checked(p) {
                if ipv6.next_header() == smoltcp::wire::IpProtocol::Tcp {
                    if let Ok(tcp) = smoltcp::wire::TcpPacket::new_checked(ipv6.payload()) {
                        if tcp.syn() && !tcp.ack() {
                            dst_port = Some(tcp.dst_port());
                        }
                    }
                }
            }
        }
    }

    if let Some(port) = dst_port {
        let mut already_listening = false;
        let mut idle_handle = None;
        for (handle, socket) in stack.sockets.iter_mut() {
            if let smoltcp::socket::Socket::Tcp(tcp) = socket {
                if tcp.state() == tcp::State::Listen {
                    if tcp.listen_endpoint().port == port {
                        already_listening = true;
                        break;
                    }
                } else if tcp.state() == tcp::State::Closed {
                    idle_handle = Some(handle);
                }
            }
        }
        if !already_listening {
            if let Some(handle) = idle_handle {
                let socket = stack.sockets.get_mut::<TcpSocket>(handle);
                let _ = socket.listen(port);
            }
        }
    }
}

fn parse_udp_packet(p: &[u8]) -> Option<TunUdpPacket> {
    if p.len() < 20 {
        return None;
    }

    let version = p[0] >> 4;
    if version == 4 {
        let ipv4 = smoltcp::wire::Ipv4Packet::new_checked(p).ok()?;
        if ipv4.next_header() != smoltcp::wire::IpProtocol::Udp {
            return None;
        }
        let udp = smoltcp::wire::UdpPacket::new_checked(ipv4.payload()).ok()?;
        return Some(TunUdpPacket {
            src_addr: IpAddr::from(ipv4.src_addr()),
            src_port: udp.src_port(),
            dst_addr: IpAddr::from(ipv4.dst_addr()),
            dst_port: udp.dst_port(),
            payload: udp.payload().to_vec(),
        });
    }

    if version == 6 {
        let ipv6 = smoltcp::wire::Ipv6Packet::new_checked(p).ok()?;
        if ipv6.next_header() != smoltcp::wire::IpProtocol::Udp {
            return None;
        }
        let udp = smoltcp::wire::UdpPacket::new_checked(ipv6.payload()).ok()?;
        return Some(TunUdpPacket {
            src_addr: IpAddr::from(ipv6.src_addr()),
            src_port: udp.src_port(),
            dst_addr: IpAddr::from(ipv6.dst_addr()),
            dst_port: udp.dst_port(),
            payload: udp.payload().to_vec(),
        });
    }

    None
}

/// Async wrapper for a smoltcp TCP socket.
pub struct AsyncTcpSocket {
    pub stack: Arc<Mutex<TunStack>>,
    pub handle: SocketHandle,
    pub poll_waker: Arc<Notify>,
}

impl AsyncRead for AsyncTcpSocket {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut stack = self.stack.lock().unwrap();
        let socket = stack.sockets.get_mut::<TcpSocket>(self.handle);

        if !socket.is_open() {
            return std::task::Poll::Ready(Ok(()));
        }

        if socket.can_recv() {
            let mut read_buf = vec![0; buf.remaining()];
            match socket.recv_slice(&mut read_buf) {
                Ok(size) => {
                    buf.put_slice(&read_buf[..size]);
                    self.poll_waker.notify_one();
                    std::task::Poll::Ready(Ok(()))
                }
                Err(smoltcp::socket::tcp::RecvError::Finished) => std::task::Poll::Ready(Ok(())),
                Err(smoltcp::socket::tcp::RecvError::InvalidState) => std::task::Poll::Ready(Err(
                    std::io::Error::new(std::io::ErrorKind::NotConnected, "invalid state"),
                )),
            }
        } else {
            socket.register_recv_waker(cx.waker());
            std::task::Poll::Pending
        }
    }
}

impl AsyncWrite for AsyncTcpSocket {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let mut stack = self.stack.lock().unwrap();
        let socket = stack.sockets.get_mut::<TcpSocket>(self.handle);

        if !socket.is_open() {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "socket closed",
            )));
        }

        if socket.can_send() {
            match socket.send_slice(buf) {
                Ok(size) => {
                    self.poll_waker.notify_one();
                    std::task::Poll::Ready(Ok(size))
                }
                Err(smoltcp::socket::tcp::SendError::InvalidState) => std::task::Poll::Ready(Err(
                    std::io::Error::new(std::io::ErrorKind::NotConnected, "invalid state"),
                )),
            }
        } else {
            socket.register_send_waker(cx.waker());
            std::task::Poll::Pending
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut stack = self.stack.lock().unwrap();
        let socket = stack.sockets.get_mut::<TcpSocket>(self.handle);
        socket.close();
        socket.register_send_waker(cx.waker());
        self.poll_waker.notify_one();
        std::task::Poll::Ready(Ok(()))
    }
}

pub struct StackState {
    pub stack: Arc<Mutex<TunStack>>,
    pub poll_waker: Arc<Notify>,
}

impl StackState {
    pub fn new(
        address: IpAddr,
        prefix_len: u8,
        mtu: usize,
        tcp_sockets: usize,
        udp_sockets: usize,
        vm_id: String,
        tx_sender: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Self {
        let mut device = QueueDevice::new(tx_sender, mtu);
        let mut config = Config::new(smoltcp::wire::HardwareAddress::Ip);
        config.random_seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let mut interface = Interface::new(config, &mut device, smoltcp::time::Instant::now());

        // Add IP address
        let ip_addr = match address {
            IpAddr::V4(v4) => IpAddress::Ipv4(v4.into()),
            IpAddr::V6(v6) => IpAddress::Ipv6(v6.into()),
        };
        interface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(ip_addr, prefix_len)).unwrap();
        });

        // Enable any IP to accept all incoming packets
        interface.set_any_ip(true);

        let mut sockets = SocketSet::new(vec![]);

        // Pre-allocate TCP sockets but don't listen yet
        for _ in 0..tcp_sockets {
            let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
            let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
            let tcp_socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);
            sockets.add(tcp_socket);
        }

        // Add one wildcard UDP socket to catch all incoming UDP traffic
        let udp_rx_buffer = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; udp_sockets],
            vec![0; 1500 * udp_sockets],
        );
        let udp_tx_buffer = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; udp_sockets],
            vec![0; 1500 * udp_sockets],
        );
        let mut udp_socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);
        udp_socket.bind(53).unwrap();
        sockets.add(udp_socket);

        Self {
            stack: Arc::new(Mutex::new(TunStack {
                interface,
                sockets,
                device,
                active_tcp_sockets: HashSet::new(),
                vm_id,
            })),
            poll_waker: Arc::new(Notify::new()),
        }
    }

    /// Spawns the main event loop
    pub async fn run_loop(
        self,
        tcp_handler: Arc<dyn TunTcpHandler>,
        udp_handler: Arc<dyn TunUdpHandler>,
        dns_handler: Arc<dyn TunDnsHandler>,
        mut rx_queue: mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        loop {
            let processed;
            let mut spawn_udp_tasks = Vec::new();
            let mut spawn_dns_tasks = Vec::new();
            // Process queue
            let mut has_new_packets = false;
            while let Ok(packet) = rx_queue.try_recv() {
                if let Some(pkt) = parse_udp_packet(&packet) {
                    if pkt.src_port == 53 || pkt.dst_port == 53 {
                        spawn_dns_tasks.push(pkt);
                    } else {
                        spawn_udp_tasks.push(pkt);
                    }
                    has_new_packets = true;
                    continue;
                }
                let mut stack = self.stack.lock().unwrap();
                parse_packet_and_add_socket(&mut stack, &packet);
                stack.device.rx_queue.push_back(packet);
                has_new_packets = true;
            }

            let mut sockets_to_replace = Vec::new();
            let mut spawn_tcp_tasks = Vec::new();

            let delay;
            {
                let mut stack = self.stack.lock().unwrap();
                let now = smoltcp::time::Instant::now();
                let TunStack {
                    interface,
                    sockets,
                    device,
                    active_tcp_sockets,
                    vm_id: _,
                } = &mut *stack;
                processed = interface.poll(now, device, sockets);

                // Handle incoming TCP connections
                for (handle, socket) in sockets.iter_mut() {
                    if let smoltcp::socket::Socket::Tcp(tcp) = socket {
                        if tcp.is_active()
                            && tcp.state() != tcp::State::Listen
                            && !active_tcp_sockets.contains(&handle)
                        {
                            active_tcp_sockets.insert(handle);
                            sockets_to_replace.push(handle);

                            let local_ep = tcp.local_endpoint().unwrap();
                            let remote_ep = tcp.remote_endpoint().unwrap();

                            let meta = TunTcpMeta {
                                src_addr: remote_ep.addr.into(),
                                src_port: remote_ep.port,
                                dst_addr: local_ep.addr.into(),
                                dst_port: local_ep.port,
                            };

                            spawn_tcp_tasks.push((handle, meta));
                        }
                    }
                }

                // Replace consumed TCP sockets with new closed sockets
                for _ in sockets_to_replace.iter() {
                    let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
                    let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
                    let tcp_socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);
                    sockets.add(tcp_socket);
                }

                // Handle incoming UDP packets
                for (_handle, socket) in sockets.iter_mut() {
                    if let smoltcp::socket::Socket::Udp(udp) = socket {
                        while udp.can_recv() {
                            if let Ok((payload, meta)) = udp.recv() {
                                let pkt = TunUdpPacket {
                                    src_addr: meta.endpoint.addr.into(),
                                    src_port: meta.endpoint.port,
                                    dst_addr: "0.0.0.0".parse().unwrap(),
                                    dst_port: 0,
                                    payload: payload.to_vec(),
                                };

                                if pkt.src_port == 53 || pkt.dst_port == 53 {
                                    spawn_dns_tasks.push(pkt);
                                } else {
                                    spawn_udp_tasks.push(pkt);
                                }
                            } else {
                                break;
                            }
                        }
                    }
                }

                delay = interface.poll_delay(now, sockets);
            } // MutexGuard is dropped here

            for (handle, meta) in spawn_tcp_tasks {
                let async_socket = AsyncTcpSocket {
                    stack: self.stack.clone(),
                    handle,
                    poll_waker: self.poll_waker.clone(),
                };
                let tcp_handler_clone = tcp_handler.clone();
                tokio::spawn(async move {
                    let (mut client_s, server_s) = tokio::io::duplex(65535);
                    let mut stack_s = async_socket;
                    tokio::spawn(async move {
                        tcp_handler_clone.handle_tcp(meta, server_s).await;
                    });
                    let _ = tokio::io::copy_bidirectional(&mut client_s, &mut stack_s).await;

                    // Wait for the socket to cleanly close before removing it
                    loop {
                        let mut closed = false;
                        {
                            let mut stack = stack_s.stack.lock().unwrap();
                            let socket = stack.sockets.get_mut::<tcp::Socket>(stack_s.handle);
                            if socket.state() == smoltcp::socket::tcp::State::Closed {
                                stack.sockets.remove(stack_s.handle);
                                stack.active_tcp_sockets.remove(&stack_s.handle);
                                // Replace consumed TCP sockets with new closed sockets
                                let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
                                let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
                                let tcp_socket = TcpSocket::new(tcp_rx_buffer, tcp_tx_buffer);
                                stack.sockets.add(tcp_socket);
                                closed = true;
                            }
                        }
                        if closed {
                            break;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                });
            }

            for pkt in spawn_dns_tasks {
                let handler = dns_handler.clone();
                tokio::spawn(async move {
                    handler.handle_dns(pkt).await;
                });
            }

            for pkt in spawn_udp_tasks {
                let handler = udp_handler.clone();
                tokio::spawn(async move {
                    handler.handle_udp(pkt).await;
                });
            }

            if processed == smoltcp::iface::PollResult::None && !has_new_packets {
                let poll_future = self.poll_waker.notified();
                if let Some(d) = delay {
                    tokio::select! {
                        _ = tokio::time::sleep(d.into()) => {}
                        _ = poll_future => {}
                        packet = rx_queue.recv() => {
                            if let Some(p) = packet {
                                if let Some(pkt) = parse_udp_packet(&p) {
                                    let handler = if pkt.src_port == 53 || pkt.dst_port == 53 {
                                        None
                                    } else {
                                        Some(udp_handler.clone())
                                    };
                                    if let Some(handler) = handler {
                                        tokio::spawn(async move {
                                            handler.handle_udp(pkt).await;
                                        });
                                    } else {
                                        let handler = dns_handler.clone();
                                        tokio::spawn(async move {
                                            handler.handle_dns(pkt).await;
                                        });
                                    }
                                    continue;
                                }
                                let mut stack = self.stack.lock().unwrap();
                                parse_packet_and_add_socket(&mut stack, &p);
                                stack.device.rx_queue.push_back(p);
                            } else {
                                break; // channel closed
                            }
                        }
                    }
                } else {
                    tokio::select! {
                        _ = poll_future => {}
                        packet = rx_queue.recv() => {
                            if let Some(p) = packet {
                                if let Some(pkt) = parse_udp_packet(&p) {
                                    let handler = if pkt.src_port == 53 || pkt.dst_port == 53 {
                                        None
                                    } else {
                                        Some(udp_handler.clone())
                                    };
                                    if let Some(handler) = handler {
                                        tokio::spawn(async move {
                                            handler.handle_udp(pkt).await;
                                        });
                                    } else {
                                        let handler = dns_handler.clone();
                                        tokio::spawn(async move {
                                            handler.handle_dns(pkt).await;
                                        });
                                    }
                                    continue;
                                }
                                let mut stack = self.stack.lock().unwrap();
                                parse_packet_and_add_socket(&mut stack, &p);
                                stack.device.rx_queue.push_back(p);
                            } else {
                                break; // channel closed
                            }
                        }
                    }
                }
            }
        }
    }
}
