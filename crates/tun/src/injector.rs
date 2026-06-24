use crate::stack::{AsyncTcpSocket, TunStack};
use mesh::tun::TunInjector;
use smoltcp::socket::tcp;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

pub struct MeshTunInjector {
    stack: Arc<Mutex<TunStack>>,
    poll_waker: Arc<Notify>,
}

impl MeshTunInjector {
    pub fn new(stack: Arc<Mutex<TunStack>>, poll_waker: Arc<Notify>) -> Self {
        Self { stack, poll_waker }
    }
}

fn internet_checksum(bytes: &[u8]) -> u16 {
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

fn build_ipv4_udp_packet(
    src_addr: Ipv4Addr,
    src_port: u16,
    dst_addr: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, anyhow::Error> {
    let udp_len = 8usize
        .checked_add(payload.len())
        .ok_or_else(|| anyhow::anyhow!("UDP payload too large"))?;
    let total_len = 20usize
        .checked_add(udp_len)
        .ok_or_else(|| anyhow::anyhow!("IPv4 packet too large"))?;
    if total_len > u16::MAX as usize {
        anyhow::bail!("IPv4 packet too large: {total_len}");
    }

    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src_addr.octets());
    packet[16..20].copy_from_slice(&dst_addr.octets());
    let header_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    let udp = &mut packet[20..];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[8..].copy_from_slice(payload);

    Ok(packet)
}

#[async_trait::async_trait]
impl TunInjector for MeshTunInjector {
    async fn connect_tcp(
        &self,
        src_addr: IpAddr,
        src_port: u16,
        dst_addr: IpAddr,
        dst_port: u16,
    ) -> Result<tokio::io::DuplexStream, anyhow::Error> {
        let handle = {
            let mut stack = self.stack.lock().unwrap();
            let tcp_rx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
            let tcp_tx_buffer = tcp::SocketBuffer::new(vec![0; 65535]);
            let mut socket = tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer);

            socket
                .connect(
                    stack.interface.context(),
                    (smoltcp::wire::IpAddress::from(dst_addr), dst_port),
                    (smoltcp::wire::IpAddress::from(src_addr), src_port),
                )
                .map_err(|e| anyhow::anyhow!("Connect error: {:?}", e))?;

            let handle = stack.sockets.add(socket);
            stack.active_tcp_sockets.insert(handle);
            handle
        };

        self.poll_waker.notify_one();

        let async_socket = AsyncTcpSocket {
            stack: self.stack.clone(),
            handle,
            poll_waker: self.poll_waker.clone(),
        };

        let (mut client_s, server_s) = tokio::io::duplex(65535);

        // Bridge task
        tokio::spawn(async move {
            let mut stack_s = async_socket;
            let _ = tokio::io::copy_bidirectional(&mut client_s, &mut stack_s).await;
            // When bridge drops, we should ideally remove the socket from the stack
            // Wait for the socket to cleanly close before removing it
            loop {
                let mut closed = false;
                {
                    let mut stack = stack_s.stack.lock().unwrap();
                    let socket = stack.sockets.get_mut::<tcp::Socket>(stack_s.handle);
                    if socket.state() == smoltcp::socket::tcp::State::Closed {
                        stack.sockets.remove(stack_s.handle);
                        stack.active_tcp_sockets.remove(&stack_s.handle);
                        closed = true;
                    }
                }
                if closed {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        });

        Ok(server_s)
    }

    async fn inject_udp(
        &self,
        src_addr: IpAddr,
        src_port: u16,
        dst_addr: IpAddr,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<(), anyhow::Error> {
        let packet = match (src_addr, dst_addr) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                build_ipv4_udp_packet(src, src_port, dst, dst_port, payload)?
            }
            (IpAddr::V6(_), IpAddr::V6(_)) => {
                anyhow::bail!("IPv6 UDP injection is not implemented yet")
            }
            _ => anyhow::bail!("source and destination IP versions differ"),
        };

        let tx = {
            let stack = self.stack.lock().unwrap();
            stack.device.tx_sender.clone()
        };
        tx.send(packet)
            .map_err(|_| anyhow::anyhow!("TUN output queue closed"))?;
        self.poll_waker.notify_one();
        Ok(())
    }
}
