use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use std::collections::VecDeque;
use tokio::sync::mpsc;

/// A queue-backed device for smoltcp.
/// This allows decoupling the asynchronous I/O (like a TUN interface or a test pipe)
/// from the synchronous `smoltcp` stack.
pub struct QueueDevice {
    pub rx_queue: VecDeque<Vec<u8>>,
    pub tx_sender: mpsc::UnboundedSender<Vec<u8>>,
    pub mtu: usize,
}

impl QueueDevice {
    pub fn new(tx_sender: mpsc::UnboundedSender<Vec<u8>>, mtu: usize) -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_sender,
            mtu,
        }
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = RxTokenImpl;
    type TxToken<'a> = TxTokenImpl<'a>;

    fn receive(&mut self, _timestamp: smoltcp::time::Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx_queue.pop_front().map(|buffer| {
            (
                RxTokenImpl(buffer),
                TxTokenImpl {
                    tx: &self.tx_sender,
                },
            )
        })
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TxTokenImpl {
            tx: &self.tx_sender,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu;
        caps.medium = Medium::Ip;
        caps
    }
}

pub struct RxTokenImpl(Vec<u8>);

impl smoltcp::phy::RxToken for RxTokenImpl {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&mut self.0)
    }
}

pub struct TxTokenImpl<'a> {
    tx: &'a mpsc::UnboundedSender<Vec<u8>>,
}

impl<'a> smoltcp::phy::TxToken for TxTokenImpl<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        let mut flags = String::new();
        if buffer.len() >= 40 {
            if let Ok(ipv4) = smoltcp::wire::Ipv4Packet::new_checked(&buffer) {
                if ipv4.next_header() == smoltcp::wire::IpProtocol::Tcp {
                    if let Ok(tcp) = smoltcp::wire::TcpPacket::new_checked(ipv4.payload()) {
                        if tcp.syn() { flags.push_str("SYN "); }
                        if tcp.ack() { flags.push_str("ACK "); }
                        if tcp.rst() { flags.push_str("RST "); }
                        if tcp.fin() { flags.push_str("FIN "); }
                        if tcp.psh() { flags.push_str("PSH "); }
                    }
                }
            }
        }
        println!("Transmitting packet of len {}: {}", buffer.len(), flags);
        // Ignore send errors in case the receiving end is dropped
        let _ = self.tx.send(buffer);
        result
    }
}
