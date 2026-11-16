//! Transport-neutral `#![no_std]` link-layer traits and metadata (`PeerL2Address`,
//! `LinkInfo`, `LinkMeta`, `PacketLink`).
//!
//! Link-layer crates (UART/PPP, BLE CoC, raw ESP-NOW/Wi-Fi, UDP) implement this
//! boundary against [`crate::pool::PoolPacket`] without depending on QUIC crates.

use crate::pool::PoolPacket;

/// Opaque non-zero L2 peer identifier on a link (e.g. encoded MAC or serial token).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PeerL2Address(u64);

impl PeerL2Address {
    /// Construct a [`PeerL2Address`] from a non-zero raw token.
    #[inline]
    pub const fn new(raw: u64) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    /// Encode a 6-byte IEEE 802 MAC address into a non-zero [`PeerL2Address`].
    #[inline]
    pub const fn from_mac(mac: [u8; 6]) -> Self {
        let mut raw = 0u64;
        let mut i = 0;
        while i < 6 {
            raw = (raw << 8) | (mac[i] as u64);
            i += 1;
        }
        // Set bit 48 so an all-zero MAC still yields a non-zero token if ever passed.
        Self(raw | (1u64 << 48))
    }

    /// Raw numeric value of this peer address.
    #[inline]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Short ASCII link-layer name (up to 16 bytes).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LinkName {
    bytes: [u8; 16],
    len: u8,
}

impl LinkName {
    /// Construct a [`LinkName`] from a non-empty ASCII string of at most 16 bytes.
    pub const fn new(name: &str) -> Option<Self> {
        let raw = name.as_bytes();
        if raw.is_empty() || raw.len() > 16 {
            return None;
        }
        let mut bytes = [0u8; 16];
        let mut i = 0;
        while i < raw.len() {
            if !raw[i].is_ascii() {
                return None;
            }
            bytes[i] = raw[i];
            i += 1;
        }
        Some(Self {
            bytes,
            len: raw.len() as u8,
        })
    }

    /// Borrow the link name as `&str`.
    #[inline]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len as usize]).unwrap_or("")
    }
}

/// Static capabilities and framing requirements reported by a link adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkInfo {
    /// Short link identifier (e.g. `"uart"`, `"ble-coc"`, `"espnow"`, `"udp"`).
    pub name: LinkName,
    /// Maximum payload bytes the link accepts per packet.
    pub max_packet_size: usize,
    /// Required headroom bytes before the payload slice.
    pub prefix_required: usize,
    /// Required tailroom bytes after the payload slice.
    pub suffix_required: usize,
    /// True if the link itself lacks encryption and requires upper-layer encryption.
    pub requires_packet_encryption: bool,
    /// True if the underlying link already provides link-layer confidentiality/auth.
    pub secure_link: bool,
    /// Nominal bitrate in bits per second (`0` if unknown).
    pub nominal_bitrate_bps: u64,
    /// Optional local 6-byte MAC address.
    pub local_mac: Option<[u8; 6]>,
}

/// Per-packet receive metadata produced by a link adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkMeta {
    /// L2 source peer address.
    pub peer: PeerL2Address,
    /// Monotonic receive timestamp in microseconds.
    pub received_at_us: u64,
    /// Optional signed RSSI in dBm.
    pub rssi_dbm: Option<i8>,
}

/// Outcome of submitting one packet to a link adapter when packet ownership was consumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkTxOutcome {
    /// Frame was accepted by the bearer or handed to the physical medium.
    ///
    /// For connectionless radios or UDP, `Sent` means local transmission completed, not that the
    /// peer received the packet (end-to-end ACKs confirm peer receipt).
    Sent,
    /// Local transport definitely failed to transmit the packet before medium delivery.
    Failed,
    /// Ambiguous local outcome; the packet remains in flight until ACK or timeout resolves it.
    Indeterminate,
}

/// Synchronous packet-link egress boundary implemented by L2 adapters.
pub trait PacketLink<P: PoolPacket> {
    /// Link capabilities and framing constraints.
    fn info(&self) -> &LinkInfo;

    /// Submit one pooled packet toward `peer`.
    ///
    /// When the link TX queue is temporarily blocked or full, the adapter returns `Err(packet)`
    /// so the caller retains the exact lease without copying. Returning `Ok(outcome)` consumes
    /// `packet` with the observed [`LinkTxOutcome`].
    fn send_packet(&mut self, peer: PeerL2Address, packet: P) -> Result<LinkTxOutcome, P>;
}

/// Asynchronous packet-link ingress sink implemented by link consumers.
pub trait LinkIngress<P: PoolPacket>: Send + Sync {
    /// Deliver one received pooled packet with its L2 metadata.
    fn on_packet(&self, meta: LinkMeta, packet: P);

    /// Notify the consumer that a previously full TX path may accept packets again.
    fn on_tx_ready(&self) {}
}
