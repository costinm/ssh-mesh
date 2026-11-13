//! RFC 9221 Unreliable `DATAGRAM` (`0x30` / `0x31`) policy, priority admission, and zero-copy framing.

use quic_base::pool::PoolPacket;
use quic_base::wire::WireError;

use crate::wire::encode_datagram_header;

/// Configuration for RFC 9221 unreliable `DATAGRAM` frames on an association.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatagramConfig {
    /// Maximum incoming `DATAGRAM` frame size we accept (`0` disables incoming datagrams).
    pub max_recv_datagram_size: usize,
    /// Peer-advertised maximum `DATAGRAM` frame size (`0` disables outgoing datagrams).
    pub max_send_datagram_size: usize,
    /// Advisory connection flow-control window reserve in bytes required before admitting
    /// `LOW` (`192`) or `BULK` (`255`) datagrams (e.g. diagnostic logs).
    ///
    /// Mirrors `quic-lite::DatagramPriority::Low` policy so bulk/log datagrams never starve
    /// active reliable streams when the connection window or link congestion window is tight.
    pub low_priority_window_reserve_bytes: u64,
}

impl Default for DatagramConfig {
    fn default() -> Self {
        Self {
            max_recv_datagram_size: 1456,
            max_send_datagram_size: 1456,
            low_priority_window_reserve_bytes: 1200,
        }
    }
}

/// Errors returned when sending an unreliable `DATAGRAM`.
#[derive(Debug, PartialEq, Eq)]
pub enum DatagramSendError<P> {
    /// Outgoing datagrams are disabled on this association (`max_send_datagram_size == 0`).
    Disabled(P),
    /// Payload exceeds the peer's `max_send_datagram_size` or the best link's writable MTU.
    TooLarge {
        /// Unmodified packet lease returned to the caller.
        packet: P,
        /// Maximum datagram payload length currently writable.
        max_payload_len: usize,
    },
    /// Low/Bulk-priority datagram shed because the advisory connection/congestion window reserve
    /// is below [`DatagramConfig::low_priority_window_reserve_bytes`].
    LowPriorityShed(P),
    /// All candidate links (that admit `priority`) are currently busy or rate-limited.
    Busy(P),
    /// Insufficient packet headroom to prepend the `DATAGRAM` frame header in-place.
    Wire(WireError, P),
}

/// Prepend a `DATAGRAM` (`0x30` or `0x31` + length varint) header in-place in front of
/// `packet.range().start`.
pub fn prepend_datagram_frame_in_place<P: PoolPacket>(
    packet: &mut P,
    include_len: bool,
) -> Result<usize, WireError> {
    let payload_len = packet.bytes().len();
    let mut hdr_buf = [0u8; 9];
    let hdr_len = encode_datagram_header(payload_len, include_len, &mut hdr_buf)?;
    packet
        .prepend(&hdr_buf[..hdr_len])
        .map_err(|_| WireError::BufferTooSmall)?;
    Ok(hdr_len)
}
