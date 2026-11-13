//! Zero-copy packet-borrow stream primitives (`RxStreamChunk`, `RxOutcome`, `TxStreamData`,
//! and [`PacketStreamHandler`]) shared across embedded modules, links, and host multiplexers.

use crate::pool::{PacketPool, PoolPacket};

/// Outcome returned by a stream consumer (`on_stream_data` / [`PacketStreamHandler::on_data`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxOutcome<P> {
    /// Handler consumed `n` bytes synchronously (or transferred ownership of `P` immediately)
    /// and releases receive credit for `n` bytes now.
    Consumed(usize),
    /// Handler consumed `consumed` prefix bytes (`consumed < chunk.len()`) and returns ownership of
    /// `packet` so the multiplexer can retain the unconsumed suffix `consumed..chunk.len()`
    /// until the stream is resumed.
    Partial {
        /// Number of prefix bytes consumed now.
        consumed: usize,
        /// Returned packet lease holding the unconsumed suffix.
        packet: P,
    },
    /// Handler took ownership of `RxStreamChunk::packet` (`Some(P)`) and will release receive
    /// credit once downstream forwarding completes.
    RetainedPendingCredit,
}

/// Borrowed or pool-leased incoming stream chunk.
///
/// Exactly one of `packet` or `small_buf` is populated:
/// - **Single-stream packet, or the `> 1/2 MTU` frame in a multi-frame packet:**
///   `packet` is `Some(P)` (`P::is_unique() == true`) with `P::range()` set to the stream payload,
///   and `small_buf` is `&[]`. Ownership of `P` is transferred to the handler, which may forward
///   `P` directly to another stream (proxy/gateway zero-copy forwarding).
/// - **Small frame (`<= 1/2 MTU`) in a multi-frame packet or borrowed slice:**
///   `packet` is `None` and `small_buf` holds `&'a [u8]`.
pub struct RxStreamChunk<'a, P: PoolPacket> {
    /// Owned packet lease when the stream chunk owns the single-stream packet.
    pub packet: Option<P>,
    /// Borrowed payload slice when multiple stream frames share a packet or on slice-based transports.
    pub small_buf: &'a [u8],
}

impl<'a, P: PoolPacket> RxStreamChunk<'a, P> {
    /// Construct a chunk transferring ownership of `packet`.
    #[inline]
    pub const fn from_packet(packet: P) -> Self {
        Self {
            packet: Some(packet),
            small_buf: &[],
        }
    }

    /// Construct a chunk borrowing `small_buf`.
    #[inline]
    pub const fn from_slice(small_buf: &'a [u8]) -> Self {
        Self {
            packet: None,
            small_buf,
        }
    }

    /// Payload slice regardless of whether backed by `packet` or `small_buf`.
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        match &self.packet {
            Some(pkt) => pkt.bytes(),
            None => self.small_buf,
        }
    }

    /// Alias for [`Self::bytes`].
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.bytes()
    }

    /// Take ownership of the underlying `PoolPacket` (`Some(P)` on single-stream packets).
    #[inline]
    pub fn take_packet(&mut self) -> Option<P> {
        self.packet.take()
    }

    /// Length of the payload in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes().len()
    }

    /// Whether the payload is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Outbound stream payload passed to a stream multiplexer or transport.
pub enum TxStreamData<'a, P: PoolPacket> {
    /// Zero-copy pool packet: caller placed payload in the middle (`range.start >= headroom`).
    /// The multiplexer prepends the stream header in-place in front of `range.start`.
    Packet(P),
    /// Small non-pool buffer provided by the caller.
    Bytes(&'a [u8]),
}

impl<'a, P: PoolPacket> TxStreamData<'a, P> {
    /// Length of the outbound payload in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        match self {
            Self::Packet(pkt) => pkt.bytes().len(),
            Self::Bytes(b) => b.len(),
        }
    }

    /// Whether the outbound payload is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Tier-1 zero-copy, event-driven stream handler over borrowed slices or pool packets.
///
/// Suitable for low-memory `#![no_std]` environments (such as XIP modules using `xip_abi::Stream`
/// or `QuicMux` / `SingleStreamEndpoint` without intermediate buffering).
pub trait PacketStreamHandler<P: PoolPacket> {
    /// Handler-specific error type.
    type Error;

    /// Called once when the opening request envelope has been decoded.
    ///
    /// `fields` is the borrowed encoded payload/fields map (envelope key `5` / `"fields"`).
    /// `fin` is `true` if the peer half-closed the stream immediately after the envelope.
    fn on_open(&mut self, request_id: u64, fields: &[u8], fin: bool) -> Result<(), Self::Error>;

    /// Called when contiguous in-order stream body bytes arrive.
    ///
    /// Returns [`RxOutcome::Consumed`] with the number of bytes accepted (`0..=chunk.len()`),
    /// [`RxOutcome::Partial`] when returning an unconsumed packet suffix, or
    /// [`RxOutcome::RetainedPendingCredit`] when taking ownership of `chunk.packet`.
    fn on_data<'a>(
        &mut self,
        chunk: RxStreamChunk<'a, P>,
        fin: bool,
    ) -> Result<RxOutcome<P>, Self::Error>;

    /// Pull the next outbound response packet `(packet, fin)` to transmit.
    fn poll_transmit<Pool: PacketPool<Packet = P>>(
        &mut self,
        pool: &Pool,
    ) -> Result<Option<(P, bool)>, Self::Error>;
}
