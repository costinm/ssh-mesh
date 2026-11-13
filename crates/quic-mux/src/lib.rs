//! `#![no_std]` QUIC stream multiplexer, zero-copy pool prefix framing, and 3-tier flow control.
//!
//! Shared packet pools, wire codecs, ordered stream reassembly, and link traits live in
//! [`quic_base`] and are re-exported here for convenience.
//!
//! ### Feature Flags
//! - **Default (`default-features = false`):** Pure `#![no_std]` + `alloc` core ([`QuicMux`],
//!   [`PacketPool`], [`SackRetransmitLedger`], wire codecs, and 3-tier flow control) suitable for
//!   embedded/ESP32 targets as well as custom host runtimes.
//! - **`tokio`:** Enables [`TokioMux`], [`MuxStream`], [`MuxReadHalf`], [`MuxWriteHalf`], and
//!   [`tokio_mux::TokioLinkSet`] (`AsyncRead + AsyncWrite` + zero-copy packet ownership API over
//!   single or multipath TCP/UDS/TLS links).

#![no_std]
extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

pub use quic_base::{flow, header, link, pool, streams, wire};

pub mod mux;
#[cfg(any(test, feature = "tokio"))]
pub mod tokio_mux;
#[cfg(any(test, feature = "tokio"))]
pub mod tokio_stream;

pub use flow::{
    AssociationBrokenReason, GAP_TIMEOUT_ERROR_CODE, MuxCallbacks, RESOURCE_PRESSURE_ERROR_CODE,
    RecvFlowControl, RxOutcome, SendFlowControl, StreamCloseReason, StreamError, StreamPriority,
    StreamSendCapacity,
};
pub use link::{
    AckRange, AssociationEgress, AssociationId, LinkSendError, MASTER_ASSOC, OWNER_ASSOC,
    RetransmitCandidate, RxMeta, SackRetransmitLedger, TxPacketMeta, default_coalesce_threshold,
    try_coalesce_tx_packet,
};
pub use mux::{AssociationLimits, MuxError, MuxLimits, MuxSendError, QuicMux};
pub use pool::{
    DEFAULT_HEADROOM, DEFAULT_MAX_PAYLOAD, DEFAULT_SLOT_SIZE, DEFAULT_TAIL, PacketPool, PoolError,
    PoolPacket,
};
#[cfg(any(feature = "std", test))]
pub use pool::{
    HEAP_PACKET_SLOT_OVERHEAD, HeapPacketAllocator, HeapPacketLease, HeapPacketPool,
    HeapPacketPoolError, SlabPacket, SlabPool, StaticPacketLease, StaticPacketPool, XipLazyPacket,
    XipLazyPool, XipPacketRef,
};
pub use streams::{
    OrderedStream, QueuedPayload, ReassemblyError, RxStreamChunk, StreamState, TxStreamData,
};
#[cfg(any(test, feature = "tokio"))]
pub use tokio_stream::{
    DEFAULT_ASSOCIATION_ID, MuxReadHalf, MuxStream, MuxWriteHalf, OwnedRxChunk, TokioMux,
    TokioMuxAcceptor, TokioMuxConfig,
};
pub use wire::{Frame, StreamFrameRange, StreamId, WireError};

#[cfg(test)]
mod tests;
