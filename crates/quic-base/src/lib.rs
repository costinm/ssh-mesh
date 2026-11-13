//! Shared `#![no_std]` foundation crate (`quic-base`) for `quic-mux`, `quic-link`, and `quic-relay`.
//!
//! Provides:
//! - [`pool`]: Zero-copy packet pool traits ([`PoolPacket`], [`PacketPool`]) and three pool
//!   implementations ([`StaticPacketPool`], [`HeapPacketPool`], and [`XipLazyPool`] / [`SlabPool`]).
//! - [`wire`]: QUIC RFC 9000 varint codec, [`StreamId`], [`Frame`] (`STREAM`, `MAX_DATA`,
//!   `MAX_STREAM_DATA`, `MAX_STREAMS`, `RESET_STREAM`, `STOP_SENDING`, `CONNECTION_CLOSE`), and
//!   byte-stream frame planning ([`stream_frame_header_step`], [`plan_stream_packet`]).
//! - [`header`]: Compact [`ConnectionId`] (1/2/4/8B), [`ShortHeader`] / [`ShortHeaderPrefix`] with
//!   RFC 9000 sliding-window packet-number reconstruction, [`AckRanges`] (`0x02`),
//!   [`AckFrequencyFrame`] (`0xaf`), and RFC 9221 `DATAGRAM` (`0x30`/`0x31`) codecs.
//! - [`flow`] & [`streams`]: [`StreamPriority`], [`RecvFlowControl`], [`SendFlowControl`],
//!   [`OrderedStream`], [`StreamState`], [`RxStreamChunk`], [`TxStreamData`], [`RxOutcome`], and
//!   [`MuxCallbacks`].
//! - [`link`]: [`AssociationId`], [`RxMeta`], [`TxPacketMeta`], [`AssociationEgress`],
//!   [`try_coalesce_tx_packet`], and [`SackRetransmitLedger`].

#![no_std]
#![deny(missing_docs)]

extern crate alloc;
#[cfg(any(test, feature = "std"))]
extern crate std;

pub mod crypto;
pub mod flow;
pub mod header;
pub mod link;
pub mod policy;
pub mod pool;
pub mod streams;
pub mod wire;

pub use crypto::{
    AEAD_TAG_LEN, ASSOCIATION_RANDOM_LEN, CryptoError, CryptoRole, DirectionKeyMaterial,
    FLAG_PROTECTED, PacketCrypto, TRAFFIC_IV_LEN, TRAFFIC_KEY_LEN, canonical_short_header_aad,
    make_packet_nonce, open_short_packet_in_place, seal_short_packet_in_place,
};
#[cfg(feature = "rust-crypto")]
pub use crypto::{EndpointKeys, RustAes128Gcm, TrafficKeys, derive_traffic_keys};

pub use flow::{
    AssociationBrokenReason, GAP_TIMEOUT_ERROR_CODE, MuxCallbacks, RESOURCE_PRESSURE_ERROR_CODE,
    RecvFlowControl, RxOutcome, SendFlowControl, StreamCloseReason, StreamError, StreamPriority,
    StreamSendCapacity,
};
pub use header::{
    ACK_RANGE_CAPACITY, AckFrequencyFrame, AckRangeSet, AckRanges, ConnectionId, FRAME_ACK,
    FRAME_ACK_FREQUENCY, FRAME_DATAGRAM, FRAME_DATAGRAM_LEN, FRAME_PADDING, FRAME_PING, LinkFrame,
    PacketAckRange, ShortHeader, ShortHeaderPrefix, decode_ack_frame_body,
    encode_ack_frequency_frame, encode_ack_frame, encode_datagram_header, packet_number_len,
    plan_short_header_stream_packet,
};
pub use link::{
    AckRange, AssociationEgress, AssociationId, LinkSendError, MASTER_ASSOC, OWNER_ASSOC,
    RetransmitCandidate, RxMeta, SackRetransmitLedger, TxPacketMeta, default_coalesce_threshold,
    try_coalesce_tx_packet,
};
pub use policy::PacketPoolPolicy;
pub use pool::{
    DEFAULT_HEADROOM, DEFAULT_MAX_PAYLOAD, DEFAULT_SLOT_SIZE, DEFAULT_TAIL, PacketPool, PoolError,
    PoolPacket,
};
#[cfg(any(feature = "std", feature = "host-pools", test))]
pub use pool::{
    HEAP_PACKET_SLOT_OVERHEAD, HeapPacketAllocator, HeapPacketLease, HeapPacketPool,
    HeapPacketPoolError, SlabPacket, SlabPool, StaticPacketLease, StaticPacketPool, XipLazyPacket,
    XipLazyPool, XipPacketRef,
};
pub use streams::{
    OrderedStream, QueuedChunk, QueuedPayload, ReassemblyError, RxStreamChunk, StreamState,
    TxStreamData,
};
pub use wire::{
    Frame, MAX_STREAM_FRAME_HEADER_LEN, MAX_VARINT, StreamFrameRange, StreamHeaderStep, StreamId,
    StreamPacketPlan, WireError, decode_frame, decode_varint, encode_control_frame,
    encode_stream_header, encode_varint, plan_stream_packet, stream_frame_header_step, varint_len,
};
