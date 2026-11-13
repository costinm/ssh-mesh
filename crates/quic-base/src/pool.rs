//! Re-exports the transport-neutral packet pool traits (and host pool implementations) from [`mesh_api::pool`].

pub use mesh_api::pool::{
    DEFAULT_HEADROOM, DEFAULT_MAX_PAYLOAD, DEFAULT_SLOT_SIZE, DEFAULT_TAIL, PacketPool, PoolError,
    PoolPacket,
};
#[cfg(any(feature = "std", feature = "host-pools", test))]
pub use mesh_api::pool::{
    HEAP_PACKET_SLOT_OVERHEAD, HeapPacketAllocator, HeapPacketLease, HeapPacketPool,
    HeapPacketPoolError, SlabPacket, SlabPool, StaticPacketLease, StaticPacketPool, XipLazyPacket,
    XipLazyPool, XipPacketRef,
};
