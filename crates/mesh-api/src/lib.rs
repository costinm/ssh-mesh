#![no_std]

//! Portable mesh contracts shared by firmware and host implementations.
//!
//! WIP: more code will move here, as needed for the ESP32/no_std implementation.
//! `mesh-api` intentionally has no executor, socket, QUIC, SSH, HTTP, or
//! platform dependency. QUIC-lite implements its association boundary here;
//! the host `mesh` crate adds Tokio stream adapters above it.

extern crate alloc;

use alloc::string::String;

/// Minimal definite-length CBOR shared by firmware and host implementations,
/// with `minicbor`-compatible method names where signatures agree.
pub mod cbor;

/// Passive, compile-time component and method descriptors (`ComponentSpec`, `MethodSpec`).
pub mod component;

/// Borrowed single-pass request/response envelope codec (`Record`, `Envelope`, `Name`,
/// and `decode_envelope_prefix`).
pub mod envelope;

/// Zero-copy packet pool traits (`PoolPacket`, `PacketPool`), capacity policy (`PacketPoolPolicy`),
/// and pool implementations (`StaticPacketPool`, `HeapPacketPool`, `XipLazyPool`).
pub mod pool;

/// Zero-copy packet-borrow stream primitives (`RxStreamChunk`, `RxOutcome`, `TxStreamData`,
/// and `PacketStreamHandler`).
pub mod stream;

pub use component::{ComponentSpec, MethodExecution, MethodSpec, find_component, resolve_method};

pub use envelope::{
    DevicePrefixDecode, DeviceRecord, Envelope, MAX_ENVELOPE_BYTES, Name, PrefixDecode, Record,
    decode, decode_any, decode_device, decode_device_envelope_prefix, decode_device_prefix,
    decode_envelope_prefix, decode_prefix, destination, encode_error_header,
    encode_numeric_data_response, encode_numeric_empty_request, encode_numeric_error,
    encode_numeric_response,
};
pub use pool::{
    DEFAULT_HEADROOM, DEFAULT_MAX_PAYLOAD, DEFAULT_SLOT_SIZE, DEFAULT_TAIL, PacketPool,
    PacketPoolPolicy, PoolError, PoolPacket,
};
#[cfg(any(feature = "std", feature = "host-pools", test))]
pub use pool::{
    HEAP_PACKET_SLOT_OVERHEAD, HeapPacketAllocator, HeapPacketLease, HeapPacketPool,
    HeapPacketPoolError, SlabPacket, SlabPool, StaticPacketLease, StaticPacketPool, XipLazyPacket,
    XipLazyPool, XipPacketRef,
};
pub use stream::{PacketStreamHandler, RxOutcome, RxStreamChunk, TxStreamData};

/// Generated numeric wire identity for the `mesh-init` control surface
/// (component/method and by-method field tags).
///
/// The constants are the stable wire identities documented in
/// `crates/mesh-init/API.md`; `mesh-api-gen --api crates/mesh-init/API.md`
/// regenerates this module. Host and peer implementations that speak the
/// mesh-init control protocol directly (its own seqpacket decoder, and
/// sibling clients such as the ssh-mesh terminal delegation bridge) build
/// records against these constants instead of translating through the
/// loaded public catalog. The generated catalog file stays the shared
/// source of truth for regenerating both sides.
pub mod mesh_init_ids;

/// Logical peer identity and an optional one-call egress-path request.
///
/// `node` keys one reusable peer association. `path` selects a particular
/// verified bearer path for one call without creating another association.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MeshTarget {
    pub node: String,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub path: Option<String>,
}

impl MeshTarget {
    pub fn node(node: impl Into<String>) -> Self {
        Self {
            node: node.into(),
            path: None,
        }
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }
}

/// Minimal association boundary available to frame adapters.
///
/// The adapter supplies an opaque path token and complete packet bytes. It
/// must not inspect CIDs, packet numbers, stream IDs, or handler payloads.
/// Association implementations retain those internals and choose the return
/// path from the latest accepted packet.
pub trait MeshAssociation {
    type Error;
    type Path: Copy;

    /// Path selected explicitly for the next outbound operation, if any.
    /// This is the portable representation of a `to` path override; it must
    /// not create a new association or discard the peer identity.
    fn selected_path(&self) -> Option<Self::Path>;
    fn active_path(&self) -> Option<Self::Path>;
    /// Recently verified paths retained by the association. Implementations
    /// keep this bounded; order is newest first and `None` marks unused
    /// capacity. A caller may render these as UART/NOW/UDP, but it must not
    /// infer packet, CID, or transport state from the token.
    fn known_paths(&self) -> [Option<Self::Path>; 4];
    fn select_path(&mut self, path: Self::Path);
    fn clear_selected_path(&mut self);
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::MeshTarget;

    #[test]
    fn target_keeps_node_identity_when_path_is_selected() {
        let target = MeshTarget::node("e7").with_path("udp://[fe80::1%br-lan]");
        assert_eq!(target.node, "e7");
        assert_eq!(target.path.as_deref(), Some("udp://[fe80::1%br-lan]"));
    }
}
