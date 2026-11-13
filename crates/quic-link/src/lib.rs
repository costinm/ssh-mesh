//! `#![no_std]` QUIC packet/association layer (`quic-link`) supporting heterogeneous multi-link
//! scheduling, per-link congestion control (`FlowControlled`, `NewRenoPaced`, `Radio` without L2 ACKs),
//! Selective ACKs (`0x02`), RFC 9221 unreliable `DATAGRAM`s (`0x30`/`0x31`), `QuicMux` integration
//! via [`quic_base::AssociationEgress`], and standalone single-stream UDP/radio endpoints.

#![no_std]
#![deny(missing_docs)]

extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

/// Key-value map used for link and stream-affinity tables in `quic-link` (`BTreeMap` when the
/// `btree` feature is enabled, or a compact sorted `Vec` on embedded targets by default).
#[cfg(feature = "btree")]
pub type LinkMap<K, V> = alloc::collections::BTreeMap<K, V>;

/// Key-value map used for link and stream-affinity tables in `quic-link` (compact sorted `Vec`
/// by default on embedded targets; enable the `btree` feature for `BTreeMap`).
#[cfg(not(feature = "btree"))]
#[derive(Clone, Debug)]
pub struct LinkMap<K, V>(alloc::vec::Vec<(K, V)>);

#[cfg(not(feature = "btree"))]
impl<K, V> Default for LinkMap<K, V> {
    #[inline]
    fn default() -> Self {
        Self(alloc::vec::Vec::new())
    }
}

#[cfg(not(feature = "btree"))]
impl<K: Ord, V> LinkMap<K, V> {
    /// Create an empty `LinkMap`.
    #[inline]
    pub const fn new() -> Self {
        Self(alloc::vec::Vec::new())
    }

    /// Look up a reference to the value for `key`.
    #[inline]
    pub fn get(&self, key: &K) -> Option<&V> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Look up a mutable reference to the value for `key`.
    #[inline]
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.0.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Insert or replace `(key, value)` in sorted key order.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let mut idx = 0;
        while idx < self.0.len() {
            if self.0[idx].0 == key {
                return Some(core::mem::replace(&mut self.0[idx].1, value));
            }
            if self.0[idx].0 > key {
                break;
            }
            idx += 1;
        }
        self.0.insert(idx, (key, value));
        None
    }

    /// Remove `key` and return its value if present.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let idx = self.0.iter().position(|(k, _)| k == key)?;
        Some(self.0.remove(idx).1)
    }

    /// Retain only entries satisfying `f`.
    #[inline]
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        self.0.retain_mut(|(k, v)| f(&*k, v));
    }

    /// Iterate over `(&K, &V)` pairs.
    #[inline]
    pub fn iter(&self) -> core::iter::Map<core::slice::Iter<'_, (K, V)>, fn(&(K, V)) -> (&K, &V)> {
        self.0.iter().map(|(k, v)| (k, v))
    }

    /// Iterate over `&V` values.
    #[inline]
    pub fn values(&self) -> core::iter::Map<core::slice::Iter<'_, (K, V)>, fn(&(K, V)) -> &V> {
        self.0.iter().map(|(_, v)| v)
    }
}

#[cfg(not(feature = "btree"))]
impl<K: Ord, V> core::ops::Index<&K> for LinkMap<K, V> {
    type Output = V;

    #[inline]
    fn index(&self, key: &K) -> &Self::Output {
        self.get(key).expect("LinkMap key not found")
    }
}

#[cfg(not(feature = "btree"))]
impl<K, V> IntoIterator for LinkMap<K, V> {
    type Item = (K, V);
    type IntoIter = alloc::vec::IntoIter<(K, V)>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(not(feature = "btree"))]
impl<'a, K, V> IntoIterator for &'a LinkMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter =
        core::iter::Map<core::slice::Iter<'a, (K, V)>, fn(&'a (K, V)) -> (&'a K, &'a V)>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter().map(|(k, v)| (k, v))
    }
}

#[cfg(not(feature = "btree"))]
impl<'a, K, V> IntoIterator for &'a mut LinkMap<K, V> {
    type Item = (&'a K, &'a mut V);
    type IntoIter =
        core::iter::Map<core::slice::IterMut<'a, (K, V)>, fn(&'a mut (K, V)) -> (&'a K, &'a mut V)>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut().map(|(k, v)| (&*k, v))
    }
}

pub use quic_base::{flow, header as wire, link, pool, streams, wire::StreamId};

pub mod assoc;
pub mod congestion;
pub mod datagram;
pub mod reset;
pub mod sack;
pub mod sim;
pub mod transport_path;
#[cfg(feature = "tokio")]
pub mod udp;

pub use assoc::{
    AssocConfig, DemuxOutcome, LinkRecvError, OutboundLinkPacket, QuicLinkAssoc,
    SingleStreamCallbacks, SingleStreamConfig, SingleStreamEndpoint,
};
pub use congestion::{
    CongestionController, CongestionMode, LinkFraming, LinkId, LinkProfile, LinkState, LinkStats,
    LinkTxOutcome, PacingConfig, RttEstimator,
};
pub use datagram::{DatagramConfig, DatagramSendError, prepend_datagram_frame_in_place};
#[cfg(all(feature = "std", feature = "stateless-reset"))]
pub use reset::{
    StatelessResetKey, stateless_reset_key_from_environment, stateless_reset_key_from_private_file,
};
pub use reset::{
    STATELESS_RESET_MIN_PACKET_LEN, STATELESS_RESET_TOKEN_LEN, StatelessResetToken,
};
pub use sack::{AckProcessOutcome, LinkRetransmitCandidate, MultiLinkSackLedger};
pub use transport_path::{
    EgressPolicy, PacketPath, PathBindingTable, PeerPathHandle, TransportId, TransportMask,
};
#[cfg(feature = "tokio")]
pub use udp::{
    HOST_UDP_SOCKET_BUFFER_BYTES, TokioUdpLink, UdpSocketConfig, parse_udp_peer,
    spawn_udp_assoc_packet_link, spawn_udp_packet_link, wildcard_bind,
};
pub use wire::{
    ACK_RANGE_CAPACITY, AckFrequencyFrame, AckRangeSet, AckRanges, ConnectionId, FRAME_ACK,
    FRAME_ACK_FREQUENCY, FRAME_DATAGRAM, FRAME_DATAGRAM_LEN, FRAME_PADDING, FRAME_PING, LinkFrame,
    PacketAckRange, ShortHeader, ShortHeaderPrefix, decode_ack_frame_body,
    encode_ack_frequency_frame, encode_ack_frame, encode_datagram_header, packet_number_len,
    plan_short_header_stream_packet,
};

#[cfg(test)]
mod tests;
