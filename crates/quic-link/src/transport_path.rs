//! Common packet-path metadata and egress policy for bearer adapters.
//!
//! This sits below application services and above platform framing. UART PPP,
//! ESP-NOW action frames, raw UDP6, FSK, and LoRa each decode into the same
//! path facts. A connection may prefer its ingress path for a reply, while a
//! multipath scheduler may select any eligible live bearer.

/// Non-zero opaque local-link path handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct PeerPathHandle(core::num::NonZeroU64);

impl PeerPathHandle {
    /// Construct a [`PeerPathHandle`] from a non-zero `u64`.
    pub const fn new(raw: u64) -> Option<Self> {
        match core::num::NonZeroU64::new(raw) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// Return the underlying non-zero `u64`.
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Stable platform-neutral bearer identifier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
pub struct TransportId(pub u8);

impl TransportId {
    /// IPv6 UDP bearer (`1`).
    pub const UDP6: Self = Self(1);
    /// ESP-NOW bearer (`2`).
    pub const NOW: Self = Self(2);
    /// Serial UART/PPP bearer (`3`).
    pub const UART: Self = Self(3);
    /// Wi-Fi Aware / NAN bearer (`4`).
    pub const NAN: Self = Self(4);
    /// Sub-GHz FSK bearer (`5`).
    pub const FSK: Self = Self(5);
    /// LoRa radio bearer (`6`).
    pub const LORA: Self = Self(6);
    /// Bluetooth Low Energy bearer (`7`).
    pub const BLE: Self = Self(7);

    /// Bit used by [`TransportMask`].
    pub const fn mask_bit(self) -> u32 {
        if self.0 == 0 || self.0 > 32 {
            0
        } else {
            1_u32 << (self.0 - 1)
        }
    }
}

/// Bitmask of bearers eligible for one egress frame.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct TransportMask(pub u32);

impl TransportMask {
    /// Empty bearer mask.
    pub const NONE: Self = Self(0);

    /// Single-bearer mask containing only `transport`.
    pub const fn only(transport: TransportId) -> Self {
        Self(transport.mask_bit())
    }

    /// Check whether `transport` is present in this mask.
    pub const fn contains(self, transport: TransportId) -> bool {
        self.0 & transport.mask_bit() != 0
    }

    /// Bitwise union of two bearer masks.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Packet provenance retained after an adapter has released its native frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketPath {
    /// Ingress bearer identifier.
    pub ingress: TransportId,
    /// Stable local-link peer MAC/identity when known.
    pub peer: [u8; 6],
    /// Platform-owned link hint (for example STA/AP interface index).
    pub link_hint: u8,
}

/// Fixed-capacity mapping between a platform address `K` and an opaque [`PeerPathHandle`].
pub struct PathBindingTable<K, const N: usize> {
    entries: [Option<(PeerPathHandle, K)>; N],
    next: u64,
}

impl<K: Copy + Eq, const N: usize> PathBindingTable<K, N> {
    /// Create an empty [`PathBindingTable`] starting handle allocation at `first_path_value`.
    pub const fn new(first_path_value: u64) -> Self {
        Self {
            entries: [None; N],
            next: first_path_value,
        }
    }

    /// Return the stable handle for an exact address, allocating one empty
    /// slot when first observed.
    pub fn bind(&mut self, key: K) -> Option<PeerPathHandle> {
        if let Some((path, _)) = self
            .entries
            .iter()
            .flatten()
            .find(|(_, known)| *known == key)
        {
            return Some(*path);
        }
        let slot = self.entries.iter().position(Option::is_none)?;
        let path = loop {
            let candidate = PeerPathHandle::new(self.next)?;
            self.next = self.next.checked_add(1)?;
            if !self
                .entries
                .iter()
                .flatten()
                .any(|(known, _)| *known == candidate)
            {
                break candidate;
            }
        };
        self.entries[slot] = Some((path, key));
        Some(path)
    }

    /// Look up the platform address associated with `path`.
    pub fn get(&self, path: PeerPathHandle) -> Option<K> {
        self.entries
            .iter()
            .flatten()
            .find_map(|(known, key)| (*known == path).then_some(*key))
    }

    /// Resolve an already observed return address without allocating a binding.
    pub fn find(&self, matches: impl Fn(&K) -> bool) -> Option<PeerPathHandle> {
        self.entries
            .iter()
            .flatten()
            .find_map(|(path, key)| matches(key).then_some(*path))
    }

    /// Remove `path` from the table.
    pub fn remove(&mut self, path: PeerPathHandle) -> bool {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_some_and(|(known, _)| known == path))
        else {
            return false;
        };
        *entry = None;
        true
    }

    /// Reclaim one platform binding only after its connection owner confirms
    /// the opaque path is no longer live.
    pub fn reclaim_one(&mut self, reclaimable: impl Fn(PeerPathHandle) -> bool) -> bool {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|(path, _)| reclaimable(*path)))
        else {
            return false;
        };
        *entry = None;
        true
    }
}

/// Policy supplied with a queued outbound frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EgressPolicy {
    /// Preferred bearer when available.
    pub preferred: TransportId,
    /// Eligible fallback bearers.
    pub eligible: TransportMask,
}

impl EgressPolicy {
    /// Construct a reply policy pinned to `path.ingress`.
    pub const fn reply(path: PacketPath) -> Self {
        Self {
            preferred: path.ingress,
            eligible: TransportMask::only(path.ingress),
        }
    }

    /// Pick the preferred bearer when it is live; otherwise choose the first
    /// live eligible bearer.
    pub const fn select(self, available: TransportMask) -> Option<TransportId> {
        if self.eligible.contains(self.preferred) && available.contains(self.preferred) {
            return Some(self.preferred);
        }
        let eligible = self.eligible.0 & available.0;
        if eligible == 0 {
            return None;
        }
        Some(TransportId(eligible.trailing_zeros() as u8 + 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_stays_on_ingress_until_policy_expands_it() {
        let path = PacketPath {
            ingress: TransportId::NOW,
            peer: [1; 6],
            link_hint: 0,
        };
        let policy = EgressPolicy::reply(path);
        let available =
            TransportMask::only(TransportId::NOW).union(TransportMask::only(TransportId::UART));
        assert_eq!(policy.select(available), Some(TransportId::NOW));
    }

    #[test]
    fn multipath_policy_falls_back_without_losing_preference() {
        let policy = EgressPolicy {
            preferred: TransportId::NOW,
            eligible: TransportMask::only(TransportId::NOW)
                .union(TransportMask::only(TransportId::UDP6))
                .union(TransportMask::only(TransportId::UART)),
        };
        assert_eq!(
            policy.select(TransportMask::only(TransportId::UDP6)),
            Some(TransportId::UDP6)
        );
    }

    #[test]
    fn exact_path_bindings_do_not_alias_two_udp_ports_on_one_peer() {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        struct UdpPeer {
            ip: [u8; 16],
            port: u16,
            mac: [u8; 6],
        }
        let first = UdpPeer {
            ip: [1; 16],
            port: 3337,
            mac: [2; 6],
        };
        let second = UdpPeer {
            port: 49152,
            ..first
        };
        let mut bindings = PathBindingTable::<UdpPeer, 2>::new(0x1_0000_0000_0001);
        let first_path = bindings.bind(first).unwrap();
        let second_path = bindings.bind(second).unwrap();
        assert_ne!(first_path, second_path);
        assert_eq!(bindings.bind(first), Some(first_path));
        assert_eq!(bindings.get(first_path), Some(first));
        assert_eq!(bindings.get(second_path), Some(second));
        assert_eq!(
            bindings.find(|peer| peer.ip == second.ip && peer.port == second.port),
            Some(second_path)
        );
        assert_eq!(
            bindings.find(|peer| peer.ip == first.ip && peer.port == first.port),
            Some(first_path)
        );
        assert_eq!(bindings.find(|peer| peer.port == 12345), None);
        assert!(bindings.remove(first_path));
        assert_eq!(bindings.get(first_path), None);
        assert_eq!(bindings.find(|peer| peer.port == first.port), None);
    }

    #[test]
    fn full_path_table_reclaims_only_connection_confirmed_inactive_binding() {
        let mut bindings = PathBindingTable::<u16, 2>::new(10);
        let live = bindings.bind(3337).unwrap();
        let stale = bindings.bind(49152).unwrap();
        assert_eq!(bindings.bind(49153), None);
        assert!(!bindings.reclaim_one(|_| false));
        assert_eq!(bindings.get(live), Some(3337));
        assert_eq!(bindings.get(stale), Some(49152));

        assert!(bindings.reclaim_one(|path| path == stale));
        let replacement = bindings.bind(49153).unwrap();
        assert_ne!(replacement, live);
        assert_ne!(replacement, stale);
        assert_eq!(bindings.get(live), Some(3337));
        assert_eq!(bindings.get(replacement), Some(49153));
    }
}
