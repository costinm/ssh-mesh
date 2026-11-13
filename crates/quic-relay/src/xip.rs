//! ESP-XIP compatible QUIC header classification, weighted multi-hop relay table,
//! zero-copy short-header DCID rewriting, terminal circuit encapsulation, and
//! CBOR reply bookkeeping.
//!
//! Mirrors `components/xip_runtime/src/xip_quic.c` (`include/xip_quic.h`) and
//! `xip-abi::quic` (`RelayHop`, `RelayRoute`, `RelayStats`) 100% in `#![no_std]` Rust.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cmp::Ordering;
use quic_base::PoolPacket;

/// Maximum forwarded QUIC packet size (`1500 - 48 (IPv6 + UDP) - 4 = 1448` bytes),
/// matching `XIP_QUIC_MAX_PACKET`.
pub const MAX_PACKET: usize = 1448;

/// Maximum connection ID length kept in relay tables (`20` bytes, RFC 9000),
/// matching `XIP_QUIC_CID_MAX`.
pub const CID_MAX: usize = 20;

/// Maximum entries in a runtime relay table (`64`), matching `XIP_QUIC_TABLE_MAX`.
pub const TABLE_MAX: usize = 64;

/// DMesh QUIC long-header version (`0x444d_0001`), matching `XIP_QUIC_VERSION_DMESH`.
pub const VERSION_DMESH: u32 = 0x444d_0001;

/// CBOR datagram long-header version (`0x444d_0002`), matching `XIP_QUIC_VERSION_CBOR`.
pub const VERSION_CBOR: u32 = 0x444d_0002;

/// Reply note retention window in milliseconds (`5000` ms), matching `XIP_QUIC_REPLY_MS`.
pub const REPLY_MS: u64 = 5000;

/// Capacity of the CBOR datagram reply table (`8` slots), matching `XIP_QUIC_REPLIES`.
pub const REPLIES: usize = 8;

/// Host-scale default maximum entries in an [`XipRelayTable`] (`16,384` routes).
pub const HOST_TABLE_MAX: usize = 16_384;

/// Host-scale default capacity of the CBOR datagram [`ReplyTable`] (`2,048` slots).
pub const HOST_REPLIES: usize = 2_048;

/// Host-scale default CBOR reply retention window in milliseconds (`15,000` ms).
pub const HOST_REPLY_MS: u64 = 15_000;

/// Configurable capacity and timeout parameters for [`XipRelayTable`] and [`ReplyTable`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XipRelayConfig {
    /// Maximum DCID entries in [`XipRelayTable`] (`64` on embedded C runtime, `16,384` on host).
    pub max_entries: usize,
    /// Maximum concurrent CBOR reply notes in [`ReplyTable`] (`8` on embedded, `2,048` on host).
    pub max_replies: usize,
    /// Retention window in milliseconds for [`ReplyTable`] notes (`5,000` ms on embedded, `15,000` ms on host).
    pub reply_timeout_ms: u64,
    /// Maximum forwarded QUIC packet size (`1,448` bytes).
    pub max_packet_size: usize,
}

impl XipRelayConfig {
    /// Embedded / ESP-XIP C-simulator defaults (`64` routes, `8` replies, `5,000` ms timeout, `1,448` MTU).
    pub const fn embedded() -> Self {
        Self {
            max_entries: TABLE_MAX,
            max_replies: REPLIES,
            reply_timeout_ms: REPLY_MS,
            max_packet_size: MAX_PACKET,
        }
    }

    /// Host-scale defaults (`16,384` routes, `2,048` replies, `15,000` ms timeout, `1,448` MTU).
    pub const fn host() -> Self {
        Self {
            max_entries: HOST_TABLE_MAX,
            max_replies: HOST_REPLIES,
            reply_timeout_ms: HOST_REPLY_MS,
            max_packet_size: MAX_PACKET,
        }
    }
}

impl Default for XipRelayConfig {
    fn default() -> Self {
        Self::embedded()
    }
}

/// Success return code (`0`), matching `XIP_OK`.
pub const OK: i32 = 0;
/// Invalid argument error (`-1`), matching `XIP_ERR_ARG`.
pub const ERR_ARG: i32 = -1;
/// Resource busy / owned by another component (`-5`), matching `XIP_ERR_BUSY`.
pub const ERR_BUSY: i32 = -5;
/// Out of memory / table full (`-6`), matching `XIP_ERR_NOMEM`.
pub const ERR_NOMEM: i32 = -6;
/// Route or entry not found (`-7`), matching `XIP_ERR_NOTFOUND`.
pub const ERR_NOTFOUND: i32 = -7;
/// Packet or buffer size exceeded (`-8`), matching `XIP_ERR_SIZE`.
pub const ERR_SIZE: i32 = -8;

/// Classification of the first bytes of a frame (`xip_quic_class` in `xip_quic.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuicClass {
    /// Empty, or the fixed bit (`0x40`) is clear: not a QUIC packet.
    NotQuic,
    /// Looks like QUIC (`0x40` set) but the header is truncated or a length is invalid.
    Malformed,
    /// Short-header QUIC packet (`0x80` clear, `0x40` set).
    Short,
    /// Long-header QUIC packet (`0xc0` set, RFC 8999 invariants).
    Long,
}

/// Parsed outer QUIC header fields (`xip_quic_hdr` in `xip_quic.h`).
///
/// For a long packet, `body` is the byte offset immediately after the SCID.
/// For a short packet, `body` is the byte offset immediately after the DCID
/// (where the packet number begins).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QuicHeader {
    /// First byte (`flags`) of the packet.
    pub first: u8,
    /// `true` if long header (`first & 0x80 != 0`).
    pub is_long: bool,
    /// 32-bit version field (non-zero only for long headers).
    pub version: u32,
    /// Destination connection ID bytes (`1..=20` for short headers, `0..=20` for long headers).
    pub dcid: Vec<u8>,
    /// Source connection ID bytes (empty for short headers, `0..=20` for long headers).
    pub scid: Vec<u8>,
    /// Offset of the payload/packet-number body following the CIDs.
    pub body: usize,
}

/// One weighted egress alternative in a [`RelayRoute`] (`xip_relay_hop` in `xip.h`, 64 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayHop {
    /// Link-specific opaque peer token (MACs use `mac_token`).
    pub token: u64,
    /// Outgoing link address/handle (`!= 0`).
    pub link: u32,
    /// Relative round-robin weight (`0` disables this alternative; sum across hops must be `> 0`).
    pub weight: u16,
    /// Length of `rewritten_dcid` (`1..=20`).
    pub cid_len: u8,
    /// `0` uses `token`; `22` is IPv6 (or IPv4-mapped), big-endian port, and 4-byte scope.
    pub address_len: u8,
    /// Outbound DCID written before forwarding on this hop.
    pub rewritten_dcid: [u8; 20],
    /// Reserved zero padding (`[0; 4]`).
    pub padding: [u8; 4],
    /// Optional 22-byte socket address (padded to 24 bytes with trailing zeros).
    pub address: [u8; 24],
}

/// Multi-hop weighted forwarding route (`xip_relay_route` in `xip.h`, 280 bytes).
///
/// At most four egress alternatives (`hops[..hop_count]`). Zero weights disable an alternative;
/// at least one weight must be positive. Selection is weighted round-robin per packet.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayRoute {
    /// Up to 4 weighted egress hops.
    pub hops: [RelayHop; 4],
    /// Local destination connection ID matched on ingress (`dcid[..dcid_len]`).
    pub dcid: [u8; 20],
    /// Length of `dcid` (`1..=20`, or `0` when requesting allocation via `relay_create`).
    pub dcid_len: u8,
    /// Number of active hops in `hops` (`1..=4`).
    pub hop_count: u8,
    /// `1` terminates an opaque short-header circuit (decapsulating/encapsulating the outer
    /// `0x40 | dcid | pn=0` wrapper); `0` performs intermediate DCID rewrite forwarding.
    pub endpoint: u8,
    /// Reserved byte (must be `0`).
    pub reserved: u8,
}

/// Monotonic local activity observation for a managed relay route (`xip_relay_stats` in `xip.h`, 16 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayStats {
    /// Timestamp (in microseconds) when this route last forwarded a packet.
    /// Configuration reads never refresh `last_used_us`.
    pub last_used_us: u64,
    /// Inactivity timeout in milliseconds (`0` disables inactivity expiry).
    pub idle_ms: u32,
    /// Reserved field (must be `0`).
    pub reserved: u32,
}

const _: () = assert!(core::mem::size_of::<RelayHop>() == 64);
const _: () = assert!(core::mem::size_of::<RelayRoute>() == 280);
const _: () = assert!(core::mem::size_of::<RelayStats>() == 16);

/// Target kind of an entry in the runtime DCID table (`xip_quic_kind` in `xip_quic.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuicKind {
    /// Terminated locally: short packets go to the local QUIC stack callback/module.
    Local,
    /// Forwarded: short packets go to `egress` and peer `token` with DCID rewritten to `out_cid`.
    Relay,
}

/// One entry in the XIP QUIC DCID table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuicEntry {
    /// Timestamp (microseconds) when this route was last selected by a packet.
    pub last_used_us: u64,
    /// Inactivity timeout in milliseconds (`0` = never expires).
    pub idle_ms: u32,
    /// Module-managed route state: `(owner_id, route, weighted_rr_cursor)`.
    pub managed: Option<(usize, RelayRoute, u32)>,
    /// Whether this entry terminates locally or forwards to another hop.
    pub kind: QuicKind,
    /// Selected egress link handle.
    pub egress: u32,
    /// Selected peer token on `egress`.
    pub token: u64,
    /// Selected outbound DCID bytes (`1..=20`).
    pub out_cid: Vec<u8>,
    /// Selected optional socket address (`0` or `22` bytes).
    pub address: Vec<u8>,
}

/// Diagnostic counters for the common QUIC classifier and relay (`xip_quic_stats` in C runtime).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QuicStats {
    /// Total frames offered to the QUIC classifier.
    pub rx: u32,
    /// Frames declined because the fixed bit (`0x40`) was clear or the packet was empty.
    pub declined: u32,
    /// Frames dropped because the QUIC header was truncated or invalid.
    pub malformed: u32,
    /// Frames dropped because their length exceeded [`MAX_PACKET`] (`1448`).
    pub oversize: u32,
    /// Short-header packets delivered to the local endpoint callback.
    pub short_local: u32,
    /// Short-header packets rewritten and forwarded through a relay entry.
    pub short_relay: u32,
    /// Short-header relay packets whose rewrite or egress link transmit failed.
    pub short_relay_failed: u32,
    /// Short-header packets whose DCID was not found in the table and not claimed by a module.
    pub short_unknown: u32,
    /// Short-header packets matching a [`QuicKind::Local`] entry when no local handler is attached.
    pub short_no_handler: u32,
    /// Long-header `VERSION_CBOR` (`0x444d_0002`) request envelopes delivered to a target module.
    pub long_cbor: u32,
    /// Long-header `VERSION_CBOR` packets with a missing or invalid CBOR routing envelope.
    pub long_cbor_bad: u32,
    /// Long-header `VERSION_CBOR` requests whose target component was not found or whose inbox was full.
    pub long_cbor_no_target: u32,
    /// Long-header `VERSION_CBOR` response envelopes (carrying field `6` or `7`) delivered locally.
    pub long_cbor_response: u32,
    /// Long-header packets with versions other than `VERSION_CBOR` delivered to the local callback.
    pub long_other: u32,
    /// Long-header packets with versions other than `VERSION_CBOR` dropped because no handler is attached.
    pub long_other_dropped: u32,
}

/// Length of a compact DMesh/quic-lite connection ID from its first byte
/// (`bit 7 == 0 -> 1`; bits `7..5` in `100, 101, 110 -> 2, 4, 8`; `111 -> 0` reserved).
#[inline]
pub const fn cid_class_len(first: u8) -> usize {
    if first & 0x80 == 0 {
        return 1;
    }
    match (first >> 5) & 3 {
        0 => 2,
        1 => 4,
        2 => 8,
        _ => 0,
    }
}

/// Encode `value` (`1 ..= (1 << 61) - 1`) into a compact connection ID (`1`, `2`, `4`, or `8` bytes).
///
/// Returns `None` if `value == 0` or `value >= (1 << 61)`.
pub fn cid_encode(value: u64) -> Option<Vec<u8>> {
    if value == 0 || value >= (1u64 << 61) {
        return None;
    }
    let cid = quic_base::ConnectionId::new(value)?;
    let mut buf = [0u8; 8];
    let n = cid.encode(&mut buf).ok()?;
    Some(buf[..n].to_vec())
}

/// Classify `p` into [`QuicClass`] and extract its [`QuicHeader`] (`xip_quic_classify`).
///
/// `short_cid_len`: `0` uses the compact CID class rule ([`cid_class_len`]); non-zero overrides
/// the short-header DCID length to that fixed number of bytes.
pub fn classify(p: &[u8], short_cid_len: usize) -> (QuicClass, QuicHeader) {
    let mut h = QuicHeader::default();
    if p.is_empty() || p[0] & 0x40 == 0 {
        return (QuicClass::NotQuic, h);
    }
    h.first = p[0];
    if p[0] & 0x80 == 0 {
        let n = if short_cid_len != 0 {
            short_cid_len
        } else if p.len() > 1 {
            cid_class_len(p[1])
        } else {
            0
        };
        let pn = (p[0] & 3) as usize + 1;
        if n == 0 || n > CID_MAX || p.len() < 1 + n + pn {
            return (QuicClass::Malformed, h);
        }
        h.dcid = p[1..1 + n].to_vec();
        h.body = 1 + n;
        return (QuicClass::Short, h);
    }
    // RFC 8999 invariants: first byte, 4-byte version, DCID length + DCID, SCID length + SCID.
    if p.len() < 7 {
        return (QuicClass::Malformed, h);
    }
    h.is_long = true;
    h.version = u32::from_be_bytes([p[1], p[2], p[3], p[4]]);
    let dl = p[5] as usize;
    if dl > CID_MAX || p.len() < 6 + dl + 1 {
        return (QuicClass::Malformed, h);
    }
    h.dcid = p[6..6 + dl].to_vec();
    let sl = p[6 + dl] as usize;
    let at = 7 + dl;
    if sl > CID_MAX || p.len() < at + sl {
        return (QuicClass::Malformed, h);
    }
    h.scid = p[at..at + sl].to_vec();
    h.body = at + sl;
    (QuicClass::Long, h)
}

/// Build a long header (`0xc0 | version | dcid_len | dcid | scid_len | scid`), matching `xip_quic_long_build`.
pub fn long_build(version: u32, dcid: &[u8], scid: &[u8]) -> Option<Vec<u8>> {
    if dcid.len() > CID_MAX || scid.len() > CID_MAX {
        return None;
    }
    let mut v = Vec::with_capacity(7 + dcid.len() + scid.len());
    v.push(0xc0);
    v.extend_from_slice(&version.to_be_bytes());
    v.push(dcid.len() as u8);
    v.extend_from_slice(dcid);
    v.push(scid.len() as u8);
    v.extend_from_slice(scid);
    Some(v)
}

/// Replace the DCID of the short packet at `p` (length `len`, classified as `h`) with `ncid`
/// in-place without moving the packet number or payload (`xip_quic_short_rewrite`).
///
/// Writes the flags byte and `ncid` right before the packet number at `p.offset(d)`, where
/// `d = h.dcid.len() as isize - ncid.len() as isize`. Negative `d` grows earlier into `room`
/// bytes of headroom.
///
/// # Safety
/// `p` must point to `len` readable and writable bytes with at least `room` writable bytes
/// immediately before `p`.
pub unsafe fn short_rewrite(
    p: *mut u8,
    len: usize,
    h: &QuicHeader,
    ncid: &[u8],
    room: usize,
) -> Result<isize, i32> {
    if h.is_long || ncid.is_empty() || ncid.len() > CID_MAX {
        return Err(ERR_ARG);
    }
    let d = h.dcid.len() as isize - ncid.len() as isize;
    if (d < 0 && (-d) as usize > room) || (len as isize - d) as usize > MAX_PACKET {
        return Err(ERR_SIZE);
    }
    let q = unsafe { p.offset(d) };
    unsafe {
        *q = h.first;
        core::ptr::copy(ncid.as_ptr(), q.add(1), ncid.len());
    }
    Ok(d)
}

/// Zero-copy in-place short-header DCID rewrite on any [`PoolPacket`] (`StaticPacketPool`,
/// `HeapPacketPool`, or `XipLazyPool`).
///
/// Only the flags byte and DCID bytes are written; the packet number and encrypted body stay at
/// their exact slot offsets.
pub fn short_rewrite_packet<P: PoolPacket>(
    packet: &mut P,
    h: &QuicHeader,
    ncid: &[u8],
    min_headroom: usize,
) -> Result<(), i32> {
    if h.is_long || ncid.is_empty() || ncid.len() > CID_MAX {
        return Err(ERR_ARG);
    }
    let r = packet.range();
    let len = r.len();
    if len < 1 + h.dcid.len() {
        return Err(ERR_ARG);
    }
    let d = h.dcid.len() as isize - ncid.len() as isize;
    let new_start = (r.start as isize) + d;
    if new_start < (min_headroom as isize) {
        return Err(ERR_SIZE);
    }
    let new_start = new_start as usize;
    let new_len = r.end.saturating_sub(new_start);
    if new_len > MAX_PACKET {
        return Err(ERR_SIZE);
    }
    let first = h.first;
    let slot = packet.slot_slice_mut().map_err(|_| ERR_BUSY)?;
    slot[new_start] = first;
    slot[new_start + 1..new_start + 1 + ncid.len()].copy_from_slice(ncid);
    packet.set_range(new_start..r.end).map_err(|_| ERR_SIZE)
}

/// Prepend an outer terminal-circuit short header (`0x40 | out_cid | pn=0`, `out_cid.len() + 2` bytes)
/// onto `packet` in-place.
pub fn prepend_circuit_header<P: PoolPacket>(
    packet: &mut P,
    out_cid: &[u8],
    min_headroom: usize,
) -> Result<(), i32> {
    if out_cid.is_empty() || out_cid.len() > CID_MAX {
        return Err(ERR_ARG);
    }
    let r = packet.range();
    let prefix = out_cid.len() + 2;
    if r.start < min_headroom + prefix || r.len() + prefix > MAX_PACKET {
        return Err(ERR_SIZE);
    }
    let new_start = r.start - prefix;
    let slot = packet.slot_slice_mut().map_err(|_| ERR_BUSY)?;
    slot[new_start] = 0x40;
    slot[new_start + 1..new_start + 1 + out_cid.len()].copy_from_slice(out_cid);
    slot[new_start + prefix - 1] = 0;
    packet.set_range(new_start..r.end).map_err(|_| ERR_SIZE)
}

/// Strip an outer terminal-circuit short header (`1 + dcid.len() + 1` bytes, requiring 1-byte PN
/// `first & 3 == 0`) from `packet` in-place and return the 8-byte little-endian source token.
pub fn strip_circuit_header<P: PoolPacket>(packet: &mut P, h: &QuicHeader) -> Result<u64, i32> {
    if h.is_long || h.dcid.is_empty() || h.dcid.len() > 8 || (h.first & 3) != 0 {
        return Err(ERR_ARG);
    }
    let prefix = h.dcid.len() + 2;
    let r = packet.range();
    if r.len() <= prefix {
        return Err(ERR_SIZE);
    }
    let mut cid = [0u8; 8];
    cid[..h.dcid.len()].copy_from_slice(&h.dcid);
    packet
        .set_range((r.start + prefix)..r.end)
        .map_err(|_| ERR_SIZE)?;
    Ok(u64::from_le_bytes(cid))
}

/// Validate a [`RelayRoute`] according to `xip_quic_relay_set` rules.
pub fn validate_relay_route(r: &RelayRoute) -> Result<(), i32> {
    if r.dcid_len == 0
        || (r.dcid_len as usize) > CID_MAX
        || r.hop_count == 0
        || r.hop_count > 4
        || r.reserved != 0
        || r.endpoint > 1
    {
        return Err(ERR_ARG);
    }
    if r.endpoint != 0
        && (r.dcid_len > 8
            || (r.dcid_len == 1 && r.dcid[0] == 0)
            || cid_class_len(r.dcid[0]) != r.dcid_len as usize)
    {
        return Err(ERR_ARG);
    }
    let mut total = 0u32;
    for h in &r.hops[..r.hop_count as usize] {
        if h.link == 0
            || h.cid_len == 0
            || (h.cid_len as usize) > CID_MAX
            || (h.address_len != 0 && h.address_len != 22)
            || h.padding != [0; 4]
        {
            return Err(ERR_ARG);
        }
        if h.address_len == 22
            && ((h.address[16] == 0 && h.address[17] == 0) || h.address[22..] != [0, 0])
        {
            return Err(ERR_ARG);
        }
        total += u32::from(h.weight);
    }
    if total == 0 {
        return Err(ERR_ARG);
    }
    Ok(())
}

/// Key wrapper that sorts CIDs by `(len, bytes)` just like `xip_quic.c`'s `cmp()`,
/// while allowing borrowed slice lookups via `AsRef<[u8]>`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CidKey(Vec<u8>);

impl PartialOrd for CidKey {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CidKey {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.as_slice().cmp(other.0.as_slice()))
    }
}

/// One recorded CBOR datagram request note (`xip_quic_reply` in `xip_quic.h`),
/// used to wrap the module's response in a `VERSION_CBOR` long header with swapped CIDs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplyNote {
    /// Link handle the request arrived on.
    pub link: u32,
    /// Peer address token on `link`.
    pub source: u64,
    /// Request identifier (CBOR envelope key `3`).
    pub id: u64,
    /// Timestamp (milliseconds) when the request arrived.
    pub at_ms: u64,
    /// Reply DCID (copied from the request's SCID).
    pub dcid: Vec<u8>,
    /// Reply SCID (copied from the request's DCID).
    pub scid: Vec<u8>,
}

/// Configurable-capacity CBOR datagram reply correlation table (`xip_quic_replies`).
///
/// Defaults to the ESP-XIP C-runtime small limits (`REPLIES = 8`, `REPLY_MS = 5000`),
/// and can be scaled via [`Self::with_limits`] or [`Self::set_limits`] on mesh hosts.
#[derive(Clone, Debug)]
pub struct ReplyTable {
    /// Active reply notes (`<= max_replies`).
    pub entries: Vec<ReplyNote>,
    next_slot: usize,
    max_replies: usize,
    reply_timeout_ms: u64,
}

impl Default for ReplyTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplyTable {
    /// Construct an empty [`ReplyTable`] with embedded C-runtime defaults (`REPLIES = 8`, `REPLY_MS = 5000`).
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_slot: 0,
            max_replies: REPLIES,
            reply_timeout_ms: REPLY_MS,
        }
    }

    /// Construct an empty [`ReplyTable`] with explicit `max_replies` and `reply_timeout_ms`.
    pub const fn with_limits(max_replies: usize, reply_timeout_ms: u64) -> Self {
        Self {
            entries: Vec::new(),
            next_slot: 0,
            max_replies: if max_replies == 0 { 1 } else { max_replies },
            reply_timeout_ms: if reply_timeout_ms == 0 {
                REPLY_MS
            } else {
                reply_timeout_ms
            },
        }
    }

    /// Construct a host-scale [`ReplyTable`] (`HOST_REPLIES = 2048`, `HOST_REPLY_MS = 15000`).
    pub const fn host() -> Self {
        Self::with_limits(HOST_REPLIES, HOST_REPLY_MS)
    }

    /// Update `max_replies` and `reply_timeout_ms` at runtime.
    pub fn set_limits(&mut self, max_replies: usize, reply_timeout_ms: u64) {
        self.max_replies = max_replies.max(1);
        self.reply_timeout_ms = if reply_timeout_ms == 0 {
            REPLY_MS
        } else {
            reply_timeout_ms
        };
        if self.entries.len() > self.max_replies {
            self.entries.truncate(self.max_replies);
        }
        self.next_slot %= self.max_replies;
    }

    /// Configured maximum number of concurrent reply notes.
    #[inline]
    pub const fn max_replies(&self) -> usize {
        self.max_replies
    }

    /// Configured reply retention timeout in milliseconds.
    #[inline]
    pub const fn reply_timeout_ms(&self) -> u64 {
        self.reply_timeout_ms
    }

    /// Number of currently stored reply notes.
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the reply table has no stored notes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Record a pending CBOR datagram request so its reply can swap `dcid`/`scid`.
    pub fn note(&mut self, link: u32, source: u64, id: u64, request: &QuicHeader, now_ms: u64) {
        if request.dcid.len() > CID_MAX || request.scid.len() > CID_MAX || self.max_replies == 0 {
            return;
        }
        let r = ReplyNote {
            link,
            source,
            id,
            at_ms: now_ms,
            dcid: request.scid.clone(),
            scid: request.dcid.clone(),
        };
        let timeout_ms = self.reply_timeout_ms;
        let live = |x: &ReplyNote| now_ms.saturating_sub(x.at_ms) <= timeout_ms;
        if let Some(at) = self
            .entries
            .iter()
            .position(|x| x.link == link && x.source == source && x.id == id)
        {
            self.entries[at] = r;
        } else if self.entries.len() < self.max_replies {
            self.entries.push(r);
        } else if let Some(at) = self.entries.iter().position(|x| !live(x)) {
            self.entries[at] = r;
        } else {
            let slot = self.next_slot % self.max_replies;
            self.entries[slot] = r;
            self.next_slot = (slot + 1) % self.max_replies;
        }
    }

    /// Find a live reply note (`now_ms - at_ms <= reply_timeout_ms`) matching `(link, source, id)`.
    pub fn find(&self, link: u32, source: u64, id: u64, now_ms: u64) -> Option<&ReplyNote> {
        let timeout_ms = self.reply_timeout_ms;
        self.entries.iter().find(|r| {
            r.link == link
                && r.source == source
                && r.id == id
                && now_ms.saturating_sub(r.at_ms) <= timeout_ms
        })
    }

    /// Consume/remove a reply note matching `(link, source, id)`.
    pub fn done(&mut self, link: u32, source: u64, id: u64) {
        self.entries
            .retain(|r| !(r.link == link && r.source == source && r.id == id));
    }
}

/// Complete XIP runtime DCID and multi-hop weighted relay table (`xip_quic_table` in `xip_quic.c`).
///
/// Supports both:
/// - Runtime-issued / unmanaged entries (`table_add`, `table_alloc`, `table_remove`), and
/// - Module-owned managed routes (`relay_set`, `relay_get`, `relay_remove`, `relay_create`,
///   `relay_stats`, `relay_expire`, `relay_idle`, `relay_release_owner`, `select`).
///
/// Defaults to `max_entries = TABLE_MAX (64)` for exact ESP-XIP C-runtime validation, and scales
/// to `HOST_TABLE_MAX (16,384)` or higher via [`Self::with_max_entries`] / [`Self::set_max_entries`].
#[derive(Clone, Debug)]
pub struct XipRelayTable {
    entries: BTreeMap<CidKey, QuicEntry>,
    /// Monotonic counter for high-range `(1u64 << 60) | next_relay_cid` CIDs issued by [`Self::relay_create`].
    pub next_relay_cid: u64,
    /// Maximum allowed entries in this table (`64` by default, configurable for host scale).
    max_entries: usize,
    /// Lower bound on the smallest free compact CID value (`>= 1`) for [`Self::table_alloc`].
    lowest_free_cid: u64,
}

impl Default for XipRelayTable {
    fn default() -> Self {
        Self::new()
    }
}

impl XipRelayTable {
    /// Construct an empty [`XipRelayTable`] with the default C-runtime limit (`TABLE_MAX = 64`).
    pub const fn new() -> Self {
        Self::with_max_entries(TABLE_MAX)
    }

    /// Construct an empty [`XipRelayTable`] with an explicit `max_entries` ceiling.
    pub const fn with_max_entries(max_entries: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            next_relay_cid: 0,
            max_entries,
            lowest_free_cid: 1,
        }
    }

    /// Construct a host-scale [`XipRelayTable`] (`HOST_TABLE_MAX = 16,384`).
    pub const fn host() -> Self {
        Self::with_max_entries(HOST_TABLE_MAX)
    }

    /// Configured maximum number of entries in this table.
    #[inline]
    pub const fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Update the maximum number of entries admitted into this table.
    /// Raising the limit takes effect immediately; lowering it never evicts live entries.
    #[inline]
    pub fn set_max_entries(&mut self, max_entries: usize) {
        self.max_entries = max_entries;
    }

    /// Number of entries currently in the table.
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.lowest_free_cid = 1;
    }

    #[inline]
    fn note_removed_cid(&mut self, cid: &[u8]) {
        if let Ok((decoded, used)) = quic_base::ConnectionId::decode(cid)
            && used == cid.len()
            && decoded.value() > 0
            && decoded.value() < self.lowest_free_cid
        {
            self.lowest_free_cid = decoded.value();
        }
    }

    /// Look up an entry by raw `cid` bytes without modifying `last_used_us` or weighted cursor.
    pub fn get(&self, cid: &[u8]) -> Option<&QuicEntry> {
        if cid.is_empty() || cid.len() > CID_MAX {
            return None;
        }
        self.entries.get(&CidKey(cid.to_vec()))
    }

    /// Mutable lookup by raw `cid` bytes.
    pub fn get_mut(&mut self, cid: &[u8]) -> Option<&mut QuicEntry> {
        if cid.is_empty() || cid.len() > CID_MAX {
            return None;
        }
        self.entries.get_mut(&CidKey(cid.to_vec()))
    }

    /// Whether `cid` is present in the table.
    pub fn contains_key(&self, cid: &[u8]) -> bool {
        self.get(cid).is_some()
    }

    /// Iterate over all `(cid_bytes, entry)` pairs in canonical `(len, bytes)` order.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &QuicEntry)> {
        self.entries.iter().map(|(k, v)| (k.0.as_slice(), v))
    }

    /// Iterate over all entries in canonical `(len, bytes)` order.
    pub fn values(&self) -> impl Iterator<Item = &QuicEntry> {
        self.entries.values()
    }

    /// Whether any managed route in the table has `endpoint != 0` (terminal circuit).
    pub fn has_terminal_endpoint(&self) -> bool {
        self.entries
            .values()
            .any(|e| e.managed.as_ref().is_some_and(|(_, r, _)| r.endpoint != 0))
    }

    /// Add or replace an unmanaged runtime table entry (`xip_quic_table_add`).
    pub fn table_add(
        &mut self,
        cid: &[u8],
        kind: QuicKind,
        egress: u32,
        token: u64,
        out_cid: &[u8],
    ) -> i32 {
        if cid.is_empty() || cid.len() > CID_MAX {
            return ERR_ARG;
        }
        let key = CidKey(cid.to_vec());
        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
            return ERR_NOMEM;
        }
        if kind == QuicKind::Relay && (out_cid.is_empty() || out_cid.len() > CID_MAX) {
            return ERR_ARG;
        }
        self.entries.insert(
            key,
            QuicEntry {
                last_used_us: 0,
                idle_ms: 0,
                managed: None,
                kind,
                egress,
                token,
                out_cid: if kind == QuicKind::Relay {
                    out_cid.to_vec()
                } else {
                    Vec::new()
                },
                address: Vec::new(),
            },
        );
        OK
    }

    /// Issue the lowest free compact connection ID (`1` byte for the first 127 entries),
    /// insert the entry, and return the encoded CID (`xip_quic_table_alloc`).
    pub fn table_alloc(
        &mut self,
        kind: QuicKind,
        egress: u32,
        token: u64,
        out_cid: &[u8],
    ) -> Result<Vec<u8>, i32> {
        if self.entries.len() >= self.max_entries {
            return Err(ERR_NOMEM);
        }
        let mut v = self.lowest_free_cid.max(1);
        loop {
            let cid = cid_encode(v).ok_or(ERR_NOMEM)?;
            if !self.contains_key(&cid) {
                let rc = self.table_add(&cid, kind, egress, token, out_cid);
                if rc == OK {
                    self.lowest_free_cid = v.saturating_add(1);
                    return Ok(cid);
                }
                return Err(rc);
            }
            v += 1;
        }
    }

    /// Remove an entry by `cid` (`xip_quic_table_remove`).
    pub fn table_remove(&mut self, cid: &[u8]) -> i32 {
        if cid.is_empty() || cid.len() > CID_MAX {
            return ERR_ARG;
        }
        if self.entries.remove(&CidKey(cid.to_vec())).is_some() {
            self.note_removed_cid(cid);
            OK
        } else {
            ERR_NOTFOUND
        }
    }

    /// Validate whether `route` can be inserted (`mode == 0`) or replaced (`mode == 1`) by `owner`
    /// without mutating the table.
    pub fn relay_can_set(&self, owner: usize, route: &RelayRoute, mode: u32) -> Result<(), i32> {
        if mode > 1 {
            return Err(ERR_ARG);
        }
        validate_relay_route(route)?;
        let cid = &route.dcid[..route.dcid_len as usize];
        let key = CidKey(cid.to_vec());
        if let Some(old) = self.entries.get(&key) {
            if mode == 0 || !old.managed.as_ref().is_some_and(|(o, _, _)| *o == owner) {
                return Err(ERR_BUSY);
            }
        } else if mode == 1 {
            return Err(ERR_NOTFOUND);
        } else if self.entries.len() >= self.max_entries {
            return Err(ERR_NOMEM);
        }
        Ok(())
    }

    /// Atomically create (`mode == 0`) or replace (`mode == 1`) a module-owned [`RelayRoute`]
    /// (`xip_quic_relay_set`).
    pub fn relay_set(&mut self, owner: usize, route: &RelayRoute, mode: u32) -> i32 {
        if let Err(rc) = self.relay_can_set(owner, route, mode) {
            return rc;
        }
        let cid = &route.dcid[..route.dcid_len as usize];
        let key = CidKey(cid.to_vec());
        let h = &route.hops[0];
        let (last_used_us, idle_ms) = self
            .entries
            .get(&key)
            .map_or((0, 0), |e| (e.last_used_us, e.idle_ms));
        self.entries.insert(
            key,
            QuicEntry {
                last_used_us,
                idle_ms,
                managed: Some((owner, *route, 0)),
                kind: QuicKind::Relay,
                egress: h.link,
                token: h.token,
                out_cid: h.rewritten_dcid[..h.cid_len as usize].to_vec(),
                address: Vec::new(),
            },
        );
        OK
    }

    /// Read `owner`'s managed route at `index` in canonical `(len, bytes)` order (`xip_quic_relay_get`).
    pub fn relay_get(&self, owner: usize, index: u32) -> Result<RelayRoute, i32> {
        self.entries
            .values()
            .filter_map(|e| e.managed.as_ref())
            .filter(|(o, _, _)| *o == owner)
            .nth(index as usize)
            .map(|(_, r, _)| *r)
            .ok_or(ERR_NOTFOUND)
    }

    /// Remove a managed route owned by `owner` (`xip_quic_relay_remove`).
    pub fn relay_remove(&mut self, owner: usize, cid: &[u8]) -> i32 {
        if cid.is_empty() || cid.len() > CID_MAX {
            return ERR_ARG;
        }
        let key = CidKey(cid.to_vec());
        let Some(e) = self.entries.get(&key) else {
            return ERR_NOTFOUND;
        };
        if !e.managed.as_ref().is_some_and(|(o, _, _)| *o == owner) {
            return ERR_BUSY;
        }
        self.entries.remove(&key);
        self.note_removed_cid(cid);
        OK
    }

    /// Remove all managed routes belonging to `owner` when the module stops (`xip_quic_relay_release`).
    pub fn relay_release_owner(&mut self, owner: usize) {
        let mut lowest = self.lowest_free_cid;
        self.entries.retain(|k, e| {
            let remove = e.managed.as_ref().is_some_and(|(o, _, _)| *o == owner);
            if remove
                && let Ok((decoded, used)) = quic_base::ConnectionId::decode(&k.0)
                && used == k.0.len()
                && decoded.value() > 0
                && decoded.value() < lowest
            {
                lowest = decoded.value();
            }
            !remove
        });
        self.lowest_free_cid = lowest;
    }

    /// Expire inactive routes owned by `owner` (`None` = all owners) at `now_us` (`xip_quic_relay_expire`).
    ///
    /// Returns the number of expired routes removed.
    pub fn relay_expire(&mut self, owner: Option<usize>, now_us: u64) -> usize {
        let before = self.entries.len();
        let mut lowest = self.lowest_free_cid;
        self.entries.retain(|k, e| {
            let expired = e.managed.as_ref().is_some_and(|(o, _, _)| {
                owner.map_or(true, |expected| *o == expected)
                    && e.idle_ms != 0
                    && now_us.saturating_sub(e.last_used_us) >= u64::from(e.idle_ms) * 1000
            });
            if expired
                && let Ok((decoded, used)) = quic_base::ConnectionId::decode(&k.0)
                && used == k.0.len()
                && decoded.value() > 0
                && decoded.value() < lowest
            {
                lowest = decoded.value();
            }
            !expired
        });
        self.lowest_free_cid = lowest;
        before - self.entries.len()
    }

    /// Read activity statistics for `owner`'s route at `cid` without refreshing `last_used_us`
    /// (`xip_quic_relay_stats`).
    pub fn relay_stats(&self, owner: usize, cid: &[u8]) -> Result<RelayStats, i32> {
        if cid.is_empty() || cid.len() > CID_MAX {
            return Err(ERR_ARG);
        }
        let Some(e) = self.get(cid) else {
            return Err(ERR_NOTFOUND);
        };
        if !e.managed.as_ref().is_some_and(|(o, _, _)| *o == owner) {
            return Err(ERR_NOTFOUND);
        }
        Ok(RelayStats {
            last_used_us: e.last_used_us,
            idle_ms: e.idle_ms,
            reserved: 0,
        })
    }

    /// Update the inactivity timeout `idle_ms` for `owner`'s route at `cid` (`xip_quic_relay_idle`).
    pub fn relay_idle(&mut self, owner: usize, cid: &[u8], idle_ms: u32) -> i32 {
        if cid.is_empty() || cid.len() > CID_MAX {
            return ERR_ARG;
        }
        let Some(e) = self.get_mut(cid) else {
            return ERR_NOTFOUND;
        };
        if !e.managed.as_ref().is_some_and(|(o, _, _)| *o == owner) {
            return ERR_NOTFOUND;
        }
        e.idle_ms = idle_ms;
        OK
    }

    /// Allocate an opaque high-range CID (`(1 << 60) | n`, 8 bytes) or reuse an identical live
    /// single-hop forwarding owned by `owner` (`xip_quic_relay_create`).
    ///
    /// Returns `Ok(1)` when an existing route was reused, `Ok(0)` when a fresh CID was allocated,
    /// or `Err(rc)` on validation/capacity failure.
    pub fn relay_create(
        &mut self,
        owner: usize,
        route: &mut RelayRoute,
        idle_ms: u32,
        reuse: bool,
        now_us: u64,
    ) -> Result<i32, i32> {
        if route.dcid_len != 0 || route.hop_count != 1 {
            return Err(ERR_ARG);
        }
        self.relay_expire(Some(owner), now_us);
        if reuse {
            for e in self.entries.values_mut() {
                if let Some((old_owner, old, _)) = &e.managed {
                    if *old_owner == owner
                        && e.idle_ms == idle_ms
                        && old.endpoint == route.endpoint
                        && old.hop_count == 1
                        && old.hops[0] == route.hops[0]
                    {
                        *route = *old;
                        e.last_used_us = now_us;
                        return Ok(1);
                    }
                }
            }
        }
        for _ in 0..=self.max_entries {
            if self.next_relay_cid >= (1u64 << 60) - 1 {
                return Err(ERR_NOMEM);
            }
            self.next_relay_cid += 1;
            let cid = cid_encode((1u64 << 60) | self.next_relay_cid).ok_or(ERR_NOMEM)?;
            if self.contains_key(&cid) {
                continue;
            }
            let mut candidate = *route;
            candidate.dcid[..cid.len()].copy_from_slice(&cid);
            candidate.dcid_len = cid.len() as u8;
            let rc = self.relay_set(owner, &candidate, 0);
            if rc < 0 {
                return Err(rc);
            }
            let e = self.get_mut(&cid).expect("just inserted");
            e.last_used_us = now_us;
            e.idle_ms = idle_ms;
            *route = candidate;
            return Ok(0);
        }
        Err(ERR_NOMEM)
    }

    /// Select an entry for `cid` at `now_us`, checking inactivity expiry, refreshing `last_used_us`,
    /// and advancing weighted round-robin hop selection (`xip_quic_relay_select_at`).
    pub fn select(&mut self, cid: &[u8], now_us: u64) -> Option<QuicEntry> {
        let entry = self.get_mut(cid)?;
        if entry.managed.is_some()
            && entry.idle_ms != 0
            && now_us.saturating_sub(entry.last_used_us) >= u64::from(entry.idle_ms) * 1000
        {
            return None;
        }
        if entry.managed.is_some() && now_us >= entry.last_used_us {
            entry.last_used_us = now_us;
        }
        if let Some((_, route, cursor)) = &mut entry.managed {
            let total: u32 = route.hops[..route.hop_count as usize]
                .iter()
                .map(|h| u32::from(h.weight))
                .sum();
            if total > 0 {
                let mut at = *cursor % total;
                *cursor = cursor.wrapping_add(1);
                for hop in &route.hops[..route.hop_count as usize] {
                    let w = u32::from(hop.weight);
                    if at < w {
                        entry.egress = hop.link;
                        entry.token = hop.token;
                        entry.out_cid = hop.rewritten_dcid[..hop.cid_len as usize].to_vec();
                        entry.address = hop.address[..hop.address_len as usize].to_vec();
                        break;
                    }
                    at -= w;
                }
            }
        }
        Some(entry.clone())
    }
}
