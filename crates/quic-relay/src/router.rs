//! Capacity-limited DCID registry, `PATH_OPEN` / `PATH_OPEN_ACK` setup codecs,
//! setup transaction cache, and zero-copy packet forwarding router ported from
//! `quic-lite::relay` and built on `quic-base`.

use alloc::vec::Vec;
use quic_base::{
    ConnectionId, PoolPacket, ShortHeader, ShortHeaderPrefix, WireError, decode_varint,
    encode_varint,
};

/// Default bearer payload ceiling (`1,100` bytes) shared with `quic-lite`.
pub const DEFAULT_MAX_PACKET_SIZE: usize = 1100;

/// Version assigned to the DMesh long-header extension (`0x444d_0001`).
pub const DMESH_LONG_HEADER_VERSION: u32 = 0x444d_0001;

/// Long-header packet type `0`: `INITIAL` (`OPEN` / `OPEN_ACK`).
pub const LONG_PACKET_INITIAL: u8 = 0;

/// Long-header packet type `1`: `PATH_OPEN`.
pub const LONG_PACKET_PATH_OPEN: u8 = 1;

/// Long-header packet type `2`: `PATH_OPEN_ACK`.
pub const LONG_PACKET_PATH_OPEN_ACK: u8 = 2;

/// Setup protocol wire version `1`.
pub const SETUP_VERSION: u8 = 1;

/// Setup request protocol wire version `2` (includes `RelayRouteMode`).
pub const SETUP_REQUEST_VERSION: u8 = 2;

/// Maximum number of setup instruction blocks in a single `PATH_OPEN`.
pub const MAX_SETUP_BLOCKS: usize = 8;

/// Maximum byte size of a single setup block payload.
pub const MAX_SETUP_BLOCK_BYTES: usize = 256;

/// Maximum byte size of a complete `PATH_OPEN` or `PATH_OPEN_ACK` body.
pub const MAX_SETUP_BODY_BYTES: usize = DEFAULT_MAX_PACKET_SIZE - 64;

/// Default maximum concurrent pending setup transactions per router.
pub const DEFAULT_MAX_PENDING_SETUPS: usize = 4;

/// Default maximum cached setup replies per router.
pub const DEFAULT_MAX_CACHED_SETUP_REPLIES: usize = 8;

/// Default maximum byte size of a cached setup reply.
pub const DEFAULT_SETUP_REPLY_BYTES: usize = 256;

/// Default total byte storage reserved for setup replies.
pub const DEFAULT_SETUP_REPLY_STORAGE_BYTES: usize = 1_024;

/// Default timeout for a pending setup transaction (`10` seconds in microseconds).
pub const DEFAULT_SETUP_PENDING_TIMEOUT_US: u64 = 10_000_000;

/// Default retention window for a completed or expired setup transaction (`5` seconds).
pub const DEFAULT_SETUP_REPLY_RETENTION_US: u64 = 5_000_000;

/// Default relay forward rule inactivity lease (`60` seconds in microseconds).
pub const DEFAULT_SETUP_LEASE_US: u64 = 60_000_000;

/// Setup block kind `1`: intermediate relay hop instruction (`SetupHopInstruction`).
pub const SETUP_BLOCK_RELAY: u8 = 1;

/// Setup block kind `2`: terminal endpoint block (`SetupCreateEndpoint` / `SetupJoinEndpoint`).
pub const SETUP_BLOCK_ENDPOINT: u8 = 2;

/// Maximum byte length of an embedded bootstrap `OPEN_ACK` inside a `PATH_OPEN_ACK`.
pub const MAX_SETUP_BOOTSTRAP_ACK_BYTES: usize = 128;

/// Maximum byte length of an opaque next-hop address inside a `SetupHopInstruction`.
pub const MAX_SETUP_HOP_ADDRESS_BYTES: usize = 18;

/// Maximum number of nearby return relay hints advertised in `SetupCreateEndpoint`.
pub const MAX_NEARBY_RETURN_RELAYS: usize = 3;

/// Errors returned by `quic-relay` packet/setup codecs and rewrite helpers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayError {
    /// Output buffer or packet headroom is too small.
    BufferTooSmall,
    /// Input packet ended before a complete header or field was decoded.
    Truncated,
    /// Header, version, CID, or setup field is structurally invalid.
    Invalid,
    /// QUIC variable-length integer is malformed or overflows 62 bits.
    InvalidVarint,
    /// Packet is shared (`refs > 1`) and cannot be rewritten in-place.
    Blocked,
}

impl From<WireError> for RelayError {
    fn from(err: WireError) -> Self {
        match err {
            WireError::UnexpectedEof => Self::Truncated,
            WireError::BufferTooSmall => Self::BufferTooSmall,
            WireError::VarIntOverflow => Self::InvalidVarint,
            WireError::UnsupportedFrame(_) | WireError::InvalidFrame => Self::Invalid,
        }
    }
}

#[inline]
fn put_varint(v: u64, out: &mut [u8]) -> Result<usize, RelayError> {
    encode_varint(v, out).map_err(RelayError::from)
}

#[inline]
fn get_varint(input: &[u8]) -> Result<(u64, usize), RelayError> {
    decode_varint(input).map_err(|e| match e {
        WireError::UnexpectedEof => RelayError::Truncated,
        _ => RelayError::InvalidVarint,
    })
}

/// Endpoint role (`Client` or `Server`) for circuit keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Initiating client role (`0` on the wire).
    Client,
    /// Accepting server role (`1` on the wire).
    Server,
}

/// Parsed DMesh long header (`DMESH_LONG_HEADER_VERSION = 0x444d_0001`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LongHeader {
    /// Long packet type (`LONG_PACKET_INITIAL`, `LONG_PACKET_PATH_OPEN`, `LONG_PACKET_PATH_OPEN_ACK`).
    pub packet_type: u8,
    /// 32-bit wire version (`DMESH_LONG_HEADER_VERSION`).
    pub version: u32,
    /// Optional destination connection ID (`None` when length byte is `0`).
    pub dcid: Option<ConnectionId>,
    /// Optional source connection ID (`None` when length byte is `0`).
    pub scid: Option<ConnectionId>,
    /// Truncated packet number (`1..=4` bytes).
    pub packet_number: u32,
    /// Encoded packet number length in bytes (`1..=4`).
    pub packet_number_len: u8,
}

/// Encode a DMesh long-header packet (`0x444d_0001`) into `out`, returning total bytes written.
pub fn encode_long_packet(
    packet_type: u8,
    dcid: Option<ConnectionId>,
    scid: Option<ConnectionId>,
    packet_number: u32,
    packet_number_len: u8,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, RelayError> {
    if packet_type > 3 || !matches!(packet_number_len, 1..=4) || payload.is_empty() {
        return Err(RelayError::Invalid);
    }
    let mut at = 0usize;
    let need = 1
        + 4
        + 1
        + dcid.map_or(0, ConnectionId::encoded_len)
        + 1
        + scid.map_or(0, ConnectionId::encoded_len)
        + usize::from(packet_type == LONG_PACKET_INITIAL)
        + 8
        + usize::from(packet_number_len)
        + payload.len();
    if out.len() < need {
        return Err(RelayError::BufferTooSmall);
    }
    out[at] = 0xc0 | (packet_type << 4) | (packet_number_len - 1);
    at += 1;
    out[at..at + 4].copy_from_slice(&DMESH_LONG_HEADER_VERSION.to_be_bytes());
    at += 4;
    for cid in [dcid, scid] {
        let len = cid.map_or(0, ConnectionId::encoded_len);
        out[at] = len as u8;
        at += 1;
        if let Some(cid) = cid {
            cid.encode(&mut out[at..at + len])?;
            at += len;
        }
    }
    if packet_type == LONG_PACKET_INITIAL {
        out[at] = 0;
        at += 1;
    }
    let body_len = u64::from(packet_number_len) + payload.len() as u64;
    let length_len = put_varint(body_len, &mut out[at..])?;
    at += length_len;
    let pn = packet_number.to_be_bytes();
    out[at..at + usize::from(packet_number_len)]
        .copy_from_slice(&pn[4 - usize::from(packet_number_len)..]);
    at += usize::from(packet_number_len);
    out[at..at + payload.len()].copy_from_slice(payload);
    Ok(at + payload.len())
}

/// Decode a DMesh long-header packet (`0x444d_0001`), returning `(LongHeader, payload_offset, payload_len)`.
pub fn decode_long_packet(input: &[u8]) -> Result<(LongHeader, usize, usize), RelayError> {
    if input.len() < 9 || input[0] & 0xc0 != 0xc0 {
        return Err(RelayError::Invalid);
    }
    let version = u32::from_be_bytes(input[1..5].try_into().map_err(|_| RelayError::Truncated)?);
    if version != DMESH_LONG_HEADER_VERSION {
        return Err(RelayError::Invalid);
    }
    let packet_type = (input[0] >> 4) & 0x03;
    let packet_number_len = (input[0] & 0x03) + 1;
    let mut at = 5usize;
    let mut cids = [None, None];
    for slot in &mut cids {
        let len = *input.get(at).ok_or(RelayError::Truncated)? as usize;
        at += 1;
        if len != 0 {
            if !matches!(len, 1 | 2 | 4 | 8) || input.len() < at + len {
                return Err(RelayError::Invalid);
            }
            let (cid, used) = ConnectionId::decode(&input[at..at + len])?;
            if used != len {
                return Err(RelayError::Invalid);
            }
            *slot = Some(cid);
            at += len;
        }
    }
    if packet_type == LONG_PACKET_INITIAL {
        let (token_len, used) = get_varint(input.get(at..).ok_or(RelayError::Truncated)?)?;
        at += used;
        let token_len = usize::try_from(token_len).map_err(|_| RelayError::Invalid)?;
        at = at.checked_add(token_len).ok_or(RelayError::Invalid)?;
        if input.len() < at {
            return Err(RelayError::Truncated);
        }
    }
    let (body_len, used) = get_varint(&input[at..])?;
    at += used;
    let body_len = usize::try_from(body_len).map_err(|_| RelayError::Invalid)?;
    if body_len < usize::from(packet_number_len) || input.len() != at + body_len {
        return Err(RelayError::Invalid);
    }
    let mut pn = [0u8; 4];
    let pn_len = usize::from(packet_number_len);
    pn[4 - pn_len..].copy_from_slice(&input[at..at + pn_len]);
    at += pn_len;
    Ok((
        LongHeader {
            packet_type,
            version,
            dcid: cids[0],
            scid: cids[1],
            packet_number: u32::from_be_bytes(pn),
            packet_number_len,
        },
        at,
        body_len - pn_len,
    ))
}

/// Decode the routing prefix (`ShortHeaderPrefix`) from either a short-header or DMesh long-header packet.
pub fn decode_routing_prefix(input: &[u8]) -> Result<ShortHeaderPrefix, RelayError> {
    if input.first().is_some_and(|flags| flags & 0x80 != 0) {
        let (header, header_len, _) = decode_long_packet(input)?;
        Ok(ShortHeaderPrefix {
            flags: input[0],
            dcid: header
                .dcid
                .unwrap_or(ConnectionId::new(0).ok_or(RelayError::Invalid)?),
            truncated_packet_number: header.packet_number,
            packet_number_len: header.packet_number_len,
            header_len,
        })
    } else {
        ShortHeader::decode_prefix(input).map_err(RelayError::from)
    }
}

fn rewrite_destination(
    input: &[u8],
    outbound_dcid: Option<ConnectionId>,
    out: &mut [u8],
) -> Result<usize, RelayError> {
    if input.first().is_some_and(|flags| flags & 0x80 != 0) {
        let (header, payload_at, payload_len) = decode_long_packet(input)?;
        return encode_long_packet(
            header.packet_type,
            outbound_dcid,
            header.scid,
            header.packet_number,
            header.packet_number_len,
            &input[payload_at..payload_at + payload_len],
            out,
        );
    }
    let outbound_dcid = outbound_dcid.ok_or(RelayError::Invalid)?;
    let prefix = ShortHeader::decode_prefix(input)?;
    let inbound_len = prefix.dcid.encoded_len();
    let outbound_len = outbound_dcid.encoded_len();
    let used = input
        .len()
        .checked_sub(inbound_len)
        .and_then(|len| len.checked_add(outbound_len))
        .ok_or(RelayError::Invalid)?;
    if out.len() < used {
        return Err(RelayError::BufferTooSmall);
    }
    out[0] = input[0];
    outbound_dcid.encode(&mut out[1..])?;
    let input_tail = 1 + inbound_len;
    let output_tail = 1 + outbound_len;
    out[output_tail..used].copy_from_slice(&input[input_tail..]);
    Ok(used)
}

/// Rewrite only the DCID of a short-header or DMesh long-header packet into `out`.
pub fn rewrite_dcid(
    input: &[u8],
    outbound_dcid: ConnectionId,
    out: &mut [u8],
) -> Result<usize, RelayError> {
    if outbound_dcid.value() == 0 {
        return Err(RelayError::Invalid);
    }
    rewrite_destination(input, Some(outbound_dcid), out)
}

/// Rewrite a DMesh long-header packet's destination CID to empty (`None`) for bootstrap delivery.
pub fn rewrite_bootstrap_destination(input: &[u8], out: &mut [u8]) -> Result<usize, RelayError> {
    rewrite_destination(input, None, out)
}

/// Zero-copy in-place short-header DCID rewrite on any [`PoolPacket`] (`StaticPacketPool`,
/// `HeapPacketPool`, or `XipLazyPool`).
///
/// Only the flags byte and DCID bytes are written in the packet's headroom; the packet number,
/// encrypted payload, and AEAD tag remain at their exact backing addresses even when the CID
/// encoded byte length changes (`1`, `2`, `4`, or `8` bytes).
pub fn rewrite_dcid_in_place<P: PoolPacket>(
    mut packet: P,
    destination: ConnectionId,
    prefix_required: usize,
    max_packet: usize,
) -> Result<P, (RelayError, P)> {
    if destination.value() == 0 || packet.bytes().first().is_some_and(|b| b & 0x80 != 0) {
        return Err((RelayError::Invalid, packet));
    }
    let prefix = match ShortHeader::decode_prefix(packet.bytes()) {
        Ok(p) => p,
        Err(e) => return Err((RelayError::from(e), packet)),
    };
    let range = packet.range();
    let tail = range.start + 1 + prefix.dcid.encoded_len();
    let header_len = 1 + destination.encoded_len();
    let Some(start) = tail.checked_sub(header_len) else {
        return Err((RelayError::BufferTooSmall, packet));
    };
    if start < prefix_required || range.end - start > max_packet {
        return Err((RelayError::BufferTooSmall, packet));
    }
    let mut header = [0u8; 9];
    header[0] = packet.bytes()[0];
    if let Err(e) = destination.encode(&mut header[1..header_len]) {
        return Err((RelayError::from(e), packet));
    }
    let Ok(slot) = packet.slot_slice_mut() else {
        return Err((RelayError::Blocked, packet));
    };
    slot[start..start + header_len].copy_from_slice(&header[..header_len]);
    if packet.set_range(start..range.end).is_err() {
        return Err((RelayError::BufferTooSmall, packet));
    }
    Ok(packet)
}

/// Destination selected by an opaque relay rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardDestination {
    /// Rewrite the packet's DCID to this compact `ConnectionId`.
    Connection(ConnectionId),
    /// Rewrite a DMesh long-header packet's DCID to empty (`None`) for terminal bootstrap delivery.
    Bootstrap,
}

/// Adjacent egress hop selected by a relay rule (`(bearer_id, peer_l2_address)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForwardNextHop {
    /// Node-local bearer/link identifier (`!= 0`).
    pub bearer: u16,
    /// Bearer-local peer L2 token/address (`!= 0`).
    pub peer_l2_address: u64,
}

/// Opaque forwarding action selected by a non-zero local DCID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForwardRule<NextHop> {
    /// Platform-owned adjacent-peer or egress handle.
    pub next_hop: NextHop,
    /// Destination written before submitting the packet to `next_hop`.
    pub destination: ForwardDestination,
    /// Inactivity lease duration in microseconds.
    pub lease_duration_us: u64,
    /// Absolute expiry on the node's monotonic clock.
    pub lease_expires_at_us: u64,
    /// Shared lifecycle key for the two directions of one installed path (`0` = standalone).
    pub lease_group_id: u64,
    /// Maximum admitted packets for this direction (`0` = unlimited).
    pub packet_quota: u64,
    /// Packets admitted in the current quota window.
    pub forwarded_packets: u64,
    /// Admitted control packets, which may use the control reserve (`1/16` of quota).
    pub forwarded_control_packets: u64,
    /// Start of the fixed quota window in microseconds.
    pub quota_window_started_us: u64,
}

/// Admission result for one setup retry in [`SetupTransactionTable`].
#[derive(Debug, PartialEq, Eq)]
pub enum SetupTransactionLookup<'a> {
    /// First request for this `(previous_hop, transaction_id)` pair.
    New,
    /// Identical retry while downstream setup is still pending.
    PendingRetry,
    /// Matching transaction whose setup already expired or was cancelled.
    Expired,
    /// Identical retry after installation; replay these exact response bytes.
    Replay(&'a [u8]),
    /// Same transaction key was reused with different request bytes.
    Conflict,
    /// Configured pending, cache, request, or response storage is exhausted.
    Full,
    /// Transaction identifiers, retry deadlines, or reply sizes are invalid.
    Invalid,
}

/// Error returned when updating or completing a [`SetupTransactionTable`] entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupTransactionError {
    /// No matching transaction exists.
    Missing,
    /// Transaction has already expired or been cancelled.
    Expired,
    /// Reply exceeds the reserved byte capacity.
    ReplyTooLarge,
    /// Downstream hop, relay state, or reply payload conflicts with existing state.
    Conflict,
}

/// Relay CID pair and quota state retained while a downstream `PATH_OPEN` is in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupRelayState {
    /// Forward-direction local DCID allocated by this relay.
    pub forward_cid: ConnectionId,
    /// Reverse-direction local DCID allocated by this relay.
    pub reverse_cid: ConnectionId,
    /// Upstream reverse target CID on `previous_hop`.
    pub reverse_target: ConnectionId,
    /// Negotiated inactivity lease duration in microseconds.
    pub lease_duration_us: u64,
    /// Negotiated packet quota per lease window.
    pub packet_quota: u64,
}

/// Result of validating a downstream `PATH_OPEN_ACK` against [`SetupTransactionTable`].
#[derive(Debug, PartialEq, Eq)]
pub enum SetupDownstreamReply<'a> {
    /// Downstream reply was already processed; replay the cached upstream reply to `previous_hop`.
    Replay {
        /// Upstream hop to send the replayed `PATH_OPEN_ACK` to.
        previous_hop: ForwardNextHop,
        /// Cached upstream `PATH_OPEN_ACK` packet bytes.
        reply: &'a [u8],
    },
    /// First valid downstream reply; install the paired forward rules and complete the transaction.
    New {
        /// Upstream hop to send the completed `PATH_OPEN_ACK` to.
        previous_hop: ForwardNextHop,
        /// Provisional relay CIDs and lease parameters recorded during `PATH_OPEN`.
        relay_state: SetupRelayState,
    },
}

struct SetupTransaction {
    previous_hop: ForwardNextHop,
    transaction_id: u64,
    request: Vec<u8>,
    reply: Vec<u8>,
    downstream_reply: Vec<u8>,
    downstream_hop: Option<ForwardNextHop>,
    relay_state: Option<SetupRelayState>,
    reply_ready: bool,
    expired: bool,
    pending_deadline_us: u64,
    cache_expiry_us: u64,
    reserved_reply_bytes: usize,
}

/// Fixed-policy transaction and reply cache for relay setup retries (`PATH_OPEN` / `PATH_OPEN_ACK`).
pub struct SetupTransactionTable {
    entries: Vec<SetupTransaction>,
    max_pending: usize,
    max_cached_replies: usize,
    max_request_bytes: usize,
    max_reply_bytes: usize,
    max_reserved_reply_bytes: usize,
    reserved_reply_bytes: usize,
    pending_count: usize,
    cached_count: usize,
    retention_us: u64,
}

impl SetupTransactionTable {
    /// Construct a new [`SetupTransactionTable`] with explicit resource ceilings.
    pub fn new(
        max_pending: usize,
        max_cached_replies: usize,
        max_request_bytes: usize,
        max_reply_bytes: usize,
        max_reserved_reply_bytes: usize,
        retention_us: u64,
    ) -> Self {
        Self {
            entries: Vec::new(),
            max_pending,
            max_cached_replies,
            max_request_bytes,
            max_reply_bytes,
            max_reserved_reply_bytes,
            reserved_reply_bytes: 0,
            pending_count: 0,
            cached_count: 0,
            retention_us,
        }
    }

    /// Admit a setup request or classify a retry.
    pub fn begin<'a>(
        &'a mut self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
        request: &[u8],
        reply_capacity: usize,
        now_us: u64,
        pending_deadline_us: u64,
    ) -> SetupTransactionLookup<'a> {
        self.expire(now_us);
        if transaction_id == 0
            || request.is_empty()
            || request.len() > self.max_request_bytes
            || reply_capacity == 0
            || reply_capacity > self.max_reply_bytes
            || pending_deadline_us <= now_us
        {
            return SetupTransactionLookup::Invalid;
        }
        if let Some(index) = self.entries.iter().position(|entry| {
            entry.previous_hop == previous_hop && entry.transaction_id == transaction_id
        }) {
            let request_matches = self.entries[index].request == request;
            let reply_ready = self.entries[index].reply_ready;
            let expired = self.entries[index].expired;
            if !request_matches {
                return SetupTransactionLookup::Conflict;
            }
            if expired {
                return SetupTransactionLookup::Expired;
            }
            return if reply_ready {
                SetupTransactionLookup::Replay(&self.entries[index].reply)
            } else {
                SetupTransactionLookup::PendingRetry
            };
        }
        let Some(reserved_reply_bytes) = self.reserved_reply_bytes.checked_add(reply_capacity)
        else {
            return SetupTransactionLookup::Full;
        };
        if self.pending_count >= self.max_pending
            || self.entries.len() >= self.max_cached_replies
            || reserved_reply_bytes > self.max_reserved_reply_bytes
        {
            return SetupTransactionLookup::Full;
        }

        let mut owned_request = Vec::new();
        if owned_request.try_reserve_exact(request.len()).is_err() {
            return SetupTransactionLookup::Full;
        }
        let mut reply = Vec::new();
        if reply.try_reserve_exact(reply_capacity).is_err() || self.entries.try_reserve(1).is_err()
        {
            return SetupTransactionLookup::Full;
        }
        owned_request.extend_from_slice(request);
        self.entries.push(SetupTransaction {
            previous_hop,
            transaction_id,
            request: owned_request,
            reply,
            downstream_reply: Vec::new(),
            downstream_hop: None,
            relay_state: None,
            reply_ready: false,
            expired: false,
            pending_deadline_us,
            cache_expiry_us: 0,
            reserved_reply_bytes: reply_capacity,
        });
        self.pending_count += 1;
        self.reserved_reply_bytes = reserved_reply_bytes;
        SetupTransactionLookup::New
    }

    /// Complete a pending setup transaction with its encoded `PATH_OPEN_ACK` reply bytes.
    pub fn complete(
        &mut self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
        reply: &[u8],
        now_us: u64,
    ) -> Result<(), SetupTransactionError> {
        let Some(index) = self.entries.iter().position(|entry| {
            entry.previous_hop == previous_hop && entry.transaction_id == transaction_id
        }) else {
            return Err(SetupTransactionError::Missing);
        };
        if self.entries[index].expired || now_us >= self.entries[index].pending_deadline_us {
            return Err(SetupTransactionError::Expired);
        }
        if self.entries[index].reply_ready {
            return Err(SetupTransactionError::Missing);
        }
        if reply.is_empty() || reply.len() > self.entries[index].reserved_reply_bytes {
            return Err(SetupTransactionError::ReplyTooLarge);
        }
        let entry = &mut self.entries[index];
        entry.reply.extend_from_slice(reply);
        entry.reply_ready = true;
        entry.cache_expiry_us = now_us.saturating_add(self.retention_us);
        self.pending_count -= 1;
        self.cached_count += 1;
        Ok(())
    }

    /// Record the selected downstream hop for a pending transaction.
    pub fn set_downstream_hop(
        &mut self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
        downstream_hop: ForwardNextHop,
    ) -> Result<(), SetupTransactionError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| {
                entry.previous_hop == previous_hop && entry.transaction_id == transaction_id
            })
            .ok_or(SetupTransactionError::Missing)?;
        if entry.expired || entry.reply_ready {
            return Err(SetupTransactionError::Expired);
        }
        if entry
            .downstream_hop
            .is_some_and(|existing| existing != downstream_hop)
        {
            return Err(SetupTransactionError::Conflict);
        }
        entry.downstream_hop = Some(downstream_hop);
        Ok(())
    }

    /// Return the recorded downstream hop for `(previous_hop, transaction_id)`.
    pub fn downstream_hop(
        &self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
    ) -> Option<ForwardNextHop> {
        self.entries
            .iter()
            .find(|entry| {
                entry.previous_hop == previous_hop && entry.transaction_id == transaction_id
            })
            .and_then(|entry| entry.downstream_hop)
    }

    /// Record provisional [`SetupRelayState`] for a pending transaction.
    pub fn set_relay_state(
        &mut self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
        relay_state: SetupRelayState,
    ) -> Result<(), SetupTransactionError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| {
                entry.previous_hop == previous_hop && entry.transaction_id == transaction_id
            })
            .ok_or(SetupTransactionError::Missing)?;
        if entry.expired || entry.reply_ready {
            return Err(SetupTransactionError::Expired);
        }
        if entry
            .relay_state
            .is_some_and(|existing| existing != relay_state)
        {
            return Err(SetupTransactionError::Conflict);
        }
        entry.relay_state = Some(relay_state);
        Ok(())
    }

    /// Return the recorded [`SetupRelayState`] for `(previous_hop, transaction_id)`.
    pub fn relay_state(
        &self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
    ) -> Option<SetupRelayState> {
        self.entries
            .iter()
            .find(|entry| {
                entry.previous_hop == previous_hop && entry.transaction_id == transaction_id
            })
            .and_then(|entry| entry.relay_state)
    }

    /// Validate a downstream `PATH_OPEN_ACK` packet against a pending transaction.
    pub fn validate_downstream_reply(
        &mut self,
        downstream_hop: ForwardNextHop,
        transaction_id: u64,
        circuit: SetupCircuitKey,
        reply: &[u8],
    ) -> Result<SetupDownstreamReply<'_>, SetupTransactionError> {
        let index = self
            .entries
            .iter()
            .position(|entry| {
                entry.downstream_hop == Some(downstream_hop)
                    && entry.transaction_id == transaction_id
            })
            .ok_or(SetupTransactionError::Missing)?;
        let entry = &mut self.entries[index];
        if entry.expired {
            return Err(SetupTransactionError::Expired);
        }
        let decoded =
            decode_setup_reply_packet(reply).map_err(|_| SetupTransactionError::Conflict)?;
        if decoded.transaction_id != transaction_id || decoded.circuit != circuit {
            return Err(SetupTransactionError::Conflict);
        }
        if !entry.downstream_reply.is_empty() {
            if entry.downstream_reply != reply {
                return Err(SetupTransactionError::Conflict);
            }
            if entry.reply_ready {
                return Ok(SetupDownstreamReply::Replay {
                    previous_hop: entry.previous_hop,
                    reply: &entry.reply,
                });
            }
        } else {
            if reply.is_empty() || reply.len() > self.max_reply_bytes {
                return Err(SetupTransactionError::ReplyTooLarge);
            }
            entry
                .downstream_reply
                .try_reserve_exact(reply.len())
                .map_err(|_| SetupTransactionError::ReplyTooLarge)?;
            entry.downstream_reply.extend_from_slice(reply);
        }
        let relay_state = entry.relay_state.ok_or(SetupTransactionError::Missing)?;
        Ok(SetupDownstreamReply::New {
            previous_hop: entry.previous_hop,
            relay_state,
        })
    }

    /// Complete a transaction identified by its `downstream_hop` and `transaction_id`.
    pub fn complete_from_downstream(
        &mut self,
        downstream_hop: ForwardNextHop,
        transaction_id: u64,
        reply: &[u8],
        now_us: u64,
    ) -> Result<ForwardNextHop, SetupTransactionError> {
        let previous_hop = self
            .entries
            .iter()
            .find(|entry| {
                entry.downstream_hop == Some(downstream_hop)
                    && entry.transaction_id == transaction_id
            })
            .map(|entry| entry.previous_hop)
            .ok_or(SetupTransactionError::Missing)?;
        self.complete(previous_hop, transaction_id, reply, now_us)?;
        Ok(previous_hop)
    }

    /// Cancel a provisional transaction and release its reply byte reservation.
    pub fn cancel(&mut self, previous_hop: ForwardNextHop, transaction_id: u64) -> bool {
        let Some(index) = self.entries.iter().position(|entry| {
            entry.previous_hop == previous_hop && entry.transaction_id == transaction_id
        }) else {
            return false;
        };
        self.mark_expired(index);
        true
    }

    /// Expire pending transactions past `pending_deadline_us` and cached entries past `cache_expiry_us`.
    pub fn expire(&mut self, now_us: u64) -> usize {
        let mut removed = 0usize;
        let mut index = 0;
        while index < self.entries.len() {
            let pending_expired = !self.entries[index].reply_ready
                && !self.entries[index].expired
                && self.entries[index].pending_deadline_us <= now_us;
            if pending_expired {
                self.mark_expired(index);
                removed += 1;
            }
            if (self.entries[index].reply_ready || self.entries[index].expired)
                && self.entries[index].cache_expiry_us <= now_us
            {
                self.remove(index);
                if !pending_expired {
                    removed += 1;
                }
            } else {
                index += 1;
            }
        }
        removed
    }

    /// Number of currently pending transactions.
    pub fn pending_count(&self) -> usize {
        self.pending_count
    }

    /// Number of completed transactions whose replies are currently cached.
    pub fn cached_count(&self) -> usize {
        self.cached_count
    }

    /// Total reply bytes currently reserved across pending and cached transactions.
    pub fn reserved_reply_bytes(&self) -> usize {
        self.reserved_reply_bytes
    }

    /// Earliest pending or cache expiry deadline across all active transactions.
    pub fn next_deadline(&self) -> Option<u64> {
        self.entries
            .iter()
            .map(|entry| {
                if entry.reply_ready || entry.expired {
                    entry.cache_expiry_us
                } else {
                    entry.pending_deadline_us
                }
            })
            .min()
    }

    fn remove(&mut self, index: usize) {
        let entry = self.entries.remove(index);
        if entry.reply_ready {
            self.cached_count -= 1;
        } else if !entry.expired {
            self.pending_count -= 1;
        }
        self.reserved_reply_bytes = self
            .reserved_reply_bytes
            .saturating_sub(entry.reserved_reply_bytes);
    }

    fn mark_expired(&mut self, index: usize) {
        let entry = &mut self.entries[index];
        if entry.reply_ready || entry.expired {
            return;
        }
        entry.expired = true;
        entry.cache_expiry_us = entry.pending_deadline_us.saturating_add(self.retention_us);
        entry.reply = Vec::new();
        self.pending_count -= 1;
        self.reserved_reply_bytes = self
            .reserved_reply_bytes
            .saturating_sub(entry.reserved_reply_bytes);
        entry.reserved_reply_bytes = 0;
    }
}

/// Opaque egress address and lease parameters for one relay hop in a `PATH_OPEN`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupHopInstruction {
    /// Address namespace understood by the relay (`!= 0`).
    pub address_kind: u8,
    /// Number of meaningful bytes in `address` (`1..=18`).
    pub address_len: u8,
    /// Opaque next-hop address bytes.
    pub address: [u8; MAX_SETUP_HOP_ADDRESS_BYTES],
    /// Requested inactivity lease duration in microseconds (`!= 0`).
    pub lease_us: u64,
    /// Requested packet quota per lease window (`!= 0`).
    pub packet_quota: u64,
}

impl SetupHopInstruction {
    /// Construct a validated [`SetupHopInstruction`] from an address slice.
    pub fn new(
        address_kind: u8,
        address: &[u8],
        lease_us: u64,
        packet_quota: u64,
    ) -> Result<Self, RelayError> {
        if address_kind == 0
            || address.is_empty()
            || address.len() > MAX_SETUP_HOP_ADDRESS_BYTES
            || lease_us == 0
            || packet_quota == 0
        {
            return Err(RelayError::Invalid);
        }
        let mut stored = [0u8; MAX_SETUP_HOP_ADDRESS_BYTES];
        stored[..address.len()].copy_from_slice(address);
        Ok(Self {
            address_kind,
            address_len: address.len() as u8,
            address: stored,
            lease_us,
            packet_quota,
        })
    }

    /// Encode this hop instruction into `output`.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, RelayError> {
        let address_len = usize::from(self.address_len);
        if self.address_kind == 0
            || address_len == 0
            || address_len > MAX_SETUP_HOP_ADDRESS_BYTES
            || self.lease_us == 0
            || self.packet_quota == 0
        {
            return Err(RelayError::Invalid);
        }
        let mut pos = 0usize;
        put_setup_byte(output, &mut pos, self.address_kind)?;
        put_setup_byte(output, &mut pos, self.address_len)?;
        if output.len().saturating_sub(pos) < address_len {
            return Err(RelayError::BufferTooSmall);
        }
        output[pos..pos + address_len].copy_from_slice(&self.address[..address_len]);
        pos += address_len;
        pos += put_varint(self.lease_us, &mut output[pos..])?;
        pos += put_varint(self.packet_quota, &mut output[pos..])?;
        if pos > MAX_SETUP_BLOCK_BYTES {
            return Err(RelayError::Invalid);
        }
        Ok(pos)
    }

    /// Decode a [`SetupHopInstruction`] from `input`.
    pub fn decode(input: &[u8]) -> Result<Self, RelayError> {
        let mut pos = 0usize;
        let address_kind = take_setup_byte(input, &mut pos)?;
        let address_len = take_setup_byte(input, &mut pos)?;
        let address_len_usize = usize::from(address_len);
        if address_kind == 0
            || address_len_usize == 0
            || address_len_usize > MAX_SETUP_HOP_ADDRESS_BYTES
            || input.len().saturating_sub(pos) < address_len_usize
        {
            return Err(RelayError::Invalid);
        }
        let mut address = [0u8; MAX_SETUP_HOP_ADDRESS_BYTES];
        address[..address_len_usize].copy_from_slice(&input[pos..pos + address_len_usize]);
        pos += address_len_usize;
        let (lease_us, used) = get_varint(&input[pos..])?;
        pos += used;
        let (packet_quota, used) = get_varint(&input[pos..])?;
        pos += used;
        if lease_us == 0 || packet_quota == 0 || pos != input.len() {
            return Err(RelayError::Invalid);
        }
        Ok(Self {
            address_kind,
            address_len,
            address,
            lease_us,
            packet_quota,
        })
    }
}

/// Setup mode (`Create` a new association or `Join` an existing association).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupMode {
    /// Create a new association (`0` on the wire).
    Create,
    /// Join a circuit to an existing association (`1` on the wire).
    Join,
}

/// Routing contract carried by a relayed `CREATE` or `JOIN`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayRouteMode {
    /// Each relay follows the explicit next-hop instruction in the request.
    Layered,
    /// The first gateway resolves the destination VIP through local policy.
    VipRouted,
    /// Relays extend the route incrementally under one circuit identity.
    Telescoping,
}

/// Opener role and circuit sequence number identifying a setup circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupCircuitKey {
    /// Whether the circuit was opened by the client or server.
    pub opener_role: Role,
    /// Non-zero circuit sequence number.
    pub sequence: u64,
}

/// One versioned instruction block inside a [`SetupRequest`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupBlock<'a> {
    /// Block kind (`SETUP_BLOCK_RELAY` or `SETUP_BLOCK_ENDPOINT`).
    pub kind: u8,
    /// Block format version (`>= 1`).
    pub version: u8,
    /// Protection profile (`0` = unencrypted setup profile).
    pub protection: u8,
    /// Raw block payload bytes.
    pub payload: &'a [u8],
}

/// Endpoint payload for joining a new circuit to an existing association.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupJoinEndpoint {
    /// Target association's join connection ID.
    pub join_cid: ConnectionId,
    /// Opener's receive connection ID for the new circuit.
    pub opener_receive_cid: ConnectionId,
}

impl SetupJoinEndpoint {
    /// Encode this join endpoint payload into `output`.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, RelayError> {
        if self.join_cid.value() == 0 || self.opener_receive_cid.value() == 0 {
            return Err(RelayError::Invalid);
        }
        let mut pos = self.join_cid.encode(output)?;
        pos += self.opener_receive_cid.encode(&mut output[pos..])?;
        Ok(pos)
    }

    /// Decode a [`SetupJoinEndpoint`] from `input`.
    pub fn decode(input: &[u8]) -> Result<Self, RelayError> {
        let (join_cid, first_used) = ConnectionId::decode(input)?;
        let (opener_receive_cid, second_used) = ConnectionId::decode(&input[first_used..])?;
        if join_cid.value() == 0
            || opener_receive_cid.value() == 0
            || first_used.saturating_add(second_used) != input.len()
        {
            return Err(RelayError::Invalid);
        }
        Ok(Self {
            join_cid,
            opener_receive_cid,
        })
    }
}

/// One untrusted nearby-relay hint supplied with a relayed association open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NearbyRelayHint {
    /// 8-byte device identity of the suggested nearby relay.
    pub relay_id: [u8; 8],
    /// Relay-local egress instruction the peer may use for a return route.
    pub hop: SetupHopInstruction,
}

/// Fixed-size nearby-relay hints carried from the path opener to the accepted endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NearbyRelayHints {
    len: u8,
    entries: [Option<NearbyRelayHint>; MAX_NEARBY_RETURN_RELAYS],
}

impl NearbyRelayHints {
    /// Empty hint set.
    pub const EMPTY: Self = Self {
        len: 0,
        entries: [None; MAX_NEARBY_RETURN_RELAYS],
    };

    /// Validate and copy at most [`MAX_NEARBY_RETURN_RELAYS`] unique relay hints.
    pub fn new(hints: &[NearbyRelayHint]) -> Option<Self> {
        if hints.len() > MAX_NEARBY_RETURN_RELAYS {
            return None;
        }
        let mut entries = [None; MAX_NEARBY_RETURN_RELAYS];
        for (index, hint) in hints.iter().enumerate() {
            if hint.relay_id == [0; 8]
                || hints[..index]
                    .iter()
                    .any(|previous| previous.relay_id == hint.relay_id)
            {
                return None;
            }
            entries[index] = Some(*hint);
        }
        Some(Self {
            len: hints.len() as u8,
            entries,
        })
    }

    /// Whether no return relay hints are present.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Number of retained nearby relay hints.
    pub const fn len(self) -> usize {
        self.len as usize
    }

    /// Iterate over the copied return relay hints.
    pub fn iter(&self) -> impl Iterator<Item = &NearbyRelayHint> {
        self.entries[..self.len()].iter().flatten()
    }
}

/// Version-2 endpoint payload for relayed association creation.
pub struct SetupCreateEndpoint<'a> {
    /// Opaque client Initial packet bytes.
    pub initial_packet: &'a [u8],
    /// Advisory nearby return relay hints.
    pub return_hints: NearbyRelayHints,
}

impl SetupCreateEndpoint<'_> {
    /// Encode this create-endpoint block into `output`.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, RelayError> {
        if self.initial_packet.is_empty() || self.return_hints.len() > MAX_NEARBY_RETURN_RELAYS {
            return Err(RelayError::Invalid);
        }
        let mut pos = put_varint(self.initial_packet.len() as u64, output)?;
        if output.len().saturating_sub(pos) < self.initial_packet.len().saturating_add(1) {
            return Err(RelayError::BufferTooSmall);
        }
        output[pos..pos + self.initial_packet.len()].copy_from_slice(self.initial_packet);
        pos += self.initial_packet.len();
        output[pos] = self.return_hints.len() as u8;
        pos += 1;
        for hint in self.return_hints.iter() {
            if output.len().saturating_sub(pos) < hint.relay_id.len() {
                return Err(RelayError::BufferTooSmall);
            }
            output[pos..pos + hint.relay_id.len()].copy_from_slice(&hint.relay_id);
            pos += hint.relay_id.len();
            let mut encoded_hop = [0u8; MAX_SETUP_BLOCK_BYTES];
            let encoded_hop_len = hint.hop.encode(&mut encoded_hop)?;
            pos += put_varint(encoded_hop_len as u64, &mut output[pos..])?;
            if output.len().saturating_sub(pos) < encoded_hop_len {
                return Err(RelayError::BufferTooSmall);
            }
            output[pos..pos + encoded_hop_len].copy_from_slice(&encoded_hop[..encoded_hop_len]);
            pos += encoded_hop_len;
        }
        if pos > MAX_SETUP_BLOCK_BYTES {
            return Err(RelayError::BufferTooSmall);
        }
        Ok(pos)
    }

    /// Decode a create-endpoint block (`block_version == 1` or `2`).
    pub fn decode(
        payload: &[u8],
        block_version: u8,
    ) -> Result<(&[u8], NearbyRelayHints), RelayError> {
        if block_version == 1 {
            return Ok((payload, NearbyRelayHints::EMPTY));
        }
        if block_version != 2 {
            return Err(RelayError::Invalid);
        }
        let (initial_len, mut pos) = get_varint(payload)?;
        let initial_len = usize::try_from(initial_len).map_err(|_| RelayError::Invalid)?;
        let initial_end = pos.checked_add(initial_len).ok_or(RelayError::Invalid)?;
        if initial_len == 0 || initial_end >= payload.len() {
            return Err(RelayError::Invalid);
        }
        let initial_packet = &payload[pos..initial_end];
        pos = initial_end;
        let hint_count = usize::from(take_setup_byte(payload, &mut pos)?);
        if hint_count > MAX_NEARBY_RETURN_RELAYS {
            return Err(RelayError::Invalid);
        }
        let mut hints = [None; MAX_NEARBY_RETURN_RELAYS];
        for entry in hints.iter_mut().take(hint_count) {
            let end = pos.checked_add(8).ok_or(RelayError::Invalid)?;
            let relay_id: [u8; 8] = payload
                .get(pos..end)
                .ok_or(RelayError::Truncated)?
                .try_into()
                .map_err(|_| RelayError::Invalid)?;
            pos = end;
            let (encoded_len, used) = get_varint(&payload[pos..])?;
            pos = pos.checked_add(used).ok_or(RelayError::Invalid)?;
            let encoded_len = usize::try_from(encoded_len).map_err(|_| RelayError::Invalid)?;
            let encoded_end = pos.checked_add(encoded_len).ok_or(RelayError::Invalid)?;
            let encoded_hop = payload
                .get(pos..encoded_end)
                .ok_or(RelayError::Truncated)?;
            let hop = SetupHopInstruction::decode(encoded_hop)?;
            pos = encoded_end;
            *entry = Some(NearbyRelayHint { relay_id, hop });
        }
        if pos != payload.len() {
            return Err(RelayError::Invalid);
        }
        let compacted = hints
            .into_iter()
            .take(hint_count)
            .flatten()
            .collect::<Vec<_>>();
        let return_hints = NearbyRelayHints::new(&compacted).ok_or(RelayError::Invalid)?;
        Ok((initial_packet, return_hints))
    }
}

/// Outbound `PATH_OPEN` setup request builder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupRequest<'a> {
    /// Non-zero transaction ID.
    pub transaction_id: u64,
    /// `Create` or `Join`.
    pub mode: SetupMode,
    /// `Layered`, `VipRouted`, or `Telescoping`.
    pub route_mode: RelayRouteMode,
    /// Circuit key (`opener_role` + `sequence`).
    pub circuit: SetupCircuitKey,
    /// Optional 64-bit destination VIP.
    pub destination_vip: Option<u64>,
    /// Optional reverse CID allocated by the previous hop.
    pub previous_reverse_cid: Option<ConnectionId>,
    /// Ordered setup instruction blocks.
    pub blocks: &'a [SetupBlock<'a>],
}

impl SetupRequest<'_> {
    /// Encode a complete connectionless long-header `PATH_OPEN` packet into `output`.
    pub fn encode_packet(&self, output: &mut [u8]) -> Result<usize, RelayError> {
        let mut body = [0u8; MAX_SETUP_BODY_BYTES];
        let body_len = self.encode(&mut body)?;
        encode_long_packet(
            LONG_PACKET_PATH_OPEN,
            None,
            None,
            0,
            1,
            &body[..body_len],
            output,
        )
    }

    /// Encode only the `PATH_OPEN` body into `output`.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, RelayError> {
        if self.transaction_id == 0
            || self.circuit.sequence == 0
            || self.blocks.is_empty()
            || self.blocks.len() > MAX_SETUP_BLOCKS
            || self.destination_vip == Some(0)
            || self
                .previous_reverse_cid
                .is_some_and(|cid| cid.value() == 0)
            || self.blocks.iter().any(|block| {
                block.kind == 0
                    || block.version == 0
                    || block.protection != 0
                    || block.payload.is_empty()
                    || block.payload.len() > MAX_SETUP_BLOCK_BYTES
            })
        {
            return Err(RelayError::Invalid);
        }
        let mut pos = 0usize;
        put_setup_byte(output, &mut pos, SETUP_REQUEST_VERSION)?;
        pos += put_varint(self.transaction_id, &mut output[pos..])?;
        put_setup_byte(
            output,
            &mut pos,
            match self.mode {
                SetupMode::Create => 0,
                SetupMode::Join => 1,
            },
        )?;
        put_setup_byte(
            output,
            &mut pos,
            match self.route_mode {
                RelayRouteMode::Layered => 0,
                RelayRouteMode::VipRouted => 1,
                RelayRouteMode::Telescoping => 2,
            },
        )?;
        put_setup_byte(
            output,
            &mut pos,
            match self.circuit.opener_role {
                Role::Client => 0,
                Role::Server => 1,
            },
        )?;
        pos += put_varint(self.circuit.sequence, &mut output[pos..])?;
        match self.destination_vip {
            Some(vip) => {
                put_setup_byte(output, &mut pos, 1)?;
                if output.len().saturating_sub(pos) < 8 {
                    return Err(RelayError::BufferTooSmall);
                }
                output[pos..pos + 8].copy_from_slice(&vip.to_be_bytes());
                pos += 8;
            }
            None => put_setup_byte(output, &mut pos, 0)?,
        }
        match self.previous_reverse_cid {
            Some(cid) => {
                put_setup_byte(output, &mut pos, 1)?;
                pos += cid.encode(&mut output[pos..])?;
            }
            None => put_setup_byte(output, &mut pos, 0)?,
        }
        pos += put_varint(self.blocks.len() as u64, &mut output[pos..])?;
        for block in self.blocks {
            put_setup_byte(output, &mut pos, block.kind)?;
            put_setup_byte(output, &mut pos, block.version)?;
            put_setup_byte(output, &mut pos, block.protection)?;
            pos += put_varint(block.payload.len() as u64, &mut output[pos..])?;
            if output.len().saturating_sub(pos) < block.payload.len() {
                return Err(RelayError::BufferTooSmall);
            }
            output[pos..pos + block.payload.len()].copy_from_slice(block.payload);
            pos += block.payload.len();
            if pos > MAX_SETUP_BODY_BYTES {
                return Err(RelayError::Invalid);
            }
        }
        Ok(pos)
    }

    /// Decode a `PATH_OPEN` body into a borrowed [`SetupRequestView`].
    pub fn decode(input: &[u8]) -> Result<SetupRequestView<'_>, RelayError> {
        if input.len() > MAX_SETUP_BODY_BYTES
            || !matches!(
                input.first().copied(),
                Some(SETUP_VERSION | SETUP_REQUEST_VERSION)
            )
        {
            return Err(RelayError::Invalid);
        }
        let version = input[0];
        let mut pos = 1usize;
        let (transaction_id, used) = get_varint(&input[pos..])?;
        pos += used;
        let mode = match take_setup_byte(input, &mut pos)? {
            0 => SetupMode::Create,
            1 => SetupMode::Join,
            _ => return Err(RelayError::Invalid),
        };
        let route_mode = if version == SETUP_VERSION {
            RelayRouteMode::Layered
        } else {
            match take_setup_byte(input, &mut pos)? {
                0 => RelayRouteMode::Layered,
                1 => RelayRouteMode::VipRouted,
                2 => RelayRouteMode::Telescoping,
                _ => return Err(RelayError::Invalid),
            }
        };
        let opener_role = match take_setup_byte(input, &mut pos)? {
            0 => Role::Client,
            1 => Role::Server,
            _ => return Err(RelayError::Invalid),
        };
        let (sequence, used) = get_varint(&input[pos..])?;
        pos += used;
        let destination_vip = match take_setup_byte(input, &mut pos)? {
            0 => None,
            1 => {
                if input.len().saturating_sub(pos) < 8 {
                    return Err(RelayError::Invalid);
                }
                let vip = u64::from_be_bytes(
                    input[pos..pos + 8]
                        .try_into()
                        .map_err(|_| RelayError::Invalid)?,
                );
                pos += 8;
                if vip == 0 {
                    return Err(RelayError::Invalid);
                }
                Some(vip)
            }
            _ => return Err(RelayError::Invalid),
        };
        let previous_reverse_cid = match take_setup_byte(input, &mut pos)? {
            0 => None,
            1 => {
                let (cid, used) = ConnectionId::decode(&input[pos..])?;
                pos += used;
                if cid.value() == 0 {
                    return Err(RelayError::Invalid);
                }
                Some(cid)
            }
            _ => return Err(RelayError::Invalid),
        };
        let (block_count, used) = get_varint(&input[pos..])?;
        pos += used;
        let block_count = usize::try_from(block_count).map_err(|_| RelayError::Invalid)?;
        if transaction_id == 0
            || sequence == 0
            || block_count == 0
            || block_count > MAX_SETUP_BLOCKS
        {
            return Err(RelayError::Invalid);
        }
        let blocks_start = pos;
        for _ in 0..block_count {
            let kind = take_setup_byte(input, &mut pos)?;
            let block_version = take_setup_byte(input, &mut pos)?;
            let protection = take_setup_byte(input, &mut pos)?;
            let (len, used) = get_varint(&input[pos..])?;
            pos += used;
            let len = usize::try_from(len).map_err(|_| RelayError::Invalid)?;
            if kind == 0
                || block_version == 0
                || protection != 0
                || len == 0
                || len > MAX_SETUP_BLOCK_BYTES
                || input.len().saturating_sub(pos) < len
            {
                return Err(RelayError::Invalid);
            }
            pos += len;
        }
        if pos != input.len() {
            return Err(RelayError::Invalid);
        }
        Ok(SetupRequestView {
            version,
            transaction_id,
            mode,
            route_mode,
            circuit: SetupCircuitKey {
                opener_role,
                sequence,
            },
            destination_vip,
            previous_reverse_cid,
            blocks: SetupBlockBytes {
                bytes: &input[blocks_start..],
                count: block_count,
            },
            raw: input,
        })
    }
}

/// Decode a complete connectionless long-header `PATH_OPEN` packet.
pub fn decode_setup_request_packet(input: &[u8]) -> Result<SetupRequestView<'_>, RelayError> {
    let (header, body_at, body_len) = decode_long_packet(input)?;
    if header.packet_type != LONG_PACKET_PATH_OPEN || header.dcid.is_some() || header.scid.is_some()
    {
        return Err(RelayError::Invalid);
    }
    SetupRequest::decode(&input[body_at..body_at + body_len])
}

/// Borrowed slice of validated setup blocks inside a [`SetupRequestView`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupBlockBytes<'a> {
    bytes: &'a [u8],
    count: usize,
}

impl<'a> SetupBlockBytes<'a> {
    /// Number of setup blocks.
    pub fn count(self) -> usize {
        self.count
    }

    /// Raw encoded bytes of all remaining setup blocks.
    pub fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Decode the `index`-th setup block.
    pub fn get(self, index: usize) -> Option<Result<SetupBlock<'a>, RelayError>> {
        if index >= self.count {
            return None;
        }
        let mut pos = 0usize;
        for current in 0..=index {
            let kind = take_setup_byte(self.bytes, &mut pos).ok()?;
            let version = take_setup_byte(self.bytes, &mut pos).ok()?;
            let protection = take_setup_byte(self.bytes, &mut pos).ok()?;
            let (len, used) = get_varint(&self.bytes[pos..]).ok()?;
            pos += used;
            let len = usize::try_from(len).ok()?;
            let end = pos.checked_add(len)?;
            let payload = self.bytes.get(pos..end)?;
            if current == index {
                return Some(Ok(SetupBlock {
                    kind,
                    version,
                    protection,
                    payload,
                }));
            }
            pos = end;
        }
        None
    }
}

/// Borrowed view of a decoded `PATH_OPEN` request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupRequestView<'a> {
    version: u8,
    /// Non-zero transaction ID.
    pub transaction_id: u64,
    /// `Create` or `Join`.
    pub mode: SetupMode,
    /// `Layered`, `VipRouted`, or `Telescoping`.
    pub route_mode: RelayRouteMode,
    /// Circuit key (`opener_role` + `sequence`).
    pub circuit: SetupCircuitKey,
    /// Optional 64-bit destination VIP.
    pub destination_vip: Option<u64>,
    /// Optional reverse CID from the previous hop.
    pub previous_reverse_cid: Option<ConnectionId>,
    /// Validated setup instruction blocks.
    pub blocks: SetupBlockBytes<'a>,
    raw: &'a [u8],
}

impl<'a> SetupRequestView<'a> {
    /// Raw encoded body slice of this request.
    pub fn request_body(self) -> &'a [u8] {
        self.raw
    }

    /// Decode this relay's leading instruction block (`SETUP_BLOCK_RELAY`).
    pub fn current_hop_instruction(self) -> Result<SetupHopInstruction, RelayError> {
        let block = self.blocks.get(0).ok_or(RelayError::Invalid)??;
        if block.kind != SETUP_BLOCK_RELAY || block.version != 1 || block.protection != 0 {
            return Err(RelayError::Invalid);
        }
        SetupHopInstruction::decode(block.payload)
    }

    /// Re-encode this request after consuming the first relay instruction block.
    pub fn encode_after_first_block(self, output: &mut [u8]) -> Result<usize, RelayError> {
        self.encode_after_first_block_with_reverse_cid(self.previous_reverse_cid, output)
    }

    /// Re-encode this request after consuming the first relay block and substituting `previous_reverse_cid`.
    pub fn encode_after_first_block_with_reverse_cid(
        self,
        previous_reverse_cid: Option<ConnectionId>,
        output: &mut [u8],
    ) -> Result<usize, RelayError> {
        let consumed_blocks = usize::from(self.route_mode != RelayRouteMode::Telescoping);
        if self.blocks.count <= consumed_blocks {
            return Err(RelayError::Invalid);
        }
        let _ = self.current_hop_instruction()?;
        let mut block_pos = 0usize;
        for _ in 0..consumed_blocks {
            let _ = take_setup_byte(self.blocks.bytes, &mut block_pos)?;
            let _ = take_setup_byte(self.blocks.bytes, &mut block_pos)?;
            let _ = take_setup_byte(self.blocks.bytes, &mut block_pos)?;
            let (block_len, used) = get_varint(&self.blocks.bytes[block_pos..])?;
            block_pos += used;
            let block_len = usize::try_from(block_len).map_err(|_| RelayError::Invalid)?;
            block_pos = block_pos
                .checked_add(block_len)
                .filter(|end| *end <= self.blocks.bytes.len())
                .ok_or(RelayError::Invalid)?;
        }

        let mut pos = 0usize;
        put_setup_byte(output, &mut pos, self.version)?;
        pos += put_varint(self.transaction_id, &mut output[pos..])?;
        put_setup_byte(
            output,
            &mut pos,
            match self.mode {
                SetupMode::Create => 0,
                SetupMode::Join => 1,
            },
        )?;
        if self.version >= SETUP_REQUEST_VERSION {
            put_setup_byte(
                output,
                &mut pos,
                match self.route_mode {
                    RelayRouteMode::Layered => 0,
                    RelayRouteMode::VipRouted => 1,
                    RelayRouteMode::Telescoping => 2,
                },
            )?;
        }
        put_setup_byte(
            output,
            &mut pos,
            match self.circuit.opener_role {
                Role::Client => 0,
                Role::Server => 1,
            },
        )?;
        pos += put_varint(self.circuit.sequence, &mut output[pos..])?;
        match self.destination_vip {
            Some(vip) => {
                put_setup_byte(output, &mut pos, 1)?;
                if output.len().saturating_sub(pos) < 8 {
                    return Err(RelayError::BufferTooSmall);
                }
                output[pos..pos + 8].copy_from_slice(&vip.to_be_bytes());
                pos += 8;
            }
            None => put_setup_byte(output, &mut pos, 0)?,
        }
        match previous_reverse_cid {
            Some(cid) => {
                put_setup_byte(output, &mut pos, 1)?;
                pos += cid.encode(&mut output[pos..])?;
            }
            None => put_setup_byte(output, &mut pos, 0)?,
        }
        pos += put_varint(
            (self.blocks.count - consumed_blocks) as u64,
            &mut output[pos..],
        )?;
        let remaining = &self.blocks.bytes[block_pos..];
        if output.len().saturating_sub(pos) < remaining.len() {
            return Err(RelayError::BufferTooSmall);
        }
        output[pos..pos + remaining.len()].copy_from_slice(remaining);
        pos += remaining.len();
        if pos > MAX_SETUP_BODY_BYTES {
            return Err(RelayError::Invalid);
        }
        Ok(pos)
    }

    /// Encode a complete `PATH_OPEN` packet after consuming the first relay block.
    pub fn encode_packet_after_first_block_with_reverse_cid(
        self,
        previous_reverse_cid: Option<ConnectionId>,
        output: &mut [u8],
    ) -> Result<usize, RelayError> {
        let mut body = [0u8; MAX_SETUP_BODY_BYTES];
        let body_len =
            self.encode_after_first_block_with_reverse_cid(previous_reverse_cid, &mut body)?;
        encode_long_packet(
            LONG_PACKET_PATH_OPEN,
            None,
            None,
            0,
            1,
            &body[..body_len],
            output,
        )
    }
}

/// Outcome carried by a [`SetupReply`] (`PATH_OPEN_ACK`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupResult {
    /// Setup was accepted with the upstream entry `endpoint_cid` and `lease_us`.
    Accepted {
        /// Entry CID for the upstream hop.
        endpoint_cid: ConnectionId,
        /// Granted lease duration in microseconds.
        lease_us: u64,
    },
    /// Setup was rejected with a non-zero error `code`.
    Rejected {
        /// Non-zero rejection code.
        code: u64,
    },
}

/// Embedded bootstrap `OPEN_ACK` carried inside an accepted `CREATE` [`SetupReply`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupBootstrapAck {
    len: u8,
    bytes: [u8; MAX_SETUP_BOOTSTRAP_ACK_BYTES],
}

impl SetupBootstrapAck {
    /// Copy `input` (`1..=128` bytes) into a [`SetupBootstrapAck`].
    pub fn from_slice(input: &[u8]) -> Result<Self, RelayError> {
        if input.is_empty() || input.len() > MAX_SETUP_BOOTSTRAP_ACK_BYTES {
            return Err(RelayError::Invalid);
        }
        let mut bytes = [0u8; MAX_SETUP_BOOTSTRAP_ACK_BYTES];
        bytes[..input.len()].copy_from_slice(input);
        Ok(Self {
            len: input.len() as u8,
            bytes,
        })
    }

    /// Borrow the encoded bootstrap `OPEN_ACK` bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// Ordered list of forward relay CIDs accumulated along a `PATH_OPEN_ACK` return path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupRelayCids {
    len: u8,
    cids: [Option<ConnectionId>; MAX_SETUP_BLOCKS - 1],
}

impl SetupRelayCids {
    /// Construct an empty [`SetupRelayCids`].
    pub const fn empty() -> Self {
        Self {
            len: 0,
            cids: [None; MAX_SETUP_BLOCKS - 1],
        }
    }

    /// Return the first (most recently prepended) CID, if any.
    pub fn first(self) -> Option<ConnectionId> {
        self.cids.first().copied().flatten()
    }

    /// Number of relay CIDs in the list.
    pub fn count(self) -> usize {
        usize::from(self.len)
    }

    /// Return the `index`-th relay CID.
    pub fn get(self, index: usize) -> Option<ConnectionId> {
        self.cids
            .get(index)
            .copied()
            .flatten()
            .filter(|_| index < usize::from(self.len))
    }

    /// Prepend `cid` to the front of the list as `PATH_OPEN_ACK` travels upstream.
    pub fn prepend(&mut self, cid: ConnectionId) -> Result<(), RelayError> {
        let len = usize::from(self.len);
        if cid.value() == 0 || len >= self.cids.len() {
            return Err(RelayError::Invalid);
        }
        for index in (0..len).rev() {
            self.cids[index + 1] = self.cids[index];
        }
        self.cids[0] = Some(cid);
        self.len += 1;
        Ok(())
    }

    fn encode(self, output: &mut [u8]) -> Result<usize, RelayError> {
        let mut pos = put_varint(u64::from(self.len), output)?;
        for index in 0..usize::from(self.len) {
            let cid = self.cids[index].ok_or(RelayError::Invalid)?;
            pos += cid.encode(&mut output[pos..])?;
        }
        Ok(pos)
    }

    fn decode(input: &[u8], pos: &mut usize) -> Result<Self, RelayError> {
        let (len, used) = get_varint(&input[*pos..])?;
        *pos += used;
        let len = usize::try_from(len).map_err(|_| RelayError::Invalid)?;
        if len > MAX_SETUP_BLOCKS - 1 {
            return Err(RelayError::Invalid);
        }
        let mut cids = Self::empty();
        for index in 0..len {
            let (cid, used) = ConnectionId::decode(&input[*pos..])?;
            *pos += used;
            if cid.value() == 0 {
                return Err(RelayError::Invalid);
            }
            cids.cids[index] = Some(cid);
        }
        cids.len = len as u8;
        Ok(cids)
    }
}

/// Decoded or outbound `PATH_OPEN_ACK` setup reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupReply {
    /// Echoed non-zero transaction ID.
    pub transaction_id: u64,
    /// Echoed circuit key.
    pub circuit: SetupCircuitKey,
    /// `Accepted` or `Rejected`.
    pub result: SetupResult,
    /// Optional embedded `OPEN_ACK` for `CREATE` requests.
    pub bootstrap_ack: Option<SetupBootstrapAck>,
    /// Accumulated hop CIDs.
    pub relay_cids: SetupRelayCids,
}

impl SetupReply {
    /// Encode a complete connectionless `PATH_OPEN_ACK` long-header packet into `output`.
    pub fn encode_packet(self, output: &mut [u8]) -> Result<usize, RelayError> {
        let mut body = [0u8; DEFAULT_SETUP_REPLY_BYTES];
        let body_len = self.encode(&mut body)?;
        encode_long_packet(
            LONG_PACKET_PATH_OPEN_ACK,
            None,
            None,
            0,
            1,
            &body[..body_len],
            output,
        )
    }

    /// Encode only the `PATH_OPEN_ACK` body into `output`.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, RelayError> {
        if self.transaction_id == 0 || self.circuit.sequence == 0 {
            return Err(RelayError::Invalid);
        }
        let mut pos = 0usize;
        put_setup_byte(output, &mut pos, SETUP_VERSION)?;
        pos += put_varint(self.transaction_id, &mut output[pos..])?;
        put_setup_byte(
            output,
            &mut pos,
            match self.circuit.opener_role {
                Role::Client => 0,
                Role::Server => 1,
            },
        )?;
        pos += put_varint(self.circuit.sequence, &mut output[pos..])?;
        match self.result {
            SetupResult::Accepted {
                endpoint_cid,
                lease_us,
            } if endpoint_cid.value() != 0 && lease_us != 0 => {
                put_setup_byte(output, &mut pos, 0)?;
                pos += endpoint_cid.encode(&mut output[pos..])?;
                pos += put_varint(lease_us, &mut output[pos..])?;
            }
            SetupResult::Rejected { code } => {
                if code == 0 {
                    return Err(RelayError::Invalid);
                }
                put_setup_byte(output, &mut pos, 1)?;
                pos += put_varint(code, &mut output[pos..])?;
            }
            SetupResult::Accepted { .. } => return Err(RelayError::Invalid),
        }
        match (self.result, self.bootstrap_ack) {
            (SetupResult::Accepted { .. }, Some(ack)) => {
                put_setup_byte(output, &mut pos, 1)?;
                pos += put_varint(ack.as_bytes().len() as u64, &mut output[pos..])?;
                if output.len().saturating_sub(pos) < ack.as_bytes().len() {
                    return Err(RelayError::BufferTooSmall);
                }
                output[pos..pos + ack.as_bytes().len()].copy_from_slice(ack.as_bytes());
                pos += ack.as_bytes().len();
            }
            (SetupResult::Accepted { .. }, None) | (SetupResult::Rejected { .. }, None) => {
                put_setup_byte(output, &mut pos, 0)?;
            }
            (SetupResult::Rejected { .. }, Some(_)) => return Err(RelayError::Invalid),
        }
        if matches!(self.result, SetupResult::Rejected { .. }) && self.relay_cids.len != 0 {
            return Err(RelayError::Invalid);
        }
        pos += self.relay_cids.encode(&mut output[pos..])?;
        if pos > MAX_SETUP_BODY_BYTES {
            return Err(RelayError::Invalid);
        }
        Ok(pos)
    }

    /// Decode a `PATH_OPEN_ACK` body from `input`.
    pub fn decode(input: &[u8]) -> Result<Self, RelayError> {
        if input.len() > MAX_SETUP_BODY_BYTES || input.first().copied() != Some(SETUP_VERSION) {
            return Err(RelayError::Invalid);
        }
        let mut pos = 1usize;
        let (transaction_id, used) = get_varint(&input[pos..])?;
        pos += used;
        let opener_role = match take_setup_byte(input, &mut pos)? {
            0 => Role::Client,
            1 => Role::Server,
            _ => return Err(RelayError::Invalid),
        };
        let (sequence, used) = get_varint(&input[pos..])?;
        pos += used;
        let result = match take_setup_byte(input, &mut pos)? {
            0 => {
                let (endpoint_cid, used) = ConnectionId::decode(&input[pos..])?;
                if endpoint_cid.value() == 0 {
                    return Err(RelayError::Invalid);
                }
                pos += used;
                let (lease_us, used) = get_varint(&input[pos..])?;
                pos += used;
                if lease_us == 0 {
                    return Err(RelayError::Invalid);
                }
                SetupResult::Accepted {
                    endpoint_cid,
                    lease_us,
                }
            }
            1 => {
                let (code, used) = get_varint(&input[pos..])?;
                pos += used;
                if code == 0 {
                    return Err(RelayError::Invalid);
                }
                SetupResult::Rejected { code }
            }
            _ => return Err(RelayError::Invalid),
        };
        let bootstrap_ack = match take_setup_byte(input, &mut pos)? {
            0 => None,
            1 => {
                let (len, used) = get_varint(&input[pos..])?;
                pos += used;
                let len = usize::try_from(len).map_err(|_| RelayError::Invalid)?;
                let end = pos
                    .checked_add(len)
                    .filter(|end| *end <= input.len())
                    .ok_or(RelayError::Invalid)?;
                let ack = SetupBootstrapAck::from_slice(&input[pos..end])?;
                pos = end;
                Some(ack)
            }
            _ => return Err(RelayError::Invalid),
        };
        let relay_cids = SetupRelayCids::decode(input, &mut pos)?;
        if matches!(result, SetupResult::Rejected { .. }) && bootstrap_ack.is_some() {
            return Err(RelayError::Invalid);
        }
        if matches!(result, SetupResult::Rejected { .. }) && relay_cids.len != 0 {
            return Err(RelayError::Invalid);
        }
        if transaction_id == 0 || sequence == 0 || pos != input.len() {
            return Err(RelayError::Invalid);
        }
        Ok(Self {
            transaction_id,
            circuit: SetupCircuitKey {
                opener_role,
                sequence,
            },
            result,
            bootstrap_ack,
            relay_cids,
        })
    }
}

/// Decode a complete connectionless long-header `PATH_OPEN_ACK` packet.
pub fn decode_setup_reply_packet(input: &[u8]) -> Result<SetupReply, RelayError> {
    let (header, body_at, body_len) = decode_long_packet(input)?;
    if header.packet_type != LONG_PACKET_PATH_OPEN_ACK
        || header.dcid.is_some()
        || header.scid.is_some()
    {
        return Err(RelayError::Invalid);
    }
    SetupReply::decode(&input[body_at..body_at + body_len])
}

fn put_setup_byte(output: &mut [u8], pos: &mut usize, value: u8) -> Result<(), RelayError> {
    let Some(byte) = output.get_mut(*pos) else {
        return Err(RelayError::BufferTooSmall);
    };
    *byte = value;
    *pos += 1;
    Ok(())
}

fn take_setup_byte(input: &[u8], pos: &mut usize) -> Result<u8, RelayError> {
    let Some(byte) = input.get(*pos).copied() else {
        return Err(RelayError::Invalid);
    };
    *pos += 1;
    Ok(byte)
}

/// Target stored in a [`DcidRegistry`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DcidTarget<Endpoint, NextHop> {
    /// Local endpoint owner.
    Endpoint(Endpoint),
    /// Opaque forwarding rule.
    Forward(ForwardRule<NextHop>),
}

/// Error returned by [`DcidRegistry`] operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcidRegistryError {
    /// Connection ID is zero (`0` is reserved for empty long-header destinations).
    InvalidConnectionId,
    /// Connection ID or lease group is already occupied.
    Occupied,
    /// Registry has reached `max_entries` or heap allocation failed.
    Full,
    /// Connection ID was not found in the registry.
    Missing,
    /// Target kind does not match the requested operation (e.g. updating an endpoint as a forward rule).
    WrongTarget,
    /// Paired forward rules have mismatched lease/quota fields or zero `lease_group_id`.
    InvalidLeaseGroup,
}

/// Result of a DCID lookup in [`DcidRegistry::ingress`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcidIngress<'a, Endpoint, NextHop> {
    /// Packet targets a local endpoint.
    Endpoint(ShortHeaderPrefix, &'a Endpoint),
    /// Packet targets a forwarding rule.
    Forward(ShortHeaderPrefix, &'a ForwardRule<NextHop>),
}

/// Target classification returned by [`PacketRouter::target`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouterTarget<'a, Endpoint, NextHop> {
    /// Local endpoint owner.
    Endpoint(&'a Endpoint),
    /// Opaque forwarding rule.
    Forward(&'a ForwardRule<NextHop>),
    /// Unknown DCID.
    Missing,
}

/// Outcome of classifying and rewriting one packet via [`dispatch_packet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcidPacket<'a, Endpoint, NextHop> {
    /// Packet belongs to a local `endpoint`.
    Endpoint {
        /// Destination CID decoded from the packet.
        received_dcid: ConnectionId,
        /// Registered endpoint handle.
        endpoint: &'a Endpoint,
    },
    /// Packet matched a forwarding `rule` and was rewritten into `output[..used]`.
    Forward {
        /// Inbound DCID before rewriting.
        received_dcid: ConnectionId,
        /// Matched forwarding rule.
        rule: &'a ForwardRule<NextHop>,
        /// Number of rewritten bytes written into `output`.
        used: usize,
    },
}

/// Outcome of zero-copy in-place [`PoolPacket`] dispatch via [`dispatch_pool_packet`].
#[derive(Debug, PartialEq, Eq)]
pub enum DcidPoolPacket<'a, P, Endpoint, NextHop> {
    /// Packet belongs to a local `endpoint` (returned unmodified).
    Endpoint {
        /// Destination CID decoded from the packet.
        received_dcid: ConnectionId,
        /// Registered endpoint handle.
        endpoint: &'a Endpoint,
        /// Unmodified pool packet.
        packet: P,
    },
    /// Packet matched a forwarding `rule` and its short-header DCID was rewritten in-place.
    Forward {
        /// Inbound DCID before rewriting.
        received_dcid: ConnectionId,
        /// Matched forwarding rule.
        rule: &'a ForwardRule<NextHop>,
        /// Rewritten pool packet ready for egress submission.
        packet: P,
    },
}

/// Failure while classifying or rewriting a packet in [`dispatch_packet`] / [`dispatch_pool_packet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcidPacketError {
    /// Packet header could not be parsed.
    Header(RelayError),
    /// DCID was not found in the registry.
    Registry(DcidRegistryError),
    /// Outbound DCID rewrite failed (e.g. insufficient headroom or buffer capacity).
    Rewrite(RelayError),
}

/// Classify one packet against `registry` and rewrite its DCID into `output` when it matches a
/// [`ForwardRule`].
pub fn dispatch_packet<'a, Endpoint, NextHop>(
    registry: &'a DcidRegistry<Endpoint, NextHop>,
    input: &'a [u8],
    output: &mut [u8],
) -> Result<DcidPacket<'a, Endpoint, NextHop>, DcidPacketError> {
    let prefix = decode_routing_prefix(input).map_err(DcidPacketError::Header)?;
    match registry
        .ingress(prefix)
        .map_err(DcidPacketError::Registry)?
    {
        DcidIngress::Endpoint(prefix, endpoint) => Ok(DcidPacket::Endpoint {
            received_dcid: prefix.dcid,
            endpoint,
        }),
        DcidIngress::Forward(_, rule) => {
            let used = match rule.destination {
                ForwardDestination::Connection(dcid) => rewrite_dcid(input, dcid, output),
                ForwardDestination::Bootstrap => rewrite_bootstrap_destination(input, output),
            }
            .map_err(DcidPacketError::Rewrite)?;
            Ok(DcidPacket::Forward {
                received_dcid: prefix.dcid,
                rule,
                used,
            })
        }
    }
}

/// Classify one [`PoolPacket`] against `registry` and rewrite its short-header DCID in-place
/// (zero-copy) when it matches a [`ForwardDestination::Connection`] rule.
pub fn dispatch_pool_packet<'a, P: PoolPacket, Endpoint, NextHop>(
    registry: &'a DcidRegistry<Endpoint, NextHop>,
    packet: P,
    prefix_required: usize,
    max_packet: usize,
) -> Result<DcidPoolPacket<'a, P, Endpoint, NextHop>, (DcidPacketError, P)> {
    let prefix = match decode_routing_prefix(packet.bytes()) {
        Ok(p) => p,
        Err(e) => return Err((DcidPacketError::Header(e), packet)),
    };
    match registry.ingress(prefix) {
        Ok(DcidIngress::Endpoint(prefix, endpoint)) => Ok(DcidPoolPacket::Endpoint {
            received_dcid: prefix.dcid,
            endpoint,
            packet,
        }),
        Ok(DcidIngress::Forward(_, rule)) => match rule.destination {
            ForwardDestination::Connection(dcid) => {
                match rewrite_dcid_in_place(packet, dcid, prefix_required, max_packet) {
                    Ok(rewritten) => Ok(DcidPoolPacket::Forward {
                        received_dcid: prefix.dcid,
                        rule,
                        packet: rewritten,
                    }),
                    Err((e, pkt)) => Err((DcidPacketError::Rewrite(e), pkt)),
                }
            }
            ForwardDestination::Bootstrap => {
                Err((DcidPacketError::Rewrite(RelayError::Invalid), packet))
            }
        },
        Err(e) => Err((DcidPacketError::Registry(e), packet)),
    }
}

/// Sorted, capacity-limited registry for all non-zero local DCIDs (`Endpoint` and `ForwardRule`).
#[derive(Clone, Debug)]
pub struct DcidRegistry<Endpoint, NextHop> {
    entries: Vec<(ConnectionId, DcidTarget<Endpoint, NextHop>)>,
    max_entries: usize,
}

impl<Endpoint, NextHop> Default for DcidRegistry<Endpoint, NextHop> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Endpoint, NextHop> DcidRegistry<Endpoint, NextHop> {
    /// Construct an empty [`DcidRegistry`].
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            max_entries: usize::MAX,
        }
    }

    /// Construct an empty [`DcidRegistry`] with an explicit `max_entries` ceiling.
    pub const fn with_max_entries(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
        }
    }

    /// Configured maximum number of entries allowed in the registry.
    pub const fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Set the maximum number of entries allowed in the registry.
    pub fn set_max_entries(&mut self, max_entries: usize) {
        self.max_entries = max_entries;
    }

    /// Number of entries currently registered.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Earliest `lease_expires_at_us` across all forward rules.
    pub fn next_forward_lease_deadline(&self) -> Option<u64> {
        self.entries
            .iter()
            .filter_map(|(_, target)| match target {
                DcidTarget::Forward(rule) => Some(rule.lease_expires_at_us),
                DcidTarget::Endpoint(_) => None,
            })
            .min()
    }

    /// Remove all forward rules whose `lease_expires_at_us <= now_us`, returning the count removed.
    pub fn expire_forward_leases(&mut self, now_us: u64) -> usize {
        let previous_len = self.entries.len();
        self.entries.retain(|(_, target)| match target {
            DcidTarget::Forward(rule) => rule.lease_expires_at_us > now_us,
            DcidTarget::Endpoint(_) => true,
        });
        previous_len - self.entries.len()
    }

    /// Whether `dcid` is currently registered.
    pub fn contains(&self, dcid: ConnectionId) -> bool {
        self.find(dcid).is_ok()
    }

    /// Register a local `endpoint` at `dcid`.
    pub fn insert_endpoint(
        &mut self,
        dcid: ConnectionId,
        endpoint: Endpoint,
    ) -> Result<(), DcidRegistryError> {
        self.insert(dcid, DcidTarget::Endpoint(endpoint))
    }

    /// Install a standalone (`lease_group_id == 0`) forwarding rule at `dcid`.
    pub fn install_forward(
        &mut self,
        dcid: ConnectionId,
        rule: ForwardRule<NextHop>,
    ) -> Result<(), DcidRegistryError> {
        if rule.lease_group_id != 0 {
            return Err(DcidRegistryError::InvalidLeaseGroup);
        }
        self.insert(dcid, DcidTarget::Forward(rule))
    }

    /// Atomically install a bidirectional pair of forwarding rules sharing a non-zero `lease_group_id`.
    pub fn install_forward_pair(
        &mut self,
        first_cid: ConnectionId,
        first_rule: ForwardRule<NextHop>,
        second_cid: ConnectionId,
        second_rule: ForwardRule<NextHop>,
    ) -> Result<(), DcidRegistryError> {
        if first_cid.value() == 0 || second_cid.value() == 0 {
            return Err(DcidRegistryError::InvalidConnectionId);
        }
        if first_cid == second_cid
            || first_rule.lease_group_id == 0
            || first_rule.lease_group_id != second_rule.lease_group_id
            || first_rule.lease_duration_us != second_rule.lease_duration_us
            || first_rule.lease_expires_at_us != second_rule.lease_expires_at_us
            || first_rule.packet_quota != second_rule.packet_quota
            || first_rule.forwarded_packets != 0
            || second_rule.forwarded_packets != 0
            || first_rule.forwarded_control_packets != 0
            || second_rule.forwarded_control_packets != 0
        {
            return Err(DcidRegistryError::InvalidLeaseGroup);
        }
        if self.entries.iter().any(|(_, target)| {
            matches!(target, DcidTarget::Forward(rule) if rule.lease_group_id == first_rule.lease_group_id)
        }) {
            return Err(DcidRegistryError::Occupied);
        }
        if self.find(first_cid).is_ok() || self.find(second_cid).is_ok() {
            return Err(DcidRegistryError::Occupied);
        }
        if self.entries.len().saturating_add(2) > self.max_entries {
            return Err(DcidRegistryError::Full);
        }
        self.entries
            .try_reserve(2)
            .map_err(|_| DcidRegistryError::Full)?;

        let (low_cid, low_rule, high_cid, high_rule) = if first_cid < second_cid {
            (first_cid, first_rule, second_cid, second_rule)
        } else {
            (second_cid, second_rule, first_cid, first_rule)
        };
        let low_index = self.find(low_cid).unwrap_err();
        self.entries
            .insert(low_index, (low_cid, DcidTarget::Forward(low_rule)));
        let high_index = self.find(high_cid).unwrap_err();
        self.entries
            .insert(high_index, (high_cid, DcidTarget::Forward(high_rule)));
        Ok(())
    }

    /// Remove a paired bidirectional forwarding rule set.
    pub fn remove_forward_pair(&mut self, first_cid: ConnectionId, second_cid: ConnectionId) -> bool {
        let (Ok(first_index), Ok(second_index)) = (self.find(first_cid), self.find(second_cid))
        else {
            return false;
        };
        let (DcidTarget::Forward(first), DcidTarget::Forward(second)) =
            (&self.entries[first_index].1, &self.entries[second_index].1)
        else {
            return false;
        };
        if first_cid == second_cid
            || first.lease_group_id == 0
            || first.lease_group_id != second.lease_group_id
        {
            return false;
        }
        let group = first.lease_group_id;
        self.entries.retain(|(_, target)| {
            !matches!(target, DcidTarget::Forward(rule) if rule.lease_group_id == group)
        });
        true
    }

    /// Install a forward rule once, or accept an exact duplicate as an idempotent control retry.
    pub fn install_forward_idempotent(
        &mut self,
        dcid: ConnectionId,
        rule: ForwardRule<NextHop>,
    ) -> Result<bool, DcidRegistryError>
    where
        NextHop: Eq,
    {
        if dcid.value() == 0 {
            return Err(DcidRegistryError::InvalidConnectionId);
        }
        if let Ok(index) = self.find(dcid) {
            let target = &self.entries[index].1;
            return match target {
                DcidTarget::Forward(existing) if *existing == rule => Ok(false),
                _ => Err(DcidRegistryError::Occupied),
            };
        }
        self.insert(dcid, DcidTarget::Forward(rule))?;
        Ok(true)
    }

    /// Replace only an existing forwarding target.
    pub fn update_forward(
        &mut self,
        dcid: ConnectionId,
        rule: ForwardRule<NextHop>,
    ) -> Result<(), DcidRegistryError> {
        let Ok(index) = self.find(dcid) else {
            return Err(DcidRegistryError::Missing);
        };
        let target = &mut self.entries[index].1;
        if !matches!(target, DcidTarget::Forward(_)) {
            return Err(DcidRegistryError::WrongTarget);
        }
        *target = DcidTarget::Forward(rule);
        Ok(())
    }

    /// Remove and return the target registered at `dcid`.
    pub fn remove(&mut self, dcid: ConnectionId) -> Option<DcidTarget<Endpoint, NextHop>> {
        let index = self.find(dcid).ok()?;
        Some(self.entries.remove(index).1)
    }

    /// Look up the target for a decoded [`ShortHeaderPrefix`].
    pub fn ingress(
        &self,
        prefix: ShortHeaderPrefix,
    ) -> Result<DcidIngress<'_, Endpoint, NextHop>, DcidRegistryError> {
        let index = self
            .find(prefix.dcid)
            .map_err(|_| DcidRegistryError::Missing)?;
        let target = &self.entries[index].1;
        Ok(match target {
            DcidTarget::Endpoint(endpoint) => DcidIngress::Endpoint(prefix, endpoint),
            DcidTarget::Forward(rule) => DcidIngress::Forward(prefix, rule),
        })
    }

    fn find(&self, dcid: ConnectionId) -> Result<usize, usize> {
        self.entries.binary_search_by_key(&dcid, |(key, _)| *key)
    }

    fn endpoint_matching(&self, mut predicate: impl FnMut(&Endpoint) -> bool) -> Option<&Endpoint> {
        self.entries.iter().find_map(|(_, target)| match target {
            DcidTarget::Endpoint(endpoint) if predicate(endpoint) => Some(endpoint),
            _ => None,
        })
    }

    fn insert(
        &mut self,
        dcid: ConnectionId,
        target: DcidTarget<Endpoint, NextHop>,
    ) -> Result<(), DcidRegistryError> {
        if dcid.value() == 0 {
            return Err(DcidRegistryError::InvalidConnectionId);
        }
        let index = match self.find(dcid) {
            Ok(_) => return Err(DcidRegistryError::Occupied),
            Err(index) => index,
        };
        if self.entries.len() >= self.max_entries {
            return Err(DcidRegistryError::Full);
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| DcidRegistryError::Full)?;
        self.entries.insert(index, (dcid, target));
        Ok(())
    }
}

/// Configurable limits for [`PacketRouter`] (`DcidRegistry` + `SetupTransactionTable`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouterConfig {
    /// Maximum combined local endpoint and forward DCID entries in [`DcidRegistry`].
    pub max_entries: usize,
    /// Maximum concurrent pending `PATH_OPEN` transactions.
    pub max_pending_setups: usize,
    /// Maximum cached `PATH_OPEN_ACK` replies (including pending reservations).
    pub max_cached_setup_replies: usize,
    /// Maximum byte size of a `PATH_OPEN` request body.
    pub max_request_bytes: usize,
    /// Maximum byte size of a single cached `PATH_OPEN_ACK` reply.
    pub max_reply_bytes: usize,
    /// Total byte storage reserved across all pending/cached setup replies.
    pub max_reply_storage_bytes: usize,
    /// Retention window in microseconds for completed or expired setup transactions.
    pub reply_retention_us: u64,
}

impl RouterConfig {
    /// Embedded / low-RAM defaults matching `quic-lite` (`8` routes, `4` pending setups, `8` cached replies).
    pub const fn embedded() -> Self {
        Self {
            max_entries: 8,
            max_pending_setups: DEFAULT_MAX_PENDING_SETUPS,
            max_cached_setup_replies: DEFAULT_MAX_CACHED_SETUP_REPLIES,
            max_request_bytes: MAX_SETUP_BODY_BYTES,
            max_reply_bytes: DEFAULT_SETUP_REPLY_BYTES,
            max_reply_storage_bytes: DEFAULT_SETUP_REPLY_STORAGE_BYTES,
            reply_retention_us: DEFAULT_SETUP_REPLY_RETENTION_US,
        }
    }

    /// Host-scale defaults (`16,384` routes, `512` pending setups, `2,048` cached replies, `512 KiB` reply storage).
    pub const fn host() -> Self {
        Self {
            max_entries: 16_384,
            max_pending_setups: 512,
            max_cached_setup_replies: 2_048,
            max_request_bytes: MAX_SETUP_BODY_BYTES,
            max_reply_bytes: DEFAULT_SETUP_REPLY_BYTES,
            max_reply_storage_bytes: 512 * 1024,
            reply_retention_us: DEFAULT_SETUP_REPLY_RETENTION_US,
        }
    }
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self::embedded()
    }
}

/// Combined DCID namespace (`DcidRegistry`) and `PATH_OPEN` transaction manager (`SetupTransactionTable`).
pub struct PacketRouter<Endpoint, NextHop> {
    registry: DcidRegistry<Endpoint, NextHop>,
    setup_transactions: SetupTransactionTable,
}

impl<Endpoint, NextHop> Default for PacketRouter<Endpoint, NextHop> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Endpoint, NextHop> PacketRouter<Endpoint, NextHop> {
    /// Construct a new [`PacketRouter`] with default setup transaction limits.
    pub fn new() -> Self {
        Self {
            registry: DcidRegistry::new(),
            setup_transactions: SetupTransactionTable::new(
                DEFAULT_MAX_PENDING_SETUPS,
                DEFAULT_MAX_CACHED_SETUP_REPLIES,
                MAX_SETUP_BODY_BYTES,
                DEFAULT_SETUP_REPLY_BYTES,
                DEFAULT_SETUP_REPLY_STORAGE_BYTES,
                DEFAULT_SETUP_REPLY_RETENTION_US,
            ),
        }
    }

    /// Construct a new [`PacketRouter`] from explicit [`RouterConfig`] limits.
    pub fn with_config(config: RouterConfig) -> Self {
        Self {
            registry: DcidRegistry::with_max_entries(config.max_entries),
            setup_transactions: SetupTransactionTable::new(
                config.max_pending_setups,
                config.max_cached_setup_replies,
                config.max_request_bytes,
                config.max_reply_bytes,
                config.max_reply_storage_bytes,
                config.reply_retention_us,
            ),
        }
    }

    /// Construct a host-scale [`PacketRouter`] (`RouterConfig::host()`).
    pub fn host() -> Self {
        Self::with_config(RouterConfig::host())
    }

    /// Borrow the underlying [`DcidRegistry`].
    pub fn registry(&self) -> &DcidRegistry<Endpoint, NextHop> {
        &self.registry
    }

    /// Mutably borrow the underlying [`DcidRegistry`].
    pub fn registry_mut(&mut self) -> &mut DcidRegistry<Endpoint, NextHop> {
        &mut self.registry
    }

    /// Set the maximum number of DCID entries in the registry.
    pub fn set_max_entries(&mut self, max_entries: usize) {
        self.registry.set_max_entries(max_entries);
    }

    /// Number of active routes/endpoints in the registry.
    pub fn route_count(&self) -> usize {
        self.registry.len()
    }

    /// Register a local `endpoint` at `dcid`.
    pub fn register_endpoint(
        &mut self,
        dcid: ConnectionId,
        endpoint: Endpoint,
    ) -> Result<(), DcidRegistryError> {
        self.registry.insert_endpoint(dcid, endpoint)
    }

    /// Register a standalone forwarding rule at `dcid`.
    pub fn register_forward(
        &mut self,
        dcid: ConnectionId,
        rule: ForwardRule<NextHop>,
    ) -> Result<(), DcidRegistryError> {
        self.registry.install_forward(dcid, rule)
    }

    /// Atomically install a bidirectional pair of forwarding rules.
    pub fn register_forward_pair(
        &mut self,
        first_cid: ConnectionId,
        first_rule: ForwardRule<NextHop>,
        second_cid: ConnectionId,
        second_rule: ForwardRule<NextHop>,
    ) -> Result<(), DcidRegistryError> {
        self.registry
            .install_forward_pair(first_cid, first_rule, second_cid, second_rule)
    }

    /// Admit or deduplicate a setup transaction.
    pub fn begin_setup_transaction<'a>(
        &'a mut self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
        request: &[u8],
        reply_capacity: usize,
        now_us: u64,
        pending_deadline_us: u64,
    ) -> SetupTransactionLookup<'a> {
        self.setup_transactions.begin(
            previous_hop,
            transaction_id,
            request,
            reply_capacity,
            now_us,
            pending_deadline_us,
        )
    }

    /// Record the downstream hop for a pending setup transaction.
    pub fn set_setup_downstream_hop(
        &mut self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
        downstream_hop: ForwardNextHop,
    ) -> Result<(), SetupTransactionError> {
        self.setup_transactions
            .set_downstream_hop(previous_hop, transaction_id, downstream_hop)
    }

    /// Look up the downstream hop for a pending setup transaction.
    pub fn setup_downstream_hop(
        &self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
    ) -> Option<ForwardNextHop> {
        self.setup_transactions
            .downstream_hop(previous_hop, transaction_id)
    }

    /// Record provisional relay state for a pending setup transaction.
    pub fn set_setup_relay_state(
        &mut self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
        relay_state: SetupRelayState,
    ) -> Result<(), SetupTransactionError> {
        self.setup_transactions
            .set_relay_state(previous_hop, transaction_id, relay_state)
    }

    /// Look up provisional relay state for a pending setup transaction.
    pub fn setup_relay_state(
        &self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
    ) -> Option<SetupRelayState> {
        self.setup_transactions
            .relay_state(previous_hop, transaction_id)
    }

    /// Validate a downstream `PATH_OPEN_ACK` reply.
    pub fn validate_setup_downstream_reply(
        &mut self,
        downstream_hop: ForwardNextHop,
        transaction_id: u64,
        circuit: SetupCircuitKey,
        reply: &[u8],
    ) -> Result<SetupDownstreamReply<'_>, SetupTransactionError> {
        self.setup_transactions.validate_downstream_reply(
            downstream_hop,
            transaction_id,
            circuit,
            reply,
        )
    }

    /// Complete a setup transaction from its downstream hop.
    pub fn complete_setup_from_downstream(
        &mut self,
        downstream_hop: ForwardNextHop,
        transaction_id: u64,
        reply: &[u8],
        now_us: u64,
    ) -> Result<ForwardNextHop, SetupTransactionError> {
        self.setup_transactions.complete_from_downstream(
            downstream_hop,
            transaction_id,
            reply,
            now_us,
        )
    }

    /// Complete a setup transaction identified by `previous_hop`.
    pub fn complete_setup_transaction(
        &mut self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
        reply: &[u8],
        now_us: u64,
    ) -> Result<(), SetupTransactionError> {
        self.setup_transactions
            .complete(previous_hop, transaction_id, reply, now_us)
    }

    /// Cancel a provisional setup transaction.
    pub fn cancel_setup_transaction(
        &mut self,
        previous_hop: ForwardNextHop,
        transaction_id: u64,
    ) -> bool {
        self.setup_transactions.cancel(previous_hop, transaction_id)
    }

    /// Expire pending and cached setup transactions at `now_us`.
    pub fn expire_setup_transactions(&mut self, now_us: u64) -> usize {
        self.setup_transactions.expire(now_us)
    }

    /// Earliest setup transaction deadline.
    pub fn next_setup_deadline(&self) -> Option<u64> {
        self.setup_transactions.next_deadline()
    }

    /// Return `(pending_count, cached_count, reserved_reply_bytes)`.
    pub fn setup_transaction_counts(&self) -> (usize, usize, usize) {
        (
            self.setup_transactions.pending_count(),
            self.setup_transactions.cached_count(),
            self.setup_transactions.reserved_reply_bytes(),
        )
    }

    /// Whether `dcid` is registered in this router.
    pub fn contains(&self, dcid: ConnectionId) -> bool {
        self.registry.contains(dcid)
    }

    /// Return the local endpoint registered for `dcid`, if any.
    pub fn endpoint_for_cid(&self, dcid: ConnectionId) -> Option<&Endpoint> {
        let index = self.registry.find(dcid).ok()?;
        match &self.registry.entries[index].1 {
            DcidTarget::Endpoint(endpoint) => Some(endpoint),
            DcidTarget::Forward(_) => None,
        }
    }

    /// Remove an endpoint matching both `dcid` and `expected`.
    pub fn remove_endpoint(&mut self, dcid: ConnectionId, expected: &Endpoint) -> bool
    where
        Endpoint: PartialEq,
    {
        let Ok(index) = self.registry.find(dcid) else {
            return false;
        };
        if !matches!(&self.registry.entries[index].1, DcidTarget::Endpoint(endpoint) if endpoint == expected)
        {
            return false;
        }
        self.registry.entries.remove(index);
        true
    }

    /// Remove a standalone forwarding rule at `dcid`.
    pub fn remove_forward(&mut self, dcid: ConnectionId) -> bool {
        let Ok(index) = self.registry.find(dcid) else {
            return false;
        };
        if !matches!(self.registry.entries[index].1, DcidTarget::Forward(_)) {
            return false;
        }
        self.registry.entries.remove(index);
        true
    }

    /// Remove a paired bidirectional forwarding rule set.
    pub fn remove_forward_pair(
        &mut self,
        first_cid: ConnectionId,
        second_cid: ConnectionId,
    ) -> bool {
        self.registry.remove_forward_pair(first_cid, second_cid)
    }

    /// Check and consume packet quota for `dcid` at `now_us` (reserving `1/16` of quota for control packets).
    pub fn consume_forward_quota(
        &mut self,
        dcid: ConnectionId,
        control_packet: bool,
        now_us: u64,
    ) -> bool {
        let Ok(index) = self.registry.find(dcid) else {
            return false;
        };
        let DcidTarget::Forward(rule) = &mut self.registry.entries[index].1 else {
            return false;
        };
        if rule.packet_quota == 0 {
            return true;
        }
        let window_us = rule.lease_duration_us.max(1);
        let elapsed_us = now_us.saturating_sub(rule.quota_window_started_us);
        if elapsed_us >= window_us {
            let elapsed_windows = elapsed_us / window_us;
            rule.quota_window_started_us = rule
                .quota_window_started_us
                .saturating_add(elapsed_windows.saturating_mul(window_us));
            rule.forwarded_packets = 0;
            rule.forwarded_control_packets = 0;
        }
        if rule.forwarded_packets >= rule.packet_quota {
            return false;
        }
        let control_reserve = (rule.packet_quota / 16).max(1);
        if !control_packet
            && rule.forwarded_packets >= rule.packet_quota.saturating_sub(control_reserve)
        {
            return false;
        }
        rule.forwarded_packets = rule.forwarded_packets.saturating_add(1);
        if control_packet {
            rule.forwarded_control_packets = rule.forwarded_control_packets.saturating_add(1);
        }
        true
    }

    /// Look up the [`RouterTarget`] for an encoded packet `input`.
    pub fn target(&self, input: &[u8]) -> Result<RouterTarget<'_, Endpoint, NextHop>, RelayError> {
        let prefix = decode_routing_prefix(input)?;
        match self.registry.ingress(prefix) {
            Ok(DcidIngress::Endpoint(_, endpoint)) => Ok(RouterTarget::Endpoint(endpoint)),
            Ok(DcidIngress::Forward(_, rule)) => Ok(RouterTarget::Forward(rule)),
            Err(DcidRegistryError::Missing) => Ok(RouterTarget::Missing),
            Err(_) => unreachable!("registry lookup reports only a missing key"),
        }
    }

    /// Expire an idle forward rule or renew its inactivity lease (including its paired direction) at `now_us`.
    pub fn refresh_forward_lease(&mut self, input: &[u8], now_us: u64) -> Result<bool, RelayError> {
        if !self.forward_lease_active(input, now_us)? {
            return Ok(false);
        }
        let prefix = decode_routing_prefix(input)?;
        let Ok(index) = self.registry.find(prefix.dcid) else {
            return Ok(true);
        };
        let DcidTarget::Forward(rule) = &self.registry.entries[index].1 else {
            return Ok(true);
        };
        let group_id = rule.lease_group_id;
        let expires_at_us = now_us.saturating_add(rule.lease_duration_us);
        if group_id == 0 {
            if let DcidTarget::Forward(rule) = &mut self.registry.entries[index].1 {
                rule.lease_expires_at_us = expires_at_us;
            }
        } else {
            for (_, target) in &mut self.registry.entries {
                if let DcidTarget::Forward(rule) = target
                    && rule.lease_group_id == group_id
                {
                    rule.lease_expires_at_us = expires_at_us;
                }
            }
        }
        Ok(true)
    }

    /// Check lease validity without extending an active rule, removing expired paired directions together.
    pub fn forward_lease_active(&mut self, input: &[u8], now_us: u64) -> Result<bool, RelayError> {
        let prefix = decode_routing_prefix(input)?;
        let Ok(index) = self.registry.find(prefix.dcid) else {
            return Ok(true);
        };
        let DcidTarget::Forward(rule) = &self.registry.entries[index].1 else {
            return Ok(true);
        };
        if rule.lease_expires_at_us > now_us {
            return Ok(true);
        }
        let group_id = rule.lease_group_id;
        if group_id == 0 {
            self.registry.entries.remove(index);
        } else {
            self.registry.entries.retain(|(_, target)| {
                !matches!(target, DcidTarget::Forward(rule) if rule.lease_group_id == group_id)
            });
        }
        Ok(false)
    }

    /// Earliest forward lease expiry deadline.
    pub fn next_forward_lease_deadline(&self) -> Option<u64> {
        self.registry.next_forward_lease_deadline()
    }

    /// Remove all expired forward rules at `now_us`.
    pub fn expire_forward_leases(&mut self, now_us: u64) -> usize {
        self.registry.expire_forward_leases(now_us)
    }

    /// Find a registered endpoint satisfying `accepts`.
    pub fn opaque_endpoint(&self, accepts: impl FnMut(&Endpoint) -> bool) -> Option<&Endpoint> {
        self.registry.endpoint_matching(accepts)
    }
}
