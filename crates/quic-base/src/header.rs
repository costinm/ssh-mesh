//! Wire codecs for `quic-link`: compact `ConnectionId` (1/2/4/8B), `ShortHeader` with RFC 9000
//! packet-number window reconstruction, descending `AckRanges<32>` (`0x02`), `ACK_FREQUENCY` (`0xaf`),
//! and RFC 9221 `DATAGRAM` (`0x30` / `0x31`) frames.

use core::cmp::{max, min};
use core::ops::Range;

use crate::wire::{WireError, decode_varint, encode_varint};

/// Fixed bit (`0x40`) required on QUIC short headers.
pub const FLAG_FIXED: u8 = 0x40;
/// Reserved short-header bits (`0x18`) that must be zero.
pub const FLAG_RESERVED: u8 = 0x18;
/// Key-phase / packet-protection bit (`0x04`).
pub const FLAG_KEY_PHASE: u8 = 0x04;

/// Frame type `0x00`: `PADDING`.
pub const FRAME_PADDING: u64 = 0x00;
/// Frame type `0x01`: `PING`.
pub const FRAME_PING: u64 = 0x01;
/// Frame type `0x02`: `ACK`.
pub const FRAME_ACK: u64 = 0x02;
/// Frame type `0x30`: `DATAGRAM` (extends to end of packet).
pub const FRAME_DATAGRAM: u64 = 0x30;
/// Frame type `0x31`: `DATAGRAM_LEN` (carries explicit length varint).
pub const FRAME_DATAGRAM_LEN: u64 = 0x31;
/// Frame type `0xaf`: `ACK_FREQUENCY`.
pub const FRAME_ACK_FREQUENCY: u64 = 0xaf;

/// Maximum number of disjoint ACK ranges tracked per association.
pub const ACK_RANGE_CAPACITY: usize = 32;

/// Compact DMesh/QUIC-lite connection identifier (`1`, `2`, `4`, or `8` bytes on the wire).
///
/// Byte 0 carries a length class:
/// - `0xxxxxxx` -> 1-byte CID (`0..=0x7f`)
/// - `100xxxxx` -> 2-byte CID (`0x80..=0x1fff`)
/// - `101xxxxx` -> 4-byte CID (`0x2000..=0x1fff_ffff`)
/// - `110xxxxx` -> 8-byte CID (`0x2000_0000..=(1<<61)-1`)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(u64);

impl ConnectionId {
    /// Maximum representable 61-bit connection ID value.
    pub const MAX_VALUE: u64 = (1u64 << 61) - 1;

    /// Construct a `ConnectionId` if `value <= MAX_VALUE`.
    #[inline]
    pub const fn new(value: u64) -> Option<Self> {
        if value <= Self::MAX_VALUE {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Raw numeric connection ID value.
    #[inline]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Wire encoded length in bytes (`1`, `2`, `4`, or `8`).
    #[inline]
    pub const fn encoded_len(self) -> usize {
        if self.0 <= 0x7f {
            1
        } else if self.0 <= 0x1fff {
            2
        } else if self.0 <= 0x1fff_ffff {
            4
        } else {
            8
        }
    }

    /// Encode this `ConnectionId` into `out`, returning the number of bytes written.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, WireError> {
        let n = self.encoded_len();
        if out.len() < n {
            return Err(WireError::BufferTooSmall);
        }
        let tag = match n {
            1 => 0,
            2 => 0b100,
            4 => 0b101,
            _ => 0b110,
        } << 5;
        for i in 0..n {
            out[i] = (self.0 >> (8 * (n - i - 1))) as u8;
        }
        out[0] = (out[0] & if n == 1 { 0x7f } else { 0x1f }) | tag;
        Ok(n)
    }

    /// Decode a `ConnectionId` from the start of `input`, returning `(cid, bytes_used)`.
    pub fn decode(input: &[u8]) -> Result<(Self, usize), WireError> {
        if input.is_empty() {
            return Err(WireError::UnexpectedEof);
        }
        let (n, value_mask) = if input[0] & 0x80 == 0 {
            (1, 0x7f)
        } else {
            match (input[0] >> 5) & 0x03 {
                0 => (2, 0x1f),
                1 => (4, 0x1f),
                2 => (8, 0x1f),
                _ => return Err(WireError::InvalidFrame),
            }
        };
        if input.len() < n {
            return Err(WireError::UnexpectedEof);
        }
        let mut value = (input[0] & value_mask) as u64;
        for &b in &input[1..n] {
            value = (value << 8) | b as u64;
        }
        let cid = Self(value);
        if cid.encoded_len() != n {
            return Err(WireError::InvalidFrame);
        }
        Ok((cid, n))
    }
}

/// QUIC short packet header (`flags | dcid | packet_number`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShortHeader {
    /// Header flags byte (`FLAG_FIXED` set, low 2 bits encode `packet_number_len - 1`).
    pub flags: u8,
    /// Destination connection identifier.
    pub dcid: ConnectionId,
    /// Reconstructed (or full) 32-bit packet number.
    pub packet_number: u32,
    /// Wire length of the truncated packet number (`1..=4` bytes).
    pub packet_number_len: u8,
}

/// Decoded short-header prefix prior to full packet-number window reconstruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShortHeaderPrefix {
    /// Raw header flags byte.
    pub flags: u8,
    /// Destination connection identifier.
    pub dcid: ConnectionId,
    /// Truncated wire packet number (`1..=4` bytes).
    pub truncated_packet_number: u32,
    /// Encoded packet number length (`1..=4` bytes).
    pub packet_number_len: u8,
    /// Total encoded byte length of the short header (`1 + dcid.encoded_len() + packet_number_len`).
    pub header_len: usize,
}

impl ShortHeaderPrefix {
    /// Reconstruct the full `u32` packet number nearest to `expected` using RFC 9000's sliding window rule.
    pub fn reconstruct(self, expected: u32) -> Result<ShortHeader, WireError> {
        let pn_len = self.packet_number_len as usize;
        let window = 1u64 << (pn_len * 8);
        let half_window = window / 2;
        let truncated = u64::from(self.truncated_packet_number);
        let expected = u64::from(expected);
        let epoch = expected & !(window - 1);
        let mut candidate = epoch | truncated;
        if candidate + half_window <= expected && candidate + window <= u64::from(u32::MAX) {
            candidate += window;
        } else if candidate > expected + half_window {
            if candidate < window {
                return Err(WireError::InvalidFrame);
            }
            candidate -= window;
        }
        if candidate > u64::from(u32::MAX) {
            return Err(WireError::InvalidFrame);
        }
        Ok(ShortHeader {
            flags: self.flags,
            dcid: self.dcid,
            packet_number: candidate as u32,
            packet_number_len: self.packet_number_len,
        })
    }
}

impl ShortHeader {
    /// Maximum encoded byte length of a `ShortHeader` (`1` flag + `8` CID + `4` PN = `13` bytes).
    pub const MAX_LEN: usize = 1 + 8 + 4;

    /// Encode this `ShortHeader` into `out`, returning the number of bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let pn_len = self.packet_number_len.clamp(1, 4) as usize;
        let cid_len = self.dcid.encoded_len();
        if out.len() < 1 + cid_len + pn_len {
            return Err(WireError::BufferTooSmall);
        }
        let flags = self.flags & !FLAG_RESERVED;
        out[0] = flags | FLAG_FIXED | ((pn_len as u8 - 1) & 3);
        let n = self.dcid.encode(&mut out[1..])?;
        for i in 0..pn_len {
            out[1 + n + i] = (self.packet_number >> (8 * (pn_len - i - 1))) as u8;
        }
        Ok(1 + n + pn_len)
    }

    /// Decode the `ShortHeaderPrefix` from the start of `input`.
    pub fn decode_prefix(input: &[u8]) -> Result<ShortHeaderPrefix, WireError> {
        if input.is_empty() {
            return Err(WireError::UnexpectedEof);
        }
        if input[0] & 0x80 != 0 || input[0] & FLAG_FIXED == 0 || input[0] & FLAG_RESERVED != 0 {
            return Err(WireError::InvalidFrame);
        }
        let pn_len = ((input[0] & 3) + 1) as usize;
        let (dcid, cid_len) = ConnectionId::decode(&input[1..])?;
        if input.len() < 1 + cid_len + pn_len {
            return Err(WireError::UnexpectedEof);
        }
        let mut pn = 0u32;
        for &b in &input[1 + cid_len..1 + cid_len + pn_len] {
            pn = (pn << 8) | b as u32;
        }
        Ok(ShortHeaderPrefix {
            flags: input[0],
            dcid,
            truncated_packet_number: pn,
            packet_number_len: pn_len as u8,
            header_len: 1 + cid_len + pn_len,
        })
    }

    /// Decode a `ShortHeader` and reconstruct the full packet number relative to `expected`.
    pub fn decode_with_expected(input: &[u8], expected: u32) -> Result<(Self, usize), WireError> {
        let prefix = Self::decode_prefix(input)?;
        Ok((prefix.reconstruct(expected)?, prefix.header_len))
    }

    /// Decode a `ShortHeader` without window reconstruction (leaving the truncated wire value).
    pub fn decode(input: &[u8]) -> Result<(Self, usize), WireError> {
        let prefix = Self::decode_prefix(input)?;
        Ok((
            Self {
                flags: prefix.flags,
                dcid: prefix.dcid,
                packet_number: prefix.truncated_packet_number,
                packet_number_len: prefix.packet_number_len,
            },
            prefix.header_len,
        ))
    }
}

/// Select the shortest packet-number encoding (`1..=4` bytes) whose reconstruction window is
/// unambiguous relative to `largest_acked`.
#[inline]
pub fn packet_number_len(next: u32, largest_acked: Option<u32>) -> u8 {
    let baseline = largest_acked.unwrap_or(0);
    let distance = next.saturating_sub(baseline) as u64;
    let needed = distance.saturating_mul(2).max(1);
    if needed < (1 << 8) {
        1
    } else if needed < (1 << 16) {
        2
    } else if needed < (1 << 24) {
        3
    } else {
        4
    }
}

/// Inclusive packet-number range `[start ..= end]` in a QUIC `ACK` frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketAckRange {
    /// First acknowledged packet number in the contiguous block (inclusive).
    pub start: u32,
    /// Last acknowledged packet number in the contiguous block (inclusive).
    pub end: u32,
}

impl PacketAckRange {
    /// Construct an inclusive packet-number range `[start ..= end]`.
    #[inline]
    pub const fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }

    /// Whether `pn` falls within `[self.start ..= self.end]`.
    #[inline]
    pub const fn contains(self, pn: u32) -> bool {
        pn >= self.start && pn <= self.end
    }
}

/// Fixed-capacity descending set of disjoint [`PacketAckRange`]s (ported from `quic-lite::AckRanges`).
///
/// Ranges are maintained sorted from newest (highest packet numbers at index `0`) to oldest.
/// When full (`N` disjoint ranges), inserting a newer range evicts the oldest range so the peer
/// always receives acknowledgements for its most recent transmissions.
#[derive(Clone, Copy, Debug)]
pub struct AckRanges<const N: usize = ACK_RANGE_CAPACITY> {
    ranges: [PacketAckRange; N],
    len: usize,
}

impl<const N: usize> PartialEq for AckRanges<N> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<const N: usize> Eq for AckRanges<N> {}

/// Standard 32-range ACK set used by `quic-link`.
pub type AckRangeSet = AckRanges<ACK_RANGE_CAPACITY>;

impl<const N: usize> Default for AckRanges<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> AckRanges<N> {
    /// Create an empty `AckRanges` set.
    pub const fn new() -> Self {
        Self {
            ranges: [PacketAckRange { start: 0, end: 0 }; N],
            len: 0,
        }
    }

    /// Number of disjoint ranges currently stored.
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the range set is empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Largest acknowledged packet number (`ranges[0].end`), if any.
    #[inline]
    pub const fn largest(&self) -> Option<u32> {
        if self.len == 0 {
            None
        } else {
            Some(self.ranges[0].end)
        }
    }

    /// Borrow the active descending slice of ranges.
    #[inline]
    pub fn as_slice(&self) -> &[PacketAckRange] {
        &self.ranges[..self.len]
    }

    /// Get the range at `index` (`0` is the newest/highest range).
    #[inline]
    pub const fn get(&self, index: usize) -> Option<PacketAckRange> {
        if index < self.len {
            Some(self.ranges[index])
        } else {
            None
        }
    }

    /// Discard packet numbers strictly below `floor` once the peer has acknowledged our ACKs.
    pub fn discard_below(&mut self, floor: u32) {
        let mut retained = 0;
        while retained < self.len && self.ranges[retained].end >= floor {
            if self.ranges[retained].start < floor {
                self.ranges[retained].start = floor;
            }
            retained += 1;
        }
        self.len = retained;
    }

    /// Insert a single received packet number `pn`, returning `true` if an old range was evicted.
    pub fn insert(&mut self, pn: u32) -> bool {
        self.insert_range(PacketAckRange { start: pn, end: pn })
    }

    /// Insert an inclusive range `new`, merging adjacent or overlapping ranges and returning `true`
    /// if the oldest range was dropped due to capacity `N`.
    pub fn insert_range(&mut self, mut new: PacketAckRange) -> bool {
        if new.start > new.end {
            return false;
        }
        if self.len != 0 {
            let newest = self.ranges[0];
            if u64::from(new.start) <= u64::from(newest.end) + 1
                && u64::from(new.end) + 1 >= u64::from(newest.start)
                && (self.len == 1 || u64::from(new.start) > u64::from(self.ranges[1].end) + 1)
            {
                self.ranges[0] = PacketAckRange {
                    start: min(new.start, newest.start),
                    end: max(new.end, newest.end),
                };
                return false;
            }
        }
        let mut dropped = false;
        let mut i = 0;
        while i < self.len {
            let current = self.ranges[i];
            if u64::from(new.start) > u64::from(current.end) + 1 {
                if self.len < N {
                    for j in (i..self.len).rev() {
                        self.ranges[j + 1] = self.ranges[j];
                    }
                    self.ranges[i] = new;
                    self.len += 1;
                } else if i < N {
                    for j in (i..N - 1).rev() {
                        self.ranges[j + 1] = self.ranges[j];
                    }
                    self.ranges[i] = new;
                    dropped = true;
                }
                return dropped;
            }
            if u64::from(new.end) + 1 < u64::from(current.start) {
                i += 1;
                continue;
            }
            new.start = min(new.start, current.start);
            new.end = max(new.end, current.end);
            for j in i..self.len - 1 {
                self.ranges[j] = self.ranges[j + 1];
            }
            self.len -= 1;
        }
        if self.len < N {
            let mut at = self.len;
            while at > 0 && self.ranges[at - 1].end < new.end {
                self.ranges[at] = self.ranges[at - 1];
                at -= 1;
            }
            self.ranges[at] = new;
            self.len += 1;
        } else {
            dropped = true;
        }
        dropped
    }

    /// Binary-search membership check in $O(\log N)$ time.
    pub fn contains(&self, pn: u32) -> bool {
        let Some(newest) = self.ranges[..self.len].first() else {
            return false;
        };
        if pn > newest.end {
            return false;
        }
        if pn >= newest.start {
            return true;
        }
        let mut low = 1;
        let mut high = self.len;
        while low < high {
            let middle = low + (high - low) / 2;
            let range = self.ranges[middle];
            if pn > range.end {
                high = middle;
            } else if pn < range.start {
                low = middle + 1;
            } else {
                return true;
            }
        }
        false
    }
}

/// `ACK_FREQUENCY` frame parameters (`0xaf`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckFrequencyFrame {
    /// Monotonically increasing sequence number for this policy update.
    pub sequence: u64,
    /// Maximum ack-eliciting packets before sending an ACK.
    pub packet_threshold: u64,
    /// Requested maximum ACK delay in microseconds.
    pub max_ack_delay_us: u64,
    /// Packet reordering threshold before sending an immediate ACK.
    pub reordering_threshold: u64,
}

/// Decoded link-layer frame (`ACK`, `ACK_FREQUENCY`, `DATAGRAM`) or inner `quic-mux` frame slice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkFrame {
    /// `0x00` PADDING.
    Padding,
    /// `0x01` PING.
    Ping,
    /// `0x02` Selective ACK frame.
    Ack {
        /// Largest acknowledged packet number.
        largest: u32,
        /// Peer ACK delay in microseconds.
        delay_us: u64,
        /// Descending acknowledged packet-number ranges.
        ranges: AckRangeSet,
    },
    /// `0xaf` `ACK_FREQUENCY` frame.
    AckFrequency(AckFrequencyFrame),
    /// `0x30` or `0x31` RFC 9221 `DATAGRAM` frame with payload byte range inside the packet.
    Datagram {
        /// Whether the wire frame carried an explicit length varint (`0x31`).
        has_length: bool,
        /// Byte range `[start .. end]` of the datagram payload within the packet slice.
        payload_range: Range<usize>,
    },
}

/// Encode a QUIC `ACK` (`0x02`) frame into `out`, returning the number of bytes written.
pub fn encode_ack_frame(
    ranges: &AckRangeSet,
    delay_us: u64,
    out: &mut [u8],
) -> Result<usize, WireError> {
    let first = ranges.get(0).ok_or(WireError::InvalidFrame)?;
    let largest = first.end;
    let mut p = 0;
    p += encode_varint(FRAME_ACK, &mut out[p..])?;
    p += encode_varint(u64::from(largest), &mut out[p..])?;
    p += encode_varint(delay_us, &mut out[p..])?;
    p += encode_varint((ranges.len() - 1) as u64, &mut out[p..])?;
    p += encode_varint(u64::from(first.end - first.start), &mut out[p..])?;
    for i in 1..ranges.len() {
        let previous = ranges.get(i - 1).ok_or(WireError::InvalidFrame)?;
        let current = ranges.get(i).ok_or(WireError::InvalidFrame)?;
        let gap = u64::from(previous.start)
            .checked_sub(u64::from(current.end) + 2)
            .ok_or(WireError::InvalidFrame)?;
        p += encode_varint(gap, &mut out[p..])?;
        p += encode_varint(u64::from(current.end - current.start), &mut out[p..])?;
    }
    Ok(p)
}

/// Decode a QUIC `ACK` (`0x02`) frame starting after the `0x02` frame-type varint at `input[offset..]`.
pub fn decode_ack_frame_body(
    input: &[u8],
    mut at: usize,
) -> Result<(u32, u64, AckRangeSet, usize), WireError> {
    let (largest, n1) = decode_varint(input.get(at..).ok_or(WireError::UnexpectedEof)?)?;
    at += n1;
    let (delay_us, n2) = decode_varint(input.get(at..).ok_or(WireError::UnexpectedEof)?)?;
    at += n2;
    let (range_count, n3) = decode_varint(input.get(at..).ok_or(WireError::UnexpectedEof)?)?;
    at += n3;
    let (first_range, n4) = decode_varint(input.get(at..).ok_or(WireError::UnexpectedEof)?)?;
    at += n4;
    if largest > u64::from(u32::MAX)
        || first_range > largest
        || range_count >= ACK_RANGE_CAPACITY as u64
    {
        return Err(WireError::InvalidFrame);
    }
    let mut ranges = AckRangeSet::new();
    ranges.insert_range(PacketAckRange {
        start: (largest - first_range) as u32,
        end: largest as u32,
    });
    let mut previous_start = largest - first_range;
    for _ in 0..range_count {
        let (gap, ng) = decode_varint(input.get(at..).ok_or(WireError::UnexpectedEof)?)?;
        at += ng;
        let (range, nr) = decode_varint(input.get(at..).ok_or(WireError::UnexpectedEof)?)?;
        at += nr;
        let current_end = previous_start
            .checked_sub(gap + 2)
            .ok_or(WireError::InvalidFrame)?;
        let current_start = current_end
            .checked_sub(range)
            .ok_or(WireError::InvalidFrame)?;
        if current_end > u64::from(u32::MAX) || current_start > u64::from(u32::MAX) {
            return Err(WireError::InvalidFrame);
        }
        ranges.insert_range(PacketAckRange {
            start: current_start as u32,
            end: current_end as u32,
        });
        previous_start = current_start;
    }
    Ok((largest as u32, delay_us, ranges, at))
}

/// Encode an `ACK_FREQUENCY` (`0xaf`) frame into `out`.
pub fn encode_ack_frequency_frame(
    frame: &AckFrequencyFrame,
    out: &mut [u8],
) -> Result<usize, WireError> {
    let mut p = 0;
    p += encode_varint(FRAME_ACK_FREQUENCY, &mut out[p..])?;
    p += encode_varint(frame.sequence, &mut out[p..])?;
    p += encode_varint(frame.packet_threshold, &mut out[p..])?;
    p += encode_varint(frame.max_ack_delay_us, &mut out[p..])?;
    p += encode_varint(frame.reordering_threshold, &mut out[p..])?;
    Ok(p)
}

/// Encode a `DATAGRAM` frame header (`0x30` without length, or `0x31` + length varint) into `out`.
pub fn encode_datagram_header(
    payload_len: usize,
    include_len: bool,
    out: &mut [u8],
) -> Result<usize, WireError> {
    if out.is_empty() {
        return Err(WireError::BufferTooSmall);
    }
    if include_len {
        out[0] = FRAME_DATAGRAM_LEN as u8;
        let n = encode_varint(payload_len as u64, &mut out[1..])?;
        Ok(1 + n)
    } else {
        out[0] = FRAME_DATAGRAM as u8;
        Ok(1)
    }
}

/// Plan the next `PoolPacket` from a byte stream's `peek` buffer (`<= 64` bytes) when packets
/// carry a [`ShortHeader`] followed by self-delimiting link/control frames (`PADDING`, `PING`,
/// `ACK`, `ACK_FREQUENCY`, `DATAGRAM_LEN`, `MAX_DATA`, `MAX_STREAM_DATA`, `MAX_STREAMS`,
/// `RESET_STREAM`, `STOP_SENDING`, `CONNECTION_CLOSE`) and at most one `STREAM` frame (`0x08..=0x0f`
/// with the `0x02` length bit set).
pub fn plan_short_header_stream_packet(
    peek: &[u8],
    max_packet_len: usize,
) -> Result<crate::wire::StreamPacketPlan, WireError> {
    use crate::wire::{
        MAX_STREAM_FRAME_HEADER_LEN, StreamHeaderStep, StreamPacketPlan, stream_frame_header_step,
    };

    if peek.is_empty() {
        return Ok(StreamPacketPlan::NeedMoreHeader);
    }
    let prefix = match ShortHeader::decode_prefix(peek) {
        Ok(p) => p,
        Err(WireError::UnexpectedEof) => return Ok(StreamPacketPlan::NeedMoreHeader),
        Err(e) => return Err(e),
    };
    let mut at = prefix.header_len;
    if at >= peek.len() {
        return Ok(StreamPacketPlan::NeedMoreHeader);
    }

    loop {
        let rest = &peek[at..];
        if rest.is_empty() {
            return Ok(StreamPacketPlan::Ready { total_len: at });
        }
        let (ty_u64, ty_len) = match decode_varint(rest) {
            Ok(v) => v,
            Err(WireError::UnexpectedEof) => {
                if at == prefix.header_len {
                    return Ok(StreamPacketPlan::NeedMoreHeader);
                }
                return Ok(StreamPacketPlan::Ready { total_len: at });
            }
            Err(e) => return Err(e),
        };

        match ty_u64 {
            FRAME_ACK => {
                match decode_ack_frame_body(rest, ty_len) {
                    Ok((_largest, _delay, _ranges, ack_end)) => {
                        if at + ack_end > max_packet_len {
                            return Err(WireError::InvalidFrame);
                        }
                        return Ok(StreamPacketPlan::Ready {
                            total_len: at + ack_end,
                        });
                    }
                    Err(WireError::UnexpectedEof) => {
                        if peek.len() >= 64 {
                            return Err(WireError::InvalidFrame);
                        }
                        return Ok(StreamPacketPlan::NeedMoreHeader);
                    }
                    Err(e) => return Err(e),
                }
            }
            FRAME_ACK_FREQUENCY => {
                let mut cur = ty_len;
                for _ in 0..4 {
                    match rest
                        .get(cur..)
                        .ok_or(WireError::UnexpectedEof)
                        .and_then(decode_varint)
                    {
                        Ok((_, n)) => cur += n,
                        Err(WireError::UnexpectedEof) => {
                            if peek.len() >= 64 {
                                return Err(WireError::InvalidFrame);
                            }
                            return Ok(StreamPacketPlan::NeedMoreHeader);
                        }
                        Err(e) => return Err(e),
                    }
                }
                if at + cur > max_packet_len {
                    return Err(WireError::InvalidFrame);
                }
                return Ok(StreamPacketPlan::Ready {
                    total_len: at + cur,
                });
            }
            FRAME_DATAGRAM_LEN => {
                let (dlen_u64, n_len) = match rest
                    .get(ty_len..)
                    .ok_or(WireError::UnexpectedEof)
                    .and_then(decode_varint)
                {
                    Ok(v) => v,
                    Err(WireError::UnexpectedEof) => {
                        if peek.len() >= 64 {
                            return Err(WireError::InvalidFrame);
                        }
                        return Ok(StreamPacketPlan::NeedMoreHeader);
                    }
                    Err(e) => return Err(e),
                };
                let payload_len = usize::try_from(dlen_u64).map_err(|_| WireError::InvalidFrame)?;
                let frame_len = (ty_len + n_len)
                    .checked_add(payload_len)
                    .ok_or(WireError::InvalidFrame)?;
                if at + frame_len > max_packet_len {
                    return Err(WireError::InvalidFrame);
                }
                return Ok(StreamPacketPlan::Ready {
                    total_len: at + frame_len,
                });
            }
            _ => match stream_frame_header_step(rest)? {
                StreamHeaderStep::NeedMoreHeader => {
                    if rest.len() >= MAX_STREAM_FRAME_HEADER_LEN {
                        return Err(WireError::InvalidFrame);
                    }
                    return Ok(StreamPacketPlan::NeedMoreHeader);
                }
                StreamHeaderStep::Complete {
                    header_len,
                    payload_len,
                    is_stream,
                } => {
                    let frame_len = header_len
                        .checked_add(payload_len)
                        .ok_or(WireError::InvalidFrame)?;
                    if frame_len == 0 || at + frame_len > max_packet_len {
                        return Err(WireError::InvalidFrame);
                    }
                    if is_stream {
                        return Ok(StreamPacketPlan::Ready {
                            total_len: at + frame_len,
                        });
                    }
                    at += frame_len;
                    if at == peek.len() {
                        return Ok(StreamPacketPlan::Ready { total_len: at });
                    }
                    // If the next byte in `peek` begins a new `ShortHeader` (`0x40..=0x43`, and
                    // not the 2-byte `ACK_FREQUENCY` varint `0x40, 0xaf`), then this control-only
                    // packet ended at `at`. Otherwise another control or `STREAM` frame follows
                    // inside the same packet!
                    if (peek[at] & 0xfc) == 0x40 && peek.get(at + 1) != Some(&0xaf) {
                        return Ok(StreamPacketPlan::Ready { total_len: at });
                    }
                }
            },
        }
    }
}
