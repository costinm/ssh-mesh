//! Borrowed, single-pass envelope codec shared across streams and packet transports.
//!
//! Each direction of a handler stream starts with one self-delimiting CBOR map
//! (the envelope header), followed by optional raw body bytes and `FIN`.
//!
//! Why single-pass `decode_prefix` replaces `scan_header`:
//! `Decoder::position()` advances as each entry in the root map is decoded or skipped.
//! As soon as all `count` entries of the root map have been processed, `decoder.position()`
//! is the exact byte offset where the envelope ends and the raw stream body begins.
//!
//! Map keys and identifier values support both string names (`"component"`, `"method"`,
//! `"id"`, `"fields"`, `"result"`, `"error"`, `"timeout"`, `"to"`, `"data"`) and compact
//! integer tags (`1..=11`), distinguished directly by their CBOR major type.

use crate::cbor::{DEFAULT_MAX_DEPTH, DEFAULT_MAX_ITEMS, Decoder, Encoder};

/// Largest envelope header accepted on a stream before a handler is selected.
pub const MAX_ENVELOPE_BYTES: usize = 4096;

/// A component, path, method, or mesh destination identifier.
///
/// Supports string names (`Text`), compact integer IDs (`Tag`), and raw binary
/// node/MAC identifiers (`Bytes`) without copying or allocating.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Name<'a> {
    /// Numeric identifier (`major == 0`).
    Tag(u64),
    /// UTF-8 / ASCII text identifier (`major == 3`).
    Text(&'a [u8]),
    /// Binary node/MAC identifier (`major == 2`).
    Bytes(&'a [u8]),
}

impl<'a> Name<'a> {
    /// Return the identifier as a UTF-8 `&str` if it is a valid UTF-8 `Text` variant.
    pub fn as_str(&self) -> Option<&'a str> {
        match self {
            Self::Text(bytes) => core::str::from_utf8(bytes).ok(),
            _ => None,
        }
    }

    /// Return the numeric tag if this is `Name::Tag`.
    pub const fn as_tag(&self) -> Option<u64> {
        match self {
            Self::Tag(tag) => Some(*tag),
            _ => None,
        }
    }
}

/// Borrowed form of a request or response envelope.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Record<'a> {
    /// Target component or service path (`key 1` or `"component"` / `"path"`).
    pub component: Option<Name<'a>>,
    /// Method name or numeric ID (`key 2` or `"method"`).
    pub method: Option<Name<'a>>,
    /// Correlation identifier (`key 3` or `"id"`).
    pub id: Option<u64>,
    /// Borrowed positional parameter array (`key 4` or `"params"`).
    pub params: Option<&'a [u8]>,
    /// Borrowed structured fields map (`key 5` or `"fields"`).
    pub fields: Option<&'a [u8]>,
    /// Borrowed successful result value (`key 6` or `"result"`).
    pub result: Option<&'a [u8]>,
    /// Borrowed error value (`key 7` or `"error"`).
    pub error: Option<&'a [u8]>,
    /// Request timeout in milliseconds (`key 8` or `"timeout"`).
    pub timeout: Option<u64>,
    /// Destination node or URI (`key 9` or `"to"`).
    pub to: Option<Name<'a>>,
    /// Opaque inline byte payload (`key 10` or `"data"`).
    pub data: Option<&'a [u8]>,
    /// Unsigned bearer-local extensions (`key 11` or `"extensions"`).
    pub extensions: Option<&'a [u8]>,
}

/// Type alias emphasizing the role of [`Record`] as a stream/message envelope.
pub type Envelope<'a> = Record<'a>;

/// Result of attempting to decode a self-delimiting envelope prefix at the start of a stream buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrefixDecode<'a> {
    /// Complete root envelope decoded in a single pass.
    /// `body_offset` is the exact byte index where the envelope ends and the raw stream body begins.
    Complete {
        record: Record<'a>,
        body_offset: usize,
    },
    /// Buffer contains a valid prefix so far, but more bytes are needed from the stream.
    Incomplete,
    /// Input is not a valid envelope or exceeds [`MAX_ENVELOPE_BYTES`].
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StepError {
    NeedMore,
    Malformed,
}

fn read_head(data: &[u8], pos: &mut usize) -> Result<(u8, Option<u64>), StepError> {
    let first = *data.get(*pos).ok_or(StepError::NeedMore)?;
    *pos += 1;
    let major = first >> 5;
    let ai = first & 0x1f;
    let val = match ai {
        0..=23 => Some(u64::from(ai)),
        24 => {
            let b = *data.get(*pos).ok_or(StepError::NeedMore)?;
            *pos += 1;
            if major == 7 && b < 32 {
                return Err(StepError::Malformed);
            }
            Some(u64::from(b))
        }
        25 => {
            let end = pos.checked_add(2).ok_or(StepError::Malformed)?;
            let s = data.get(*pos..end).ok_or(StepError::NeedMore)?;
            *pos = end;
            Some(u64::from(u16::from_be_bytes([s[0], s[1]])))
        }
        26 => {
            let end = pos.checked_add(4).ok_or(StepError::Malformed)?;
            let s = data.get(*pos..end).ok_or(StepError::NeedMore)?;
            *pos = end;
            Some(u64::from(u32::from_be_bytes([s[0], s[1], s[2], s[3]])))
        }
        27 => {
            let end = pos.checked_add(8).ok_or(StepError::Malformed)?;
            let s = data.get(*pos..end).ok_or(StepError::NeedMore)?;
            *pos = end;
            Some(u64::from_be_bytes([
                s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
            ]))
        }
        31 => match major {
            2..=5 => None,
            _ => return Err(StepError::Malformed),
        },
        _ => return Err(StepError::Malformed),
    };
    Ok((major, val))
}

fn skip_one(data: &[u8], pos: &mut usize) -> Result<(), StepError> {
    #[derive(Clone, Copy)]
    enum Frame {
        Def(u64),
        Array,
        Map(bool),
        String(u8),
    }
    let mut stack = [Frame::Def(0); DEFAULT_MAX_DEPTH];
    let mut depth = 0usize;
    let mut work = 0usize;
    let mut pending = true;
    loop {
        if !pending {
            if depth == 0 {
                return Ok(());
            }
            match &mut stack[depth - 1] {
                Frame::Def(n) if *n == 0 => {
                    depth -= 1;
                    continue;
                }
                Frame::Def(n) => {
                    *n -= 1;
                }
                Frame::Map(odd) => {
                    if *data.get(*pos).ok_or(StepError::NeedMore)? == 0xff {
                        if *odd {
                            return Err(StepError::Malformed);
                        }
                        work = work.checked_add(1).ok_or(StepError::Malformed)?;
                        if work > DEFAULT_MAX_ITEMS {
                            return Err(StepError::Malformed);
                        }
                        *pos += 1;
                        depth -= 1;
                        continue;
                    }
                    *odd = !*odd;
                }
                Frame::Array | Frame::String(_) => {
                    if *data.get(*pos).ok_or(StepError::NeedMore)? == 0xff {
                        work = work.checked_add(1).ok_or(StepError::Malformed)?;
                        if work > DEFAULT_MAX_ITEMS {
                            return Err(StepError::Malformed);
                        }
                        *pos += 1;
                        depth -= 1;
                        continue;
                    }
                }
            }
        }
        pending = false;
        work = work.checked_add(1).ok_or(StepError::Malformed)?;
        if work > DEFAULT_MAX_ITEMS {
            return Err(StepError::Malformed);
        }
        let peek = *data.get(*pos).ok_or(StepError::NeedMore)?;
        if depth > 0 {
            if let Frame::String(expected) = stack[depth - 1] {
                if (peek >> 5) != expected || (peek & 0x1f) == 31 {
                    return Err(StepError::Malformed);
                }
            }
        }
        let (major, len_opt) = read_head(data, pos)?;
        match (major, len_opt) {
            (0 | 1 | 7, Some(_)) => {}
            (2 | 3, Some(len)) => {
                let len = usize::try_from(len).map_err(|_| StepError::Malformed)?;
                if len > MAX_ENVELOPE_BYTES {
                    return Err(StepError::Malformed);
                }
                let end = pos.checked_add(len).ok_or(StepError::Malformed)?;
                if end > data.len() {
                    return Err(StepError::NeedMore);
                }
                *pos = end;
            }
            (2 | 3, None) => {
                if depth >= DEFAULT_MAX_DEPTH {
                    return Err(StepError::Malformed);
                }
                stack[depth] = Frame::String(major);
                depth += 1;
            }
            (4, Some(count)) => {
                if depth >= DEFAULT_MAX_DEPTH {
                    return Err(StepError::Malformed);
                }
                stack[depth] = Frame::Def(count);
                depth += 1;
            }
            (4, None) => {
                if depth >= DEFAULT_MAX_DEPTH {
                    return Err(StepError::Malformed);
                }
                stack[depth] = Frame::Array;
                depth += 1;
            }
            (5, Some(count)) => {
                if depth >= DEFAULT_MAX_DEPTH {
                    return Err(StepError::Malformed);
                }
                let items = count.checked_mul(2).ok_or(StepError::Malformed)?;
                stack[depth] = Frame::Def(items);
                depth += 1;
            }
            (5, None) => {
                if depth >= DEFAULT_MAX_DEPTH {
                    return Err(StepError::Malformed);
                }
                stack[depth] = Frame::Map(false);
                depth += 1;
            }
            (6, Some(_)) => {
                if depth >= DEFAULT_MAX_DEPTH {
                    return Err(StepError::Malformed);
                }
                stack[depth] = Frame::Def(1);
                depth += 1;
            }
            _ => return Err(StepError::Malformed),
        }
    }
}

fn read_uint(data: &[u8], pos: &mut usize) -> Result<u64, StepError> {
    let (major, val) = read_head(data, pos)?;
    match (major, val) {
        (0, Some(v)) => Ok(v),
        _ => Err(StepError::Malformed),
    }
}

fn read_bytes_ref<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8], StepError> {
    let (major, val) = read_head(data, pos)?;
    match (major, val) {
        (2, Some(len)) => {
            let len = usize::try_from(len).map_err(|_| StepError::Malformed)?;
            if len > MAX_ENVELOPE_BYTES {
                return Err(StepError::Malformed);
            }
            let end = pos.checked_add(len).ok_or(StepError::Malformed)?;
            let slice = data.get(*pos..end).ok_or(StepError::NeedMore)?;
            *pos = end;
            Ok(slice)
        }
        _ => Err(StepError::Malformed),
    }
}

fn read_name<'a>(data: &'a [u8], pos: &mut usize) -> Result<Name<'a>, StepError> {
    let (major, val) = read_head(data, pos)?;
    match (major, val) {
        (0, Some(tag)) => Ok(Name::Tag(tag)),
        (2, Some(len)) => {
            let len = usize::try_from(len).map_err(|_| StepError::Malformed)?;
            if len > MAX_ENVELOPE_BYTES {
                return Err(StepError::Malformed);
            }
            let end = pos.checked_add(len).ok_or(StepError::Malformed)?;
            let slice = data.get(*pos..end).ok_or(StepError::NeedMore)?;
            *pos = end;
            Ok(Name::Bytes(slice))
        }
        (3, Some(len)) => {
            let len = usize::try_from(len).map_err(|_| StepError::Malformed)?;
            if len > MAX_ENVELOPE_BYTES {
                return Err(StepError::Malformed);
            }
            let end = pos.checked_add(len).ok_or(StepError::Malformed)?;
            let slice = data.get(*pos..end).ok_or(StepError::NeedMore)?;
            *pos = end;
            Ok(Name::Text(slice))
        }
        _ => Err(StepError::Malformed),
    }
}

fn read_key(data: &[u8], pos: &mut usize) -> Result<u64, StepError> {
    let (major, val) = read_head(data, pos)?;
    match (major, val) {
        (0, Some(k)) => Ok(k),
        (3, Some(len)) => {
            let len = usize::try_from(len).map_err(|_| StepError::Malformed)?;
            if len > MAX_ENVELOPE_BYTES {
                return Err(StepError::Malformed);
            }
            let end = pos.checked_add(len).ok_or(StepError::Malformed)?;
            let key_bytes = data.get(*pos..end).ok_or(StepError::NeedMore)?;
            *pos = end;
            let mapped = match key_bytes {
                b"component" | b"path" => 1,
                b"method" => 2,
                b"id" => 3,
                b"params" => 4,
                b"fields" => 5,
                b"result" => 6,
                b"error" => 7,
                b"timeout" => 8,
                b"to" => 9,
                b"data" => 10,
                b"extensions" => 11,
                _ => 0,
            };
            Ok(mapped)
        }
        _ => Err(StepError::Malformed),
    }
}

fn parse_record_map<'a>(data: &'a [u8], pos: &mut usize) -> Result<Record<'a>, StepError> {
    let (major, count_opt) = read_head(data, pos)?;
    if major != 5 {
        return Err(StepError::Malformed);
    }
    let mut record = Record::default();
    let apply_entry = |record: &mut Record<'a>, key: u64, data: &'a [u8], pos: &mut usize| -> Result<(), StepError> {
        match key {
            1 => record.component = Some(read_name(data, pos)?),
            2 => record.method = Some(read_name(data, pos)?),
            3 => record.id = Some(read_uint(data, pos)?),
            4 => {
                let start = *pos;
                skip_one(data, pos)?;
                record.params = Some(&data[start..*pos]);
            }
            5 => {
                let start = *pos;
                skip_one(data, pos)?;
                record.fields = Some(&data[start..*pos]);
            }
            6 => {
                let start = *pos;
                skip_one(data, pos)?;
                record.result = Some(&data[start..*pos]);
            }
            7 => {
                let start = *pos;
                skip_one(data, pos)?;
                record.error = Some(&data[start..*pos]);
            }
            8 => record.timeout = Some(read_uint(data, pos)?),
            9 => record.to = Some(read_name(data, pos)?),
            10 => record.data = Some(read_bytes_ref(data, pos)?),
            11 => {
                let start = *pos;
                skip_one(data, pos)?;
                record.extensions = Some(&data[start..*pos]);
            }
            _ => skip_one(data, pos)?,
        }
        Ok(())
    };

    match count_opt {
        Some(count) => {
            for _ in 0..count {
                let key = read_key(data, pos)?;
                apply_entry(&mut record, key, data, pos)?;
                if *pos > MAX_ENVELOPE_BYTES {
                    return Err(StepError::Malformed);
                }
            }
        }
        None => loop {
            if *data.get(*pos).ok_or(StepError::NeedMore)? == 0xff {
                *pos += 1;
                break;
            }
            let key = read_key(data, pos)?;
            apply_entry(&mut record, key, data, pos)?;
            if *pos > MAX_ENVELOPE_BYTES {
                return Err(StepError::Malformed);
            }
        },
    }
    Ok(record)
}

/// Borrowed form of a numeric-only device request or response envelope.
///
/// Designed for embedded/XIP modules (`< 64 KiB` flash, low RAM) where envelope map keys
/// and component/method identifiers are always unsigned integers (`1..=11`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeviceRecord<'a> {
    /// Numeric component ID (`key 1`).
    pub component: Option<u64>,
    /// Numeric method ID (`key 2`).
    pub method: Option<u64>,
    /// Correlation identifier (`key 3`).
    pub id: Option<u64>,
    /// Borrowed positional parameter array (`key 4`).
    pub params: Option<&'a [u8]>,
    /// Borrowed structured fields map (`key 5`).
    pub fields: Option<&'a [u8]>,
    /// Borrowed successful result value (`key 6`).
    pub result: Option<&'a [u8]>,
    /// Borrowed error value (`key 7`).
    pub error: Option<&'a [u8]>,
    /// Request timeout in milliseconds (`key 8`).
    pub timeout: Option<u64>,
    /// Numeric destination token (`key 9`).
    pub to: Option<u64>,
    /// Opaque inline byte payload (`key 10`).
    pub data: Option<&'a [u8]>,
    /// Unsigned bearer-local extensions (`key 11`).
    pub extensions: Option<&'a [u8]>,
}

impl<'a> From<DeviceRecord<'a>> for Record<'a> {
    fn from(d: DeviceRecord<'a>) -> Self {
        Self {
            component: d.component.map(Name::Tag),
            method: d.method.map(Name::Tag),
            id: d.id,
            params: d.params,
            fields: d.fields,
            result: d.result,
            error: d.error,
            timeout: d.timeout,
            to: d.to.map(Name::Tag),
            data: d.data,
            extensions: d.extensions,
        }
    }
}

/// Result of attempting to decode a numeric-only device envelope prefix at the start of a stream buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevicePrefixDecode<'a> {
    /// Complete root numeric envelope decoded in a single pass.
    /// `body_offset` is the exact byte index where the envelope ends and the raw stream body begins.
    Complete {
        record: DeviceRecord<'a>,
        body_offset: usize,
    },
    /// Buffer contains a valid prefix so far, but more bytes are needed from the stream.
    Incomplete,
    /// Input is not a valid numeric envelope or exceeds [`MAX_ENVELOPE_BYTES`].
    Invalid,
}

fn parse_device_record_map<'a>(
    data: &'a [u8],
    pos: &mut usize,
) -> Result<DeviceRecord<'a>, StepError> {
    let (major, count_opt) = read_head(data, pos)?;
    let Some(count) = count_opt else {
        return Err(StepError::Malformed);
    };
    if major != 5 {
        return Err(StepError::Malformed);
    }
    let mut record = DeviceRecord::default();
    for _ in 0..count {
        let key = read_uint(data, pos)?;
        match key {
            1 => record.component = Some(read_uint(data, pos)?),
            2 => record.method = Some(read_uint(data, pos)?),
            3 => record.id = Some(read_uint(data, pos)?),
            4 => {
                let start = *pos;
                skip_one(data, pos)?;
                record.params = Some(&data[start..*pos]);
            }
            5 => {
                let start = *pos;
                skip_one(data, pos)?;
                record.fields = Some(&data[start..*pos]);
            }
            6 => {
                let start = *pos;
                skip_one(data, pos)?;
                record.result = Some(&data[start..*pos]);
            }
            7 => {
                let start = *pos;
                skip_one(data, pos)?;
                record.error = Some(&data[start..*pos]);
            }
            8 => record.timeout = Some(read_uint(data, pos)?),
            9 => record.to = Some(read_uint(data, pos)?),
            10 => record.data = Some(read_bytes_ref(data, pos)?),
            11 => {
                let start = *pos;
                skip_one(data, pos)?;
                record.extensions = Some(&data[start..*pos]);
            }
            _ => skip_one(data, pos)?,
        }
        if *pos > MAX_ENVELOPE_BYTES {
            return Err(StepError::Malformed);
        }
    }
    Ok(record)
}

/// Device variant of [`decode_envelope_prefix`]: decodes a definite-length numeric-only envelope
/// in a single pass with zero string-key or text-name branches.
pub fn decode_device_envelope_prefix(buf: &[u8]) -> DevicePrefixDecode<'_> {
    let mut pos = 0;
    match parse_device_record_map(buf, &mut pos) {
        Ok(record) if pos <= MAX_ENVELOPE_BYTES => DevicePrefixDecode::Complete {
            record,
            body_offset: pos,
        },
        Ok(_) => DevicePrefixDecode::Invalid,
        Err(StepError::NeedMore) if buf.len() < MAX_ENVELOPE_BYTES => {
            DevicePrefixDecode::Incomplete
        }
        Err(StepError::NeedMore | StepError::Malformed) => DevicePrefixDecode::Invalid,
    }
}

/// Device variant of [`decode_prefix`]: decodes a numeric request envelope (`method.is_some()`)
/// at the start of `packet` and returns `(record, body_offset)`.
pub fn decode_device_prefix(packet: &[u8]) -> Option<(DeviceRecord<'_>, usize)> {
    match decode_device_envelope_prefix(packet) {
        DevicePrefixDecode::Complete {
            record,
            body_offset,
        } if record.method.is_some() => Some((record, body_offset)),
        _ => None,
    }
}

/// Device variant of [`decode`]: decodes a standalone numeric request packet (`body_offset == packet.len()`).
pub fn decode_device(packet: &[u8]) -> Option<DeviceRecord<'_>> {
    let (record, consumed) = decode_device_prefix(packet)?;
    (consumed == packet.len()).then_some(record)
}

/// Decode one self-delimiting envelope at the start of `buf` in a single pass,
/// distinguishing incomplete stream prefixes (`PrefixDecode::Incomplete`) from
/// malformed headers (`PrefixDecode::Invalid`).
///
/// Unlike a separate `scan_header` + `decode` pass, this parses the envelope map
/// once and returns `(record, body_offset)` where `&buf[body_offset..]` is the start
/// of the raw stream body. Both request envelopes (which carry `method`) and response
/// envelopes (which carry `result`, `error`, or `id`) are accepted.
pub fn decode_envelope_prefix(buf: &[u8]) -> PrefixDecode<'_> {
    let mut pos = 0;
    match parse_record_map(buf, &mut pos) {
        Ok(record) if pos <= MAX_ENVELOPE_BYTES => PrefixDecode::Complete {
            record,
            body_offset: pos,
        },
        Ok(_) => PrefixDecode::Invalid,
        Err(StepError::NeedMore) if buf.len() < MAX_ENVELOPE_BYTES => PrefixDecode::Incomplete,
        Err(StepError::NeedMore | StepError::Malformed) => PrefixDecode::Invalid,
    }
}

/// Decode one complete request envelope at the start of a stream buffer, returning
/// `(record, body_offset)` when a complete request map (with `method` present) is decoded.
pub fn decode_prefix(packet: &[u8]) -> Option<(Record<'_>, usize)> {
    match decode_envelope_prefix(packet) {
        PrefixDecode::Complete {
            record,
            body_offset,
        } if record.method.is_some() => Some((record, body_offset)),
        _ => None,
    }
}

/// Decode a standalone request packet that has no trailing stream body (`body_offset == packet.len()`).
pub fn decode(packet: &[u8]) -> Option<Record<'_>> {
    let (record, consumed) = decode_prefix(packet)?;
    (consumed == packet.len()).then_some(record)
}

/// Decode a standalone request or response envelope with no trailing stream body.
pub fn decode_any(packet: &[u8]) -> Option<Record<'_>> {
    match decode_envelope_prefix(packet) {
        PrefixDecode::Complete {
            record,
            body_offset,
        } if body_offset == packet.len() => Some(record),
        _ => None,
    }
}

/// Read only the optional destination (`key 9` or `"to"`) from a top-level envelope map.
pub fn destination(packet: &[u8]) -> Result<Option<Name<'_>>, ()> {
    let mut d = Decoder::new(packet);
    let (major, count) = d.head().ok_or(())?;
    if major != 5 || count == u64::MAX {
        return Err(());
    }
    let mut to = None;
    for _ in 0..count {
        let mut pos = d.position();
        let key = read_key(packet, &mut pos).map_err(|_| ())?;
        d.set_position(pos);
        match key {
            9 => {
                let mut p = d.position();
                let n = read_name(packet, &mut p).map_err(|_| ())?;
                d.set_position(p);
                to = Some(n);
            }
            _ => d.skip().ok_or(())?,
        }
    }
    d.is_finished().then_some(to).ok_or(())
}

/// Encode a correlated successful response in the common envelope.
pub fn encode_numeric_response(
    component: u64,
    method: u64,
    id: u64,
    result: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let mut encoder = Encoder::new(out);
    encoder.map(4)?;
    encoder.uint(1)?;
    encoder.uint(component)?;
    encoder.uint(2)?;
    encoder.uint(method)?;
    encoder.uint(3)?;
    encoder.uint(id)?;
    encoder.uint(6)?;
    encoder.encoded_value(result)?;
    Some(encoder.len())
}

/// Encode a size-limited byte/text diagnostic as a correlated result.
pub fn encode_numeric_data_response(
    component: u64,
    method: u64,
    id: u64,
    result: &[u8],
    text: bool,
    out: &mut [u8],
) -> Option<usize> {
    let mut value = alloc::vec![0; result.len().checked_add(9)?];
    let mut encoder = Encoder::new(&mut value);
    if text {
        encoder.text_value(result)?;
    } else {
        encoder.bytes_value(result)?;
    }
    let value_len = encoder.len();
    encode_numeric_response(component, method, id, &value[..value_len], out)
}

/// Encode a numeric request with no parameters or fields.
pub fn encode_numeric_empty_request(
    component: u64,
    method: u64,
    id: u64,
    out: &mut [u8],
) -> Option<usize> {
    let mut encoder = Encoder::new(out);
    encoder.map(3)?;
    encoder.uint(1)?;
    encoder.uint(component)?;
    encoder.uint(2)?;
    encoder.uint(method)?;
    encoder.uint(3)?;
    encoder.uint(id)?;
    Some(encoder.len())
}

/// Encode a correlated handler failure.
pub fn encode_numeric_error(
    component: u64,
    method: u64,
    id: u64,
    error: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let mut encoder = Encoder::new(out);
    encoder.map(4)?;
    encoder.uint(1)?;
    encoder.uint(component)?;
    encoder.uint(2)?;
    encoder.uint(method)?;
    encoder.uint(3)?;
    encoder.uint(id)?;
    encoder.uint(7)?;
    encoder.text_value(error)?;
    Some(encoder.len())
}

/// Encode an error response header with optional correlation `id`.
pub fn encode_error_header(id: Option<u64>, message: &[u8]) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec![0u8; 64 + message.len()];
    let mut encoder = Encoder::new(&mut out);
    let count = if id.is_some() { 2 } else { 1 };
    let ok = (|| {
        encoder.map(count)?;
        if let Some(id) = id {
            encoder.uint(3)?;
            encoder.uint(id)?;
        }
        encoder.uint(7)?;
        encoder.text_value(message)?;
        Some(encoder.len())
    })();
    let used = ok.unwrap_or(0);
    drop(encoder);
    out.truncate(used);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_pass_decode_prefix_finds_exact_body_offset_and_handles_partial_buffers() {
        let mut header = [0u8; 64];
        let mut e = Encoder::new(&mut header);
        e.map(4).unwrap();
        e.uint(1).unwrap();
        e.uint(8).unwrap();
        e.uint(2).unwrap();
        e.uint(2).unwrap();
        e.uint(3).unwrap();
        e.uint(42).unwrap();
        e.uint(5).unwrap();
        e.map(1).unwrap();
        e.uint(1).unwrap();
        e.uint(1024).unwrap();
        let header_len = e.len();

        let mut wire = header[..header_len].to_vec();
        wire.extend_from_slice(b"raw stream body \xff\xff");

        // Any strict prefix of the header must return Incomplete, never Invalid.
        for prefix_len in 0..header_len {
            assert_eq!(
                decode_envelope_prefix(&wire[..prefix_len]),
                PrefixDecode::Incomplete,
                "prefix {prefix_len}"
            );
        }

        // Full wire buffer decodes in one pass and yields exact body_offset = header_len.
        match decode_envelope_prefix(&wire) {
            PrefixDecode::Complete {
                record,
                body_offset,
            } => {
                assert_eq!(body_offset, header_len);
                assert_eq!(record.component, Some(Name::Tag(8)));
                assert_eq!(record.method, Some(Name::Tag(2)));
                assert_eq!(record.id, Some(42));
                assert_eq!(&wire[body_offset..], b"raw stream body \xff\xff");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn string_keys_and_string_identifiers_decode_in_single_pass() {
        let mut buf = [0u8; 128];
        let mut e = Encoder::new(&mut buf);
        e.map(4).unwrap();
        e.str(b"component").unwrap();
        e.str(b"probe").unwrap();
        e.str(b"method").unwrap();
        e.str(b"handler").unwrap();
        e.str(b"id").unwrap();
        e.uint(99).unwrap();
        e.str(b"fields").unwrap();
        e.map(1).unwrap();
        e.uint(1).unwrap();
        e.uint(512).unwrap();
        let header_len = e.len();

        let mut wire = buf[..header_len].to_vec();
        wire.extend_from_slice(b"payload-bytes");

        let (record, offset) = decode_prefix(&wire).unwrap();
        assert_eq!(offset, header_len);
        assert_eq!(record.component.unwrap().as_str(), Some("probe"));
        assert_eq!(record.method.unwrap().as_str(), Some("handler"));
        assert_eq!(record.id, Some(99));
        assert_eq!(&wire[offset..], b"payload-bytes");
    }

    #[test]
    fn malformed_and_non_map_headers_are_rejected_immediately() {
        assert_eq!(decode_envelope_prefix(&[0xff]), PrefixDecode::Invalid);
        assert_eq!(decode_envelope_prefix(&[0x1c]), PrefixDecode::Invalid);
        // Integer or byte string at root (not a map) is rejected on the first byte.
        assert_eq!(decode_envelope_prefix(&[0x01]), PrefixDecode::Invalid);
        assert_eq!(
            decode_envelope_prefix(&[0x42, 0x01, 0x02]),
            PrefixDecode::Invalid
        );
    }

    #[test]
    fn destination_and_binary_payload_stay_borrowed() {
        let wire = [
            0xa4, 1, 4, 2, 8, 9, 0x62, b'e', b'7', 10, 0x43, 0, 0xff, 0x7e,
        ];
        let record = decode(&wire).unwrap();
        assert_eq!(record.method, Some(Name::Tag(8)));
        assert_eq!(record.to, Some(Name::Text(b"e7")));
        assert_eq!(record.data, Some(&wire[11..14]));
    }

    #[test]
    fn device_numeric_envelope_decodes_numbers_and_rejects_string_keys() {
        let mut header = [0u8; 64];
        let mut e = Encoder::new(&mut header);
        e.map(4).unwrap();
        e.uint(1).unwrap();
        e.uint(8).unwrap();
        e.uint(2).unwrap();
        e.uint(2).unwrap();
        e.uint(3).unwrap();
        e.uint(42).unwrap();
        e.uint(5).unwrap();
        e.map(1).unwrap();
        e.uint(1).unwrap();
        e.uint(1024).unwrap();
        let header_len = e.len();

        let mut wire = header[..header_len].to_vec();
        wire.extend_from_slice(b"body");

        for prefix_len in 0..header_len {
            assert_eq!(
                decode_device_envelope_prefix(&wire[..prefix_len]),
                DevicePrefixDecode::Incomplete
            );
        }

        let (dev_rec, offset) = decode_device_prefix(&wire).unwrap();
        assert_eq!(offset, header_len);
        assert_eq!(dev_rec.component, Some(8));
        assert_eq!(dev_rec.method, Some(2));
        assert_eq!(dev_rec.id, Some(42));
        assert_eq!(&wire[offset..], b"body");

        // String keys are rejected by the numeric-only device variant:
        let mut str_buf = [0u8; 64];
        let mut se = Encoder::new(&mut str_buf);
        se.map(2).unwrap();
        se.str(b"component").unwrap();
        se.uint(8).unwrap();
        se.str(b"method").unwrap();
        se.uint(2).unwrap();
        let str_len = se.len();
        assert_eq!(
            decode_device_envelope_prefix(&str_buf[..str_len]),
            DevicePrefixDecode::Invalid
        );
    }
}
