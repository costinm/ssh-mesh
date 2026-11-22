//! RFC 9000-style QUIC Initial Long Header (`DMESH_QUIC_VERSION = 0x444d_0001`),
//! `CRYPTO` (`0x06`) frame codec, and varint-TLV `TransportParameters` (`#![no_std]`).

use core::ops::Range;

use crate::crypto::{ASSOCIATION_RANDOM_LEN, INITIAL_VERIFIER_LEN, PUBLIC_KEY_COMPRESSED_LEN};
use crate::header::{ConnectionId, reconstruct_packet_number};
use crate::wire::{WireError, decode_varint, encode_varint, varint_len};

/// Wire version for DMesh RFC 9000-style Long Headers (`"DM\x00\x01"`, matching
/// `DMESH_LONG_HEADER_VERSION` in `quic-relay` and `XIP_QUIC_VERSION_DMESH` in `xip_quic.c`).
pub const DMESH_QUIC_VERSION: u32 = 0x444d_0001;

/// Long-header packet type bits for `Initial` (`0b00`).
pub const LONG_PACKET_INITIAL: u8 = 0;

/// Frame type `0x06`: `CRYPTO` (carries serialized [`TransportParameters`] inside `Initial`).
pub const FRAME_CRYPTO: u64 = 0x06;

/// Transport parameter `0x00`: `original_destination_connection_id` (RFC 9000 §18.2).
pub const TP_ORIGINAL_DCID: u64 = 0x00;
/// Transport parameter `0x01`: `max_idle_timeout` in milliseconds (RFC 9000 §18.2).
pub const TP_MAX_IDLE_TIMEOUT: u64 = 0x01;
/// Transport parameter `0x02`: 16-byte `stateless_reset_token` (RFC 9000 §18.2).
pub const TP_STATELESS_RESET_TOKEN: u64 = 0x02;
/// Transport parameter `0x03`: `max_udp_payload_size` in bytes (RFC 9000 §18.2).
pub const TP_MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
/// Transport parameter `0x04`: `initial_max_data` in bytes (RFC 9000 §18.2).
pub const TP_INITIAL_MAX_DATA: u64 = 0x04;
/// Transport parameter `0x05`: `initial_max_stream_data_bidi_local` (RFC 9000 §18.2).
pub const TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
/// Transport parameter `0x06`: `initial_max_stream_data_bidi_remote` (RFC 9000 §18.2).
pub const TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
/// Transport parameter `0x08`: `initial_max_streams_bidi` (RFC 9000 §18.2).
pub const TP_INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
/// Transport parameter `0x09`: `initial_max_streams_uni` (RFC 9000 §18.2).
pub const TP_INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
/// Transport parameter `0x0f`: `initial_source_connection_id` (RFC 9000 §18.2).
pub const TP_INITIAL_SCID: u64 = 0x0f;
/// DMesh Phase A extension TLV (`0x0044_4d01`): 33-byte compressed P-256 SEC1 public key.
pub const TP_DMESH_PUBLIC_KEY: u64 = 0x0044_4d01;
/// DMesh Phase A extension TLV (`0x0044_4d02`): 32-byte per-association random nonce.
pub const TP_DMESH_RANDOM: u64 = 0x0044_4d02;
/// DMesh Phase A extension TLV (`0x0044_4d03`): 32-byte `HMAC-SHA256` verifier using `api_key`.
pub const TP_DMESH_VERIFIER: u64 = 0x0044_4d03;

/// Return `true` if `input` starts with a DMesh RFC 9000 `Initial` Long Header (`0xc0`,
/// packet type `0`, version [`DMESH_QUIC_VERSION`]).
#[inline]
pub fn is_initial_packet(input: &[u8]) -> bool {
    input.len() >= 9
        && (input[0] & 0xf0) == 0xc0
        && u32::from_be_bytes([input[1], input[2], input[3], input[4]]) == DMESH_QUIC_VERSION
}

/// RFC 9000-style `Initial` Long Header for [`DMESH_QUIC_VERSION`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitialHeader {
    /// 32-bit wire version (must be [`DMESH_QUIC_VERSION`]).
    pub version: u32,
    /// Destination connection identifier (`None` encodes length byte `0`).
    pub dcid: Option<ConnectionId>,
    /// Source connection identifier (`None` encodes length byte `0`).
    pub scid: Option<ConnectionId>,
    /// Reconstructed (or truncated when encoding) 32-bit packet number.
    pub packet_number: u32,
    /// Wire length of the truncated packet number (`1..=4` bytes).
    pub packet_number_len: u8,
    /// Byte length of the inner payload following the header (`>= 1`).
    pub payload_len: usize,
}

impl InitialHeader {
    /// Worst-case encoded byte length of an [`InitialHeader`] with 0-byte address-validation token
    /// and 8-byte DCID/SCID (`1 + 4 + 1 + 8 + 1 + 8 + 1 + 4 + 4 = 32` bytes).
    pub const MAX_LEN: usize = 32;

    /// Exact encoded byte length of this [`InitialHeader`] (with 0-byte token).
    pub fn encoded_len(&self) -> Result<usize, WireError> {
        let pn_len = usize::from(self.packet_number_len);
        if !matches!(self.packet_number_len, 1..=4) || self.payload_len == 0 {
            return Err(WireError::InvalidFrame);
        }
        let body_len = u64::try_from(pn_len + self.payload_len).map_err(|_| WireError::InvalidFrame)?;
        Ok(1
            + 4
            + 1
            + self.dcid.map_or(0, ConnectionId::encoded_len)
            + 1
            + self.scid.map_or(0, ConnectionId::encoded_len)
            + 1
            + varint_len(body_len)?
            + pn_len)
    }

    /// Encode this [`InitialHeader`] into `out`, returning the number of header bytes written.
    ///
    /// Note that `body_len = packet_number_len + payload_len` is encoded into the Long Header
    /// `Length` varint so `payload_len` payload bytes must follow immediately after the returned
    /// offset.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        if self.version != DMESH_QUIC_VERSION
            || !matches!(self.packet_number_len, 1..=4)
            || self.payload_len == 0
        {
            return Err(WireError::InvalidFrame);
        }
        let need = self.encoded_len()?;
        if out.len() < need {
            return Err(WireError::BufferTooSmall);
        }
        let pn_len = usize::from(self.packet_number_len);
        let mut at = 0usize;
        out[at] = 0xc0 | (LONG_PACKET_INITIAL << 4) | (self.packet_number_len - 1);
        at += 1;
        out[at..at + 4].copy_from_slice(&self.version.to_be_bytes());
        at += 4;
        for cid in [self.dcid, self.scid] {
            let len = cid.map_or(0, ConnectionId::encoded_len);
            out[at] = len as u8;
            at += 1;
            if let Some(cid) = cid {
                cid.encode(&mut out[at..at + len])?;
                at += len;
            }
        }
        // RFC 9000 §17.2.2 Token Length = 0 (varint `0x00`).
        out[at] = 0;
        at += 1;
        let body_len = (pn_len + self.payload_len) as u64;
        at += encode_varint(body_len, &mut out[at..])?;
        let pn_bytes = self.packet_number.to_be_bytes();
        out[at..at + pn_len].copy_from_slice(&pn_bytes[4 - pn_len..]);
        at += pn_len;
        Ok(at)
    }

    /// Decode an [`InitialHeader`] from the start of `input`, reconstructing the packet number
    /// relative to `expected_pn`, and return `(header, header_len)`.
    pub fn decode_with_expected(input: &[u8], expected_pn: u32) -> Result<(Self, usize), WireError> {
        if input.is_empty() {
            return Err(WireError::UnexpectedEof);
        }
        if (input[0] & 0xf0) != (0xc0 | (LONG_PACKET_INITIAL << 4)) {
            return Err(WireError::InvalidFrame);
        }
        if input.len() < 9 {
            return Err(WireError::UnexpectedEof);
        }
        let version = u32::from_be_bytes([input[1], input[2], input[3], input[4]]);
        if version != DMESH_QUIC_VERSION {
            return Err(WireError::InvalidFrame);
        }
        let packet_number_len = (input[0] & 0x03) + 1;
        let pn_len = usize::from(packet_number_len);

        let mut at = 5usize;
        let mut cids = [None, None];
        for slot in &mut cids {
            let len = usize::from(*input.get(at).ok_or(WireError::UnexpectedEof)?);
            at += 1;
            if len != 0 {
                if !matches!(len, 1 | 2 | 4 | 8) {
                    return Err(WireError::InvalidFrame);
                }
                if input.len() < at + len {
                    return Err(WireError::UnexpectedEof);
                }
                let (cid, used) = ConnectionId::decode(&input[at..at + len])?;
                if used != len {
                    return Err(WireError::InvalidFrame);
                }
                *slot = Some(cid);
                at += len;
            }
        }

        let (token_len_u64, tok_var_len) =
            decode_varint(input.get(at..).ok_or(WireError::UnexpectedEof)?)?;
        at += tok_var_len;
        let token_len = usize::try_from(token_len_u64).map_err(|_| WireError::InvalidFrame)?;
        at = at.checked_add(token_len).ok_or(WireError::InvalidFrame)?;
        if input.len() < at {
            return Err(WireError::UnexpectedEof);
        }

        let (body_len_u64, len_var_len) = decode_varint(&input[at..])?;
        at += len_var_len;
        let body_len = usize::try_from(body_len_u64).map_err(|_| WireError::InvalidFrame)?;
        if body_len <= pn_len {
            return Err(WireError::InvalidFrame);
        }
        let body_end = at.checked_add(body_len).ok_or(WireError::InvalidFrame)?;
        if input.len() < body_end {
            return Err(WireError::UnexpectedEof);
        }

        let mut truncated = 0u32;
        for &b in &input[at..at + pn_len] {
            truncated = (truncated << 8) | u32::from(b);
        }
        at += pn_len;
        let packet_number = reconstruct_packet_number(truncated, packet_number_len, expected_pn)?;

        Ok((
            Self {
                version,
                dcid: cids[0],
                scid: cids[1],
                packet_number,
                packet_number_len,
                payload_len: body_len - pn_len,
            },
            at,
        ))
    }

    /// Decode an [`InitialHeader`] using `expected_pn = 1`.
    #[inline]
    pub fn decode(input: &[u8]) -> Result<(Self, usize), WireError> {
        Self::decode_with_expected(input, 1)
    }
}

/// RFC 9000 §18.2 varint-TLV Transport Parameters carried inside `Initial` `CRYPTO` (`0x06`)
/// frames, extended in Phase A with `public_key`, `random`, and `verifier`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransportParameters {
    /// RFC 9000 `0x00`: original destination CID from the Client Initial.
    pub original_dcid: Option<ConnectionId>,
    /// RFC 9000 `0x01`: maximum idle timeout in milliseconds.
    pub max_idle_timeout_ms: Option<u64>,
    /// RFC 9000 `0x02`: 16-byte stateless reset token for packets sent to this endpoint.
    pub stateless_reset_token: Option<[u8; 16]>,
    /// RFC 9000 `0x03`: maximum UDP payload size in bytes.
    pub max_udp_payload_size: Option<u64>,
    /// RFC 9000 `0x04`: initial connection-level max data limit.
    pub initial_max_data: Option<u64>,
    /// RFC 9000 `0x05`: initial max stream data for locally-initiated bidirectional streams.
    pub initial_max_stream_data_bidi_local: Option<u64>,
    /// RFC 9000 `0x06`: initial max stream data for remotely-initiated bidirectional streams.
    pub initial_max_stream_data_bidi_remote: Option<u64>,
    /// RFC 9000 `0x08`: initial max bidirectional stream count.
    pub initial_max_streams_bidi: Option<u64>,
    /// RFC 9000 `0x09`: initial max unidirectional stream count.
    pub initial_max_streams_uni: Option<u64>,
    /// RFC 9000 `0x0f`: initial source CID of the endpoint sending this Initial packet.
    pub initial_scid: Option<ConnectionId>,
    /// DMesh Phase A `0x0044_4d01`: 33-byte compressed SEC1 P-256 public key of the sender.
    pub public_key: Option<[u8; PUBLIC_KEY_COMPRESSED_LEN]>,
    /// DMesh Phase A `0x0044_4d02`: 32-byte per-association random nonce for traffic key derivation.
    pub random: Option<[u8; ASSOCIATION_RANDOM_LEN]>,
    /// DMesh Phase A `0x0044_4d03`: 32-byte `HMAC-SHA256` verifier bound to `api_key`.
    pub verifier: Option<[u8; INITIAL_VERIFIER_LEN]>,
}

fn encode_tp_varint(id: u64, value: u64, out: &mut [u8]) -> Result<usize, WireError> {
    let val_len = varint_len(value)?;
    let id_len = varint_len(id)?;
    let len_len = varint_len(val_len as u64)?;
    let total = id_len + len_len + val_len;
    if out.len() < total {
        return Err(WireError::BufferTooSmall);
    }
    let mut at = encode_varint(id, out)?;
    at += encode_varint(val_len as u64, &mut out[at..])?;
    at += encode_varint(value, &mut out[at..])?;
    Ok(at)
}

fn encode_tp_cid(id: u64, cid: ConnectionId, out: &mut [u8]) -> Result<usize, WireError> {
    let cid_len = cid.encoded_len();
    let total = varint_len(id)? + varint_len(cid_len as u64)? + cid_len;
    if out.len() < total {
        return Err(WireError::BufferTooSmall);
    }
    let mut at = encode_varint(id, out)?;
    at += encode_varint(cid_len as u64, &mut out[at..])?;
    at += cid.encode(&mut out[at..])?;
    Ok(at)
}

fn encode_tp_fixed<const N: usize>(
    id: u64,
    bytes: &[u8; N],
    out: &mut [u8],
) -> Result<usize, WireError> {
    let total = varint_len(id)? + varint_len(N as u64)? + N;
    if out.len() < total {
        return Err(WireError::BufferTooSmall);
    }
    let mut at = encode_varint(id, out)?;
    at += encode_varint(N as u64, &mut out[at..])?;
    out[at..at + N].copy_from_slice(bytes);
    Ok(at + N)
}

fn decode_tp_varint(slice: &[u8]) -> Result<u64, WireError> {
    let (v, used) = decode_varint(slice)?;
    if used != slice.len() {
        return Err(WireError::InvalidFrame);
    }
    Ok(v)
}

fn decode_tp_cid(slice: &[u8]) -> Result<ConnectionId, WireError> {
    let (cid, used) = ConnectionId::decode(slice)?;
    if used != slice.len() {
        return Err(WireError::InvalidFrame);
    }
    Ok(cid)
}

fn decode_tp_fixed<const N: usize>(slice: &[u8]) -> Result<[u8; N], WireError> {
    if slice.len() != N {
        return Err(WireError::InvalidFrame);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    Ok(out)
}

impl TransportParameters {
    /// Derive the 16-byte ULA `vip6` address directly from [`Self::public_key`] using `provider`.
    pub fn peer_vip6_with(&self, provider: &crate::crypto::CryptoProvider) -> Option<[u8; 16]> {
        self.public_key
            .as_ref()
            .and_then(|pk| crate::crypto::vip6_from_public_key_with(provider, pk).ok())
    }

    /// Derive the 16-byte ULA `vip6` address directly from [`Self::public_key`] (`SHA-256`).
    #[cfg(feature = "rust-crypto")]
    pub fn peer_vip6(&self) -> Option<[u8; 16]> {
        self.public_key.as_ref().map(crate::crypto::vip6_from_public_key)
    }

    /// Exact encoded byte length of all populated fields in RFC 9000 varint-TLV format.
    pub fn encoded_len(&self) -> Result<usize, WireError> {
        let mut total = 0usize;
        if let Some(cid) = self.original_dcid {
            let l = cid.encoded_len();
            total += varint_len(TP_ORIGINAL_DCID)? + varint_len(l as u64)? + l;
        }
        if let Some(cid) = self.initial_scid {
            let l = cid.encoded_len();
            total += varint_len(TP_INITIAL_SCID)? + varint_len(l as u64)? + l;
        }
        for &(id, opt) in &[
            (TP_MAX_IDLE_TIMEOUT, self.max_idle_timeout_ms),
            (TP_MAX_UDP_PAYLOAD_SIZE, self.max_udp_payload_size),
            (TP_INITIAL_MAX_DATA, self.initial_max_data),
            (
                TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                self.initial_max_stream_data_bidi_local,
            ),
            (
                TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                self.initial_max_stream_data_bidi_remote,
            ),
            (TP_INITIAL_MAX_STREAMS_BIDI, self.initial_max_streams_bidi),
            (TP_INITIAL_MAX_STREAMS_UNI, self.initial_max_streams_uni),
        ] {
            if let Some(v) = opt {
                let vl = varint_len(v)?;
                total += varint_len(id)? + varint_len(vl as u64)? + vl;
            }
        }
        if self.stateless_reset_token.is_some() {
            total += varint_len(TP_STATELESS_RESET_TOKEN)? + 1 + 16;
        }
        if self.public_key.is_some() {
            total += varint_len(TP_DMESH_PUBLIC_KEY)? + 1 + PUBLIC_KEY_COMPRESSED_LEN;
        }
        if self.random.is_some() {
            total += varint_len(TP_DMESH_RANDOM)? + 1 + ASSOCIATION_RANDOM_LEN;
        }
        if self.verifier.is_some() {
            total += varint_len(TP_DMESH_VERIFIER)? + 1 + INITIAL_VERIFIER_LEN;
        }
        Ok(total)
    }

    /// Encode populated fields into `out` in RFC 9000 §18.2 varint-TLV format, returning bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, WireError> {
        let mut at = 0usize;
        if let Some(cid) = self.original_dcid {
            at += encode_tp_cid(TP_ORIGINAL_DCID, cid, &mut out[at..])?;
        }
        if let Some(cid) = self.initial_scid {
            at += encode_tp_cid(TP_INITIAL_SCID, cid, &mut out[at..])?;
        }
        for &(id, opt) in &[
            (TP_MAX_IDLE_TIMEOUT, self.max_idle_timeout_ms),
            (TP_MAX_UDP_PAYLOAD_SIZE, self.max_udp_payload_size),
            (TP_INITIAL_MAX_DATA, self.initial_max_data),
            (
                TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                self.initial_max_stream_data_bidi_local,
            ),
            (
                TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                self.initial_max_stream_data_bidi_remote,
            ),
            (TP_INITIAL_MAX_STREAMS_BIDI, self.initial_max_streams_bidi),
            (TP_INITIAL_MAX_STREAMS_UNI, self.initial_max_streams_uni),
        ] {
            if let Some(v) = opt {
                at += encode_tp_varint(id, v, &mut out[at..])?;
            }
        }
        if let Some(ref token) = self.stateless_reset_token {
            at += encode_tp_fixed(TP_STATELESS_RESET_TOKEN, token, &mut out[at..])?;
        }
        if let Some(ref pub_key) = self.public_key {
            at += encode_tp_fixed(TP_DMESH_PUBLIC_KEY, pub_key, &mut out[at..])?;
        }
        if let Some(ref random) = self.random {
            at += encode_tp_fixed(TP_DMESH_RANDOM, random, &mut out[at..])?;
        }
        if let Some(ref verifier) = self.verifier {
            at += encode_tp_fixed(TP_DMESH_VERIFIER, verifier, &mut out[at..])?;
        }
        Ok(at)
    }

    /// Decode RFC 9000 varint-TLV transport parameters from `input`, ignoring unknown IDs per §18.1.
    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        let mut params = Self::default();
        let mut at = 0usize;
        while at < input.len() {
            let (id, id_len) = decode_varint(&input[at..])?;
            at += id_len;
            let (val_len_u64, len_len) =
                decode_varint(input.get(at..).ok_or(WireError::UnexpectedEof)?)?;
            at += len_len;
            let val_len = usize::try_from(val_len_u64).map_err(|_| WireError::InvalidFrame)?;
            let end = at.checked_add(val_len).ok_or(WireError::InvalidFrame)?;
            if end > input.len() {
                return Err(WireError::UnexpectedEof);
            }
            let val = &input[at..end];
            at = end;
            match id {
                TP_ORIGINAL_DCID => params.original_dcid = Some(decode_tp_cid(val)?),
                TP_MAX_IDLE_TIMEOUT => params.max_idle_timeout_ms = Some(decode_tp_varint(val)?),
                TP_STATELESS_RESET_TOKEN => {
                    params.stateless_reset_token = Some(decode_tp_fixed(val)?);
                }
                TP_MAX_UDP_PAYLOAD_SIZE => params.max_udp_payload_size = Some(decode_tp_varint(val)?),
                TP_INITIAL_MAX_DATA => params.initial_max_data = Some(decode_tp_varint(val)?),
                TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    params.initial_max_stream_data_bidi_local = Some(decode_tp_varint(val)?);
                }
                TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    params.initial_max_stream_data_bidi_remote = Some(decode_tp_varint(val)?);
                }
                TP_INITIAL_MAX_STREAMS_BIDI => {
                    params.initial_max_streams_bidi = Some(decode_tp_varint(val)?);
                }
                TP_INITIAL_MAX_STREAMS_UNI => {
                    params.initial_max_streams_uni = Some(decode_tp_varint(val)?);
                }
                TP_INITIAL_SCID => params.initial_scid = Some(decode_tp_cid(val)?),
                TP_DMESH_PUBLIC_KEY => params.public_key = Some(decode_tp_fixed(val)?),
                TP_DMESH_RANDOM => params.random = Some(decode_tp_fixed(val)?),
                TP_DMESH_VERIFIER => params.verifier = Some(decode_tp_fixed(val)?),
                _ => {}
            }
        }
        Ok(params)
    }
}

/// Encode an RFC 9000 `CRYPTO` (`0x06`) frame (`[0x06][offset: varint][len: varint][data]`) into
/// `out`, returning total bytes written.
pub fn encode_crypto_frame(offset: u64, data: &[u8], out: &mut [u8]) -> Result<usize, WireError> {
    let hdr_len = 1 + varint_len(offset)? + varint_len(data.len() as u64)?;
    let total = hdr_len + data.len();
    if out.len() < total {
        return Err(WireError::BufferTooSmall);
    }
    let mut at = encode_varint(FRAME_CRYPTO, out)?;
    at += encode_varint(offset, &mut out[at..])?;
    at += encode_varint(data.len() as u64, &mut out[at..])?;
    out[at..at + data.len()].copy_from_slice(data);
    Ok(at + data.len())
}

/// Decode the body of an RFC 9000 `CRYPTO` (`0x06`) frame starting at `body_offset` (immediately
/// after the frame-type varint), returning `(offset, data_range, next_offset)`.
pub fn decode_crypto_frame_body(
    input: &[u8],
    body_offset: usize,
) -> Result<(u64, Range<usize>, usize), WireError> {
    let (offset, off_len) =
        decode_varint(input.get(body_offset..).ok_or(WireError::UnexpectedEof)?)?;
    let at_len = body_offset + off_len;
    let (len_u64, len_len) =
        decode_varint(input.get(at_len..).ok_or(WireError::UnexpectedEof)?)?;
    let data_start = at_len + len_len;
    let data_len = usize::try_from(len_u64).map_err(|_| WireError::InvalidFrame)?;
    let data_end = data_start
        .checked_add(data_len)
        .ok_or(WireError::InvalidFrame)?;
    if data_end > input.len() {
        return Err(WireError::UnexpectedEof);
    }
    Ok((offset, data_start..data_end, data_end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_header_round_trip_and_window_reconstruction() {
        for (dcid, scid, pn, pn_len, expected) in [
            (None, ConnectionId::new(7), 1u32, 1u8, 1u32),
            (ConnectionId::new(1), ConnectionId::new(0x1234), 42, 1, 1),
            (
                ConnectionId::new(0x123456),
                ConnectionId::new(0x10_0000_0001),
                0x1234,
                2,
                0x1200,
            ),
            (
                ConnectionId::new(0x7f),
                None,
                0x00ab_cdef,
                4,
                0x00ab_0000,
            ),
        ] {
            let payload = b"\x01\x06\x00\x00";
            let hdr = InitialHeader {
                version: DMESH_QUIC_VERSION,
                dcid,
                scid,
                packet_number: pn,
                packet_number_len: pn_len,
                payload_len: payload.len(),
            };
            let mut buf = [0u8; 64];
            let hdr_len = hdr.encode(&mut buf).expect("encode header");
            assert_eq!(hdr_len, hdr.encoded_len().unwrap());
            buf[hdr_len..hdr_len + payload.len()].copy_from_slice(payload);
            let pkt = &buf[..hdr_len + payload.len()];
            assert!(is_initial_packet(pkt));
            assert_eq!(pkt[0] & 0xf0, 0xc0);
            assert_eq!(&pkt[1..5], &DMESH_QUIC_VERSION.to_be_bytes());

            let (dec, dec_len) = InitialHeader::decode_with_expected(pkt, expected).unwrap();
            assert_eq!(dec_len, hdr_len);
            assert_eq!(dec, hdr);
            assert_eq!(&pkt[dec_len..dec_len + dec.payload_len], payload);
        }
    }

    #[test]
    fn initial_header_skips_nonzero_validation_token() {
        let mut raw = [
            0xc0, 0x44, 0x4d, 0x00, 0x01, // flags + DMESH_QUIC_VERSION
            0x01, 0x07, // dcid len 1 = 7
            0x01, 0x09, // scid len 1 = 9
            0x03, b't', b'o', b'k', // 3-byte validation token
            0x03, // body_len = 1 (pn) + 2 (payload)
            0x05, // pn = 5
            0xaa, 0xbb, // payload
        ];
        let (hdr, hdr_len) = InitialHeader::decode(&raw).unwrap();
        assert_eq!(hdr.dcid, ConnectionId::new(7));
        assert_eq!(hdr.scid, ConnectionId::new(9));
        assert_eq!(hdr.packet_number, 5);
        assert_eq!(hdr.payload_len, 2);
        assert_eq!(&raw[hdr_len..hdr_len + hdr.payload_len], &[0xaa, 0xbb]);

        raw[1] = 0x99;
        assert!(!is_initial_packet(&raw));
        assert_eq!(InitialHeader::decode(&raw), Err(WireError::InvalidFrame));
    }

    #[test]
    fn transport_parameters_round_trip_and_skip_unknown_tlvs() {
        let tp = TransportParameters {
            original_dcid: ConnectionId::new(1),
            max_idle_timeout_ms: Some(30_000),
            stateless_reset_token: Some([0x5a; 16]),
            max_udp_payload_size: Some(1472),
            initial_max_data: Some(64 * 1024),
            initial_max_stream_data_bidi_local: Some(32 * 1024),
            initial_max_stream_data_bidi_remote: Some(32 * 1024),
            initial_max_streams_bidi: Some(8),
            initial_max_streams_uni: Some(4),
            initial_scid: ConnectionId::new(0x1234),
            public_key: Some([0x02; PUBLIC_KEY_COMPRESSED_LEN]),
            random: Some([0x33; ASSOCIATION_RANDOM_LEN]),
            verifier: Some([0xee; INITIAL_VERIFIER_LEN]),
        };

        let mut buf = [0u8; 224];
        let n = tp.encode(&mut buf).unwrap();
        assert_eq!(n, tp.encoded_len().unwrap());
        assert!(n < 192);

        let decoded = TransportParameters::decode(&buf[..n]).unwrap();
        assert_eq!(decoded, tp);

        // Append an unknown future TLV (`id = 0x77`, `len = 3`, bytes `[1, 2, 3]`) and ensure it
        // decodes identically.
        let mut ext = [0u8; 256];
        ext[..n].copy_from_slice(&buf[..n]);
        let mut at = n;
        at += encode_varint(0x77, &mut ext[at..]).unwrap();
        at += encode_varint(3, &mut ext[at..]).unwrap();
        ext[at..at + 3].copy_from_slice(&[1, 2, 3]);
        at += 3;
        assert_eq!(TransportParameters::decode(&ext[..at]).unwrap(), tp);

        // Truncated TLV returns UnexpectedEof.
        assert_eq!(
            TransportParameters::decode(&ext[..at - 1]),
            Err(WireError::UnexpectedEof)
        );
    }

    #[test]
    fn crypto_frame_round_trip() {
        let tp = TransportParameters {
            initial_scid: ConnectionId::new(17),
            initial_max_data: Some(65_536),
            public_key: Some([0x03; PUBLIC_KEY_COMPRESSED_LEN]),
            random: Some([0x44; ASSOCIATION_RANDOM_LEN]),
            verifier: Some([0x99; INITIAL_VERIFIER_LEN]),
            ..Default::default()
        };
        let mut tp_buf = [0u8; 160];
        let tp_len = tp.encode(&mut tp_buf).unwrap();

        let mut frame = [0u8; 192];
        let f_len = encode_crypto_frame(0, &tp_buf[..tp_len], &mut frame).unwrap();
        let (ty, ty_len) = decode_varint(&frame[..f_len]).unwrap();
        assert_eq!(ty, FRAME_CRYPTO);
        let (off, range, next) = decode_crypto_frame_body(&frame[..f_len], ty_len).unwrap();
        assert_eq!(off, 0);
        assert_eq!(next, f_len);
        assert_eq!(
            TransportParameters::decode(&frame[range]).unwrap(),
            tp
        );
    }
}
