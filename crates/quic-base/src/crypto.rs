//! Pluggable `#![no_std]` packet protection (`PacketCrypto`) for `quic-base`, `quic-link`, and `quic-mux`.
//!
//! - On ESP-XIP modules, the device runtime supplies PSA Crypto (`xip_abi::Crypto`), so the module
//!   implements [`PacketCrypto`] directly without pulling in any Rust crypto crates.
//! - On hosts (`feature = "rust-crypto"`), [`RustAes128Gcm`] and [`derive_traffic_keys`] provide
//!   in-place AES-128-GCM and HKDF-SHA256 key derivation.
//! - Relays rewrite only the wire DCID; [`canonical_short_header_aad`] restores the destination
//!   endpoint's local DCID into the associated data before sealing or opening.

use crate::header::{ConnectionId, ShortHeader};
use crate::pool::PoolPacket;
use crate::wire::WireError;

/// Length of an AES-128-GCM traffic key in bytes (`16`).
pub const TRAFFIC_KEY_LEN: usize = 16;

/// Length of a QUIC / TLS 1.3 packet protection IV / nonce in bytes (`12`).
pub const TRAFFIC_IV_LEN: usize = 12;

/// Length of an AES-128-GCM / Poly1305 authentication tag in bytes (`16`).
pub const AEAD_TAG_LEN: usize = 16;

/// Length of each endpoint's per-association random in bytes (`32`).
pub const ASSOCIATION_RANDOM_LEN: usize = 32;

/// Key-phase / mandatory-protection flag bit (`0x04`) in short headers.
pub const FLAG_PROTECTED: u8 = 0x04;

/// Endpoint role (`Client` or `Server`) for directional traffic key selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoRole {
    /// Initiating client (`0` on the wire): sends with `client_to_server`, receives with `server_to_client`.
    Client,
    /// Accepting server (`1` on the wire): sends with `server_to_client`, receives with `client_to_server`.
    Server,
}

/// Errors returned by packet protection and key derivation operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// Key, CID, header, or input buffer parameter is invalid.
    Invalid,
    /// Output buffer, headroom, or packet tail room is too small for the AEAD tag.
    BufferTooSmall,
    /// AEAD authentication tag verification failed (tampered header or body).
    AuthenticationFailed,
    /// Packet is shared (`refs > 1`) and cannot be encrypted or decrypted in-place.
    SharedPacket,
}

impl From<WireError> for CryptoError {
    fn from(err: WireError) -> Self {
        match err {
            WireError::BufferTooSmall => Self::BufferTooSmall,
            _ => Self::Invalid,
        }
    }
}

/// Pluggable directional AEAD packet protection trait (`#![no_std]`).
///
/// Device modules can implement this trait over `xip-abi` / PSA Crypto (`psa_aead_encrypt` /
/// `psa_aead_decrypt`), while hosts use [`RustAes128Gcm`] (`feature = "rust-crypto"`).
pub trait PacketCrypto {
    /// Encrypt `body` in-place for `packet_number` and `associated_data`, returning the 16-byte AEAD tag.
    fn seal_in_place(
        &self,
        packet_number: u32,
        associated_data: &[u8],
        body: &mut [u8],
    ) -> Result<[u8; AEAD_TAG_LEN], CryptoError>;

    /// Authenticate and decrypt `body` in-place for `packet_number`, `associated_data`, and `tag`.
    fn open_in_place(
        &self,
        packet_number: u32,
        associated_data: &[u8],
        body: &mut [u8],
        tag: &[u8; AEAD_TAG_LEN],
    ) -> Result<(), CryptoError>;
}

/// Form a 96-bit (`12`-byte) packet nonce by XORing the big-endian `packet_number` into the low
/// 4 bytes of `iv`.
#[inline]
pub fn make_packet_nonce(iv: &[u8; TRAFFIC_IV_LEN], packet_number: u32) -> [u8; TRAFFIC_IV_LEN] {
    let mut nonce = *iv;
    let pn = packet_number.to_be_bytes();
    for (dst, src) in nonce[TRAFFIC_IV_LEN - pn.len()..].iter_mut().zip(pn) {
        *dst ^= src;
    }
    nonce
}

/// Serialize the canonical short-header associated data (`AAD`) using `endpoint_dcid`.
///
/// Intermediate relays rewrite only the wire DCID; the destination endpoint restores its own
/// `endpoint_dcid` before calling [`canonical_short_header_aad`], so relays never modify
/// ciphertext or AEAD tags.
pub fn canonical_short_header_aad(
    mut header: ShortHeader,
    endpoint_dcid: ConnectionId,
    output: &mut [u8],
) -> Result<usize, CryptoError> {
    if endpoint_dcid.value() == 0 {
        return Err(CryptoError::Invalid);
    }
    header.dcid = endpoint_dcid;
    header.encode(output).map_err(CryptoError::from)
}

/// Encrypt a short-header [`PoolPacket`] in-place using `crypto`, setting `FLAG_PROTECTED` (`0x04`)
/// on the first byte, computing canonical AAD with `endpoint_dcid`, encrypting the frame body in
/// place, and appending the 16-byte AEAD tag into the packet's tail room.
pub fn seal_short_packet_in_place<P: PoolPacket, C: PacketCrypto + ?Sized>(
    packet: &mut P,
    crypto: &C,
    endpoint_dcid: ConnectionId,
) -> Result<(), CryptoError> {
    if packet.tailroom() < AEAD_TAG_LEN {
        return Err(CryptoError::BufferTooSmall);
    }
    let range = packet.range();
    let slot = packet.slot_slice_mut().map_err(|_| CryptoError::SharedPacket)?;
    let pkt_bytes = &mut slot[range.clone()];
    if pkt_bytes.is_empty() {
        return Err(CryptoError::Invalid);
    }
    pkt_bytes[0] |= FLAG_PROTECTED;
    let (header, header_len) = ShortHeader::decode(pkt_bytes).map_err(CryptoError::from)?;
    if pkt_bytes.len() <= header_len {
        return Err(CryptoError::Invalid);
    }
    let mut aad = [0u8; 16];
    let aad_len = canonical_short_header_aad(header, endpoint_dcid, &mut aad)?;
    let tag = crypto.seal_in_place(
        header.packet_number,
        &aad[..aad_len],
        &mut pkt_bytes[header_len..],
    )?;
    packet
        .append(&tag)
        .map_err(|_| CryptoError::BufferTooSmall)?;
    Ok(())
}

/// Authenticate and decrypt a protected short-header [`PoolPacket`] in-place using `crypto` and
/// `endpoint_dcid` (with reconstructed `full_packet_number`), stripping the 16-byte trailing AEAD tag.
pub fn open_short_packet_in_place<P: PoolPacket, C: PacketCrypto + ?Sized>(
    packet: &mut P,
    crypto: &C,
    header_flags: u8,
    header_len: usize,
    full_packet_number: u32,
    packet_number_len: u8,
    endpoint_dcid: ConnectionId,
) -> Result<(), CryptoError> {
    if header_flags & FLAG_PROTECTED == 0 {
        return Err(CryptoError::AuthenticationFailed);
    }
    let range = packet.range();
    if range.len() < header_len + AEAD_TAG_LEN + 1 {
        return Err(CryptoError::Invalid);
    }
    let canonical_header = ShortHeader {
        flags: header_flags,
        dcid: endpoint_dcid,
        packet_number: full_packet_number,
        packet_number_len,
    };
    let mut aad = [0u8; 16];
    let aad_len = canonical_short_header_aad(canonical_header, endpoint_dcid, &mut aad)?;
    let slot = packet.slot_slice_mut().map_err(|_| CryptoError::SharedPacket)?;
    let pkt_bytes = &mut slot[range.clone()];
    let tag_start = pkt_bytes.len() - AEAD_TAG_LEN;
    let mut tag = [0u8; AEAD_TAG_LEN];
    tag.copy_from_slice(&pkt_bytes[tag_start..]);
    crypto.open_in_place(
        full_packet_number,
        &aad[..aad_len],
        &mut pkt_bytes[header_len..tag_start],
        &tag,
    )?;
    packet
        .set_range(range.start..(range.end - AEAD_TAG_LEN))
        .map_err(|_| CryptoError::Invalid)
}

/// Raw directional key + IV material (`16`-byte key + `12`-byte IV), usable by either host
/// `rust-crypto` or device PSA Crypto adapters.
#[derive(Clone)]
pub struct DirectionKeyMaterial {
    /// 128-bit AES-GCM key.
    pub key: [u8; TRAFFIC_KEY_LEN],
    /// 96-bit base IV.
    pub iv: [u8; TRAFFIC_IV_LEN],
}

impl DirectionKeyMaterial {
    /// Construct from a 28-byte `key || iv` slice.
    pub fn from_material(material: &[u8; TRAFFIC_KEY_LEN + TRAFFIC_IV_LEN]) -> Self {
        let mut key = [0u8; TRAFFIC_KEY_LEN];
        key.copy_from_slice(&material[..TRAFFIC_KEY_LEN]);
        let mut iv = [0u8; TRAFFIC_IV_LEN];
        iv.copy_from_slice(&material[TRAFFIC_KEY_LEN..]);
        Self { key, iv }
    }

    /// Compute the 12-byte packet nonce for `packet_number`.
    #[inline]
    pub fn nonce(&self, packet_number: u32) -> [u8; TRAFFIC_IV_LEN] {
        make_packet_nonce(&self.iv, packet_number)
    }
}

#[cfg(feature = "rust-crypto")]
mod host_crypto {
    use super::*;
    use aes_gcm::{Aes128Gcm, KeyInit, Nonce, Tag, aead::AeadInPlace};
    use hkdf::Hkdf;
    use sha2::Sha256;
    use zeroize::Zeroize;

    /// Host AES-128-GCM directional packet cipher implementing [`PacketCrypto`].
    #[derive(Clone)]
    pub struct RustAes128Gcm {
        key: [u8; TRAFFIC_KEY_LEN],
        iv: [u8; TRAFFIC_IV_LEN],
    }

    impl RustAes128Gcm {
        /// Create a new [`RustAes128Gcm`] directional key from `key` and `iv`.
        pub const fn new(key: [u8; TRAFFIC_KEY_LEN], iv: [u8; TRAFFIC_IV_LEN]) -> Self {
            Self { key, iv }
        }

        /// Create from 28-byte `key || iv` material.
        pub fn from_material(material: &[u8; TRAFFIC_KEY_LEN + TRAFFIC_IV_LEN]) -> Self {
            let m = DirectionKeyMaterial::from_material(material);
            Self {
                key: m.key,
                iv: m.iv,
            }
        }

        /// Compute the 96-bit packet nonce for `packet_number`.
        #[inline]
        pub fn nonce(&self, packet_number: u32) -> [u8; TRAFFIC_IV_LEN] {
            make_packet_nonce(&self.iv, packet_number)
        }
    }

    impl Drop for RustAes128Gcm {
        fn drop(&mut self) {
            self.key.zeroize();
            self.iv.zeroize();
        }
    }

    impl PacketCrypto for RustAes128Gcm {
        fn seal_in_place(
            &self,
            packet_number: u32,
            associated_data: &[u8],
            body: &mut [u8],
        ) -> Result<[u8; AEAD_TAG_LEN], CryptoError> {
            let cipher =
                Aes128Gcm::new_from_slice(&self.key).map_err(|_| CryptoError::Invalid)?;
            let nonce = self.nonce(packet_number);
            let tag = cipher
                .encrypt_in_place_detached(Nonce::from_slice(&nonce), associated_data, body)
                .map_err(|_| CryptoError::Invalid)?;
            let mut out = [0u8; AEAD_TAG_LEN];
            out.copy_from_slice(&tag);
            Ok(out)
        }

        fn open_in_place(
            &self,
            packet_number: u32,
            associated_data: &[u8],
            body: &mut [u8],
            tag: &[u8; AEAD_TAG_LEN],
        ) -> Result<(), CryptoError> {
            let cipher =
                Aes128Gcm::new_from_slice(&self.key).map_err(|_| CryptoError::Invalid)?;
            let nonce = self.nonce(packet_number);
            cipher
                .decrypt_in_place_detached(
                    Nonce::from_slice(&nonce),
                    associated_data,
                    body,
                    Tag::from_slice(tag),
                )
                .map_err(|_| CryptoError::AuthenticationFailed)
        }
    }

    /// Direction-separated AES-128-GCM traffic keys derived from a 256-bit PSK and per-association randoms.
    pub struct TrafficKeys {
        /// Key used by the client to seal and by the server to open.
        pub client_to_server: RustAes128Gcm,
        /// Key used by the server to seal and by the client to open.
        pub server_to_client: RustAes128Gcm,
    }

    /// Endpoint-ordered send and receive keys.
    #[derive(Clone)]
    pub struct EndpointKeys {
        /// Key used to seal outbound packets.
        pub send: RustAes128Gcm,
        /// Key used to open inbound packets.
        pub receive: RustAes128Gcm,
    }

    impl TrafficKeys {
        /// Select `(send, receive)` keys for `role`.
        pub fn for_role(self, role: CryptoRole) -> EndpointKeys {
            match role {
                CryptoRole::Client => EndpointKeys {
                    send: self.client_to_server,
                    receive: self.server_to_client,
                },
                CryptoRole::Server => EndpointKeys {
                    send: self.server_to_client,
                    receive: self.client_to_server,
                },
            }
        }
    }

    /// Derive initial directional traffic keys using HKDF-SHA256 (`dmesh/quic-lite/traffic/v1/`).
    pub fn derive_traffic_keys(
        psk: &[u8; 32],
        client_random: &[u8; ASSOCIATION_RANDOM_LEN],
        server_random: &[u8; ASSOCIATION_RANDOM_LEN],
        client_cid: ConnectionId,
        server_cid: ConnectionId,
    ) -> Result<TrafficKeys, CryptoError> {
        if client_cid.value() == 0 || server_cid.value() == 0 || client_cid == server_cid {
            return Err(CryptoError::Invalid);
        }
        let mut salt = [0u8; ASSOCIATION_RANDOM_LEN * 2];
        salt[..ASSOCIATION_RANDOM_LEN].copy_from_slice(client_random);
        salt[ASSOCIATION_RANDOM_LEN..].copy_from_slice(server_random);
        let schedule = Hkdf::<Sha256>::new(Some(&salt), psk);
        let mut c2s = [0u8; TRAFFIC_KEY_LEN + TRAFFIC_IV_LEN];
        let mut s2c = [0u8; TRAFFIC_KEY_LEN + TRAFFIC_IV_LEN];
        let mut info = [0u8; 64];
        let label = b"dmesh/quic-lite/traffic/v1/";
        info[..label.len()].copy_from_slice(label);
        info[label.len()..label.len() + 8].copy_from_slice(&client_cid.value().to_be_bytes());
        info[label.len() + 8..label.len() + 16].copy_from_slice(&server_cid.value().to_be_bytes());
        let context_len = label.len() + 16;

        info[context_len..context_len + 4].copy_from_slice(b"c2s\0");
        schedule
            .expand(&info[..context_len + 4], &mut c2s)
            .map_err(|_| CryptoError::Invalid)?;
        info[context_len..context_len + 4].copy_from_slice(b"s2c\0");
        schedule
            .expand(&info[..context_len + 4], &mut s2c)
            .map_err(|_| CryptoError::Invalid)?;
        salt.zeroize();
        info.zeroize();
        let keys = TrafficKeys {
            client_to_server: RustAes128Gcm::from_material(&c2s),
            server_to_client: RustAes128Gcm::from_material(&s2c),
        };
        c2s.zeroize();
        s2c.zeroize();
        Ok(keys)
    }
}

#[cfg(feature = "rust-crypto")]
pub use host_crypto::{EndpointKeys, RustAes128Gcm, TrafficKeys, derive_traffic_keys};

#[cfg(all(test, feature = "rust-crypto"))]
mod tests {
    use super::*;
    use crate::pool::{PacketPool, StaticPacketPool};

    #[test]
    fn association_derivation_and_zero_copy_packet_seal_open_across_relay_rewrite() {
        let client_cid = ConnectionId::new(0x1020).unwrap();
        let server_cid = ConnectionId::new(0x3040).unwrap();
        let keys =
            derive_traffic_keys(&[0x5a; 32], &[1; 32], &[2; 32], client_cid, server_cid).unwrap();
        let client_keys = keys.for_role(CryptoRole::Client);

        let keys2 =
            derive_traffic_keys(&[0x5a; 32], &[1; 32], &[2; 32], client_cid, server_cid).unwrap();
        let server_keys = keys2.for_role(CryptoRole::Server);

        let pool = StaticPacketPool::<4, 512>::new();
        let mut pkt = (&pool).alloc().unwrap();
        pkt.append(b"confidential stream frame").unwrap();

        // Client sends with wire DCID = relay hop CID (0x55), but seals AAD with canonical server_cid (0x3040).
        let relay_cid = ConnectionId::new(0x55).unwrap();
        let hdr = ShortHeader {
            flags: 0x40,
            dcid: relay_cid,
            packet_number: 42,
            packet_number_len: 2,
        };
        let mut hdr_bytes = [0u8; 16];
        let hdr_len = hdr.encode(&mut hdr_bytes).unwrap();
        pkt.prepend(&hdr_bytes[..hdr_len]).unwrap();

        seal_short_packet_in_place(&mut pkt, &client_keys.send, server_cid).unwrap();
        assert_eq!(pkt.bytes()[0] & FLAG_PROTECTED, FLAG_PROTECTED);

        // Relay rewrites wire DCID from 1-byte 0x55 to 2-byte server_cid (0x3040) in headroom without touching body/tag.
        let r = pkt.range();
        let mut new_hdr = [0u8; 16];
        let new_hdr_len = (ShortHeader {
            flags: pkt.bytes()[0],
            dcid: server_cid,
            packet_number: 42,
            packet_number_len: 2,
        })
        .encode(&mut new_hdr)
        .unwrap();
        let tail = r.start + hdr_len;
        let new_start = tail - new_hdr_len;
        pkt.slot_slice_mut().unwrap()[new_start..tail].copy_from_slice(&new_hdr[..new_hdr_len]);
        pkt.set_range(new_start..r.end).unwrap();

        // Server decodes prefix, reconstructs packet number, and opens in-place.
        let prefix = ShortHeader::decode_prefix(pkt.bytes()).unwrap();
        let full_pn = prefix.reconstruct(0).unwrap().packet_number;
        assert_eq!(full_pn, 42);
        open_short_packet_in_place(
            &mut pkt,
            &server_keys.receive,
            prefix.flags,
            prefix.header_len,
            full_pn,
            prefix.packet_number_len,
            server_cid,
        )
        .unwrap();
        assert_eq!(&pkt.bytes()[prefix.header_len..], b"confidential stream frame");
    }
}
