//! Pluggable `#![no_std]` packet protection (`PacketCrypto`, `CryptoProvider`) for `quic-base`,
//! `quic-link`, and `quic-mux`.
//!
//! - On ESP-XIP modules, the device runtime supplies native PSA Crypto (`xip_abi::Crypto`), so
//!   the module supplies a [`CryptoProvider`] backed by PSA without pulling in any Rust crypto
//!   crates (`rust-crypto` remains disabled on ESP32).
//! - On hosts (`feature = "rust-crypto"`), [`CryptoProvider::rust_crypto()`] and [`RustAes128Gcm`]
//!   provide in-place AES-128-GCM and HKDF-SHA256 key derivation.
//! - Relays rewrite only the wire DCID; [`canonical_short_header_aad`] restores the destination
//!   endpoint's local DCID into the associated data before sealing or opening.
//!
//! ### `#[inline(never)]` discipline
//! Key-derivation, handshake, and AEAD helpers in this module are marked `#[inline(never)]` so
//! their temporary stack buffers (`[u8; 64]`/`[u8; 128]`/`[u32; 64]`) stay in separate,
//! non-overlapping stack frames. Embedded ESP32 XIP modules (`mod_quic2`) run on an 8 KiB
//! FreeRTOS worker stack; without `#[inline(never)]`, LLVM inlines multiple helpers into a single
//! caller frame, risking stack overflow and bloating `.dmod` code size.

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

/// Length of a compressed SEC1 P-256 public key in bytes (`33`).
pub const PUBLIC_KEY_COMPRESSED_LEN: usize = 33;

/// Length of an HMAC-SHA256 `Initial` verifier in bytes (`32`).
pub const INITIAL_VERIFIER_LEN: usize = 32;

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

    /// Optional packet-borrow short-header transform descriptor (`(context, fn, key, base_iv)`),
    /// keeping [`PacketCrypto`] object-safe (`&dyn PacketCrypto`).
    #[inline]
    fn packet_transform(
        &self,
    ) -> Option<(
        usize,
        PacketTransformFn,
        &[u8; TRAFFIC_KEY_LEN],
        &[u8; TRAFFIC_IV_LEN],
    )> {
        None
    }
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
///
/// Uses the wire packet number directly when `packet_number_len` carries the full value; callers
/// sending truncated packet numbers (`pn >= 256` with `packet_number_len < 4`, or `pn >= 128`) must
/// call [`seal_short_packet_in_place_with_pn`] with the un-truncated 32-bit packet number.
#[inline(never)]
pub fn seal_short_packet_in_place<P: PoolPacket, C: PacketCrypto + ?Sized>(
    packet: &mut P,
    crypto: &C,
    endpoint_dcid: ConnectionId,
) -> Result<(), CryptoError> {
    seal_short_packet_inner(packet, crypto, None, endpoint_dcid)
}

/// Encrypt a short-header [`PoolPacket`] in-place using `crypto`, `full_packet_number` (for the
/// 96-bit AEAD nonce and canonical AAD), and `endpoint_dcid`, setting `FLAG_PROTECTED` (`0x04`)
/// and appending the 16-byte AEAD tag.
#[inline(never)]
pub fn seal_short_packet_in_place_with_pn<P: PoolPacket, C: PacketCrypto + ?Sized>(
    packet: &mut P,
    crypto: &C,
    full_packet_number: u32,
    endpoint_dcid: ConnectionId,
) -> Result<(), CryptoError> {
    seal_short_packet_inner(packet, crypto, Some(full_packet_number), endpoint_dcid)
}

fn seal_short_packet_inner<P: PoolPacket, C: PacketCrypto + ?Sized>(
    packet: &mut P,
    crypto: &C,
    full_packet_number: Option<u32>,
    endpoint_dcid: ConnectionId,
) -> Result<(), CryptoError> {
    if packet.tailroom() < AEAD_TAG_LEN {
        return Err(CryptoError::BufferTooSmall);
    }
    let pkt_bytes = packet.bytes();
    if pkt_bytes.is_empty() {
        return Err(CryptoError::Invalid);
    }
    let (mut header, header_len) = ShortHeader::decode(pkt_bytes).map_err(CryptoError::from)?;
    header.flags |= FLAG_PROTECTED;
    if let Some(full_pn) = full_packet_number {
        header.packet_number = full_pn;
    }
    if pkt_bytes.len() <= header_len {
        return Err(CryptoError::Invalid);
    }
    let mut aad = [0u8; 16];
    let aad_len = canonical_short_header_aad(header, endpoint_dcid, &mut aad)?;
    if let (Some((ctx, transform, key, iv)), Some(src_handle)) =
        (crypto.packet_transform(), packet.native_packet_handle())
    {
        let nonce = make_packet_nonce(iv, header.packet_number);
        let (dst_handle, dst_range) = transform(
            ctx,
            false,
            key,
            &nonce,
            &aad[..aad_len],
            header_len,
            src_handle,
            packet.slot_slice(),
            packet.range(),
        )?;
        return packet
            .swap_native_packet(dst_handle, dst_range)
            .map_err(|_| CryptoError::Invalid);
    }
    let range = packet.range();
    let tag = {
        let slot = packet.slot_slice_mut().map_err(|_| CryptoError::SharedPacket)?;
        slot[range.start] |= FLAG_PROTECTED;
        crypto.seal_in_place(
            header.packet_number,
            &aad[..aad_len],
            &mut slot[range.start + header_len..range.end],
        )?
    };
    packet
        .append(&tag)
        .map_err(|_| CryptoError::BufferTooSmall)
}

/// Authenticate and decrypt a protected short-header [`PoolPacket`] using `crypto` and
/// `endpoint_dcid` (with reconstructed `full_packet_number`), stripping the 16-byte trailing AEAD tag.
#[inline(never)]
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
    if let (Some((ctx, transform, key, iv)), Some(src_handle)) =
        (crypto.packet_transform(), packet.native_packet_handle())
    {
        let nonce = make_packet_nonce(iv, full_packet_number);
        let (dst_handle, dst_range) = transform(
            ctx,
            true,
            key,
            &nonce,
            &aad[..aad_len],
            header_len,
            src_handle,
            packet.slot_slice(),
            range,
        )?;
        return packet
            .swap_native_packet(dst_handle, dst_range)
            .map_err(|_| CryptoError::Invalid);
    }
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

fn wipe_bytes(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: `b` points to a valid initialized byte inside the mutable slice.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

impl Drop for DirectionKeyMaterial {
    fn drop(&mut self) {
        wipe_bytes(&mut self.key);
        wipe_bytes(&mut self.iv);
    }
}

/// Function pointer for optional packet-borrow AEAD transforms on native shared-pool packets.
///
/// When `open == false` (`seal`), encrypts `src_slot[src_range.start + header_len .. src_range.end]`
/// into a freshly borrowed destination pool packet and returns `(dst_handle, dst_range)` covering
/// `[wire_header_with_protected_flag | ciphertext | 16-byte tag]`.
/// When `open == true` (`open`), authenticates and decrypts into a borrowed destination packet and
/// returns `(dst_handle, dst_range)` covering `[wire_header | plaintext]`.
pub type PacketTransformFn = fn(
    context: usize,
    open: bool,
    key: &[u8; TRAFFIC_KEY_LEN],
    nonce: &[u8; TRAFFIC_IV_LEN],
    aad: &[u8],
    header_len: usize,
    src_handle: u32,
    src_slot: &[u8],
    src_range: core::ops::Range<usize>,
) -> Result<(u32, core::ops::Range<usize>), CryptoError>;

/// Pluggable `#![no_std]` cryptographic backend for SHA-256 and packet AEAD (AES-128-GCM / AES-128-CCM).
///
/// Embedded ESP-XIP firmware uses native PSA Crypto via `xip_abi::CryptoClient`, while hosts
/// and Android use [`CryptoProvider::rust_crypto()`] when `feature = "rust-crypto"` is enabled.
#[derive(Clone, Copy)]
pub struct CryptoProvider {
    /// Opaque backend context passed as the first argument to every function pointer
    /// (e.g. a `xip_abi::Hw` pointer cast to `usize` on ESP-XIP, or `0` on hosts).
    pub context: usize,
    /// Compute SHA-256 across concatenated slices `chunks`, storing the 32-byte digest in `out`.
    pub sha256: fn(context: usize, chunks: &[&[u8]], out: &mut [u8; 32]) -> Result<(), CryptoError>,
    /// Seal `body` in-place using the provider's AEAD (`key`, 12-byte `nonce`, `aad`), returning the 16-byte tag.
    pub aead_seal: fn(
        context: usize,
        key: &[u8; TRAFFIC_KEY_LEN],
        nonce: &[u8; TRAFFIC_IV_LEN],
        aad: &[u8],
        body: &mut [u8],
    ) -> Result<[u8; AEAD_TAG_LEN], CryptoError>,
    /// Authenticate and open `body` in-place using the provider's AEAD (`key`, 12-byte `nonce`, `aad`, `tag`).
    pub aead_open: fn(
        context: usize,
        key: &[u8; TRAFFIC_KEY_LEN],
        nonce: &[u8; TRAFFIC_IV_LEN],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8; AEAD_TAG_LEN],
    ) -> Result<(), CryptoError>,
    /// Optional packet-borrow short-header transform using native pool handles (`None` falls back to
    /// in-place [`Self::aead_seal`] / [`Self::aead_open`]).
    pub aead_packet: Option<PacketTransformFn>,
}

impl core::fmt::Debug for CryptoProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CryptoProvider")
            .field("context", &self.context)
            .finish_non_exhaustive()
    }
}

impl PartialEq for CryptoProvider {
    fn eq(&self, other: &Self) -> bool {
        let pkt_eq = match (self.aead_packet, other.aead_packet) {
            (Some(a), Some(b)) => core::ptr::fn_addr_eq(a, b),
            (None, None) => true,
            _ => false,
        };
        self.context == other.context
            && core::ptr::fn_addr_eq(self.sha256, other.sha256)
            && core::ptr::fn_addr_eq(self.aead_seal, other.aead_seal)
            && core::ptr::fn_addr_eq(self.aead_open, other.aead_open)
            && pkt_eq
    }
}

impl Eq for CryptoProvider {}

/// Directional packet cipher delegating sealing/opening to a [`CryptoProvider`].
#[derive(Clone)]
pub struct ProviderAeadKey {
    provider: CryptoProvider,
    material: DirectionKeyMaterial,
}

impl ProviderAeadKey {
    /// Construct from a [`CryptoProvider`] and directional key/IV material.
    pub const fn new(provider: CryptoProvider, material: DirectionKeyMaterial) -> Self {
        Self { provider, material }
    }

    /// Borrow the underlying 16-byte key and 12-byte base IV.
    #[inline]
    pub const fn material(&self) -> &DirectionKeyMaterial {
        &self.material
    }

    /// Borrow the underlying [`CryptoProvider`].
    #[inline]
    pub const fn provider(&self) -> &CryptoProvider {
        &self.provider
    }
}

impl PacketCrypto for ProviderAeadKey {
    fn seal_in_place(
        &self,
        packet_number: u32,
        associated_data: &[u8],
        body: &mut [u8],
    ) -> Result<[u8; AEAD_TAG_LEN], CryptoError> {
        let nonce = self.material.nonce(packet_number);
        (self.provider.aead_seal)(
            self.provider.context,
            &self.material.key,
            &nonce,
            associated_data,
            body,
        )
    }

    fn open_in_place(
        &self,
        packet_number: u32,
        associated_data: &[u8],
        body: &mut [u8],
        tag: &[u8; AEAD_TAG_LEN],
    ) -> Result<(), CryptoError> {
        let nonce = self.material.nonce(packet_number);
        (self.provider.aead_open)(
            self.provider.context,
            &self.material.key,
            &nonce,
            associated_data,
            body,
            tag,
        )
    }

    #[inline]
    fn packet_transform(
        &self,
    ) -> Option<(
        usize,
        PacketTransformFn,
        &[u8; TRAFFIC_KEY_LEN],
        &[u8; TRAFFIC_IV_LEN],
    )> {
        self.provider
            .aead_packet
            .map(|f| (self.provider.context, f, &self.material.key, &self.material.iv))
    }
}

/// Direction-separated AES-128-GCM traffic keys derived from a 256-bit PSK and per-association randoms.
pub struct TrafficKeys {
    /// Key used by the client to seal and by the server to open.
    pub client_to_server: ProviderAeadKey,
    /// Key used by the server to seal and by the client to open.
    pub server_to_client: ProviderAeadKey,
}

/// Endpoint-ordered send and receive keys.
#[derive(Clone)]
pub struct EndpointKeys {
    /// Key used to seal outbound packets.
    pub send: ProviderAeadKey,
    /// Key used to open inbound packets.
    pub receive: ProviderAeadKey,
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

const CONTROL_SECRET_SALT: &[u8] = b"dmesh/control/v1";
const CONTROL_SECRET_INFO_PREFIX: &[u8] = b"device-credential\0";
const API_KEY_SALT: &[u8] = b"dmesh/quic-api-key/v1";
const API_KEY_INFO_PREFIX: &[u8] = b"caller\0";
const INITIAL_VERIFIER_LABEL: &[u8] = b"dmesh/quic-initial-v1\0";

#[inline(never)]
fn hmac_sha256_with(
    provider: &CryptoProvider,
    key: &[u8],
    chunks: &[&[u8]],
) -> Result<[u8; 32], CryptoError> {
    let mut k0 = [0u8; 64];
    if key.len() > 64 {
        let mut digest = [0u8; 32];
        let res = (provider.sha256)(provider.context, &[key], &mut digest);
        if let Err(e) = res {
            wipe_bytes(&mut digest);
            return Err(e);
        }
        k0[..32].copy_from_slice(&digest);
        wipe_bytes(&mut digest);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..64 {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }
    wipe_bytes(&mut k0);

    let mut inner_chunks: [&[u8]; 8] = [&[]; 8];
    if chunks.len() > 7 {
        wipe_bytes(&mut ipad);
        wipe_bytes(&mut opad);
        return Err(CryptoError::Invalid);
    }
    inner_chunks[0] = &ipad[..];
    for (i, &chunk) in chunks.iter().enumerate() {
        inner_chunks[i + 1] = chunk;
    }
    let mut inner_hash = [0u8; 32];
    let res = (provider.sha256)(
        provider.context,
        &inner_chunks[..chunks.len() + 1],
        &mut inner_hash,
    );
    wipe_bytes(&mut ipad);
    if let Err(e) = res {
        wipe_bytes(&mut opad);
        return Err(e);
    }
    let mut out = [0u8; 32];
    let res = (provider.sha256)(provider.context, &[&opad[..], &inner_hash[..]], &mut out);
    wipe_bytes(&mut opad);
    wipe_bytes(&mut inner_hash);
    res?;
    Ok(out)
}

#[inline(never)]
fn hkdf_sha256_with(
    provider: &CryptoProvider,
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let zeros = [0u8; 32];
    let salt_eff = if salt.is_empty() { &zeros[..] } else { salt };
    let mut prk = hmac_sha256_with(provider, salt_eff, &[ikm])?;
    let mut prev = [0u8; 32];
    let mut prev_len = 0usize;
    let mut offset = 0usize;
    let mut counter = 1u8;
    while offset < out.len() {
        if counter == 0 {
            wipe_bytes(&mut prk);
            wipe_bytes(&mut prev);
            return Err(CryptoError::Invalid);
        }
        let block = match hmac_sha256_with(provider, &prk, &[&prev[..prev_len], info, &[counter]]) {
            Ok(b) => b,
            Err(e) => {
                wipe_bytes(&mut prk);
                wipe_bytes(&mut prev);
                return Err(e);
            }
        };
        let take = (out.len() - offset).min(32);
        out[offset..offset + take].copy_from_slice(&block[..take]);
        prev = block;
        prev_len = 32;
        offset += take;
        counter = counter.wrapping_add(1);
    }
    wipe_bytes(&mut prk);
    wipe_bytes(&mut prev);
    Ok(())
}

/// Derive a 16-byte ULA `vip6` address (`fc00::/8` + first 8 bytes of `SHA-256(public_key)`)
/// using `provider`.
#[inline(never)]
pub fn vip6_from_public_key_with(
    provider: &CryptoProvider,
    public_key: &[u8; PUBLIC_KEY_COMPRESSED_LEN],
) -> Result<[u8; 16], CryptoError> {
    let mut digest = [0u8; 32];
    (provider.sha256)(provider.context, &[public_key], &mut digest)?;
    let mut vip6 = [0u8; 16];
    vip6[0] = 0xfc;
    vip6[8..16].copy_from_slice(&digest[..8]);
    Ok(vip6)
}

/// Derive a node's 32-byte `node_secret` from `control_secret` and `device_public_key` using `provider`.
#[inline(never)]
pub fn derive_device_secret_with(
    provider: &CryptoProvider,
    control_secret: &[u8],
    device_public_key: &[u8; PUBLIC_KEY_COMPRESSED_LEN],
) -> Result<[u8; 32], CryptoError> {
    if control_secret.len() < 16 {
        return Err(CryptoError::Invalid);
    }
    let mut info = [0u8; 18 + PUBLIC_KEY_COMPRESSED_LEN];
    info[..CONTROL_SECRET_INFO_PREFIX.len()].copy_from_slice(CONTROL_SECRET_INFO_PREFIX);
    info[CONTROL_SECRET_INFO_PREFIX.len()..].copy_from_slice(device_public_key);
    let mut out = [0u8; 32];
    hkdf_sha256_with(provider, CONTROL_SECRET_SALT, control_secret, &info, &mut out)?;
    Ok(out)
}

/// Derive a per-caller 32-byte receive/send `api_key` from `target_node_secret` using `provider`.
#[inline(never)]
pub fn derive_peer_api_key_with(
    provider: &CryptoProvider,
    target_node_secret: &[u8; 32],
    caller_public_key: &[u8],
) -> Result<[u8; 32], CryptoError> {
    if caller_public_key.len() > PUBLIC_KEY_COMPRESSED_LEN {
        return Err(CryptoError::Invalid);
    }
    let mut info = [0u8; 7 + PUBLIC_KEY_COMPRESSED_LEN];
    info[..API_KEY_INFO_PREFIX.len()].copy_from_slice(API_KEY_INFO_PREFIX);
    let total = API_KEY_INFO_PREFIX.len() + caller_public_key.len();
    info[API_KEY_INFO_PREFIX.len()..total].copy_from_slice(caller_public_key);
    let mut out = [0u8; 32];
    hkdf_sha256_with(provider, API_KEY_SALT, target_node_secret, &info[..total], &mut out)?;
    Ok(out)
}

#[inline(never)]
fn derive_traffic_keys_inner(
    provider: &CryptoProvider,
    psk: &[u8; 32],
    client_random: &[u8; ASSOCIATION_RANDOM_LEN],
    server_random: &[u8; ASSOCIATION_RANDOM_LEN],
    client_cid: ConnectionId,
    server_cid: ConnectionId,
) -> Result<TrafficKeys, CryptoError> {
    if client_cid.value() == 0 || server_cid.value() == 0 {
        return Err(CryptoError::Invalid);
    }
    let mut salt = [0u8; ASSOCIATION_RANDOM_LEN * 2];
    salt[..ASSOCIATION_RANDOM_LEN].copy_from_slice(client_random);
    salt[ASSOCIATION_RANDOM_LEN..].copy_from_slice(server_random);
    let mut c2s = [0u8; TRAFFIC_KEY_LEN + TRAFFIC_IV_LEN];
    let mut s2c = [0u8; TRAFFIC_KEY_LEN + TRAFFIC_IV_LEN];
    let mut info = [0u8; 64];
    let label = b"dmesh/quic-lite/traffic/v1/";
    info[..label.len()].copy_from_slice(label);
    info[label.len()..label.len() + 8].copy_from_slice(&client_cid.value().to_be_bytes());
    info[label.len() + 8..label.len() + 16].copy_from_slice(&server_cid.value().to_be_bytes());
    let context_len = label.len() + 16;

    info[context_len..context_len + 4].copy_from_slice(b"c2s\0");
    let res1 = hkdf_sha256_with(provider, &salt, psk, &info[..context_len + 4], &mut c2s);
    info[context_len..context_len + 4].copy_from_slice(b"s2c\0");
    let res2 = hkdf_sha256_with(provider, &salt, psk, &info[..context_len + 4], &mut s2c);
    wipe_bytes(&mut salt);
    wipe_bytes(&mut info);
    if let Err(e) = res1.and(res2) {
        wipe_bytes(&mut c2s);
        wipe_bytes(&mut s2c);
        return Err(e);
    }
    let keys = TrafficKeys {
        client_to_server: ProviderAeadKey::new(*provider, DirectionKeyMaterial::from_material(&c2s)),
        server_to_client: ProviderAeadKey::new(*provider, DirectionKeyMaterial::from_material(&s2c)),
    };
    wipe_bytes(&mut c2s);
    wipe_bytes(&mut s2c);
    Ok(keys)
}

/// Derive initial directional traffic keys using `provider` and HKDF-SHA256.
pub fn derive_traffic_keys_with(
    provider: &CryptoProvider,
    psk: &[u8; 32],
    client_random: &[u8; ASSOCIATION_RANDOM_LEN],
    server_random: &[u8; ASSOCIATION_RANDOM_LEN],
    client_cid: ConnectionId,
    server_cid: ConnectionId,
) -> Result<TrafficKeys, CryptoError> {
    derive_traffic_keys_inner(
        provider,
        psk,
        client_random,
        server_random,
        client_cid,
        server_cid,
    )
}

/// Derive static directional traffic keys directly from a pre-shared `api_key` using `provider`.
pub fn derive_static_traffic_keys_with(
    provider: &CryptoProvider,
    api_key: &[u8; 32],
    client_cid: ConnectionId,
    server_cid: ConnectionId,
) -> Result<TrafficKeys, CryptoError> {
    derive_traffic_keys_inner(
        provider,
        api_key,
        &[0u8; ASSOCIATION_RANDOM_LEN],
        &[0u8; ASSOCIATION_RANDOM_LEN],
        client_cid,
        server_cid,
    )
}

/// Compute the 32-byte `HMAC-SHA256` `Initial` verifier using `provider`.
#[inline(never)]
pub fn compute_initial_verifier_with(
    provider: &CryptoProvider,
    api_key: &[u8; 32],
    role: CryptoRole,
    scid: Option<ConnectionId>,
    original_dcid: Option<ConnectionId>,
    public_key: &[u8; PUBLIC_KEY_COMPRESSED_LEN],
    random: &[u8; ASSOCIATION_RANDOM_LEN],
) -> Result<[u8; INITIAL_VERIFIER_LEN], CryptoError> {
    let role_byte = match role {
        CryptoRole::Client => 0u8,
        CryptoRole::Server => 1u8,
    };
    let scid_bytes = scid.map_or(0u64, ConnectionId::value).to_be_bytes();
    let orig_bytes = original_dcid.map_or(0u64, ConnectionId::value).to_be_bytes();
    hmac_sha256_with(
        provider,
        api_key,
        &[
            INITIAL_VERIFIER_LABEL,
            &[role_byte],
            &scid_bytes,
            &orig_bytes,
            public_key,
            random,
        ],
    )
}

/// Constant-time verification of a peer's 32-byte `Initial` verifier using `provider`.
#[inline(never)]
pub fn verify_initial_verifier_with(
    provider: &CryptoProvider,
    api_key: &[u8; 32],
    role: CryptoRole,
    scid: Option<ConnectionId>,
    original_dcid: Option<ConnectionId>,
    public_key: &[u8; PUBLIC_KEY_COMPRESSED_LEN],
    random: &[u8; ASSOCIATION_RANDOM_LEN],
    received_verifier: &[u8; INITIAL_VERIFIER_LEN],
) -> Result<bool, CryptoError> {
    let expected = compute_initial_verifier_with(
        provider,
        api_key,
        role,
        scid,
        original_dcid,
        public_key,
        random,
    )?;
    let mut diff = 0u8;
    for (&a, &b) in expected.iter().zip(received_verifier.iter()) {
        diff |= a ^ b;
    }
    Ok(diff == 0)
}

#[cfg(feature = "rust-crypto")]
mod host_crypto {
    use super::*;
    use aes_gcm::{Aes128Gcm, KeyInit as AeadKeyInit, Nonce, Tag, aead::AeadInPlace};
    use sha2::{Digest, Sha256};
    use zeroize::Zeroize;

    #[inline(never)]
    pub(crate) fn sha256_chunks(chunks: &[&[u8]]) -> [u8; 32] {
        let mut h = Sha256::new();
        for chunk in chunks {
            h.update(chunk);
        }
        h.finalize().into()
    }

    fn provider_sha256(_ctx: usize, chunks: &[&[u8]], out: &mut [u8; 32]) -> Result<(), CryptoError> {
        *out = sha256_chunks(chunks);
        Ok(())
    }

    fn provider_aead_seal(
        _ctx: usize,
        key: &[u8; TRAFFIC_KEY_LEN],
        nonce: &[u8; TRAFFIC_IV_LEN],
        aad: &[u8],
        body: &mut [u8],
    ) -> Result<[u8; AEAD_TAG_LEN], CryptoError> {
        let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::Invalid)?;
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, body)
            .map_err(|_| CryptoError::Invalid)?;
        let mut out = [0u8; AEAD_TAG_LEN];
        out.copy_from_slice(&tag);
        Ok(out)
    }

    fn provider_aead_open(
        _ctx: usize,
        key: &[u8; TRAFFIC_KEY_LEN],
        nonce: &[u8; TRAFFIC_IV_LEN],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8; AEAD_TAG_LEN],
    ) -> Result<(), CryptoError> {
        let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::Invalid)?;
        cipher
            .decrypt_in_place_detached(Nonce::from_slice(nonce), aad, body, Tag::from_slice(tag))
            .map_err(|_| CryptoError::AuthenticationFailed)
    }

    fn ccm_cbc_mac(
        aes: &aes_gcm::aes::Aes128,
        nonce: &[u8; TRAFFIC_IV_LEN],
        aad: &[u8],
        pt: &[u8],
    ) -> Result<[u8; 16], CryptoError> {
        use aes_gcm::aes::cipher::{BlockEncrypt, generic_array::GenericArray};

        if pt.len() > 0x00ff_ffff || aad.len() >= 0xff00 {
            return Err(CryptoError::Invalid);
        }
        let mut mac = [0u8; 16];
        mac[0] = (if aad.is_empty() { 0x00 } else { 0x40 }) | 0x38 | 0x02;
        mac[1..13].copy_from_slice(nonce);
        let len_u = pt.len() as u32;
        mac[13] = ((len_u >> 16) & 0xff) as u8;
        mac[14] = ((len_u >> 8) & 0xff) as u8;
        mac[15] = (len_u & 0xff) as u8;
        aes.encrypt_block(GenericArray::from_mut_slice(&mut mac));

        if !aad.is_empty() {
            let mut blk = [0u8; 16];
            let aad_len = aad.len() as u16;
            blk[0] = (aad_len >> 8) as u8;
            blk[1] = (aad_len & 0xff) as u8;
            let mut pos = 2usize;
            for &b in aad {
                blk[pos] = b;
                pos += 1;
                if pos == 16 {
                    for (m, &x) in mac.iter_mut().zip(blk.iter()) {
                        *m ^= x;
                    }
                    aes.encrypt_block(GenericArray::from_mut_slice(&mut mac));
                    blk = [0u8; 16];
                    pos = 0;
                }
            }
            if pos > 0 {
                for (m, &x) in mac.iter_mut().zip(blk.iter()) {
                    *m ^= x;
                }
                aes.encrypt_block(GenericArray::from_mut_slice(&mut mac));
            }
            blk.zeroize();
        }

        let mut chunks = pt.chunks_exact(16);
        for chunk in &mut chunks {
            for (m, &x) in mac.iter_mut().zip(chunk.iter()) {
                *m ^= x;
            }
            aes.encrypt_block(GenericArray::from_mut_slice(&mut mac));
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            for (m, &x) in mac.iter_mut().zip(rem.iter()) {
                *m ^= x;
            }
            aes.encrypt_block(GenericArray::from_mut_slice(&mut mac));
        }
        Ok(mac)
    }

    fn ccm_ctr_xor(aes: &aes_gcm::aes::Aes128, nonce: &[u8; TRAFFIC_IV_LEN], body: &mut [u8]) {
        use aes_gcm::aes::cipher::{BlockEncrypt, generic_array::GenericArray};

        let mut ctr = [0u8; 16];
        ctr[0] = 0x02;
        ctr[1..13].copy_from_slice(nonce);
        let mut block_idx = 1u32;
        for chunk in body.chunks_mut(16) {
            ctr[13] = ((block_idx >> 16) & 0xff) as u8;
            ctr[14] = ((block_idx >> 8) & 0xff) as u8;
            ctr[15] = (block_idx & 0xff) as u8;
            let mut ks = ctr;
            aes.encrypt_block(GenericArray::from_mut_slice(&mut ks));
            for (b, k) in chunk.iter_mut().zip(ks.iter()) {
                *b ^= *k;
            }
            ks.zeroize();
            block_idx = block_idx.wrapping_add(1);
        }
    }

    fn ccm_s0(aes: &aes_gcm::aes::Aes128, nonce: &[u8; TRAFFIC_IV_LEN]) -> [u8; 16] {
        use aes_gcm::aes::cipher::{BlockEncrypt, generic_array::GenericArray};

        let mut s0 = [0u8; 16];
        s0[0] = 0x02;
        s0[1..13].copy_from_slice(nonce);
        aes.encrypt_block(GenericArray::from_mut_slice(&mut s0));
        s0
    }

    fn provider_aead_seal_ccm(
        _ctx: usize,
        key: &[u8; TRAFFIC_KEY_LEN],
        nonce: &[u8; TRAFFIC_IV_LEN],
        aad: &[u8],
        body: &mut [u8],
    ) -> Result<[u8; AEAD_TAG_LEN], CryptoError> {
        let aes = aes_gcm::aes::Aes128::new_from_slice(key).map_err(|_| CryptoError::Invalid)?;
        let mut tag = ccm_cbc_mac(&aes, nonce, aad, body)?;
        ccm_ctr_xor(&aes, nonce, body);
        let mut s0 = ccm_s0(&aes, nonce);
        for (t, &s) in tag.iter_mut().zip(s0.iter()) {
            *t ^= s;
        }
        s0.zeroize();
        Ok(tag)
    }

    fn provider_aead_open_ccm(
        _ctx: usize,
        key: &[u8; TRAFFIC_KEY_LEN],
        nonce: &[u8; TRAFFIC_IV_LEN],
        aad: &[u8],
        body: &mut [u8],
        tag: &[u8; AEAD_TAG_LEN],
    ) -> Result<(), CryptoError> {
        let aes = aes_gcm::aes::Aes128::new_from_slice(key).map_err(|_| CryptoError::Invalid)?;
        ccm_ctr_xor(&aes, nonce, body);
        let mut mac = ccm_cbc_mac(&aes, nonce, aad, body)?;
        let mut s0 = ccm_s0(&aes, nonce);
        let mut diff = 0u8;
        for i in 0..AEAD_TAG_LEN {
            diff |= (mac[i] ^ s0[i]) ^ tag[i];
        }
        mac.zeroize();
        s0.zeroize();
        if diff == 0 {
            Ok(())
        } else {
            body.zeroize();
            Err(CryptoError::AuthenticationFailed)
        }
    }

    impl CryptoProvider {
        /// Pure-Rust SHA-256 + AES-128-GCM provider (`feature = "rust-crypto"`) for Linux/Android hosts.
        pub const fn rust_crypto() -> Self {
            Self {
                context: 0,
                sha256: provider_sha256,
                aead_seal: provider_aead_seal,
                aead_open: provider_aead_open,
                aead_packet: None,
            }
        }

        /// Pure-Rust SHA-256 + AES-128-CCM (RFC 3610, 12-byte nonce, 16-byte tag) provider (`feature = "rust-crypto"`).
        pub const fn rust_crypto_ccm() -> Self {
            Self {
                context: 0,
                sha256: provider_sha256,
                aead_seal: provider_aead_seal_ccm,
                aead_open: provider_aead_open_ccm,
                aead_packet: None,
            }
        }
    }

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
        #[inline(never)]
        fn seal_in_place(
            &self,
            packet_number: u32,
            associated_data: &[u8],
            body: &mut [u8],
        ) -> Result<[u8; AEAD_TAG_LEN], CryptoError> {
            let nonce = self.nonce(packet_number);
            provider_aead_seal(0, &self.key, &nonce, associated_data, body)
        }

        #[inline(never)]
        fn open_in_place(
            &self,
            packet_number: u32,
            associated_data: &[u8],
            body: &mut [u8],
            tag: &[u8; AEAD_TAG_LEN],
        ) -> Result<(), CryptoError> {
            let nonce = self.nonce(packet_number);
            provider_aead_open(0, &self.key, &nonce, associated_data, body, tag)
        }
    }

    /// Host AES-128-CCM (RFC 3610) directional packet cipher implementing [`PacketCrypto`].
    #[derive(Clone)]
    pub struct RustAes128Ccm {
        key: [u8; TRAFFIC_KEY_LEN],
        iv: [u8; TRAFFIC_IV_LEN],
    }

    impl RustAes128Ccm {
        /// Create a new [`RustAes128Ccm`] directional key from `key` and `iv`.
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

    impl Drop for RustAes128Ccm {
        fn drop(&mut self) {
            self.key.zeroize();
            self.iv.zeroize();
        }
    }

    impl PacketCrypto for RustAes128Ccm {
        #[inline(never)]
        fn seal_in_place(
            &self,
            packet_number: u32,
            associated_data: &[u8],
            body: &mut [u8],
        ) -> Result<[u8; AEAD_TAG_LEN], CryptoError> {
            let nonce = self.nonce(packet_number);
            provider_aead_seal_ccm(0, &self.key, &nonce, associated_data, body)
        }

        #[inline(never)]
        fn open_in_place(
            &self,
            packet_number: u32,
            associated_data: &[u8],
            body: &mut [u8],
            tag: &[u8; AEAD_TAG_LEN],
        ) -> Result<(), CryptoError> {
            let nonce = self.nonce(packet_number);
            provider_aead_open_ccm(0, &self.key, &nonce, associated_data, body, tag)
        }
    }

    /// Derive a 16-byte ULA `vip6` address (`fc00::/8` + first 8 bytes of `SHA-256(public_key)`).
    #[inline(never)]
    pub fn vip6_from_public_key(public_key: &[u8; PUBLIC_KEY_COMPRESSED_LEN]) -> [u8; 16] {
        vip6_from_public_key_with(&CryptoProvider::rust_crypto(), public_key)
            .expect("host sha256 never fails")
    }

    /// Derive a node's 32-byte `node_secret` from the control-plane root key and node `public_key`
    /// (`HKDF-SHA256(salt = "dmesh/control/v1", ikm = control_secret, info = "device-credential\0" || public_key)`).
    #[inline(never)]
    pub fn derive_device_secret(
        control_secret: &[u8],
        device_public_key: &[u8; PUBLIC_KEY_COMPRESSED_LEN],
    ) -> Result<[u8; 32], CryptoError> {
        derive_device_secret_with(&CryptoProvider::rust_crypto(), control_secret, device_public_key)
    }

    /// Derive a per-caller 32-byte receive/send `api_key` from `target_node_secret`.
    #[inline(never)]
    pub fn derive_peer_api_key(
        target_node_secret: &[u8; 32],
        caller_public_key: &[u8],
    ) -> Result<[u8; 32], CryptoError> {
        derive_peer_api_key_with(&CryptoProvider::rust_crypto(), target_node_secret, caller_public_key)
    }

    /// Derive initial directional traffic keys using HKDF-SHA256 (`dmesh/quic-lite/traffic/v1/`).
    pub fn derive_traffic_keys(
        psk: &[u8; 32],
        client_random: &[u8; ASSOCIATION_RANDOM_LEN],
        server_random: &[u8; ASSOCIATION_RANDOM_LEN],
        client_cid: ConnectionId,
        server_cid: ConnectionId,
    ) -> Result<TrafficKeys, CryptoError> {
        derive_traffic_keys_with(
            &CryptoProvider::rust_crypto(),
            psk,
            client_random,
            server_random,
            client_cid,
            server_cid,
        )
    }

    /// Derive static directional traffic keys directly from a pre-shared `api_key` without an
    /// `Initial` random exchange (used for single-association `ShortHeader`-only links).
    pub fn derive_static_traffic_keys(
        api_key: &[u8; 32],
        client_cid: ConnectionId,
        server_cid: ConnectionId,
    ) -> Result<TrafficKeys, CryptoError> {
        derive_static_traffic_keys_with(
            &CryptoProvider::rust_crypto(),
            api_key,
            client_cid,
            server_cid,
        )
    }

    /// Compute the 32-byte `HMAC-SHA256` `Initial` verifier over role, CIDs, `public_key`, and `random`.
    #[inline(never)]
    pub fn compute_initial_verifier(
        api_key: &[u8; 32],
        role: CryptoRole,
        scid: Option<ConnectionId>,
        original_dcid: Option<ConnectionId>,
        public_key: &[u8; PUBLIC_KEY_COMPRESSED_LEN],
        random: &[u8; ASSOCIATION_RANDOM_LEN],
    ) -> [u8; INITIAL_VERIFIER_LEN] {
        compute_initial_verifier_with(
            &CryptoProvider::rust_crypto(),
            api_key,
            role,
            scid,
            original_dcid,
            public_key,
            random,
        )
        .expect("host sha256 never fails")
    }

    /// Constant-time verification of a peer's 32-byte `Initial` verifier.
    #[inline(never)]
    pub fn verify_initial_verifier(
        api_key: &[u8; 32],
        role: CryptoRole,
        scid: Option<ConnectionId>,
        original_dcid: Option<ConnectionId>,
        public_key: &[u8; PUBLIC_KEY_COMPRESSED_LEN],
        random: &[u8; ASSOCIATION_RANDOM_LEN],
        received_verifier: &[u8; INITIAL_VERIFIER_LEN],
    ) -> bool {
        verify_initial_verifier_with(
            &CryptoProvider::rust_crypto(),
            api_key,
            role,
            scid,
            original_dcid,
            public_key,
            random,
            received_verifier,
        )
        .unwrap_or(false)
    }
}

#[cfg(feature = "rust-crypto")]
pub use host_crypto::{
    RustAes128Ccm, RustAes128Gcm, compute_initial_verifier, derive_device_secret,
    derive_peer_api_key, derive_static_traffic_keys, derive_traffic_keys,
    verify_initial_verifier, vip6_from_public_key,
};

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

    #[test]
    fn single_secret_api_key_verifier_and_static_short_packet_encryption() {
        let server_pub = [0x02u8; PUBLIC_KEY_COMPRESSED_LEN];
        let client_pub = [0x03u8; PUBLIC_KEY_COMPRESSED_LEN];
        let node_secret = derive_device_secret(b"control-root-secret-0123456789", &server_pub).unwrap();
        let api_key = derive_peer_api_key(&node_secret, &client_pub).unwrap();
        let owner_key = derive_peer_api_key(&node_secret, &[]).unwrap();
        assert_ne!(api_key, owner_key);

        let vip6 = vip6_from_public_key(&client_pub);
        assert_eq!(vip6[0], 0xfc);
        assert_ne!(&vip6[8..], &[0u8; 8]);

        let c_scid = ConnectionId::new(7).unwrap();
        let odcid = ConnectionId::new(0x2000_0042).unwrap();
        let verifier = compute_initial_verifier(
            &api_key,
            CryptoRole::Client,
            Some(c_scid),
            Some(odcid),
            &client_pub,
            &[0x11; 32],
        );
        assert!(verify_initial_verifier(
            &api_key,
            CryptoRole::Client,
            Some(c_scid),
            Some(odcid),
            &client_pub,
            &[0x11; 32],
            &verifier,
        ));
        assert!(!verify_initial_verifier(
            &owner_key,
            CryptoRole::Client,
            Some(c_scid),
            Some(odcid),
            &client_pub,
            &[0x11; 32],
            &verifier,
        ));

        // Static ESP32-style single-assoc encryption with shared legacy CID `1`.
        let cid1 = ConnectionId::new(1).unwrap();
        let client_keys = derive_static_traffic_keys(&owner_key, cid1, cid1)
            .unwrap()
            .for_role(CryptoRole::Client);
        let server_keys = derive_static_traffic_keys(&owner_key, cid1, cid1)
            .unwrap()
            .for_role(CryptoRole::Server);

        let pool = StaticPacketPool::<4, 512>::new();
        let mut pkt = (&pool).alloc().unwrap();
        pkt.append(b"esp32 single-assoc payload").unwrap();
        let hdr = ShortHeader {
            flags: 0x40,
            dcid: cid1,
            packet_number: 1,
            packet_number_len: 1,
        };
        let mut hdr_bytes = [0u8; 16];
        let hdr_len = hdr.encode(&mut hdr_bytes).unwrap();
        pkt.prepend(&hdr_bytes[..hdr_len]).unwrap();
        seal_short_packet_in_place(&mut pkt, &client_keys.send, cid1).unwrap();
        assert_eq!(pkt.bytes()[0] & FLAG_PROTECTED, FLAG_PROTECTED);

        let prefix = ShortHeader::decode_prefix(pkt.bytes()).unwrap();
        open_short_packet_in_place(
            &mut pkt,
            &server_keys.receive,
            prefix.flags,
            prefix.header_len,
            1,
            prefix.packet_number_len,
            cid1,
        )
        .unwrap();
        assert_eq!(&pkt.bytes()[prefix.header_len..], b"esp32 single-assoc payload");

        // Verify truncated 1-byte wire PN (256 -> wire 0x00) uses full PN=256 for nonce without
        // colliding with PN=0.
        let mut p0 = (&pool).alloc().unwrap();
        let mut p256 = (&pool).alloc().unwrap();
        p0.append(b"same-plaintext-payload").unwrap();
        p256.append(b"same-plaintext-payload").unwrap();
        for (pkt, pn) in [(&mut p0, 0u32), (&mut p256, 256u32)] {
            let hdr = ShortHeader {
                flags: 0x40,
                dcid: cid1,
                packet_number: pn,
                packet_number_len: 1,
            };
            let hl = hdr.encode(&mut hdr_bytes).unwrap();
            pkt.prepend(&hdr_bytes[..hl]).unwrap();
            seal_short_packet_in_place_with_pn(pkt, &client_keys.send, pn, cid1).unwrap();
        }
        assert_ne!(p0.bytes(), p256.bytes(), "pn=0 and pn=256 must not reuse nonce");
        let pref256 = ShortHeader::decode_prefix(p256.bytes()).unwrap();
        open_short_packet_in_place(
            &mut p256,
            &server_keys.receive,
            pref256.flags,
            pref256.header_len,
            256,
            pref256.packet_number_len,
            cid1,
        )
        .unwrap();
        assert_eq!(&p256.bytes()[pref256.header_len..], b"same-plaintext-payload");
    }

    #[test]
    fn compact_sha256_hmac_hkdf_match_rfc_vectors() {
        let p = CryptoProvider::rust_crypto();
        // FIPS 180-4 / RFC 6234 SHA-256("abc")
        assert_eq!(
            host_crypto::sha256_chunks(&[b"abc"]),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        // RFC 4231 Case 1 HMAC-SHA256(key = [0x0b; 20], data = b"Hi There")
        assert_eq!(
            hmac_sha256_with(&p, &[0x0b; 20], &[b"Hi There"]).unwrap(),
            [
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7,
            ]
        );
        // RFC 5869 Case 1 HKDF-SHA256 OKM (first 42 bytes)
        let ikm = [0x0bu8; 22];
        let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let mut okm = [0u8; 42];
        hkdf_sha256_with(&p, &salt, &ikm, &info, &mut okm).unwrap();
        assert_eq!(
            okm,
            [
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
            ]
        );
    }

    #[test]
    fn aes_128_ccm_matches_openssl_and_roundtrips_short_packets() {
        let p = CryptoProvider::rust_crypto_ccm();
        let key: [u8; 16] = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
            0x4e, 0x4f,
        ];
        let nonce: [u8; 12] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        ];
        let aad = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let pt: [u8; 24] = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        ];
        let mut buf = pt;
        let tag = (p.aead_seal)(0, &key, &nonce, &aad, &mut buf).unwrap();
        assert_eq!(
            buf,
            [
                0xe3, 0xb2, 0x01, 0xa9, 0xf5, 0xb7, 0x1a, 0x7a, 0x9b, 0x1c, 0xea, 0xec, 0xcd, 0x97,
                0xe7, 0x0b, 0x61, 0x76, 0xaa, 0xd9, 0xa4, 0x42, 0x8a, 0xa5,
            ]
        );
        assert_eq!(
            tag,
            [
                0x4e, 0xb7, 0x27, 0xd6, 0x3f, 0x92, 0xca, 0x99, 0xa3, 0xea, 0xb9, 0xa6, 0x43, 0x27,
                0x19, 0x33,
            ]
        );
        (p.aead_open)(0, &key, &nonce, &aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, pt);

        // Tamper tag -> AuthenticationFailed
        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        assert_eq!(
            (p.aead_open)(0, &key, &nonce, &aad, &mut buf, &bad_tag),
            Err(CryptoError::AuthenticationFailed)
        );

        // Short packet roundtrip over CryptoProvider::rust_crypto_ccm
        let cid = ConnectionId::new(1).unwrap();
        let keys = derive_static_traffic_keys_with(&p, &[0x9au8; 32], cid, cid)
            .unwrap()
            .for_role(CryptoRole::Client);
        let peer = derive_static_traffic_keys_with(&p, &[0x9au8; 32], cid, cid)
            .unwrap()
            .for_role(CryptoRole::Server);
        let pool = StaticPacketPool::<4, 2048>::new();
        for payload_len in [1usize, 15, 16, 31, 64, 1400] {
            let mut pkt = (&pool).alloc().unwrap();
            let mut body = alloc::vec![0u8; payload_len];
            for (i, b) in body.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(17);
            }
            pkt.append(&body).unwrap();
            let hdr = ShortHeader {
                flags: 0x40,
                dcid: cid,
                packet_number: 77 + payload_len as u32,
                packet_number_len: 2,
            };
            let mut hb = [0u8; 16];
            let hl = hdr.encode(&mut hb).unwrap();
            pkt.prepend(&hb[..hl]).unwrap();
            seal_short_packet_in_place(&mut pkt, &keys.send, cid).unwrap();
            let pref = ShortHeader::decode_prefix(pkt.bytes()).unwrap();
            open_short_packet_in_place(
                &mut pkt,
                &peer.receive,
                pref.flags,
                pref.header_len,
                77 + payload_len as u32,
                pref.packet_number_len,
                cid,
            )
            .unwrap();
            assert_eq!(&pkt.bytes()[pref.header_len..], &body[..]);
        }
    }
}
