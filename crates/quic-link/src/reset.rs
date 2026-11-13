//! Stateless reset token derivation, formatting, and constant-time matching for datagram links
//! (UDP, ESP-NOW, NAN, LoRa). Dedicated connection-oriented stream links (TCP, PPP) do not need
//! stateless resets because connection teardown is signaled by the underlying transport.

#[cfg(all(feature = "std", feature = "stateless-reset"))]
use quic_base::{ConnectionId, ShortHeader, WireError};

/// Length of a QUIC stateless-reset token in bytes (`16`).
pub const STATELESS_RESET_TOKEN_LEN: usize = 16;

/// Minimum wire length of a stateless-reset packet in bytes (`21`).
pub const STATELESS_RESET_MIN_PACKET_LEN: usize = 21;

/// Opaque 16-byte stateless-reset token retained by an association for its peer's CID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatelessResetToken([u8; STATELESS_RESET_TOKEN_LEN]);

impl StatelessResetToken {
    /// Construct a [`StatelessResetToken`] from raw 16-byte token material.
    pub const fn new(bytes: [u8; STATELESS_RESET_TOKEN_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the 16-byte token slice.
    pub const fn as_bytes(&self) -> &[u8; STATELESS_RESET_TOKEN_LEN] {
        &self.0
    }

    /// Constant-time check whether `input` (of length `>= 21`) ends with this stateless-reset token.
    ///
    /// Callers must check this only after normal packet authentication/parsing has failed.
    pub fn matches_packet(self, input: &[u8]) -> bool {
        if input.len() < STATELESS_RESET_MIN_PACKET_LEN {
            return false;
        }
        let suffix = &input[input.len() - STATELESS_RESET_TOKEN_LEN..];
        let mut diff = 0u8;
        for (&received, &expected) in suffix.iter().zip(self.0.iter()) {
            diff |= received ^ expected;
        }
        diff == 0
    }
}

#[cfg(all(feature = "std", feature = "stateless-reset"))]
mod key {
    use super::*;
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    const DEVICE_SECRET_RESET_KEY_LABEL: &[u8] = b"dmesh/quic-lite/reset-key/v1";
    const STATELESS_RESET_TOKEN_LABEL: &[u8] = b"dmesh/quic-lite/stateless-reset/v1";
    const STATELESS_RESET_PREFIX_LABEL: &[u8] = b"dmesh/quic-lite/stateless-reset/prefix/v1";

    /// Device-derived HMAC-SHA256 key used to issue and format stateless resets for unknown short-header CIDs.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct StatelessResetKey([u8; 32]);

    impl StatelessResetKey {
        /// Derive the reset-key branch from a provisioned device secret (`>= 16` bytes).
        pub fn from_device_secret(secret: &[u8]) -> Result<Self, WireError> {
            if secret.len() < 16 {
                return Err(WireError::InvalidFrame);
            }
            let mut mac =
                Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts secret bytes");
            mac.update(DEVICE_SECRET_RESET_KEY_LABEL);
            let digest = mac.finalize().into_bytes();
            let mut key = [0u8; 32];
            key.copy_from_slice(&digest);
            Ok(Self(key))
        }

        /// Derive the 16-byte [`StatelessResetToken`] for a locally-issued receive `cid`.
        pub fn token_for(self, cid: ConnectionId) -> StatelessResetToken {
            let mut cid_bytes = [0u8; 8];
            let cid_len = cid
                .encode(&mut cid_bytes)
                .expect("CID buffer is fixed-size");
            let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC accepts 32-byte key");
            mac.update(STATELESS_RESET_TOKEN_LABEL);
            mac.update(&cid_bytes[..cid_len]);
            let digest = mac.finalize().into_bytes();
            let mut token = [0u8; STATELESS_RESET_TOKEN_LEN];
            token.copy_from_slice(&digest[..STATELESS_RESET_TOKEN_LEN]);
            StatelessResetToken(token)
        }

        /// Format an RFC 9000-style opaque stateless reset packet for an unknown short-header packet.
        pub fn encode_for_unknown_packet(
            self,
            triggering_packet: &[u8],
            out: &mut [u8],
        ) -> Result<Option<usize>, WireError> {
            let (header, _) = ShortHeader::decode(triggering_packet)?;
            self.encode_for_unknown_cid(triggering_packet, header.dcid, out)
        }

        /// Format a stateless reset for a known decoded `unknown_dcid`.
        pub fn encode_for_unknown_cid(
            self,
            triggering_packet: &[u8],
            unknown_dcid: ConnectionId,
            out: &mut [u8],
        ) -> Result<Option<usize>, WireError> {
            if triggering_packet.len() < STATELESS_RESET_MIN_PACKET_LEN
                || triggering_packet
                    .first()
                    .is_none_or(|first| first & 0x80 != 0)
            {
                return Ok(None);
            }
            let used = triggering_packet.len().min(out.len());
            if used < STATELESS_RESET_MIN_PACKET_LEN {
                return Err(WireError::BufferTooSmall);
            }
            let token = self.token_for(unknown_dcid);
            let mut cid_bytes = [0u8; 8];
            let cid_len = unknown_dcid.encode(&mut cid_bytes)?;
            let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC accepts 32-byte key");
            mac.update(STATELESS_RESET_PREFIX_LABEL);
            mac.update(&cid_bytes[..cid_len]);
            mac.update(&(used as u64).to_be_bytes());
            let digest = mac.finalize().into_bytes();
            for (index, byte) in out[..used - STATELESS_RESET_TOKEN_LEN]
                .iter_mut()
                .enumerate()
            {
                *byte = digest[index % digest.len()] ^ (index as u8).wrapping_mul(0x9d);
            }
            out[0] &= 0x3f;
            out[used - STATELESS_RESET_TOKEN_LEN..used].copy_from_slice(&token.0);
            Ok(Some(used))
        }
    }

    /// Load the provisioned device/control-plane root from private platform
    /// storage and derive only its stateless-reset branch. The raw root is never
    /// returned to callers.
    #[cfg(feature = "std")]
    pub fn stateless_reset_key_from_private_file(
        path: impl AsRef<std::path::Path>,
    ) -> Result<Option<StatelessResetKey>, alloc::string::String> {
        let path = path.as_ref();
        let secret = match std::fs::read(path) {
            Ok(secret) => secret,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(alloc::format!("read device secret: {error}")),
        };
        StatelessResetKey::from_device_secret(&secret)
            .map(Some)
            .map_err(|_| alloc::string::String::from("invalid device secret: expected at least 16 private bytes"))
    }

    /// Resolve the shared host convention (`DMESH_DEVICE_SECRET_FILE` or sibling
    /// `device-secret.bin` next to `DMESH_SETTINGS_FILE`) and derive the stateless-reset key.
    #[cfg(feature = "std")]
    pub fn stateless_reset_key_from_environment() -> Result<Option<StatelessResetKey>, alloc::string::String> {
        let path = if let Some(path) = std::env::var_os("DMESH_DEVICE_SECRET_FILE") {
            std::path::PathBuf::from(path)
        } else if let Some(settings) = std::env::var_os("DMESH_SETTINGS_FILE") {
            std::path::PathBuf::from(settings)
                .parent()
                .map(|parent| parent.join("device-secret.bin"))
                .ok_or_else(|| alloc::string::String::from("settings path has no parent directory"))?
        } else {
            return Ok(None);
        };
        stateless_reset_key_from_private_file(path)
    }
}

#[cfg(all(feature = "std", feature = "stateless-reset"))]
pub use key::{
    StatelessResetKey, stateless_reset_key_from_environment, stateless_reset_key_from_private_file,
};
