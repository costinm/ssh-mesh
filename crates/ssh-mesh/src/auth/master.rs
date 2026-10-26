//! The master secret: the one secret every derived key comes from.
//!
//! It is 32 random bytes in `<SSH_BASEDIR>/mesh_secret` (hex, mode 0600),
//! generated on first start like the SSH host key. Everything else is derived
//! from it by [`MasterSecret::prf`]: HTTP API keys and session tokens today,
//! more later. No derived key is stored, so there is no key store to protect or
//! to lose. Something like a user store may exist later, but it holds public
//! keys (TOFU, WebAuthn), never secrets.
//!
//! The only operation is `prf(label, input)`, so the secret can move into a TPM
//! as a keyed-hash object: `prf` becomes a TPM HMAC call and the bytes never
//! reach this process.
//!
//! The derivation is a compatibility promise. Changing a label, or how a
//! derived key is computed, silently invalidates every key already issued;
//! the known-answer test at the bottom of this file exists to catch that.

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ring::hmac;

/// File name, in the same directory as the SSH host key.
pub const MASTER_SECRET_FILE: &str = "mesh_secret";

/// 32 secret bytes.
#[derive(Clone)]
pub struct MasterSecret([u8; 32]);

// Never print the bytes.
impl fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterSecret(..)")
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

impl MasterSecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// `HMAC-SHA256(secret, label || 0x00 || input)`.
    ///
    /// `label` names the purpose (`"ssh-mesh/http/apikey"`) so two purposes
    /// never share an output; it must not contain a NUL byte.
    pub fn prf(&self, label: &str, input: &[u8]) -> [u8; 32] {
        debug_assert!(!label.contains('\0'));
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.0);
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(label.as_bytes());
        ctx.update(&[0]);
        ctx.update(input);
        let mut out = [0u8; 32];
        out.copy_from_slice(ctx.sign().as_ref());
        out
    }

    pub fn path(dir: &Path) -> PathBuf {
        dir.join(MASTER_SECRET_FILE)
    }

    /// Read the secret from `dir`, or generate and save it if there is none.
    ///
    /// A file that exists but is not 64 hex characters is an error. It is never
    /// replaced: a new secret would silently invalidate every issued key.
    pub fn load_or_generate(dir: &Path) -> Result<Self> {
        let path = Self::path(dir);
        match std::fs::read_to_string(&path) {
            Ok(text) => return Self::parse(&text, &path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        }

        let mut bytes = [0u8; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes)
            .map_err(|_| anyhow::anyhow!("no random bytes available"))?;
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        match options.open(&path) {
            Ok(mut file) => {
                writeln!(file, "{}", hex_encode(&bytes))
                    .and_then(|()| file.sync_all())
                    .with_context(|| format!("writing {}", path.display()))?;
                log::info!("generated the master secret {}", path.display());
                Ok(Self(bytes))
            }
            // Another process created it first: use theirs.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Self::parse(&std::fs::read_to_string(&path)?, &path)
            }
            Err(e) => Err(e).with_context(|| format!("creating {}", path.display())),
        }
    }

    /// Read an existing secret; never creates one.
    pub fn load(dir: &Path) -> Result<Self> {
        let path = Self::path(dir);
        let text = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "no master secret at {}; start ssh-mesh once, or pass --keydir",
                path.display()
            )
        })?;
        Self::parse(&text, &path)
    }

    fn parse(text: &str, path: &Path) -> Result<Self> {
        let Some(bytes) = hex_decode(text.trim()).filter(|b| b.len() == 32) else {
            bail!(
                "{} must hold 64 hex characters (32 bytes); it is not replaced automatically",
                path.display()
            );
        };
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes);
        Ok(Self(secret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sequence() -> MasterSecret {
        MasterSecret::from_bytes(std::array::from_fn(|i| i as u8))
    }

    /// Reference values computed with Python's `hmac`. If this fails, derived
    /// keys have changed and every issued API key and session is invalid.
    #[test]
    fn derivation_is_frozen() {
        let m = sequence();
        assert_eq!(
            hex_encode(&m.prf("ssh-mesh/http/apikey", b"")),
            "7701dd2f925eb694917a91b8fabf98c690d1e0a5f922d46ccdc57865952042c6"
        );
        assert_eq!(
            hex_encode(&m.prf("ssh-mesh/http/session", b"")),
            "18e973ef3e05cad977a499bb0b05bf3c8ebb1aa07057e340d10adbe32417de06"
        );
    }

    #[test]
    fn labels_and_inputs_separate_outputs() {
        let m = sequence();
        let base = m.prf("a", b"x");
        assert_ne!(base, m.prf("b", b"x"));
        assert_ne!(base, m.prf("a", b"y"));
        // The NUL separator keeps ("a", "bx") and ("ab", "x") apart.
        assert_ne!(m.prf("a", b"bx"), m.prf("ab", b"x"));
        assert_ne!(base, MasterSecret::from_bytes([9; 32]).prf("a", b"x"));
        assert_eq!(format!("{:?}", m), "MasterSecret(..)");
    }

    #[test]
    fn generated_once_then_reloaded_with_private_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("ssh");
        let first = MasterSecret::load_or_generate(&sub).unwrap();
        let second = MasterSecret::load_or_generate(&sub).unwrap();
        assert_eq!(first.prf("x", b""), second.prf("x", b""));
        assert_eq!(
            MasterSecret::load(&sub).unwrap().prf("x", b""),
            first.prf("x", b"")
        );
        let text = std::fs::read_to_string(MasterSecret::path(&sub)).unwrap();
        assert_eq!(text.trim().len(), 64);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(MasterSecret::path(&sub))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Two fresh directories give different secrets.
        let other = MasterSecret::load_or_generate(&dir.path().join("other")).unwrap();
        assert_ne!(first.prf("x", b""), other.prf("x", b""));
    }

    #[test]
    fn a_bad_file_is_an_error_and_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = MasterSecret::path(dir.path());
        for bad in [
            "",
            "zz",
            "00",
            &"0".repeat(63),
            &"0".repeat(66),
            &"g".repeat(64),
        ] {
            std::fs::write(&path, bad).unwrap();
            assert!(
                MasterSecret::load_or_generate(dir.path()).is_err(),
                "{bad:?}"
            );
            assert!(MasterSecret::load(dir.path()).is_err(), "{bad:?}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), bad, "not replaced");
        }
        // `load` never creates one.
        let empty = tempfile::tempdir().unwrap();
        let err = MasterSecret::load(empty.path()).unwrap_err().to_string();
        assert!(err.contains("no master secret"), "{err}");
        assert!(!MasterSecret::path(empty.path()).exists());
        // Surrounding whitespace is fine.
        std::fs::write(&path, format!("  {}\n\n", "ab".repeat(32))).unwrap();
        assert!(MasterSecret::load(dir.path()).is_ok());
    }
}
