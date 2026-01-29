// SSH authentication - public key and certificate validation

use super::keys::AUTHORIZED_KEYS_PATH;
use super::SshAuthResult;
use anyhow::Result;
use log::warn;
use russh::{server, MethodKind};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info};

/// Entry from authorized_keys file
#[derive(Debug, Clone)]
pub struct AuthorizedKeyEntry {
    pub key: Option<ssh_key::PublicKey>,
    pub fingerprint: Option<String>,
    pub options: Option<String>,
    pub comment: Option<String>,
}

/// Validate a regular public key against authorized_keys
pub async fn validate_public_key(
    user: &str,
    key_openssh: &str,
    authorized_keys: &[AuthorizedKeyEntry],
) -> Result<SshAuthResult> {
    info!("Validating public key for user {}: {}", user, key_openssh);

    let incoming_key = ssh_key::PublicKey::from_openssh(key_openssh)
        .map_err(|e| anyhow::anyhow!("Failed to parse incoming public key: {}", e))?;
    let incoming_fp = incoming_key
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();

    for (i, entry) in authorized_keys.iter().enumerate() {
        let mut matched = false;

        if let Some(auth_key) = &entry.key {
            if auth_key.key_data() == incoming_key.key_data() {
                matched = true;
            }
        } else if let Some(auth_fp) = &entry.fingerprint {
            if auth_fp == &incoming_fp
                || (auth_fp.starts_with("SHA256:") && auth_fp == &incoming_fp)
            {
                matched = true;
            }
        }

        if matched {
            let comment = entry.comment.as_deref().unwrap_or("");
            let comment_matches = if comment.is_empty() {
                true
            } else {
                comment == user || comment.starts_with(&format!("{}@", user))
            };

            if !comment_matches {
                warn!(
                    "Key matched but comment '{}' does not match user '{}'",
                    comment, user
                );
            }
            info!(
                "Public key authentication successful for user {} (match at index {})",
                user, i
            );
            return Ok(SshAuthResult {
                status: server::Auth::Accept,
                comment: comment.to_string(),
                options: entry.options.clone(),
            });
        }
    }

    warn!(
        "No matching public key found in authorized_keys for user {}",
        user
    );
    Ok(SshAuthResult {
        status: server::Auth::Reject {
            proceed_with_methods: Some((&[MethodKind::PublicKey][..]).into()),
            partial_success: false,
        },
        comment: String::new(),
        options: None,
    })
}

/// Validate a CA-signed certificate
pub async fn validate_certificate(
    cert_data: &str,
    user: &str,
    ca_keys: &Arc<Vec<ssh_key::PublicKey>>,
) -> Result<SshAuthResult> {
    debug!("Validating certificate for user: {}", user);

    let cert = match ssh_key::Certificate::from_openssh(cert_data) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to parse certificate: {}", e);
            return Ok(SshAuthResult {
                status: server::Auth::Reject {
                    proceed_with_methods: Some((&[MethodKind::PublicKey][..]).into()),
                    partial_success: false,
                },
                comment: String::new(),
                options: None,
            });
        }
    };

    if !cert.valid_principals().contains(&user.to_string()) && !cert.valid_principals().is_empty() {
        warn!("Certificate not valid for user: {}", user);
        return Ok(SshAuthResult {
            status: server::Auth::Reject {
                proceed_with_methods: Some((&[MethodKind::PublicKey][..]).into()),
                partial_success: false,
            },
            comment: cert.key_id().to_string(),
            options: None,
        });
    }

    let fingerprints: Vec<_> = ca_keys
        .iter()
        .map(|k| k.fingerprint(ssh_key::HashAlg::Sha256))
        .collect();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if cert.validate_at(now, fingerprints.iter()).is_ok() {
        info!("Certificate validated successfully");
        let mut opts = Vec::new();
        for (k, v) in cert.critical_options().iter() {
            if v.is_empty() {
                opts.push(k.clone());
            } else {
                opts.push(format!("{}={}", k, v));
            }
        }
        for (k, v) in cert.extensions().iter() {
            if v.is_empty() {
                opts.push(k.clone());
            } else {
                opts.push(format!("{}={}", k, v));
            }
        }
        let options = if opts.is_empty() {
            None
        } else {
            Some(opts.join(","))
        };

        return Ok(SshAuthResult {
            status: server::Auth::Accept,
            comment: cert.key_id().to_string(),
            options,
        });
    }

    warn!("Certificate validation failed");
    Ok(SshAuthResult {
        status: server::Auth::Reject {
            proceed_with_methods: Some((&[MethodKind::PublicKey][..]).into()),
            partial_success: false,
        },
        comment: cert.key_id().to_string(),
        options: None,
    })
}

/// Load authorized public keys
pub fn load_authorized_keys(base_dir: &Path) -> Result<Vec<AuthorizedKeyEntry>> {
    let path = base_dir.join(AUTHORIZED_KEYS_PATH);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path)?;
    parse_authorized_keys_content(&content)
}

pub fn parse_authorized_keys_content(content: &str) -> Result<Vec<AuthorizedKeyEntry>> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        if is_known_key_type(parts[0]) {
            if let Ok(key) = ssh_key::PublicKey::from_openssh(line) {
                entries.push(AuthorizedKeyEntry {
                    comment: Some(key.comment().to_string()),
                    key: Some(key),
                    fingerprint: None,
                    options: None,
                });
            }
        } else if parts.len() >= 2 && is_known_key_type(parts[1]) {
            let options = parts[0].to_string();
            let rest = parts[1..].join(" ");
            if let Ok(key) = ssh_key::PublicKey::from_openssh(&rest) {
                entries.push(AuthorizedKeyEntry {
                    comment: Some(key.comment().to_string()),
                    key: Some(key),
                    fingerprint: None,
                    options: Some(options),
                });
            }
        } else if parts[0].starts_with("SHA256:") || parts[0].starts_with("MD5:") {
            let fingerprint = parts[0].to_string();
            let comment = if parts.len() >= 2 {
                Some(parts[1..].join(" "))
            } else {
                None
            };
            entries.push(AuthorizedKeyEntry {
                key: None,
                fingerprint: Some(fingerprint),
                options: None,
                comment,
            });
        }
    }
    Ok(entries)
}

fn is_known_key_type(s: &str) -> bool {
    s.starts_with("ssh-")
        || s.starts_with("ecdsa-")
        || s.starts_with("sk-ssh-")
        || s.starts_with("sk-ecdsa-")
}

pub fn load_authorized_cas(base_dir: &Path) -> Result<Vec<ssh_key::PublicKey>> {
    use super::keys::AUTHORIZED_CAS_PATH;
    let path = base_dir.join(AUTHORIZED_CAS_PATH);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path)?;
    parse_authorized_cas_content(&content)
}

pub fn parse_authorized_cas_content(content: &str) -> Result<Vec<ssh_key::PublicKey>> {
    let mut keys = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if !line.is_empty() && !line.starts_with('#') {
            let key_str = if line.starts_with("@cert-authority") {
                line["@cert-authority".len()..].trim()
            } else {
                line
            };
            if let Ok(key) = ssh_key::PublicKey::from_openssh(key_str) {
                keys.push(key);
            }
        }
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::rand_core::OsRng;

    #[test]
    fn test_parse_authorized_keys() {
        let key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBICtPKa3mXZss+k6LqtiNOQ3TbJFqLvjsvZGubtILlkV2Kz3HjO9+fghwCT/bb1R2SrvqHWWEj+QH6G4+ogPns=";
        let content = format!(
            "{}\nopt1,opt2 {}\nSHA256:uwB0YV5mNjM1M1M1M1M1M1M1M1M1M1M1M1M1M1M1M1M comment3",
            key, key
        );
        let entries = parse_authorized_keys_content(&content).unwrap();
        assert_eq!(entries.len(), 3);
        assert!(entries[0].key.is_some());
        assert!(entries[1].key.is_some());
        assert_eq!(entries[1].options, Some("opt1,opt2".to_string()));
        assert!(entries[2].key.is_none());
    }

    #[tokio::test]
    async fn test_validate_public_key() {
        let key_str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBICtPKa3mXZss+k6LqtiNOQ3TbJFqLvjsvZGubtILlkV2Kz3HjO9+fghwCT/bb1R2SrvqHWWEj+QH6G4+ogPns= user@host";
        let incoming_key = ssh_key::PublicKey::from_openssh(key_str).unwrap();
        let fp = incoming_key
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();

        let entries = vec![AuthorizedKeyEntry {
            key: None,
            fingerprint: Some(fp),
            options: Some("restrict".to_string()),
            comment: Some("user".to_string()),
        }];

        let res = validate_public_key("user", key_str, &entries)
            .await
            .unwrap();
        assert!(matches!(res.status, server::Auth::Accept));
        assert_eq!(res.options, Some("restrict".to_string()));
    }

    #[tokio::test]
    async fn test_validate_certificate() {
        let ca_key = ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap();
        let user_key =
            ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap();

        let mut builder = ssh_key::certificate::Builder::new_with_random_nonce(
            &mut OsRng,
            user_key.public_key().key_data().clone(),
            0,
            2000000000 + 100000,
        )
        .unwrap();

        builder
            .cert_type(ssh_key::certificate::CertType::User)
            .unwrap();
        builder.valid_principal("user").unwrap();
        builder.key_id("test-cert").unwrap();
        builder.critical_option("force-command", "ls").unwrap();

        let cert = builder.sign(&ca_key).unwrap();
        let cert_openssh = cert.to_openssh().unwrap();
        let ca_keys = Arc::new(vec![ca_key.public_key().clone()]);

        let res = validate_certificate(&cert_openssh, "user", &ca_keys)
            .await
            .unwrap();
        assert!(matches!(res.status, server::Auth::Accept));
        assert_eq!(res.comment, "test-cert");
        assert!(res.options.as_ref().unwrap().contains("force-command=ls"));
    }
}
