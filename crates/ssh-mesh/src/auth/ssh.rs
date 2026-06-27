// SSH authentication - public key and certificate validation

use super::SshAuthResult;
use super::keys::AUTHORIZED_KEYS_PATH;
use anyhow::Result;
use log::info;
use log::warn;
use rcgen::{CertificateParams, DistinguishedName, IsCa, KeyPair, SanType};
use russh::{MethodKind, server};
use ssh_key::certificate::{Builder, CertType};

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::keys::{set_permissions, ssh_key_from_pkcs8_pem, ssh_to_pkcs8_pem};

/// Entry from authorized_keys file
#[derive(Debug, Clone)]
pub struct AuthorizedKeyEntry {
    pub key: Option<ssh_key::PublicKey>,
    pub fingerprint: Option<String>,
    pub options: Option<String>,
    pub comment: Option<String>,
}

/// Validate a regular public key against authorized_keys.
///
/// Node-level authorized keys are administrative keys and may authenticate as
/// any SSH username. Per-user keys are loaded from the ssh-mesh config tree and
/// only authenticate that user.
pub async fn validate_public_key(
    user: &str,
    key_openssh: &str,
    authorized_keys: &[AuthorizedKeyEntry],
) -> Result<SshAuthResult> {
    let incoming_key = ssh_key::PublicKey::from_openssh(key_openssh)
        .map_err(|e| anyhow::anyhow!("Failed to parse incoming public key: {}", e))?;

    let incoming_fp = incoming_key
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();

    // TODO: use a hash map keyed by incoming_fp.
    for entry in authorized_keys.iter() {
        let mut matched = false;

        if let Some(auth_key) = &entry.key {
            if auth_key.key_data() == incoming_key.key_data() {
                matched = true;
            }
        } else if let Some(auth_fp) = &entry.fingerprint
            && auth_fp == &incoming_fp
        {
            matched = true;
        }

        if matched {
            let comment = entry.comment.as_deref().unwrap_or("");
            return Ok(SshAuthResult {
                status: server::Auth::Accept,
                comment: comment.to_string(),
                options: entry.options.clone(),
                user: user.to_string(),
            });
        }
    }

    Ok(SshAuthResult {
        status: server::Auth::Reject {
            proceed_with_methods: Some((&[MethodKind::PublicKey][..]).into()),
            partial_success: false,
        },
        comment: String::new(),
        options: None,
        user: String::new(),
    })
}

/// Validate a regular public key against a concrete authorized_keys path.
pub async fn validate_public_key_file(
    user: &str,
    key_openssh: &str,
    path: &Path,
) -> Result<SshAuthResult> {
    if !path.exists() {
        return Ok(SshAuthResult {
            status: server::Auth::Reject {
                proceed_with_methods: Some((&[MethodKind::PublicKey][..]).into()),
                partial_success: false,
            },
            comment: String::new(),
            options: None,
            user: String::new(),
        });
    }

    let content = fs::read_to_string(path)?;
    let authorized_keys = parse_authorized_keys_content(&content)?;
    validate_public_key(user, key_openssh, &authorized_keys).await
}

/// Validate a CA-signed certificate
pub async fn validate_certificate(
    cert_data: &str,
    user: &str,
    ca_keys: &Arc<Vec<ssh_key::PublicKey>>,
) -> Result<SshAuthResult> {
    validate_certificate_with_authz(cert_data, user, ca_keys, None).await
}

/// Validate a CA-signed certificate, with optional impersonation authorization.
pub async fn validate_certificate_with_authz(
    cert_data: &str,
    user: &str,
    ca_keys: &Arc<Vec<ssh_key::PublicKey>>,
    authz: Option<&mesh::auth::AuthConfig>,
) -> Result<SshAuthResult> {
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
                user: String::new(),
            });
        }
    };

    // TODO: at load time, also use a hashmap
    let fingerprints: Vec<_> = ca_keys
        .iter()
        .map(|k| k.fingerprint(ssh_key::HashAlg::Sha256))
        .collect();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let valid_principals: Vec<String> = cert.valid_principals().iter().cloned().collect();

    // Reject certificates with no principals before consulting authz. OpenSSH
    // never issues user certs without principals, and an empty list would let a
    // wildcard impersonation rule (`to = "*"`) match unintended identities.
    if valid_principals.is_empty() {
        warn!("Certificate has no valid principals; rejecting");
        return Ok(SshAuthResult {
            status: server::Auth::Reject {
                proceed_with_methods: Some((&[MethodKind::PublicKey][..]).into()),
                partial_success: false,
            },
            comment: cert.key_id().to_string(),
            options: None,
            user: String::new(),
        });
    }

    let authorized_principal = if valid_principals.iter().any(|principal| principal == user) {
        Some(user)
    } else {
        authz.and_then(|authz| authz.authorized_impersonator(&valid_principals, user))
    };

    if authorized_principal.is_none() {
        warn!(
            "Certificate principals {:?} not authorized for user: {}",
            valid_principals, user
        );
        return Ok(SshAuthResult {
            status: server::Auth::Reject {
                proceed_with_methods: Some((&[MethodKind::PublicKey][..]).into()),
                partial_success: false,
            },
            comment: cert.key_id().to_string(),
            options: None,
            user: String::new(),
        });
    }

    if cert.validate_at(now, fingerprints.iter()).is_ok() {
        let authorized_principal = authorized_principal.unwrap_or(user);
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
            user: authorized_principal.to_string(),
        });
    }

    Ok(SshAuthResult {
        status: server::Auth::Reject {
            proceed_with_methods: Some((&[MethodKind::PublicKey][..]).into()),
            partial_success: false,
        },
        comment: cert.key_id().to_string(),
        user: String::new(),
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

        // Split the line into an options field (optional) and the key body.
        // The options field, when present, may contain quoted strings with
        // embedded spaces and commas (e.g. `command="echo hi",no-pty`), so a
        // naive split_whitespace would mis-split. We scan token-by-token,
        // respecting double-quote pairs, until we find a token that begins
        // with a known key type.
        match split_options_and_key(line) {
            ParsedLine::KeyOnly(key_body) => {
                if let Ok(key) = ssh_key::PublicKey::from_openssh(key_body) {
                    entries.push(AuthorizedKeyEntry {
                        comment: Some(key.comment().to_string()),
                        key: Some(key),
                        fingerprint: None,
                        options: None,
                    });
                }
            }
            ParsedLine::WithOptions(options, key_body) => {
                if let Ok(key) = ssh_key::PublicKey::from_openssh(key_body) {
                    entries.push(AuthorizedKeyEntry {
                        comment: Some(key.comment().to_string()),
                        key: Some(key),
                        fingerprint: None,
                        options: Some(options),
                    });
                }
            }
            ParsedLine::FingerprintOnly(fingerprint, comment) => {
                entries.push(AuthorizedKeyEntry {
                    key: None,
                    fingerprint: Some(fingerprint),
                    options: None,
                    comment,
                });
            }
            ParsedLine::Unparsable => {
                warn!("Skipping unparsable authorized_keys line");
            }
        }
    }
    Ok(entries)
}

/// Result of splitting an authorized_keys line.
enum ParsedLine<'a> {
    /// Line is just a key (no options).
    KeyOnly(&'a str),
    /// Line has options followed by a key.
    WithOptions(String, &'a str),
    /// Line is a bare fingerprint (`SHA256:...` / `MD5:...`) with optional comment.
    FingerprintOnly(String, Option<String>),
    /// Line could not be parsed.
    Unparsable,
}

/// Split an authorized_keys line into an optional options field and the key
/// body (everything after the options, including comment). Handles quoted
/// option values that may contain spaces.
fn split_options_and_key(line: &str) -> ParsedLine<'_> {
    // Fast path: the first whitespace-delimited token is a known key type.
    let first_token = line.split_whitespace().next().unwrap_or("");
    if is_known_key_type(first_token) {
        return ParsedLine::KeyOnly(line);
    }

    // Fingerprint-only line.
    if first_token.starts_with("SHA256:") || first_token.starts_with("MD5:") {
        let fingerprint = first_token.to_string();
        let comment = line[first_token.len()..].trim();
        let comment = if comment.is_empty() {
            None
        } else {
            Some(comment.to_string())
        };
        return ParsedLine::FingerprintOnly(fingerprint, comment);
    }

    // Otherwise the first field is an options string. Scan respecting quotes
    // to find where the options end and the key begins.
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut in_quotes = false;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'"' {
            in_quotes = !in_quotes;
        } else if c == b' ' && !in_quotes {
            // End of options token.
            let options = line[..i].to_string();
            let rest = line[i..].trim_start();
            // The next token should be the key type; verify.
            let key_type = rest.split_whitespace().next().unwrap_or("");
            if is_known_key_type(key_type) {
                return ParsedLine::WithOptions(options, rest);
            }
            // Options present but no recognizable key follows.
            return ParsedLine::Unparsable;
        }
        i += 1;
    }

    // No space found outside quotes — line is just an options blob with no key.
    ParsedLine::Unparsable
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
            let key_str = if let Some(stripped) = line.strip_prefix("@cert-authority") {
                stripped.trim()
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

pub fn generate_ca(cadir: &Path, domain: &str) -> Result<()> {
    fs::create_dir_all(cadir)?;
    info!("Generating CA in {:?}", cadir);

    let ca_ssh_key = ssh_key::PrivateKey::random(
        &mut rand::rng(),
        ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        },
    )?;
    let pkcs8_pem = ssh_to_pkcs8_pem(&ca_ssh_key)?;

    let key_file = cadir.join("id_ecdsa");
    fs::write(&key_file, &pkcs8_pem)?;
    set_permissions(&key_file)?;

    fs::write(
        cadir.join("id_ecdsa.pub"),
        ca_ssh_key.public_key().to_openssh()?,
    )?;

    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, domain);
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let ca_key_pair = KeyPair::from_pem(&pkcs8_pem)?;
    let ca_cert = ca_params.self_signed(&ca_key_pair)?;

    fs::write(cadir.join("id_ecdsa.crt"), ca_cert.pem())?;
    Ok(())
}

pub fn generate_node(nodedir: &Path, name: &str, domain: &str) -> Result<()> {
    fs::create_dir_all(nodedir)?;
    info!("Generating node keys in {:?}", nodedir);

    let ssh_key = ssh_key::PrivateKey::random(
        &mut rand::rng(),
        ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        },
    )?;
    let pkcs8_pem = ssh_to_pkcs8_pem(&ssh_key)?;

    let key_file = nodedir.join("id_ecdsa");
    fs::write(&key_file, &pkcs8_pem)?;
    set_permissions(&key_file)?;

    fs::write(
        nodedir.join("id_ecdsa.pub"),
        ssh_key.public_key().to_openssh()?,
    )?;

    let mut node_params = CertificateParams::default();
    node_params.distinguished_name = DistinguishedName::new();
    let fqdn = format!("{}.{}", name, domain);
    node_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, &fqdn);
    node_params
        .subject_alt_names
        .push(SanType::DnsName(fqdn.try_into()?));

    let node_key_pair = KeyPair::from_pem(&pkcs8_pem)?;
    let node_cert = node_params.self_signed(&node_key_pair)?;

    fs::write(nodedir.join("id_ecdsa.crt"), node_cert.pem())?;
    Ok(())
}

pub fn sign_node(cadir: &Path, nodedir: &Path, name: &str, domain: &str) -> Result<()> {
    sign_node_with_options(cadir, nodedir, name, domain, None, None, None, None)
}

pub fn sign_node_with_options(
    cadir: &Path,
    nodedir: &Path,
    name: &str,
    domain: &str,
    host_principals: Option<Vec<String>>,
    user_principals: Option<Vec<String>>,
    valid_after: Option<u64>,
    valid_before: Option<u64>,
) -> Result<()> {
    info!("Signing node {:?} using CA {:?}", nodedir, cadir);

    let ca_key_pem = fs::read_to_string(cadir.join("id_ecdsa"))?;
    let ca_ssh_key = ssh_key_from_pkcs8_pem(&ca_key_pem)?;
    let ca_key_pair = KeyPair::from_pem(&ca_key_pem)?;

    let node_key_pem = fs::read_to_string(nodedir.join("id_ecdsa"))?;
    let node_pub_str = fs::read_to_string(nodedir.join("id_ecdsa.pub"))?;
    let node_pub = ssh_key::PublicKey::from_openssh(node_pub_str.trim())?;
    let node_key_pair = KeyPair::from_pem(&node_key_pem)?;

    let mut node_params = CertificateParams::default();
    node_params.distinguished_name = DistinguishedName::new();
    let fqdn = format!("{}.{}", name, domain);
    node_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, &fqdn);
    node_params
        .subject_alt_names
        .push(SanType::DnsName(fqdn.try_into()?));

    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, domain);
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let issuer = rcgen::Issuer::from_params(&ca_params, ca_key_pair);
    let node_cert = node_params.signed_by(&node_key_pair, &issuer)?;
    fs::write(nodedir.join("id_ecdsa.crt"), node_cert.pem())?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let valid_after = valid_after.unwrap_or(now.saturating_sub(24 * 60 * 60));
    let valid_before = valid_before.unwrap_or(now + 10 * 365 * 24 * 60 * 60);

    let mut host_cert_builder = Builder::new_with_random_nonce(
        &mut rand::rng(),
        node_pub.key_data().clone(),
        valid_after,
        valid_before,
    )?;
    host_cert_builder
        .cert_type(CertType::Host)?
        .key_id(format!("{}-host", name))?;
    let host_principals = host_principals.unwrap_or_else(|| vec![format!("{}.{}", name, domain)]);
    for principal in host_principals {
        host_cert_builder.valid_principal(principal)?;
    }

    let host_cert = host_cert_builder.sign(&ca_ssh_key)?;
    fs::write(
        nodedir.join("id_ecdsa-host-cert.pub"),
        host_cert.to_openssh()?,
    )?;

    let mut user_cert_builder = Builder::new_with_random_nonce(
        &mut rand::rng(),
        node_pub.key_data().clone(),
        valid_after,
        valid_before,
    )?;
    user_cert_builder
        .cert_type(CertType::User)?
        .key_id(format!("{}-user", name))?;
    let user_principals = user_principals.unwrap_or_else(|| vec![format!("{}@{}", name, domain)]);
    for principal in user_principals {
        user_cert_builder.valid_principal(principal)?;
    }

    let user_cert = user_cert_builder.sign(&ca_ssh_key)?;
    fs::write(
        nodedir.join("id_ecdsa-user-cert.pub"),
        user_cert.to_openssh()?,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_parse_authorized_keys_quoted_options_with_spaces() {
        let key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBICtPKa3mXZss+k6LqtiNOQ3TbJFqLvjsvZGubtILlkV2Kz3HjO9+fghwCT/bb1R2SrvqHWWEj+QH6G4+ogPns=";
        // Options field containing a quoted value with spaces and a comma.
        let content = format!(
            "command=\"echo hello world\",no-pty {}\nfrom=\"10.0.0.0/8\",permitlisten=\"127.0.0.1:0\" {}",
            key, key
        );
        let entries = parse_authorized_keys_content(&content).unwrap();
        assert_eq!(entries.len(), 2, "both quoted-option entries should parse");
        assert_eq!(
            entries[0].options.as_deref(),
            Some("command=\"echo hello world\",no-pty")
        );
        assert!(entries[0].key.is_some());
        assert_eq!(
            entries[1].options.as_deref(),
            Some("from=\"10.0.0.0/8\",permitlisten=\"127.0.0.1:0\"")
        );
        assert!(entries[1].key.is_some());
    }

    #[tokio::test]
    async fn test_validate_certificate() {
        let ca_key =
            ssh_key::PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let user_key =
            ssh_key::PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

        let mut builder = ssh_key::certificate::Builder::new_with_random_nonce(
            &mut rand::rng(),
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

    #[tokio::test]
    async fn test_validate_certificate_with_impersonation() {
        let ca_key =
            ssh_key::PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let user_key =
            ssh_key::PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

        let mut builder = ssh_key::certificate::Builder::new_with_random_nonce(
            &mut rand::rng(),
            user_key.public_key().key_data().clone(),
            0,
            2000000000 + 100000,
        )
        .unwrap();

        builder
            .cert_type(ssh_key::certificate::CertType::User)
            .unwrap();
        builder.valid_principal("root@example.m").unwrap();
        builder.key_id("root-cert").unwrap();

        let cert = builder.sign(&ca_key).unwrap();
        let cert_openssh = cert.to_openssh().unwrap();
        let ca_keys = Arc::new(vec![ca_key.public_key().clone()]);

        let rejected = validate_certificate(&cert_openssh, "root@host3-vm.example.m", &ca_keys)
            .await
            .unwrap();
        assert!(matches!(rejected.status, server::Auth::Reject { .. }));

        let authz = mesh::auth::AuthConfig {
            impersonation: vec![mesh::auth::ImpersonationRule {
                from: "root@example.m".to_string(),
                to: "*".to_string(),
            }],
            ..Default::default()
        };

        let accepted = validate_certificate_with_authz(
            &cert_openssh,
            "root@host3-vm.example.m",
            &ca_keys,
            Some(&authz),
        )
        .await
        .unwrap();
        assert!(matches!(accepted.status, server::Auth::Accept));
        assert_eq!(accepted.user, "root@example.m");
    }

    #[tokio::test]
    async fn test_validate_public_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let user_dir = dir.path().join("users").join("alice");
        std::fs::create_dir_all(&user_dir).unwrap();

        let key =
            ssh_key::PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let public_key = key.public_key().to_openssh().unwrap();
        std::fs::write(user_dir.join("authorized_keys"), &public_key).unwrap();

        let res = validate_public_key_file("alice", &public_key, &user_dir.join("authorized_keys"))
            .await
            .unwrap();
        assert!(matches!(res.status, server::Auth::Accept));

        let res = validate_public_key_file(
            "alice",
            &public_key,
            &dir.path().join("missing").join("authorized_keys"),
        )
        .await
        .unwrap();
        assert!(matches!(res.status, server::Auth::Reject { .. }));
    }
}
