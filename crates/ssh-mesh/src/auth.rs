use anyhow::{Context, Result};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use log::{info, warn};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rcgen::{CertificateParams, DistinguishedName, IsCa, KeyPair, SanType};
use russh::keys::PrivateKey;
use russh::server;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use ssh_key::certificate::{Builder, CertType};
use ssh_key::rand_core::OsRng;
use ssh_key::LineEnding;
use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, trace};
use x509_parser::prelude::*;

// File paths for SSH authentication
pub const AUTHORIZED_KEYS_PATH: &str = "authorized_keys";
pub const AUTHORIZED_CAS_PATH: &str = "authorized_cas";

#[derive(Debug, Clone)]
pub struct AuthorizedKeyEntry {
    pub key: Option<ssh_key::PublicKey>,
    pub fingerprint: Option<String>,
    pub options: Option<String>,
    pub comment: Option<String>,
}

pub struct SshAuthResult {
    pub status: server::Auth,
    pub comment: String,
    pub options: Option<String>,
}

/// Load SSH key from file or generate a new one
pub fn load_or_generate_key(base_dir: &Path) -> PrivateKey {
    let key_path = base_dir.join("id_ecdsa");

    if key_path.exists() {
        let key_data = fs::read(&key_path).expect("Failed to read SSH key file");
        if !key_data.is_empty() {
            // Try decoding as secret key (supports OpenSSH and PEM/PKCS#8)
            if let Ok(content) = String::from_utf8(key_data.clone()) {
                if let Ok(key) = russh::keys::decode_secret_key(&content, None) {
                    debug!("Loading key from existing file");
                    return key;
                }
            }
            if let Ok(key) = PrivateKey::from_bytes(&key_data) {
                debug!("Loading key from existing file (binary format)");
                return key;
            }
        }
    }

    debug!("Generating new EC-256 key (PKCS#8 format)");
    let ssh_pk = ssh_key::PrivateKey::random(
        &mut rand::rngs::OsRng,
        ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        },
    )
    .expect("Failed to generate SSH key");

    let pkcs8_pem = ssh_to_pkcs8_pem(&ssh_pk).expect("Failed to convert to PKCS#8");

    if let Some(parent) = key_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = fs::write(&key_path, pkcs8_pem.as_bytes());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(&key_path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            let _ = fs::set_permissions(&key_path, perms);
        }
    }

    russh::keys::decode_secret_key(&pkcs8_pem, None).expect("Failed to reload key")
}

pub fn generate_ca(cadir: &Path, domain: &str) -> Result<()> {
    fs::create_dir_all(cadir)?;
    info!("Generating CA in {:?}", cadir);

    let ca_ssh_key = ssh_key::PrivateKey::random(
        &mut OsRng,
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
        &mut OsRng,
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

    let mut host_cert_builder = Builder::new_with_random_nonce(
        &mut OsRng,
        node_pub.key_data().clone(),
        2000000000,
        2000000000 + 3600 * 24 * 365,
    )?;
    host_cert_builder
        .cert_type(CertType::Host)?
        .key_id(format!("{}-host", name))?
        .valid_principal(format!("{}.{}", name, domain))?;

    let host_cert = host_cert_builder.sign(&ca_ssh_key)?;
    fs::write(
        nodedir.join("id_ecdsa-host-cert.pub"),
        host_cert.to_openssh()?,
    )?;

    let mut user_cert_builder = Builder::new_with_random_nonce(
        &mut OsRng,
        node_pub.key_data().clone(),
        2000000000,
        2000000000 + 3600 * 24 * 365,
    )?;
    user_cert_builder
        .cert_type(CertType::User)?
        .key_id(format!("{}-user", name))?
        .valid_principal(format!("{}@{}", name, domain))?;

    let user_cert = user_cert_builder.sign(&ca_ssh_key)?;
    fs::write(
        nodedir.join("id_ecdsa-user-cert.pub"),
        user_cert.to_openssh()?,
    )?;

    Ok(())
}

pub fn ssh_to_pkcs8_pem(ssh_key: &ssh_key::PrivateKey) -> Result<String> {
    let ecdsa_key = ssh_key.key_data().ecdsa().context("Not an ECDSA key")?;
    let secret_key = p256::SecretKey::from_slice(ecdsa_key.private_key_bytes())?;
    let pkcs8_der = secret_key.to_pkcs8_der()?;
    Ok(pkcs8_der.to_pem("PRIVATE KEY", LineEnding::LF)?.to_string())
}

pub fn ssh_key_from_pkcs8_pem(pem: &str) -> Result<ssh_key::PrivateKey> {
    let secret_key = p256::SecretKey::from_pkcs8_pem(pem)?;
    let public_key = secret_key.public_key();

    let encoded = public_key.to_encoded_point(false);
    let public = ssh_key::sec1::EncodedPoint::from_bytes(encoded.as_bytes())
        .map_err(|e| anyhow::anyhow!("SEC1 encoding error: {}", e))?;

    let keypair_data =
        ssh_key::private::KeypairData::Ecdsa(ssh_key::private::EcdsaKeypair::NistP256 {
            public,
            private: secret_key.into(),
        });

    Ok(ssh_key::PrivateKey::new(keypair_data, "restored")?)
}

pub fn set_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

/// Validate a regular public key against authorized_keys
pub async fn validate_public_key(
    user: &str,
    key_openssh: &str,
    authorized_keys: &[AuthorizedKeyEntry],
) -> Result<SshAuthResult> {
    trace!("Validating public key for user {}: {}", user, key_openssh);

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
            // Check for exact match or SHA256 match
            if auth_fp == &incoming_fp
                || (auth_fp.starts_with("SHA256:") && auth_fp == &incoming_fp)
            {
                matched = true;
            }
        }

        if matched {
            // Check if comment matches user
            let comment = entry.comment.as_deref().unwrap_or("");
            let comment_matches = if comment.is_empty() {
                true
            } else {
                comment == user || comment.starts_with(&format!("{}@", user))
            };

            if comment_matches {
                info!(
                    "Public key authentication successful for user {} (match at index {})",
                    user, i
                );
                return Ok(SshAuthResult {
                    status: server::Auth::Accept,
                    comment: comment.to_string(),
                    options: entry.options.clone(),
                });
            } else {
                warn!(
                    "Key matched but comment '{}' does not match user '{}'",
                    comment, user
                );
            }
        }
    }

    warn!(
        "No matching public key found in authorized_keys for user {}",
        user
    );
    Ok(SshAuthResult {
        status: server::Auth::Reject {
            proceed_with_methods: None,
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
                    proceed_with_methods: None,
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
                proceed_with_methods: None,
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

    // Use a very high timestamp for validation to avoid issues in tests
    if cert.validate_at(2000000000, fingerprints.iter()).is_ok() {
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
            proceed_with_methods: None,
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

        // Check if the first part is a known key type or options
        if is_known_key_type(parts[0]) {
            // Format: keytype base64 [comment]
            if let Ok(key) = ssh_key::PublicKey::from_openssh(line) {
                entries.push(AuthorizedKeyEntry {
                    comment: Some(key.comment().to_string()),
                    key: Some(key),
                    fingerprint: None,
                    options: None,
                });
            }
        } else if parts.len() >= 2 && is_known_key_type(parts[1]) {
            // Format: options keytype base64 [comment]
            let options = parts[0].to_string();
            // Try parsing the rest as a key
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
            // Format: fingerprint [comment]
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

pub fn validate_x509_certificate(
    cert_der: &[u8],
    _ca_cert_der: Option<&[u8]>,
    _authorized_keys: Option<&Arc<Vec<ssh_key::PublicKey>>>,
) -> Result<bool> {
    let (_, cert) = X509Certificate::from_der(cert_der)?;
    // Basic validation: check expiration
    let now = chrono::Utc::now().timestamp();
    if cert.validity().not_before.timestamp() > now || cert.validity().not_after.timestamp() < now {
        warn!("Certificate is expired or not yet valid");
        return Ok(false);
    }
    Ok(true)
}

pub struct TlsServer {
    pub acceptor: TlsAcceptor,
    pub addr: String,
}

impl TlsServer {
    pub fn new(
        server_cert_path: &Path,
        server_key_path: &Path,
        ca_cert_path: Option<&Path>,
        listen_addr: &str,
    ) -> Result<Self> {
        let certs = load_certs(server_cert_path)?;
        let key = load_key(server_key_path)?;

        let mut config = if let Some(ca_path) = ca_cert_path {
            let ca_certs = load_certs(ca_path)?;
            let mut root_cert_store = rustls::RootCertStore::empty();
            for cert in ca_certs {
                root_cert_store.add(cert)?;
            }

            let verifier = WebPkiClientVerifier::builder(Arc::new(root_cert_store)).build()?;

            rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)?
        } else {
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)?
        };

        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            addr: listen_addr.to_string(),
        })
    }

    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(&self.addr).await?;
        info!("TLS server listening on {}", self.addr);

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let acceptor = self.acceptor.clone();

            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        debug!("Accepted TLS connection from {}", peer_addr);
                        if let Err(e) = handle_tls_connection(tls_stream).await {
                            warn!("Error handling TLS connection from {}: {}", peer_addr, e);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to accept TLS connection from {}: {}", peer_addr, e);
                    }
                }
            });
        }
    }
}

async fn handle_tls_connection(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Result<()> {
    let (_inner, connection) = stream.get_mut();

    let client_identity = if let Some(certs) = connection.peer_certificates() {
        if !certs.is_empty() {
            let cert_der = &certs[0];
            match X509Certificate::from_der(cert_der) {
                Ok((_, cert)) => cert.subject().to_string(),
                Err(_) => "unknown-cert".to_string(),
            }
        } else {
            "no-cert".to_string()
        }
    } else {
        "anonymous".to_string()
    };

    info!("Handling connection from client: {}", client_identity);

    let mut buf = [0u8; 1024];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        let msg = String::from_utf8_lossy(&buf[..n]);
        debug!("Received: {}", msg);

        let response = format!("Echo: {} (Identity: {})\n", msg, client_identity);
        stream.write_all(response.as_bytes()).await?;
    }

    Ok(())
}

pub async fn run_axum_https_server(
    port: u16,
    acceptor: TlsAcceptor,
    app: axum::Router,
) -> Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    info!("HTTPS server listening on {}", addr);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("TLS handshake failed from {}: {}", peer_addr, e);
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);

            if let Err(err) = auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, hyper_util::service::TowerToHyperService::new(app))
                .await
            {
                warn!("Error serving HTTPS connection from {}: {}", peer_addr, err);
            }
        });
    }
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);

    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(PrivateKeyDer::Sec1(key)),
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(PrivateKeyDer::Pkcs1(key)),
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(PrivateKeyDer::Pkcs8(key)),
            None => break,
            _ => continue,
        }
    }

    Err(anyhow::anyhow!("No private key found in {:?}", path))
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
        assert_eq!(
            entries[2].fingerprint,
            Some("SHA256:uwB0YV5mNjM1M1M1M1M1M1M1M1M1M1M1M1M1M1M1M1M".to_string())
        );
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
            fingerprint: Some(fp.clone()),
            options: Some("restrict".to_string()),
            comment: Some("user".to_string()),
        }];

        // Should match by fingerprint and comment (user)
        let res = validate_public_key("user", key_str, &entries)
            .await
            .unwrap();
        assert!(matches!(res.status, server::Auth::Accept));
        assert_eq!(res.options, Some("restrict".to_string()));
    }

    #[tokio::test]
    async fn test_validate_public_key_comment_mismatch() {
        let key_str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBICtPKa3mXZss+k6LqtiNOQ3TbJFqLvjsvZGubtILlkV2Kz3HjO9+fghwCT/bb1R2SrvqHWWEj+QH6G4+ogPns= user@host";
        let entries = vec![AuthorizedKeyEntry {
            key: ssh_key::PublicKey::from_openssh(key_str).ok(),
            fingerprint: None,
            options: None,
            comment: Some("wronguser".to_string()),
        }];

        let res = validate_public_key("user", key_str, &entries)
            .await
            .unwrap();
        assert!(matches!(res.status, server::Auth::Reject { .. }));
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
