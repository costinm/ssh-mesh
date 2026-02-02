// Key management - generation, loading, format conversion

use anyhow::{Context, Result};
use log::info;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rcgen::{CertificateParams, DistinguishedName, IsCa, KeyPair, SanType};
use russh::keys::PrivateKey;
use ssh_key::certificate::{Builder, CertType};
use ssh_key::rand_core::OsRng;
use ssh_key::LineEnding;
use std::fs;
use std::path::Path;
use tracing::debug;

// File paths for SSH authentication
pub const AUTHORIZED_KEYS_PATH: &str = "authorized_keys";
pub const AUTHORIZED_CAS_PATH: &str = "authorized_cas";

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

    info!("Generating new EC-256 key (PKCS#8 format)");
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
