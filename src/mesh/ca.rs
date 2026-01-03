/// CA provides the mesh certificate signing
///
/// Any node can act as a CA and sign certificates
/// for other nodes.

use anyhow::{Context, Result};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::{X509Name, X509};
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectAlternativeName};
use openssl::hash::MessageDigest;
use openssl::asn1::Asn1Time;
use std::fs;
use std::path::Path;

/// Certificate signing request containing FQDN and SANs
#[derive(Debug, Clone)]
pub struct CertSignRequest {
    pub fqdn: String,
    pub sans: Vec<String>,
    pub public_key: Option<Vec<u8>>,
}

/// Certificate Authority for signing certificates
pub struct CA {
    private_key: PKey<Private>,
    pub certificate: Option<X509>,
    pub base_dir: std::path::PathBuf,
}

impl CA {
    /// Create a new CA instance, reading or creating a P256 key at baseDir/.ssh/ca.key
    ///
    /// # Arguments
    /// * `base_dir` - Base directory containing the .ssh subdirectory
    pub fn new(base_dir: std::path::PathBuf) -> Result<Self> {
        let key_path = base_dir.join(".ssh").join("ca.key");

        let private_key = if key_path.exists() {
            // Load existing key
            Self::load_key(&key_path)?
        } else {
            // Create new P256 key
            let key = Self::generate_p256_key()?;
            Self::save_key(&key, &key_path)?;
            key
        };

        Ok(CA {
            private_key,
            certificate: None,
            base_dir,
        })
    }

    /// Generate a new P256 private key
    fn generate_p256_key() -> Result<PKey<Private>> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec_key = EcKey::generate(&group)?;
        let pkey = PKey::from_ec_key(ec_key)?;
        Ok(pkey)
    }

    /// Load a private key from a PEM file
    fn load_key(path: &Path) -> Result<PKey<Private>> {
        let pem_data = fs::read(path)?;
        let private_key = PKey::private_key_from_pem(&pem_data)?;
        Ok(private_key)
    }

    /// Save a private key to a PEM file
    fn save_key(key: &PKey<Private>, path: &Path) -> Result<()> {
        // Ensure .ssh directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let pem_data = key.private_key_to_pem_pkcs8()?;
        fs::write(path, pem_data)?;
        Ok(())
    }

    /// Load a certificate from a PEM file
    pub fn load_certificate(path: &str) -> Result<X509> {
        let pem_data = fs::read(path)?;
        let cert = X509::from_pem(&pem_data)?;
        Ok(cert)
    }

    /// Save a certificate to a PEM file
    pub fn save_certificate(cert: &X509, path: &str) -> Result<()> {
        let pem_data = cert.to_pem()?;
        fs::write(path, pem_data)?;
        Ok(())
    }

    /// Create a self-signed CA certificate
    pub fn create_ca_certificate(&mut self, common_name: &str) -> Result<()> {
        let mut name_builder = X509Name::builder()?;
        name_builder.append_entry_by_nid(Nid::COMMONNAME, common_name)?;
        let name = name_builder.build();

        let mut cert_builder = X509::builder()?;
        cert_builder.set_version(2)?; // Version 3

        // Generate a random serial number
        let mut serial = BigNum::new()?;
        serial.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
        let serial = serial.to_asn1_integer()?;
        cert_builder.set_serial_number(&serial)?;

        cert_builder.set_subject_name(&name)?;
        cert_builder.set_issuer_name(&name)?;

        cert_builder.set_pubkey(&self.private_key)?;

        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(3650)?; // 10 years
        cert_builder.set_not_before(&not_before)?;
        cert_builder.set_not_after(&not_after)?;

        // Add extensions
        let basic_constraints = BasicConstraints::new().critical().ca().build()?;
        cert_builder.append_extension(basic_constraints)?;

        let key_usage = KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?;
        cert_builder.append_extension(key_usage)?;

        cert_builder.sign(&self.private_key, MessageDigest::sha256())?;
        let cert = cert_builder.build();

        self.certificate = Some(cert);
        Ok(())
    }

    /// Sign a certificate signing request and return a PEM certificate
    pub fn sign_certificate(&self, csr: &CertSignRequest) -> Result<String> {
        let ca_cert = self.certificate.as_ref().context("CA certificate not initialized")?;

        let mut name_builder = X509Name::builder()?;
        name_builder.append_entry_by_nid(Nid::COMMONNAME, &csr.fqdn)?;
        let name = name_builder.build();

        let mut cert_builder = X509::builder()?;
        cert_builder.set_version(2)?; // Version 3

        // Generate a random serial number
        let mut serial = BigNum::new()?;
        serial.rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
        let serial = serial.to_asn1_integer()?;
        cert_builder.set_serial_number(&serial)?;

        cert_builder.set_subject_name(&name)?;
        cert_builder.set_issuer_name(ca_cert.subject_name())?;

        // Use provided public key if available, otherwise generate a new P256 key pair
        let cert_key = if let Some(public_key_bytes) = &csr.public_key {
            PKey::public_key_from_der(public_key_bytes)?
        } else {
            // Generate a new P256 key pair for the certificate
            let private_key = Self::generate_p256_key()?;
            // Convert private key to public key by getting its public component
            PKey::public_key_from_der(&private_key.public_key_to_der()?)?
        };
        cert_builder.set_pubkey(&cert_key)?;

        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(365)?; // 1 year
        cert_builder.set_not_before(&not_before)?;
        cert_builder.set_not_after(&not_after)?;

        // Add SAN extension if needed
        if !csr.sans.is_empty() {
            let mut san_extension = SubjectAlternativeName::new();
            for san in &csr.sans {
                if san.starts_with("DNS:") {
                    san_extension.dns(&san[4..]); // Skip "DNS:"
                } else if san.contains('.') {
                    san_extension.dns(san);
                } else {
                    san_extension.ip(san);
                }
            }
            let san_extension = san_extension.build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
            cert_builder.append_extension(san_extension)?;
        }

        // Add basic constraints extension
        let basic_constraints = BasicConstraints::new().build()?;
        cert_builder.append_extension(basic_constraints)?;

        // Add key usage extension
        let key_usage = KeyUsage::new()
            .digital_signature()
            .key_encipherment()
            .build()?;
        cert_builder.append_extension(key_usage)?;

        cert_builder.sign(&self.private_key, MessageDigest::sha256())?;
        let cert = cert_builder.build();

        // Convert to PEM format
        let pem = String::from_utf8(cert.to_pem()?)?;
        Ok(pem)
    }

    /// Get the CA certificate in PEM format
    pub fn get_ca_certificate_pem(&self) -> Result<String> {
        let ca_cert = self.certificate.as_ref().context("CA certificate not initialized")?;
        let pem = String::from_utf8(ca_cert.to_pem()?)?;
        Ok(pem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_ca_new() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let home_dir = temp_dir.path();
        let key_path = home_dir.join(".ssh").join("ca.key");

        // Create CA with base directory
        let _ca = CA::new(home_dir.to_path_buf())?;

        // Check that key file was created
        assert!(key_path.exists(), "Key file does not exist at {:?}", key_path);

        Ok(())
    }

    #[test]
    fn test_ca_certificate() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let _key_path = temp_dir.path().join(".ssh").join("ca.key");
        let cert_path = temp_dir.path().join("ca.crt");

        // Create CA with base directory
        let mut ca = CA::new(temp_dir.path().to_path_buf())?;

        // Create CA certificate
        ca.create_ca_certificate("Test CA")?;

        // Save CA certificate
        let ca_cert_pem = ca.get_ca_certificate_pem()?;
        fs::write(&cert_path, &ca_cert_pem)?;

        // Check that certificate file was created
        assert!(cert_path.exists());

        // Load certificate back
        let loaded_cert = CA::load_certificate(cert_path.to_str().unwrap())?;
        let loaded_cert_pem = String::from_utf8(loaded_cert.to_pem()?)?;
        assert_eq!(ca_cert_pem, loaded_cert_pem);

        Ok(())
    }

    #[test]
    fn test_sign_certificate() -> Result<()> {
        let temp_dir = TempDir::new()?;

        // Create CA with base directory
        let mut ca = CA::new(temp_dir.path().to_path_buf())?;

        // Create CA certificate
        ca.create_ca_certificate("Test CA")?;

        // Sign a certificate
        let csr = CertSignRequest {
            fqdn: "example.com".to_string(),
            sans: vec!["DNS:www.example.com".to_string(), "DNS:api.example.com".to_string()],
            public_key: None,
        };

        let cert_pem = ca.sign_certificate(&csr)?;
        assert!(!cert_pem.is_empty());
        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(cert_pem.ends_with("-----END CERTIFICATE-----\n"));

        Ok(())
    }
}
