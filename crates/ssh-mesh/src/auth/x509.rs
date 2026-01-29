// X.509 certificate validation for mTLS

use super::AuthResult;
use anyhow::Result;
use log::warn;
use x509_parser::prelude::*;

/// Validate an X.509 certificate and extract identity
pub fn validate_x509_certificate(
    cert_der: &[u8],
    _ca_cert_der: Option<&[u8]>,
) -> Result<AuthResult> {
    let (_, cert) = X509Certificate::from_der(cert_der)?;

    // Check expiration
    let now = chrono::Utc::now().timestamp();
    if cert.validity().not_before.timestamp() > now || cert.validity().not_after.timestamp() < now {
        warn!("Certificate is expired or not yet valid");
        return Ok(AuthResult::reject());
    }

    // Extract identity from CN (Common Name)
    let identity = extract_common_name(&cert).unwrap_or_else(|| "unknown".to_string());

    // Note: CA chain verification is handled by the TLS layer (rustls)
    // x509-parser is used for identity extraction only

    // Extract extensions as options
    let options = extract_extensions(&cert);

    Ok(AuthResult::accept(identity, options))
}

/// Extract the Common Name from the certificate subject
fn extract_common_name(cert: &X509Certificate) -> Option<String> {
    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            if attr.attr_type() == &oid_registry::OID_X509_COMMON_NAME {
                if let Ok(cn) = attr.attr_value().as_str() {
                    return Some(cn.to_string());
                }
            }
        }
    }
    None
}

/// Extract relevant extensions as a comma-separated options string
fn extract_extensions(cert: &X509Certificate) -> Option<String> {
    let mut opts = Vec::new();

    // Check for key usage
    if let Ok(Some(ku)) = cert.key_usage() {
        if ku.value.digital_signature() {
            opts.push("digitalSignature".to_string());
        }
        if ku.value.key_encipherment() {
            opts.push("keyEncipherment".to_string());
        }
        if ku.value.key_agreement() {
            opts.push("keyAgreement".to_string());
        }
    }

    // Check for extended key usage
    if let Ok(Some(eku)) = cert.extended_key_usage() {
        if eku.value.client_auth {
            opts.push("clientAuth".to_string());
        }
        if eku.value.server_auth {
            opts.push("serverAuth".to_string());
        }
    }

    if opts.is_empty() {
        None
    } else {
        Some(opts.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_common_name() {
        // This would need a real certificate for proper testing
        // For now, just verify the function compiles
    }
}
