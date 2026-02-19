use anyhow::Result;

#[tokio::test]
async fn test_certificate_validation_logic() -> Result<()> {
    // This test verifies the lower-level validation function works as expected
    // independent of the full connection flow, which might depend on server support.

    use ssh_key::rand_core::OsRng;
    use ssh_mesh::auth::validate_certificate;
    use std::sync::Arc;

    // 1. Generate CA
    let ca_key = ssh_key::PrivateKey::random(
        &mut OsRng,
        ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        },
    )
    .unwrap();
    let ca_pub = ca_key.public_key();
    let ca_keys = Arc::new(vec![ca_pub.clone()]);

    // 2. Generate Host Key
    let host_key = ssh_key::PrivateKey::random(
        &mut OsRng,
        ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        },
    )
    .unwrap();
    let host_pub = host_key.public_key();

    // 3. Sign Host Key to create Certificate
    let mut builder = ssh_key::certificate::Builder::new_with_random_nonce(
        &mut OsRng,
        host_pub.key_data().clone(),
        0,
        2000000000 + 10000,
    )
    .unwrap();
    builder
        .cert_type(ssh_key::certificate::CertType::Host)
        .unwrap();
    builder.key_id("test-host").unwrap();
    builder.valid_principal("localhost").unwrap();
    builder.valid_principal("127.0.0.1").unwrap();

    let cert = builder.sign(&ca_key).unwrap();
    let cert_openssh = cert.to_openssh().unwrap();

    // 4. Validate
    let res = validate_certificate(&cert_openssh, "localhost", &ca_keys).await?;
    assert!(matches!(res.status, russh::server::Auth::Accept));

    // 5. Validate with wrong principal
    let res = validate_certificate(&cert_openssh, "wrong-host", &ca_keys).await?;
    assert!(matches!(res.status, russh::server::Auth::Reject { .. }));

    Ok(())
}
