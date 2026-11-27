use anyhow::Result;
use russh::client;
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use ssh_mesh::test_utils::setup_test_environment;
use std::sync::Arc;
use std::time::Duration;

struct TestClientHandler;

impl client::Handler for TestClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[tokio::test]
async fn test_certificate_validation_logic() -> Result<()> {
    // This test verifies the lower-level validation function works as expected
    // independent of the full connection flow, which might depend on server support.

    use ssh_mesh::auth::validate_certificate;

    // 1. Generate CA
    let ca_key = ssh_key::PrivateKey::random(
        &mut rand::rng(),
        ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        },
    )
    .unwrap();
    let ca_pub = ca_key.public_key();
    let ca_keys = Arc::new(vec![ca_pub.clone()]);

    // 2. Generate Host Key
    let host_key = ssh_key::PrivateKey::random(
        &mut rand::rng(),
        ssh_key::Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        },
    )
    .unwrap();
    let host_pub = host_key.public_key();

    // 3. Sign Host Key to create Certificate
    let mut builder = ssh_key::certificate::Builder::new_with_random_nonce(
        &mut rand::rng(),
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

    // 6. Validate a "forever" certificate (valid_before = u64::MAX) signed by a trusted CA
    let mut forever_builder = ssh_key::certificate::Builder::new_with_random_nonce(
        &mut rand::rng(),
        host_pub.key_data().clone(),
        0,
        u64::MAX,
    )
    .unwrap();
    forever_builder
        .cert_type(ssh_key::certificate::CertType::Host)
        .unwrap();
    forever_builder.key_id("test-host-forever").unwrap();
    forever_builder.valid_principal("localhost").unwrap();

    let forever_cert = forever_builder.sign(&ca_key).unwrap();
    let forever_openssh = forever_cert.to_openssh().unwrap();
    let res = validate_certificate(&forever_openssh, "localhost", &ca_keys).await?;
    assert!(matches!(res.status, russh::server::Auth::Accept));

    Ok(())
}

#[tokio::test]
async fn test_invalid_cert_auth_skipped_and_continues() -> Result<()> {
    let setup = setup_test_environment(None, false).await?;
    let ssh_port = setup.ssh_port;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let untrusted_ca =
        ssh_key::PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
    let cert_key = Arc::new(
        ssh_key::PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap(),
    );

    let mut forever_builder = ssh_key::certificate::Builder::new_with_random_nonce(
        &mut rand::rng(),
        cert_key.public_key().key_data().clone(),
        0,
        u64::MAX,
    )
    .unwrap();
    forever_builder
        .cert_type(ssh_key::certificate::CertType::User)
        .unwrap();
    forever_builder.key_id("forever-untrusted").unwrap();
    forever_builder.valid_principal("testuser").unwrap();
    let forever_cert = forever_builder.sign(&untrusted_ca).unwrap();

    let mut expired_builder = ssh_key::certificate::Builder::new_with_random_nonce(
        &mut rand::rng(),
        cert_key.public_key().key_data().clone(),
        0,
        1,
    )
    .unwrap();
    expired_builder
        .cert_type(ssh_key::certificate::CertType::User)
        .unwrap();
    expired_builder.key_id("expired").unwrap();
    expired_builder.valid_principal("testuser").unwrap();
    let expired_cert = expired_builder.sign(&untrusted_ca).unwrap();

    let config = Arc::new(client::Config::default());
    let mut session = client::connect(config, ("127.0.0.1", ssh_port), TestClientHandler).await?;

    // 1. Untrusted "forever" cert (valid_before = u64::MAX) is rejected without killing the session.
    let res = session
        .authenticate_openssh_cert("testuser", cert_key.clone(), forever_cert)
        .await?;
    assert!(
        matches!(res, client::AuthResult::Failure { .. }),
        "expected Failure for untrusted forever cert, got {res:?}"
    );

    // 2. Expired cert is rejected without killing the session.
    let res = session
        .authenticate_openssh_cert("testuser", cert_key, expired_cert)
        .await?;
    assert!(
        matches!(res, client::AuthResult::Failure { .. }),
        "expected Failure for expired cert, got {res:?}"
    );

    // 3. Valid authorized key on the same SSH session succeeds.
    let key_data = std::fs::read_to_string(&setup.client_key_path)?;
    let valid_key = Arc::new(russh::keys::decode_secret_key(&key_data, None)?);
    let res = session
        .authenticate_publickey("testuser", PrivateKeyWithHashAlg::new(valid_key, None))
        .await?;
    assert_eq!(res, client::AuthResult::Success);

    setup.abort_server();
    Ok(())
}
