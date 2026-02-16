use anyhow::Result;
use ssh_mesh::sshc::SshClientManager;
use ssh_mesh::test_utils::{TestSetup, setup_test_environment};
use std::sync::Arc;

// Helper to create a manager, but this time we want to populate it with CA keys
// and potentially use a client key that is signed by the CA.
async fn setup_with_certs() -> Result<(TestSetup, Arc<SshClientManager>, String)> {
    let setup = setup_test_environment(None, false).await?;
    let base_dir = setup.base_dir.clone();
    let base_dir_ref = &base_dir;

    // 1. Generate CA
    let ca_dir = base_dir.join("ca");
    ssh_mesh::auth::generate_ca(&ca_dir, "test-ca")?;

    // Load CA public key to pass to ClientManager
    let ca_pub_path = ca_dir.join("id_ecdsa.pub");
    let ca_pub_str = std::fs::read_to_string(&ca_pub_path)?;
    let ca_pub_key = ssh_key::PublicKey::from_openssh(&ca_pub_str)?;

    // 2. Generate Server Key and Certificate
    // The server uses keys in base_dir. Let's sign the server's key.
    // server's key is at base_dir/id_ecdsa.pub
    // We need to move it to a "node" valid structure or just manually sign it?
    // ssh::sign_node expects "nodedir" to have id_ecdsa and id_ecdsa.pub.
    // Our server is running from base_dir.

    // Let's use `sign_node` to generate a signed host cert for the server.
    // The server is already running, so replacing its key on disk might be tricky if it cached it?
    // SshServer loads keys at startup.
    // But `setup_test_environment` starts the server immediately.
    // We might need to stop it or configure it to use a cert.
    // Russh server config `keys` is loaded in `SshServer::new`.

    // Actually, `test_utils::setup_test_environment` starts the server.
    // If we want to test cert auth, we need the server to present a certificate.
    // Russh server support for *presenting* a certificate as its host key is needed.
    // Does ssh-mesh server support presenting a cert?
    // SshServer::get_config() adds `self.keys`.
    // If `self.keys` contains a certificate, does russh send it?
    // partial-implementation details of russh: it usually sends the public key associated with the private key.
    // If we load a private key that includes the cert, maybe?

    // Wait, the client validates the SERVER's host key (certificate).
    // So the Server must override its host key with a Certificate.
    // `ssh_mesh::SshServer` loads `keys` from `auth::load_or_generate_key`.
    // It doesn't seem to load a certificate_chain or similar.
    // Russh `PrivateKey` can hold a certificate?
    // Russh `PrivateKey` is usually just the raw key.
    // If checking `sshc.rs` `check_server_key`:
    // It calls `server_public_key.to_openssh()`.
    // If the server sends a cert, this string will be the cert.

    // To make the server send a cert, we likely need to configure the Russh server with a key that is a cert,
    // or provides a cert.
    // If `SshServer` logic doesn't support loading `id_ecdsa-cert.pub` and attaching it,
    // then the server won't send a cert.

    // Let's check `SshServer` in `lib.rs` and `auth/keys.rs`.
    // `SshServer::new` -> `auth::load_or_generate_key`.
    // `load_or_generate_key` returns `russh::keys::PrivateKey`.
    // Russh keys doesn't seem to have a field for "associated certificate" in `PrivateKey` struct easily visible here,
    // but maybe valid if it's an OpenSSH certificate key type?

    // If the server doesn't support sending a cert, then my client "validate certificate" logic
    // can only be tested if I mock the server or modify SshServer to support certs.

    // The user task summary says: "Validating that the server's host key is a valid certificate".
    // This implies the server *should* be sending a certificate.
    // I should check if I need to update `SshServer` to load/send a host certificate.

    // Current `SshServer::get_config`:
    // config.keys.push(self.keys.clone());

    // If `self.keys` (PrivateKey) doesn't have the cert, it won't send it.
    // I might need to update `SshServer` to look for `-cert.pub` and load it?
    // Or maybe `russh` doesn't support host certificates yet?
    // Russh 0.40+ supports certificates.

    // Let's assume for this test that I can just verify the client side logic
    // by manually invoking `check_server_key` or similar?
    // Or better, update `SshServer` to support loading a host certificate if present.

    // Let's pause creating the test and check if `SshServer` needs update.
    // I'll create a placeholder test for now.

    Ok((
        setup,
        Arc::new(SshClientManager::new(
            ssh_mesh::auth::load_or_generate_key(&base_dir),
            vec![ca_pub_key],
            None,
            None,
        )),
        "".to_string(),
    ))
}

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
