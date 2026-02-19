use anyhow::Result;
use russh::client;
use russh::keys::PrivateKeyWithHashAlg;
use ssh_mesh::test_utils::setup_test_environment;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct ClientHandler;

impl client::Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        // Accept all server keys for testing
        Ok(true)
    }
}

#[tokio::test]
async fn test_sftp_integration() -> Result<()> {
    // 1. Setup server
    let setup = setup_test_environment(None, false).await?;
    let ssh_port = setup.ssh_port;

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 2. Load client key
    let key_path = setup.client_key_path;
    let key_data = std::fs::read_to_string(&key_path)?;
    let key = russh::keys::decode_secret_key(&key_data, None)?;
    // Removed: let key_pair = KeyPair::try_from(key)?;

    // 3. Connect client
    let config = Arc::new(client::Config::default());
    let sh = ClientHandler;
    let mut session = client::connect(config, ("127.0.0.1", ssh_port), sh).await?;

    // 4. Authenticate
    let key = Arc::new(key);
    let key_with_alg = PrivateKeyWithHashAlg::new(key, None);
    let auth_res = session
        .authenticate_publickey("testuser", key_with_alg)
        .await?;
    assert!(
        auth_res == client::AuthResult::Success,
        "Authentication failed"
    );

    // 5. Open SFTP
    let channel = session.channel_open_session().await?;
    channel.request_subsystem(true, "sftp").await?;

    // Initialize SFTP client
    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream()).await?;

    // 6. Test SFTP operations using native client

    // Create a file
    let filename = "test_sftp_file.txt";
    let content = b"Hello SFTP World!";
    let mut file = sftp.create(filename).await?;
    file.write_all(content).await?;
    file.shutdown().await?; // Flush and close

    // Verify file exists on server disk
    let server_file_path = setup.base_dir.join(filename);
    assert!(server_file_path.exists());
    let server_content = std::fs::read(&server_file_path)?;
    assert_eq!(server_content, content);

    // Read file via SFTP
    let mut file = sftp.open(filename).await?;
    let mut read_content = Vec::new();
    file.read_to_end(&mut read_content).await?;
    assert_eq!(read_content, content);

    // List directory
    let mut files = sftp.read_dir(".").await?;
    let found = files.any(|f| f.file_name() == filename);
    assert!(found, "File not found in directory listing");

    Ok(())
}
