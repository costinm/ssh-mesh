use anyhow::Result;
use ssh_mesh::sshc::SshClientManager;
use ssh_mesh::test_utils::setup_test_environment;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Helper: build a SshClientManager with a freshly generated key that matches
/// the test server (load_or_generate_key uses the same base_dir).
fn manager_from_setup(setup: &ssh_mesh::test_utils::TestSetup) -> Arc<SshClientManager> {
    let key = ssh_mesh::auth::load_or_generate_key(&setup.base_dir);
    Arc::new(SshClientManager::new(key, None, None))
}

#[tokio::test]
async fn test_remote_forwarding() -> Result<()> {
    // 1. Setup environment (starts SSH server)
    let setup = setup_test_environment(None, false).await?;
    let ssh_port = setup.ssh_port;
    let manager = manager_from_setup(&setup);

    // 2. Connect client to server
    let id = manager
        .connect("127.0.0.1", ssh_port, "testuser", "")
        .await?;

    // 3. Start a local echo server (the target for the remote forward)
    let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
    let echo_port = echo_listener.local_addr()?.port();

    // Spawn task to handle echo
    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    loop {
                        match socket.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if socket.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        }
    });

    // 4. Request remote forward
    // Request port 0 to let the server allocate a port
    let actual_port = manager
        .add_remote_forward(id, 0, "127.0.0.1", echo_port)
        .await?;

    assert!(actual_port > 0, "Remote forward port should be > 0");
    let remote_listen_port = actual_port as u16;

    // Give some time for the server to start listening
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // 5. Connect to the *server's* listening port
    // Since server and client are localhost, we connect to 127.0.0.1:remote_listen_port
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", remote_listen_port)).await?;

    // 6. Send data and verify echo
    let test_data = b"Hello from remote forward!";
    client.write_all(test_data).await?;

    let mut buf = vec![0u8; 1024];
    let n = client.read(&mut buf).await?;
    assert_eq!(
        &buf[..n],
        test_data,
        "Echo data mismatch via remote forward"
    );

    manager.disconnect(id).await?;
    Ok(())
}
