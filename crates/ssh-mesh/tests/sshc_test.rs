/// Integration tests for the SSH client module (sshc).
///
/// Uses the test infrastructure from `test_utils` to start an SSH server,
/// then exercises the `SshClientManager` and its REST API.
///
/// The SSH client uses the same private key as the server — no explicit
/// key is required in the connect call or REST payload.
use anyhow::Result;
use ssh_mesh::sshc::{ExecResult, SshClientManager};
use ssh_mesh::test_utils::setup_test_environment;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Helper: build a SshClientManager with a freshly generated key that matches
/// the test server (load_or_generate_key uses the same base_dir).
fn manager_from_setup(setup: &ssh_mesh::test_utils::TestSetup) -> Arc<SshClientManager> {
    let key = ssh_mesh::auth::load_or_generate_key(&setup.base_dir);
    Arc::new(SshClientManager::new(key, Vec::new(), None, None))
}

// ---------------------------------------------------------------------------
//  Direct API tests (using SshClientManager directly)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_sshc_connect_and_list() -> Result<()> {
    let setup = setup_test_environment(None, false).await?;
    let ssh_port = setup.ssh_port;
    let manager = manager_from_setup(&setup);

    // Connect (no key argument — uses the manager's built-in key)
    let id = manager
        .connect("127.0.0.1", ssh_port, "testuser", "")
        .await?;
    assert!(id > 0, "Connection ID should be positive");

    // List connections
    let conns = manager.list_connections().await;
    assert_eq!(conns.len(), 1);
    assert_eq!(conns[0].id, id);
    assert_eq!(conns[0].host, "127.0.0.1");
    assert_eq!(conns[0].port, ssh_port);
    assert_eq!(conns[0].user, "testuser");

    // Disconnect
    manager.disconnect(id).await?;
    let conns = manager.list_connections().await;
    assert_eq!(conns.len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_sshc_exec() -> Result<()> {
    let setup = setup_test_environment(None, false).await?;
    let ssh_port = setup.ssh_port;
    let manager = manager_from_setup(&setup);

    let id = manager
        .connect("127.0.0.1", ssh_port, "testuser", "")
        .await?;

    // Execute a simple command
    let result: ExecResult = manager.exec(id, "echo hello").await?;
    assert_eq!(result.stdout.trim(), "hello");
    assert_eq!(result.exit_code, 0);

    // Execute a command that writes to stderr
    let result = manager.exec(id, "echo error >&2").await?;
    assert_eq!(result.stderr.trim(), "error");
    assert_eq!(result.exit_code, 0);

    // Execute command with non-zero exit code
    let result = manager.exec(id, "exit 42").await?;
    assert_eq!(result.exit_code, 42);

    manager.disconnect(id).await?;
    Ok(())
}

#[tokio::test]
async fn test_sshc_local_forwarding() -> Result<()> {
    let setup = setup_test_environment(None, false).await?;
    let ssh_port = setup.ssh_port;
    let manager = manager_from_setup(&setup);

    // Start an echo server on a free port
    let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let echo_port = echo_listener.local_addr()?.port();
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

    let id = manager
        .connect("127.0.0.1", ssh_port, "testuser", "")
        .await?;

    // Forward local port to echo_port through SSH
    let local_forward_port = ssh_mesh::test_utils::find_free_port().unwrap();
    manager
        .add_local_forward(id, local_forward_port, "127.0.0.1", echo_port)
        .await?;

    // Give the listener a moment to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Connect through the tunnel and send data
    let mut client =
        tokio::net::TcpStream::connect(format!("127.0.0.1:{}", local_forward_port)).await?;
    let test_data = b"Hello through tunnel!";
    client.write_all(test_data).await?;

    let mut buf = vec![0u8; 1024];
    let n = client.read(&mut buf).await?;
    assert_eq!(&buf[..n], test_data, "Echo data mismatch");

    manager.disconnect(id).await?;
    Ok(())
}

#[tokio::test]
async fn test_sshc_disconnect_not_found() -> Result<()> {
    // We still need a valid key to construct the manager, even if we don't connect.
    let key =
        russh::keys::PrivateKey::random(&mut rand::rngs::OsRng, russh::keys::Algorithm::Ed25519)
            .unwrap();
    let manager = Arc::new(SshClientManager::new(key, Vec::new(), None, None));
    let result = manager.disconnect(999).await;
    assert!(result.is_err(), "Disconnecting invalid ID should fail");
    Ok(())
}

// ---------------------------------------------------------------------------
//  REST API tests (using HTTP requests to the sshc endpoints)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_sshc_rest_api_connect_and_exec() -> Result<()> {
    let setup = setup_test_environment(None, true).await?;
    let http_port = setup.http_port.expect("HTTP port should be set");
    let ssh_port = setup.ssh_port;

    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{}", http_port);

    // Connect — no private key in the payload, server key is used automatically
    let connect_resp = client
        .post(format!("{}/_m/api/sshc/connect", base_url))
        .json(&serde_json::json!({
            "host": "127.0.0.1",
            "port": ssh_port,
            "user": "testuser"
        }))
        .send()
        .await?;
    assert_eq!(connect_resp.status(), 200, "Connect should succeed");
    let body: serde_json::Value = connect_resp.json().await?;
    let conn_id = body["id"].as_u64().unwrap();

    // List connections
    let list_resp = client
        .get(format!("{}/_m/api/sshc/connections", base_url))
        .send()
        .await?;
    assert_eq!(list_resp.status(), 200);
    let conns: Vec<serde_json::Value> = list_resp.json().await?;
    assert_eq!(conns.len(), 1);

    // Exec
    let exec_resp = client
        .post(format!(
            "{}/_m/api/sshc/connections/{}/exec",
            base_url, conn_id
        ))
        .json(&serde_json::json!({"command": "echo api_test"}))
        .send()
        .await?;
    assert_eq!(exec_resp.status(), 200);
    let exec_result: serde_json::Value = exec_resp.json().await?;
    assert_eq!(exec_result["stdout"].as_str().unwrap().trim(), "api_test");

    // Disconnect
    let disc_resp = client
        .delete(format!("{}/_m/api/sshc/connections/{}", base_url, conn_id))
        .send()
        .await?;
    assert_eq!(disc_resp.status(), 200);

    // Verify empty
    let list_resp = client
        .get(format!("{}/_m/api/sshc/connections", base_url))
        .send()
        .await?;
    let conns: Vec<serde_json::Value> = list_resp.json().await?;
    assert_eq!(conns.len(), 0);

    Ok(())
}
