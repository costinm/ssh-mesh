use anyhow::Result;
use ssh_mesh::sshc::SshClientManager;
use ssh_mesh::sshmuxc::MuxClient;
use ssh_mesh::test_utils;
use std::sync::Arc;
use std::time::Duration; // Use std::time::Duration for tokio::time::sleep

#[tokio::test]
async fn test_mux_functionality() -> Result<()> {
    // 1. Setup server and client environment
    // setup_test_environment(custom_temp_dir: Option<PathBuf>, start_http: bool)
    let setup = test_utils::setup_test_environment(None, false).await?;
    let mux_dir = setup.base_dir.join("mux");
    std::fs::create_dir_all(&mux_dir)?;

    // 2. Client manager with mux_dir configured
    let client_key = ssh_mesh::auth::load_or_generate_key(&setup.base_dir);
    let manager = Arc::new(SshClientManager::new(
        client_key,
        Vec::new(),
        None,
        Some(mux_dir.clone()),
    ));

    // 3. Connect to the server
    let server_port = setup.ssh_port;
    let connect_host = "127.0.0.1";
    let connect_user = "testuser";
    let server_known_key = ""; // Empty for TOFU

    // Wait a bit for server to be ready
    tokio::time::sleep(Duration::from_millis(500)).await;

    // connect(host, port, user, server_key)
    let conn_id = manager
        .connect(connect_host, server_port, connect_user, server_known_key)
        .await
        .expect("Failed to connect to SSH server");

    println!("Connected to SSH server, conn_id={}", conn_id);

    // 4. Verify mux socket details
    // The socket path should be mux_dir / ssh-user@host
    let socket_path = ssh_mesh::mux::mux_socket_path(&mux_dir, connect_user, connect_host);
    assert!(
        socket_path.exists(),
        "Mux socket should exist at {:?}",
        socket_path
    );
    println!("Mux socket found at {:?}", socket_path);

    // 5. Connect with MuxClient
    let mut client = MuxClient::connect(&socket_path)
        .await
        .expect("Failed to connect to mux socket");
    println!("Connected to Mux socket");

    // 6. Alive check
    let pid = client.alive_check().await.expect("Alive check failed");
    assert!(pid > 0, "PID should be positive");
    println!("Mux alive check passed, server PID: {}", pid);

    // 7. New session (exec command)
    // We exec "touch <file>" to verify side effect.
    let test_file = setup.base_dir.join("mux_exec_test");
    if test_file.exists() {
        std::fs::remove_file(&test_file)?;
    }
    let cmd = format!("touch {}", test_file.display());
    println!("Executing command via mux: {}", cmd);

    use std::os::unix::io::AsRawFd;
    let stdin = std::io::stdin().as_raw_fd();
    let stdout = std::io::stdout().as_raw_fd();
    let stderr = std::io::stderr().as_raw_fd();

    let (session_id, exit_code) = client
        .new_session(&cmd, false, stdin, stdout, stderr)
        .await
        .expect("New session failed");
    println!(
        "Session {} finished with exit code {}",
        session_id, exit_code
    );
    assert_eq!(exit_code, 0);

    // Verify side effect
    // Wait a brief moment for FS to sync if needed (local shouldn't need much)
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        test_file.exists(),
        "Test file should have been created by exec"
    );

    // 8. Open Local Forward (dynamic port)
    // We wish to forward local port (random) to the SSH server's port (server_port)
    // Then connecting to local port should reach SSH server.
    let target_host = "127.0.0.1";
    let target_port = server_port;

    // open_local_forward(listen_host, listen_port, connect_host, connect_port)
    let local_port = client
        .open_local_forward("127.0.0.1", 0, target_host, target_port)
        .await
        .expect("Open local forward failed");

    assert!(local_port.is_some(), "Should get a dynamic port assigned");
    let forwarded_port = local_port.unwrap() as u16;
    println!(
        "Forwarded local port {} to {}:{}",
        forwarded_port, target_host, target_port
    );

    // Verify connectivity through forward
    // We can try to connect to the forwarded port using a TcpStream and see if we get SSH banner
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", forwarded_port))
        .await
        .expect("Failed to connect to forwarded port");

    // Read SSH banner (starts with "SSH-2.0")
    let mut buf = [0u8; 8];
    use tokio::io::AsyncReadExt;
    stream
        .read_exact(&mut buf)
        .await
        .expect("Failed to read from forwarded port");
    let banner = String::from_utf8_lossy(&buf);
    assert!(banner.starts_with("SSH-"), "Should receive SSH banner");
    println!("Received banner from forwarded port: {}", banner);

    // 9. Cleanup
    manager
        .disconnect(conn_id)
        .await
        .expect("Disconnect failed");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !socket_path.exists(),
        "Mux socket should be removed after disconnect"
    );

    Ok(())
}
