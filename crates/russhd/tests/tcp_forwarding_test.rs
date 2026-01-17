use std::net::TcpListener;
use tokio::net::TcpStream;
use std::io::{Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;
use std::thread;
use anyhow::Result;
use ssh_key::{Algorithm, PrivateKey, LineEnding};
use std::process::{Child, Command};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tokio::time::timeout;
use log::{info};
use once_cell::sync::Lazy;
use tempfile::TempDir;

static INIT_LOGGING: Lazy<()> = Lazy::new(|| {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("trace"))
        .with_level(true)
        .init();
});

// Simple echo server for testing
fn start_echo_server(port: u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(mut stream) = stream {
                thread::spawn(move || {
                    let mut buffer = [0; 1024];
                    loop {
                        match stream.read(&mut buffer) {
                            Ok(0) => break, // Connection closed
                            Ok(n) => {
                                info!("ECHO SERVER: Received {} bytes", n);
                                if stream.write_all(&buffer[..n]).is_err() {
                                    break;
                                }
                                if stream.flush().is_err() {
                                    break;
                                }
                                info!("ECHO SERVER: Echoed {} bytes", n);
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        }
    });
}

fn find_free_port() -> Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

struct TestSetup {
    temp_dir: TempDir,
    client_key_path: PathBuf,
    ssh_port: u16,
    server_handle: tokio::task::JoinHandle<()>,
}

async fn setup_test_environment() -> Result<TestSetup> {
    Lazy::force(&INIT_LOGGING);

    let temp_dir = tempfile::Builder::new().prefix("russhd-test").tempdir()?;
    let base_dir = temp_dir.path().to_path_buf();
    std::fs::create_dir_all(base_dir.join(".ssh"))?;

    let client_keypair = PrivateKey::random(&mut rand::rngs::OsRng, Algorithm::Ed25519)?;
    let client_key_path = temp_dir.path().join(".ssh/id_ed25519");
    std::fs::write(
        &client_key_path,
        client_keypair.to_openssh(LineEnding::LF)?.as_bytes(),
    )?;
    std::fs::set_permissions(&client_key_path, std::fs::Permissions::from_mode(0o600))?;

    let public_key_openssh = client_keypair.public_key().to_openssh()?;
    std::fs::write(
        base_dir.join(".ssh/authorized_keys"),
        public_key_openssh.as_bytes(),
    )?;

    let ssh_port = find_free_port()?;
    let server_base_dir = base_dir.clone();
    let server_handle = tokio::spawn(async move {
        let ssh_server = russhd::SshServer::new(0, None, server_base_dir);
        let config = ssh_server.get_config();
        russhd::run_ssh_server(ssh_port, config, ssh_server)
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(300)).await;

    Ok(TestSetup {
        temp_dir,
        client_key_path,
        ssh_port,
        server_handle,
    })
}

async fn run_test_with_timeout<F, Fut>(test_fn: F) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    timeout(Duration::from_secs(15), test_fn()).await?
}

#[tokio::test]
async fn test_local_tcp_forwarding() -> Result<()> {
    run_test_with_timeout(|| async {
        let setup = setup_test_environment().await?;
        
        let echo_port = find_free_port()?;
        start_echo_server(echo_port);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let local_forward_port = find_free_port()?;
        let mut ssh_client_process = Command::new("ssh")
            .arg("-o").arg("StrictHostKeyChecking=no")
            .arg("-o").arg("UserKnownHostsFile=/dev/null")
            .arg("-v")
            .arg("-i").arg(&setup.client_key_path)
            .arg("-p").arg(setup.ssh_port.to_string())
            .arg("-L").arg(format!("{}:127.0.0.1:{}", local_forward_port, echo_port))
            .arg("-l").arg("testuser")
            .arg("127.0.0.1")
            .arg("-N") // Do not execute a remote command.
            .spawn()?;

        tokio::time::sleep(Duration::from_millis(2000)).await;

        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", local_forward_port)).await?;
        let message = b"Hello, local forwarding test!";
        stream.write_all(message).await?;
        stream.flush().await?;

        let mut buffer = [0; 1024];
        let n = stream.read(&mut buffer).await?;
        
        assert_eq!(&buffer[..n], message);

        ssh_client_process.kill()?;
        setup.server_handle.abort();

        Ok(())
    }).await
}

#[tokio::test]
async fn test_remote_tcp_forwarding() -> Result<()> {
    run_test_with_timeout(|| async {
        let setup = setup_test_environment().await?;
        
        // This echo server is on the "client" side.
        let echo_port = find_free_port()?;
        start_echo_server(echo_port);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The port the *server* will listen on.
        let remote_forward_port = find_free_port()?;

        let mut ssh_client_process: Child = Command::new("ssh")
            .arg("-o").arg("StrictHostKeyChecking=no")
            .arg("-o").arg("UserKnownHostsFile=/dev/null")
            .arg("-v")
            .arg("-i").arg(&setup.client_key_path)
            .arg("-p").arg(setup.ssh_port.to_string())
            .arg("-R").arg(format!("127.0.0.1:{}:127.0.0.1:{}", remote_forward_port, echo_port))
            .arg("-l").arg("testuser")
            .arg("127.0.0.1")
            .arg("-N") // Do not execute a remote command.
            .spawn()?;

        // Give SSH client time to establish connection and forwarding
        tokio::time::sleep(Duration::from_millis(2000)).await;

        // Connect to the port on the server side
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", remote_forward_port)).await?;
        let message = b"Hello, remote forwarding test!";
        stream.write_all(message).await?;
        stream.flush().await?;
        info!("REMOTE TEST: Wrote to server port {}", remote_forward_port);

        // Receive echoed data
        let mut buffer = [0; 1024];
        let n = stream.read(&mut buffer).await?;
        info!("REMOTE TEST: Read from server port {}", remote_forward_port);
        
        assert_eq!(&buffer[..n], message);

        ssh_client_process.kill()?;
        setup.server_handle.abort();

        Ok(())
    }).await
}