use anyhow::Result;
use once_cell::sync::Lazy;
use serde_json::Value;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;

static INIT_LOGGING: Lazy<()> = Lazy::new(|| {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("trace"))
        .with_level(true)
        .init();
});

fn find_free_port() -> Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

struct TestSetup {
    _temp_dir: TempDir,
    client_key_path: PathBuf,
    ssh_port: u16,
    http_port: u16,
    server_handle: tokio::task::JoinHandle<()>,
}

async fn setup_test_environment() -> Result<TestSetup> {
    Lazy::force(&INIT_LOGGING);

    let temp_dir = tempfile::Builder::new().prefix("russhd-api-test").tempdir()?;
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
    let http_port = find_free_port()?;
    let server_base_dir = base_dir.clone();

    let server_handle = tokio::spawn(async move {
        let ssh_server = std::sync::Arc::new(russhd::SshServer::new(0, None, server_base_dir));
        let app_state = russhd::AppState {
            ssh_server: ssh_server.clone(),
            proc_mon: std::sync::Arc::new(pmond::ProcMon::new().unwrap()),
            ws_server: std::sync::Arc::new(ws::WSServer::new()),
        };

        let ssh_server_clone = ssh_server.clone();
        tokio::spawn(async move {
            let config = ssh_server_clone.get_config();
            if let Err(e) = russhd::run_ssh_server(ssh_port, config, (*ssh_server_clone).clone()).await {
                eprintln!("SSH server failed: {}", e);
            }
        });

        let app = russhd::handlers::app(app_state);
        let addr = format!("127.0.0.1:{}", http_port);
        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        axum::serve(listener, app.into_make_service()).await.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    Ok(TestSetup {
        _temp_dir: temp_dir,
        client_key_path,
        ssh_port,
        http_port,
        server_handle,
    })
}

async fn run_test_with_timeout<F, Fut>(test_fn: F) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    timeout(Duration::from_secs(20), test_fn()).await?
}

#[tokio::test]
async fn test_client_api() -> Result<()> {
    run_test_with_timeout(|| async {
        let setup = setup_test_environment().await?;
        let client = reqwest::Client::new();

        // 1. Initially, no clients should be connected
        let res: Value = client
            .get(format!("http://127.0.0.1:{}/api/ssh/clients", setup.http_port))
            .send()
            .await?
            .json()
            .await?;
        assert!(res.as_object().unwrap().is_empty());

        // 2. Connect an SSH client
        let mut ssh_client_process = Command::new("ssh")
            .arg("-v") // Enable verbose logging for client debugging
            .arg("-o").arg("StrictHostKeyChecking=no")
            .arg("-o").arg("UserKnownHostsFile=/dev/null")
            .arg("-o").arg("ControlMaster=no")
            .arg("-o").arg("ControlPath=none")
            .arg("-i").arg(setup.client_key_path.to_str().unwrap())
            .arg("-p").arg(setup.ssh_port.to_string())
            .arg("-l").arg("testuser")
            .arg("127.0.0.1")
            .arg("-N") // Do not execute a remote command, just connect.
            .spawn()?;

        // Give it time to connect and authenticate
        tokio::time::sleep(Duration::from_secs(2)).await;

        // 3. Verify the client is listed in the API
        let res: Value = client
            .get(format!("http://127.0.0.1:{}/api/ssh/clients", setup.http_port))
            .send()
            .await?
            .json()
            .await?;
        
        let clients = res.as_object().unwrap();
        assert_eq!(clients.len(), 1); // Should have 1 client now
        let client_info = clients.values().next().unwrap();
        assert_eq!(client_info["user"], "testuser");


        // 4. Disconnect the client
        ssh_client_process.kill()?;
        ssh_client_process.wait()?;

        // Give the server a moment to recognize the disconnect
        tokio::time::sleep(Duration::from_secs(10)).await;

        // 5. Verify the client is no longer listed
        let res: Value = client
            .get(format!("http://127.0.0.1:{}/api/ssh/clients", setup.http_port))
            .send()
            .await?
            .json()
            .await?;
        assert!(res.as_object().unwrap().is_empty());

        setup.server_handle.abort();
        Ok(())
    })
    .await
}
