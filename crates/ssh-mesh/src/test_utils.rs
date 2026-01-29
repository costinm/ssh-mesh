use anyhow::Result;
use once_cell::sync::Lazy;
use russh::keys::PublicKeyBase64;
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;

static INIT_LOGGING: Lazy<()> = Lazy::new(|| {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("trace"))
        .with_level(true)
        .try_init();
});

pub fn find_free_port() -> Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

pub struct TestSetup {
    pub temp_dir: Option<TempDir>,
    pub base_dir: PathBuf,
    pub client_key_path: PathBuf,
    pub ssh_port: u16,
    pub http_port: Option<u16>,
    pub server_handle: tokio::task::JoinHandle<()>,
}

pub async fn setup_test_environment(
    custom_temp_dir: Option<PathBuf>,
    start_http: bool,
) -> Result<TestSetup> {
    Lazy::force(&INIT_LOGGING);

    let (temp_dir, base_dir) = if let Some(path) = custom_temp_dir {
        (None, path)
    } else {
        let td = tempfile::Builder::new().prefix("ssh-mesh-test").tempdir()?;
        let path = td.path().to_path_buf();
        (Some(td), path)
    };

    let client_key_path = base_dir.join("id_ecdsa");

    // Unified key management via auth module
    let key = crate::auth::load_or_generate_key(&base_dir);

    if temp_dir.is_some() {
        // For temporary test setups, we need to populate authorized_keys
        // so the test client (using the newly generated key) can connect to the server.
        let public_key_line = format!("ecdsa-sha2-nistp256 {} test-key\n", key.public_key_base64());
        std::fs::write(base_dir.join("authorized_keys"), public_key_line.as_bytes())?;
    }

    let mut http_port = None;
    let mut http_listener = None;
    if start_http {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
        http_port = Some(listener.local_addr()?.port());
        http_listener = Some(listener);
    }

    let mut ssh_port = find_free_port()?;
    if let Some(h_port) = http_port {
        while ssh_port == h_port {
            tokio::time::sleep(Duration::from_millis(10)).await;
            ssh_port = find_free_port()?;
        }
    }

    let server_base_dir = base_dir.clone();
    let server_handle = tokio::spawn(async move {
        println!(
            "Starting SshServer for tests at base_dir: {:?}",
            server_base_dir
        );
        let ssh_server = std::sync::Arc::new(crate::SshServer::new(0, None, server_base_dir));

        if start_http {
            let app_state = crate::AppState {
                ssh_server: ssh_server.clone(),
                ws_server: std::sync::Arc::new(ws::WSServer::new()),
                target_http_address: std::env::var("HTTP_PORT").ok(),
            };

            let ssh_server_clone = ssh_server.clone();
            tokio::spawn(async move {
                let config = ssh_server_clone.get_config();
                println!("Starting real SSH server on port {}", ssh_port);
                if let Err(e) =
                    crate::run_ssh_server(ssh_port, config, (*ssh_server_clone).clone()).await
                {
                    eprintln!("SSH server failed: {}", e);
                }
            });

            let app = crate::handlers::app(app_state);
            if let Some(listener) = http_listener {
                let addr = listener.local_addr().unwrap();
                println!("Starting Axum server on {}", addr);
                match axum::serve(listener, app.into_make_service()).await {
                    Ok(_) => println!("Axum server finished"),
                    Err(e) => eprintln!("Axum server failed: {}", e),
                }
            }
        } else {
            let config = ssh_server.get_config();
            if let Err(e) = crate::run_ssh_server(ssh_port, config, (*ssh_server).clone()).await {
                eprintln!("SSH server failed: {}", e);
            }
        }
    });

    tokio::time::sleep(Duration::from_secs(2)).await;

    Ok(TestSetup {
        temp_dir,
        base_dir,
        client_key_path,
        ssh_port,
        http_port,
        server_handle,
    })
}
