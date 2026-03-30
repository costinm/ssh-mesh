use anyhow::Result;
use once_cell::sync::Lazy;
use russh::keys::PublicKeyBase64;
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;

static INIT_LOGGING: Lazy<()> = Lazy::new(|| {
    let _ = tracing_subscriber::fmt()
        //.with_env_filter(tracing_subscriber::EnvFilter::new("trace"))
        .with_level(true)
        .try_init();
});

pub fn find_free_port() -> Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

pub struct TestSetup {
    pub temp_dir: Option<TempDir>,
    // temp file where keys are saved.
    pub client_key_path: PathBuf,

    pub mesh_node: std::sync::Arc<crate::MeshNode>,

    // Convenience fields for backward compat with tests
    pub base_dir: PathBuf,
    pub ssh_port: u16,
    pub http_port: Option<u16>,
}

impl TestSetup {
    pub fn abort_server(&self) {
        let handle = self.mesh_node.server_handle.lock().unwrap();
        if let Some(ref h) = *handle {
            h.abort();
        }
    }
}

// Setup a SSH mesh server on a temp dir. Keys are generated ahead
// of time. Returns a TestSetup with a MeshNode that has ssh_port,
// http_port, and server_handle populated.
pub async fn setup_test_environment(
    _custom_temp_dir: Option<PathBuf>,
    _start_http: bool,
) -> Result<TestSetup> {
    Lazy::force(&INIT_LOGGING);
    let start_http = _start_http;

    let td = tempfile::Builder::new().prefix("ssh-mesh-test").tempdir()?;
    let path = td.path().to_path_buf();
    let (temp_dir, base_dir) = (Some(td), path);

    let client_key_path = base_dir.join("id_ecdsa");

    let key = crate::auth::load_or_generate_keys_save(&base_dir);

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

    let cfg = crate::MeshNodeConfig {
        base_dir: Some(base_dir.clone()),
        ssh_port: Some(ssh_port),
        http_port,
        ..Default::default()
    };
    let mesh_node = std::sync::Arc::new(crate::MeshNode::new(Some(base_dir.clone()), Some(cfg)));

    let mesh_node_clone = mesh_node.clone();
    let server_handle = tokio::spawn(async move {
        println!(
            "Starting MeshNode for tests at base_dir: {:?}",
            mesh_node_clone.base_dir()
        );

        if start_http {
            let app_state = crate::AppState {
                ssh_server: mesh_node_clone.clone(),
                target_http_address: std::env::var("HTTP_PORT").ok(),
                ssh_client_manager: std::sync::Arc::new(crate::sshc::SshClientManager::new(
                    mesh_node_clone.private_key().clone(),
                    Vec::new(),
                    None,
                    None,
                )),
            };

            let mesh_node_for_ssh = mesh_node_clone.clone();
            tokio::spawn(async move {
                let config = mesh_node_for_ssh.get_config();
                println!("Starting real SSH server on port {}", ssh_port);
                if let Err(e) =
                    crate::run_ssh_server(ssh_port, config, (*mesh_node_for_ssh).clone()).await
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
            let config = mesh_node_clone.get_config();
            if let Err(e) =
                crate::run_ssh_server(ssh_port, config, (*mesh_node_clone).clone()).await
            {
                eprintln!("SSH server failed: {}", e);
            }
        }
    });

    // Store server_handle in the mesh_node
    {
        let mut handle_lock = mesh_node.server_handle.lock().unwrap();
        *handle_lock = Some(server_handle);
    }

    Ok(TestSetup {
        temp_dir,
        base_dir,
        client_key_path,
        ssh_port,
        http_port,
        mesh_node,
    })
}
