use anyhow::Result;
use once_cell::sync::Lazy;
use russh::keys::PublicKeyBase64;
use ssh_key::LineEnding;
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

    pub mock_mesh_init_handle: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl TestSetup {
    pub fn abort_server(&self) {
        let handle = self.mesh_node.server_handle.lock().unwrap();
        if let Some(ref h) = *handle {
            h.abort();
        }
        let mock_handle = self.mock_mesh_init_handle.lock().unwrap();
        if let Some(ref h) = *mock_handle {
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

    // Start mock mesh-init server
    let socket_path = base_dir.join("mesh-init-control.sock");
    let mock_mesh_init_handle = start_mock_mesh_init(socket_path, base_dir.clone());

    let client_key_path = base_dir.join("id_ecdsa");

    let key = crate::auth::load_or_generate_keys_save(&base_dir);

    // Re-save the key in OpenSSH format so the system SSH client can read it.
    // load_or_generate_keys_save saves in PKCS#8 PEM which OpenSSH client doesn't support.
    let pem_data = std::fs::read_to_string(&client_key_path)?;
    if let Ok(ssh_key) = crate::auth::ssh_key_from_pkcs8_pem(&pem_data) {
        let openssh_pem = ssh_key.to_openssh(LineEnding::LF)?;
        std::fs::write(&client_key_path, openssh_pem.as_bytes())?;
    }

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
            Ok(())
        } else {
            let config = mesh_node_clone.get_config();
            crate::run_ssh_server(ssh_port, config, (*mesh_node_clone).clone()).await
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
        mock_mesh_init_handle: std::sync::Mutex::new(Some(mock_mesh_init_handle)),
    })
}

pub fn start_mock_mesh_init(socket_path: PathBuf, base_dir: PathBuf) -> tokio::task::JoinHandle<()> {
    // 1. Create a home directory for the test users
    let _ = std::fs::create_dir_all(base_dir.join("alice"));
    let _ = std::fs::create_dir_all(base_dir.join("testuser"));
    let _ = std::fs::create_dir_all(base_dir.join("system"));

    // 2. Set environment variables
    unsafe {
        std::env::set_var("SSH_MESH_HOME_ROOT", base_dir.to_str().unwrap());
        std::env::set_var("MESH_INIT_SOCK", socket_path.to_str().unwrap());
    }

    // 3. Remove any stale UDS socket
    let _ = std::fs::remove_file(&socket_path);

    tokio::spawn(async move {
        let listener = match tokio::net::UnixListener::bind(&socket_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Mock mesh-init failed to bind: {}", e);
                return;
            }
        };

        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                // Read the JSON request line
                use tokio::io::AsyncBufReadExt;
                let mut reader = tokio::io::BufReader::new(&mut stream);
                let mut line = String::new();
                if reader.read_line(&mut line).await.is_err() {
                    return;
                }

                // Parse the request
                let val: serde_json::Value = serde_json::from_str(&line).unwrap_or(serde_json::Value::Null);
                let command_opt = val.get("command").and_then(|c| c.as_str()).map(|s| s.to_string());

                // Receive the file descriptor
                let mut std_stream = match stream.into_std() {
                    Ok(s) => s,
                    Err(_) => return,
                };
                if std_stream.set_nonblocking(false).is_err() {
                    return;
                }

                use nix::sys::socket::{recvmsg, MsgFlags, ControlMessageOwned};
                use nix::cmsg_space;
                use std::io::IoSliceMut;
                use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

                let mut buf = [0u8; 1];
                let mut iov = [IoSliceMut::new(&mut buf)];
                let mut cmsgspace = cmsg_space!([std::os::fd::RawFd; 1]);
                let msg = match recvmsg::<()>(
                    std_stream.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsgspace),
                    MsgFlags::empty(),
                ) {
                    Ok(m) => m,
                    Err(_) => return,
                };

                let mut passed_fd = None;
                for cmsg in msg.cmsgs().unwrap() {
                    if let ControlMessageOwned::ScmRights(fds) = cmsg {
                        if let Some(fd) = fds.first() {
                            passed_fd = Some(unsafe { OwnedFd::from_raw_fd(*fd) });
                        }
                    }
                }

                let fd = match passed_fd {
                    Some(f) => f,
                    None => return,
                };

                // Spawn the command
                let cmd_str = command_opt.unwrap_or_else(|| "printf ok".to_string());

                let mut child = match std::process::Command::new("/bin/sh")
                    .args(&["-c", &cmd_str])
                    .stdin(std::process::Stdio::from(fd.try_clone().unwrap()))
                    .stdout(std::process::Stdio::from(fd.try_clone().unwrap()))
                    .stderr(std::process::Stdio::from(fd))
                    .spawn() {
                        Ok(c) => c,
                        Err(_) => return,
                    };

                let pid = child.id();

                let response = serde_json::json!({
                    "success": true,
                    "data": {
                        "pid": pid,
                        "terminal_id": "term-0"
                    }
                });

                let response_str = format!("{}\n", response.to_string());
                use std::io::Write;
                let _ = std_stream.write_all(response_str.as_bytes());
                let _ = std_stream.flush();

                tokio::task::spawn_blocking(move || {
                    let _ = child.wait();
                });
            });
        }
    })
}
