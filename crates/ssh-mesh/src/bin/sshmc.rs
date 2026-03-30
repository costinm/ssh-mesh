//! sshmc — CLI client for the extended OpenSSH mux protocol.
//!
//! This emulates `ssh -S PATH HOST` - the PATH points to an UDS socket
//! created based on ssh config ControlPath, when ControlMaster is set,
//!
//! Usage:
//!   sshmc example.com
//! Forwards stdin/stdout/stderr to a new shell connection running on example.com
//!
//!   sshmc -L local_port:remote_host:remote_port example.com
//!   sshmc -L local_port:remote_UDS example.com
//!   sshmc -L local_UDS:remote_host:remote_port example.com
//!   sshmc -L local_UDS:remote_UDS example.com
//! Opens a listener on local_port or local_UDS.
//! All accepted connections are forwarded to remote_host:remote_port via example.com.
//! Unlike ssh, the bind address is not supported, localhost is used in all cases.
//! A separate option may be added to support a bind address forwarding and other
//! special local transports (virtio, etc).
//!
//!   sshmc -W dest.com:80 example.com
//! Forwards stdin/stdout to dest.com:80, via example.com. This can be used as ProxyCommand
//! for ProxyJump, `ssh -W '[%h]:%p jump`.
//!   
//!  sshmc -R bind_addr:remote_port:local_host:local_port example.com
//! Opens a listeners on example.com on bind_addr:remote_port. The port is
//! typically 80, 443, 22 - used for multiplexing
//!
//!   sshmc -R remote_uds:local_uds
//!   sshmc -R remote_uds:local_host:local_port
//!   sshmc -R port
//!   sshmc -R remote_port:local_uds
//!
//! The SSH_MUX env will point to the directory for the control sockets, defaulting
//! to  /run/user/${UID}/sshmux
//!
//! The control sockets are named by the hostname ('example.com').
//! The `-S` option can override this and point to a specific file.
use anyhow::{Context, Result};
use clap::Parser;
use http_body_util::Full;
use hyper::Request;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use log::debug;
use nix::unistd;
use serde_json::json;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::UnixStream;
use tokio::time::sleep;

// TODO:
// - add '-f -N' - to put in background or drop stdin (backward compat)
// - if forward + command is passed, exit
// - add option to stop forwarding
// - fix terminal echo and exit in shell

#[derive(Parser, Debug)]
#[command(name = "sshmc", about = "OpenSSH mux protocol client")]
struct Cli {
    /// Path to the mux control socket.
    #[arg(short = 'S', long)]
    socket: Option<PathBuf>,

    /// Local port forward spec: [bind_addr:]port:host:hostport or socket:socket
    #[arg(short = 'L', long)]
    local_forward: Vec<String>,

    /// Remote port forward spec: [bind_addr:]port:host:hostport
    #[arg(short = 'R', long)]
    remote_forward: Vec<String>,

    /// Stdio forwarding: host:port
    #[arg(short = 'W', long)]
    stdio_forward: Option<String>,

    /// Force pseudo-terminal allocation.
    #[arg(short = 't', long)]
    tty: bool,

    /// OpenSSH compatibility - do not execute a remote commands, forwards will
    /// terminate when this process ends. If not set, forwards will be set and the
    /// current process will exit, forwards will outlast it - but not supported by
    /// OpenSSH.
    #[arg(short = 'N', long)]
    no_command: bool,

    /// Destination [user@]hostname
    destination: String,

    /// Command to execute
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

#[derive(Debug)]
enum ForwardSpec {
    Tcp {
        listen_host: String,
        listen_port: u16,
        connect_host: String,
        connect_port: u16,
    },
    Unix {
        listen_path: String,
        connect_path: String,
    },
}

fn parse_forward_spec(s: &str, is_remote: bool) -> Result<ForwardSpec> {
    // Check if it looks like unix socket forwarding: /path/to/socket:/another/path
    if s.starts_with('/')
        && let Some((listen, connect)) = s.split_once(':') {
        return Ok(ForwardSpec::Unix {
            listen_path: listen.to_string(),
            connect_path: connect.to_string(),
        });
    }

    // [bind_addr:]port:host:hostport
    let parts: Vec<&str> = s.split(':').collect();

    let (listen_host, listen_port, connect, connect_port_idx) = if parts.len() == 4 {
        (
            parts[0],
            parts[1].parse::<u16>().context("parsing listen port")?,
            parts[2],
            3,
        )
    } else if parts.len() == 3 {
        // default bind addr
        let default_bind = if is_remote { "0.0.0.0" } else { "localhost" };
        (
            default_bind,
            parts[0].parse::<u16>().context("parsing listen port")?,
            parts[1],
            2,
        )
    } else {
        anyhow::bail!("Invalid forward spec: {}", s);
    };

    let connect_port = parts[connect_port_idx]
        .parse::<u16>()
        .context("parsing connect port")?;

    Ok(ForwardSpec::Tcp {
        listen_host: listen_host.to_string(),
        listen_port,
        connect_host: connect.to_string(),
        connect_port,
    })
}

// Logic to determine socket path
fn resolve_socket_path(cli: &Cli) -> Result<PathBuf> {
    if let Some(path) = &cli.socket {
        return Ok(path.clone());
    }

    let dest = &cli.destination;
    let (user, host) = if let Some((u, h)) = dest.split_once('@') {
        (u.to_string(), h.to_string())
    } else {
        let current_user = std::env::var("USER").unwrap_or_else(|_| "root".to_string());
        (current_user, dest.clone())
    };

    let mux_dir = std::env::var("SSH_MUX")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let uid = unistd::getuid();
            PathBuf::from(format!("/run/user/{}/sshmux", uid))
        });

    let filename = format!("ssh-{}@{}", user, host);
    Ok(mux_dir.join(filename))
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    let socket_path = resolve_socket_path(&cli)?;
    debug!("Connecting to mux socket at {:?}", socket_path);

    let mut client = match ssh_mesh::sshmuxc::MuxClient::connect(&socket_path).await {
        Ok(c) => c,
        Err(e) => {
            debug!("Failed to connect to mux, trying UDS HTTP fallback: {}", e);

            let base_dir = std::env::var("SSH_BASEDIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    let mut path = std::env::var("HOME")
                        .map(PathBuf::from)
                        .unwrap_or_else(|_| PathBuf::from("/tmp"));
                    path.push(".ssh");
                    path
                });
            let control_uds_path = base_dir.join("control.sock");

            // Fallback: try to request a connection via HTTP API over UDS
            let (user, host) = if let Some((u, h)) = cli.destination.split_once('@') {
                (u.to_string(), h.to_string())
            } else {
                (
                    std::env::var("USER").unwrap_or_else(|_| "root".to_string()),
                    cli.destination.clone(),
                )
            };

            let json_body = json!({
                "host": host,
                "port": 15022,
                "user": user,
                "server_key": ""
            })
            .to_string();

            let stream = UnixStream::connect(&control_uds_path)
                .await
                .context(format!("Failed to connect to control UDS at {:?}", control_uds_path))?;

            let (mut request_sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .context("HTTP handshake failed")?;

            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    debug!("Error in UDS connection: {}", e);
                }
            });

            let request = Request::builder()
                .uri("/_m/api/sshc/connect")
                .method("POST")
                .header("Host", "localhost")
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(json_body)))
                .context("Failed to build HTTP request")?;

            let response = request_sender
                .send_request(request)
                .await
                .context("Failed to send HTTP request over UDS")?;

            if response.status().is_success() {
                debug!("HTTP connect request successful, waiting for mux socket...");
                // Wait for the mux socket to be created
                let mut maybe_client = None;
                for _ in 0..10 {
                    sleep(Duration::from_millis(500)).await;
                    if let Ok(c) = ssh_mesh::sshmuxc::MuxClient::connect(&socket_path).await {
                        maybe_client = Some(c);
                        break;
                    }
                }
                match maybe_client {
                    Some(c) => c,
                    None => anyhow::bail!("Mux socket failed to appear after HTTP connect request"),
                }
            } else {
                anyhow::bail!(
                    "HTTP fallback failed with status {}: {:?}",
                    response.status(),
                    response.into_body()
                );
            }
        }
    };

    // Handle Local Forwards
    for spec_str in &cli.local_forward {
        let spec = parse_forward_spec(spec_str, false)?;
        match spec {
            ForwardSpec::Tcp {
                listen_host,
                listen_port,
                connect_host,
                connect_port,
            } => {
                let actual = client
                    .open_local_forward(
                        &listen_host,
                        listen_port as u32,
                        &connect_host,
                        connect_port as u32,
                    )
                    .await?;
                if let Some(port) = actual {
                    println!("Allocated port {}", port);
                }
            }
            ForwardSpec::Unix {
                listen_path,
                connect_path,
            } => {
                client
                    .open_local_forward(&listen_path, 0xFFFF_FFFE, &connect_path, 0xFFFF_FFFE)
                    .await?;
                println!(
                    "Local Unix forward established: {} -> {}",
                    listen_path, connect_path
                );
            }
        }
    }

    // Handle Remote Forwards
    for spec_str in &cli.remote_forward {
        let spec = parse_forward_spec(spec_str, true)?;
        match spec {
            ForwardSpec::Tcp {
                listen_host,
                listen_port,
                connect_host,
                connect_port,
            } => {
                let actual = client
                    .open_remote_forward(
                        &listen_host,
                        listen_port as u32,
                        &connect_host,
                        connect_port as u32,
                    )
                    .await?;
                match actual {
                    Some(port) => println!("Remote forward established on port {}", port),
                    None => println!("Remote forward established"),
                }
            }
            ForwardSpec::Unix {
                listen_path,
                connect_path,
            } => {
                client
                    .open_remote_forward(&listen_path, 0xFFFF_FFFE, &connect_path, 0xFFFF_FFFE)
                    .await?;
                println!(
                    "Remote Unix forward established: {} -> {}",
                    listen_path, connect_path
                );
            }
        }
    }

    let has_forwards = !cli.local_forward.is_empty() || !cli.remote_forward.is_empty();

    if has_forwards {
        if cli.no_command {
            if !cli.command.is_empty() {
                anyhow::bail!("Cannot execute command with -N");
            }
            if cli.stdio_forward.is_some() {
                anyhow::bail!("Cannot open stdio forward with -N");
            }
            // Wait for Ctrl-C - '-N' specified.
            tokio::signal::ctrl_c().await?;
            return Ok(());
        } else {
            // Exit immediately
            return Ok(());
        }
    } else if cli.no_command {
        // -N but no forwards
        if !cli.command.is_empty() {
            anyhow::bail!("Cannot execute command with -N");
        }
        if cli.stdio_forward.is_some() {
            anyhow::bail!("Cannot open stdio forward with -N");
        }
        tokio::signal::ctrl_c().await?;
        return Ok(());
    }

    // Handle Stdio Forward (-W)
    if let Some(stdio_spec) = &cli.stdio_forward {
        // host:port
        let (host, port_str) = stdio_spec.split_once(':').context("Invalid -W spec")?;
        let port: u16 = port_str.parse().context("Invalid port in -W")?;

        client.open_stdio_forward(host, port).await?;
        return Ok(());
    }

    // If we have a command or just a shell
    let (cmd, want_tty) = if !cli.command.is_empty() {
        (cli.command.join(" "), cli.tty)
    } else {
        (String::new(), true)
    };

    // We need to pass stdin/stdout/stderr.
    // In `sshmuxc::new_session`, it takes RawFd.
    use std::os::unix::io::AsRawFd;
    let stdin = std::io::stdin().as_raw_fd();
    let stdout = std::io::stdout().as_raw_fd();
    let stderr = std::io::stderr().as_raw_fd();

    let (session_id, exit_code) = client
        .new_session(&cmd, want_tty, stdin, stdout, stderr)
        .await?;
    debug!(
        "Session {} finished with exit code {}",
        session_id, exit_code
    );

    std::process::exit(exit_code as i32);
}
