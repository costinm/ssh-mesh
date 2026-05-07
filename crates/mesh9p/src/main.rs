//! 9P filesystem server.
//!
//! Serves the unpfs (Unix Passthrough Filesystem) using the 9P2000.L protocol.
//! Can serve over stdin/stdout (default) or listen on a Unix Domain Socket.
//!
//! Usage:
//!   unpfs [root_directory] [--listen <path>]
//!
//! If no root directory is specified, defaults to current directory (".").

use clap::Parser;
use mesh9p::unpfs::Unpfs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "unpfs", about = "9P2000.L filesystem server")]
struct Args {
    /// Root directory to serve
    #[arg(default_value = ".")]
    root: PathBuf,

    /// Unix Domain Socket suffix (appended to ~/.run/unpfs/) or abstract name (if starts with _)
    #[arg(short, long)]
    listen: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();

    let root = args
        .root
        .canonicalize()
        .unwrap_or_else(|_| args.root.clone());

    let fs = Unpfs {
        realroot: root.clone(),
    };

    if let Ok(fd_str) = std::env::var("LISTEN_FD") {
        if let Ok(fd) = fd_str.parse::<i32>() {
            tracing::info!("unpfs: serving {:?} from LISTEN_FD {}", root, fd);

            use std::os::unix::io::FromRawFd;

            // Try detecting if it's a TCP or Unix socket by calling local_addr()
            let is_tcp = {
                let tcp = unsafe { std::net::TcpListener::from_raw_fd(fd) };
                let is_tcp = tcp.local_addr().is_ok();
                std::mem::forget(tcp);
                is_tcp
            };

            if is_tcp {
                let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
                if let Err(e) = listener.set_nonblocking(true) {
                    tracing::warn!("Failed to set non-blocking on LISTEN_FD TCP socket: {}", e);
                }
                let listener = tokio::net::TcpListener::from_std(listener)?;

                loop {
                    let (stream, peer) = listener.accept().await?;
                    tracing::info!("accepted TCP connection from {:?}", peer);
                    let fs = fs.clone();
                    tokio::spawn(async move {
                        let (readhalf, writehalf) = stream.into_split();
                        if let Err(e) = mesh9p::srv::dispatch(fs, readhalf, writehalf).await {
                            tracing::error!("Error: {:?}", e);
                        }
                    });
                }
            } else {
                let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
                if let Err(e) = listener.set_nonblocking(true) {
                    tracing::warn!("Failed to set non-blocking on LISTEN_FD Unix socket: {}", e);
                }
                let listener = tokio::net::UnixListener::from_std(listener)?;

                loop {
                    let (stream, peer) = listener.accept().await?;
                    tracing::info!("accepted UDS connection from {:?}", peer);
                    let fs = fs.clone();
                    tokio::spawn(async move {
                        let (readhalf, writehalf) = tokio::io::split(stream);
                        if let Err(e) = mesh9p::srv::dispatch(fs, readhalf, writehalf).await {
                            tracing::error!("Error: {:?}", e);
                        }
                    });
                }
            }
        }
    }

    if let Some(listen_str) = args.listen {
        let path_str = if listen_str.starts_with('_') {
            listen_str.replacen('_', "\0", 1)
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
            let dir = format!("{}/.run/unpfs", home);
            let _ = std::fs::create_dir_all(&dir);
            format!("{}/{}", dir, listen_str)
        };

        tracing::info!("unpfs: serving {:?} on UDS {:?}", root, path_str);

        // Remove existing socket file if it exists and it's not an abstract socket
        if !path_str.starts_with('\0') {
            let path = std::path::Path::new(&path_str);
            if path.exists() {
                std::fs::remove_file(path)?;
            }
        }

        mesh9p::srv::srv_async_unix(fs, &path_str).await?;
    } else {
        tracing::info!("unpfs: serving {:?} over stdin/stdout", root);
        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();
        mesh9p::srv::dispatch(fs, stdin, stdout).await?;
    }

    Ok(())
}
