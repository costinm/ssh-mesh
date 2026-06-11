use clap::Parser;
use sftp_server::FileSystemHandler;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UnixListener;
use tracing::{error, info};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser)]
#[command(name = "sftp-server", about = "SFTP server over stdin/stdout or UDS")]
struct Args {
    /// Root directory to serve
    #[arg(default_value = ".")]
    root: PathBuf,

    /// Unix Domain Socket path to listen on
    #[arg(short, long)]
    listen: Option<PathBuf>,
}

struct StdioStream {
    stdin: tokio::io::Stdin,
    stdout: tokio::io::Stdout,
}

impl AsyncRead for StdioStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdin).poll_read(cx, buf)
    }
}

impl AsyncWrite for StdioStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stdout).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdout).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdout).poll_shutdown(cx)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_telemetry();

    let args = Args::parse();

    let root = if args.root.exists() {
        args.root.canonicalize().unwrap_or(args.root)
    } else {
        args.root
    };

    if let Some(path) = args.listen {
        info!("sftp-server: listening on UDS {:?}", path);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        let listener = UnixListener::bind(&path)?;

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    info!("Accepted UDS connection");
                    let handler = FileSystemHandler::new(root.clone());
                    tokio::spawn(async move {
                        russh_sftp::server::run(stream, handler).await;
                    });
                }
                Err(e) => {
                    error!("Error accepting UDS connection: {}", e);
                }
            }
        }
    } else {
        info!("sftp-server: serving {:?} over stdin/stdout", root);
        let stream = StdioStream {
            stdin: tokio::io::stdin(),
            stdout: tokio::io::stdout(),
        };
        let handler = FileSystemHandler::new(root);
        russh_sftp::server::run(stream, handler).await;
    }

    Ok(())
}

fn init_telemetry() {
    let filter = tracing_subscriber::EnvFilter::from_default_env();
    let log_path = std::env::var("MESH_LOG_FILE").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/.run/sftp-server/sftp-server.log", home)
    });

    if let Some(parent) = std::path::Path::new(&log_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    if let Ok(file) = OpenOptions::new().create(true).append(true).open(&log_path) {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(move || file.try_clone().expect("clone sftp-server log file"))
            .init();
    } else {
        tracing_subscriber::registry().with(filter).init();
    }
}
