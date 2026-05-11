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

    let mut listener = mesh::server::MeshListener::new("mesh9p", args.listen.as_deref())?;

    tracing::info!("unpfs: serving {:?} via MeshListener", root);

    while let Some(stream) = listener.accept().await? {
        let fs = fs.clone();
        tokio::spawn(async move {
            let (readhalf, writehalf) = tokio::io::split(stream);
            if let Err(e) = mesh9p::srv::dispatch(fs, readhalf, writehalf).await {
                tracing::error!("Error serving 9p connection: {:?}", e);
            }
        });
    }

    Ok(())
}
