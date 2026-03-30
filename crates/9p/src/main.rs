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
use fsd::unpfs::Unpfs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "unpfs", about = "9P2000.L filesystem server")]
struct Args {
    /// Root directory to serve
    #[arg(default_value = ".")]
    root: PathBuf,

    /// Unix Domain Socket path to listen on
    #[arg(short, long)]
    listen: Option<PathBuf>,
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

    if let Some(path) = args.listen {
        tracing::info!("unpfs: serving {:?} on UDS {:?}", root, path);

        // Remove existing socket file if it exists
        if path.exists() {
            std::fs::remove_file(&path)?;
        }

        fsd::srv::srv_async_unix(fs, path.to_str().ok_or("Invalid UDS path")?).await?;
    } else {
        tracing::info!("unpfs: serving {:?} over stdin/stdout", root);
        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();
        fsd::srv::dispatch(fs, stdin, stdout).await?;
    }

    Ok(())
}
