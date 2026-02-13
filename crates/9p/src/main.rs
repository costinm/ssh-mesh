//! 9P filesystem server over stdin/stdout.
//!
//! Serves the unpfs (Unix Passthrough Filesystem) using the 9P2000.L protocol
//! over stdin/stdout, suitable for use as an SSH subsystem or ForceCommand.
//!
//! Usage:
//!   unpfs [root_directory]
//!
//! If no root directory is specified, defaults to "/".

use clap::Parser;
use rs9p::unpfs::Unpfs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "unpfs", about = "9P2000.L filesystem server over stdin/stdout")]
struct Args {
    /// Root directory to serve
    #[arg(default_value = "/")]
    root: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();

    let root = args.root.canonicalize().unwrap_or_else(|_| args.root.clone());

    tracing::info!("unpfs: serving {:?} over stdin/stdout", root);

    let fs = Unpfs {
        realroot: root,
    };

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    rs9p::srv::dispatch(fs, stdin, stdout).await?;

    Ok(())
}
