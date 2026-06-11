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
use std::fs::OpenOptions;
use std::path::PathBuf;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

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
    init_telemetry();

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

fn init_telemetry() {
    let filter = tracing_subscriber::EnvFilter::from_default_env();
    let log_path = std::env::var("MESH_LOG_FILE").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/.run/mesh9p/mesh9p.log", home)
    });

    if let Some(parent) = std::path::Path::new(&log_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    if let Ok(file) = OpenOptions::new().create(true).append(true).open(&log_path) {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(move || file.try_clone().expect("clone mesh9p log file"))
            .init();
    } else {
        tracing_subscriber::registry().with(filter).init();
    }
}
