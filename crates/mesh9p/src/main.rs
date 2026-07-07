//! 9P filesystem server.
//!
//! Serves the unpfs (Unix Passthrough Filesystem) using the 9P2000.L protocol.
//! Can serve over stdin/stdout (default) or listen on a Unix Domain Socket.
//!
//! Usage:
//!   mesh9p [export[:mountpoint][:rw] ...] [--listen <path>]
//!
//! If no export is specified, defaults to the current directory mounted read-write at "/".

use clap::Parser;
use mesh9p::unpfs::{Export, Unpfs};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "unpfs", about = "9P2000.L filesystem server")]
struct Args {
    /// Directory export specs: /source[:/mountpoint][:rw]
    #[arg(value_name = "EXPORT")]
    exports: Vec<String>,

    /// Unix Domain Socket suffix (appended to ~/.run/unpfs/) or abstract name (if starts with _)
    #[arg(short, long, conflicts_with = "tcp")]
    listen: Option<String>,

    /// TCP listen address for networked clients, for example 127.0.0.1:15101
    #[arg(long, value_name = "ADDR")]
    tcp: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (_log_buffer, _trace_guard) = mesh::local_trace::init("mesh9p");

    let args = Args::parse();

    let exports = parse_exports(&args.exports)?;
    let fs = Unpfs::new(exports.clone())?;

    for export in &exports {
        tracing::info!(
            "mesh9p: exporting {:?} at {:?} ({})",
            export.source,
            export.mountpoint,
            if export.writable { "rw" } else { "ro" }
        );
    }

    if let Some(addr) = args.tcp {
        tracing::info!("mesh9p: listening on tcp://{}", addr);
        mesh9p::srv::srv_async_tcp(fs, &addr).await?;
        return Ok(());
    }

    let mut listener = mesh::server::MeshListener::new("mesh9p", args.listen.as_deref())?;

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

fn parse_exports(specs: &[String]) -> Result<Vec<Export>, Box<dyn std::error::Error>> {
    let specs = if specs.is_empty() {
        vec![".:/:rw".to_string()]
    } else {
        specs.to_vec()
    };

    specs.into_iter().map(|spec| parse_export(&spec)).collect()
}

fn parse_export(spec: &str) -> Result<Export, Box<dyn std::error::Error>> {
    let mut writable = false;
    let mut fields: Vec<&str> = spec.split(':').collect();
    if fields.last() == Some(&"rw") {
        writable = true;
        fields.pop();
    }

    if fields.is_empty() || fields[0].is_empty() || fields.len() > 2 {
        return Err(format!("invalid export spec: {spec}").into());
    }

    let source = PathBuf::from(fields[0]);
    let source = source.canonicalize().unwrap_or(source);
    let mountpoint = match fields.get(1).copied().filter(|field| !field.is_empty()) {
        Some(path) => PathBuf::from(path),
        None => source.clone(),
    };

    if !mountpoint.is_absolute() {
        return Err(format!("export mountpoint must be absolute: {spec}").into());
    }

    Ok(Export {
        source,
        mountpoint: normalize_mountpoint(&mountpoint),
        writable,
    })
}

fn normalize_mountpoint(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        if let std::path::Component::Normal(name) = component {
            normalized.push(name);
        }
    }
    normalized
}

