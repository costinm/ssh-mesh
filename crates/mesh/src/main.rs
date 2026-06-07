//! mesh — generic UDS control client for mesh applications.
//!
//! Locates the UDS socket for an application and sends JSON-lines requests.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use mesh::protocol::{Request, Response};

#[derive(Parser, Debug)]
#[clap(name = "mesh", version = "0.1.0")]
struct Args {
    /// Application name (used to locate the UDS socket).
    app: String,

    /// Subcommand (the request method).
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Start a service (mesh-init specific).
    Start {
        name: String,
        /// Additional arguments.
        #[clap(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Stop a service.
    Stop {
        name: String,
        /// Signal (default: 15).
        #[clap(long)]
        signal: Option<i32>,
    },
    /// Freeze a service.
    Freeze { name: String },
    /// Unfreeze a service.
    Unfreeze { name: String },
    /// Status of a service or all services.
    Status { name: Option<String> },
    /// Shutdown the daemon.
    Shutdown,
    /// Reload configurations.
    Reload,
    /// Send a raw JSON request.
    Raw {
        method: String,
        #[clap(trailing_var_arg = true)]
        params: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let socket_path = get_socket_path(&args.app);

    let request = match args.command {
        Command::Start { name, args } => Request::Start {
            name,
            args,
            env: HashMap::new(),
            context: None,
        },
        Command::Stop { name, signal } => Request::Stop { name, signal },
        Command::Freeze { name } => Request::Freeze { name },
        Command::Unfreeze { name } => Request::Unfreeze { name },
        Command::Status { name } => Request::Status { name },
        Command::Shutdown => Request::Shutdown,
        Command::Reload => Request::Reload,
        Command::Raw { method, params } => {
            // Very basic raw command construction
            let mut map = serde_json::Map::new();
            map.insert("method".to_string(), json!(method));
            if !params.is_empty() {
                map.insert("params".to_string(), json!(params));
            }
            serde_json::from_value(serde_json::Value::Object(map))?
        }
    };

    let response = send_request(&socket_path, &request).await?;

    if response.success {
        if let Some(data) = &response.data {
            println!("{}", serde_json::to_string_pretty(data)?);
        } else {
            println!("OK");
        }
    } else {
        eprintln!(
            "Error: {}",
            response.error.as_deref().unwrap_or("unknown error")
        );
        std::process::exit(1);
    }

    Ok(())
}

fn get_socket_path(app: &str) -> String {
    let env_prefix = app.to_uppercase().replace("-", "_");
    let env_var = format!("{}_RUN", env_prefix);

    let run_dir = if let Ok(dir) = std::env::var(&env_var) {
        dir
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/.run/{}", home, app)
    };
    format!("{}/control.sock", run_dir)
}

async fn send_request(socket_path: &str, request: &Request) -> Result<Response> {
    let stream = tokio::net::UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("failed to connect to UDS at {}", socket_path))?;
    let (reader, mut writer) = stream.into_split();

    let request_json = serde_json::to_string(request)?;
    writer.write_all(request_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    // Shutdown the write side
    drop(writer);

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    if line.trim().is_empty() {
        return Ok(Response::err("Empty response from server"));
    }

    let response: Response = serde_json::from_str(line.trim())
        .with_context(|| format!("failed to parse response: {}", line))?;
    Ok(response)
}
