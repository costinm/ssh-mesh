//! mesh — generic UDS control client for mesh applications.
//!
//! Locates the UDS socket for an application and sends JSON-lines requests.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::IoSlice;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use mesh::protocol::{NamespaceKind, Request, Response};

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
    /// Start a mesh-init terminal/stdio session and bridge it to this process.
    Terminal {
        name: String,
        #[clap(long)]
        home: String,
        #[clap(long)]
        uid: u32,
        #[clap(long)]
        gid: Option<u32>,
        #[clap(long)]
        pty: bool,
        #[clap(long)]
        command: Option<String>,
    },
    /// Register this process's namespace with mesh-init by passing a namespace fd.
    RegisterNamespace {
        name: String,
        /// Namespace kind. Currently only `net` is accepted.
        #[clap(long, default_value = "net")]
        kind: String,
        /// Namespace path to open and pass. Defaults to this process's netns.
        #[clap(long, default_value = "/proc/self/ns/net")]
        path: String,
        /// Stable process PID in the namespace, used by mesh-tun while the fd
        /// attach path is being kept behind mesh-init.
        #[clap(long)]
        target_pid: Option<u32>,
    },
    /// Resize an active terminal session.
    TerminalResize {
        terminal_id: String,
        cols: u32,
        rows: u32,
        #[clap(long, default_value_t = 0)]
        pix_width: u32,
        #[clap(long, default_value_t = 0)]
        pix_height: u32,
    },
    /// Send a control command to an active terminal session.
    TerminalCommand {
        terminal_id: String,
        command: String,
        #[clap(long)]
        data: Option<String>,
    },
    /// Send a raw JSON request.
    Raw {
        method: String,
        #[clap(trailing_var_arg = true)]
        params: Vec<String>,
    },
    /// Send an arbitrary flat JSONL method to an app.
    Jsonl {
        method: String,
        #[clap(long)]
        params: Option<String>,
    },
    /// Send an arbitrary JSON-RPC method to an app.
    Jsonrpc {
        method: String,
        #[clap(long)]
        params: Option<String>,
    },
    /// Print this app's curated tools.json command catalog.
    Tools,
    /// Call a named tool through the app's MCP-compatible JSONL surface.
    Tool {
        name: String,
        #[clap(long)]
        params: Option<String>,
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
        Command::Terminal {
            name,
            home,
            uid,
            gid,
            pty,
            command,
        } => {
            let request = Request::StartTerminal {
                name,
                home,
                uid,
                gid,
                pty,
                env: HashMap::new(),
                context: None,
                command,
                fd_count: None,
            };
            send_terminal_request(&socket_path, &request, pty).await?;
            return Ok(());
        }
        Command::RegisterNamespace {
            name,
            kind,
            path,
            target_pid,
        } => {
            let kind = parse_namespace_kind(&kind)?;
            let fd = std::fs::File::open(&path)
                .with_context(|| format!("failed to open namespace path {}", path))?
                .into();
            let request = Request::RegisterNamespace {
                name,
                kind,
                target_pid,
            };
            let response = send_request_with_fd(&socket_path, &request, &fd)?;
            print_response(&response)?;
            return Ok(());
        }
        Command::TerminalResize {
            terminal_id,
            cols,
            rows,
            pix_width,
            pix_height,
        } => Request::TerminalResize {
            terminal_id,
            col_width: cols,
            row_height: rows,
            pix_width,
            pix_height,
        },
        Command::TerminalCommand {
            terminal_id,
            command,
            data,
        } => Request::TerminalCommand {
            terminal_id,
            command,
            data: match data {
                Some(data) => serde_json::from_str(&data)?,
                None => json!({}),
            },
        },
        Command::Raw { method, params } => {
            // Very basic raw command construction
            let mut map = serde_json::Map::new();
            map.insert("method".to_string(), json!(method));
            if !params.is_empty() {
                map.insert("params".to_string(), json!(params));
            }
            serde_json::from_value(serde_json::Value::Object(map))?
        }
        Command::Jsonl { method, params } => {
            let mut request = serde_json::Map::new();
            request.insert("method".to_string(), json!(method));
            if let Some(params) = params {
                let params: serde_json::Value = serde_json::from_str(&params)?;
                if let Some(params) = params.as_object() {
                    for (key, value) in params {
                        request.insert(key.clone(), value.clone());
                    }
                } else {
                    anyhow::bail!("--params for jsonl must be a JSON object");
                }
            }
            let response = send_value(&socket_path, &serde_json::Value::Object(request)).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
            return Ok(());
        }
        Command::Jsonrpc { method, params } => {
            let params = match params {
                Some(params) => serde_json::from_str(&params)?,
                None => json!({}),
            };
            let request = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            });
            let response = send_value(&socket_path, &request).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
            return Ok(());
        }
        Command::Tools => {
            let tools = read_tools_catalog(&args.app)?;
            println!("{}", serde_json::to_string_pretty(&tools)?);
            return Ok(());
        }
        Command::Tool { name, params } => {
            let params = match params {
                Some(params) => serde_json::from_str(&params)?,
                None => json!({}),
            };
            let request = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": name,
                    "arguments": params,
                },
            });
            let response = send_value(&socket_path, &request).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
            return Ok(());
        }
    };

    let response = send_request(&socket_path, &request).await?;

    print_response(&response)?;

    Ok(())
}

fn parse_namespace_kind(kind: &str) -> Result<NamespaceKind> {
    match kind {
        "net" => Ok(NamespaceKind::Net),
        "user" => Ok(NamespaceKind::User),
        other => anyhow::bail!("unsupported namespace kind: {}", other),
    }
}

fn print_response(response: &Response) -> Result<()> {
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

    if let Ok(dir) = std::env::var(&env_var) {
        return std::path::PathBuf::from(dir)
            .join("control.sock")
            .to_string_lossy()
            .into_owned();
    }

    if app == "mesh-init" {
        mesh::paths::AppPaths::for_app("mesh-init")
            .mesh_socket()
            .to_string_lossy()
            .into_owned()
    } else {
        mesh::paths::AppPaths::for_app(app)
            .mesh_socket()
            .to_string_lossy()
            .into_owned()
    }
}

fn read_tools_catalog(app: &str) -> Result<Value> {
    let paths = mesh::paths::AppPaths::for_app(app);
    let resource_dirs = paths.resource_dirs();
    for dir in &resource_dirs {
        let path = dir.join("tools.json");
        if path.is_file() {
            let data = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            return serde_json::from_str(&data)
                .with_context(|| format!("failed to parse {}", path.display()));
        }
    }
    anyhow::bail!(
        "tools.json not found for {app}; checked {}",
        resource_dirs
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )
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

async fn send_value(socket_path: &str, request: &serde_json::Value) -> Result<serde_json::Value> {
    let stream = tokio::net::UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("failed to connect to UDS at {}", socket_path))?;
    let (reader, mut writer) = stream.into_split();

    writer
        .write_all(serde_json::to_string(request)?.as_bytes())
        .await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    drop(writer);

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    Ok(serde_json::from_str(line.trim())?)
}

async fn send_terminal_request(
    socket_path: &str,
    request: &Request,
    pty: bool,
) -> Result<Response> {
    let (passed_fd, mut stream): (OwnedFd, Box<dyn AsyncDuplex>) = if pty {
        let (master, slave) = open_pty_pair()?;
        let master_file = std::fs::File::from(master);
        (slave, Box::new(tokio::fs::File::from_std(master_file)))
    } else {
        let (child_end, parent_end) = std::os::unix::net::UnixStream::pair()?;
        parent_end.set_nonblocking(true)?;
        (
            child_end.into(),
            Box::new(tokio::net::UnixStream::from_std(parent_end)?),
        )
    };

    let response = send_request_with_fd(socket_path, request, &passed_fd)?;
    print_response(&response)?;
    if response.success {
        let mut stdio = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());
        let _ = tokio::io::copy_bidirectional(&mut stdio, &mut stream).await;
    }
    Ok(response)
}

trait AsyncDuplex: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T> AsyncDuplex for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

fn send_request_with_fd(socket_path: &str, request: &Request, fd: &OwnedFd) -> Result<Response> {
    use std::io::{Read, Write};

    let mut stream = std::os::unix::net::UnixStream::connect(socket_path)
        .with_context(|| format!("failed to connect to UDS at {}", socket_path))?;
    let request_json = serde_json::to_string(request)?;
    stream.write_all(request_json.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let iov = [IoSlice::new(b"F")];
    let fds = [fd.as_raw_fd()];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    sendmsg::<()>(stream.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)?;

    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            break;
        }
        response.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    anyhow::ensure!(!response.is_empty(), "empty response from server");
    let response = String::from_utf8(response)?;
    Ok(serde_json::from_str(response.trim())?)
}

fn open_pty_pair() -> Result<(OwnedFd, OwnedFd)> {
    let mut master = -1;
    let mut slave = -1;
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if rc < 0 {
        anyhow::bail!("openpty failed: {}", std::io::Error::last_os_error());
    }
    // SAFETY: openpty returned owned file descriptors on success.
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };
    Ok((master, slave))
}
