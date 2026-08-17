//! Generic mesh command client.
//!
//! The binary intentionally has no `mesh-init`, SSH implementation, or HTTP
//! stack dependency. Explicit RPC endpoints use mesh baseline codecs; a bare
//! host falls back to the system OpenSSH client, while `mux://` uses the shared
//! local ControlMaster implementation.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use mesh::cbor::{decode_record, decode_stream_frame, encode_record, encode_stream_frame};
use mesh::mux_client::MuxClient;
use mesh::tagged::{NameOrTag, TaggedCatalog, TaggedRecord};
use serde_json::{Map, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::time::{Duration, timeout};

#[derive(Clone, Parser, Debug)]
#[command(name = "mesh", about = "Generic mesh and SSH-compatible client")]
struct Cli {
    /// OpenSSH ControlMaster socket. Selects native mux mode.
    #[arg(short = 'S')]
    control_path: Option<PathBuf>,
    /// Local port forward, using the OpenSSH `-L` spelling.
    #[arg(short = 'L')]
    local_forward: Vec<String>,
    /// Remote port forward, using the OpenSSH `-R` spelling.
    #[arg(short = 'R')]
    remote_forward: Vec<String>,
    /// Standard input/output forward, using the OpenSSH `-W` spelling.
    #[arg(short = 'W')]
    stdio_forward: Option<String>,
    /// Request a terminal for a mux session.
    #[arg(short = 't')]
    tty: bool,
    /// Do not start a command after establishing forwards.
    #[arg(short = 'N')]
    no_command: bool,
    /// Maximum time to wait for an RPC response or streaming subscription.
    #[arg(long, default_value_t = 9)]
    timeout_sec: u64,
    /// Destination endpoint, host, service name, or URI.
    destination: String,
    /// SSH command for a host/mux endpoint, or COMPONENT METHOD arguments for
    /// an explicit RPC endpoint.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    arguments: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DestinationFormat {
    Json,
    Cbor,
    Text,
}

impl DestinationFormat {
    fn from_env() -> Result<Self> {
        match std::env::var("MESH_DEST_FORMAT")
            .unwrap_or_else(|_| "auto".to_owned())
            .as_str()
        {
            "auto" | "json" => Ok(Self::Json),
            "cbor" => Ok(Self::Cbor),
            "text" => Ok(Self::Text),
            "mux" => anyhow::bail!("MESH_DEST_FORMAT=mux selects a transport, not an RPC codec"),
            value => anyhow::bail!("unsupported MESH_DEST_FORMAT={value}"),
        }
    }
}

#[derive(Debug)]
enum ForwardSpec {
    Tcp {
        listen_host: String,
        listen_port: u32,
        connect_host: String,
        connect_port: u32,
    },
    Unix {
        listen_path: String,
        connect_path: String,
    },
}

fn parse_forward(value: &str, remote: bool) -> Result<ForwardSpec> {
    if value.starts_with('/')
        && let Some((listen_path, connect_path)) = value.split_once(':')
    {
        return Ok(ForwardSpec::Unix {
            listen_path: listen_path.to_owned(),
            connect_path: connect_path.to_owned(),
        });
    }
    let parts: Vec<_> = value.split(':').collect();
    let (listen_host, listen_port, connect_host, connect_port) = match parts.as_slice() {
        [port, host, target_port] => (
            if remote { "0.0.0.0" } else { "127.0.0.1" },
            port.parse()?,
            *host,
            target_port.parse()?,
        ),
        [bind, port, host, target_port] => (*bind, port.parse()?, *host, target_port.parse()?),
        _ => anyhow::bail!("invalid forward specification {value}"),
    };
    Ok(ForwardSpec::Tcp {
        listen_host: listen_host.to_owned(),
        listen_port,
        connect_host: connect_host.to_owned(),
        connect_port,
    })
}

fn is_rpc_endpoint(destination: &str) -> bool {
    destination.starts_with('/')
        || destination.starts_with("./")
        || destination.starts_with("unix://")
        || destination.starts_with("tcp://")
}

fn unix_path(destination: &str) -> Option<&str> {
    destination.strip_prefix("unix://").or_else(|| {
        (destination.starts_with('/') || destination.starts_with("./")).then_some(destination)
    })
}

fn tcp_address(destination: &str) -> Option<&str> {
    destination.strip_prefix("tcp://")
}

/// Resolve a logical service name through the common mesh-init service format.
///
/// `MESH_SERVICE_DIR` may name either one TOML file or a directory containing
/// `<service>.toml`. This is deliberately separate from the old SSH config
/// parser: the CLI only understands common `mesh::config` service definitions.
fn service_address(service: &str) -> Result<Option<String>> {
    if let Some((section, _)) = service_mesh_config(service)? {
        return Ok(Some(section.address.unwrap_or_else(|| {
            format!(
                "unix://{}",
                mesh::paths::AppPaths::for_app(service)
                    .mesh_socket()
                    .display()
            )
        })));
    }
    if let Some((endpoint, namespace)) = service.split_once('.')
        && !endpoint.is_empty()
        && !namespace.is_empty()
        && !endpoint.contains('.')
        && !namespace.contains('.')
        && endpoint
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && namespace
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Ok(Some(format!(
            "unix:///run/mesh/{namespace}/{endpoint}.sock"
        )));
    }
    // A conventional mesh-init service without a [Mesh] section still owns
    // the standard per-service control socket.  This lets `mesh lmesh ...`
    // select the local service without conflating it with an SSH host.
    if service_config_candidates(service)
        .into_iter()
        .any(|path| path.is_file())
    {
        return Ok(Some(format!("unix:///run/mesh/{service}/mesh.sock")));
    }
    if std::env::var_os("MESH_SERVICE_DIR").is_none() {
        let default = match service {
            "mesh-init" => "/run/mesh/mesh-init/mesh.sock",
            _ => return Ok(None),
        };
        return Ok(Some(format!("unix://{default}")));
    }
    Ok(None)
}

fn service_config_candidates(service: &str) -> Vec<PathBuf> {
    if let Some(source) = std::env::var_os("MESH_SERVICE_DIR").map(PathBuf::from) {
        return vec![if source.is_dir() {
            source.join(format!("{service}.toml"))
        } else {
            source
        }];
    }
    vec![
        PathBuf::from(format!("/opt/system/etc/mesh-init/{service}.toml")),
        PathBuf::from(format!("/home/system/etc/mesh-init/{service}.toml")),
        PathBuf::from(format!("etc/mesh-init/{service}.toml")),
    ]
}

fn service_mesh_config(service: &str) -> Result<Option<(mesh::config::MeshSection, PathBuf)>> {
    for path in service_config_candidates(service).into_iter().rev() {
        if !path.is_file() {
            continue;
        }
        let config = mesh::config::parse_service(
            &std::fs::read_to_string(&path)
                .with_context(|| format!("read service definition {}", path.display()))?,
            Some(service),
        )
        .with_context(|| format!("parse service definition {}", path.display()))?;
        if let Some(section) = config.mesh {
            return Ok(Some((section, path)));
        }
    }
    Ok(None)
}

fn tools_path(destination: &str) -> Result<Option<PathBuf>> {
    if let Some(path) = std::env::var_os("MESH_TOOLS") {
        return Ok(Some(PathBuf::from(path)));
    }
    if let Some((section, config_path)) = service_mesh_config(destination)? {
        return Ok(section.tools.map(|tools| {
            let path = PathBuf::from(tools);
            if path.is_absolute() {
                path
            } else {
                config_path.parent().unwrap_or(Path::new(".")).join(path)
            }
        }));
    }
    Ok(None)
}

fn print_local_help(destination: &str, command: Option<&str>) -> Result<()> {
    let path = tools_path(destination)?.with_context(|| {
        format!(
            "no local Tools catalog configured for {destination}; set [Mesh].Tools in its node-local service config"
        )
    })?;
    let value: Value = serde_json::from_str(
        &std::fs::read_to_string(&path)
            .with_context(|| format!("read tools catalog {}", path.display()))?,
    )?;
    let tools = value
        .as_array()
        .or_else(|| value.get("tools").and_then(Value::as_array))
        .context("tools catalog must be an array or contain a tools array")?;
    if let Some(command) = command {
        let tool = tools
            .iter()
            .find(|tool| tool.get("name").and_then(Value::as_str) == Some(command))
            .with_context(|| format!("unknown command {command}"))?;
        let mut stdout = std::io::stdout().lock();
        if let Err(error) = writeln!(stdout, "{}", serde_json::to_string_pretty(tool)?)
            && error.kind() != std::io::ErrorKind::BrokenPipe
        {
            return Err(error.into());
        }
        return Ok(());
    }
    let mut stdout = std::io::stdout().lock();
    for tool in tools {
        let Some(name) = tool.get("name").and_then(Value::as_str) else {
            continue;
        };
        let summary = tool
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .lines()
            .next()
            .unwrap_or_default();
        if let Err(error) = writeln!(stdout, "{name:<20} {summary}") {
            if error.kind() == std::io::ErrorKind::BrokenPipe {
                return Ok(());
            }
            return Err(error.into());
        }
    }
    Ok(())
}

fn text_value(value: &str) -> Value {
    if let Ok(value) = value.parse::<i64>() {
        Value::from(value)
    } else if let Ok(value) = value.parse::<f64>() {
        Value::from(value)
    } else if matches!(value, "true" | "false") {
        Value::Bool(value == "true")
    } else {
        Value::String(value.to_owned())
    }
}

fn catalog() -> Result<Option<TaggedCatalog>> {
    let Ok(path) = std::env::var("MESH_TOOLS") else {
        return Ok(None);
    };
    let contents =
        std::fs::read_to_string(&path).with_context(|| format!("read MESH_TOOLS={path}"))?;
    Ok(Some(TaggedCatalog::from_tools_json(
        &serde_json::from_str(&contents)?,
    )?))
}

fn record(arguments: &[String], catalog: Option<&TaggedCatalog>) -> Result<TaggedRecord> {
    let component = arguments
        .first()
        .context("RPC endpoints require COMPONENT METHOD [options/parameters]")?;
    // Catalog methods are named `component.method`. Preserve that documented
    // dotted spelling while also accepting the older two-word form.
    let (method_name, invocation_args) = if component.contains('.') {
        (component.clone(), arguments[1..].to_vec())
    } else {
        let method = arguments
            .get(1)
            .context("RPC endpoints require COMPONENT METHOD [options/parameters]")?;
        (format!("{component}.{method}"), arguments[2..].to_vec())
    };
    if let Some(catalog) = catalog {
        return catalog.parse_argv(&method_name, &invocation_args);
    }
    let (component, method) = if component.contains('.') {
        component
            .split_once('.')
            .context("dotted RPC method must contain a component and method")?
    } else {
        (
            component.as_str(),
            arguments
                .get(1)
                .context("RPC endpoints require COMPONENT METHOD [options/parameters]")?
                .as_str(),
        )
    };
    let mut env = BTreeMap::new();
    let mut params = Vec::new();
    let mut options = true;
    for value in &invocation_args {
        if options && value == "--" {
            options = false;
        } else if options && value.starts_with('-') {
            let (key, value) = value
                .trim_start_matches('-')
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("option {value} requires =value"))?;
            env.insert(NameOrTag::parse(key), text_value(value));
        } else if options
            && let Some((key, value)) = value.split_once('=')
            && !key.is_empty()
        {
            env.insert(NameOrTag::parse(key), text_value(value));
        } else {
            params.push(text_value(value));
        }
    }
    Ok(TaggedRecord {
        component: NameOrTag::parse(component),
        method: NameOrTag::parse(method),
        id: None,
        params,
        env,
    })
}

fn json_request(record: &TaggedRecord, catalog: Option<&TaggedCatalog>) -> Value {
    if let Some(catalog) = catalog {
        return catalog.to_jsonl(record);
    }
    let mut value = Map::new();
    value.insert(
        "method".to_owned(),
        Value::String(format!(
            "{}.{}",
            record.component.text(),
            record.method.text()
        )),
    );
    for (key, item) in &record.env {
        value.insert(key.text(), item.clone());
    }
    if !record.params.is_empty() {
        value.insert("params".to_owned(), Value::Array(record.params.clone()));
    }
    Value::Object(value)
}

fn text_request(record: &TaggedRecord) -> String {
    let mut values = vec![format!(
        "{}.{}",
        record.component.text(),
        record.method.text()
    )];
    values.extend(
        record
            .env
            .iter()
            // Bare key=value fields are the mesh UDS wire format. The
            // leading-dash spelling belongs to the CLI/catalog parser, not
            // to mesh.sock or lmesh's text protocol.
            .map(|(key, value)| format!("{}={}", key.text(), render_text_value(value))),
    );
    values.extend(record.params.iter().map(render_text_value));
    format!("{}\n", values.join(" "))
}

fn render_text_value(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

async fn rpc<S>(
    stream: S,
    record: TaggedRecord,
    catalog: Option<&TaggedCatalog>,
    format: DestinationFormat,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (read, mut write) = tokio::io::split(stream);
    match format {
        DestinationFormat::Json => {
            write
                .write_all(serde_json::to_string(&json_request(&record, catalog))?.as_bytes())
                .await?;
            write.write_all(b"\n").await?;
        }
        DestinationFormat::Text => write.write_all(text_request(&record).as_bytes()).await?,
        DestinationFormat::Cbor => {
            write
                .write_all(&encode_stream_frame(&encode_record(&record)?)?)
                .await?
        }
    }
    write.flush().await?;
    let is_subscribe = record.method.text().ends_with("subscribe")
        || record.component.text().ends_with("subscribe");
    let mut reader = BufReader::new(read);

    if is_subscribe {
        let mut line = String::new();
        while reader.read_line(&mut line).await? > 0 {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                if trimmed.starts_with('{') || trimmed.starts_with('[') {
                    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
                        println!("{}", serde_json::to_string_pretty(&value)?);
                    } else {
                        println!("{trimmed}");
                    }
                } else {
                    println!("{trimmed}");
                }
            }
            line.clear();
        }
        return Ok(());
    }

    drop(write);
    let first = reader
        .fill_buf()
        .await?
        .first()
        .copied()
        .context("empty RPC response")?;
    if first == 0 {
        let mut header = [0_u8; 4];
        reader.read_exact(&mut header).await?;
        let len = u32::from_be_bytes(header) as usize;
        let mut frame = Vec::with_capacity(len + 4);
        frame.extend_from_slice(&header);
        frame.resize(len + 4, 0);
        reader.read_exact(&mut frame[4..]).await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json_request(
                &decode_record(decode_stream_frame(&frame)?)?,
                catalog
            ))?
        );
    } else {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim_start().starts_with('{') || line.trim_start().starts_with('[') {
            let value: Value = serde_json::from_str(line.trim())?;
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            print!("{line}");
        }
    }
    Ok(())
}

async fn rpc_destination(cli: &Cli) -> Result<()> {
    if !cli.local_forward.is_empty()
        || !cli.remote_forward.is_empty()
        || cli.stdio_forward.is_some()
        || cli.no_command
    {
        anyhow::bail!("SSH forwarding flags require a session/mux endpoint");
    }
    if cli.arguments.is_empty() {
        return match DestinationFormat::from_env()? {
            DestinationFormat::Json => interactive_rpc(connect_rpc(&cli.destination).await?).await,
            DestinationFormat::Cbor => interactive_rpc(connect_rpc(&cli.destination).await?).await,
            DestinationFormat::Text => interactive_rpc(connect_rpc(&cli.destination).await?).await,
        };
    }
    let catalog = catalog()?;
    let record = record(&cli.arguments, catalog.as_ref())?;
    let format = DestinationFormat::from_env()?;
    let stream = connect_rpc(&cli.destination).await?;
    timeout(
        Duration::from_secs(cli.timeout_sec),
        rpc(stream, record, catalog.as_ref(), format),
    )
    .await
    .context("mesh RPC timed out")??;
    Ok(())
}

async fn connect_rpc(destination: &str) -> Result<Box<dyn AsyncReadWrite>> {
    if let Some(path) = unix_path(destination) {
        return Ok(Box::new(tokio::net::UnixStream::connect(path).await?));
    }
    if let Some(address) = tcp_address(destination) {
        return Ok(Box::new(tokio::net::TcpStream::connect(address).await?));
    }
    unreachable!()
}

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

async fn interactive_rpc(stream: Box<dyn AsyncReadWrite>) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut output = Box::pin(tokio::io::copy(&mut reader, &mut stdout));
    let input_result = {
        let mut input = Box::pin(tokio::io::copy(&mut stdin, &mut writer));
        tokio::select! {
            result = &mut input => Some(result?),
            result = &mut output => {
                result?;
                None
            }
        }
    };
    if input_result.is_some() {
        writer.shutdown().await?;
        output.await?;
    }
    Ok(())
}

async fn mux_destination(cli: &Cli, path: PathBuf) -> Result<()> {
    let mut client = MuxClient::connect(&path).await?;
    for value in &cli.local_forward {
        match parse_forward(value, false)? {
            ForwardSpec::Tcp {
                listen_host,
                listen_port,
                connect_host,
                connect_port,
            } => {
                client
                    .open_local_forward(&listen_host, listen_port, &connect_host, connect_port)
                    .await?;
            }
            ForwardSpec::Unix {
                listen_path,
                connect_path,
            } => {
                client
                    .open_local_forward(&listen_path, u32::MAX - 1, &connect_path, u32::MAX - 1)
                    .await?;
            }
        }
    }
    for value in &cli.remote_forward {
        match parse_forward(value, true)? {
            ForwardSpec::Tcp {
                listen_host,
                listen_port,
                connect_host,
                connect_port,
            } => {
                client
                    .open_remote_forward(&listen_host, listen_port, &connect_host, connect_port)
                    .await?;
            }
            ForwardSpec::Unix {
                listen_path,
                connect_path,
            } => {
                client
                    .open_remote_forward(&listen_path, u32::MAX - 1, &connect_path, u32::MAX - 1)
                    .await?;
            }
        }
    }
    if let Some(value) = &cli.stdio_forward {
        let (host, port) = value.split_once(':').context("-W expects host:port")?;
        client.open_stdio_forward(host, port.parse()?).await?;
        return Ok(());
    }
    if cli.no_command {
        return Ok(());
    }
    let command = cli.arguments.join(" ");
    let (_, exit_code) = client
        .new_session(
            &command,
            cli.tty || command.is_empty(),
            std::io::stdin().as_raw_fd(),
            std::io::stdout().as_raw_fd(),
            std::io::stderr().as_raw_fd(),
        )
        .await?;
    std::process::exit(exit_code as i32);
}

fn external_ssh() -> Result<()> {
    let binary = std::env::var_os("MESH_SSH_COMMAND").unwrap_or_else(|| "/usr/bin/ssh".into());
    let status = std::process::Command::new(&binary)
        .args(std::env::args_os().skip(1))
        .status()
        .with_context(|| format!("run external OpenSSH {:?}", binary))?;
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bare_named_rpc_argument_is_a_top_level_field() {
        let arguments = vec![
            "mesh-init".to_owned(),
            "stop".to_owned(),
            "name=demo".to_owned(),
        ];
        let record = record(&arguments, None).unwrap();
        assert_eq!(
            json_request(&record, None),
            json!({"method": "mesh-init.stop", "name": "demo"})
        );
    }

    #[test]
    fn dotted_rpc_method_preserves_named_fields() {
        let arguments = vec![
            "esp.serial.command".to_owned(),
            "port=lora2".to_owned(),
            "command=status".to_owned(),
        ];
        let record = record(&arguments, None).unwrap();
        assert_eq!(record.component.text(), "esp");
        assert_eq!(record.method.text(), "serial.command");
        assert_eq!(
            json_request(&record, None),
            json!({"method": "esp.serial.command", "port": "lora2", "command": "status"})
        );
    }

    #[test]
    fn dotted_rpc_method_accepts_no_parameters() {
        let arguments = vec!["usb.serial.forward.list".to_owned()];
        let record = record(&arguments, None).unwrap();
        assert_eq!(
            json_request(&record, None),
            json!({"method": "usb.serial.forward.list"})
        );
    }

    #[test]
    fn text_request_uses_mesh_wire_fields_without_cli_dashes() {
        let arguments = vec![
            "esp.serial.command".to_owned(),
            "port=lora3".to_owned(),
            "command=status".to_owned(),
        ];
        let record = record(&arguments, None).unwrap();
        assert_eq!(
            text_request(&record),
            "esp.serial.command command=status port=lora3\n"
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut cli = Cli::parse();
    if !is_rpc_endpoint(&cli.destination)
        && cli.arguments.first().map(String::as_str) == Some("help")
    {
        return print_local_help(&cli.destination, cli.arguments.get(1).map(String::as_str));
    }
    if !is_rpc_endpoint(&cli.destination)
        && !cli.destination.starts_with("mux://")
        && let Some(address) = service_address(&cli.destination)?
    {
        // The logical destination selects a service endpoint.  RPC components
        // remain command arguments, so a catalog-backed call reads naturally
        // as `mesh lmesh esp serial.command ...`.
        cli.destination = address;
    }
    if is_rpc_endpoint(&cli.destination) {
        return rpc_destination(&cli).await;
    }
    if let Some(path) = cli.destination.strip_prefix("mux://") {
        return mux_destination(&cli, PathBuf::from(path)).await;
    }
    if let Some(path) = &cli.control_path {
        return mux_destination(&cli, path.clone()).await;
    }
    external_ssh()
}
