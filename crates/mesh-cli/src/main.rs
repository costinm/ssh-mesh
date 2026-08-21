//! Generic mesh command client.
//!
//! The binary intentionally has no `mesh-init`, SSH implementation, or HTTP
//! stack dependency. Explicit RPC endpoints use mesh baseline codecs; a bare
//! host falls back to the system OpenSSH client, while `mux://` uses the shared
//! local ControlMaster implementation.

use std::io::Write as _;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use mesh::cbor::{decode_record, decode_stream_frame, encode_record, encode_stream_frame};
use mesh::mux_client::MuxClient;
use mesh::tagged::{TaggedCatalog, TaggedRecord, record_from_argv, to_json};
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
    /// RPC codec: auto (numeric catalog selects tagged-CBOR), cbor, or
    /// json-rpc. Environment `MESH_DEST_FORMAT` supplies the same default.
    #[arg(long, value_parser = ["auto", "cbor", "json-rpc"])]
    rpc_format: Option<String>,
    /// Destination endpoint, host, service name, or URI.
    destination: String,
    /// SSH command for a host/mux endpoint, or COMPONENT METHOD arguments for
    /// an explicit RPC endpoint.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    arguments: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DestinationFormat {
    Cbor,
    JsonRpc,
}

impl DestinationFormat {
    fn from_cli(value: Option<&str>, has_numeric_tags: bool) -> Result<Self> {
        let value = value.map(str::to_owned).unwrap_or_else(|| {
            std::env::var("MESH_DEST_FORMAT").unwrap_or_else(|_| "auto".to_owned())
        });
        Self::from_value(&value, has_numeric_tags)
    }

    fn from_value(value: &str, has_numeric_tags: bool) -> Result<Self> {
        match value {
            // CBOR is intentionally the *tagged* wire format. Without a
            // generated catalog JSON-RPC is less ambiguous than inventing a
            // second, text-named CBOR compatibility dialect.
            "auto" if has_numeric_tags => Ok(Self::Cbor),
            "auto" => Ok(Self::JsonRpc),
            "cbor" if has_numeric_tags => Ok(Self::Cbor),
            "cbor" => anyhow::bail!(
                "MESH_DEST_FORMAT=cbor requires a generated catalog with numeric tags"
            ),
            "json-rpc" => Ok(Self::JsonRpc),
            "mux" => anyhow::bail!("MESH_DEST_FORMAT=mux selects a transport, not an RPC codec"),
            value => {
                anyhow::bail!("unsupported MESH_DEST_FORMAT={value}; use auto, cbor, or json-rpc")
            }
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
    // A packaged service can expose its generated catalog even before a local
    // service-definition file is installed. This is especially useful for the
    // mesh-init bootstrap endpoint. Do not manufacture a schema: absence
    // remains a JSON-RPC selection, exactly like a remote/gateway endpoint.
    Ok(packaged_tools_path(
        mesh::paths::AppPaths::for_app(destination).resource_dirs(),
    ))
}

fn packaged_tools_path(resource_dirs: impl IntoIterator<Item = PathBuf>) -> Option<PathBuf> {
    resource_dirs
        .into_iter()
        .map(|resource_dir| resource_dir.join("tools.json"))
        .find(|candidate| candidate.is_file())
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

fn catalog(destination: &str) -> Result<Option<TaggedCatalog>> {
    let Some(path) = tools_path(destination)? else {
        return Ok(None);
    };
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("read tools catalog {}", path.display()))?;
    Ok(Some(TaggedCatalog::from_tools_json(
        &serde_json::from_str(&contents)?,
    )?))
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
        DestinationFormat::JsonRpc => {
            write
                .write_all(serde_json::to_string(&json_rpc_request(&record, catalog))?.as_bytes())
                .await?;
            write.write_all(b"\n").await?;
        }
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
            serde_json::to_string_pretty(&to_json(
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

/// The explicit JSON gateway spelling is real JSON-RPC, not the older flat
/// JSONL dialect. Its payload comes from the same tagged request as CBOR.
fn json_rpc_request(record: &TaggedRecord, catalog: Option<&TaggedCatalog>) -> Value {
    let mut flat = to_json(record, catalog);
    let object = flat
        .as_object_mut()
        .expect("tagged record JSON adapter always returns an object");
    let method = object
        .remove("method")
        .expect("tagged record JSON adapter always includes method");
    let id = object.remove("id").unwrap_or(Value::Null);
    let mut request = Map::new();
    request.insert("jsonrpc".to_owned(), Value::String("2.0".to_owned()));
    request.insert("id".to_owned(), id);
    request.insert("method".to_owned(), method);
    request.insert("params".to_owned(), Value::Object(std::mem::take(object)));
    Value::Object(request)
}

async fn rpc_destination(cli: &Cli, catalog_destination: &str) -> Result<()> {
    if !cli.local_forward.is_empty()
        || !cli.remote_forward.is_empty()
        || cli.stdio_forward.is_some()
        || cli.no_command
    {
        anyhow::bail!("SSH forwarding flags require a session/mux endpoint");
    }
    if cli.arguments.is_empty() {
        anyhow::bail!(
            "mesh does not provide a text interactive RPC mode; use a command or a manual gateway client"
        );
    }
    // Service-name resolution may already have replaced `cli.destination`
    // with a Unix address. Catalog lookup stays tied to the logical service
    // name so its [Mesh].Tools entry (or packaged generated catalog) remains
    // available after transport resolution.
    let catalog = catalog(catalog_destination)?;
    let mut record = record_from_argv(&cli.arguments, catalog.as_ref())?;
    // CLI invocations are request/reply exchanges. One-way events are emitted
    // by service code, not fabricated by a command-line client.
    record.id = Some(Value::from(1_u64));
    let format = DestinationFormat::from_cli(
        cli.rpc_format.as_deref(),
        matches!(
            (&record.component, &record.method),
            (
                mesh::tagged::NameOrTag::Tag(_),
                mesh::tagged::NameOrTag::Tag(_)
            )
        ),
    )?;
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
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    #[test]
    fn bare_named_rpc_argument_is_a_top_level_field() {
        let arguments = vec![
            "mesh-init".to_owned(),
            "stop".to_owned(),
            "name=demo".to_owned(),
        ];
        let record = record_from_argv(&arguments, None).unwrap();
        assert_eq!(
            to_json(&record, None),
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
        let record = record_from_argv(&arguments, None).unwrap();
        assert_eq!(record.component.text(), "esp");
        assert_eq!(record.method.text(), "serial.command");
        assert_eq!(
            to_json(&record, None),
            json!({"method": "esp.serial.command", "port": "lora2", "command": "status"})
        );
    }

    #[test]
    fn dotted_rpc_method_accepts_no_parameters() {
        let arguments = vec!["usb.serial.forward.list".to_owned()];
        let record = record_from_argv(&arguments, None).unwrap();
        assert_eq!(
            to_json(&record, None),
            json!({"method": "usb.serial.forward.list"})
        );
    }

    #[test]
    fn json_rpc_gateway_uses_the_common_tagged_request() {
        let arguments = vec![
            "esp.serial.command".to_owned(),
            "port=lora3".to_owned(),
            "command=status".to_owned(),
        ];
        let mut record = record_from_argv(&arguments, None).unwrap();
        record.id = Some(json!(12));
        assert_eq!(
            json_rpc_request(&record, None),
            json!({
                "jsonrpc": "2.0",
                "id": 12,
                "method": "esp.serial.command",
                "params": {"port": "lora3", "command": "status"}
            })
        );
    }

    #[test]
    fn automatic_codec_requires_numeric_tags_for_cbor() {
        assert_eq!(
            DestinationFormat::from_value("auto", true).unwrap(),
            DestinationFormat::Cbor
        );
        assert_eq!(
            DestinationFormat::from_value("auto", false).unwrap(),
            DestinationFormat::JsonRpc
        );
        assert!(DestinationFormat::from_value("cbor", false).is_err());
    }

    #[test]
    fn explicit_cli_codec_overrides_environment_selection() {
        assert_eq!(
            DestinationFormat::from_cli(Some("json-rpc"), true).unwrap(),
            DestinationFormat::JsonRpc
        );
    }

    #[test]
    fn packaged_generated_catalog_is_discoverable_without_service_toml() {
        let directory = std::env::temp_dir().join(format!(
            "mesh-cli-generated-tools-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let catalog = directory.join("tools.json");
        std::fs::write(&catalog, "[]").unwrap();
        assert_eq!(packaged_tools_path(vec![directory.clone()]), Some(catalog));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn rpc_uses_json_rpc_on_wire_without_numeric_schema() {
        let (client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let (read, mut write) = tokio::io::split(server);
            let mut line = String::new();
            BufReader::new(read).read_line(&mut line).await.unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(request["jsonrpc"], "2.0");
            assert_eq!(request["method"], "mesh.status");
            assert_eq!(request["params"]["verbose"], true);
            write
                .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n")
                .await
                .unwrap();
        });
        let record = TaggedRecord {
            component: mesh::tagged::NameOrTag::Name("mesh".to_owned()),
            method: mesh::tagged::NameOrTag::Name("status".to_owned()),
            id: Some(json!(1)),
            env: [(
                mesh::tagged::NameOrTag::Name("verbose".to_owned()),
                json!(true),
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        rpc(client, record, None, DestinationFormat::JsonRpc)
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn rpc_uses_tagged_cbor_on_wire_with_numeric_schema() {
        let catalog = TaggedCatalog::from_tools_json(&json!([{
            "name": "mesh.status",
            "x-component-index": 1,
            "x-method-index": 2,
            "inputSchema": {"properties": {
                "verbose": {"x-protobuf-index": 3}
            }}
        }]))
        .unwrap();
        let mut record = catalog
            .parse_argv("mesh.status", &["verbose=true".to_owned()])
            .unwrap();
        record.id = Some(json!(1));
        let (client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut header = [0_u8; 4];
            server.read_exact(&mut header).await.unwrap();
            let mut frame = vec![0_u8; u32::from_be_bytes(header) as usize + 4];
            frame[..4].copy_from_slice(&header);
            server.read_exact(&mut frame[4..]).await.unwrap();
            let request = decode_record(decode_stream_frame(&frame).unwrap()).unwrap();
            assert_eq!(request.component, mesh::tagged::NameOrTag::Tag(1));
            assert_eq!(request.method, mesh::tagged::NameOrTag::Tag(2));
            assert_eq!(
                request.env.get(&mesh::tagged::NameOrTag::Tag(3)),
                Some(&json!(true))
            );
            server
                .write_all(
                    &encode_stream_frame(
                        &encode_record(&TaggedRecord {
                            id: Some(json!(1)),
                            result: Some(json!({"ok": true})),
                            ..Default::default()
                        })
                        .unwrap(),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
        });
        rpc(client, record, Some(&catalog), DestinationFormat::Cbor)
            .await
            .unwrap();
        server_task.await.unwrap();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut cli = Cli::parse();
    let catalog_destination = cli.destination.clone();
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
        return rpc_destination(&cli, &catalog_destination).await;
    }
    if let Some(path) = cli.destination.strip_prefix("mux://") {
        return mux_destination(&cli, PathBuf::from(path)).await;
    }
    if let Some(path) = &cli.control_path {
        return mux_destination(&cli, path.clone()).await;
    }
    external_ssh()
}
