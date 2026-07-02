//! Systemd socket unit file parser.
//!
//! Parses `.socket` files using the systemd socket unit configuration spec
//! (INI-like format with a `[Socket]` section). Produces activation configs
//! that can be attached to mesh-init services.
//!
//! No external dependencies — uses only `std` and `libc`.

use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, error, info, warn};

pub use mesh::config::ActivationConfig;

/// Configuration parsed from a systemd `.socket` unit file.
#[derive(Debug, Clone, Default)]
pub struct SystemdSocketConfig {
    /// Service name to activate (from filename stem or `Service=` directive).
    pub service_name: String,
    /// Listen addresses from `ListenStream=` directives.
    pub listen_streams: Vec<String>,
    /// Listen addresses from `ListenDatagram=` directives.
    pub listen_datagrams: Vec<String>,
    /// If true, accept connections and pass client FDs in inetd style.
    /// If false, pass the listening FD using systemd-style activation.
    /// Internally maps to the runtime listener-passing flag.
    pub accept: bool,
    /// Socket file permissions (octal).
    pub socket_mode: Option<u32>,
    /// Socket file owner.
    pub socket_user: Option<String>,
    /// Socket file group.
    pub socket_group: Option<String>,
    /// Name assigned to all descriptors from this socket unit.
    pub file_descriptor_name: Option<String>,
    /// Optional descriptor names assigned by listener order. This is populated
    /// by splitting a single `FileDescriptorName=` value on whitespace.
    pub file_descriptor_names: Vec<String>,
}

// ============================================================================
// INI Parser
// ============================================================================

/// Parse a systemd-style INI unit file into sections.
///
/// Returns a map of `section_name → (key → [values])`. Multiple values for
/// the same key are accumulated in order (e.g. multiple `ListenStream=` lines).
fn parse_ini(content: &str) -> Result<HashMap<String, HashMap<String, Vec<String>>>, String> {
    let mut sections: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
    let mut current_section: Option<String> = None;

    for (line_num, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        // Section header: [SectionName]
        if line.starts_with('[') {
            if !line.ends_with(']') {
                return Err(format!(
                    "line {}: malformed section header: {}",
                    line_num + 1,
                    raw_line
                ));
            }
            let section_name = line[1..line.len() - 1].trim().to_string();
            if section_name.is_empty() {
                return Err(format!("line {}: empty section name", line_num + 1));
            }
            current_section = Some(section_name);
            continue;
        }

        let section = current_section
            .as_ref()
            .ok_or_else(|| {
                format!(
                    "line {}: key-value outside of section: {}",
                    line_num + 1,
                    raw_line
                )
            })?
            .clone();

        // Key=Value or Key=Value with continuation
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim().to_string();
            if key.is_empty() {
                return Err(format!("line {}: empty key name", line_num + 1));
            }
            let value = line[eq_pos + 1..].trim().to_string();
            sections
                .entry(section)
                .or_default()
                .entry(key)
                .or_default()
                .push(value);
        } else {
            return Err(format!(
                "line {}: expected key=value format: {}",
                line_num + 1,
                raw_line
            ));
        }
    }

    Ok(sections)
}

// ============================================================================
// Socket file parsing
// ============================================================================

/// Parse a systemd `.socket` file from disk.
pub fn parse_socket_file(path: &Path) -> Result<SystemdSocketConfig, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read '{}': {}", path.display(), e))?;

    let sections = parse_ini(&content)?;

    let socket_section = sections
        .get("Socket")
        .ok_or_else(|| format!("'{}' is missing [Socket] section", path.display()))?;

    // Determine service name from filename
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    let socket_file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();

    // Service= directive overrides the service name
    let service_name = socket_section
        .get("Service")
        .and_then(|v| v.first().cloned())
        .unwrap_or(stem);

    if service_name.is_empty() {
        return Err(format!(
            "'{}' has no service name (filename stem or Service=)",
            path.display()
        ));
    }

    // Parse ListenStream= directives
    let listen_streams = socket_section
        .get("ListenStream")
        .cloned()
        .unwrap_or_default();

    // Parse ListenDatagram= directives
    let listen_datagrams = socket_section
        .get("ListenDatagram")
        .cloned()
        .unwrap_or_default();

    if listen_streams.is_empty() && listen_datagrams.is_empty() {
        return Err(format!(
            "'{}' has no ListenStream= or ListenDatagram= directives",
            path.display()
        ));
    }

    // Parse Accept= directive (default false)
    let accept = socket_section
        .get("Accept")
        .and_then(|v| v.first())
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1" || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(false);

    // Parse SocketMode= (octal, e.g. "0660")
    let socket_mode = socket_section
        .get("SocketMode")
        .and_then(|v| v.first())
        .and_then(|v| u32::from_str_radix(v.trim_start_matches("0"), 8).ok());

    // Parse SocketUser=
    let socket_user = socket_section
        .get("SocketUser")
        .and_then(|v| v.first().cloned())
        .filter(|s| !s.is_empty());

    // Parse SocketGroup=
    let socket_group = socket_section
        .get("SocketGroup")
        .and_then(|v| v.first().cloned())
        .filter(|s| !s.is_empty());
    let configured_fd_name = socket_section
        .get("FileDescriptorName")
        .and_then(|v| v.last())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let file_descriptor_names = configured_fd_name
        .map(parse_file_descriptor_name_list)
        .transpose()?
        .unwrap_or_default();
    let file_descriptor_name = configured_fd_name
        .filter(|value| !value.split_whitespace().nth(1).is_some())
        .map(str::to_string)
        .or_else(|| {
            if socket_file_name.is_empty() {
                None
            } else {
                Some(socket_file_name)
            }
        });

    Ok(SystemdSocketConfig {
        service_name,
        listen_streams,
        listen_datagrams,
        accept,
        socket_mode,
        socket_user,
        socket_group,
        file_descriptor_name,
        file_descriptor_names,
    })
}

fn parse_file_descriptor_name_list(value: &str) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for name in value.split_whitespace() {
        if !valid_file_descriptor_name(name) {
            return Err(format!("invalid FileDescriptorName entry '{}'", name));
        }
        names.push(name.to_string());
    }
    Ok(names)
}

fn valid_file_descriptor_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.contains(':')
        && name.bytes().all(|b| b.is_ascii() && !b.is_ascii_control())
}

// ============================================================================
// Address parsing
// ============================================================================

/// Parse a `ListenStream=` or `ListenDatagram=` address into an `ActivationConfig`.
fn parse_listen_address(address: &str, accept: bool, datagram: bool) -> Option<ActivationConfig> {
    let addr = address.trim();

    if addr.is_empty() {
        return None;
    }

    if let Some(rest) = addr.strip_prefix("vsock:") {
        if datagram {
            // AF_VSOCK/SOCK_DGRAM is not a practical systemd-compatible
            // activation target today: Linux exposes constants on some
            // systems, but virtio-vsock datagram transport support is not
            // consistently available and Rust std/tokio provide no socket
            // wrapper. Add this with a raw-fd binder once there is a concrete
            // guest/host transport to validate against.
            warn!(
                "ListenDatagram AF_VSOCK address '{}' is not supported",
                addr
            );
            return None;
        }
        let Some((cid_str, port_str)) = rest.split_once(':') else {
            warn!("Cannot parse ListenStream AF_VSOCK address '{}'", addr);
            return None;
        };
        let vsock_cid = if cid_str.is_empty() {
            None
        } else {
            match cid_str.parse::<u32>() {
                Ok(cid) => Some(cid),
                Err(_) => {
                    warn!("Cannot parse ListenStream AF_VSOCK CID '{}'", addr);
                    return None;
                }
            }
        };
        let Ok(vsock_port) = port_str.parse::<u32>() else {
            warn!("Cannot parse ListenStream AF_VSOCK port '{}'", addr);
            return None;
        };
        return Some(ActivationConfig {
            vsock_cid,
            vsock_port: Some(vsock_port),
            wait: !accept,
            datagram,
            ..Default::default()
        });
    }

    // Abstract namespace socket (starts with @ or \0). systemd accepts these
    // for Unix sockets, but mesh-init intentionally supports pathname sockets
    // first because they fit service configs, permissions, and child fd names.
    if addr.starts_with('@') || addr.starts_with('\0') {
        warn!(
            "Abstract namespace socket '{}' is not supported in activation config",
            addr
        );
        return None;
    }

    // Unix socket path (starts with /)
    if addr.starts_with('/') {
        return Some(ActivationConfig {
            socket: Some(addr.to_string()),
            wait: !accept,
            datagram,
            ..Default::default()
        });
    }

    // Bare port number
    if let Ok(port) = addr.parse::<u16>() {
        return Some(ActivationConfig {
            port: Some(port),
            bind: Some("[::]".to_string()),
            wait: !accept,
            datagram,
            ..Default::default()
        });
    }

    // host:port or [host]:port format
    if addr.contains(':') {
        // IPv6: [::1]:8080
        if addr.starts_with('[') {
            if let Some(bracket_end) = addr.find(']') {
                let host = &addr[1..bracket_end];
                let rest = &addr[bracket_end + 1..];
                if let Some(port_str) = rest.strip_prefix(':') {
                    if let Ok(port) = port_str.parse::<u16>() {
                        return Some(ActivationConfig {
                            port: Some(port),
                            bind: Some(format!("[{}]", host)),
                            wait: !accept,
                            datagram,
                            ..Default::default()
                        });
                    }
                }
            }
        } else {
            // IPv4: host:port
            if let Some((host, port_str)) = addr.rsplit_once(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    return Some(ActivationConfig {
                        port: Some(port),
                        bind: Some(host.to_string()),
                        wait: !accept,
                        datagram,
                        ..Default::default()
                    });
                }
            }
        }
    }

    // Missing systemd socket families for follow-up:
    // - ListenSequentialPacket: Unix SOCK_SEQPACKET needs a separate socket
    //   kind and accept loop, not the stream/datagram split used here.
    // - ListenFIFO, ListenSpecial, ListenMessageQueue, ListenNetlink: these
    //   are not internet/Unix socket listeners and need resource-specific
    //   open/bind logic plus service readiness tests.
    warn!(
        "Cannot parse {} address '{}'",
        if datagram {
            "ListenDatagram"
        } else {
            "ListenStream"
        },
        addr
    );
    None
}

// ============================================================================
// Conversion
// ============================================================================

/// Convert a parsed systemd socket config into a list of activation configs.
pub fn socket_to_activation_configs(config: &SystemdSocketConfig) -> Vec<ActivationConfig> {
    let mut results = Vec::new();

    for addr in &config.listen_streams {
        if let Some(act) = parse_listen_address(addr, config.accept, false) {
            results.push(act);
        }
    }

    let (udp_datagrams, unix_datagrams): (Vec<_>, Vec<_>) = config
        .listen_datagrams
        .iter()
        .partition(|addr| !addr.trim().starts_with('/'));

    for addr in udp_datagrams.into_iter().chain(unix_datagrams) {
        if let Some(act) = parse_listen_address(addr, config.accept, true) {
            // Accept=true + datagram is not supported
            // because accepting a datagram connection doesn't produce a connected
            // client socket suitable for stdin/stdout passing.
            if config.accept {
                error!(
                    "Accept=true with ListenDatagram='{}' is not supported - skipping",
                    addr
                );
                continue;
            }
            results.push(act);
        }
    }

    // Apply socket metadata to each activation config
    if config.socket_mode.is_some() || config.socket_user.is_some() || config.socket_group.is_some()
    {
        for act in &mut results {
            if act.socket.is_some() {
                act.socket_mode = config.socket_mode;
                act.socket_user.clone_from(&config.socket_user);
                act.socket_group.clone_from(&config.socket_group);
            }
        }
    }
    for (idx, act) in results.iter_mut().enumerate() {
        act.fd_name = config
            .file_descriptor_names
            .get(idx)
            .cloned()
            .or_else(|| config.file_descriptor_name.clone());
    }

    results
}

// ============================================================================
// Directory scanning
// ============================================================================

/// Load all systemd `.socket` files from a directory.
///
/// Returns a list of `(service_name, activation_configs)` pairs. Only files
/// with the `.socket` extension are considered. Invalid files are logged as
/// warnings and skipped.
pub fn load_socket_units(dir: &str) -> Vec<(String, Vec<ActivationConfig>)> {
    let dir_path = Path::new(dir);
    if !dir_path.is_dir() {
        debug!("Socket unit directory {} does not exist, skipping", dir);
        return Vec::new();
    }

    let mut results = Vec::new();

    let entries = match std::fs::read_dir(dir_path) {
        Ok(entries) => entries,
        Err(e) => {
            warn!("Failed to read socket unit directory {}: {}", dir, e);
            return Vec::new();
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("socket") {
            match parse_socket_file(&path) {
                Ok(socket_config) => {
                    let activation_configs = socket_to_activation_configs(&socket_config);
                    if activation_configs.is_empty() {
                        warn!(
                            "No valid activation configs from socket unit '{}'",
                            path.display()
                        );
                        continue;
                    }
                    info!(
                        "Loaded socket unit '{}' for service '{}' with {} listener(s)",
                        path.display(),
                        socket_config.service_name,
                        activation_configs.len()
                    );
                    results.push((socket_config.service_name, activation_configs));
                }
                Err(e) => {
                    warn!("Failed to parse socket unit '{}': {}", path.display(), e);
                }
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ini_basic() {
        let ini = r#"
[Socket]
ListenStream=8080
Accept=false
"#;
        let sections = parse_ini(ini).unwrap();
        let socket = sections.get("Socket").unwrap();
        assert_eq!(socket.get("ListenStream").unwrap(), &vec!["8080"]);
        assert_eq!(socket.get("Accept").unwrap(), &vec!["false"]);
    }

    #[test]
    fn test_parse_ini_multiple_values() {
        let ini = r#"
[Socket]
ListenStream=8080
ListenStream=/run/myapp.sock
"#;
        let sections = parse_ini(ini).unwrap();
        let socket = sections.get("Socket").unwrap();
        assert_eq!(
            socket.get("ListenStream").unwrap(),
            &vec!["8080", "/run/myapp.sock"]
        );
    }

    #[test]
    fn test_parse_ini_comments() {
        let ini = r#"
# This is a comment
[Socket]
; also a comment
ListenStream=8080
"#;
        let sections = parse_ini(ini).unwrap();
        let socket = sections.get("Socket").unwrap();
        assert_eq!(socket.get("ListenStream").unwrap(), &vec!["8080"]);
    }

    #[test]
    fn test_parse_ini_no_section_error() {
        let ini = "ListenStream=8080";
        assert!(parse_ini(ini).is_err());
    }

    #[test]
    fn test_parse_socket_file_descriptor_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web.socket");
        std::fs::write(
            &path,
            r#"
[Socket]
ListenStream=8080
FileDescriptorName=http
"#,
        )
        .unwrap();
        let cfg = parse_socket_file(&path).unwrap();

        let acts = socket_to_activation_configs(&cfg);
        assert_eq!(acts[0].fd_name.as_deref(), Some("http"));
    }

    #[test]
    fn test_parse_socket_file_descriptor_name_applies_to_all_listeners() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ssh-mesh.socket");
        std::fs::write(
            &path,
            r#"
[Socket]
ListenStream=15022
ListenStream=80
ListenStream=vsock:2:5000
FileDescriptorName=ssh-mesh
"#,
        )
        .unwrap();
        let cfg = parse_socket_file(&path).unwrap();
        let acts = socket_to_activation_configs(&cfg);
        assert_eq!(acts.len(), 3);
        assert_eq!(acts[0].fd_name.as_deref(), Some("ssh-mesh"));
        assert_eq!(acts[1].fd_name.as_deref(), Some("ssh-mesh"));
        assert_eq!(acts[2].fd_name.as_deref(), Some("ssh-mesh"));
    }

    #[test]
    fn test_parse_socket_file_descriptor_name_list_by_listener_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ssh-mesh.socket");
        std::fs::write(
            &path,
            r#"
[Socket]
ListenStream=15022
ListenStream=80
ListenStream=vsock:2:5000
FileDescriptorName=ssh http vsock
"#,
        )
        .unwrap();
        let cfg = parse_socket_file(&path).unwrap();
        let acts = socket_to_activation_configs(&cfg);
        assert_eq!(acts.len(), 3);
        assert_eq!(acts[0].fd_name.as_deref(), Some("ssh"));
        assert_eq!(acts[1].fd_name.as_deref(), Some("http"));
        assert_eq!(acts[2].fd_name.as_deref(), Some("vsock"));
    }

    #[test]
    fn test_parse_socket_file_descriptor_name_list_default_for_missing_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ssh-mesh.socket");
        std::fs::write(
            &path,
            r#"
[Socket]
ListenStream=15022
ListenStream=80
ListenStream=vsock:2:5000
FileDescriptorName=ssh http
"#,
        )
        .unwrap();
        let cfg = parse_socket_file(&path).unwrap();
        let acts = socket_to_activation_configs(&cfg);
        assert_eq!(acts[0].fd_name.as_deref(), Some("ssh"));
        assert_eq!(acts[1].fd_name.as_deref(), Some("http"));
        assert_eq!(acts[2].fd_name.as_deref(), Some("ssh-mesh.socket"));
    }

    #[test]
    fn test_parse_socket_file_descriptor_name_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web.socket");
        std::fs::write(
            &path,
            r#"
[Socket]
ListenStream=8080
"#,
        )
        .unwrap();
        let cfg = parse_socket_file(&path).unwrap();
        assert_eq!(cfg.file_descriptor_name.as_deref(), Some("web.socket"));
    }

    #[test]
    fn test_parse_listen_address_bare_port() {
        let act = parse_listen_address("8080", false, false).unwrap();
        assert_eq!(act.port, Some(8080));
        assert_eq!(act.bind.as_deref(), Some("[::]"));
        assert_eq!(act.wait, true); // !accept = !false
        assert!(!act.datagram);
    }

    #[test]
    fn test_parse_listen_address_uds() {
        let act = parse_listen_address("/run/test.sock", true, false).unwrap();
        assert_eq!(act.socket.as_deref(), Some("/run/test.sock"));
        assert_eq!(act.wait, false); // !accept = !true
    }

    #[test]
    fn test_parse_listen_address_host_port() {
        let act = parse_listen_address("127.0.0.1:9090", false, false).unwrap();
        assert_eq!(act.port, Some(9090));
        assert_eq!(act.bind.as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn test_parse_listen_address_ipv6() {
        let act = parse_listen_address("[::1]:443", false, false).unwrap();
        assert_eq!(act.port, Some(443));
        assert_eq!(act.bind.as_deref(), Some("[::1]"));
    }

    #[test]
    fn test_parse_listen_address_vsock() {
        let act = parse_listen_address("vsock:2:5000", false, false).unwrap();
        assert_eq!(act.vsock_cid, Some(2));
        assert_eq!(act.vsock_port, Some(5000));
        assert_eq!(act.wait, true);
        assert!(!act.datagram);
    }

    #[test]
    fn test_parse_listen_address_vsock_default_cid() {
        let act = parse_listen_address("vsock::5000", false, false).unwrap();
        assert_eq!(act.vsock_cid, None);
        assert_eq!(act.vsock_port, Some(5000));
    }

    #[test]
    fn test_parse_listen_address_vsock_datagram_skipped() {
        assert!(parse_listen_address("vsock:2:5000", false, true).is_none());
    }

    #[test]
    fn test_parse_listen_address_datagram() {
        let act = parse_listen_address("8080", true, true).unwrap();
        assert_eq!(act.port, Some(8080));
        assert_eq!(act.wait, false);
        assert!(act.datagram);
    }

    #[test]
    fn test_parse_listen_address_abstract_skipped() {
        assert!(parse_listen_address("@abstract", false, false).is_none());
        assert!(parse_listen_address("\0abstract", false, false).is_none());
    }

    #[test]
    fn test_parse_listen_address_empty() {
        assert!(parse_listen_address("", false, false).is_none());
    }

    #[test]
    fn test_socket_to_activation_configs() {
        let cfg = SystemdSocketConfig {
            service_name: "test".to_string(),
            listen_streams: vec!["8080".to_string(), "/run/test.sock".to_string()],
            listen_datagrams: vec![],
            accept: false,
            socket_mode: None,
            socket_user: None,
            socket_group: None,
            file_descriptor_name: Some("test.socket".to_string()),
            file_descriptor_names: Vec::new(),
        };
        let acts = socket_to_activation_configs(&cfg);
        assert_eq!(acts.len(), 2);
        assert_eq!(acts[0].port, Some(8080));
        assert_eq!(acts[0].bind.as_deref(), Some("[::]"));
        assert_eq!(acts[0].fd_name.as_deref(), Some("test.socket"));
        assert_eq!(acts[0].wait, true);
        assert_eq!(acts[1].socket.as_deref(), Some("/run/test.sock"));
        assert_eq!(acts[1].fd_name.as_deref(), Some("test.socket"));
        assert_eq!(acts[1].wait, true);
    }

    #[test]
    fn test_socket_to_activation_configs_accept() {
        let cfg = SystemdSocketConfig {
            service_name: "test".to_string(),
            listen_streams: vec!["8080".to_string()],
            listen_datagrams: vec![],
            accept: true,
            socket_mode: None,
            socket_user: None,
            socket_group: None,
            file_descriptor_name: None,
            file_descriptor_names: Vec::new(),
        };
        let acts = socket_to_activation_configs(&cfg);
        assert_eq!(acts.len(), 1);
        assert_eq!(acts[0].port, Some(8080));
        assert_eq!(acts[0].wait, false);
    }

    #[test]
    fn test_socket_to_activation_configs_datagram_wait_false_skipped() {
        let cfg = SystemdSocketConfig {
            service_name: "test".to_string(),
            listen_streams: vec![],
            listen_datagrams: vec!["8080".to_string()],
            accept: true,
            socket_mode: None,
            socket_user: None,
            socket_group: None,
            file_descriptor_name: None,
            file_descriptor_names: Vec::new(),
        };
        // Accept=true + datagram is skipped with an error.
        let acts = socket_to_activation_configs(&cfg);
        assert!(acts.is_empty());
    }

    #[test]
    fn test_socket_to_activation_configs_datagram_wait_true() {
        let cfg = SystemdSocketConfig {
            service_name: "test".to_string(),
            listen_streams: vec![],
            listen_datagrams: vec!["8080".to_string()],
            accept: false,
            socket_mode: None,
            socket_user: None,
            socket_group: None,
            file_descriptor_name: None,
            file_descriptor_names: Vec::new(),
        };
        let acts = socket_to_activation_configs(&cfg);
        assert_eq!(acts.len(), 1);
        assert_eq!(acts[0].port, Some(8080));
        assert_eq!(acts[0].wait, true);
        assert!(acts[0].datagram);
    }

    #[test]
    fn test_socket_to_activation_configs_datagram_udp_before_unix() {
        let cfg = SystemdSocketConfig {
            service_name: "test".to_string(),
            listen_streams: vec![],
            listen_datagrams: vec!["/run/test.sock".to_string(), "8125".to_string()],
            accept: false,
            socket_mode: None,
            socket_user: None,
            socket_group: None,
            file_descriptor_name: None,
            file_descriptor_names: Vec::new(),
        };
        let acts = socket_to_activation_configs(&cfg);
        assert_eq!(acts.len(), 2);
        assert_eq!(acts[0].port, Some(8125));
        assert_eq!(acts[1].socket.as_deref(), Some("/run/test.sock"));
        assert!(acts.iter().all(|act| act.datagram));
    }
}
