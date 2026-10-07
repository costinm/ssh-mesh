//! Target resolution: from what a user typed to the trails that serve it.
//!
//! A *target* is a service name, a device name, an FQDN, a VIP, a MAC, a socket path, a serial
//! path or an explicit URL; how it is matched is an implementation detail of the resolvers.
//!
//! The result is a set of candidate [`Trail`]s, because reaching a node usually has several
//! answers with different trade-offs. A trail is the *start of a path*: an ordered list of
//! [`Hop`]s that the resolver knows, and [`Onward`] says what happens after the last one: it is the
//! target, or a gateway (or the Internet) that picks the rest of the path itself from the SNI, the
//! authority or a QUIC connection ID, or nothing is known. A direct path has one hop; a relay
//! circuit or an egress-gateway path has several, and the client dials only the first (the opener
//! passes the rest on in the form the protocol has). A hop has several equivalent addresses (DNS
//! records, an IPv4 and an IPv6 address) and its own protocol and metadata: peer SAN, root CA, SNI
//! and so on, as an xDS-style control plane would inject them. Each trail carries its
//! [`Tradeoffs`] (preference, cost, latency, whether reaching it wakes a sleepy node, whether it is
//! metered) and the resolver it came from.
//!
//! Every resolver that knows the target contributes candidates. Who decides between them is
//! open: a control plane that holds all discovery and cost data can hand back ranked candidates
//! (their `preference`), and a client can run its own [`Policy`] over them for the current
//! [`Conditions`] (on battery, metered network, ...) and keep several policies for different
//! situations. There is no connector concept and nothing here knows QUIC: [`Protocol::Quic`] is a
//! value that a registered opener can serve.
//!
//! Resolvers: the local service socket, saved discovery (registered by the embedding application),
//! an explicit address, then DNS (see [`Resolvers::standard`]).
//!
//! Protocol defaults when the source gives none:
//!
//! | Trail | Protocol |
//! |---|---|
//! | Internet IP or FQDN | HTTPS (port 443) |
//! | Unix seqpacket socket (`.cbor`) | tagged CBOR |
//! | Unix stream socket | JSONL |
//! | Serial/USB path, local or link-local address | QUIC |
//!
//! A port may select the protocol (see [`PortMap`]); an explicit scheme or metadata overrides it.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;

use anyhow::{Context, Result};

/// The wire protocol a trail speaks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Protocol {
    /// Newline-delimited JSON (regular unix-domain stream sockets).
    Jsonl,
    /// Tagged CBOR (packet-oriented unix sockets).
    Cbor,
    Http,
    Https,
    Ssh,
    /// QUIC (quic-lite): serial/USB and local or link-local addresses.
    Quic,
}

/// Where a trail is.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Address {
    /// A unix-domain socket.
    Unix(PathBuf),
    /// A serial or USB character device.
    Serial(PathBuf),
    /// A host (name or IP, no brackets) and an optional port.
    Host { host: String, port: Option<u16> },
}

/// One step of a path: a node reached at one of several equivalent addresses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hop {
    /// Equivalent addresses of this hop (DNS records, IPv4 and IPv6, several bearers), in order.
    pub addresses: Vec<Address>,
    pub protocol: Protocol,
    /// Protocol-specific facts from discovery: `san`, `ca`, `sni`, `format`, ...
    pub metadata: BTreeMap<String, String>,
}

impl Hop {
    pub fn new(address: Address, protocol: Protocol) -> Self {
        Self { addresses: vec![address], protocol, metadata: BTreeMap::new() }
    }

    pub fn with_address(mut self, address: Address) -> Self {
        self.addresses.push(address);
        self
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_owned(), value.to_owned());
        self
    }
}

/// What a client may use to pick the rest of the path once the known hops are used up.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Selector {
    /// TLS server name.
    Sni,
    /// HTTP authority / host.
    Authority,
    /// QUIC connection ID.
    ConnectionId,
    /// Some other label in the request, such as a relay label.
    Label,
}

/// What follows the last hop of a trail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Onward {
    /// The last hop is the target (or the Internet, which reaches the named host by itself).
    Target,
    /// The last hop is a gateway that continues toward the target by looking at this.
    Gateway(Selector),
    /// The resolver does not know how the path continues.
    Unknown,
}

/// What choosing a trail costs. All fields are optional facts or hints; a [`Policy`] decides
/// what they are worth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tradeoffs {
    /// Lower is tried first; set by the resolver or a control plane. Default 100.
    pub preference: u32,
    /// Relative price (a relay's, a metered link's). Default 0.
    pub cost: u32,
    pub latency_ms: Option<u32>,
    /// Reaching it requires waking a sleepy node first (battery and delay).
    pub wake: bool,
    /// The path crosses a metered or limited link.
    pub metered: bool,
}

impl Default for Tradeoffs {
    fn default() -> Self {
        Self { preference: 100, cost: 0, latency_ms: None, wake: false, metered: false }
    }
}

/// One way to reach a target: the known start of a path (one or more hops), what follows it, and
/// its trade-offs. A resolver returns several of these when there are several ways.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Trail {
    /// At least one hop. The client dials the first; later hops are passed on by the opener.
    pub hops: Vec<Hop>,
    /// What happens after the last known hop.
    pub onward: Onward,
    pub tradeoffs: Tradeoffs,
    /// The resolver that produced it (`local`, `explicit`, `dns`, or the application's name).
    pub source: String,
}

impl Trail {
    /// A direct, single-hop, single-address trail.
    pub fn new(address: Address, protocol: Protocol) -> Self {
        Self::path(vec![Hop::new(address, protocol)])
    }

    /// A path through several hops (a relay circuit, an egress gateway), first to last.
    pub fn path(hops: Vec<Hop>) -> Self {
        assert!(!hops.is_empty(), "a trail has at least one hop");
        Self { hops, onward: Onward::Target, tradeoffs: Tradeoffs::default(), source: String::new() }
    }

    /// Say what follows the last known hop (default: it is the target).
    pub fn with_onward(mut self, onward: Onward) -> Self {
        self.onward = onward;
        self
    }

    pub fn with_tradeoffs(mut self, tradeoffs: Tradeoffs) -> Self {
        self.tradeoffs = tradeoffs;
        self
    }

    pub fn with_source(mut self, source: &str) -> Self {
        self.source = source.to_owned();
        self
    }

    /// Metadata of the last known hop (the target's identity when `onward` is `Target`).
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        if let Some(last) = self.hops.last_mut() {
            last.metadata.insert(key.to_owned(), value.to_owned());
        }
        self
    }

    /// The hop the client dials.
    pub fn first_hop(&self) -> &Hop {
        &self.hops[0]
    }

    /// The last known hop.
    pub fn target_hop(&self) -> &Hop {
        self.hops.last().expect("a trail has at least one hop")
    }

    /// Whether the path goes through intermediaries.
    pub fn is_relayed(&self) -> bool {
        self.hops.len() > 1
    }

    /// The first address of the first hop, and its protocol: what a client dials.
    pub fn address(&self) -> &Address {
        &self.first_hop().addresses[0]
    }

    pub fn protocol(&self) -> Protocol {
        self.first_hop().protocol
    }

    /// The canonical URL of the first hop's first address. A unix trail is `unix://PATH`, a
    /// serial device is its path, and a host trail takes its scheme from the protocol (`tcp`
    /// for a JSONL or CBOR stream).
    pub fn url(&self) -> String {
        match (self.address(), self.protocol()) {
            (Address::Unix(path), _) => format!("unix://{}", path.display()),
            (Address::Serial(path), _) => path.display().to_string(),
            (Address::Host { host, port }, protocol) => {
                let scheme = match protocol {
                    Protocol::Jsonl | Protocol::Cbor => "tcp",
                    Protocol::Http => "http",
                    Protocol::Https => "https",
                    Protocol::Ssh => "ssh",
                    Protocol::Quic => "quic",
                };
                let host = if host.contains(':') { format!("[{host}]") } else { host.clone() };
                match port {
                    Some(port) => format!("{scheme}://{host}:{port}"),
                    None => format!("{scheme}://{host}"),
                }
            }
        }
    }
}

/// What is true of the client right now, for a [`Policy`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Conditions {
    pub on_battery: bool,
    pub metered_network: bool,
}

/// Orders candidate trails for the current conditions. A resolver gathers every way it knows;
/// the policy says which to try first. A control plane's ranking arrives as `preference`;
/// [`PreferenceOnly`] trusts it, [`DefaultPolicy`] adds the client's own conditions, and an
/// application can keep several policies and choose by situation.
pub trait Policy {
    fn order(&self, conditions: &Conditions, candidates: &mut Vec<Trail>);
}

/// Trust the resolver's ranking: order by `preference` only (ties keep their resolver order).
pub struct PreferenceOnly;

impl Policy for PreferenceOnly {
    fn order(&self, _: &Conditions, candidates: &mut Vec<Trail>) {
        candidates.sort_by_key(|trail| trail.tradeoffs.preference);
    }
}

/// The default: an explicit preference first; a metered path last when the network is metered; a
/// wake-up last when on battery; then fewer hops, no wake-up, lower cost, lower latency. Ties keep
/// their resolver order.
pub struct DefaultPolicy;

impl Policy for DefaultPolicy {
    fn order(&self, conditions: &Conditions, candidates: &mut Vec<Trail>) {
        candidates.sort_by_key(|trail| {
            let t = &trail.tradeoffs;
            (
                t.preference,
                t.metered && conditions.metered_network,
                t.wake && conditions.on_battery,
                trail.hops.len(),
                t.wake,
                t.cost,
                t.latency_ms.unwrap_or(u32::MAX),
            )
        });
    }
}

/// Ports that select a protocol. An application adds its own default ports (for example its QUIC
/// port) to the standard ones.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortMap {
    pub ssh: Vec<u16>,
    pub https: Vec<u16>,
    pub http: Vec<u16>,
    pub quic: Vec<u16>,
}

impl Default for PortMap {
    fn default() -> Self {
        Self { ssh: vec![22, 15022], https: vec![443, 15443], http: vec![80], quic: Vec::new() }
    }
}

impl PortMap {
    pub fn with_quic(mut self, port: u16) -> Self {
        self.quic.push(port);
        self
    }

    pub fn with_http(mut self, port: u16) -> Self {
        self.http.push(port);
        self
    }

    /// The protocol a port selects, if any.
    pub fn protocol(&self, port: u16) -> Option<Protocol> {
        [
            (&self.ssh, Protocol::Ssh),
            (&self.https, Protocol::Https),
            (&self.http, Protocol::Http),
            (&self.quic, Protocol::Quic),
        ]
        .into_iter()
        .find_map(|(ports, protocol)| ports.contains(&port).then_some(protocol))
    }
}

/// Whether an address is on the local network: loopback, private, link-local, unique-local.
/// Anything else is an Internet address.
pub fn is_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            ip.is_loopback()
                || ip.is_unspecified()
                || first & 0xffc0 == 0xfe80 // link-local
                || first & 0xfe00 == 0xfc00 // unique-local (includes mesh VIPs)
        }
    }
}

/// An unscoped host name that looks like a DNS name: dotted labels of letters, digits and `-`,
/// not an IP literal.
pub fn is_fqdn(value: &str) -> bool {
    let value = value.strip_suffix('.').unwrap_or(value);
    value.contains('.')
        && value.parse::<IpAddr>().is_err()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn protocol_for_unix(path: &str) -> Protocol {
    if path.ends_with(".cbor") { Protocol::Cbor } else { Protocol::Jsonl }
}

fn split_host_port(rest: &str) -> Option<(String, Option<u16>)> {
    if let Some(bracketed) = rest.strip_prefix('[') {
        let (host, tail) = bracketed.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(port) => Some(port.parse().ok()?),
            None if tail.is_empty() => None,
            None => return None,
        };
        return Some((host.to_owned(), port));
    }
    // A bare IPv6 literal has more than one colon and no port.
    if rest.parse::<Ipv6Addr>().is_ok() {
        return Some((rest.to_owned(), None));
    }
    match rest.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !host.contains(':') => {
            Some((host.to_owned(), Some(port.parse().ok()?)))
        }
        Some(_) => None,
        None if !rest.is_empty() => Some((rest.to_owned(), None)),
        None => None,
    }
}

/// Parse a syntactically explicit address into a one-hop trail: `unix://PATH`, an absolute or `./` path, a `/dev/`
/// serial path, `scheme://host[:port]` (`tcp`, `http`, `https`, `ssh`, `quic`, `udp`), or a bare IP
/// literal, optionally with a port. A bare name, a name with `@` or `/` and an FQDN without a
/// scheme are not explicit; other resolvers handle them.
pub fn parse_trail(value: &str, ports: &PortMap) -> Option<Trail> {
    if let Some(path) = value.strip_prefix("unix://") {
        return Some(Trail::new(Address::Unix(path.into()), protocol_for_unix(path)));
    }
    if value.starts_with("/dev/") {
        return Some(Trail::new(Address::Serial(value.into()), Protocol::Quic));
    }
    if value.starts_with('/') || value.starts_with("./") {
        return Some(Trail::new(Address::Unix(value.into()), protocol_for_unix(value)));
    }
    if let Some((scheme, rest)) = value.split_once("://") {
        let protocol = match scheme {
            "tcp" => Protocol::Jsonl,
            "http" => Protocol::Http,
            "https" => Protocol::Https,
            "ssh" => Protocol::Ssh,
            "quic" | "udp" => Protocol::Quic,
            _ => return None,
        };
        let (host, port) = split_host_port(rest)?;
        return Some(Trail::new(Address::Host { host, port }, protocol));
    }
    if value.contains('@') || value.contains('/') {
        return None;
    }
    let (host, port) = split_host_port(value)?;
    let ip: Option<IpAddr> = host.parse().ok();
    match (ip, port) {
        // An IP literal: the port selects the protocol, else local addresses speak QUIC and
        // Internet addresses HTTPS.
        (Some(ip), port) => {
            let protocol = port.and_then(|p| ports.protocol(p)).unwrap_or(if is_local_ip(ip) {
                Protocol::Quic
            } else {
                Protocol::Https
            });
            Some(Trail::new(Address::Host { host, port }, protocol))
        }
        // `name:port` selects a protocol only through a known port.
        (None, Some(port)) => {
            let protocol = ports.protocol(port)?;
            Some(Trail::new(Address::Host { host, port: Some(port) }, protocol))
        }
        (None, None) => None,
    }
}

/// The canonical spelling of a request's destination (`to`): `scheme://target`, where a bare
/// target is a mesh node resolved by discovery (`mesh://`). Returns `None` for text that cannot
/// be a destination (whitespace, `,`, `#`, `?`, `/` in the target, an unusable scheme).
pub fn canonical_target(value: &str) -> Option<String> {
    let (scheme, target) = value.split_once("://").unwrap_or(("mesh", value));
    if scheme.is_empty()
        || !scheme.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || target.is_empty()
        || target.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        || target.contains([',', '#', '?', '/'])
    {
        return None;
    }
    Some(format!("{scheme}://{target}"))
}

/// Something that can turn a target into trails (candidate starts of a path). `Ok(None)` means "not mine"; `Ok(Some(..))`
/// contributes candidates (possibly none).
pub trait Resolver: Send + Sync {
    fn resolve(&self, target: &str) -> Result<Option<Vec<Trail>>>;
}

/// Resolvers, consulted in order; every one that knows the target contributes.
#[derive(Default)]
pub struct Resolvers(Vec<Box<dyn Resolver>>);

impl Resolvers {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(mut self, resolver: impl Resolver + 'static) -> Self {
        self.0.push(Box::new(resolver));
        self
    }

    /// The standard order: the local service socket, the application's saved discovery, an explicit
    /// address, then DNS.
    pub fn standard(discovery: Option<Box<dyn Resolver>>, ports: PortMap) -> Self {
        let mut resolvers = Self::new().push(LocalServiceResolver { ports: ports.clone() });
        if let Some(discovery) = discovery {
            resolvers.0.push(discovery);
        }
        resolvers.push(ExplicitResolver { ports }).push(DnsResolver)
    }

    /// Every candidate, ordered by the default policy with no special conditions (empty when
    /// nothing knows the target).
    pub fn resolve(&self, target: &str) -> Result<Vec<Trail>> {
        self.resolve_with(target, &Conditions::default(), &DefaultPolicy)
    }

    /// Every candidate from every resolver that knows the target, ordered by `policy`.
    pub fn resolve_with(
        &self,
        target: &str,
        conditions: &Conditions,
        policy: &dyn Policy,
    ) -> Result<Vec<Trail>> {
        let mut candidates = Vec::new();
        for resolver in &self.0 {
            if let Some(trails) = resolver.resolve(target)? {
                candidates.extend(trails);
            }
        }
        policy.order(conditions, &mut candidates);
        Ok(candidates)
    }
}

/// Explicit addresses (see [`parse_trail`]).
pub struct ExplicitResolver {
    pub ports: PortMap,
}

impl Resolver for ExplicitResolver {
    fn resolve(&self, target: &str) -> Result<Option<Vec<Trail>>> {
        Ok(parse_trail(target, &self.ports).map(|trail| vec![trail.with_source("explicit")]))
    }
}

/// A fully qualified name that nothing else claimed: HTTPS on the default port. The name is not
/// looked up here; opening the trail resolves it.
pub struct DnsResolver;

impl Resolver for DnsResolver {
    fn resolve(&self, target: &str) -> Result<Option<Vec<Trail>>> {
        Ok(is_fqdn(target).then(|| {
            vec![Trail::new(
                Address::Host { host: target.trim_end_matches('.').to_owned(), port: None },
                Protocol::Https,
            )
            .with_source("dns")]
        }))
    }
}

/// A service on this machine: a mesh-init service (its `[Mesh]` address, or its standard control
/// socket) or an `endpoint.namespace` socket under `/run/mesh`.
pub struct LocalServiceResolver {
    pub ports: PortMap,
}

fn service_config_candidates(service: &str) -> Vec<PathBuf> {
    if let Some(source) = std::env::var_os("MESH_SERVICE_DIR").map(PathBuf::from) {
        return vec![if source.is_dir() { source.join(format!("{service}.toml")) } else { source }];
    }
    vec![
        PathBuf::from(format!("/home/system/etc/mesh-init/{service}.toml")),
        PathBuf::from(format!("etc/mesh-init/{service}.toml")),
    ]
}

fn simple_label(label: &str) -> bool {
    !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

impl LocalServiceResolver {
    fn unix(&self, service: &str) -> Trail {
        let path = crate::paths::resolve_service_socket(service);
        let protocol = protocol_for_unix(&path.to_string_lossy());
        Trail::new(Address::Unix(path), protocol)
    }
}

impl Resolver for LocalServiceResolver {
    fn resolve(&self, service: &str) -> Result<Option<Vec<Trail>>> {
        Ok(self.resolve_service(service)?.map(|trails| {
            trails.into_iter().map(|trail| trail.with_source("local")).collect()
        }))
    }
}

impl LocalServiceResolver {
    fn resolve_service(&self, service: &str) -> Result<Option<Vec<Trail>>> {
        if service.is_empty() || service.contains(['/', '@', ':']) {
            return Ok(None);
        }
        // A service definition with a `[Mesh]` section names its own address.
        for path in service_config_candidates(service).into_iter().rev() {
            if !path.is_file() {
                continue;
            }
            let config = crate::config::parse_service(
                &std::fs::read_to_string(&path)
                    .with_context(|| format!("read service definition {}", path.display()))?,
                Some(service),
            )
            .with_context(|| format!("parse service definition {}", path.display()))?;
            if let Some(section) = config.mesh {
                return Ok(Some(vec![match section.address {
                    Some(address) => parse_trail(&address, &self.ports)
                        .with_context(|| format!("service {service} has address {address:?}"))?,
                    None => self.unix(service),
                }]));
            }
        }
        // `endpoint.namespace` is a socket under /run/mesh.
        if let Some((endpoint, namespace)) = service.split_once('.')
            && simple_label(endpoint)
            && simple_label(namespace)
        {
            return Ok(Some(vec![Trail::new(
                Address::Unix(format!("/run/mesh/{namespace}/{endpoint}.sock").into()),
                Protocol::Jsonl,
            )]));
        }
        // A mesh-init service without a `[Mesh]` section, or with a live socket, owns the
        // standard per-service control socket.
        let configured = service_config_candidates(service).iter().any(|path| path.is_file());
        let live = crate::paths::service_socket_candidates(service).iter().any(|path| path.exists());
        Ok((configured || live).then(|| vec![self.unix(service)]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ports() -> PortMap {
        PortMap::default().with_quic(3339).with_http(18480)
    }

    fn parsed(value: &str) -> Option<(String, Protocol)> {
        parse_trail(value, &ports()).map(|e| (e.url(), e.protocol()))
    }

    #[test]
    fn sockets_follow_their_kind_and_serial_paths_speak_quic() {
        assert_eq!(parsed("/run/mesh/lmesh/mesh.sock"), Some(("unix:///run/mesh/lmesh/mesh.sock".into(), Protocol::Jsonl)));
        assert_eq!(parsed("unix:///run/x/y.cbor"), Some(("unix:///run/x/y.cbor".into(), Protocol::Cbor)));
        assert_eq!(parsed("./local.sock").unwrap().1, Protocol::Jsonl);
        assert_eq!(parsed("/dev/serial/by-id/usb-x"), Some(("/dev/serial/by-id/usb-x".into(), Protocol::Quic)));
    }

    #[test]
    fn schemes_select_the_protocol_and_hosts_keep_their_ports() {
        assert_eq!(parsed("tcp://127.0.0.1:15101").unwrap().1, Protocol::Jsonl);
        assert_eq!(parsed("http://h:18480"), Some(("http://h:18480".into(), Protocol::Http)));
        assert_eq!(parsed("https://api.example.com"), Some(("https://api.example.com".into(), Protocol::Https)));
        assert_eq!(parsed("ssh://u.example.com:2222").unwrap().1, Protocol::Ssh);
        assert_eq!(parsed("udp://[fe80::1%5]:3339").unwrap().1, Protocol::Quic);
        assert_eq!(parsed("udp://[fe80::1]:3339").unwrap().0, "quic://[fe80::1]:3339");
        assert_eq!(parsed("gopher://x"), None);
    }

    #[test]
    fn ports_select_the_protocol() {
        for (port, protocol) in [
            (22, Protocol::Ssh), (15022, Protocol::Ssh),
            (443, Protocol::Https), (15443, Protocol::Https),
            (80, Protocol::Http), (18480, Protocol::Http),
            (3339, Protocol::Quic),
        ] {
            assert_eq!(parsed(&format!("203.0.113.9:{port}")).unwrap().1, protocol, "{port}");
            assert_eq!(parsed(&format!("host:{port}")).unwrap().1, protocol, "{port}");
        }
        // A name with an unknown port is not explicit.
        assert_eq!(parsed("host:9999"), None);
        // An IP with an unknown port falls back to the address default.
        assert_eq!(parsed("203.0.113.9:9999").unwrap().1, Protocol::Https);
        assert_eq!(parsed("10.0.0.1:9999").unwrap().1, Protocol::Quic);
    }

    #[test]
    fn address_defaults_are_https_for_the_internet_and_quic_for_local_addresses() {
        for local in ["10.78.0.1", "192.168.1.5", "127.0.0.1", "169.254.1.1", "fe80::1", "fc00::9569:f648", "::1", "[fe80::1]:3339"] {
            assert_eq!(parsed(local).unwrap().1, Protocol::Quic, "{local}");
        }
        for internet in ["8.8.8.8", "203.0.113.9", "2001:db8::1", "172.32.0.1"] {
            assert_eq!(parsed(internet).unwrap().1, Protocol::Https, "{internet}");
        }
        assert!(is_local_ip("172.16.0.1".parse().unwrap()) && is_local_ip("172.31.255.1".parse().unwrap()));
    }

    #[test]
    fn names_and_ssh_style_destinations_are_not_explicit() {
        for value in ["e8", "lmesh", "user@host", "host.example.com", "a/b", "", "svc.ns"] {
            assert_eq!(parsed(value), None, "{value:?}");
        }
        assert!(is_fqdn("service.namespace.example.com") && is_fqdn("e8.lab."));
        assert!(!is_fqdn("e8") && !is_fqdn("10.0.0.1") && !is_fqdn("bad_name.example.com") && !is_fqdn("-a.b"));
    }

    #[test]
    fn a_destination_has_one_canonical_spelling() {
        assert_eq!(canonical_target("fc00::a4").as_deref(), Some("mesh://fc00::a4"));
        assert_eq!(canonical_target("e8").as_deref(), Some("mesh://e8"));
        assert_eq!(canonical_target("espnow://02:11:22:33:44:55").as_deref(), Some("espnow://02:11:22:33:44:55"));
        for bad in ["", "x y", "a,b", "a#b", "a?b", "a/b", "UPPER://x", "://x", "mesh://"] {
            assert_eq!(canonical_target(bad), None, "{bad:?}");
        }
    }

    struct Fake(&'static str, Option<Vec<Trail>>);
    impl Resolver for Fake {
        fn resolve(&self, target: &str) -> Result<Option<Vec<Trail>>> {
            Ok((target == self.0).then(|| self.1.clone().unwrap_or_default()))
        }
    }

    #[test]
    fn every_resolver_that_knows_a_target_contributes_candidates() {
        let a = Trail::new(Address::Unix("/a".into()), Protocol::Jsonl).with_source("a");
        let b = Trail::new(Address::Unix("/b".into()), Protocol::Jsonl).with_source("b");
        let resolvers = Resolvers::new()
            .push(Fake("x", Some(vec![a.clone()])))
            .push(Fake("x", Some(vec![b.clone()])))
            .push(Fake("y", None));
        assert_eq!(resolvers.resolve("x").unwrap(), vec![a, b]);
        assert!(resolvers.resolve("y").unwrap().is_empty());
        assert!(resolvers.resolve("z").unwrap().is_empty());
    }

    fn host(name: &str, protocol: Protocol) -> Hop {
        Hop::new(Address::Host { host: name.into(), port: None }, protocol)
    }

    #[test]
    fn a_path_has_hops_and_a_hop_has_several_equivalent_addresses() {
        // A relay circuit: dial the relay, which reaches an egress gateway, which reaches the node.
        let circuit = Trail::path(vec![
            host("relay.lab", Protocol::Quic),
            host("egress.example.com", Protocol::Https).with_metadata("sni", "egress.example.com"),
            host("e8.example.com", Protocol::Https).with_metadata("san", "spiffe://lab/e8"),
        ]);
        assert!(circuit.is_relayed());
        assert_eq!(circuit.url(), "quic://relay.lab");
        assert_eq!(circuit.protocol(), Protocol::Quic);
        assert_eq!(circuit.target_hop().metadata.get("san").map(String::as_str), Some("spiffe://lab/e8"));
        // Several DNS answers for one hop are one hop, tried in order.
        let hop = host("e8.example.com", Protocol::Https)
            .with_address(Address::Host { host: "2001:db8::8".into(), port: None });
        assert_eq!(hop.addresses.len(), 2);
        assert!(!Trail::path(vec![hop]).is_relayed());
    }

    fn order_of(policy: &dyn Policy, conditions: &Conditions, mut candidates: Vec<Trail>) -> Vec<String> {
        policy.order(conditions, &mut candidates);
        candidates.iter().map(|e| e.source.clone()).collect()
    }

    fn direct(name: &str, tradeoffs: Tradeoffs) -> Trail {
        Trail::new(Address::Host { host: name.into(), port: None }, Protocol::Quic)
            .with_tradeoffs(tradeoffs)
            .with_source(name)
    }

    #[test]
    fn the_default_policy_trades_preference_hops_wake_cost_and_latency() {
        let t = Tradeoffs::default;
        let relayed = Trail::path(vec![host("relay", Protocol::Quic), host("node", Protocol::Quic)]).with_source("relayed");
        let candidates = vec![
            direct("dear", Tradeoffs { cost: 9, ..t() }),
            direct("sleepy", Tradeoffs { wake: true, ..t() }),
            relayed,
            direct("cheap", Tradeoffs { cost: 1, ..t() }),
            direct("fast", Tradeoffs { cost: 1, latency_ms: Some(5), ..t() }),
            direct("pinned", Tradeoffs { preference: 1, wake: true, cost: 99, ..t() }),
        ];
        // An explicit preference wins; then fewer hops, no wake-up, lower cost and latency.
        assert_eq!(
            order_of(&DefaultPolicy, &Conditions::default(), candidates),
            ["pinned", "fast", "cheap", "dear", "sleepy", "relayed"]
        );
    }

    #[test]
    fn conditions_change_the_order_and_a_control_plane_ranking_can_be_trusted() {
        let t = Tradeoffs::default;
        let candidates = || vec![
            direct("metered", Tradeoffs { metered: true, ..t() }),
            direct("wakes", Tradeoffs { wake: true, ..t() }),
            Trail::path(vec![host("relay", Protocol::Quic), host("node", Protocol::Quic)]).with_source("relayed"),
            direct("plain", Tradeoffs { cost: 5, ..t() }),
        ];
        let normal = Conditions::default();
        let battery = Conditions { on_battery: true, ..normal };
        let metered = Conditions { metered_network: true, ..normal };
        assert_eq!(order_of(&DefaultPolicy, &normal, candidates()), ["metered", "plain", "wakes", "relayed"]);
        // On battery a wake-up is the last resort, even behind a relay.
        assert_eq!(order_of(&DefaultPolicy, &battery, candidates()), ["metered", "plain", "relayed", "wakes"]);
        // On a metered network a metered path goes last.
        assert_eq!(order_of(&DefaultPolicy, &metered, candidates()), ["plain", "wakes", "relayed", "metered"]);
        // A control plane that ranked the candidates is trusted as sent.
        let ranked = vec![
            direct("second", Tradeoffs { preference: 2, ..t() }),
            direct("first", Tradeoffs { preference: 1, wake: true, metered: true, ..t() }),
        ];
        assert_eq!(order_of(&PreferenceOnly, &battery, ranked), ["first", "second"]);
    }

    #[test]
    fn a_trail_says_what_follows_its_known_hops() {
        let internet = Trail::new(Address::Host { host: "e8.example.com".into(), port: None }, Protocol::Https);
        assert_eq!(internet.onward, Onward::Target);
        // A gateway that picks the rest of the path from the SNI, or from a QUIC connection ID.
        let via_sni = Trail::path(vec![host("gw.example.com", Protocol::Https)]).with_onward(Onward::Gateway(Selector::Sni));
        let via_dcid = Trail::path(vec![host("relay.lab", Protocol::Quic)]).with_onward(Onward::Gateway(Selector::ConnectionId));
        assert_ne!(via_sni.onward, via_dcid.onward);
        assert_eq!(Trail::path(vec![host("x", Protocol::Quic)]).with_onward(Onward::Unknown).onward, Onward::Unknown);
    }

    #[test]
    fn an_application_policy_replaces_the_default_order() {
        struct PreferRelayed;
        impl Policy for PreferRelayed {
            fn order(&self, _: &Conditions, candidates: &mut Vec<Trail>) {
                candidates.sort_by_key(|e| !e.is_relayed());
            }
        }
        let direct = Trail::new(Address::Unix("/d".into()), Protocol::Jsonl);
        let relayed = Trail::path(vec![host("r", Protocol::Quic), host("n", Protocol::Quic)]);
        let resolvers = Resolvers::new().push(Fake("t", Some(vec![direct.clone(), relayed.clone()])));
        assert_eq!(resolvers.resolve("t").unwrap(), vec![direct.clone(), relayed.clone()]);
        assert_eq!(
            resolvers.resolve_with("t", &Conditions::default(), &PreferRelayed).unwrap(),
            vec![relayed, direct]
        );
    }

    #[test]
    fn the_standard_order_is_local_then_discovery_then_explicit_then_dns() {
        let discovery = Fake("e8", Some(vec![Trail::new(
            Address::Host { host: "fc00::1".into(), port: None }, Protocol::Quic,
        ).with_metadata("san", "e8.lab")]));
        let resolvers = Resolvers::standard(Some(Box::new(discovery)), ports());
        // Saved discovery claims a device name and carries control-plane metadata.
        let found = resolvers.resolve("e8").unwrap();
        assert_eq!(found[0].target_hop().metadata.get("san").map(String::as_str), Some("e8.lab"));
        // An explicit address, an FQDN and an unknown name.
        assert_eq!(resolvers.resolve("10.78.0.5:3339").unwrap()[0].protocol(), Protocol::Quic);
        let dns = resolvers.resolve("service.namespace.example.com").unwrap();
        assert_eq!((dns[0].protocol(), dns[0].url()), (Protocol::Https, "https://service.namespace.example.com".into()));
        assert!(resolvers.resolve("nobody-has-this-name").unwrap().is_empty());
    }

    #[test]
    fn an_endpoint_namespace_name_is_a_run_mesh_socket() {
        let resolver = LocalServiceResolver { ports: ports() };
        let trail = resolver.resolve("health.istio").unwrap().unwrap().remove(0);
        assert_eq!(trail.url(), "unix:///run/mesh/istio/health.sock");
        assert_eq!(resolver.resolve("a.b.c").unwrap().map(|e| e.len()).unwrap_or(0), 0);
    }
}
