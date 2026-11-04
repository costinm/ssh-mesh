//! Stream routing: from a destination to where the stream goes.
//!
//! This is the gateway (ingress) side. ssh-mesh accepts many streams, serves
//! a few with handlers in this process, and forwards most to a component on
//! the same host (UDS, VM, container) or to a remote node.
//!
//! Every ingress (HTTP POST or CONNECT via hyper, SSH `direct-tcpip`,
//! WebSocket, UDS, vsock) turns an incoming stream into a [`StreamRequest`]
//! and calls [`Router::route_stream`]. Nothing here knows about URL paths:
//! the key is the destination (FQDN, IP address, or chained connection ID).
//!
//! The table has two sources:
//!
//! - static entries, from the user's config files, replaced as a whole on
//!   reload ([`RouteTable::set_static`]);
//! - dynamic entries, from verified claims ([`ClaimSink`]), held in memory
//!   with an expiry.
//!
//! Static entries always win over dynamic ones. How a claim was verified
//! (certificates, VIP derivation, signatures) is not this module's concern.
//!
//! Record forwarding by envelope `to` stays in [`mesh::route::MeshRouter`];
//! that is the message path, this is the stream path.

use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use anyhow::{Result, anyhow, bail};
use mesh::client::{MeshClient, MeshStream, MeshTarget};
use mesh::resolve::{Address as TrailAddress, Trail};
use mesh::wire::TaggedRecordHandler;

use crate::mesh_rest::{MeshServiceBackend, MeshServiceRegistry};
use mesh::tagged::NameOrTag;
use std::path::PathBuf;

/// Where an incoming stream or message wants to go.
///
/// The main sources are the HTTP `:authority` and the SSH target host
/// (`direct-tcpip`); the vhost of a [`RouteTarget::Local`] comes from the
/// same place. The CBOR payload and its `to` field are not read here: a
/// handler may use them to forward over a different transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Destination {
    /// A DNS-style name, lower case, without a trailing dot.
    Host { name: String, port: Option<u16> },
    /// An IP address, usually an IPv6 VIP.
    Ip { addr: IpAddr, port: Option<u16> },
    /// A chained stream: an opaque payload tagged with this hop's connection
    /// ID. The ID is allocated by this node (the receiver) and swapped at each
    /// hop, so it is only meaningful in this node's table.
    ConnId(u64),
}

impl Destination {
    /// Parse an authority (`host`, `host:port`, `[v6]:port`, `v6`) as sent in
    /// an HTTP `:authority`, a CONNECT target or an SSH `direct-tcpip` host.
    pub fn from_authority(authority: &str) -> Option<Self> {
        if authority.is_empty() {
            return None;
        }
        let parse_port = |p: &str| -> Option<u16> {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            p.parse().ok()
        };
        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            let end = rest.find(']')?;
            let addr: Ipv6Addr = rest[..end].parse().ok()?;
            let tail = &rest[end + 1..];
            let port = if tail.is_empty() {
                None
            } else {
                Some(parse_port(tail.strip_prefix(':')?)?)
            };
            return Some(Destination::Ip {
                addr: IpAddr::V6(addr),
                port,
            });
        } else {
            match authority.matches(':').count() {
                0 => (authority, None),
                1 => {
                    let (h, p) = authority.split_once(':')?;
                    (h, Some(parse_port(p)?))
                }
                _ => {
                    let addr: Ipv6Addr = authority.parse().ok()?;
                    return Some(Destination::Ip {
                        addr: IpAddr::V6(addr),
                        port: None,
                    });
                }
            }
        };
        if host.is_empty() {
            return None;
        }
        if let Ok(addr) = host.parse::<IpAddr>() {
            return Some(Destination::Ip { addr, port });
        }
        let name = host.strip_suffix('.').unwrap_or(host);
        if name.is_empty() {
            return None;
        }
        Some(Destination::Host {
            name: name.to_ascii_lowercase(),
            port,
        })
    }
}

/// What a route entry matches.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteMatch {
    /// One name, exactly.
    Host(String),
    /// Every name under a suffix: `HostSuffix("lab.example.m")` matches
    /// `a.lab.example.m` but not `lab.example.m` itself.
    HostSuffix(String),
    /// An address prefix: `/128` for one VIP, shorter for a range.
    IpPrefix { addr: IpAddr, len: u8 },
    /// One chained connection ID.
    ConnId(u64),
    /// Anything not matched by another entry.
    Default,
}

/// Where a matched stream goes.
#[derive(Clone)]
pub enum RouteTarget {
    /// Forward to another node or service. Several trails are alternatives
    /// (failover now, multipath later); the trail policy picks.
    Trails(Vec<Trail>),
    /// A component on this host, found by the [`Locator`] when the stream
    /// arrives (and started on demand by the [`Activator`]). A field the route
    /// leaves unset is taken from the request; an unset vhost is the physical
    /// host running ssh-mesh.
    Local {
        vhost: Option<String>,
        component: Option<String>,
    },
    /// A built-in or registered stream handler (static files, exec, the SSH
    /// server, the legacy admin app).
    Handler(Arc<dyn StreamHandler>),
}

impl RouteTarget {
    /// The first configured forwarding address, shared by stream and HTTP adapters.
    /// Selection currently uses the first trail, hop and address for both ingress types.
    pub(crate) fn first_trail_node(&self) -> Result<String> {
        let Self::Trails(trails) = self else {
            bail!("route is not a forwarding trail");
        };
        let address = trails
            .first()
            .and_then(|trail| trail.hops.first())
            .and_then(|hop| hop.addresses.first())
            .ok_or_else(|| anyhow!("route has no trail address"))?;
        trail_node(address)
    }
}

/// Who may use a route. Empty means anyone who reached the listener.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RoutePolicy {
    /// Identity patterns such as `*@example.m`.
    pub allow: Vec<String>,
    /// Only callers whose ingress is local (UDS, trusted vsock, loopback).
    pub local_only: bool,
}

/// Where an entry came from; decides precedence and expiry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteSource {
    /// From a config file, named for listings and errors.
    Static { file: String },
    /// From a verified claim by `node`, valid until `expires`.
    Dynamic { node: NodeId, expires: Instant },
}

#[derive(Clone)]
pub struct RouteEntry {
    pub matches: RouteMatch,
    pub target: RouteTarget,
    pub policy: RoutePolicy,
    pub source: RouteSource,
}

/// The ingress a stream arrived on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ingress {
    Http,
    Ssh,
    WebSocket,
    Uds,
    Vsock,
}

/// The authenticated caller of a stream, as established by the ingress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Caller {
    /// Authenticated identity (SSH principal, certificate SAN), if any.
    pub identity: Option<String>,
    pub ingress: Ingress,
    /// Set only by ingress already inside the node's trust boundary.
    pub local: bool,
}

/// An accepted stream: where it goes, who sent it, and its request header.
/// The body is passed separately.
pub struct StreamRequest {
    pub destination: Destination,
    pub caller: Caller,
    /// The request header as a record: the ingress maps HTTP or SSH request
    /// headers into it. The router does not read it; handlers may.
    pub header: mesh::tagged::TaggedRecord,
}

/// A handler that takes over a routed stream.
#[async_trait::async_trait]
pub trait StreamHandler: Send + Sync {
    async fn handle(&self, request: StreamRequest, stream: Box<dyn MeshStream>) -> Result<()>;
}

/// Identity of a node making claims, as named by the claim verifier.
pub type NodeId = String;

/// A name a node has proven it owns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Claim {
    Ip(IpAddr),
    Host(String),
}

/// Input for dynamic routes. Callers have already verified the claims.
pub trait ClaimSink: Send + Sync {
    /// `names` are owned by `node`, reachable through `trails`, until
    /// `expires`. Replaces any earlier claim by the same node.
    fn claim(&self, node: NodeId, names: Vec<Claim>, trails: Vec<Trail>, expires: Instant);
    /// Remove everything `node` claimed.
    fn withdraw(&self, node: &NodeId);
}

/// The routing table.
///
/// Lookup order: connection ID, exact host, longest host suffix, longest IP
/// prefix, default. Within one key a static entry wins over a dynamic one;
/// expired dynamic entries are ignored.
#[derive(Default)]
pub struct RouteTable {
    inner: RwLock<Inner>,
}

#[derive(Default)]
struct Inner {
    statics: Vec<RouteEntry>,
    conn_ids: Vec<(u64, RouteEntry)>,
    dynamic: Vec<(NodeId, Vec<RouteEntry>)>,
}

fn is_live(entry: &RouteEntry, now: Instant) -> bool {
    match &entry.source {
        RouteSource::Dynamic { expires, .. } => *expires > now,
        RouteSource::Static { .. } => true,
    }
}

/// Is `name` strictly under `suffix` (case-insensitive, on a label boundary)?
fn under_suffix(name: &str, suffix: &str) -> bool {
    let (n, s) = (name.as_bytes(), suffix.as_bytes());
    n.len() > s.len() + 1
        && n[n.len() - s.len() - 1] == b'.'
        && n[n.len() - s.len()..].eq_ignore_ascii_case(s)
}

fn ip_bits(addr: IpAddr) -> (u128, u8) {
    match addr {
        IpAddr::V4(a) => (u128::from(u32::from(a)), 32),
        IpAddr::V6(a) => (u128::from(a), 128),
    }
}

fn ip_contains(prefix: IpAddr, len: u8, addr: IpAddr) -> bool {
    if prefix.is_ipv4() != addr.is_ipv4() {
        return false;
    }
    let (p, width) = ip_bits(prefix);
    let (a, _) = ip_bits(addr);
    if len > width {
        return false;
    }
    if len == 0 {
        return true;
    }
    let shift = u32::from(width - len);
    (p >> shift) == (a >> shift)
}

fn default_score(m: &RouteMatch) -> Option<u32> {
    matches!(m, RouteMatch::Default).then_some(0)
}

impl Inner {
    /// The best entry by `score` (higher wins, first wins ties); static
    /// entries are tried before dynamic ones.
    fn best(
        &self,
        now: Instant,
        score: impl Fn(&RouteMatch) -> Option<u32>,
    ) -> Option<&RouteEntry> {
        fn pick<'a>(
            it: impl Iterator<Item = &'a RouteEntry>,
            score: &impl Fn(&RouteMatch) -> Option<u32>,
        ) -> Option<&'a RouteEntry> {
            let mut best: Option<(u32, &RouteEntry)> = None;
            for e in it {
                if let Some(sc) = score(&e.matches)
                    && best.is_none_or(|(b, _)| sc > b)
                {
                    best = Some((sc, e));
                }
            }
            best.map(|(_, e)| e)
        }
        pick(self.statics.iter(), &score).or_else(|| {
            pick(
                self.dynamic
                    .iter()
                    .flat_map(|(_, v)| v.iter())
                    .filter(|e| is_live(e, now)),
                &score,
            )
        })
    }
}

impl RouteTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace all static entries (startup and reload).
    pub fn set_static(&self, entries: Vec<RouteEntry>) {
        self.inner.write().unwrap().statics = entries;
    }

    /// Replace one configuration source's entries, retaining other static routes
    /// and all verified dynamic claims in the shared table.
    pub fn set_static_source(&self, file: &str, mut entries: Vec<RouteEntry>) {
        for entry in &mut entries {
            entry.source = RouteSource::Static {
                file: file.to_owned(),
            };
        }
        let mut inner = self.inner.write().unwrap();
        inner.statics.retain(|entry| !matches!(&entry.source, RouteSource::Static { file: source } if source == file));
        inner.statics.extend(entries);
    }

    /// Install a chained connection ID allocated by this node.
    pub fn bind_conn_id(&self, id: u64, target: RouteTarget) {
        let entry = RouteEntry {
            matches: RouteMatch::ConnId(id),
            target,
            policy: RoutePolicy::default(),
            source: RouteSource::Static {
                file: "conn-id".into(),
            },
        };
        let mut inner = self.inner.write().unwrap();
        inner.conn_ids.retain(|(i, _)| *i != id);
        inner.conn_ids.push((id, entry));
    }

    pub fn unbind_conn_id(&self, id: u64) {
        self.inner
            .write()
            .unwrap()
            .conn_ids
            .retain(|(i, _)| *i != id);
    }

    /// The entry for a destination, or `None` when nothing matches.
    pub fn lookup(&self, destination: &Destination) -> Option<RouteEntry> {
        let now = Instant::now();
        let inner = self.inner.read().unwrap();
        match destination {
            Destination::ConnId(id) => inner
                .conn_ids
                .iter()
                .find(|(i, _)| i == id)
                .map(|(_, e)| e.clone()),
            Destination::Host { name, .. } => inner
                .best(now, |m| match m {
                    RouteMatch::Host(h) => h.eq_ignore_ascii_case(name).then_some(0),
                    _ => None,
                })
                .or_else(|| {
                    inner.best(now, |m| match m {
                        RouteMatch::HostSuffix(s) if under_suffix(name, s) => Some(s.len() as u32),
                        _ => None,
                    })
                })
                .or_else(|| inner.best(now, default_score))
                .cloned(),
            Destination::Ip { addr, .. } => inner
                .best(now, |m| match m {
                    RouteMatch::IpPrefix { addr: p, len } if ip_contains(*p, *len, *addr) => {
                        Some(u32::from(*len))
                    }
                    _ => None,
                })
                .or_else(|| inner.best(now, default_score))
                .cloned(),
        }
    }

    /// All current entries, for the admin listing.
    pub fn entries(&self) -> Vec<RouteEntry> {
        let now = Instant::now();
        let inner = self.inner.read().unwrap();
        inner
            .statics
            .iter()
            .cloned()
            .chain(inner.conn_ids.iter().map(|(_, e)| e.clone()))
            .chain(
                inner
                    .dynamic
                    .iter()
                    .flat_map(|(_, v)| v.iter())
                    .filter(|e| is_live(e, now))
                    .cloned(),
            )
            .collect()
    }
}

impl ClaimSink for RouteTable {
    fn claim(&self, node: NodeId, names: Vec<Claim>, trails: Vec<Trail>, expires: Instant) {
        let entries = names
            .into_iter()
            .map(|c| RouteEntry {
                matches: match c {
                    Claim::Host(name) => RouteMatch::Host(name),
                    Claim::Ip(addr) => RouteMatch::IpPrefix {
                        addr,
                        len: if addr.is_ipv4() { 32 } else { 128 },
                    },
                },
                target: RouteTarget::Trails(trails.clone()),
                policy: RoutePolicy::default(),
                source: RouteSource::Dynamic {
                    node: node.clone(),
                    expires,
                },
            })
            .collect();
        let mut inner = self.inner.write().unwrap();
        let now = Instant::now();
        // Replace this node's entries and prune other nodes' expired ones.
        inner
            .dynamic
            .retain(|(n, v)| *n != node && v.iter().any(|e| is_live(e, now)));
        inner.dynamic.push((node, entries));
    }

    fn withdraw(&self, node: &NodeId) {
        self.inner
            .write()
            .unwrap()
            .dynamic
            .retain(|(n, _)| n != node);
    }
}

/// A component on this host: `(vhost, component)`, matching what gRPC and
/// HTTP gateways carry. The vhost is the authority (which VM, container or
/// host); `None` is the physical host running ssh-mesh.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Address {
    pub vhost: Option<String>,
    pub component: String,
}

impl Address {
    pub fn new(vhost: Option<&str>, component: &str) -> Self {
        Self {
            vhost: vhost.map(str::to_owned),
            component: component.to_owned(),
        }
    }
}

/// Where a located component is served.
#[derive(Clone)]
pub enum Endpoint {
    /// A component served in this process (a `Direct` backend in
    /// [`MeshServiceRegistry`]).
    InProcess(Arc<dyn TaggedRecordHandler>),
    /// A tagged-CBOR seqpacket socket (`.cbor`).
    Seqpacket(PathBuf),
    /// A JSONL stream socket.
    UdsStream(PathBuf),
    /// Inside a VM or container: open a stream to it (vsock, a trusted UDS,
    /// SSH) and deliver there.
    Forward(Arc<dyn MeshClient>),
}

/// Finds where `(vhost, component)` is served, without a pre-built table.
///
/// Checks, in order: services registered in [`MeshServiceRegistry`], the
/// component's socket path by convention ([`mesh::paths::AppPaths`]), and
/// the vhost's VM or container. A small cache of recent answers is allowed;
/// the full set is never listed, to keep memory small.
#[async_trait::async_trait]
pub trait Locator: Send + Sync {
    /// `Ok(None)` when the target does not exist and cannot be started.
    async fn locate(&self, to: &Address) -> Result<Option<Endpoint>>;
}

/// Starts targets through mesh-init, which owns process start and the UID
/// change; ssh-mesh never spawns apps itself.
#[async_trait::async_trait]
pub trait Activator: Send + Sync {
    /// Start a target that has no socket yet (mesh-init `start`: loads its
    /// config, allocates or switches the UID, spawns it).
    async fn activate(&self, to: &Address, caller: &Caller) -> Result<()>;

    /// Before connecting to a socket mesh-init owns, pass the caller's context
    /// for the socket-activated start (mesh-init `prepare_activation`).
    async fn prepare(&self, to: &Address, caller: &Caller) -> Result<()> {
        let _ = (to, caller);
        Ok(())
    }
}

/// Connects ingresses to the table and to targets.
pub struct Router {
    pub table: Arc<RouteTable>,
    /// Opens outgoing streams for [`RouteTarget::Trails`].
    pub client: Arc<dyn MeshClient>,
    /// Finds [`RouteTarget::Local`] targets.
    pub locator: Arc<dyn Locator>,
    /// `None` disables on-demand start.
    pub activator: Option<Arc<dyn Activator>>,
}

/// Why [`Router::check`] refused a stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteError {
    /// Nothing in the table matches the destination.
    NoRoute,
    /// The route's policy rejects the caller.
    Denied,
}

impl std::fmt::Display for RouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteError::NoRoute => f.write_str("no route for destination"),
            RouteError::Denied => f.write_str("caller not allowed by route policy"),
        }
    }
}

impl std::error::Error for RouteError {}

/// An identity pattern: an exact string, or a single leading `*` for a suffix.
fn identity_matches(pattern: &str, identity: &str) -> bool {
    match pattern.strip_prefix('*') {
        Some(suffix) => identity.ends_with(suffix),
        None => pattern == identity,
    }
}

fn policy_allows(policy: &RoutePolicy, caller: &Caller) -> bool {
    if policy.local_only && !caller.local {
        return false;
    }
    if policy.allow.is_empty() {
        return true;
    }
    match &caller.identity {
        Some(id) => policy.allow.iter().any(|p| identity_matches(p, id)),
        None => false,
    }
}

fn describe(destination: &Destination) -> String {
    match destination {
        Destination::Host { name, port } => match port {
            Some(p) => format!("{name}:{p}"),
            None => name.clone(),
        },
        Destination::Ip { addr, port } => match (addr, port) {
            (IpAddr::V6(_), Some(p)) => format!("[{addr}]:{p}"),
            (_, Some(p)) => format!("{addr}:{p}"),
            _ => addr.to_string(),
        },
        Destination::ConnId(id) => format!("conn-id {id}"),
    }
}

/// The node string for a trail address: `host:port` for TCP, the path for a
/// UDS (as `mesh::route::TcpClient` and `UdsClient` expect).
fn trail_node(address: &TrailAddress) -> Result<String> {
    match address {
        TrailAddress::Unix(path) => Ok(path.to_string_lossy().into_owned()),
        TrailAddress::Host {
            host,
            port: Some(port),
        } => {
            if host.contains(':') {
                Ok(format!("[{host}]:{port}"))
            } else {
                Ok(format!("{host}:{port}"))
            }
        }
        TrailAddress::Host { host, port: None } => Ok(host.clone()),
        TrailAddress::Serial(_) => bail!("serial trail addresses cannot carry streams"),
    }
}

impl Router {
    /// Look up the destination and check the policy, without touching the
    /// stream. Ingresses call this before replying, so they can answer 404 or
    /// 403; [`Self::route_stream`] calls it again.
    pub fn check(&self, request: &StreamRequest) -> Result<RouteEntry, RouteError> {
        let entry = self
            .table
            .lookup(&request.destination)
            .ok_or(RouteError::NoRoute)?;
        if policy_allows(&entry.policy, &request.caller) {
            Ok(entry)
        } else {
            Err(RouteError::Denied)
        }
    }

    fn checked_entry(&self, request: &StreamRequest) -> Result<RouteEntry> {
        self.check(request).map_err(|error| match error {
            RouteError::NoRoute => anyhow!("no route for {}", describe(&request.destination)),
            RouteError::Denied => anyhow!(
                "caller not allowed to reach {}",
                describe(&request.destination)
            ),
        })
    }

    /// Open a policy-checked target for an ingress that owns its framing.
    /// Direct targets are connected before returning; in-process handlers run
    /// behind a bounded duplex stream and report later failures through EOF.
    pub async fn open_stream(&self, request: StreamRequest) -> Result<Box<dyn MeshStream>> {
        let entry = self.checked_entry(&request)?;
        match self.open_target(request, entry.target).await? {
            ResolvedTarget::Stream(stream) => Ok(stream),
            target => {
                let (peer, server) = tokio::io::duplex(64 * 1024);
                tokio::spawn(async move {
                    if let Err(error) = target.serve(Box::new(server), "opened route").await {
                        log::debug!("routed handler session ended: {error:#}");
                    }
                });
                Ok(Box::new(peer))
            }
        }
    }

    /// Route a bidirectional stream through the node's shared table and policy.
    pub async fn route_stream(
        &self,
        request: StreamRequest,
        stream: Box<dyn MeshStream>,
    ) -> Result<()> {
        let entry = self.checked_entry(&request)?;
        let label = describe(&request.destination);
        self.open_target(request, entry.target)
            .await?
            .serve(stream, &label)
            .await
    }

    async fn open_target(
        &self,
        request: StreamRequest,
        target: RouteTarget,
    ) -> Result<ResolvedTarget> {
        match target {
            RouteTarget::Handler(handler) => Ok(ResolvedTarget::Handler(handler, request)),
            target @ RouteTarget::Trails(_) => self
                .client
                .open_stream(&MeshTarget::node(target.first_trail_node()?))
                .await
                .map(ResolvedTarget::Stream),
            RouteTarget::Local { vhost, component } => {
                let vhost = vhost.or_else(|| match &request.destination {
                    Destination::Host { name, .. } => Some(name.clone()),
                    Destination::Ip { .. } | Destination::ConnId(_) => None,
                });
                let component = match component {
                    Some(c) => c,
                    None => match &request.header.component {
                        NameOrTag::Name(c) if !c.is_empty() => c.clone(),
                        _ => bail!(
                            "no component for {}: the route sets none and the request header has no named component",
                            describe(&request.destination)
                        ),
                    },
                };
                let addr = Address {
                    vhost: vhost.clone(),
                    component: component.clone(),
                };
                let mut endpoint = self.locator.locate(&addr).await?;
                if endpoint.is_none()
                    && let Some(activator) = &self.activator
                {
                    activator.activate(&addr, &request.caller).await?;
                    endpoint = self.locator.locate(&addr).await?;
                }
                let endpoint = endpoint.ok_or_else(|| {
                    anyhow!(
                        "component {component} not found (vhost {})",
                        vhost.as_deref().unwrap_or("-")
                    )
                })?;
                if let (Endpoint::UdsStream(_), Some(activator)) = (&endpoint, &self.activator)
                    && let Err(e) = activator.prepare(&addr, &request.caller).await
                {
                    // The socket may not be mesh-init's; connect anyway.
                    log::debug!(
                        "route_stream: prepare_activation for {}: {e:#}",
                        addr.component
                    );
                }
                self.open_endpoint(endpoint, &addr).await
            }
        }
    }

    async fn open_endpoint(&self, endpoint: Endpoint, addr: &Address) -> Result<ResolvedTarget> {
        match endpoint {
            Endpoint::InProcess(handler) => Ok(ResolvedTarget::Component(handler)),
            Endpoint::Seqpacket(_) => {
                bail!("seqpacket endpoints not supported by route_stream yet")
            }
            Endpoint::UdsStream(path) => Ok(ResolvedTarget::Stream(Box::new(
                tokio::net::UnixStream::connect(path).await?,
            ))),
            Endpoint::Forward(client) => {
                let node = addr.vhost.as_deref().unwrap_or(&addr.component);
                client
                    .open_stream(&MeshTarget::node(node))
                    .await
                    .map(ResolvedTarget::Stream)
            }
        }
    }
}

// Resolution is shared by channel-based ingresses and ingresses that already
// own a stream. The latter retain synchronous handler/session error propagation.
enum ResolvedTarget {
    Stream(Box<dyn MeshStream>),
    Handler(Arc<dyn StreamHandler>, StreamRequest),
    Component(Arc<dyn TaggedRecordHandler>),
}

impl ResolvedTarget {
    async fn serve(self, mut stream: Box<dyn MeshStream>, label: &str) -> Result<()> {
        match self {
            Self::Stream(upstream) => {
                crate::utils::bridge(stream, upstream, label).await;
                Ok(())
            }
            Self::Handler(handler, request) => handler.handle(request, stream).await,
            Self::Component(handler) => {
                mesh::wire::serve_cbor_session(&mut stream, &DynHandler(handler)).await
            }
        }
    }
}

/// Adapts a shared handler to the `Sized` bound of `serve_cbor_session`.
struct DynHandler(Arc<dyn TaggedRecordHandler>);

#[async_trait::async_trait]
impl TaggedRecordHandler for DynHandler {
    async fn handle_record(
        &self,
        record: mesh::tagged::TaggedRecord,
    ) -> Result<Option<mesh::tagged::TaggedRecord>> {
        self.0.handle_record(record).await
    }

    async fn forward_record(
        &self,
        record: mesh::tagged::TaggedRecord,
    ) -> Result<Option<mesh::tagged::TaggedRecord>> {
        self.0.forward_record(record).await
    }
}

/// Finds components: services registered in [`MeshServiceRegistry`], else
/// the component's mesh socket path by convention ([`mesh::paths::AppPaths`]).
pub struct ConventionLocator {
    pub services: MeshServiceRegistry,
    /// Domain names this host terminates: the names of its certificates
    /// ([`crate::certs::cert_dir_names`]).
    /// A vhost matching one of them means the physical host.
    pub local_names: Vec<String>,
}

#[async_trait::async_trait]
impl Locator for ConventionLocator {
    async fn locate(&self, to: &Address) -> Result<Option<Endpoint>> {
        // A named vhost other than this host is a VM or container; looking
        // those up comes later.
        if let Some(vhost) = &to.vhost
            && !crate::certs::is_local_name(&self.local_names, vhost)
        {
            return Ok(None);
        }
        if let Ok(service) = self.services.service(&to.component) {
            return Ok(Some(match service.backend {
                MeshServiceBackend::Direct(handler) => Endpoint::InProcess(handler),
                MeshServiceBackend::UdsStream(path) => Endpoint::UdsStream(path),
                MeshServiceBackend::UdsSeqpacket(path) => Endpoint::Seqpacket(path),
            }));
        }
        mesh::config::validate_service_name(&to.component)
            .map_err(|reason| anyhow!("invalid routed component: {reason}"))?;
        let path = mesh::paths::AppPaths::for_app(&to.component)
            .mesh_socket()
            .clone();
        let mut cbor = path.clone().into_os_string();
        cbor.push(".cbor");
        let cbor = PathBuf::from(cbor);
        // Prefer the stream socket while route_stream cannot bridge
        // seqpacket record by record.
        if path.exists() {
            Ok(Some(Endpoint::UdsStream(path)))
        } else if cbor.exists() {
            Ok(Some(Endpoint::Seqpacket(cbor)))
        } else {
            Ok(None)
        }
    }
}

/// Starts components through mesh-init.
pub struct MeshInitActivator;

fn activation_context(caller: &Caller) -> mesh::protocol::ActivationContext {
    mesh::protocol::ActivationContext {
        kind: "route-stream".to_string(),
        user: caller.identity.clone().unwrap_or_default(),
        certificate_user: caller.identity.clone(),
        ..Default::default()
    }
}

#[async_trait::async_trait]
impl Activator for MeshInitActivator {
    async fn activate(&self, to: &Address, caller: &Caller) -> Result<()> {
        crate::sshd::mesh_init_request(&mesh::protocol::Request::Start {
            name: to.component.clone(),
            args: Vec::new(),
            env: Default::default(),
            context: Some(activation_context(caller)),
        })
        .await
    }

    async fn prepare(&self, to: &Address, caller: &Caller) -> Result<()> {
        crate::sshd::prepare_activation(&to.component, activation_context(caller)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mesh::resolve::{Address as RAddress, Protocol};
    use std::time::Duration;

    fn trail(host: &str) -> Trail {
        Trail::new(
            RAddress::Host {
                host: host.into(),
                port: Some(22),
            },
            Protocol::Ssh,
        )
    }

    fn st(m: RouteMatch, tag: &str) -> RouteEntry {
        RouteEntry {
            matches: m,
            target: RouteTarget::Trails(vec![trail(tag)]),
            policy: RoutePolicy::default(),
            source: RouteSource::Static { file: tag.into() },
        }
    }

    fn file(e: &Option<RouteEntry>) -> Option<String> {
        match &e.as_ref()?.source {
            RouteSource::Static { file } => Some(file.clone()),
            RouteSource::Dynamic { node, .. } => Some(format!("dyn:{node}")),
        }
    }

    fn host(n: &str) -> Destination {
        Destination::Host {
            name: n.into(),
            port: None,
        }
    }

    fn ip(a: &str) -> Destination {
        Destination::Ip {
            addr: a.parse().unwrap(),
            port: None,
        }
    }

    fn pfx(a: &str, len: u8) -> RouteMatch {
        RouteMatch::IpPrefix {
            addr: a.parse().unwrap(),
            len,
        }
    }

    fn later() -> Instant {
        Instant::now() + Duration::from_secs(3600)
    }

    fn first_host(e: &RouteEntry) -> String {
        match &e.target {
            RouteTarget::Trails(v) => match v[0].address() {
                RAddress::Host { host, .. } => host.clone(),
                _ => panic!("not a host"),
            },
            _ => panic!("not trails"),
        }
    }

    #[test]
    fn authority_forms() {
        let d = Destination::from_authority;
        assert_eq!(d("example.m"), Some(host("example.m")));
        assert_eq!(
            d("example.m:443"),
            Some(Destination::Host {
                name: "example.m".into(),
                port: Some(443)
            })
        );
        assert_eq!(d("[fd00::1]"), Some(ip("fd00::1")));
        assert_eq!(
            d("[fd00::1]:22"),
            Some(Destination::Ip {
                addr: "fd00::1".parse().unwrap(),
                port: Some(22)
            })
        );
        assert_eq!(d("fd00::1"), Some(ip("fd00::1")));
        assert_eq!(d("10.0.0.1"), Some(ip("10.0.0.1")));
        assert_eq!(
            d("10.0.0.1:80"),
            Some(Destination::Ip {
                addr: "10.0.0.1".parse().unwrap(),
                port: Some(80)
            })
        );
    }

    #[test]
    fn authority_normalises_and_rejects() {
        let d = Destination::from_authority;
        assert_eq!(d("Foo.Example.M."), Some(host("foo.example.m")));
        assert_eq!(
            d("Foo.M.:8080"),
            Some(Destination::Host {
                name: "foo.m".into(),
                port: Some(8080)
            })
        );
        for bad in [
            "",
            ":80",
            "host:",
            "host:abc",
            "host:70000",
            "host:-1",
            "[fd00::1",
            "[fd00::1]x",
            "[fd00::1]:",
            "[fd00::1]:x",
            "[]",
            "[example]:1",
            ".",
            "a:b:c",
            "[::1]:99999",
        ] {
            assert_eq!(d(bad), None, "{bad}");
        }
    }

    #[test]
    fn host_precedence() {
        let t = RouteTable::new();
        t.set_static(vec![
            st(RouteMatch::Default, "default"),
            st(RouteMatch::HostSuffix("example.m".into()), "wide"),
            st(RouteMatch::HostSuffix("lab.example.m".into()), "lab"),
            st(RouteMatch::Host("a.lab.example.m".into()), "exact"),
        ]);
        assert_eq!(file(&t.lookup(&host("a.lab.example.m"))).unwrap(), "exact");
        assert_eq!(file(&t.lookup(&host("A.LAB.example.m"))).unwrap(), "exact");
        assert_eq!(file(&t.lookup(&host("b.lab.example.m"))).unwrap(), "lab");
        assert_eq!(file(&t.lookup(&host("x.y.lab.example.m"))).unwrap(), "lab");
        assert_eq!(file(&t.lookup(&host("b.example.m"))).unwrap(), "wide");
        assert_eq!(file(&t.lookup(&host("other.org"))).unwrap(), "default");
    }

    #[test]
    fn suffix_boundaries() {
        let t = RouteTable::new();
        t.set_static(vec![st(
            RouteMatch::HostSuffix("lab.example.m".into()),
            "lab",
        )]);
        assert!(t.lookup(&host("a.lab.example.m")).is_some());
        assert!(t.lookup(&host("lab.example.m")).is_none());
        assert!(t.lookup(&host("xlab.example.m")).is_none());
        assert!(t.lookup(&host(".lab.example.m")).is_none());
    }

    #[test]
    fn ip_prefixes() {
        let t = RouteTable::new();
        t.set_static(vec![
            st(RouteMatch::Default, "default"),
            st(pfx("fd00::", 16), "p16"),
            st(pfx("fd00:1::", 32), "p32"),
            st(pfx("fd00:1::5", 128), "vip"),
            st(pfx("10.1.0.0", 16), "v4"),
        ]);
        assert_eq!(file(&t.lookup(&ip("fd00:1::5"))).unwrap(), "vip");
        assert_eq!(file(&t.lookup(&ip("fd00:1::6"))).unwrap(), "p32");
        assert_eq!(file(&t.lookup(&ip("fd00:2::1"))).unwrap(), "p16");
        assert_eq!(file(&t.lookup(&ip("fe80::1"))).unwrap(), "default");
        assert_eq!(file(&t.lookup(&ip("10.1.2.3"))).unwrap(), "v4");
        assert_eq!(file(&t.lookup(&ip("10.2.0.1"))).unwrap(), "default");
    }

    #[test]
    fn family_mismatch() {
        let t = RouteTable::new();
        t.set_static(vec![
            st(pfx("::", 0), "v6all"),
            st(pfx("0.0.0.0", 0), "v4all"),
        ]);
        assert_eq!(file(&t.lookup(&ip("10.0.0.1"))).unwrap(), "v4all");
        assert_eq!(file(&t.lookup(&ip("fd00::1"))).unwrap(), "v6all");
        t.set_static(vec![st(pfx("10.0.0.0", 8), "v4")]);
        assert!(t.lookup(&ip("::a00:1")).is_none());
        assert!(t.lookup(&ip("fd00::1")).is_none());
    }

    #[test]
    fn static_beats_dynamic() {
        let t = RouteTable::new();
        t.claim(
            "n1".into(),
            vec![Claim::Host("a.m".into())],
            vec![trail("n1")],
            later(),
        );
        assert_eq!(file(&t.lookup(&host("a.m"))).unwrap(), "dyn:n1");
        t.set_static(vec![st(RouteMatch::Host("a.m".into()), "static")]);
        assert_eq!(file(&t.lookup(&host("a.m"))).unwrap(), "static");
        // A dynamic exact still beats a static suffix.
        t.set_static(vec![st(RouteMatch::HostSuffix("m".into()), "suffix")]);
        assert_eq!(file(&t.lookup(&host("a.m"))).unwrap(), "dyn:n1");
        assert_eq!(file(&t.lookup(&host("b.m"))).unwrap(), "suffix");
    }

    #[test]
    fn expired_ignored() {
        let t = RouteTable::new();
        let past = Instant::now() - Duration::from_secs(1);
        t.claim(
            "n1".into(),
            vec![
                Claim::Host("a.m".into()),
                Claim::Ip("fd00::1".parse().unwrap()),
            ],
            vec![trail("n1")],
            past,
        );
        assert!(t.lookup(&host("a.m")).is_none());
        assert!(t.lookup(&ip("fd00::1")).is_none());
        assert!(t.entries().is_empty());
    }

    #[test]
    fn claim_entries_replace_withdraw() {
        let t = RouteTable::new();
        let exp = later();
        t.claim(
            "n1".into(),
            vec![
                Claim::Host("a.m".into()),
                Claim::Ip("fd00::1".parse().unwrap()),
                Claim::Ip("10.0.0.1".parse().unwrap()),
            ],
            vec![trail("n1")],
            exp,
        );
        let e = t.entries();
        assert_eq!(e.len(), 3);
        assert_eq!(e[0].matches, RouteMatch::Host("a.m".into()));
        assert_eq!(e[1].matches, pfx("fd00::1", 128));
        assert_eq!(e[2].matches, pfx("10.0.0.1", 32));
        assert_eq!(
            e[0].source,
            RouteSource::Dynamic {
                node: "n1".into(),
                expires: exp
            }
        );
        assert!(matches!(&e[0].target, RouteTarget::Trails(v) if v.len() == 1));
        assert!(t.lookup(&ip("fd00::1")).is_some());

        t.claim(
            "n2".into(),
            vec![Claim::Host("b.m".into())],
            vec![trail("n2")],
            exp,
        );
        t.claim(
            "n1".into(),
            vec![Claim::Host("c.m".into())],
            vec![trail("n1")],
            exp,
        );
        assert!(t.lookup(&host("a.m")).is_none());
        assert!(t.lookup(&ip("fd00::1")).is_none());
        assert!(t.lookup(&host("c.m")).is_some());
        assert!(t.lookup(&host("b.m")).is_some());

        t.withdraw(&"n1".to_string());
        assert!(t.lookup(&host("c.m")).is_none());
        assert!(t.lookup(&host("b.m")).is_some());
        t.withdraw(&"nobody".to_string());
        assert_eq!(t.entries().len(), 1);
    }

    #[test]
    fn conn_id_bind_rebind_unbind() {
        let t = RouteTable::new();
        t.set_static(vec![st(RouteMatch::Default, "default")]);
        assert!(t.lookup(&Destination::ConnId(7)).is_none());
        t.bind_conn_id(7, RouteTarget::Trails(vec![trail("a")]));
        let e = t.lookup(&Destination::ConnId(7)).unwrap();
        assert_eq!(e.matches, RouteMatch::ConnId(7));
        assert_eq!(
            e.source,
            RouteSource::Static {
                file: "conn-id".into()
            }
        );
        assert_eq!(first_host(&e), "a");
        t.bind_conn_id(7, RouteTarget::Trails(vec![trail("b")]));
        let e = t.lookup(&Destination::ConnId(7)).unwrap();
        assert_eq!(first_host(&e), "b");
        assert_eq!(t.entries().len(), 2);
        // Default does not match conn IDs, and conn IDs are not host entries.
        assert_eq!(file(&t.lookup(&host("x"))).unwrap(), "default");
        assert!(t.lookup(&Destination::ConnId(8)).is_none());
        t.unbind_conn_id(7);
        assert!(t.lookup(&Destination::ConnId(7)).is_none());
        t.unbind_conn_id(7);
        assert_eq!(t.entries().len(), 1);
    }

    #[test]
    fn set_static_replaces() {
        let t = RouteTable::new();
        t.set_static(vec![
            st(RouteMatch::Host("a.m".into()), "one"),
            st(RouteMatch::Host("b.m".into()), "one"),
        ]);
        t.bind_conn_id(1, RouteTarget::Trails(vec![]));
        t.claim("n".into(), vec![Claim::Host("d.m".into())], vec![], later());
        t.set_static(vec![st(RouteMatch::Host("c.m".into()), "two")]);
        assert!(t.lookup(&host("a.m")).is_none());
        assert!(t.lookup(&host("c.m")).is_some());
        // Order: static, conn-id, dynamic.
        let m: Vec<_> = t.entries().into_iter().map(|e| e.matches).collect();
        assert_eq!(
            m,
            vec![
                RouteMatch::Host("c.m".into()),
                RouteMatch::ConnId(1),
                RouteMatch::Host("d.m".into())
            ]
        );
        t.set_static(vec![]);
        assert_eq!(t.entries().len(), 2);
    }

    // ---- route_stream, policy, locator ----

    use mesh::tagged::TaggedRecord;
    use mesh::wire::{TaggedRecordHandler, read_cbor_record, response_ok, write_cbor_record};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct NoClient;

    #[async_trait::async_trait]
    impl MeshClient for NoClient {
        async fn open_stream(&self, _t: &MeshTarget) -> Result<Box<dyn MeshStream>> {
            bail!("unused client")
        }
    }

    struct WriteOk;

    #[async_trait::async_trait]
    impl StreamHandler for WriteOk {
        async fn handle(&self, _r: StreamRequest, mut s: Box<dyn MeshStream>) -> Result<()> {
            s.write_all(b"ok").await?;
            s.shutdown().await?;
            Ok(())
        }
    }

    struct Pong;

    #[async_trait::async_trait]
    impl TaggedRecordHandler for Pong {
        async fn handle_record(&self, record: TaggedRecord) -> Result<Option<TaggedRecord>> {
            Ok(record
                .id
                .map(|id| response_ok(id, serde_json::json!("pong"))))
        }
    }

    fn router_with(services: MeshServiceRegistry, client: Arc<dyn MeshClient>) -> Router {
        Router {
            table: Arc::new(RouteTable::new()),
            client,
            locator: Arc::new(ConventionLocator {
                services,
                local_names: vec![],
            }),
            activator: None,
        }
    }

    fn router() -> Router {
        router_with(MeshServiceRegistry::default(), Arc::new(NoClient))
    }

    #[tokio::test]
    async fn component_lookup_rejects_paths_outside_the_service_namespace() {
        let locator = ConventionLocator {
            services: Default::default(),
            local_names: vec![],
        };
        for component in ["..", "../mesh-init", "/run/mesh/mesh-init"] {
            assert!(
                locator
                    .locate(&Address::new(None, component))
                    .await
                    .is_err()
            );
        }
    }

    /// A registry serving `name` in process with [`Pong`].
    fn services_with(name: &str) -> MeshServiceRegistry {
        let services = MeshServiceRegistry::default();
        services.register(
            name,
            crate::mesh_rest::MeshService {
                backend: MeshServiceBackend::Direct(Arc::new(Pong)),
                encoding: crate::mesh_rest::MeshServiceEncoding::TaggedCbor,
                component: name.to_owned(),
            },
        );
        services
    }

    fn caller(identity: Option<&str>, local: bool) -> Caller {
        Caller {
            identity: identity.map(str::to_owned),
            ingress: Ingress::Http,
            local,
        }
    }

    fn req(dest: &str, c: Caller) -> StreamRequest {
        StreamRequest {
            destination: Destination::from_authority(dest).unwrap(),
            caller: c,
            header: TaggedRecord::default(),
        }
    }

    fn route(r: &Router, target: RouteTarget, policy: RoutePolicy) {
        r.table.set_static(vec![RouteEntry {
            matches: RouteMatch::Default,
            target,
            policy,
            source: RouteSource::Static { file: "t".into() },
        }]);
    }

    fn duplex() -> (Box<dyn MeshStream>, tokio::io::DuplexStream) {
        let (a, b) = tokio::io::duplex(4096);
        (Box::new(a), b)
    }

    #[tokio::test]
    async fn no_route_is_error() {
        let r = router();
        let (s, _peer) = duplex();
        let e = r
            .route_stream(req("x.m", caller(None, true)), s)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("no route for x.m"), "{e}");
        assert_eq!(
            r.check(&req("x.m", caller(None, true))).err(),
            Some(RouteError::NoRoute)
        );
    }

    #[tokio::test]
    async fn local_only_denies_remote_caller() {
        let r = router();
        route(
            &r,
            RouteTarget::Handler(Arc::new(WriteOk)),
            RoutePolicy {
                local_only: true,
                allow: vec![],
            },
        );
        let (s, _peer) = duplex();
        let e = r
            .route_stream(req("x.m", caller(None, false)), s)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("not allowed"), "{e}");
        assert_eq!(
            r.check(&req("x.m", caller(None, false))).err(),
            Some(RouteError::Denied)
        );
        assert!(r.check(&req("x.m", caller(None, true))).is_ok());
    }

    #[tokio::test]
    async fn allow_pattern_denies_and_suffix_allows() {
        let r = router();
        route(
            &r,
            RouteTarget::Handler(Arc::new(WriteOk)),
            RoutePolicy {
                local_only: false,
                allow: vec!["root@h".into(), "*@example.m".into()],
            },
        );
        for id in [
            None,
            Some("bob@other.m"),
            Some("example.m"),
            Some("root@h2"),
        ] {
            let (s, _peer) = duplex();
            assert!(
                r.route_stream(req("x.m", caller(id, true)), s)
                    .await
                    .is_err(),
                "{id:?}"
            );
        }
        for id in ["alice@example.m", "root@h"] {
            let (s, mut peer) = duplex();
            r.route_stream(req("x.m", caller(Some(id), false)), s)
                .await
                .unwrap();
            let mut out = String::new();
            peer.read_to_string(&mut out).await.unwrap();
            assert_eq!(out, "ok");
        }
    }

    #[tokio::test]
    async fn handler_target_receives_stream() {
        let r = router();
        route(
            &r,
            RouteTarget::Handler(Arc::new(WriteOk)),
            RoutePolicy::default(),
        );
        let (s, mut peer) = duplex();
        r.route_stream(req("x.m", caller(None, false)), s)
            .await
            .unwrap();
        let mut out = String::new();
        peer.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "ok");
    }

    fn local_request(dest: &str, component: &str) -> StreamRequest {
        let mut r = req(dest, caller(None, true));
        r.header.component = NameOrTag::Name(component.into());
        r
    }

    #[tokio::test]
    async fn local_in_process_serves_cbor_session() {
        let r = router_with(services_with("ping"), Arc::new(NoClient));
        // An IP destination gives no vhost, so the convention locator can answer.
        route(
            &r,
            RouteTarget::Local {
                vhost: None,
                component: None,
            },
            RoutePolicy::default(),
        );
        let (s, mut peer) = duplex();
        let task =
            tokio::spawn(async move { r.route_stream(local_request("10.0.0.1", "ping"), s).await });
        let request = TaggedRecord {
            component: NameOrTag::Name("ping".into()),
            method: NameOrTag::Name("ping".into()),
            id: Some(serde_json::json!(1)),
            ..Default::default()
        };
        write_cbor_record(&mut peer, &request).await.unwrap();
        let reply = read_cbor_record(&mut peer).await.unwrap().unwrap();
        assert_eq!(reply.result, Some(serde_json::json!("pong")));
        drop(peer);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn local_missing_component_and_hostname_vhost() {
        let r = router_with(services_with("ping"), Arc::new(NoClient));
        route(
            &r,
            RouteTarget::Local {
                vhost: None,
                component: None,
            },
            RoutePolicy::default(),
        );
        // Host destination makes the vhost Some, which the convention locator
        // does not resolve yet.
        let (s, _p) = duplex();
        let e = r
            .route_stream(local_request("a.m", "ping"), s)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("not found"), "{e}");
        // No component anywhere.
        let (s, _p) = duplex();
        let e = r
            .route_stream(req("10.0.0.1", caller(None, true)), s)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("no component"), "{e}");
        // Seqpacket is refused.
        struct Seq;
        #[async_trait::async_trait]
        impl Locator for Seq {
            async fn locate(&self, _t: &Address) -> Result<Option<Endpoint>> {
                Ok(Some(Endpoint::Seqpacket("/x".into())))
            }
        }
        let mut r2 = router();
        r2.locator = Arc::new(Seq);
        route(
            &r2,
            RouteTarget::Local {
                vhost: None,
                component: Some("c".into()),
            },
            RoutePolicy::default(),
        );
        let (s, _p) = duplex();
        let e = r2
            .route_stream(req("a.m", caller(None, true)), s)
            .await
            .unwrap_err();
        assert!(e.to_string().contains("seqpacket endpoints not supported"));
    }

    #[tokio::test]
    async fn activator_runs_once_then_locates_again() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Flip(Arc<AtomicBool>);
        #[async_trait::async_trait]
        impl Locator for Flip {
            async fn locate(&self, _t: &Address) -> Result<Option<Endpoint>> {
                Ok(self
                    .0
                    .load(Ordering::SeqCst)
                    .then(|| Endpoint::InProcess(Arc::new(Pong))))
            }
        }
        #[async_trait::async_trait]
        impl Activator for Flip {
            async fn activate(&self, _t: &Address, _c: &Caller) -> Result<()> {
                self.0.store(true, Ordering::SeqCst);
                Ok(())
            }
        }
        let flag = Arc::new(AtomicBool::new(false));
        let mut r = router_with(services_with("c"), Arc::new(NoClient));
        r.locator = Arc::new(Flip(flag.clone()));
        r.activator = Some(Arc::new(Flip(flag.clone())));
        route(
            &r,
            RouteTarget::Local {
                vhost: None,
                component: Some("c".into()),
            },
            RoutePolicy::default(),
        );
        let (s, peer) = duplex();
        drop(peer);
        r.route_stream(req("a.m", caller(None, true)), s)
            .await
            .unwrap();
        assert!(flag.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn convention_locator() {
        let l = ConventionLocator {
            services: services_with("here"),
            local_names: vec!["node1.example.m".into()],
        };
        assert!(matches!(
            l.locate(&Address::new(None, "here")).await.unwrap(),
            Some(Endpoint::InProcess(_))
        ));
        // This host's own name is the physical host.
        assert!(matches!(
            l.locate(&Address::new(Some("NODE1.example.m"), "here"))
                .await
                .unwrap(),
            Some(Endpoint::InProcess(_))
        ));
        // Another vhost is not resolved yet, even for a registered component.
        assert!(
            l.locate(&Address::new(Some("vm1"), "here"))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            l.locate(&Address::new(None, "no-such-component-xyz"))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn trails_forward_to_tcp() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut c, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            c.read_exact(&mut buf).await.unwrap();
            c.write_all(&buf).await.unwrap();
        });
        let r = router_with(
            MeshServiceRegistry::default(),
            Arc::new(mesh::route::TcpClient),
        );
        route(
            &r,
            RouteTarget::Trails(vec![Trail::new(
                RAddress::Host {
                    host: "127.0.0.1".into(),
                    port: Some(port),
                },
                Protocol::Ssh,
            )]),
            RoutePolicy::default(),
        );
        let (s, mut peer) = duplex();
        let task =
            tokio::spawn(async move { r.route_stream(req("far.m", caller(None, false)), s).await });
        peer.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        peer.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        drop(peer);
        task.await.unwrap().unwrap();
    }
}
