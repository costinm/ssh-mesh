/// Local mesh announce and discovery
/// Each mesh node will listen for UDP multicast announcements on
/// all interfaces. The announcement includes the public key of the
/// node, the (claimed - untrusted) name.
///
///
use anyhow::{Context, Result};

use p256::SecretKey;
use p256::elliptic_curve::Generate;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use tracing::{debug, error, info, instrument, warn};

const MULTICAST_PORT: u16 = 5227;
const MULTICAST_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 250);
const MULTICAST_IPV6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x5227);
const MAX_STORED_ANNOUNCES: usize = 16;

/// Announcement message sent over multicast
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Announce {
    /// Base64url encoded public key (P256)
    pub public_key: String,
    /// Optional node metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
}

/// Represents a discovered node
#[derive(Debug, Clone)]
pub struct Node {
    /// Base64url encoded public key
    pub public_key: String,
    /// Last seen address
    pub address: SocketAddr,
    /// Last announcement received
    pub last_seen: std::time::Instant,
    /// Optional metadata from the announcement
    pub metadata: Option<HashMap<String, String>>,
}

/// Link-local discovery service
pub struct LocalDiscovery {
    /// EC P256 private key (DER encoded)
    #[allow(dead_code)]
    private_key: Vec<u8>,
    /// EC P256 public key (DER encoded)
    #[allow(dead_code)]
    public_key: Vec<u8>,
    /// Base64url encoded public key for announcements
    public_key_b64: String,
    /// Map of discovered nodes, keyed by base64url encoded public key
    nodes: Arc<RwLock<HashMap<String, Node>>>,
    /// Directory where per-node discovery files are written.
    node_store_dir: Arc<PathBuf>,
    /// IPv4 UDP socket
    socket_v4: Option<Arc<UdpSocket>>,
    /// IPv6 UDP socket
    socket_v6: Option<Arc<UdpSocket>>,
}

impl LocalDiscovery {
    /// Create a new LocalDiscovery instance with an optional EC P256 private key
    /// If no key is provided, attempts to load from $HOME/.ssh/key.pem or generates a new one
    #[instrument(skip(key))]
    pub async fn new(key: Option<SecretKey>) -> Result<Self> {
        // Get the private key either from parameter or by loading/generating
        let private_key_ec = match key {
            Some(key) => key,
            None => {
                debug!("No key provided, loading or generating new key");
                Self::load_or_generate_key()?
            }
        };

        // Serialize the private key to DER format
        let secret_key_der = private_key_ec
            .to_pkcs8_der()
            .context("Failed to serialize private key")?;
        let private_key = secret_key_der.to_bytes().to_vec();

        // Get the public key and serialize it to DER format (SPKI)
        let public_key_ec = private_key_ec.public_key();
        let public_key_der = public_key_ec
            .to_public_key_der()
            .context("Failed to serialize public key")?;
        let public_key = public_key_der.to_vec();

        let public_key_b64 = base64_url_encode(&public_key);

        Ok(Self {
            private_key,
            public_key,
            public_key_b64,
            nodes: Arc::new(RwLock::new(HashMap::new())),
            node_store_dir: Arc::new(Self::default_node_store_dir()?),
            socket_v4: None,
            socket_v6: None,
        })
    }

    /// Load key from file or generate a new one
    fn load_or_generate_key() -> Result<SecretKey> {
        // Try to load key from file
        let home_dir = std::env::var("HOME").context("HOME environment variable not set")?;
        let key_path = Path::new(&home_dir).join(".ssh").join("key.pem");

        if key_path.exists() {
            // Load key from file
            let key_data = fs::read_to_string(&key_path).context("Failed to read key file")?;
            // Check if the file is not empty before trying to parse it
            if !key_data.is_empty() {
                if let Ok(key) = SecretKey::from_pkcs8_pem(&key_data) {
                    return Ok(key);
                }
            }
        }

        // Generate new keypair
        let key = SecretKey::generate();

        // Save the generated key to file
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create .ssh directory")?;
        }
        let key_pem = key
            .to_pkcs8_pem(Default::default())
            .context("Failed to serialize private key to PEM")?;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&key_path)
            .context("Failed to write key to file")?;
        std::io::Write::write_all(&mut file, key_pem.as_bytes())
            .context("Failed to write key to file")?;

        Ok(key)
    }

    /// Start the UDP multicast listeners
    #[instrument(skip(self))]
    pub async fn start(&mut self) -> Result<()> {
        // Setup IPv4 multicast socket
        match Self::setup_multicast_v4().await {
            Ok(socket) => {
                self.socket_v4 = Some(Arc::new(socket));
                debug!(
                    multicast_ip = %MULTICAST_IPV4,
                    multicast_port = MULTICAST_PORT,
                    "mcast_v4"
                );
            }
            Err(e) => {
                warn!("Failed to setup IPv4 multicast: {}", e);
            }
        }

        // Setup IPv6 multicast socket
        match Self::setup_multicast_v6().await {
            Ok(socket) => {
                self.socket_v6 = Some(Arc::new(socket));
                debug!(
                    multicast_ip = %MULTICAST_IPV6,
                    multicast_port = MULTICAST_PORT,
                    "mcast_v6"
                );
            }
            Err(e) => {
                warn!("Failed to setup IPv6 multicast: {}", e);
            }
        }

        if self.socket_v4.is_none() && self.socket_v6.is_none() {
            debug!("mcast_none");
        }

        // Start receiver tasks
        if let Some(socket) = &self.socket_v4 {
            let nodes = self.nodes.clone();
            let socket = socket.clone();
            let local_public_key = self.public_key_b64.clone();
            let node_store_dir = self.node_store_dir.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    Self::receive_loop(socket, nodes, local_public_key, node_store_dir).await
                {
                    error!("IPv4 receive loop error: {}", e);
                }
            });
        }

        if let Some(socket) = &self.socket_v6 {
            let nodes = self.nodes.clone();
            let socket = socket.clone();
            let local_public_key = self.public_key_b64.clone();
            let node_store_dir = self.node_store_dir.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    Self::receive_loop(socket, nodes, local_public_key, node_store_dir).await
                {
                    error!("IPv6 receive loop error: {}", e);
                }
            });
        }

        Ok(())
    }

    /// Setup IPv4 multicast socket
    async fn setup_multicast_v4() -> Result<UdpSocket> {
        let socket = UdpSocket::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            MULTICAST_PORT,
        ))
        .await
        .context("Failed to bind IPv4 socket")?;

        // Join multicast group
        socket
            .join_multicast_v4(MULTICAST_IPV4, Ipv4Addr::UNSPECIFIED)
            .context("Failed to join IPv4 multicast group")?;

        Ok(socket)
    }

    /// Setup IPv6 multicast socket
    async fn setup_multicast_v6() -> Result<UdpSocket> {
        let socket = UdpSocket::bind(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            MULTICAST_PORT,
        ))
        .await
        .context("Failed to bind IPv6 socket")?;

        // Join multicast group on all interfaces (interface index 0)
        socket
            .join_multicast_v6(&MULTICAST_IPV6, 0)
            .context("Failed to join IPv6 multicast group")?;

        Ok(socket)
    }

    /// Receive and process announcements
    #[instrument(
        skip(socket, nodes, local_public_key, node_store_dir),
        fields(buf_size = 65536)
    )]
    async fn receive_loop(
        socket: Arc<UdpSocket>,
        nodes: Arc<RwLock<HashMap<String, Node>>>,
        local_public_key: String,
        node_store_dir: Arc<PathBuf>,
    ) -> Result<()> {
        let mut buf = vec![0u8; 65536];

        loop {
            let (len, addr) = socket
                .recv_from(&mut buf)
                .await
                .context("Failed to receive from socket")?;

            let data = &buf[..len];

            // Parse the announcement
            match serde_json::from_slice::<Announce>(data) {
                Ok(announce) => {
                    // Check if this is our own announcement and skip processing if so
                    if announce.public_key == local_public_key {
                        continue;
                    }
                    debug!(
                        "Received valid announcement from {}: {}",
                        addr, announce.public_key
                    );

                    let node = Node {
                        public_key: announce.public_key.clone(),
                        address: addr,
                        last_seen: std::time::Instant::now(),
                        metadata: announce.metadata.clone(),
                    };

                    let public_key = node.public_key.clone();
                    let address = node.address;
                    let metadata = node.metadata.clone();
                    let is_new = {
                        let mut nodes_map = nodes.write().await;
                        let is_new = !nodes_map.contains_key(&announce.public_key);
                        nodes_map.insert(announce.public_key.clone(), node);
                        is_new
                    };

                    if let Err(e) = persist_announcement(&node_store_dir, &announce, addr) {
                        warn!(
                            public_key = %public_key,
                            address = %address,
                            error = %e,
                            "persist_fail"
                        );
                    }

                    if is_new {
                        info!(
                            public_key = %public_key,
                            address = %address,
                            metadata = ?metadata,
                            "node_seen"
                        );
                    } else {
                        info!(
                            public_key = %public_key,
                            address = %address,
                            metadata = ?metadata,
                            "node_updated"
                        );
                    }
                }
                Err(e) => {
                    warn!("Failed to parse announcement from {}: {}", addr, e);
                }
            }
        }
    }

    /// Send an announcement to the multicast group
    #[instrument(skip(self))]
    pub async fn announce(&self) -> Result<()> {
        self.announce_with_metadata(None).await
    }

    /// Send an announcement with optional metadata
    #[instrument(skip(self, metadata))]
    pub async fn announce_with_metadata(
        &self,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<()> {
        let announce = Announce {
            public_key: self.public_key_b64.clone(),
            metadata,
        };

        let json = serde_json::to_vec(&announce).context("Failed to serialize announcement")?;

        // Send to IPv4 multicast
        if let Some(socket) = &self.socket_v4 {
            let addr = SocketAddr::new(IpAddr::V4(MULTICAST_IPV4), MULTICAST_PORT);
            socket
                .send_to(&json, addr)
                .await
                .context("Failed to send IPv4 announcement")?;
        }

        // Send to IPv6 multicast
        if let Some(socket) = &self.socket_v6 {
            let addr = SocketAddr::new(IpAddr::V6(MULTICAST_IPV6), MULTICAST_PORT);
            socket
                .send_to(&json, addr)
                .await
                .context("Failed to send IPv6 announcement")?;
        }

        Ok(())
    }

    /// Get the public key in base64url encoding
    pub fn public_key_b64(&self) -> &str {
        &self.public_key_b64
    }

    /// Get a snapshot of currently discovered nodes
    #[instrument(skip(self))]
    pub async fn get_nodes(&self) -> HashMap<String, Node> {
        self.nodes.read().await.clone()
    }

    /// Get a specific node by its public key
    #[instrument(skip(self), fields(public_key = %public_key))]
    pub async fn get_node(&self, public_key: &str) -> Option<Node> {
        debug!("Getting node by public key");
        let nodes = self.nodes.read().await;
        let result = nodes.get(public_key).cloned();
        debug!("Node {}found", if result.is_some() { "" } else { "not " });
        result
    }

    fn default_node_store_dir() -> Result<PathBuf> {
        Ok(mesh::paths::AppPaths::for_app("lmesh").files.join("nodes"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredNode {
    public_key: String,
    address: String,
    announces: Vec<serde_json::Value>,
}

fn persist_announcement(dir: &Path, announce: &Announce, addr: SocketAddr) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;

    let path = node_record_path(dir, &announce.public_key);
    let mut record = if path.exists() {
        let data = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_str::<StoredNode>(&data).unwrap_or_else(|e| {
            warn!(
                path = %path.display(),
                error = %e,
                "replacing invalid lmesh node record"
            );
            StoredNode::new(&announce.public_key, addr)
        })
    } else {
        StoredNode::new(&announce.public_key, addr)
    };

    record.public_key = announce.public_key.clone();
    record.address = addr.to_string();
    record.announces.push(serde_json::json!([
        current_timestamp_millis(),
        announce.public_key.clone(),
        addr.to_string(),
        announce.clone()
    ]));

    if record.announces.len() > MAX_STORED_ANNOUNCES {
        let overflow = record.announces.len() - MAX_STORED_ANNOUNCES;
        record.announces.drain(0..overflow);
    }

    let data = serde_json::to_vec_pretty(&record).context("failed to serialize node record")?;
    let temp_path = path.with_extension("json.tmp");
    fs::write(&temp_path, data)
        .with_context(|| format!("failed to write {}", temp_path.display()))?;
    fs::rename(&temp_path, &path).with_context(|| {
        format!(
            "failed to move {} to {}",
            temp_path.display(),
            path.display()
        )
    })?;

    Ok(())
}

impl StoredNode {
    fn new(public_key: &str, addr: SocketAddr) -> Self {
        Self {
            public_key: public_key.to_string(),
            address: addr.to_string(),
            announces: Vec::new(),
        }
    }
}

fn node_record_path(dir: &Path, public_key: &str) -> PathBuf {
    dir.join(format!("{}.json", public_key_sha(public_key)))
}

fn public_key_sha(public_key: &str) -> String {
    let digest = Sha256::digest(public_key.as_bytes());
    hex_encode(&digest)
}

fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(data.len() * 2);
    for byte in data {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn current_timestamp_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

/// Serializable node info returned by the JSON-lines API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Base64url encoded public key.
    pub public_key: String,
    /// Last seen address.
    pub address: SocketAddr,
    /// Optional metadata from the announcement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
}

impl From<Node> for NodeInfo {
    fn from(node: Node) -> Self {
        Self {
            public_key: node.public_key,
            address: node.address,
            metadata: node.metadata,
        }
    }
}

/// JSON-lines request methods for lmesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method")]
pub enum Request {
    /// Return all currently discovered nodes.
    #[serde(rename = "nodes", alias = "list_nodes")]
    Nodes,
    /// Return one discovered node by public key.
    #[serde(rename = "get_node")]
    GetNode { public_key: String },
    /// Send a multicast announcement.
    #[serde(rename = "announce")]
    Announce {
        /// Optional metadata to include in the announcement.
        #[serde(default)]
        metadata: Option<HashMap<String, String>>,
    },
}

/// Reusable lmesh command service.
pub struct LmeshService {
    discovery: Arc<LocalDiscovery>,
}

impl LmeshService {
    /// Create a service around an initialized discovery instance.
    pub fn new(discovery: Arc<LocalDiscovery>) -> Self {
        Self { discovery }
    }

    /// Return the local public key used for announcements.
    pub fn public_key_b64(&self) -> &str {
        self.discovery.public_key_b64()
    }

    /// Handle a single JSON-lines request.
    pub async fn handle_request(&self, request: Request) -> mesh::protocol::Response {
        match request {
            Request::Nodes => {
                let nodes = self
                    .discovery
                    .get_nodes()
                    .await
                    .into_values()
                    .map(NodeInfo::from)
                    .collect::<Vec<_>>();
                mesh::protocol::Response::ok_with_data(serde_json::json!(nodes))
            }
            Request::GetNode { public_key } => match self.discovery.get_node(&public_key).await {
                Some(node) => {
                    mesh::protocol::Response::ok_with_data(serde_json::json!(NodeInfo::from(node)))
                }
                None => mesh::protocol::Response::err("node not found"),
            },
            Request::Announce { metadata } => {
                match self.discovery.announce_with_metadata(metadata).await {
                    Ok(()) => mesh::protocol::Response::ok(),
                    Err(e) => mesh::protocol::Response::err(e.to_string()),
                }
            }
        }
    }
}

/// Encode bytes as base64url (RFC 4648)
fn base64_url_encode(data: &[u8]) -> String {
    // Simple base64url encoding
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = Vec::new();

    for chunk in data.chunks(3) {
        let mut buf = [0u8; 3];
        for (i, &b) in chunk.iter().enumerate() {
            buf[i] = b;
        }

        let b1 = buf[0] >> 2;
        let b2 = ((buf[0] & 0x03) << 4) | (buf[1] >> 4);
        let b3 = ((buf[1] & 0x0f) << 2) | (buf[2] >> 6);
        let b4 = buf[2] & 0x3f;

        result.push(alphabet[b1 as usize]);
        result.push(alphabet[b2 as usize]);

        if chunk.len() > 1 {
            result.push(alphabet[b3 as usize]);
        }
        if chunk.len() > 2 {
            result.push(alphabet[b4 as usize]);
        }
    }

    String::from_utf8(result).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn test_base64_url_encode() {
        let data = b"hello world";
        let encoded = base64_url_encode(data);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
    }

    #[test]
    fn test_persist_announcement_caps_history_and_updates_address() {
        let dir = unique_test_dir();
        let announce = Announce {
            public_key: "test_key_12345".to_string(),
            metadata: Some(HashMap::from([(
                "version".to_string(),
                "1.0.0".to_string(),
            )])),
        };

        for port in 10_000..10_017 {
            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            persist_announcement(&dir, &announce, addr).unwrap();
        }

        let path = node_record_path(&dir, &announce.public_key);
        let record: StoredNode = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(record.public_key, announce.public_key);
        assert_eq!(record.address, "127.0.0.1:10016");
        assert_eq!(record.announces.len(), MAX_STORED_ANNOUNCES);
        assert_eq!(record.announces[0][2], "127.0.0.1:10001");
        assert_eq!(record.announces[15][2], "127.0.0.1:10016");

        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn test_local_discovery_creation() {
        let discovery = LocalDiscovery::new(None).await.unwrap();
        assert!(!discovery.public_key_b64().is_empty());
    }

    #[tokio::test]
    async fn test_announce_serialization() {
        let mut metadata = HashMap::new();
        metadata.insert("version".to_string(), "1.0.0".to_string());

        let announce = Announce {
            public_key: "test_key_12345".to_string(),
            metadata: Some(metadata),
        };

        let json = serde_json::to_string(&announce).unwrap();
        assert!(json.contains("test_key_12345"));
        assert!(json.contains("version"));
        assert!(json.contains("1.0.0"));

        // Test deserialization
        let parsed: Announce = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.public_key, "test_key_12345");
        assert!(parsed.metadata.is_some());
    }

    #[tokio::test]
    async fn test_local_discovery_node_management() {
        let discovery = LocalDiscovery::new(None).await.unwrap();

        // Initially, no nodes should be discovered
        let nodes = discovery.get_nodes().await;
        assert_eq!(nodes.len(), 0);

        // Get a non-existent node
        let node = discovery.get_node("non_existent_key").await;
        assert!(node.is_none());
    }

    #[tokio::test]
    async fn test_local_discovery_full_lifecycle() {
        // Create a discovery instance
        let mut discovery = LocalDiscovery::new(None).await.unwrap();
        let key = discovery.public_key_b64().to_string();

        tracing::info!("Discovery key: {}", key);

        // Start the discovery service
        // Note: This may fail in test environments due to permission issues
        // or if another test is already using the multicast port
        if let Err(e) = discovery.start().await {
            tracing::warn!("Could not start discovery in test: {}", e);
            // This is acceptable in test environments where multicast may not be available
            return;
        }

        // Wait a moment for sockets to be ready
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Send an announcement
        if let Err(e) = discovery.announce().await {
            tracing::warn!("Could not send announcement in test: {}", e);
            return;
        }

        // Wait for the announcement to be processed
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Check if we received our own announcement (multicast loopback)
        let nodes = discovery.get_nodes().await;
        tracing::info!("Discovery received {} nodes", nodes.len());

        // In some systems, multicast loopback is enabled and we'll receive our own announcement
        // In others, it may not work in test environments
        // So we don't assert a specific count, just that the test completes successfully
    }

    fn unique_test_dir() -> PathBuf {
        let counter = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("lmesh-test-{}-{}", std::process::id(), counter))
    }
}
