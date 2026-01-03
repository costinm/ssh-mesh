/// Local mesh announce and discovery
/// Each mesh node will listen for UDP multicast announcements on
/// all interfaces. The announcement includes the public key of the
/// node, the (claimed - untrusted) name.
/// 
/// 
use anyhow::{Context, Result};
use openssl::ec::EcKey;
use openssl::pkey::Private;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

const MULTICAST_PORT: u16 = 5227;
const MULTICAST_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 250);
const MULTICAST_IPV6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x5227);

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
    /// IPv4 UDP socket
    socket_v4: Option<Arc<UdpSocket>>,
    /// IPv6 UDP socket
    socket_v6: Option<Arc<UdpSocket>>,
}

impl LocalDiscovery {
    /// Create a new LocalDiscovery instance with an optional EC P256 private key
    /// If no key is provided, attempts to load from $HOME/.ssh/key.pem or generates a new one
    pub async fn new(key: Option<EcKey<Private>>) -> Result<Self> {
        // Get the private key either from parameter or by loading/generating
        let private_key_ec = match key {
            Some(key) => key,
            None => Self::load_or_generate_key()?,
        };

        // Serialize the private key to DER format
        let private_key = private_key_ec
            .private_key_to_der()
            .context("Failed to serialize private key")?;

        // Get the public key and serialize it to DER format
        let public_key_ec = private_key_ec
            .public_key_to_der()
            .context("Failed to serialize public key")?;
        let public_key = public_key_ec;

        let public_key_b64 = base64_url_encode(&public_key);

        Ok(Self {
            private_key,
            public_key,
            public_key_b64,
            nodes: Arc::new(RwLock::new(HashMap::new())),
            socket_v4: None,
            socket_v6: None,
        })
    }

    /// Load key from file or generate a new one
    fn load_or_generate_key() -> Result<EcKey<Private>> {
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;

        // Try to load key from file
        let home_dir = std::env::var("HOME").context("HOME environment variable not set")?;
        let key_path = Path::new(&home_dir).join(".ssh").join("key.pem");

        if key_path.exists() {
            // Load key from file
            let key_data = fs::read(&key_path).context("Failed to read key file")?;
            // Check if the file is not empty before trying to parse it
            if !key_data.is_empty() {
                if let Ok(key) = EcKey::private_key_from_pem(&key_data) {
                    return Ok(key);
                }
                // If parsing fails, we'll generate a new key below
            }
        }

        // Generate new keypair
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
            .context("Failed to create P256 curve group")?;
        let key = EcKey::generate(&group).context("Failed to generate EC key")?;

        // Save the generated key to file
        std::fs::create_dir_all(key_path.parent().unwrap()).context("Failed to create .ssh directory")?;
        let key_pem = key.private_key_to_pem().context("Failed to serialize private key to PEM")?;
        fs::write(&key_path, &key_pem).context("Failed to write key to file")?;

        Ok(key)
    }

    
    /// Start the UDP multicast listeners
    pub async fn start(&mut self) -> Result<()> {
        // Setup IPv4 multicast socket
        match Self::setup_multicast_v4().await {
            Ok(socket) => {
                self.socket_v4 = Some(Arc::new(socket));
                log::info!("IPv4 multicast listener started on {}:{}", MULTICAST_IPV4, MULTICAST_PORT);
            }
            Err(e) => {
                log::warn!("Failed to setup IPv4 multicast: {}", e);
            }
        }

        // Setup IPv6 multicast socket
        match Self::setup_multicast_v6().await {
            Ok(socket) => {
                self.socket_v6 = Some(Arc::new(socket));
                log::info!("IPv6 multicast listener started on [{}]:{}", MULTICAST_IPV6, MULTICAST_PORT);
            }
            Err(e) => {
                log::warn!("Failed to setup IPv6 multicast: {}", e);
            }
        }

        if self.socket_v4.is_none() && self.socket_v6.is_none() {
            anyhow::bail!("Failed to setup any multicast sockets");
        }

        // Start receiver tasks
        if let Some(socket) = &self.socket_v4 {
            let nodes = self.nodes.clone();
            let socket = socket.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::receive_loop(socket, nodes).await {
                    log::error!("IPv4 receive loop error: {}", e);
                }
            });
        }

        if let Some(socket) = &self.socket_v6 {
            let nodes = self.nodes.clone();
            let socket = socket.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::receive_loop(socket, nodes).await {
                    log::error!("IPv6 receive loop error: {}", e);
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
    async fn receive_loop(
        socket: Arc<UdpSocket>,
        nodes: Arc<RwLock<HashMap<String, Node>>>,
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
                    log::debug!("Received announcement from {}: {}", addr, announce.public_key);

                    let node = Node {
                        public_key: announce.public_key.clone(),
                        address: addr,
                        last_seen: std::time::Instant::now(),
                        metadata: announce.metadata,
                    };

                    // Update nodes map
                    let mut nodes_map = nodes.write().await;
                    nodes_map.insert(announce.public_key, node);
                }
                Err(e) => {
                    log::warn!("Failed to parse announcement from {}: {}", addr, e);
                }
            }
        }
    }

    /// Send an announcement to the multicast group
    pub async fn announce(&self) -> Result<()> {
        self.announce_with_metadata(None).await
    }

    /// Send an announcement with optional metadata
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
            log::debug!("Sent IPv4 announcement to {}", addr);
        }

        // Send to IPv6 multicast
        if let Some(socket) = &self.socket_v6 {
            let addr = SocketAddr::new(IpAddr::V6(MULTICAST_IPV6), MULTICAST_PORT);
            socket
                .send_to(&json, addr)
                .await
                .context("Failed to send IPv6 announcement")?;
            log::debug!("Sent IPv6 announcement to {}", addr);
        }

        Ok(())
    }

    /// Get the public key in base64url encoding
    pub fn public_key_b64(&self) -> &str {
        &self.public_key_b64
    }

    /// Get a snapshot of currently discovered nodes
    pub async fn get_nodes(&self) -> HashMap<String, Node> {
        self.nodes.read().await.clone()
    }

    /// Get a specific node by its public key
    pub async fn get_node(&self, public_key: &str) -> Option<Node> {
        self.nodes.read().await.get(public_key).cloned()
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

    #[test]
    fn test_base64_url_encode() {
        let data = b"hello world";
        let encoded = base64_url_encode(data);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
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
        env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Debug)
            .try_init()
            .ok();

        // Create a discovery instance
        let mut discovery = LocalDiscovery::new(None).await.unwrap();
        let key = discovery.public_key_b64().to_string();

        log::info!("Discovery key: {}", key);

        // Start the discovery service
        // Note: This may fail in test environments due to permission issues
        // or if another test is already using the multicast port
        if let Err(e) = discovery.start().await {
            log::warn!("Could not start discovery in test: {}", e);
            // This is acceptable in test environments where multicast may not be available
            return;
        }

        // Wait a moment for sockets to be ready
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Send an announcement
        if let Err(e) = discovery.announce().await {
            log::warn!("Could not send announcement in test: {}", e);
            return;
        }

        // Wait for the announcement to be processed
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Check if we received our own announcement (multicast loopback)
        let nodes = discovery.get_nodes().await;
        log::info!("Discovery received {} nodes", nodes.len());

        // In some systems, multicast loopback is enabled and we'll receive our own announcement
        // In others, it may not work in test environments
        // So we don't assert a specific count, just that the test completes successfully
    }
}
