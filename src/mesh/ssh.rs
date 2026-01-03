#[allow(dead_code, unused)]

use std::{env, net::SocketAddr, sync::Arc, pin::Pin, task::{Context, Poll}, convert::Infallible, fs, path::{Path, PathBuf}};
use anyhow::Context as AnyhowContext;
use log::{info, error};
use russh::{server, ChannelId, MethodKind};
use russh::server::Server;
use russh::keys::{PrivateKey, PublicKey, PublicKeyBase64};
use tokio::sync::{Mutex, mpsc};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use hyper::{Request, Response, body::Incoming};
use hyper::body::Bytes;
use http_body_util::{Full, BodyExt};
use bytes::Buf;
use crate::mesh::http;

// File paths for SSH authentication
const AUTHORIZED_KEYS_PATH: &str = ".ssh/authorized_keys";
const AUTHORIZED_CAS_PATH: &str = ".ssh/authorized_cas";

/// Load authorized public keys from baseDir/.ssh/authorized_keys
///
/// # Arguments
/// * `base_dir` - Base directory containing the .ssh subdirectory
///
/// Returns an empty vector if the file doesn't exist.
/// Malformed lines are logged and skipped.
fn load_authorized_keys(base_dir: &Path) -> Result<Vec<ssh_key::PublicKey>, anyhow::Error> {
    let path = base_dir.join(AUTHORIZED_KEYS_PATH);

    // Return empty vector if file doesn't exist (not an error)
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    parse_authorized_keys_content(&content)
}

/// Parse authorized_keys file content
fn parse_authorized_keys_content(content: &str) -> Result<Vec<ssh_key::PublicKey>, anyhow::Error> {
    let mut keys = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parse the line as an OpenSSH public key
        match ssh_key::PublicKey::from_openssh(line) {
            Ok(key) => keys.push(key),
            Err(e) => {
                // Log warning but continue (don't fail on malformed lines)
                log::warn!("Failed to parse authorized_keys line {}: {}", line_num + 1, e);
            }
        }
    }

    Ok(keys)
}

/// Load CA public keys from baseDir/.ssh/authorized_cas
///
/// # Arguments
/// * `base_dir` - Base directory containing the .ssh subdirectory
///
/// Returns an empty vector if the file doesn't exist.
/// Malformed lines are logged and skipped.
fn load_authorized_cas(base_dir: &Path) -> Result<Vec<ssh_key::PublicKey>, anyhow::Error> {
    let path = base_dir.join(AUTHORIZED_CAS_PATH);

    // Return empty vector if file doesn't exist
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    parse_authorized_cas_content(&content)
}

/// Parse authorized_cas file content
fn parse_authorized_cas_content(content: &str) -> Result<Vec<ssh_key::PublicKey>, anyhow::Error> {
    let mut ca_keys = Vec::new();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // OpenSSH format with @cert-authority marker:
        // @cert-authority [principals="..."] keytype base64-key [comment]
        if !line.starts_with("@cert-authority") && !line.starts_with("cert-authority") {
            log::warn!("authorized_cas line {} missing cert-authority marker, skipping", line_num + 1);
            continue;
        }

        // Find the key part (after @cert-authority and optional principals)
        let parts: Vec<&str> = line.split_whitespace().collect();

        // Find where the actual key starts (skip @cert-authority and principals=...)
        let mut key_start = 1; // Start after @cert-authority
        while key_start < parts.len() {
            if parts[key_start].starts_with("principals=") || parts[key_start] == "*" {
                key_start += 1;
            } else {
                break;
            }
        }

        if key_start >= parts.len() {
            log::warn!("authorized_cas line {} has no key data", line_num + 1);
            continue;
        }

        // Reconstruct the key line (keytype base64-key comment)
        let key_line = parts[key_start..].join(" ");

        match ssh_key::PublicKey::from_openssh(&key_line) {
            Ok(key) => ca_keys.push(key),
            Err(e) => {
                log::warn!("Failed to parse authorized_cas line {}: {}", line_num + 1, e);
            }
        }
    }

    Ok(ca_keys)
}

// Configuration for the SSH server
#[derive(Clone)]
#[allow(unused)]
pub struct SshServer {
    keys: PrivateKey,
    clients: Arc<Mutex<Vec<usize>>>,
    id_counter: Arc<Mutex<usize>>,
    pub authorized_keys: Arc<Vec<ssh_key::PublicKey>>,
    pub ca_keys: Arc<Vec<ssh_key::PublicKey>>,
    pub base_dir: PathBuf,
}

impl SshServer {
    /// Create a new SshServer instance with an optional private key
    /// If no key is provided, attempts to load from baseDir/.ssh/id_ed25519 or generates a new one
    ///
    /// # Arguments
    /// * `id` - Server ID
    /// * `key` - Optional private key
    /// * `base_dir` - Base directory containing the .ssh subdirectory
    pub fn new(id: usize, key: Option<PrivateKey>, base_dir: PathBuf) -> Self {
        let keys = match key {
            Some(key) => key,
            None => Self::load_or_generate_key(&base_dir),
        };

        // Load authorized keys
        let authorized_keys = match load_authorized_keys(&base_dir) {
            Ok(keys) => {
                info!("Loaded {} authorized keys", keys.len());
                Arc::new(keys)
            }
            Err(e) => {
                error!("Failed to load authorized_keys: {}", e);
                Arc::new(Vec::new())
            }
        };

        // Load CA keys
        let ca_keys = match load_authorized_cas(&base_dir) {
            Ok(cas) => {
                info!("Loaded {} CA keys", cas.len());
                Arc::new(cas)
            }
            Err(e) => {
                error!("Failed to load authorized_cas: {}", e);
                Arc::new(Vec::new())
            }
        };

        SshServer {
            keys,
            clients: Arc::new(Mutex::new(Vec::new())),
            id_counter: Arc::new(Mutex::new(id)),
            authorized_keys,
            ca_keys,
            base_dir,
        }
    }
   
    /// Load SSH key from file or generate a new one
    ///
    /// # Arguments
    /// * `base_dir` - Base directory containing the .ssh subdirectory
    fn load_or_generate_key(base_dir: &Path) -> PrivateKey {
        // Try to load key from file - use the same path as local discovery for consistency
        let key_path = base_dir.join(".ssh").join("key.pem");

        if key_path.exists() {
            // Load key from file
            let key_data = fs::read(&key_path).expect("Failed to read SSH key file");
            // Check if the file is not empty before trying to parse it
            if !key_data.is_empty() {
                // Try to parse as OpenSSH format first
                if let Ok(key) = PrivateKey::from_openssh(&key_data) {
                    return key;
                }
                // Try to parse as binary format
                if let Ok(key) = PrivateKey::from_bytes(&key_data) {
                    return key;
                }
                // If parsing fails, we'll generate a new key below
            }
        }

        // Generate new key
        let key = PrivateKey::random(&mut rand::rngs::OsRng, russh::keys::Algorithm::Ed25519)
            .expect("Failed to generate SSH key");

        // Save the generated key to file in OpenSSH format
        std::fs::create_dir_all(key_path.parent().unwrap()).expect("Failed to create .ssh directory");
        // Just generate a new key each time for simplicity - in a production implementation
        // you would properly serialize and save the key
        let _ = fs::write(&key_path, b""); // Create empty file to avoid repeated key generation in tests

        key
    }

    pub fn get_config(&self) -> server::Config {
        let mut config = server::Config::default();
        // connection_timeout is not available in this version
        config.auth_rejection_time = std::time::Duration::from_secs(1);
        config.keys.push(self.keys.clone());
        config.server_id = russh::SshId::Standard(String::from("SSH-2.0-Rust-SSH-Server"));
        config
    }
}

/// Validate a regular public key against authorized_keys
async fn validate_public_key(
    key_openssh: &str,
    authorized_keys: &Arc<Vec<ssh_key::PublicKey>>,
) -> Result<server::Auth, anyhow::Error> {
    // Parse the incoming key from OpenSSH format
    let incoming_key = match ssh_key::PublicKey::from_openssh(key_openssh) {
        Ok(key) => key,
        Err(e) => {
            info!("Failed to parse public key: {}", e);
            return Ok(server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }
    };

    // Compare against all authorized keys using fingerprints
    let incoming_fingerprint = incoming_key.fingerprint(ssh_key::HashAlg::Sha256);

    for authorized_key in authorized_keys.iter() {
        let authorized_fingerprint = authorized_key.fingerprint(ssh_key::HashAlg::Sha256);

        if incoming_fingerprint == authorized_fingerprint {
            info!("Public key authentication successful");
            return Ok(server::Auth::Accept);
        }
    }

    info!("Public key not found in authorized_keys");
    Ok(server::Auth::Reject {
        proceed_with_methods: None,
        partial_success: false,
    })
}

/// Validate a CA-signed certificate
async fn validate_certificate(
    cert_data: &str,
    user: &str,
    ca_keys: &Arc<Vec<ssh_key::PublicKey>>,
) -> Result<server::Auth, anyhow::Error> {
    use ssh_key::Certificate;

    // Parse the certificate
    let certificate = match Certificate::from_openssh(cert_data) {
        Ok(cert) => cert,
        Err(e) => {
            info!("Failed to parse certificate: {}", e);
            return Ok(server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }
    };

    // Build CA fingerprints from trusted CA keys
    let ca_fingerprints: Vec<ssh_key::Fingerprint> = ca_keys
        .iter()
        .map(|key| key.fingerprint(ssh_key::HashAlg::Sha256))
        .collect();

    if ca_fingerprints.is_empty() {
        info!("No CA keys configured, rejecting certificate");
        return Ok(server::Auth::Reject {
            proceed_with_methods: None,
            partial_success: false,
        });
    }

    // Validate certificate (signature, validity window, extensions)
    if let Err(e) = certificate.validate(&ca_fingerprints) {
        info!("Certificate validation failed: {}", e);
        return Ok(server::Auth::Reject {
            proceed_with_methods: None,
            partial_success: false,
        });
    }

    // Check principals (usernames for user certificates)
    let valid_principals = certificate.valid_principals();

    // Empty principals list means valid for any principal
    if !valid_principals.is_empty() {
        let user_matches = valid_principals.iter().any(|p| p == user);

        if !user_matches {
            info!(
                "Certificate principals {:?} do not include user '{}'",
                valid_principals, user
            );
            return Ok(server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }
    }

    // Check certificate type (should be user certificate)
    if certificate.cert_type() != ssh_key::certificate::CertType::User {
        info!("Certificate is not a user certificate");
        return Ok(server::Auth::Reject {
            proceed_with_methods: None,
            partial_success: false,
        });
    }

    info!("Certificate authentication successful for user: {}", user);
    Ok(server::Auth::Accept)
}


#[allow(unused)]
#[derive(Clone)]
pub struct SshHandler {
    id: usize,
    server: SshServer,
}
 
/// Handler deals with one SSH session, after crypto and
/// low level networking.
impl server::Handler for SshHandler {
    type Error = anyhow::Error;
   
    fn auth_password(&mut self, user: &str, _password: &str) -> impl std::future::Future<Output = Result<server::Auth, Self::Error>> + Send {
        info!("Password auth attempt for user: {} - REJECTED", user);
        async move { Ok(server::Auth::Reject {
            proceed_with_methods: Some((&[MethodKind::PublicKey, MethodKind::KeyboardInteractive][..]).into()),
            partial_success: false,
        }) }
    }
 
    fn auth_publickey(&mut self, user: &str, public_key: &PublicKey) -> impl std::future::Future<Output = Result<server::Auth, Self::Error>> + Send {
        info!("Public key auth attempt for user: {}", user);

        let authorized_keys = self.server.authorized_keys.clone();
        let ca_keys = self.server.ca_keys.clone();
        let user = user.to_string();

        // Serialize russh key to OpenSSH format for ssh-key crate
        let key_base64 = public_key.public_key_base64();
        let algorithm = public_key.algorithm();
        let key_type_name = algorithm.as_str();
        let key_openssh = format!("{} {}", key_type_name, key_base64);

        async move {
            // Detect if this is a certificate or regular key
            if key_openssh.contains("-cert-v01@openssh.com") {
                validate_certificate(&key_openssh, &user, &ca_keys).await
            } else {
                validate_public_key(&key_openssh, &authorized_keys).await
            }
        }
    }
 
    fn channel_open_session(&mut self, channel: russh::Channel<russh::server::Msg>, _session: &mut server::Session) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        info!("New session opened on channel {:?}", channel.id());
        async move { Ok(true) }
    }

    fn exec_request(&mut self, channel: ChannelId, data: &[u8], session: &mut server::Session) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let command = String::from_utf8_lossy(data).to_string();
        info!("Executing command: {}", command);
        
        let channel_id = channel;
        let command_str = command.clone();
        
        async move {
            // Execute the command and capture output
            let output = std::process::Command::new("sh")
                .arg("-c")
                .arg(&command_str)
                .output()
                .map_err(|e| anyhow::Error::new(e))?;
            
            // Send the command output back to the client
            if !output.stdout.is_empty() {
                session.data(channel_id, output.stdout.into()).map_err(|e| anyhow::Error::new(e))?;
            }
            
            if !output.stderr.is_empty() {
                session.extended_data(channel_id, 1, output.stderr.into()).map_err(|e| anyhow::Error::new(e))?;
            }
            
            // Send exit status
            let _ = session.exit_status_request(channel_id, output.status.code().unwrap_or(0) as u32);
            
            Ok(())
        }
    }
 
    fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut server::Session) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let data_str = String::from_utf8_lossy(data).to_string();
        info!("Received data on channel {:?}: {}", channel, data_str);
       
        // Echo the data back (SSH echo handler)
        let data_vec = data.to_vec();
        let _ = session.data(channel, data_vec.into());
        
        async move { Ok(()) }
    }
 
    fn channel_eof(&mut self, channel: ChannelId, _session: &mut server::Session) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        info!("Channel EOF: {:?}", channel);
        async move { Ok(()) }
    }
 
    fn channel_close(&mut self, channel: ChannelId, _session: &mut server::Session) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        info!("Channel closed: {:?}", channel);
        async move { Ok(()) }
    }
}
 
impl server::Server for SshServer {
    type Handler = SshHandler;
 
    fn new_client(&mut self, _peer_addr: Option<SocketAddr>) -> Self::Handler {
        let mut id = self.id_counter.try_lock().unwrap();
        *id += 1;
        SshHandler {
            id: *id,
            server: self.clone(),
        }
    }
}
 
// Function to start the SSH server
pub async fn run_ssh_server(port: u16, config: server::Config, server: SshServer) -> Result<(), anyhow::Error> {
    let addr = format!("0.0.0.0:{}", port);
    info!("Starting SSH server on {}", addr);
    
    let mut server = server;
    server.run_on_address(Arc::new(config), &addr).await?;
    Ok(())
}

// SSH handler for /_ssh* paths - handles SSH over HTTP/2
pub async fn handle_ssh_request(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    info!("Received SSH request: {} {}", req.method(), req.uri());

    // Get base directory from environment or use home directory as default
    let base_dir = env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"));

    // Create SSH server with handler
    let mut ssh_server = SshServer::new(1, None, base_dir);
    let config = Arc::new(ssh_server.get_config());
    let handler = ssh_server.new_client(None);
    
    // Create a bidirectional stream adapter for HTTP/2 body
    let (reader_tx, reader_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(100);
    let (writer_tx, _writer_rx) = mpsc::channel::<Bytes>(100);
    
    // Spawn task to read from HTTP request body and feed to SSH
    let body = req.into_body();
    tokio::spawn(async move {
        let mut body = body;
        loop {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        if reader_tx.send(Ok(data)).await.is_err() {
                            break;
                        }
                    }
                }
                Some(Err(e)) => {
                    let _ = reader_tx.send(Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Body read error: {}", e)
                    ))).await;
                    break;
                }
                None => break,
            }
        }
    });
    
    // Create the bidirectional stream adapter
    let stream = Http2SshStream {
        reader: reader_rx,
        writer: writer_tx,
        read_buf: bytes::BytesMut::new(),
    };
    
    // Run SSH over the HTTP/2 stream
    match russh::server::run_stream(config, stream, handler).await {
        Ok(session) => {
            info!("SSH session started successfully");
            
            // Spawn task to handle the SSH session and collect output
            tokio::spawn(async move {
                if let Err(e) = session.await {
                    error!("SSH session error: {:?}", e);
                }
            });
            
            // For now, return a simple success response
            // In a real implementation, you'd want to stream the response
            let response = Response::builder()
                .status(200)
                .body(Full::new(Bytes::from("SSH session established over HTTP/2")))
                .unwrap();
            
            Ok(response)
        }
        Err(e) => {
            error!("Failed to start SSH session: {:?}", e);
            let response = Response::builder()
                .status(500)
                .body(Full::new(Bytes::from(format!("SSH session failed: {:?}", e))))
                .unwrap();
            Ok(response)
        }
    }
}

// Adapter to bridge HTTP/2 body streams with AsyncRead + AsyncWrite
struct Http2SshStream {
    reader: mpsc::Receiver<Result<Bytes, std::io::Error>>,
    writer: mpsc::Sender<Bytes>,
    read_buf: bytes::BytesMut,
}

impl AsyncRead for Http2SshStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // If we have buffered data, use it first
        if !self.read_buf.is_empty() {
            let to_copy = buf.remaining().min(self.read_buf.len());
            buf.put_slice(&self.read_buf[..to_copy]);
            self.read_buf.advance(to_copy);
            return Poll::Ready(Ok(()));
        }
        
        // Try to receive more data
        match self.reader.poll_recv(cx) {
            Poll::Ready(Some(Ok(data))) => {
                let to_copy = buf.remaining().min(data.len());
                buf.put_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    self.read_buf.extend_from_slice(&data[to_copy..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for Http2SshStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Try to send data through the channel
        let data = Bytes::copy_from_slice(buf);
        match self.writer.try_send(data) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Channel is full, register waker and return pending
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "Channel closed"
                )))
            }
        }
    }
    
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// Function to start the HTTP/2 server (delegated to http module)
pub async fn run_h2c_server(port: u16) -> Result<(), anyhow::Error> {
    http::run_h2c_server(port).await
}

// ============================================================================
// SSH CA Management Functions
// ============================================================================

/// Generate a new Ed25519 CA keypair for SSH certificate signing
pub fn generate_ca_keypair() -> Result<(ssh_key::PrivateKey, ssh_key::PublicKey), anyhow::Error> {
    use ssh_key::Algorithm;

    let private_key = ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, Algorithm::Ed25519)?;
    let public_key = private_key.public_key().clone();

    Ok((private_key, public_key))
}

/// Save CA keypair to baseDir/.ssh/id_ca and baseDir/.ssh/id_ca.pub
///
/// # Arguments
/// * `private_key` - The private key to save
/// * `public_key` - The public key to save
/// * `base_dir` - Base directory containing the .ssh subdirectory
pub fn save_ca_keypair(
    private_key: &ssh_key::PrivateKey,
    public_key: &ssh_key::PublicKey,
    base_dir: &Path
) -> Result<(), anyhow::Error> {
    let ssh_dir = base_dir.join(".ssh");

    // Create .ssh directory if it doesn't exist
    fs::create_dir_all(&ssh_dir)?;

    let private_key_path = ssh_dir.join("id_ca");
    let public_key_path = ssh_dir.join("id_ca.pub");

    // Save private key in OpenSSH format
    let private_key_pem = private_key.to_openssh(ssh_key::LineEnding::LF)?;
    fs::write(&private_key_path, private_key_pem.as_bytes())?;

    // Set proper permissions on private key (0600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&private_key_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&private_key_path, perms)?;
    }

    // Save public key in OpenSSH format
    let public_key_str = public_key.to_openssh()?;
    fs::write(&public_key_path, public_key_str.as_bytes())?;

    info!("CA keypair saved to {} and {}", private_key_path.display(), public_key_path.display());
    Ok(())
}

/// Load CA private key from baseDir/.ssh/id_ca
///
/// # Arguments
/// * `base_dir` - Base directory containing the .ssh subdirectory
pub fn load_ca_private_key(base_dir: &Path) -> Result<ssh_key::PrivateKey, anyhow::Error> {
    let private_key_path = base_dir.join(".ssh").join("id_ca");

    if !private_key_path.exists() {
        return Err(anyhow::Error::msg(format!(
            "CA private key not found at {}. Run generate_ca_keypair() first.",
            private_key_path.display()
        )));
    }

    let private_key_data = fs::read_to_string(&private_key_path)?;
    let private_key = ssh_key::PrivateKey::from_openssh(&private_key_data)?;

    Ok(private_key)
}

/// Sign a user's public key with the CA to create an SSH certificate
///
/// # Arguments
/// * `ca_private_key` - The CA's private key for signing
/// * `user_public_key` - The user's public key to be certified
/// * `principals` - List of principals (usernames) this certificate is valid for
/// * `validity_days` - Number of days the certificate is valid from now
pub fn sign_user_certificate(
    ca_private_key: &ssh_key::PrivateKey,
    user_public_key: &ssh_key::PublicKey,
    principals: Vec<String>,
    validity_days: u64,
) -> Result<ssh_key::Certificate, anyhow::Error> {
    use ssh_key::certificate::{Builder, CertType};
    use std::time::{SystemTime, UNIX_EPOCH};

    // Calculate validity window
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();
    let valid_after = now;
    let valid_before = now + (validity_days * 24 * 60 * 60);

    // Build certificate
    let mut builder = Builder::new_with_random_nonce(
        &mut rand::rngs::OsRng,
        user_public_key.clone(),
        valid_after,
        valid_before,
    )?;

    builder.cert_type(CertType::User)?;

    // Add principals
    for principal in principals {
        builder.valid_principal(principal)?;
    }

    // Sign the certificate
    let certificate = builder.sign(ca_private_key)?;

    Ok(certificate)
}

/// Save an SSH certificate to a file
pub fn save_certificate(
    certificate: &ssh_key::Certificate,
    output_path: &Path
) -> Result<(), anyhow::Error> {
    let cert_str = certificate.to_openssh()?;
    fs::write(output_path, cert_str.as_bytes())?;
    info!("Certificate saved to {}", output_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_get_port_from_env() {
        // Test with default value
        let default_port = 1234;
        let random_var = "NONEXISTENT_VAR";
        assert_eq!(http::get_port_from_env(random_var, default_port), default_port);
        
        // Test with environment variable set
        let test_port = 5678;
        let test_var = "TEST_PORT";
        env::set_var(test_var, test_port.to_string());
        assert_eq!(http::get_port_from_env(test_var, default_port), test_port);
        
        // Cleanup
        env::remove_var(test_var);
    }
    
    #[test]
    fn test_ssh_server_creation() {
        let base_dir = env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp"));
        let server = SshServer::new(42, None, base_dir);
        let config = server.get_config();

        // Verify some configuration settings
        assert_eq!(config.keys.len(), 1);
        match &config.server_id {
            russh::SshId::Standard(id) => assert_eq!(id, "SSH-2.0-Rust-SSH-Server"),
            _ => panic!("Unexpected server ID format"),
        }
        // connection_timeout field was removed in this version
    }
}
