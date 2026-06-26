//! Standalone SOCKS5 server implementation.
//!
//! This module implements a minimal SOCKS5 proxy server that supports:
//! - No-auth (`0x00`) and username/password (`0x02`, RFC 1929) methods
//! - CONNECT command with IPv4, IPv6, and domain name addresses
//! - Direct TCP forwarding to the target destination
//!
//! When credentials are configured via [`Socks5Config::credentials`], only
//! authenticated connections are accepted; otherwise the server advertises
//! no-auth only. To avoid becoming an open proxy, bind to `127.0.0.1` when
//! no auth is configured (see `main.rs`).

use byteorder::{BigEndian, ByteOrder};
use log::{debug, error, info, warn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Username/password credentials accepted by the SOCKS5 server.
#[derive(Clone, Debug)]
pub struct Socks5Credentials {
    pub username: String,
    pub password: String,
}

/// Configuration for the SOCKS5 server.
#[derive(Clone, Default)]
pub struct Socks5Config {
    /// If set, the server advertises username/password auth and requires it.
    /// If unset, the server advertises no-auth only.
    pub credentials: Option<Socks5Credentials>,
}

/// SOCKS5 server that listens on a TCP port and forwards connections.
pub struct Socks5Server {
    listener: TcpListener,
    config: Socks5Config,
}

impl Socks5Server {
    /// Create a new SOCKS5 server bound to the given address.
    pub async fn bind(addr: &str) -> Result<Self, std::io::Error> {
        Self::bind_with_config(addr, Socks5Config::default()).await
    }

    /// Create a new SOCKS5 server bound to the given address with config.
    pub async fn bind_with_config(
        addr: &str,
        config: Socks5Config,
    ) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        info!(
            "SOCKS5 server listening on {} (auth: {})",
            listener.local_addr()?,
            if config.credentials.is_some() {
                "username/password"
            } else {
                "none"
            }
        );
        Ok(Self { listener, config })
    }

    /// Get the local address the server is bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Run the SOCKS5 server, accepting and handling connections.
    pub async fn run(self) {
        let config = self.config.clone();
        loop {
            match self.listener.accept().await {
                Ok((stream, peer_addr)) => {
                    debug!("SOCKS5: New connection from {}", peer_addr);
                    let cfg = config.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, &cfg).await {
                            warn!("SOCKS5: Connection from {} failed: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("SOCKS5: Failed to accept connection: {}", e);
                }
            }
        }
    }
}

/// Handle a single SOCKS5 connection.
async fn handle_connection(
    mut stream: TcpStream,
    config: &Socks5Config,
) -> Result<(), Socks5Error> {
    // Perform SOCKS5 handshake and get target address
    let target_addr = negotiate_socks5(&mut stream, config).await?;

    // Connect to the target
    debug!("SOCKS5: Connecting to target {}", target_addr);
    let target_stream = match TcpStream::connect(&target_addr).await {
        Ok(s) => s,
        Err(e) => {
            send_error(&mut stream, SocksReply::HostUnreachable).await;
            return Err(Socks5Error::Connect(e));
        }
    };

    // Send success response
    let local_addr = target_stream
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0));
    send_success(&mut stream, local_addr).await?;

    // Bidirectional forwarding
    let (mut client_read, mut client_write) = stream.into_split();
    let (mut target_read, mut target_write) = target_stream.into_split();

    let client_to_target = async {
        let _ = tokio::io::copy(&mut client_read, &mut target_write).await;
        let _ = target_write.shutdown().await;
    };

    let target_to_client = async {
        let _ = tokio::io::copy(&mut target_read, &mut client_write).await;
        let _ = client_write.shutdown().await;
    };

    tokio::join!(client_to_target, target_to_client);
    debug!("SOCKS5: Connection completed");

    Ok(())
}

/// Negotiate a SOCKS5 connection and return the target address.
async fn negotiate_socks5(
    stream: &mut TcpStream,
    config: &Socks5Config,
) -> Result<SocketAddr, Socks5Error> {
    // Read version and number of auth methods
    let mut version = [0u8; 2];
    stream.read_exact(&mut version).await?;

    if version[0] != 0x05 {
        return Err(Socks5Error::Protocol(format!(
            "unsupported SOCKS version: {}",
            version[0]
        )));
    }

    let nmethods = version[1] as usize;
    if nmethods == 0 {
        return Err(Socks5Error::Protocol("no auth methods provided".into()));
    }

    // Read auth methods
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    let needs_auth = config.credentials.is_some();
    let offered_no_auth = methods.contains(&0x00);
    let offered_userpass = methods.contains(&0x02);

    // Select authentication method.
    if needs_auth {
        // Require username/password auth when credentials are configured.
        if !offered_userpass {
            // Reply with "no acceptable methods"
            stream.write_all(&[0x05, 0xFF]).await?;
            return Err(Socks5Error::Protocol(
                "client did not offer username/password auth".into(),
            ));
        }
        // Accept username/password method
        stream.write_all(&[0x05, 0x02]).await?;
        // Perform RFC 1929 sub-negotiation.
        if !authenticate_userpass(stream, config).await? {
            // Auth failed: send failure version+status, then the client closes.
            stream.write_all(&[0x01, 0x01]).await?;
            return Err(Socks5Error::Protocol("authentication failed".into()));
        }
    } else if offered_no_auth {
        // No credentials configured: accept no-auth only.
        stream.write_all(&[0x05, 0x00]).await?;
    } else {
        stream.write_all(&[0x05, 0xFF]).await?;
        return Err(Socks5Error::Protocol(
            "only unauthenticated connections are supported".into(),
        ));
    }

    // Read connection request
    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;

    if request[0] != 0x05 {
        return Err(Socks5Error::Protocol(format!(
            "unexpected version in request: {}",
            request[0]
        )));
    }

    // Only support CONNECT (0x01)
    if request[1] != 0x01 {
        send_error(stream, SocksReply::CommandNotSupported).await;
        return Err(Socks5Error::Protocol(format!(
            "unsupported command: {} (only CONNECT is supported)",
            request[1]
        )));
    }

    // request[2] is reserved, request[3] is address type
    let atyp = request[3];

    let ip = match atyp {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            IpAddr::V4(Ipv4Addr::from(addr))
        }
        0x04 => {
            // IPv6
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            IpAddr::V6(Ipv6Addr::from(addr))
        }
        0x03 => {
            // Domain name
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;

            let domain_str = String::from_utf8(domain)
                .map_err(|_| Socks5Error::Protocol("invalid domain name encoding".into()))?;

            // Resolve domain name
            let resolved = tokio::net::lookup_host(format!("{}:0", domain_str))
                .await
                .map_err(|e| Socks5Error::Dns(domain_str.clone(), e))?
                .next()
                .ok_or_else(|| {
                    Socks5Error::Dns(
                        domain_str,
                        std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses found"),
                    )
                })?;
            resolved.ip()
        }
        _ => {
            send_error(stream, SocksReply::AddressTypeNotSupported).await;
            return Err(Socks5Error::Protocol(format!(
                "unsupported address type: {}",
                atyp
            )));
        }
    };

    // Read port (2 bytes, big-endian)
    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    let port = BigEndian::read_u16(&port_bytes);

    Ok(SocketAddr::new(ip, port))
}

/// Perform RFC 1929 username/password authentication.
///
/// Returns `Ok(true)` on success, `Ok(false)` on bad credentials, `Err` on
/// protocol/IO errors. The caller is responsible for sending the final
/// status byte.
async fn authenticate_userpass(
    stream: &mut TcpStream,
    config: &Socks5Config,
) -> Result<bool, Socks5Error> {
    // Version byte
    let mut ver = [0u8; 1];
    stream.read_exact(&mut ver).await?;
    if ver[0] != 0x01 {
        return Err(Socks5Error::Protocol(format!(
            "unexpected userauth subnegotiation version: {}",
            ver[0]
        )));
    }

    // ULEN (1 byte) + UNAME
    let mut ulen = [0u8; 1];
    stream.read_exact(&mut ulen).await?;
    let mut username = vec![0u8; ulen[0] as usize];
    stream.read_exact(&mut username).await?;

    // PLEN (1 byte) + PASSWD
    let mut plen = [0u8; 1];
    stream.read_exact(&mut plen).await?;
    let mut password = vec![0u8; plen[0] as usize];
    stream.read_exact(&mut password).await?;

    // Zeroize password copies as soon as we can.
    let ok = config
        .credentials
        .as_ref()
        .map(|c| {
            // Constant-time-ish comparison: avoids short-circuiting on first
            // mismatched byte. Not a true constant-time implementation but
            // better than `==` on the whole slices.
            let user_match = same_length_constant_time_compare(&username, c.username.as_bytes());
            let pass_match = same_length_constant_time_compare(&password, c.password.as_bytes());
            user_match && pass_match
        })
        .unwrap_or(false);

    // Send success status.
    stream
        .write_all(&[0x01, if ok { 0x00 } else { 0x01 }])
        .await?;

    // Best-effort zeroize of the received buffers.
    for b in username.iter_mut() {
        *b = 0;
    }
    for b in password.iter_mut() {
        *b = 0;
    }

    Ok(ok)
}

/// Compare two equal-length slices in (approximately) constant time.
fn same_length_constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// SOCKS5 reply codes
#[allow(dead_code)]
#[repr(u8)]
enum SocksReply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

/// Send a SOCKS5 success response.
async fn send_success(stream: &mut TcpStream, bound_addr: SocketAddr) -> Result<(), Socks5Error> {
    send_response(stream, SocksReply::Succeeded, bound_addr).await
}

/// Send a SOCKS5 error response.
async fn send_error(stream: &mut TcpStream, reply: SocksReply) {
    let dummy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
    let _ = send_response(stream, reply, dummy_addr).await;
}

/// Send a SOCKS5 response.
async fn send_response(
    stream: &mut TcpStream,
    reply: SocksReply,
    bound_addr: SocketAddr,
) -> Result<(), Socks5Error> {
    let mut buf = Vec::with_capacity(22);
    buf.push(0x05); // Version
    buf.push(reply as u8); // Reply
    buf.push(0x00); // Reserved

    match bound_addr {
        SocketAddr::V4(addr) => {
            buf.push(0x01); // IPv4
            buf.extend_from_slice(&addr.ip().octets());
        }
        SocketAddr::V6(addr) => {
            buf.push(0x04); // IPv6
            buf.extend_from_slice(&addr.ip().octets());
        }
    }

    buf.extend_from_slice(&bound_addr.port().to_be_bytes());
    stream.write_all(&buf).await?;

    Ok(())
}

/// SOCKS5 errors
#[derive(Debug)]
pub enum Socks5Error {
    Io(std::io::Error),
    Protocol(String),
    Dns(String, std::io::Error),
    Connect(std::io::Error),
}

impl std::fmt::Display for Socks5Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Socks5Error::Io(e) => write!(f, "I/O error: {}", e),
            Socks5Error::Protocol(msg) => write!(f, "protocol error: {}", msg),
            Socks5Error::Dns(domain, e) => write!(f, "DNS resolution failed for {}: {}", domain, e),
            Socks5Error::Connect(e) => write!(f, "connection failed: {}", e),
        }
    }
}

impl std::error::Error for Socks5Error {}

impl From<std::io::Error> for Socks5Error {
    fn from(e: std::io::Error) -> Self {
        Socks5Error::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_socks5_server_bind() {
        let server = match Socks5Server::bind("127.0.0.1:0").await {
            Ok(server) => server,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping TCP bind check: {e}");
                return;
            }
            Err(e) => panic!("failed to bind SOCKS5 server: {e}"),
        };
        let addr = server.local_addr().unwrap();
        assert!(addr.port() > 0);
    }

    #[tokio::test]
    async fn test_socks5_userpass_rejects_no_auth_offer() {
        let server = Socks5Server::bind_with_config(
            "127.0.0.1:0",
            Socks5Config {
                credentials: Some(Socks5Credentials {
                    username: "u".into(),
                    password: "p".into(),
                }),
            },
        )
        .await
        .expect("bind");
        let addr = server.local_addr().unwrap();

        tokio::spawn(server.run());

        // Client offers only no-auth (0x00); server must reject (0xFF).
        let mut s = TcpStream::connect(addr).await.expect("connect");
        s.write_all(&[0x05, 0x01, 0x00]).await.expect("send");
        let mut resp = [0u8; 2];
        s.read_exact(&mut resp).await.expect("read");
        assert_eq!(resp[0], 0x05);
        assert_eq!(resp[1], 0xFF, "server must reject when userpass required");
    }

    #[tokio::test]
    async fn test_socks5_userpass_accepts_correct_credentials() {
        let server = Socks5Server::bind_with_config(
            "127.0.0.1:0",
            Socks5Config {
                credentials: Some(Socks5Credentials {
                    username: "alice".into(),
                    password: "secret".into(),
                }),
            },
        )
        .await
        .expect("bind");
        let addr = server.local_addr().unwrap();

        tokio::spawn(server.run());

        let mut s = TcpStream::connect(addr).await.expect("connect");
        // Offer no-auth + userpass.
        s.write_all(&[0x05, 0x02, 0x00, 0x02]).await.expect("send");
        let mut resp = [0u8; 2];
        s.read_exact(&mut resp).await.expect("read");
        assert_eq!(resp, [0x05, 0x02], "server must select userpass");

        // RFC 1929: VER=1, ULEN=5, "alice", PLEN=6, "secret"
        s.write_all(&[
            0x01, 0x05, b'a', b'l', b'i', b'c', b'e', 0x06, b's', b'e', b'c', b'r', b'e', b't',
        ])
        .await
        .expect("send userpass");
        let mut auth_resp = [0u8; 2];
        s.read_exact(&mut auth_resp).await.expect("read auth resp");
        assert_eq!(auth_resp, [0x01, 0x00], "auth should succeed");
    }
}
