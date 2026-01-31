//! Standalone SOCKS5 server implementation.
//!
//! This module implements a minimal SOCKS5 proxy server that supports:
//! - Unauthenticated connections only
//! - CONNECT command with IPv4, IPv6, and domain name addresses
//! - Direct TCP forwarding to the target destination
//!
//! Future enhancements will add forwarding over HTTP/2 or SSH tunnels.

use byteorder::{BigEndian, ByteOrder};
use log::{debug, error, info, warn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// SOCKS5 server that listens on a TCP port and forwards connections.
pub struct Socks5Server {
    listener: TcpListener,
}

impl Socks5Server {
    /// Create a new SOCKS5 server bound to the given address.
    pub async fn bind(addr: &str) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        info!("SOCKS5 server listening on {}", listener.local_addr()?);
        Ok(Self { listener })
    }

    /// Get the local address the server is bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Run the SOCKS5 server, accepting and handling connections.
    pub async fn run(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer_addr)) => {
                    debug!("SOCKS5: New connection from {}", peer_addr);
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream).await {
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
async fn handle_connection(mut stream: TcpStream) -> Result<(), Socks5Error> {
    // Perform SOCKS5 handshake and get target address
    let target_addr = negotiate_socks5(&mut stream).await?;

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
async fn negotiate_socks5(stream: &mut TcpStream) -> Result<SocketAddr, Socks5Error> {
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

    // Check for "no authentication" method (0x00)
    if !methods.contains(&0x00) {
        // Reply with "no acceptable methods"
        stream.write_all(&[0x05, 0xFF]).await?;
        return Err(Socks5Error::Protocol(
            "only unauthenticated connections are supported".into(),
        ));
    }

    // Reply: accept "no authentication"
    stream.write_all(&[0x05, 0x00]).await?;

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
        let server = Socks5Server::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        assert!(addr.port() > 0);
    }
}
