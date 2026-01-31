//! SOCKS5 server integration tests

use anyhow::Result;
use log::info;
use ssh_mesh::test_utils::find_free_port;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Start a simple echo server for testing
fn start_echo_server(port: u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(mut stream) = stream {
                thread::spawn(move || {
                    let mut buffer = [0; 1024];
                    loop {
                        match stream.read(&mut buffer) {
                            Ok(0) => break,
                            Ok(n) => {
                                info!("ECHO SERVER: Received {} bytes", n);
                                if stream.write_all(&buffer[..n]).is_err() {
                                    break;
                                }
                                if stream.flush().is_err() {
                                    break;
                                }
                                info!("ECHO SERVER: Echoed {} bytes", n);
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        }
    });
}

/// Perform SOCKS5 handshake to connect to a target via the proxy
async fn socks5_connect(
    proxy_stream: &mut TcpStream,
    target_addr: std::net::SocketAddr,
) -> Result<()> {
    // Send greeting: version 5, 1 auth method (no auth)
    proxy_stream.write_all(&[0x05, 0x01, 0x00]).await?;

    // Receive server's chosen auth method
    let mut response = [0u8; 2];
    proxy_stream.read_exact(&mut response).await?;
    assert_eq!(response[0], 0x05, "SOCKS version mismatch");
    assert_eq!(response[1], 0x00, "Server did not accept no-auth");

    // Send CONNECT request
    let mut request = Vec::new();
    request.push(0x05); // Version
    request.push(0x01); // CONNECT command
    request.push(0x00); // Reserved

    match target_addr {
        std::net::SocketAddr::V4(addr) => {
            request.push(0x01); // IPv4
            request.extend_from_slice(&addr.ip().octets());
        }
        std::net::SocketAddr::V6(addr) => {
            request.push(0x04); // IPv6
            request.extend_from_slice(&addr.ip().octets());
        }
    }

    request.extend_from_slice(&target_addr.port().to_be_bytes());
    proxy_stream.write_all(&request).await?;

    // Read response (at least 10 bytes for IPv4)
    let mut response = [0u8; 10];
    proxy_stream.read_exact(&mut response).await?;
    assert_eq!(response[0], 0x05, "SOCKS version mismatch in response");
    assert_eq!(response[1], 0x00, "SOCKS connect failed");

    Ok(())
}

async fn run_test_with_timeout<F, Fut>(test_fn: F) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    timeout(Duration::from_secs(10), test_fn()).await?
}

#[tokio::test]
async fn test_socks5_connect_ipv4() -> Result<()> {
    run_test_with_timeout(|| async {
        // Start echo server
        let echo_port = find_free_port()?;
        start_echo_server(echo_port);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Start SOCKS5 server
        let socks_port = find_free_port()?;
        let socks_addr = format!("127.0.0.1:{}", socks_port);
        let server = ssh_mesh::socks5::Socks5Server::bind(&socks_addr).await?;

        tokio::spawn(async move {
            server.run().await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Connect through SOCKS5 proxy
        let mut proxy_stream = TcpStream::connect(format!("127.0.0.1:{}", socks_port)).await?;
        let target_addr: std::net::SocketAddr = format!("127.0.0.1:{}", echo_port).parse()?;
        socks5_connect(&mut proxy_stream, target_addr).await?;

        // Send data through the proxy
        let message = b"Hello, SOCKS5 world!";
        proxy_stream.write_all(message).await?;
        proxy_stream.flush().await?;

        // Receive echoed data
        let mut buffer = [0u8; 1024];
        let n = proxy_stream.read(&mut buffer).await?;
        assert_eq!(&buffer[..n], message);

        Ok(())
    })
    .await
}

#[tokio::test]
async fn test_socks5_connect_domain() -> Result<()> {
    run_test_with_timeout(|| async {
        // Start echo server
        let echo_port = find_free_port()?;
        start_echo_server(echo_port);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Start SOCKS5 server
        let socks_port = find_free_port()?;
        let socks_addr = format!("127.0.0.1:{}", socks_port);
        let server = ssh_mesh::socks5::Socks5Server::bind(&socks_addr).await?;

        tokio::spawn(async move {
            server.run().await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Connect through SOCKS5 proxy using domain name
        let mut proxy_stream = TcpStream::connect(format!("127.0.0.1:{}", socks_port)).await?;

        // Send greeting
        proxy_stream.write_all(&[0x05, 0x01, 0x00]).await?;

        let mut response = [0u8; 2];
        proxy_stream.read_exact(&mut response).await?;
        assert_eq!(response[0], 0x05);
        assert_eq!(response[1], 0x00);

        // Send CONNECT request with domain name (using 127.0.0.1 as domain since
        // "localhost" may resolve to IPv6 first while echo server is on IPv4)
        let domain = b"127.0.0.1";
        let mut request = Vec::new();
        request.push(0x05); // Version
        request.push(0x01); // CONNECT
        request.push(0x00); // Reserved
        request.push(0x03); // Domain name
        request.push(domain.len() as u8);
        request.extend_from_slice(domain);
        request.extend_from_slice(&echo_port.to_be_bytes());
        proxy_stream.write_all(&request).await?;

        // Read response
        let mut response = [0u8; 10];
        proxy_stream.read_exact(&mut response).await?;
        assert_eq!(response[0], 0x05);
        assert_eq!(
            response[1], 0x00,
            "SOCKS connect failed with reply: {}",
            response[1]
        );

        // Send and receive data
        let message = b"Hello via domain!";
        proxy_stream.write_all(message).await?;
        proxy_stream.flush().await?;

        let mut buffer = [0u8; 1024];
        let n = proxy_stream.read(&mut buffer).await?;
        assert_eq!(&buffer[..n], message);

        Ok(())
    })
    .await
}
