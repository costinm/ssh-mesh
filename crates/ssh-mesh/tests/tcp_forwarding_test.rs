use anyhow::Result;
use log::info;
use ssh_mesh::test_utils::{find_free_port, setup_test_environment};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command};
use std::thread;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

// Simple echo server for testing
fn start_echo_server(port: u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(mut stream) = stream {
                thread::spawn(move || {
                    let mut buffer = [0; 1024];
                    loop {
                        match stream.read(&mut buffer) {
                            Ok(0) => break, // Connection closed
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

async fn run_test_with_timeout<F, Fut>(test_fn: F) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    timeout(Duration::from_secs(15), test_fn()).await?
}

#[tokio::test]
async fn test_local_tcp_forwarding() -> Result<()> {
    run_test_with_timeout(|| async {
        let setup = setup_test_environment(None, false).await?;

        let echo_port = find_free_port()?;
        start_echo_server(echo_port);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let local_forward_port = find_free_port()?;
        let mut ssh_client_process = Command::new("ssh")
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg("-o")
            .arg("UserKnownHostsFile=/dev/null")
            .arg("-v")
            .arg("-i")
            .arg(&setup.client_key_path)
            .arg("-p")
            .arg(setup.ssh_port.to_string())
            .arg("-L")
            .arg(format!("{}:127.0.0.1:{}", local_forward_port, echo_port))
            .arg("-l")
            .arg("testuser")
            .arg("127.0.0.1")
            .arg("-N") // Do not execute a remote command.
            .spawn()?;

        tokio::time::sleep(Duration::from_millis(2000)).await;

        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", local_forward_port)).await?;
        let message = b"Hello, local forwarding test!";
        stream.write_all(message).await?;
        stream.flush().await?;

        let mut buffer = [0; 1024];
        let n = stream.read(&mut buffer).await?;

        assert_eq!(&buffer[..n], message);

        ssh_client_process.kill()?;
        setup.server_handle.abort();

        Ok(())
    })
    .await
}

#[tokio::test]
async fn test_remote_tcp_forwarding() -> Result<()> {
    run_test_with_timeout(|| async {
        let setup = setup_test_environment(None, false).await?;

        // This echo server is on the "client" side.
        let echo_port = find_free_port()?;
        start_echo_server(echo_port);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The port the *server* will listen on.
        let remote_forward_port = find_free_port()?;

        let mut ssh_client_process: Child = Command::new("ssh")
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg("-o")
            .arg("UserKnownHostsFile=/dev/null")
            .arg("-v")
            .arg("-i")
            .arg(&setup.client_key_path)
            .arg("-p")
            .arg(setup.ssh_port.to_string())
            .arg("-R")
            .arg(format!(
                "127.0.0.1:{}:127.0.0.1:{}",
                remote_forward_port, echo_port
            ))
            .arg("-l")
            .arg("testuser")
            .arg("127.0.0.1")
            .arg("-N") // Do not execute a remote command.
            .spawn()?;

        // Give SSH client time to establish connection and forwarding
        tokio::time::sleep(Duration::from_millis(2000)).await;

        // Connect to the port on the server side
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", remote_forward_port)).await?;
        let message = b"Hello, remote forwarding test!";
        stream.write_all(message).await?;
        stream.flush().await?;
        info!("REMOTE TEST: Wrote to server port {}", remote_forward_port);

        // Receive echoed data
        let mut buffer = [0; 1024];
        let n = stream.read(&mut buffer).await?;
        info!("REMOTE TEST: Read from server port {}", remote_forward_port);

        assert_eq!(&buffer[..n], message);

        ssh_client_process.kill()?;
        setup.server_handle.abort();

        Ok(())
    })
    .await
}

#[tokio::test]
async fn test_local_tcp_forwarding_large_data() -> Result<()> {
    run_test_with_timeout(|| async {
        let setup = setup_test_environment(None, false).await?;

        let echo_port = find_free_port()?;
        start_echo_server(echo_port);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let local_forward_port = find_free_port()?;
        let mut ssh_client_process = Command::new("ssh")
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg("-o")
            .arg("UserKnownHostsFile=/dev/null")
            .arg("-i")
            .arg(&setup.client_key_path)
            .arg("-p")
            .arg(setup.ssh_port.to_string())
            .arg("-L")
            .arg(format!("{}:127.0.0.1:{}", local_forward_port, echo_port))
            .arg("-l")
            .arg("testuser")
            .arg("127.0.0.1")
            .arg("-N")
            .spawn()?;

        tokio::time::sleep(Duration::from_millis(2000)).await;

        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", local_forward_port)).await?;
        
        // 1MB of data
        let size = 1024 * 1024;
        let mut message = vec![0u8; size];
        for i in 0..size {
            message[i] = (i % 256) as u8;
        }
        
        let message_clone = message.clone();
        tokio::spawn(async move {
            let mut stream = stream;
            stream.write_all(&message_clone).await.unwrap();
            stream.flush().await.unwrap();
            
            let mut buffer = vec![0u8; size];
            let mut total_read = 0;
            while total_read < size {
                let n = stream.read(&mut buffer[total_read..]).await.unwrap();
                if n == 0 { break; }
                total_read += n;
            }
            assert_eq!(total_read, size);
            assert_eq!(buffer, message_clone);
        }).await?;

        ssh_client_process.kill()?;
        setup.server_handle.abort();

        Ok(())
    })
    .await
}

#[tokio::test]
async fn test_local_tcp_forwarding_localhost() -> Result<()> {
    run_test_with_timeout(|| async {
        let setup = setup_test_environment(None, false).await?;

        let echo_port = find_free_port()?;
        start_echo_server(echo_port);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let local_forward_port = find_free_port()?;
        let mut ssh_client_process = Command::new("ssh")
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg("-o")
            .arg("UserKnownHostsFile=/dev/null")
            .arg("-i")
            .arg(&setup.client_key_path)
            .arg("-p")
            .arg(setup.ssh_port.to_string())
            .arg("-L")
            .arg(format!("{}:localhost:{}", local_forward_port, echo_port))
            .arg("-l")
            .arg("testuser")
            .arg("127.0.0.1")
            .arg("-N")
            .spawn()?;

        tokio::time::sleep(Duration::from_millis(2000)).await;

        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", local_forward_port)).await?;
        let message = b"Hello, localhost forwarding test!";
        stream.write_all(message).await?;
        stream.flush().await?;

        let mut buffer = [0; 1024];
        let n = stream.read(&mut buffer).await?;

        assert_eq!(&buffer[..n], message);

        ssh_client_process.kill()?;
        setup.server_handle.abort();

        Ok(())
    })
    .await
}
