use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use ssh_mesh::test_utils::{find_free_port, setup_test_environment};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use url::Url;

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
                            Ok(0) => break,
                            Ok(n) => {
                                if stream.write_all(&buffer[..n]).is_err() {
                                    break;
                                }
                                if stream.flush().is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        }
    });
}

#[tokio::test]
async fn test_ws_tcp_proxy() -> Result<()> {
    let setup = setup_test_environment(None, true).await?;
    let http_port = setup.http_port.expect("HTTP port should be set");

    let echo_port = find_free_port()?;
    start_echo_server(echo_port);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let url = Url::parse(&format!(
        "ws://127.0.0.1:{}/_ws/_tcp/127.0.0.1/{}",
        http_port, echo_port
    ))?;
    let (ws_stream, _) = connect_async(url.as_str()).await?;
    let (mut write, mut read) = ws_stream.split();

    let message = b"Hello, WS TCP proxy test!";
    write.send(Message::Binary(message.to_vec())).await?;

    let msg = read.next().await.unwrap()?;
    if let Message::Binary(data) = msg {
        assert_eq!(&data[..], &message[..]);
    } else {
        panic!("Expected binary message, got {:?}", msg);
    }

    setup.server_handle.abort();
    Ok(())
}

#[tokio::test]
async fn test_ws_uds_proxy() -> Result<()> {
    let setup = setup_test_environment(None, true).await?;
    let http_port = setup.http_port.expect("HTTP port should be set");

    let tmp_dir = tempfile::tempdir()?;
    let socket_path = tmp_dir.path().join("test_ws.sock");
    let socket_path_str = socket_path.to_str().unwrap().to_string();

    let listener = UnixListener::bind(&socket_path)?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0; 1024];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if stream.write_all(&buffer[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });

    let url = Url::parse(&format!(
        "ws://127.0.0.1:{}/_ws/_uds{}",
        http_port, socket_path_str
    ))?;
    let (ws_stream, _) = connect_async(url.as_str()).await?;
    let (mut write, mut read) = ws_stream.split();

    let message = b"Hello from WS UDS!";
    write.send(Message::Binary(message.to_vec())).await?;

    let msg = read.next().await.unwrap()?;
    if let Message::Binary(data) = msg {
        assert_eq!(&data[..], &message[..]);
    } else {
        panic!("Expected binary message, got {:?}", msg);
    }

    setup.server_handle.abort();
    Ok(())
}

#[tokio::test]
async fn test_ws_exec_cat() -> Result<()> {
    let setup = setup_test_environment(None, true).await?;
    let http_port = setup.http_port.expect("HTTP port should be set");

    let url = Url::parse(&format!("ws://127.0.0.1:{}/_ws/_exec/cat", http_port))?;
    let (ws_stream, _) = connect_async(url.as_str()).await?;
    let (mut write, mut read) = ws_stream.split();

    let message = b"Hello from WS cat!";
    write.send(Message::Binary(message.to_vec())).await?;

    let msg = read.next().await.unwrap()?;
    if let Message::Binary(data) = msg {
        assert_eq!(&data[..], &message[..]);
    } else {
        panic!("Expected binary message, got {:?}", msg);
    }

    setup.server_handle.abort();
    Ok(())
}

#[tokio::test]
async fn test_ws_ssh_proxy() -> Result<()> {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let testdata_dir = manifest_dir.join("tests/testdata");
    let alice_dir = testdata_dir.join("alice");
    let bob_dir = testdata_dir.join("bob");

    // Start server with bob's configuration
    let setup = setup_test_environment(Some(bob_dir), true).await?;
    let http_port = setup.http_port.expect("HTTP port should be set");

    let wst_binary = env!("CARGO_BIN_EXE_wst");
    let proxy_command = format!("{} ws://127.0.0.1:{}/_ws/_ssh", wst_binary, http_port);

    // Use alice's keys and configs to connect
    let mut ssh_client_process = tokio::process::Command::new("ssh")
        .arg("-v")
        .arg("-o")
        .arg("StrictHostKeyChecking=yes")
        .arg("-o")
        .arg("CheckHostIP=no")
        .arg("-o")
        .arg(format!(
            "UserKnownHostsFile={}",
            alice_dir.join("known_hosts").to_str().unwrap()
        ))
        .arg("-o")
        .arg("GlobalKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg("-o")
        .arg("ControlMaster=no")
        .arg("-o")
        .arg("ControlPath=none")
        .arg("-o")
        .arg(format!("ProxyCommand={}", proxy_command))
        .arg("-o")
        .arg("HostName=127.0.0.1")
        .arg("-i")
        .arg(alice_dir.join("id_ecdsa").to_str().unwrap())
        .arg("-p")
        .arg("22")
        .arg("-l")
        .arg("alice@test.m")
        .arg("bob.test.m")
        .arg("echo 'SUCCESS'")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()?;

    let mut output = String::new();
    let mut stdout = ssh_client_process.stdout.take().unwrap();

    let read_res = tokio::time::timeout(Duration::from_secs(25), async {
        stdout.read_to_string(&mut output).await
    })
    .await;

    println!("SSH STDOUT: {}", output);

    match read_res {
        Ok(Ok(_)) => {
            if !output.contains("SUCCESS") {
                panic!("SSH failed. Output: {}", output);
            }
        }
        Ok(Err(e)) => panic!("Failed to read SSH stdout: {}", e),
        Err(_) => {
            let _ = ssh_client_process.kill().await;
            panic!("SSH command timed out. Output: {}", output);
        }
    }

    setup.server_handle.abort();
    Ok(())
}
