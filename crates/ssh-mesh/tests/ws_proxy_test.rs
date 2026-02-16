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

