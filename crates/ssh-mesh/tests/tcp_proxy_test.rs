use anyhow::Result;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Bytes, Frame};
use hyper::{Method, Request};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use ssh_mesh::test_utils::{find_free_port, setup_test_environment};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc;
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

async fn test_tcp_proxy_with_method(method: Method) -> Result<()> {
    let setup = setup_test_environment(None, true).await?;
    let http_port = setup.http_port.expect("HTTP port should be set");

    let echo_port = find_free_port()?;
    start_echo_server(echo_port);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create HTTP/2 client
    let mut https_connector = HttpConnector::new();
    https_connector.enforce_http(false);

    let client = Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build(https_connector);

    let uri = format!(
        "http://127.0.0.1:{}/_tcp/127.0.0.1/{}",
        http_port, echo_port
    );

    // Create a channel for sending body chunks
    let (tx, rx) =
        mpsc::channel::<Result<Frame<Bytes>, Box<dyn std::error::Error + Send + Sync>>>(10);
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = StreamBody::new(stream);

    let request = Request::builder().method(method).uri(uri).body(body)?;
    let method_str = request.method().to_string();
    let response = client.request(request).await?;

    assert_eq!(
        response.status(),
        200,
        "Response status should be 200 for method {}",
        method_str
    );

    let message = b"Hello, TCP proxy test!";
    tx.send(Ok(Frame::data(Bytes::from_static(message))))
        .await
        .unwrap();

    let mut response_body = response.into_body();
    let frame_opt = timeout(Duration::from_secs(5), BodyExt::frame(&mut response_body))
        .await
        .map_err(|e| anyhow::anyhow!("Timeout waiting for response: {}", e))?;
    let frame_res = frame_opt.ok_or_else(|| anyhow::anyhow!("Response body ended prematurely"))?;
    let frame = frame_res.map_err(|e| anyhow::anyhow!("Hyper error: {}", e))?;

    let data = frame
        .into_data()
        .map_err(|_| anyhow::anyhow!("Frame was not data"))?;

    assert_eq!(&data[..], &message[..]);

    // Cleanup
    drop(tx); // Close the request stream
    setup.server_handle.abort();
    Ok(())
}

#[tokio::test]
async fn test_tcp_proxy_post() -> Result<()> {
    test_tcp_proxy_with_method(Method::POST).await
}
