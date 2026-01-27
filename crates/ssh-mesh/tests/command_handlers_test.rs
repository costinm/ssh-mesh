use anyhow::Result;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Bytes, Frame};
use hyper::{Method, Request, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use ssh_mesh::test_utils::setup_test_environment;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio::time::timeout;

async fn create_h2_client() -> Client<
    HttpConnector,
    StreamBody<
        tokio_stream::wrappers::ReceiverStream<
            Result<Frame<Bytes>, Box<dyn std::error::Error + Send + Sync>>,
        >,
    >,
> {
    let mut https_connector = HttpConnector::new();
    https_connector.enforce_http(false);

    Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build(https_connector)
}

#[tokio::test]
async fn test_uds_proxy() -> Result<()> {
    let setup = setup_test_environment(None, true).await?;
    let http_port = setup.http_port.expect("HTTP port should be set");

    let tmp_dir = tempfile::tempdir()?;
    let socket_path = tmp_dir.path().join("test.sock");
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

    let client = create_h2_client().await;
    let (tx, rx) =
        mpsc::channel::<Result<Frame<Bytes>, Box<dyn std::error::Error + Send + Sync>>>(10);
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = StreamBody::new(stream);

    let uri = format!("http://127.0.0.1:{}/_uds{}", http_port, socket_path_str);
    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .body(body)?;

    let response = client.request(request).await?;
    assert_eq!(response.status(), StatusCode::OK);

    let message = b"Hello from UDS!";
    tx.send(Ok(Frame::data(Bytes::from_static(message))))
        .await
        .unwrap();

    let mut response_body = response.into_body();
    let frame_opt = timeout(Duration::from_secs(5), BodyExt::frame(&mut response_body))
        .await
        .map_err(|e| anyhow::anyhow!("Timeout: {}", e))?;

    let frame_res = frame_opt.ok_or_else(|| anyhow::anyhow!("No frame"))?;
    let frame = frame_res.map_err(|e| anyhow::anyhow!("Hyper error: {}", e))?;
    let data = frame.into_data().map_err(|_| anyhow::anyhow!("Not data"))?;
    assert_eq!(&data[..], &message[..]);

    setup.server_handle.abort();
    Ok(())
}

#[tokio::test]
async fn test_exec_cat() -> Result<()> {
    let setup = setup_test_environment(None, true).await?;
    let http_port = setup.http_port.expect("HTTP port should be set");

    let client = create_h2_client().await;
    let (tx, rx) =
        mpsc::channel::<Result<Frame<Bytes>, Box<dyn std::error::Error + Send + Sync>>>(10);
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = StreamBody::new(stream);

    let uri = format!("http://127.0.0.1:{}/_exec/cat", http_port);
    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .body(body)?;

    let response = client.request(request).await?;
    assert_eq!(response.status(), StatusCode::OK);

    let message = b"Hello from cat!";
    tx.send(Ok(Frame::data(Bytes::from_static(message))))
        .await
        .unwrap();

    let mut response_body = response.into_body();
    let frame_opt = timeout(Duration::from_secs(5), BodyExt::frame(&mut response_body))
        .await
        .map_err(|e| anyhow::anyhow!("Timeout: {}", e))?;

    let frame_res = frame_opt.ok_or_else(|| anyhow::anyhow!("No frame"))?;
    let frame = frame_res.map_err(|e| anyhow::anyhow!("Hyper error: {}", e))?;
    let data = frame.into_data().map_err(|_| anyhow::anyhow!("Not data"))?;
    assert_eq!(&data[..], &message[..]);

    setup.server_handle.abort();
    Ok(())
}

#[tokio::test]
async fn test_exec_env() -> Result<()> {
    let setup = setup_test_environment(None, true).await?;
    let http_port = setup.http_port.expect("HTTP port should be set");

    let client = create_h2_client().await;
    let (_tx, rx) =
        mpsc::channel::<Result<Frame<Bytes>, Box<dyn std::error::Error + Send + Sync>>>(10);
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = StreamBody::new(stream);

    // We use a command that prints an environment variable
    let uri = format!("http://127.0.0.1:{}/_exec/echo%20%24TEST_VAR", http_port);
    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("X-E-TEST-VAR", "SUCCESS")
        .body(body)?;

    let response = client.request(request).await?;
    drop(_tx); // Signal EOF to the server
    assert_eq!(response.status(), StatusCode::OK);

    let mut response_body = response.into_body();
    let mut full_data = Vec::new();
    while let Some(frame_res) = response_body.frame().await {
        let frame = frame_res?;
        if let Ok(data) = frame.into_data() {
            full_data.extend_from_slice(&data);
        }
    }

    let output = String::from_utf8(full_data)?;
    assert!(output.contains("SUCCESS"));

    setup.server_handle.abort();
    Ok(())
}
