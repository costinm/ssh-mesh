use mesh::local_trace::{self, LogEntry};
use otel::trace_server::{trace_router, TraceServerState};
use std::time::Duration;

/// Helper: start the trace server on a random port, return the base URL
async fn start_test_server(base_dir: std::path::PathBuf) -> (String, TraceServerState) {
    let state = TraceServerState::new(base_dir);
    let app = trace_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    (format!("http://{}", addr), state)
}

#[tokio::test]
async fn test_discover_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let (base_url, _state) = start_test_server(tmp.path().to_path_buf()).await;

    let resp = reqwest::get(format!("{}/api/discover", base_url))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert!(body.is_empty(), "Expected empty discover list");
}

#[tokio::test]
async fn test_discover_finds_sockets() {
    let tmp = tempfile::tempdir().unwrap();
    // Create fake .sock files
    std::fs::write(tmp.path().join("app1.sock"), "").unwrap();
    std::fs::write(tmp.path().join("app2.sock"), "").unwrap();
    std::fs::write(tmp.path().join("not-a-socket.txt"), "").unwrap();

    let (base_url, _state) = start_test_server(tmp.path().to_path_buf()).await;

    let resp = reqwest::get(format!("{}/api/discover", base_url))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(
        body.len(),
        2,
        "Should discover 2 .sock files, got {:?}",
        body
    );

    let names: Vec<&str> = body.iter().map(|v| v["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"app1"));
    assert!(names.contains(&"app2"));
}

#[tokio::test]
async fn test_connect_nonexistent_source() {
    let tmp = tempfile::tempdir().unwrap();
    let (base_url, _state) = start_test_server(tmp.path().to_path_buf()).await;

    let resp = reqwest::get(format!(
        "{}/api/sources/connect?name=bad&path=/nonexistent/path.sock",
        base_url
    ))
    .await
    .unwrap();
    // Should fail with 502 since socket doesn't exist
    assert_eq!(resp.status(), 502);
}

#[tokio::test]
async fn test_connect_and_disconnect_source() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("test.sock");

    // Start a UDS listener that the trace server can connect to
    let log_buffer = local_trace::create_log_buffer();
    let sock_path_str = sock_path.to_string_lossy().to_string();
    let listener_buffer = log_buffer.clone();
    let listener_path = sock_path.clone();
    tokio::spawn(async move {
        let _ = local_trace::start_uds_listener(&listener_path, listener_buffer).await;
    });
    // Give the listener time to start
    tokio::time::sleep(Duration::from_millis(200)).await;

    let (base_url, _state) = start_test_server(tmp.path().to_path_buf()).await;

    // Connect
    let resp = reqwest::get(format!(
        "{}/api/sources/connect?name=test&path={}",
        base_url,
        urlencoding::encode(&sock_path_str)
    ))
    .await
    .unwrap();
    assert_eq!(resp.status(), 200, "Connect should succeed");

    // List sources — should have 1
    let resp = reqwest::get(format!("{}/api/sources", base_url))
        .await
        .unwrap();
    let sources: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0]["name"], "test");

    // Connect again — should 409 conflict
    let resp = reqwest::get(format!(
        "{}/api/sources/connect?name=test&path={}",
        base_url,
        urlencoding::encode(&sock_path_str)
    ))
    .await
    .unwrap();
    assert_eq!(resp.status(), 409);

    // Disconnect
    let resp = reqwest::get(format!("{}/api/sources/disconnect?name=test", base_url))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // List should be empty now
    let resp = reqwest::get(format!("{}/api/sources", base_url))
        .await
        .unwrap();
    let sources: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert!(
        sources.is_empty(),
        "Sources should be empty after disconnect"
    );
}

#[tokio::test]
async fn test_disconnect_nonexistent() {
    let tmp = tempfile::tempdir().unwrap();
    let (base_url, _state) = start_test_server(tmp.path().to_path_buf()).await;

    let resp = reqwest::get(format!(
        "{}/api/sources/disconnect?name=doesnotexist",
        base_url
    ))
    .await
    .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_connect_and_stream_sse() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("producer.sock");
    let sock_path_str = sock_path.to_string_lossy().to_string();

    // Start a UDS trace listener (the producer side)
    let log_buffer = local_trace::create_log_buffer();
    let listener_buffer = log_buffer.clone();
    let listener_path = sock_path.clone();
    tokio::spawn(async move {
        let _ = local_trace::start_uds_listener(&listener_path, listener_buffer).await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let (base_url, _state) = start_test_server(tmp.path().to_path_buf()).await;

    // Connect the source
    let resp = reqwest::get(format!(
        "{}/api/sources/connect?name=producer&path={}",
        base_url,
        urlencoding::encode(&sock_path_str)
    ))
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);

    // Give the UDS reader a moment to start
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Start SSE stream FIRST (before pushing data) so the subscriber is active
    let client = reqwest::Client::new();
    let mut resp = client
        .get(format!("{}/api/stream", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Push a log entry AFTER the SSE client is connected (from a spawned task)
    let push_buffer = log_buffer.clone();
    tokio::spawn(async move {
        // Small delay to ensure the SSE subscriber is receiving
        tokio::time::sleep(Duration::from_millis(300)).await;
        push_buffer.push(LogEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            level: "info".to_string(),
            target: "test_module".to_string(),
            message: "hello from SSE test".to_string(),
            fields: None,
        });
    });

    // Read chunks until we find our message or timeout
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let mut collected = String::new();
        while let Some(chunk) = resp.chunk().await.unwrap() {
            collected.push_str(&String::from_utf8_lossy(&chunk));
            if collected.contains("hello from SSE test") {
                return collected;
            }
        }
        collected
    })
    .await;

    assert!(
        result.is_ok(),
        "SSE stream should return data within timeout"
    );
    let body_text = result.unwrap();
    assert!(
        body_text.contains("hello from SSE test"),
        "SSE stream should contain our test message, got: {}",
        body_text
    );
}

#[tokio::test]
async fn test_perfetto_config() {
    let tmp = tempfile::tempdir().unwrap();
    let (base_url, _state) = start_test_server(tmp.path().to_path_buf()).await;

    let resp = reqwest::get(format!("{}/api/perfetto", base_url))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["socket"], "/tmp/perfetto-consumer");
    assert_eq!(body["connected"], false);
}

#[tokio::test]
async fn test_otel_status_and_toggle() {
    let tmp = tempfile::tempdir().unwrap();
    let (base_url, _state) = start_test_server(tmp.path().to_path_buf()).await;

    // Initial status should be inactive
    let resp = reqwest::get(format!("{}/api/otel", base_url))
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["active"], false);

    // Toggle on
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/otel/toggle", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["active"], true);

    // Toggle off
    let resp = client
        .post(format!("{}/api/otel/toggle", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["active"], false);
}

#[tokio::test]
async fn test_serve_trace_viewer_html() {
    let tmp = tempfile::tempdir().unwrap();
    let (base_url, _state) = start_test_server(tmp.path().to_path_buf()).await;

    let resp = reqwest::get(format!("{}/", base_url)).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("Trace Hub"), "Should serve trace_viewer.html");
}

#[tokio::test]
async fn test_sse_source_filter() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("filtered.sock");
    let sock_path_str = sock_path.to_string_lossy().to_string();

    let log_buffer = local_trace::create_log_buffer();
    let listener_buffer = log_buffer.clone();
    let listener_path = sock_path.clone();
    tokio::spawn(async move {
        let _ = local_trace::start_uds_listener(&listener_path, listener_buffer).await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let (base_url, _state) = start_test_server(tmp.path().to_path_buf()).await;

    // Connect source
    reqwest::get(format!(
        "{}/api/sources/connect?name=filtered&path={}",
        base_url,
        urlencoding::encode(&sock_path_str)
    ))
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Push a log (will have source="filtered" from the trace server)
    log_buffer.push(LogEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        level: "warn".to_string(),
        target: "filter_test".to_string(),
        message: "filter message".to_string(),
        fields: None,
    });

    // Stream with a source filter for a different source — should NOT get our message
    let resp = reqwest::get(format!("{}/api/stream?sources=other_source", base_url))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // With a short timeout, we should NOT see the message since it's filtered
    let body =
        tokio::time::timeout(Duration::from_secs(2), async { resp.text().await.unwrap() }).await;

    // Timeout is expected (no matching data), or empty
    match body {
        Err(_) => {} // Timeout is expected — no matching event
        Ok(text) => {
            assert!(
                !text.contains("filter message"),
                "Filtered source stream should not contain the message"
            );
        }
    }
}
