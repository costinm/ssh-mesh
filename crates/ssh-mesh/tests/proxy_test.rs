use axum::{Router, body::Body, http::Request, routing::get};
use ssh_mesh::test_utils::{find_free_port, setup_test_environment};

#[tokio::test]
async fn test_mesh_proxy_fallback() {
    // 1. Start a small echo http handler
    let echo_port = find_free_port().unwrap();

    let echo_app = Router::new().route(
        "/*path",
        get(|req: Request<Body>| async move {
            let path = req.uri().path().to_string();
            format!("Mesh Echo: {}", path)
        }),
    );

    let echo_listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", echo_port))
        .await
        .unwrap();

    tokio::spawn(async move {
        axum::serve(echo_listener, echo_app).await.unwrap();
    });

    // 2. Start ssh-mesh with target_http_address pointing to echo server
    // We need to set HTTP_PORT environment variable for the mesh to pick it up in AppState
    // SAFETY: We ensure HTTP_PORT is only used in single-threaded tests
    unsafe { std::env::set_var("HTTP_PORT", echo_port.to_string()) };

    let setup = setup_test_environment(None, true).await.unwrap();
    let mesh_port = setup.http_port.expect("HTTP port should be set");

    // Give servers a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // 3. Test mesh routes
    let client = reqwest::Client::new();

    // Test /_sshm/admin (should be mesh's own route)
    let res = client
        .get(format!("http://127.0.0.1:{}/_sshm/admin", mesh_port))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    // DASHBOARD check
    let body = res.text().await.unwrap();
    // Assuming the index serves something with "SSH" or similar
    // The index route serves "ssh.html" which should contain "SSH"
    assert!(body.contains("SSH"));

    // Test fallback proxy
    let res = client
        .get(format!("http://127.0.0.1:{}/some/random/path", mesh_port))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    let body = res.text().await.unwrap();
    assert_eq!(body, "Mesh Echo: /some/random/path");

    setup.server_handle.abort();
    // SAFETY: Cleaning up after test
    unsafe { std::env::remove_var("HTTP_PORT") };
}
