//! Routing bugs found in the first review of the `/_m` routes: prefixed
//! paths broke every handler that extracts path parameters, a bare `/_m/_uds`
//! always failed, the admin fallback matched `/_m/adm` anywhere in a path,
//! and a TCP port was parsed as `u32`.

use anyhow::Result;
use reqwest::{Client, StatusCode, redirect::Policy};
use ssh_mesh::test_utils::setup_test_environment;

fn client() -> Client {
    Client::builder().redirect(Policy::none()).build().unwrap()
}

#[tokio::test]
async fn prefixed_mesh_routes_reach_their_handlers() -> Result<()> {
    let setup = setup_test_environment(None, true).await?;
    let base = format!("http://127.0.0.1:{}", setup.http_port.unwrap());
    let c = client();

    // `_tcp` and `_uds` extract path parameters; with a prefix they used to
    // fail with 400 / 500 before reaching the handler, which answers 405 to
    // anything but POST.
    for prefix in ["", "/a", "/a/b"] {
        for path in ["/_m/_tcp/127.0.0.1/80", "/_m/_uds/tmp/none.sock"] {
            let res = c.get(format!("{base}{prefix}{path}")).send().await?;
            assert_eq!(
                res.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "GET {prefix}{path}"
            );
        }
    }

    // The admin index and the redirect keep the prefix.
    for prefix in ["", "/a", "/a/b"] {
        let res = c.get(format!("{base}{prefix}/_m/adm/")).send().await?;
        assert_eq!(res.status(), StatusCode::OK, "{prefix}/_m/adm/");
    }
    let res = c.get(format!("{base}/a/b/_m/adm")).send().await?;
    assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(res.headers()["location"], "/a/b/_m/adm/");
    Ok(())
}

#[tokio::test]
async fn bare_uds_route_is_not_a_server_error() -> Result<()> {
    let setup = setup_test_environment(None, true).await?;
    let base = format!("http://127.0.0.1:{}", setup.http_port.unwrap());
    let res = client().post(format!("{base}/_m/_uds")).send().await?;
    assert_ne!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}

#[tokio::test]
async fn tcp_port_is_a_u16() -> Result<()> {
    let setup = setup_test_environment(None, true).await?;
    let base = format!("http://127.0.0.1:{}", setup.http_port.unwrap());
    let res = client()
        .post(format!("{base}/_m/_tcp/127.0.0.1/70000"))
        .send()
        .await?;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn admin_fallback_only_applies_to_short_prefixes() -> Result<()> {
    let setup = setup_test_environment(None, true).await?;
    let base = format!("http://127.0.0.1:{}", setup.http_port.unwrap());
    // Three leading segments are an upstream app's path, not a prefix of ours.
    let res = client().get(format!("{base}/a/b/c/_m/adm/")).send().await?;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    Ok(())
}

/// Serve `router` on a free loopback port and return its base URL.
async fn serve(router: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{addr}")
}

/// What a listener reachable from the network serves: the admin routes
/// (`_exec`, `_tcp`, `_uds`, the SSH client API, the mesh REST API) have no
/// authorization of their own and must not be there.
#[tokio::test]
async fn public_router_does_not_serve_admin_routes() -> Result<()> {
    let setup = setup_test_environment(None, false).await?;
    let node = setup.mesh_node.clone();
    let state = || ssh_mesh::AppState {
        ssh_server: node.clone(),
        target_http_address: None,
        ssh_client_manager: std::sync::Arc::new(ssh_mesh::sshc::SshClientManager::new(
            node.private_key().clone(),
            Vec::new(),
            None,
            None,
        )),
        mesh_services: ssh_mesh::mesh_rest::MeshServiceRegistry::default(),
        web_root: None,
    };
    let public = serve(ssh_mesh::handlers::app_core(state())).await;
    let full = serve(ssh_mesh::handlers::app(state())).await;
    let c = client();

    let admin = [
        ("POST", "/_m/_exec/ls"),
        ("POST", "/_m/_tcp/127.0.0.1/80"),
        ("POST", "/_m/_uds/tmp/x.sock"),
        ("GET", "/_m/api/ssh/clients"),
        ("GET", "/_m/api/sshc/connections"),
        ("GET", "/_m/mesh/services"),
    ];
    for (method, path) in admin {
        let request = |base: &str| {
            c.request(method.parse().unwrap(), format!("{base}{path}"))
                .send()
        };
        assert_eq!(
            request(&public).await?.status(),
            StatusCode::NOT_FOUND,
            "public {method} {path}"
        );
        // Control: the full router does serve it.
        assert_ne!(
            request(&full).await?.status(),
            StatusCode::NOT_FOUND,
            "full {method} {path}"
        );
    }
    Ok(())
}
