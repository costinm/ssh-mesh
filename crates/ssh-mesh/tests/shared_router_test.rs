//! Shared node routing across authenticated HTTP and actual SSH channels.
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use mesh::resolve::{Address, Protocol, Trail};
use mesh::tagged::{NameOrTag, TaggedRecord};
use mesh::wire::{TaggedRecordHandler, response_ok};
use serde_json::json;
use ssh_mesh::auth::MasterSecret;
use ssh_mesh::httpauth::{AuthMode, HttpAuth, HttpAuthConfig, Secrets};
use ssh_mesh::router::{RouteEntry, RouteMatch, RoutePolicy, RouteSource, RouteTarget};
use ssh_mesh::sshc::SshClientManager;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn connect_fixture(manager: &SshClientManager, port: u16) -> Result<u64> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match manager.connect("127.0.0.1", port, "testuser", "").await {
            Ok(connection) => return Ok(connection),
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => return Err(error),
        }
    }
}
use tower::Service;

fn web(node: &ssh_mesh::MeshNode) -> (Router, String) {
    let secrets = Secrets::from_master(&MasterSecret::from_bytes([41; 32]));
    let key = secrets.api_key("testuser").unwrap();
    let auth = HttpAuth::new(secrets, AuthMode::ApiKey, &HttpAuthConfig::default(), true);
    (
        auth.apply_web(ssh_mesh::http_proxy::routes(
            node.router.clone(),
            Router::new(),
        )),
        key,
    )
}

async fn http(
    app: &mut Router,
    host: &str,
    key: &str,
    path: &str,
    payload: Option<Vec<u8>>,
) -> Result<(StatusCode, Vec<u8>)> {
    let request = if payload.is_some() {
        Request::post(path)
    } else {
        Request::get(path)
    }
    .header("host", host)
    .header("authorization", format!("Bearer {key}"))
    .body(Body::from(payload.unwrap_or_default()))?;
    let response = app.call(request).await?;
    let status = response.status();
    let body = tokio::time::timeout(
        Duration::from_secs(5),
        axum::body::to_bytes(response.into_body(), 65536),
    )
    .await??;
    Ok((status, body.to_vec()))
}

async fn backend(marker: &'static str) -> Result<(u16, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let app = Router::new().fallback(move || async move { marker });
    Ok((
        port,
        tokio::spawn(async { axum::serve(listener, app).await.unwrap() }),
    ))
}

fn forwarding(host: &str, port: u16, identity: &str) -> RouteEntry {
    RouteEntry {
        matches: RouteMatch::Host(host.into()),
        target: RouteTarget::Trails(vec![Trail::new(
            Address::Host {
                host: "127.0.0.1".into(),
                port: Some(port),
            },
            Protocol::Http,
        )]),
        policy: RoutePolicy {
            allow: vec![identity.into()],
            local_only: false,
        },
        source: RouteSource::Static {
            file: "shared-test".into(),
        },
    }
}

#[tokio::test]
async fn http_stream_and_ssh_observe_the_same_route_updates_and_policy() -> Result<()> {
    let setup = ssh_mesh::test_utils::setup_test_environment(None, false).await?;
    let manager = SshClientManager::new(
        ssh_mesh::auth::load_or_generate_key(&setup.base_dir),
        vec![],
        None,
        None,
    );
    let connection = connect_fixture(&manager, setup.ssh_port).await?;
    let (mut app, key) = web(&setup.mesh_node);
    let first = backend("first backend").await?;
    let second = backend("second backend").await?;
    for (port, expected) in [(first.0, "first backend"), (second.0, "second backend")] {
        setup.mesh_node.router.table.set_static_source(
            "shared-test",
            vec![forwarding("shared-router.invalid", port, "testuser")],
        );
        let (status, body) = http(&mut app, "shared-router.invalid", &key, "/", None).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, expected.as_bytes());
        let mut stream = manager
            .open_stream(connection, "shared-router.invalid", 443)
            .await?;
        stream
            .write_all(
                b"GET / HTTP/1.1\r\nHost: shared-router.invalid\r\nConnection: close\r\n\r\n",
            )
            .await?;
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_string(&mut response))
            .await??;
        assert!(response.contains(expected), "{response}");
        // A full-duplex HTTP tunnel keeps its transmit body open while
        // consuming the response; END_STREAM is a TCP write-half close.
        use http_body_util::BodyExt;
        let (sender, receiver) =
            tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(1);
        sender
            .send(Ok(bytes::Bytes::from_static(
                b"GET / HTTP/1.1\r\nHost: shared-router.invalid\r\nConnection: close\r\n\r\n",
            )))
            .await?;
        let request = Request::post("/_m/stream")
            .header("host", "shared-router.invalid")
            .header("authorization", format!("Bearer {key}"))
            .body(Body::from_stream(
                tokio_stream::wrappers::ReceiverStream::new(receiver),
            ))?;
        let response = app.call(request).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body();
        let mut received = Vec::new();
        while !String::from_utf8_lossy(&received).contains(expected) {
            let frame = tokio::time::timeout(Duration::from_secs(3), body.frame())
                .await?
                .ok_or_else(|| anyhow::anyhow!("tunnel ended before backend response"))??;
            if let Ok(data) = frame.into_data() {
                received.extend_from_slice(&data);
            }
        }
        drop(sender);
        let _ = tokio::time::timeout(Duration::from_secs(3), axum::body::to_bytes(body, 65536))
            .await??;
    }
    // Loading the HTTP mapping source cannot erase another source's routes.
    ssh_mesh::http_proxy::configure(
        &setup.mesh_node.router,
        &std::collections::HashMap::from([(
            "another.invalid".into(),
            format!("127.0.0.1:{}", first.0),
        )]),
    )?;
    assert_eq!(
        http(&mut app, "shared-router.invalid", &key, "/", None)
            .await?
            .1,
        b"second backend"
    );
    // A denied shared route must not fall through to allow_direct_tcpip's TCP dial.
    setup.mesh_node.router.table.set_static_source(
        "shared-test",
        vec![forwarding("localhost", first.0, "different-user")],
    );
    assert_eq!(
        http(&mut app, "localhost", &key, "/", None).await?.0,
        StatusCode::FORBIDDEN
    );
    assert!(
        manager
            .open_stream(connection, "localhost", first.0)
            .await
            .is_err()
    );
    manager.disconnect(connection).await?;
    first.1.abort();
    second.1.abort();
    setup.abort_server();
    Ok(())
}

struct Echo;
#[async_trait::async_trait]
impl TaggedRecordHandler for Echo {
    async fn handle_record(&self, request: TaggedRecord) -> Result<Option<TaggedRecord>> {
        Ok(request.id.map(|id| response_ok(id, json!("node registry"))))
    }
}

#[tokio::test]
async fn node_component_registry_is_shared_with_http_and_ssh_stream_routing() -> Result<()> {
    let setup = ssh_mesh::test_utils::setup_test_environment(None, false).await?;
    let (mut app, key) = web(&setup.mesh_node);
    // Register after the HTTP adapter and node locator have been constructed.
    setup.mesh_node.mesh_services.register(
        "echo",
        ssh_mesh::mesh_rest::MeshService {
            backend: ssh_mesh::mesh_rest::MeshServiceBackend::Direct(Arc::new(Echo)),
            encoding: ssh_mesh::mesh_rest::MeshServiceEncoding::TaggedCbor,
            component: "echo".into(),
        },
    );
    setup.mesh_node.router.table.set_static_source(
        "components",
        vec![RouteEntry {
            matches: RouteMatch::IpPrefix {
                addr: "127.0.0.2".parse()?,
                len: 32,
            },
            target: RouteTarget::Local {
                vhost: None,
                component: Some("echo".into()),
            },
            policy: RoutePolicy {
                allow: vec!["testuser".into()],
                local_only: false,
            },
            source: RouteSource::Static {
                file: "components".into(),
            },
        }],
    );
    let request = TaggedRecord {
        component: NameOrTag::Name("echo".into()),
        method: NameOrTag::Name("ping".into()),
        id: Some(json!(1)),
        ..Default::default()
    };
    let bytes = mesh::cbor::encode_stream_frame(&mesh::cbor::encode_record(&request)?)?;
    let (status, body) = http(
        &mut app,
        "127.0.0.2",
        &key,
        "/_m/stream/echo/ping",
        Some(bytes),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let reply = mesh::cbor::decode_record(mesh::cbor::decode_stream_frame(&body)?)?;
    assert_eq!(reply.result, Some(json!("node registry")));
    let manager = SshClientManager::new(
        ssh_mesh::auth::load_or_generate_key(&setup.base_dir),
        vec![],
        None,
        None,
    );
    let connection = connect_fixture(&manager, setup.ssh_port).await?;
    let mut stream = manager.open_stream(connection, "127.0.0.2", 7777).await?;
    mesh::wire::write_cbor_record(&mut stream, &request).await?;
    let reply = tokio::time::timeout(
        Duration::from_secs(5),
        mesh::wire::read_cbor_record(&mut stream),
    )
    .await??
    .unwrap();
    assert_eq!(reply.result, Some(json!("node registry")));
    manager.disconnect(connection).await?;
    setup.abort_server();
    Ok(())
}
