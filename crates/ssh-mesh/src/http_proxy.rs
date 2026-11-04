//! HTTPS adapter for the stream router and the shared HTTP reverse proxy.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header, uri::Authority};
use axum::response::{IntoResponse, Response};
use mesh::resolve::{Address, Protocol, Trail};
use tower::Service;

use crate::httpauth::Identity;
use crate::router::{
    Caller, Destination, Ingress, RouteEntry, RouteError, RouteMatch, RoutePolicy, RouteSource,
    RouteTarget, Router as StreamRouter, StreamRequest,
};

#[derive(Clone)]
struct ProxyState {
    router: Arc<StreamRouter>,
    fallback: Router,
}

/// Load HTTPS host mappings into the stream router's static route table.
///
/// Keys are DNS names without ports; values are HTTP upstream `host:port`
/// authorities. Invalid or duplicate normalized names and upstreams are errors.
/// Other static sources and verified dynamic routes remain in the shared table.
pub fn configure(router: &StreamRouter, hosts: &HashMap<String, String>) -> anyhow::Result<()> {
    let mut names = HashSet::new();
    let mut entries = Vec::new();
    for (host, upstream) in hosts {
        let _: Authority = host.parse()?;
        let name = match Destination::from_authority(host) {
            Some(Destination::Host { name, port: None }) => name,
            _ => anyhow::bail!("invalid HTTP proxy host: {host}"),
        };
        let authority: Authority = upstream
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid HTTP proxy upstream for {host}"))?;
        anyhow::ensure!(
            authority.port_u16().is_some() && !authority.as_str().contains('@'),
            "HTTP proxy upstream for {host} must be host:port"
        );
        anyhow::ensure!(
            names.insert(name.clone()),
            "duplicate HTTP proxy host: {host}"
        );
        entries.push(RouteEntry {
            matches: RouteMatch::Host(name),
            target: RouteTarget::Trails(vec![Trail::new(
                Address::Host {
                    host: authority
                        .host()
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .to_string(),
                    port: authority.port_u16(),
                },
                Protocol::Http,
            )]),
            policy: RoutePolicy::default(),
            source: RouteSource::Static {
                file: "http_proxies".to_string(),
            },
        });
    }
    router.table.set_static_source("http_proxies", entries);
    Ok(())
}

/// Adapt HTTPS requests to a node-owned router and the shared reverse proxy.
/// The caller must wrap this application in HTTPS web authentication.
pub fn routes(router: Arc<StreamRouter>, fallback: Router) -> Router {
    Router::new()
        .route("/_m/stream", axum::routing::any(stream))
        .route("/_m/stream/*path", axum::routing::any(stream))
        .fallback(proxy)
        .with_state(Arc::new(ProxyState { router, fallback }))
}

async fn stream(State(state): State<Arc<ProxyState>>, mut request: Request) -> Response {
    if request
        .extensions()
        .get::<crate::httpauth::PublicWebHost>()
        .is_some()
    {
        return proxy(State(state), request).await;
    }
    let caller = caller(&request);
    let suffix = request
        .uri()
        .path()
        .strip_prefix("/_m/stream")
        .unwrap_or("/");
    let path = if suffix.is_empty() { "/" } else { suffix };
    let path = match request.uri().query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_string(),
    };
    let mut parts = request.uri().clone().into_parts();
    parts.path_and_query = match path.parse() {
        Ok(path) => Some(path),
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    *request.uri_mut() = match axum::http::Uri::from_parts(parts) {
        Ok(uri) => uri,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    crate::http_ingress::handle(state.router.clone(), caller, request).await
}

fn caller(request: &Request) -> Caller {
    Caller {
        identity: request
            .extensions()
            .get::<Identity>()
            .map(|id| id.name.clone()),
        ingress: Ingress::Http,
        local: false,
    }
}

async fn proxy(State(state): State<Arc<ProxyState>>, request: Request) -> Response {
    let authority = request
        .uri()
        .authority()
        .map(|a| a.as_str())
        .or_else(|| request.headers().get(header::HOST)?.to_str().ok());
    let destination = authority.and_then(Destination::from_authority);
    let route = destination.map(|destination| {
        state.router.check(&StreamRequest {
            destination,
            caller: caller(&request),
            header: crate::http_ingress::header_record(&request),
        })
    });
    let entry = match route {
        Some(Ok(entry)) => entry,
        Some(Err(RouteError::Denied)) => return StatusCode::FORBIDDEN.into_response(),
        None | Some(Err(RouteError::NoRoute)) => {
            return match state.fallback.clone().call(request).await {
                Ok(response) => response,
                Err(never) => match never {},
            };
        }
    };
    let target = match entry.target.first_trail_node() {
        Ok(target) => target,
        Err(error) => {
            log::warn!("HTTPS route has no HTTP upstream: {error}");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    crate::handlers::reverse_proxy_request(
        &target,
        request,
        crate::handlers::ProxyOptions {
            preserve_host: true,
            forwarded_proto: Some("https"),
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::{ConventionLocator, RouteTable};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{HeaderValue, Request};
    use axum::routing::get;
    use futures_util::{SinkExt, StreamExt};

    use crate::auth::MasterSecret;
    use crate::httpauth::{AuthMode, HttpAuth, HttpAuthConfig, Secrets};

    fn auth() -> (HttpAuth, String) {
        let secrets = Secrets::from_master(&MasterSecret::from_bytes([13; 32]));
        let key = secrets.api_key("proxy-test").unwrap();
        let config = HttpAuthConfig {
            exempt: vec!["/public/".to_string()],
            ..Default::default()
        };
        (HttpAuth::new(secrets, AuthMode::Login, &config, true), key)
    }

    fn configured(hosts: &HashMap<String, String>, fallback: Router) -> anyhow::Result<Router> {
        let router = Arc::new(StreamRouter {
            table: Arc::new(RouteTable::new()),
            client: Arc::new(mesh::route::TcpClient),
            locator: Arc::new(ConventionLocator {
                services: Default::default(),
                local_names: vec![],
            }),
            activator: None,
        });
        configure(&router, hosts)?;
        Ok(routes(router, fallback))
    }

    fn app(upstream: String) -> (Router, String) {
        let fallback = Router::new().fallback(|| async { "static fallback" });
        let router = configured(
            &HashMap::from([("oc.example.org".into(), upstream)]),
            fallback,
        )
        .unwrap();
        let (auth, key) = auth();
        (auth.apply_web(router), key)
    }

    #[tokio::test]
    async fn stream_router_policy_is_checked_for_authenticated_web_requests() {
        let table = Arc::new(RouteTable::new());
        table.set_static(vec![RouteEntry {
            matches: RouteMatch::Host("oc.example.org".into()),
            target: RouteTarget::Trails(vec![]),
            policy: RoutePolicy {
                allow: vec!["different-user".into()],
                local_only: false,
            },
            source: RouteSource::Static {
                file: "test".into(),
            },
        }]);
        let state = ProxyState {
            router: Arc::new(StreamRouter {
                table,
                client: Arc::new(mesh::route::TcpClient),
                locator: Arc::new(ConventionLocator {
                    services: Default::default(),
                    local_names: vec![],
                }),
                activator: None,
            }),
            fallback: Router::new().fallback(|| async { "fallback" }),
        };
        let (auth, key) = auth();
        let mut app = auth.apply_web(Router::new().fallback(proxy).with_state(Arc::new(state)));
        let response = app
            .call(
                Request::get("/")
                    .header("host", "oc.example.org")
                    .header("authorization", format!("Bearer {key}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn proxy_requires_auth_and_preserves_request_and_response() {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let backend = Router::new().fallback(move |request: axum::extract::Request| {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                let body = format!(
                    "{} {} {:?}",
                    request.method(),
                    request.uri(),
                    request.headers()
                );
                let data = axum::body::to_bytes(request.into_body(), 4096)
                    .await
                    .unwrap();
                (
                    StatusCode::CREATED,
                    [("x-backend", "yes")],
                    format!("{body}\n{}", String::from_utf8_lossy(&data)),
                )
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async { axum::serve(listener, backend).await.unwrap() });
        let (mut app, key) = app(target);
        for path in [
            "/",
            "/.well-known/private",
            "/_m/_ssh",
            "/_m/_ws/_ssh",
            "/public/private",
        ] {
            let response = app
                .call(
                    Request::get(path)
                        .header("host", "oc.example.org")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let browser = app
            .call(
                Request::get("/session?a=1")
                    .header("host", "oc.example.org")
                    .header("accept", "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(browser.status(), StatusCode::SEE_OTHER);
        assert!(
            browser.headers()[header::LOCATION]
                .to_str()
                .unwrap()
                .starts_with("/_m/login?next=")
        );

        let response = app
            .call(
                Request::post("/session?a=1")
                    .header("host", "OC.EXAMPLE.ORG:443")
                    .header("authorization", format!("Bearer {key}"))
                    .header("cookie", "app=value; mesh_session=private")
                    .header("connection", "keep-alive, x-hop")
                    .header("x-hop", "discard-me")
                    .body(Body::from("request body"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()["x-backend"], "yes");
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body = String::from_utf8_lossy(&body);
        assert!(body.contains("POST /session?a=1"), "{body}");
        assert!(body.contains("app=value"), "{body}");
        assert!(body.contains("https"), "{body}");
        assert!(body.contains("request body"), "{body}");
        assert!(
            !body.contains("mesh_session") && !body.contains(&key) && !body.contains("discard-me"),
            "{body}"
        );

        // Browser sessions use the same proxy after the gateway's login form.
        let login = app
            .call(
                Request::post("/_m/login")
                    .header("host", "oc.example.org")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!("key={key}&next=%2F")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::SEE_OTHER);
        let cookie = login.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let response = app
            .call(
                Request::get("/")
                    .header("host", "oc.example.org")
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let response = app
            .call(
                Request::get("/")
                    .header("host", "unrelated.example.org")
                    .header("authorization", format!("Bearer {key}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap(),
            "static fallback"
        );
        server.abort();
    }

    #[tokio::test]
    async fn gateway_session_preserves_independent_upstream_credentials() {
        let backend = Router::new().fallback(|request: axum::extract::Request| async move {
            assert_eq!(request.headers()["authorization"], "Basic YXBwOnBhc3M=");
            assert_eq!(request.headers()["x-api-key"], "application-key");
            assert_eq!(request.headers()["cookie"], "app=value");
            (
                [("set-cookie", "app=renewed; Path=/")],
                "authenticated upstream",
            )
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async { axum::serve(listener, backend).await.unwrap() });
        let (mut app, _) = app(target);
        let token = Secrets::from_master(&MasterSecret::from_bytes([13; 32])).issue_token(
            "proxy-test",
            Duration::from_secs(3600),
            std::time::SystemTime::now(),
        );
        let response = app
            .call(
                Request::get("/api/health")
                    .header("host", "oc.example.org")
                    .header("authorization", "Basic YXBwOnBhc3M=")
                    .header("x-api-key", "application-key")
                    .header("cookie", format!("app=value; mesh_session={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookies: Vec<_> = response.headers().get_all("set-cookie").iter().collect();
        assert_eq!(
            cookies.len(),
            2,
            "upstream and renewed gateway cookies survive"
        );
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap(),
            "authenticated upstream"
        );
        server.abort();
    }

    #[tokio::test]
    async fn per_host_auth_keeps_public_backend_and_admin_separate() {
        let backend = Router::new().fallback(|request: axum::extract::Request| async move {
            assert!(
                !request
                    .headers()
                    .get("cookie")
                    .is_some_and(|v| v.to_str().unwrap().contains("mesh_session"))
            );
            format!(
                "backend {} {}",
                request.uri(),
                request
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("none")
            )
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async { axum::serve(listener, backend).await.unwrap() });
        let router = configured(
            &HashMap::from([
                ("oc.example.org".into(), target.clone()),
                ("admin.example.org".into(), target),
            ]),
            Router::new(),
        )
        .unwrap();
        let secrets = Secrets::from_master(&MasterSecret::from_bytes([13; 32]));
        let config = HttpAuthConfig {
            hosts: HashMap::from([
                ("oc.example.org".into(), AuthMode::None),
                ("admin.example.org".into(), AuthMode::Login),
            ]),
            ..Default::default()
        };
        let mut app = HttpAuth::new(secrets, AuthMode::Login, &config, true).apply_web(router);
        for path in ["/api/location", "/_m/stream/internal/admin"] {
            let response = app
                .call(
                    Request::get(path)
                        .header("host", "OC.EXAMPLE.ORG:443")
                        .header("authorization", "Basic application-password")
                        .header("cookie", "mesh_session=old-gateway-cookie")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap(),
                format!("backend {path} Basic application-password")
            );
        }
        for host in [
            "admin.example.org",
            "ADMIN.EXAMPLE.ORG.:443",
            "unknown.example.org",
        ] {
            let response = app
                .call(
                    Request::get("/")
                        .header("host", host)
                        .header("accept", "text/html")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SEE_OTHER, "{host}");
        }
        server.abort();
    }

    #[tokio::test]
    async fn event_stream_is_forwarded_before_the_upstream_finishes() {
        use http_body_util::BodyExt;
        let (sender, receiver) =
            tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(2);
        let receiver = Arc::new(tokio::sync::Mutex::new(Some(receiver)));
        let backend = Router::new().route(
            "/events",
            get(move || {
                let receiver = receiver.clone();
                async move {
                    Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(
                        receiver.lock().await.take().unwrap(),
                    ))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async { axum::serve(listener, backend).await.unwrap() });
        let (mut app, key) = app(target);
        sender
            .send(Ok(bytes::Bytes::from_static(b"data: first\n\n")))
            .await
            .unwrap();
        let response = app
            .call(
                Request::get("/events")
                    .header("host", "oc.example.org")
                    .header("authorization", format!("Bearer {key}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let mut body = response.into_body();
        let frame = tokio::time::timeout(Duration::from_secs(2), body.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(frame.into_data().unwrap(), "data: first\n\n");
        drop(sender);
        server.abort();
    }

    #[tokio::test]
    async fn authenticated_websocket_upgrade_is_bidirectional() {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = upstream.local_addr().unwrap().to_string();
        let backend = tokio::spawn(async move {
            let (stream, _) = upstream.accept().await.unwrap();
            let mut websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let message = websocket.next().await.unwrap().unwrap();
            websocket.send(message).await.unwrap();
        });
        let (app, key) = app(target);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let certificate =
            rcgen::generate_simple_self_signed(vec!["oc.example.org".into()]).unwrap();
        let cert = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        std::fs::write(&cert, certificate.cert.pem()).unwrap();
        std::fs::write(&key_path, certificate.signing_key.serialize_pem()).unwrap();
        let tls =
            crate::auth::TlsServer::new(&cert, &key_path, None, &address.to_string()).unwrap();
        let server = tokio::spawn(async {
            crate::auth::run_axum_https_listener(listener, tls.acceptor, app)
                .await
                .unwrap()
        });
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate.cert.der().clone()).unwrap();
        let connector = tokio_tungstenite::Connector::Rustls(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let mut request = format!("wss://oc.example.org:{}/terminal", address.port())
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert(header::HOST, HeaderValue::from_static("oc.example.org"));
        request.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {key}")).unwrap(),
        );
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let (mut websocket, _) =
            tokio_tungstenite::client_async_tls_with_config(request, stream, None, Some(connector))
                .await
                .unwrap();
        websocket
            .send(tokio_tungstenite::tungstenite::Message::Text(
                "duplex proof".into(),
            ))
            .await
            .unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(2), websocket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(echoed.into_text().unwrap(), "duplex proof");
        backend.await.unwrap();
        server.abort();
    }

    #[test]
    fn invalid_upstreams_and_duplicate_normalized_hosts_are_rejected() {
        for upstream in ["http://127.0.0.1:80/path", "127.0.0.1", "user@127.0.0.1:80"] {
            assert!(
                configured(
                    &HashMap::from([("oc.example.org".into(), upstream.into())]),
                    Router::new()
                )
                .is_err()
            );
        }
        assert!(
            configured(
                &HashMap::from([
                    ("OC.example.org".into(), "127.0.0.1:1".into()),
                    ("oc.example.org.".into(), "127.0.0.1:2".into())
                ]),
                Router::new()
            )
            .is_err()
        );
    }
}
