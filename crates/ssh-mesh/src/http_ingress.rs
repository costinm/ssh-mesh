//! HTTP entry point for the stream router.
//!
//! Turns an HTTP `POST` or `CONNECT` into a [`StreamRequest`] and a
//! bidirectional stream (request body in, response body out), then hands both
//! to [`Router::route_stream`]. The destination is the URI authority (CONNECT
//! target or HTTP/2 `:authority`), else the `Host` header; the URL path is not
//! used for routing, except that a gRPC-style `/component/method` path fills
//! the header record.
//!
//! The lookup and policy check run before the response starts, so a missing
//! route is a 404 and a denied caller a 403. After that the response is `200`
//! and a routing failure can only be logged.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use mesh::tagged::{NameOrTag, TaggedRecord};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;

use crate::router::{Caller, Destination, RouteError, Router, StreamRequest};

/// Prefix of request headers copied into the record `env`.
const ENV_PREFIX: &str = "x-m-";

/// The destination named by the request: URI authority, else `Host`.
fn destination(req: &Request<Body>) -> Option<Destination> {
    if let Some(authority) = req.uri().authority() {
        return Destination::from_authority(authority.as_str());
    }
    let host = req.headers().get(axum::http::header::HOST)?.to_str().ok()?;
    Destination::from_authority(host)
}

/// The header record for a request: `/component/method` and `x-m-*` headers.
pub(crate) fn header_record(req: &Request<Body>) -> TaggedRecord {
    let mut record = TaggedRecord::default();
    let segments: Vec<&str> = req.uri().path().split('/').collect();
    // A leading empty segment from the first `/`, then exactly two names.
    if let ["", component, method] = segments.as_slice()
        && !component.is_empty()
        && !method.is_empty()
    {
        record.component = NameOrTag::parse(component);
        record.method = NameOrTag::parse(method);
    }
    for (name, value) in req.headers() {
        if let Some(rest) = name.as_str().strip_prefix(ENV_PREFIX)
            && !rest.is_empty()
            && let Ok(value) = value.to_str()
        {
            record.env.insert(
                NameOrTag::Name(rest.to_owned()),
                serde_json::Value::String(value.to_owned()),
            );
        }
    }
    record
}

/// Serve one HTTP request through the router.
pub async fn handle(router: Arc<Router>, caller: Caller, req: Request<Body>) -> Response {
    if req.method() != Method::POST && req.method() != Method::CONNECT {
        return (StatusCode::METHOD_NOT_ALLOWED, "use POST or CONNECT").into_response();
    }
    let Some(destination) = destination(&req) else {
        return (StatusCode::BAD_REQUEST, "missing or invalid authority").into_response();
    };
    let request = StreamRequest {
        destination,
        caller,
        header: header_record(&req),
    };
    if let Err(e) = router.check(&request) {
        return match e {
            RouteError::NoRoute => (StatusCode::NOT_FOUND, e.to_string()).into_response(),
            RouteError::Denied => (StatusCode::FORBIDDEN, e.to_string()).into_response(),
        };
    }

    // Same pattern as `handlers::handle_tcp_proxy`: the request body feeds a
    // channel, the response body drains another, and `ChannelStream` joins them.
    let (reader_tx, reader_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(100);
    let (writer_tx, writer_rx) = mpsc::channel::<Bytes>(100);
    tokio::spawn(crate::handlers::pipe_body_to_tx(req.into_body(), reader_tx));
    let stream = crate::utils::ChannelStream::new(reader_rx, writer_tx);
    tokio::spawn(async move {
        if let Err(e) = router.route_stream(request, Box::new(stream)).await {
            log::warn!("http ingress: route_stream failed: {e:#}");
        }
    });

    let response_stream =
        tokio_stream::wrappers::ReceiverStream::new(writer_rx).map(Ok::<_, std::io::Error>);
    (StatusCode::OK, Body::from_stream(response_stream)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::{
        ConventionLocator, Ingress, RouteEntry, RouteMatch, RoutePolicy, RouteSource, RouteTable,
        RouteTarget, StreamHandler,
    };
    use mesh::client::{MeshClient, MeshStream, MeshTarget};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct NoClient;

    #[async_trait::async_trait]
    impl MeshClient for NoClient {
        async fn open_stream(&self, _t: &MeshTarget) -> anyhow::Result<Box<dyn MeshStream>> {
            anyhow::bail!("unused")
        }
    }

    /// Echoes the body, and records the header it was given.
    struct Echo(std::sync::Mutex<Option<TaggedRecord>>);

    #[async_trait::async_trait]
    impl StreamHandler for Echo {
        async fn handle(
            &self,
            request: StreamRequest,
            mut stream: Box<dyn MeshStream>,
        ) -> anyhow::Result<()> {
            *self.0.lock().unwrap() = Some(request.header);
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await?;
            stream.write_all(&buf).await?;
            stream.shutdown().await?;
            Ok(())
        }
    }

    fn router(target: Option<RouteTarget>, policy: RoutePolicy) -> Arc<Router> {
        let table = Arc::new(RouteTable::new());
        if let Some(target) = target {
            table.set_static(vec![RouteEntry {
                matches: RouteMatch::Default,
                target,
                policy,
                source: RouteSource::Static { file: "t".into() },
            }]);
        }
        Arc::new(Router {
            table,
            client: Arc::new(NoClient),
            locator: Arc::new(ConventionLocator {
                services: crate::mesh_rest::MeshServiceRegistry::default(),
                local_names: vec![],
            }),
            activator: None,
        })
    }

    fn caller() -> Caller {
        Caller {
            identity: None,
            ingress: Ingress::Http,
            local: false,
        }
    }

    fn request(method: &str, uri: &str, host: Option<&str>) -> Request<Body> {
        let mut b = Request::builder().method(method).uri(uri);
        if let Some(h) = host {
            b = b.header("host", h);
        }
        b.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn get_is_405() {
        let r = router(None, RoutePolicy::default());
        let resp = handle(r, caller(), request("GET", "/", Some("a.m"))).await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn missing_authority_is_400() {
        let r = router(None, RoutePolicy::default());
        let resp = handle(r, caller(), request("POST", "/", None)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn no_route_is_404() {
        let r = router(None, RoutePolicy::default());
        let resp = handle(r, caller(), request("POST", "/", Some("a.m"))).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn denied_is_403() {
        let r = router(
            Some(RouteTarget::Handler(Arc::new(Echo(Default::default())))),
            RoutePolicy {
                local_only: true,
                allow: vec![],
            },
        );
        let resp = handle(r, caller(), request("POST", "/", Some("a.m"))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn header_record_maps_path_and_env() {
        let mut req = request("POST", "/comp/method", Some("a.m"));
        req.headers_mut().insert("x-m-k", "v".parse().unwrap());
        req.headers_mut().insert("x-other", "no".parse().unwrap());
        let rec = header_record(&req);
        assert_eq!(rec.component, NameOrTag::Name("comp".into()));
        assert_eq!(rec.method, NameOrTag::Name("method".into()));
        assert_eq!(
            rec.env.get(&NameOrTag::Name("k".into())),
            Some(&serde_json::json!("v"))
        );
        assert_eq!(rec.env.len(), 1);
        for p in ["/", "/a", "/a/b/c", "//b", "/a/"] {
            let rec = header_record(&request("POST", p, Some("a.m")));
            assert_eq!(rec.component, NameOrTag::default(), "{p}");
        }
    }

    #[tokio::test]
    async fn post_echoes_body_over_real_server() {
        let echo = Arc::new(Echo(Default::default()));
        let r = router(
            Some(RouteTarget::Handler(echo.clone())),
            RoutePolicy::default(),
        );
        let app = axum::Router::new().fallback(move |req: Request<Body>| {
            let r = r.clone();
            async move { handle(r, caller(), req).await }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/comp/method"))
            .header("x-m-who", "me")
            .body("hello body")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), "hello body");
        let header = echo.0.lock().unwrap().clone().unwrap();
        assert_eq!(header.component, NameOrTag::Name("comp".into()));
        assert_eq!(header.method, NameOrTag::Name("method".into()));
    }
}
