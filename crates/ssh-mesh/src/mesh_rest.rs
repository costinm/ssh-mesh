//! Generic REST adapter for tagged mesh records.
//!
//! This module deliberately depends only on the public `mesh` record/handler
//! APIs.  Services may be embedded (direct handler lookup) or live behind a
//! UDS; neither path knows about DMesh, local radio, or Android.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use mesh::{
    cbor::{decode_record, encode_record},
    tagged::{RecordKind, TaggedCatalog, TaggedRecord, record_from_json, to_json},
    wire::{TaggedRecordHandler, read_cbor_record, write_cbor_record},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::UnixStream;

use crate::AppState;

#[derive(Clone)]
pub enum MeshServiceBackend {
    Direct(Arc<dyn TaggedRecordHandler>),
    Uds(PathBuf),
}

#[derive(Clone)]
pub struct MeshService {
    pub backend: MeshServiceBackend,
    /// An optional generated `tools.json` value.  Raw numeric JSON and CBOR
    /// remain usable when this is absent.
    pub catalog: Option<Value>,
}

#[derive(Clone)]
pub struct MeshServiceRegistry {
    services: Arc<RwLock<HashMap<String, MeshService>>>,
    api_key: Arc<RwLock<Option<String>>>,
    next_request_id: Arc<AtomicU64>,
}

impl Default for MeshServiceRegistry {
    fn default() -> Self {
        let registry = Self {
            services: Arc::new(RwLock::new(HashMap::new())),
            api_key: Arc::new(RwLock::new(None)),
            next_request_id: Arc::new(AtomicU64::new(1)),
        };
        // This is an ssh-mesh HTTP setting, not a property of an individual
        // service such as lmesh.  Empty values deliberately disable the
        // bootstrap key for localhost development.
        registry.set_api_key(std::env::var("SSH_MESH_HTTP_API_KEY").ok());
        registry
    }
}

impl MeshServiceRegistry {
    pub fn register(&self, name: impl Into<String>, service: MeshService) {
        self.services
            .write()
            .expect("mesh service registry lock poisoned")
            .insert(name.into(), service);
    }

    /// Configure the optional localhost bootstrap key.  Strong identity and
    /// policy remain separate mesh features; this prevents accidental access
    /// through a local browser/forward during the initial admin phase.
    pub fn set_api_key(&self, key: Option<String>) {
        *self
            .api_key
            .write()
            .expect("mesh service registry lock poisoned") = key.filter(|key| !key.is_empty());
    }

    /// Returns whether a valid query parameter should be persisted as a
    /// cookie. Query parameters take precedence over a cookie so callers can
    /// rotate a local key without clearing browser state.
    fn authorize(&self, query_key: Option<&str>, headers: &HeaderMap) -> Result<bool> {
        let expected = self
            .api_key
            .read()
            .expect("mesh service registry lock poisoned")
            .clone();
        let cookie_key = headers
            .get(header::COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(api_key_from_cookie);
        let supplied = query_key.or(cookie_key.as_deref());
        if expected
            .as_deref()
            .is_none_or(|expected| supplied == Some(expected))
        {
            Ok(query_key.is_some() && expected.is_some())
        } else {
            bail!("missing or invalid api key")
        }
    }

    fn service(&self, name: &str) -> Result<MeshService> {
        self.services
            .read()
            .expect("mesh service registry lock poisoned")
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown mesh service {name:?}"))
    }

    fn assign_request_id(&self, record: &mut TaggedRecord) {
        if record.id.is_none() {
            // IDs are connection-local only for a framed stream. HTTP has one
            // request per dispatch, so the router assigns a bounded numeric
            // correlation ID when the caller did not provide one.
            let id = self.next_request_id.fetch_add(1, Ordering::Relaxed).max(1);
            record.id = Some(json!(id));
        }
    }

    fn describe(&self) -> Value {
        let mut services = self
            .services
            .read()
            .expect("mesh service registry lock poisoned")
            .iter()
            .map(|(name, service)| {
                json!({
                    "name": name,
                    "backend": match &service.backend {
                        MeshServiceBackend::Direct(_) => "direct",
                        MeshServiceBackend::Uds(_) => "uds",
                    },
                    "catalog": service.catalog.is_some(),
                })
            })
            .collect::<Vec<_>>();
        services.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
        json!({"services": services})
    }
}

fn api_key_from_cookie(header: &str) -> Option<String> {
    header.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        (name == "mesh_api_key").then(|| value.to_owned())
    })
}

fn persist_api_key(mut response: Response, query_key: Option<&str>, persist: bool) -> Response {
    if persist
        && let Some(key) = query_key
        // Keep the bootstrap cookie grammar deliberately narrow. A key that
        // cannot be represented safely remains usable in the query parameter.
        && key.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && let Ok(value) = format!("mesh_api_key={key}; Path=/; HttpOnly; SameSite=Strict").parse()
    {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

#[derive(Debug, Deserialize, Default)]
struct DeliveryQuery {
    mode: Option<String>,
    to: Option<String>,
    apikey: Option<String>,
}

fn is_oneway(query: &DeliveryQuery, record: &TaggedRecord) -> Result<bool> {
    match query.mode.as_deref() {
        None | Some("request") => Ok(false),
        Some("oneway") => {
            if record.id.is_some() {
                bail!("oneway mode requires a tagged record without id")
            }
            Ok(true)
        }
        Some(_) => bail!("mode must be request or oneway"),
    }
}

fn prepare_delivery(
    registry: &MeshServiceRegistry,
    query: &DeliveryQuery,
    record: &mut TaggedRecord,
) -> Result<bool> {
    let one_way = is_oneway(query, record)?;
    if !one_way {
        registry.assign_request_id(record);
    }
    Ok(one_way)
}

async fn dispatch(service: &MeshService, record: TaggedRecord) -> Result<Option<TaggedRecord>> {
    match &service.backend {
        MeshServiceBackend::Direct(handler) => {
            if record.to.is_some() {
                handler.forward_record(record).await
            } else {
                handler.handle_record(record).await
            }
        }
        MeshServiceBackend::Uds(path) => {
            let mut stream = UnixStream::connect(path)
                .await
                .with_context(|| format!("connect tagged-CBOR UDS {}", path.display()))?;
            let one_way = matches!(record.kind()?, RecordKind::Message);
            write_cbor_record(&mut stream, &record).await?;
            if one_way {
                Ok(None)
            } else {
                read_cbor_record(&mut stream)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("UDS closed before tagged-CBOR response"))
                    .map(Some)
            }
        }
    }
}

async fn post_record(
    State(state): State<AppState>,
    Path(service_name): Path<String>,
    Query(query): Query<DeliveryQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let persist = match state
        .mesh_services
        .authorize(query.apikey.as_deref(), &headers)
    {
        Ok(persist) => persist,
        Err(error) => return error_response(StatusCode::UNAUTHORIZED, error),
    };
    let cbor = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|value| value.trim() == "application/cbor")
        });
    let accepts_cbor = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|value| value.trim() == "application/cbor")
        });
    let result = async {
        let mut record = if cbor {
            decode_record(&body).context("decode application/cbor tagged record")?
        } else {
            let value: Value =
                serde_json::from_slice(&body).context("decode JSON tagged record")?;
            record_from_json(&value)?
        };
        let one_way = prepare_delivery(&state.mesh_services, &query, &mut record)?;
        let service = state.mesh_services.service(&service_name)?;
        let response = dispatch(&service, record.clone()).await?;
        if one_way {
            if response.is_some() {
                bail!("oneway handler unexpectedly returned a response")
            }
            return Ok::<_, anyhow::Error>((
                StatusCode::ACCEPTED,
                json!({
                    "accepted": true,
                    "completion": "local_submission",
                    "directed": record.to.is_some(),
                }),
                None,
            ));
        }
        let response =
            response.ok_or_else(|| anyhow::anyhow!("request did not receive a response"))?;
        if response.id != record.id {
            bail!("tagged-CBOR response id does not match request")
        }
        let status = if response.error.is_some() {
            StatusCode::BAD_GATEWAY
        } else {
            StatusCode::OK
        };
        Ok((status, to_json(&response, None), Some(response)))
    }
    .await;
    let response = match result {
        Ok((status, _json, Some(record))) if accepts_cbor => match encode_record(&record) {
            Ok(bytes) => {
                (status, [(header::CONTENT_TYPE, "application/cbor")], bytes).into_response()
            }
            Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
        },
        Ok((status, value, _)) => (status, Json(value)).into_response(),
        Err(error) => error_response(StatusCode::BAD_REQUEST, error),
    };
    persist_api_key(response, query.apikey.as_deref(), persist)
}

/// Catalog-assisted convenience endpoint.  Raw numeric JSON and CBOR continue
/// to use `records`; this route never makes a catalog a relay requirement.
async fn post_call(
    State(state): State<AppState>,
    Path((service_name, method)): Path<(String, String)>,
    Query(query): Query<DeliveryQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let persist = match state
        .mesh_services
        .authorize(query.apikey.as_deref(), &headers)
    {
        Ok(persist) => persist,
        Err(error) => return error_response(StatusCode::UNAUTHORIZED, error),
    };
    let result = async {
        let service = state.mesh_services.service(&service_name)?;
        let catalog = service
            .catalog
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("service has no catalog; use records"))?;
        let arguments: Value =
            serde_json::from_slice(&body).context("decode JSON call arguments")?;
        let catalog = TaggedCatalog::from_tools_json(catalog)?;
        if catalog.method(&method).is_none() {
            bail!("method is not present in the service catalog; use records for raw calls")
        }
        let mut record = catalog.record_from_value(&method, &arguments)?;
        if let Some(to) = &query.to {
            if record.to.as_ref().is_some_and(|value| value != to) {
                bail!("query to conflicts with body to")
            }
            record.to = Some(Value::String(to.clone()));
        }
        let one_way = prepare_delivery(&state.mesh_services, &query, &mut record)?;
        let response = dispatch(&service, record.clone()).await?;
        if one_way {
            if response.is_some() {
                bail!("oneway handler unexpectedly returned a response")
            }
            return Ok::<_, anyhow::Error>((
                StatusCode::ACCEPTED,
                json!({
                    "accepted": true,
                    "completion": "local_submission",
                    "directed": record.to.is_some(),
                }),
            ));
        }
        let response =
            response.ok_or_else(|| anyhow::anyhow!("request did not receive a response"))?;
        if response.id != record.id {
            bail!("tagged-CBOR response id does not match request")
        }
        let status = if response.error.is_some() {
            StatusCode::BAD_GATEWAY
        } else {
            StatusCode::OK
        };
        Ok((status, to_json(&response, Some(&catalog))))
    }
    .await;
    let response = match result {
        Ok((status, value)) => (status, Json(value)).into_response(),
        Err(error) => error_response(StatusCode::BAD_REQUEST, error),
    };
    persist_api_key(response, query.apikey.as_deref(), persist)
}

async fn list_services(
    State(state): State<AppState>,
    Query(query): Query<DeliveryQuery>,
    headers: HeaderMap,
) -> Response {
    match state
        .mesh_services
        .authorize(query.apikey.as_deref(), &headers)
    {
        Ok(persist) => persist_api_key(
            Json(state.mesh_services.describe()).into_response(),
            query.apikey.as_deref(),
            persist,
        ),
        Err(error) => error_response(StatusCode::UNAUTHORIZED, error),
    }
}

async fn get_tools(
    State(state): State<AppState>,
    Path(service_name): Path<String>,
    Query(query): Query<DeliveryQuery>,
    headers: HeaderMap,
) -> Response {
    let persist = match state
        .mesh_services
        .authorize(query.apikey.as_deref(), &headers)
    {
        Ok(persist) => persist,
        Err(error) => return error_response(StatusCode::UNAUTHORIZED, error),
    };
    match state.mesh_services.service(&service_name) {
        Ok(service) => match service.catalog {
            Some(catalog) => persist_api_key(
                Json(catalog).into_response(),
                query.apikey.as_deref(),
                persist,
            ),
            None => persist_api_key(
                StatusCode::NO_CONTENT.into_response(),
                query.apikey.as_deref(),
                persist,
            ),
        },
        Err(error) => error_response(StatusCode::NOT_FOUND, error),
    }
}

fn error_response(status: StatusCode, error: anyhow::Error) -> Response {
    (status, Json(json!({"error": error.to_string()}))).into_response()
}

/// Generic REST routes.  Callers register service backends on `AppState`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/services", get(list_services))
        .route("/services/:service/tools", get(get_tools))
        .route("/services/:service/records", post(post_record))
        .route("/services/:service/call/:method", post(post_call))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use mesh::{
        tagged::NameOrTag,
        wire::{response_ok, serve_cbor_session},
    };

    struct Echo;

    #[async_trait]
    impl TaggedRecordHandler for Echo {
        async fn handle_record(&self, record: TaggedRecord) -> Result<Option<TaggedRecord>> {
            Ok(record.id.map(|id| response_ok(id, json!({"local": true}))))
        }
    }

    #[tokio::test]
    async fn direct_backend_dispatches_request_without_a_stream() {
        let service = MeshService {
            backend: MeshServiceBackend::Direct(Arc::new(Echo)),
            catalog: None,
        };
        let record = TaggedRecord {
            component: NameOrTag::Tag(1),
            method: NameOrTag::Tag(2),
            id: Some(json!(7)),
            ..Default::default()
        };
        let response = dispatch(&service, record).await.unwrap().unwrap();
        assert_eq!(response.result, Some(json!({"local": true})));
    }

    #[tokio::test]
    async fn uds_backend_has_the_same_tagged_completion_semantics() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("mesh.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            serve_cbor_session(&mut stream, &Echo).await.unwrap();
        });
        let service = MeshService {
            backend: MeshServiceBackend::Uds(socket),
            catalog: None,
        };
        let response = dispatch(
            &service,
            TaggedRecord {
                component: NameOrTag::Tag(1),
                method: NameOrTag::Tag(2),
                id: Some(json!(7)),
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.id, Some(json!(7)));
        assert_eq!(response.result, Some(json!({"local": true})));
        server.await.unwrap();
    }

    #[test]
    fn missing_http_id_is_assigned_unless_oneway_is_explicit() {
        let mut record = TaggedRecord {
            component: NameOrTag::Tag(1),
            method: NameOrTag::Tag(2),
            ..Default::default()
        };
        let registry = MeshServiceRegistry::default();
        assert!(!prepare_delivery(&registry, &DeliveryQuery::default(), &mut record).unwrap());
        assert_eq!(record.id, Some(json!(1)));

        let mut one_way = TaggedRecord {
            component: NameOrTag::Tag(1),
            method: NameOrTag::Tag(2),
            ..Default::default()
        };
        assert!(
            prepare_delivery(
                &registry,
                &DeliveryQuery {
                    mode: Some("oneway".to_owned()),
                    to: None,
                    apikey: None
                },
                &mut one_way,
            )
            .unwrap()
        );
        assert!(one_way.id.is_none());
    }

    #[test]
    fn optional_api_key_only_restricts_when_configured() {
        let registry = MeshServiceRegistry::default();
        let headers = HeaderMap::new();
        assert!(registry.authorize(None, &headers).is_ok());
        registry.set_api_key(Some("test-key".to_owned()));
        assert!(registry.authorize(None, &headers).is_err());
        assert!(registry.authorize(Some("wrong"), &headers).is_err());
        assert!(registry.authorize(Some("test-key"), &headers).unwrap());
        let mut cookie_headers = HeaderMap::new();
        cookie_headers.insert(header::COOKIE, "mesh_api_key=test-key".parse().unwrap());
        assert!(!registry.authorize(None, &cookie_headers).unwrap());
    }
}
