use anyhow::Error;
use axum::{
    routing::{delete, get, post},
    Router,
};
use log::info;
use opentelemetry::global;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use std::env;
use std::sync::Arc;
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};
use ws::WSServer;

fn init_telemetry() {
    let otlp_endpoint = env::var("OTEL_EXPORTER_OTLP_ENDPOINT");

    let tracer = if let Ok(endpoint) = otlp_endpoint {
        let exporter = opentelemetry_otlp::new_exporter()
            .http()
            .with_endpoint(endpoint);
        let tracer = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(exporter)
            .install_batch(opentelemetry_sdk::runtime::Tokio)
            .expect("failed to install OTLP tracer");
        Some(tracer)
    } else {
        None
    };

    let registry = Registry::default().with(EnvFilter::from_default_env());

    if let Some(tracer) = tracer {
        let tracing_layer = tracing_opentelemetry::layer().with_tracer(tracer);
        registry
            .with(tracing_layer)
            .with(tracing_subscriber::fmt::layer())
            .init();
    } else {
        registry.with(tracing_subscriber::fmt::layer()).init();
    };

    global::set_text_map_propagator(TraceContextPropagator::new());
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    init_telemetry();

    let http_port = env::var("HTTP_PORT")
        .map(|port| port.parse::<u16>().unwrap_or(8083))
        .unwrap_or(8083);

    info!("Starting HTTP and WebSocket server on port {}", http_port);

    let server = Arc::new(WSServer::new());

    let app = Router::new()
        .route("/", get(ws::static_file_handler))
        .route("/*path", get(ws::static_file_handler))
        .route("/ws", get(ws::handle_websocket_upgrade))
        .route("/api/clients", get(ws::handle_list_clients))
        .route("/api/clients/:id", delete(ws::handle_remove_client))
        .route(
            "/api/clients/:id/message",
            post(ws::handle_send_message),
        )
        .route("/api/broadcast", post(ws::handle_broadcast))
        .with_state(server)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::default().include_headers(true)),
        );

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], http_port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .await
        .map_err(|e| Error::new(e))?;

    Ok(())
}

