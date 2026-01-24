use std::collections::HashMap;
use std::env;
use opentelemetry::global;
use opentelemetry_sdk::{propagation::TraceContextPropagator, trace::Sampler, Resource};
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use opentelemetry::trace::TracerProvider as _;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

pub fn init_telemetry() {
    let otlp_endpoint = env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .or_else(|_| env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"));

    global::set_text_map_propagator(TraceContextPropagator::new());

    let (tracer, logger_provider): (Option<opentelemetry_sdk::trace::Tracer>, Option<opentelemetry_sdk::logs::LoggerProvider>) = if let Ok(endpoint) = otlp_endpoint {
        let mut headers = HashMap::new();

        if let Ok(headers_str) = env::var("OTEL_EXPORTER_OTLP_HEADERS") {
            for s in headers_str.split(',') {
                let mut parts = s.splitn(2, '=');
                if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                    headers.insert(key.trim().to_string(), value.trim().to_string());
                }
            }
        }

        if let Ok(token) = env::var("OTEL_EXPORTER_OTLP_TOKEN") {
             let auth_val = if token.contains(':') {
                 // If it contains a colon, assume it's user:pass and base64 encode it
                 let encoded = STANDARD.encode(token);
                 format!("Basic {}", encoded)
             } else if token.starts_with("Basic ") || token.starts_with("Bearer ") {
                 // Already has prefix
                 token
             } else {
                 // Default to Basic as requested by user in prev turn
                 format!("Basic {}", token)
             };
             eprintln!("OTLP: Using Authorization header: {}", if auth_val.len() > 20 { &auth_val[..20] } else { &auth_val });
             headers.insert("Authorization".to_string(), auth_val);
             headers.insert("stream-name".to_string(), format!("default"));
        }

        let insecure = env::var("OTEL_EXPORTER_OTLP_INSECURE")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);

        let mut client_builder = reqwest::Client::builder();
        if insecure {
            client_builder = client_builder.danger_accept_invalid_certs(true);
            eprintln!("OTLP: Insecure mode enabled (danger_accept_invalid_certs)");
        }
        let client = client_builder.build().expect("failed to create reqwest client");

        eprintln!("OTLP: Connecting to: {}", endpoint);

        // Trace Provider
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(endpoint.clone())
            .with_headers(headers.clone())
            .with_http_client(client.clone())
            .build()
            .expect("failed to create OTLP trace exporter");

        let tracer_provider = opentelemetry_sdk::trace::TracerProvider::builder()
            .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
            .with_sampler(Sampler::AlwaysOn)
            .with_resource(Resource::default())
            .build();
            
        let tracer = tracer_provider.tracer("pmond");

        // Log Provider
        let log_exporter = opentelemetry_otlp::LogExporter::builder()
            .with_http()
            .with_endpoint(endpoint)
            .with_headers(headers)
            .with_http_client(client)
            .build()
            .expect("failed to create OTLP log exporter");

        let logger_provider = opentelemetry_sdk::logs::LoggerProvider::builder()
            .with_batch_exporter(log_exporter, opentelemetry_sdk::runtime::Tokio)
            .with_resource(Resource::default())
            .build();

        (Some(tracer), Some(logger_provider))
    } else {
        (None, None)
    };

    let tracer_layer = tracer.map(|t| tracing_opentelemetry::layer().with_tracer(t));
    let logger_layer = logger_provider.map(|lp| {
        opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&lp)
    });

    Registry::default()
        .with(EnvFilter::from_default_env())
        .with(tracer_layer)
        .with(logger_layer)
        .with(tracing_subscriber::fmt::layer())
        .init();
}
