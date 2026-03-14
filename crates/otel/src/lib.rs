use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::{propagation::TraceContextPropagator, trace::Sampler, Resource};
use perfetto_sdk::{
    producer::{Backends, Producer, ProducerInitArgsBuilder},
    protos::trace::track_event::{
        source_location::SourceLocationFieldNumber, track_event::TrackEventFieldNumber,
    },
    track_event::{
        EventContext, TrackEvent, TrackEventDebugArg, TrackEventFlow, TrackEventProtoField,
        TrackEventProtoFields,
    },
    track_event_categories,
};
use std::collections::HashMap;
use std::env;
use tracing::field::{Field, Visit};
use tracing::Subscriber;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;
use tracing_subscriber::{EnvFilter, Registry};

track_event_categories! {
    pub mod te_ns {
        ( "default", "Default category", [] ),
        ( "tracing", "Tracing spans", [] ),
    }
}

use te_ns as perfetto_te_ns;

// --- Field storage for spans ---

/// A single debug arg value that owns its data (for storage in span extensions).
#[derive(Clone, Debug)]
enum StoredArg {
    Bool(bool),
    I64(i64),
    U64(u64),
    F64(f64),
    Str(String),
}

/// Stored span fields, kept in the span's extensions.
#[derive(Clone, Debug, Default)]
struct PerfettoFields {
    fields: Vec<(String, StoredArg)>,
}

impl PerfettoFields {
    /// Emit all stored fields as debug args on the given EventContext.
    fn emit(&self, ctx: &mut EventContext) {
        for (name, val) in &self.fields {
            match val {
                StoredArg::Bool(v) => {
                    ctx.add_debug_arg(name, TrackEventDebugArg::Bool(*v));
                }
                StoredArg::I64(v) => {
                    ctx.add_debug_arg(name, TrackEventDebugArg::Int64(*v));
                }
                StoredArg::U64(v) => {
                    ctx.add_debug_arg(name, TrackEventDebugArg::Uint64(*v));
                }
                StoredArg::F64(v) => {
                    ctx.add_debug_arg(name, TrackEventDebugArg::Double(*v));
                }
                StoredArg::Str(v) => {
                    ctx.add_debug_arg(name, TrackEventDebugArg::String(v));
                }
            }
        }
    }
}

/// Visitor that collects tracing fields into a PerfettoFields.
struct FieldVisitor<'a> {
    fields: &'a mut PerfettoFields,
}

impl<'a> Visit for FieldVisitor<'a> {
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .fields
            .push((field.name().to_string(), StoredArg::Bool(value)));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .fields
            .push((field.name().to_string(), StoredArg::I64(value)));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .fields
            .push((field.name().to_string(), StoredArg::U64(value)));
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.fields
            .fields
            .push((field.name().to_string(), StoredArg::F64(value)));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields
            .fields
            .push((field.name().to_string(), StoredArg::Str(value.to_string())));
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields.fields.push((
            field.name().to_string(),
            StoredArg::Str(format!("{:?}", value)),
        ));
    }
}

/// Helper: emit source location proto fields from tracing metadata.
fn emit_source_location(ctx: &mut EventContext, meta: &tracing::Metadata<'_>) {
    if let (Some(file), Some(line)) = (meta.file(), meta.line()) {
        ctx.set_proto_fields(&TrackEventProtoFields {
            fields: &[TrackEventProtoField::Nested(
                TrackEventFieldNumber::SourceLocation as u32,
                &[
                    TrackEventProtoField::Cstr(SourceLocationFieldNumber::FileName as u32, file),
                    TrackEventProtoField::VarInt(
                        SourceLocationFieldNumber::LineNumber as u32,
                        line as u64,
                    ),
                ],
            )],
        });
    }
}

/// Helper: emit level and target as debug args.
fn emit_metadata(ctx: &mut EventContext, meta: &tracing::Metadata<'_>) {
    ctx.add_debug_arg("level", TrackEventDebugArg::String(meta.level().as_str()));
    ctx.add_debug_arg("target", TrackEventDebugArg::String(meta.target()));
    if let Some(module) = meta.module_path() {
        ctx.add_debug_arg("module", TrackEventDebugArg::String(module));
    }
}

// --- The Layer ---

pub struct PerfettoLayer;

impl<S> Layer<S> for PerfettoLayer
where
    S: Subscriber,
    S: for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    /// Capture span fields at creation time and store them in span extensions.
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if let Some(span) = ctx.span(id) {
            let mut pf = PerfettoFields::default();
            let mut visitor = FieldVisitor { fields: &mut pf };
            attrs.values().record(&mut visitor);
            span.extensions_mut().insert(pf);
        }
    }

    /// Append fields recorded after span creation.
    fn on_record(
        &self,
        id: &tracing::Id,
        values: &tracing::span::Record<'_>,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if let Some(span) = ctx.span(id) {
            let mut exts = span.extensions_mut();
            if let Some(pf) = exts.get_mut::<PerfettoFields>() {
                let mut visitor = FieldVisitor { fields: pf };
                values.record(&mut visitor);
            }
        }
    }

    /// Map on_follows_from to Perfetto flow events.
    fn on_follows_from(
        &self,
        _id: &tracing::Id,
        follows: &tracing::Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        // Emit an instant event marking the flow origin from the followed span.
        let flow_id = follows.into_u64();
        let flow = TrackEventFlow::process_scoped_flow(flow_id);
        perfetto_sdk::track_event_instant!("tracing", "follows_from", |ctx: &mut EventContext| {
            ctx.set_flow(&flow);
            ctx.add_debug_arg("follows_span_id", TrackEventDebugArg::Uint64(flow_id));
        });
    }

    /// Emit track_event_begin with span name, fields, source location, level, target.
    fn on_enter(&self, id: &tracing::Id, ctx: tracing_subscriber::layer::Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let name = span.name();
            let meta = span.metadata();

            // Clone fields so we can use them inside the macro closure.
            let fields = span
                .extensions()
                .get::<PerfettoFields>()
                .cloned()
                .unwrap_or_default();

            perfetto_sdk::track_event_begin!("tracing", "span", |pctx: &mut EventContext| {
                pctx.add_debug_arg("name", TrackEventDebugArg::String(name));
                // Structured fields
                fields.emit(pctx);
                // Level, target, module
                emit_metadata(pctx, meta);
                // Source location
                emit_source_location(pctx, meta);
            });
        }
    }

    fn on_exit(&self, _id: &tracing::Id, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        perfetto_sdk::track_event_end!("tracing");
    }

    /// Emit track_event_instant with all event fields, source location, level, target.
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let meta = event.metadata();
        let event_name = meta.name();

        // Collect event fields
        let mut pf = PerfettoFields::default();
        let mut visitor = FieldVisitor { fields: &mut pf };
        event.record(&mut visitor);

        perfetto_sdk::track_event_instant!("tracing", "event", |pctx: &mut EventContext| {
            pctx.add_debug_arg("name", TrackEventDebugArg::String(event_name));
            // Structured fields (including "message" if present)
            pf.emit(pctx);
            // Level, target, module
            emit_metadata(pctx, meta);
            // Source location
            emit_source_location(pctx, meta);
        });
    }
}

pub fn init_telemetry() {
    dotenvy::dotenv().ok();
    let otlp_endpoint = env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .or_else(|_| env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"));

    global::set_text_map_propagator(TraceContextPropagator::new());

    let (tracer, logger_provider): (
        Option<opentelemetry_sdk::trace::Tracer>,
        Option<opentelemetry_sdk::logs::LoggerProvider>,
    ) = if let Ok(endpoint) = otlp_endpoint {
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
            eprintln!(
                "OTLP: Using Authorization header: {}",
                if auth_val.len() > 20 {
                    &auth_val[..20]
                } else {
                    &auth_val
                }
            );
            headers.insert("Authorization".to_string(), auth_val);
            headers.insert("stream-name".to_string(), format!("otrs"));
        }

        let insecure = env::var("OTEL_EXPORTER_OTLP_INSECURE")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);

        let mut client_builder = reqwest::Client::builder();
        if insecure {
            client_builder = client_builder.danger_accept_invalid_certs(true);
            eprintln!("OTLP: Insecure mode enabled (danger_accept_invalid_certs)");
        }
        let client = client_builder
            .build()
            .expect("failed to create reqwest client");

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
    let logger_layer = logger_provider
        .map(|lp| opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(&lp));

    // Initialize Perfetto SDK
    let args = ProducerInitArgsBuilder::new().backends(Backends::SYSTEM | Backends::IN_PROCESS);
    Producer::init(args.build());
    TrackEvent::init();
    let _ = te_ns::register();

    Registry::default()
        .with(EnvFilter::from_default_env())
        .with(tracer_layer)
        .with(logger_layer)
        .with(PerfettoLayer)
        .with(tracing_subscriber::fmt::layer())
        .init();
}
pub mod perfetto_pull;
pub mod proto_extractor;
pub mod trace_server;
