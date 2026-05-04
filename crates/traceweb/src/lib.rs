use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::collections::HashMap;
use std::env;
use tracing::field::{Field, Visit};
use tracing::Subscriber;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;
use tracing_subscriber::{EnvFilter, Registry};


pub mod trace_server;
