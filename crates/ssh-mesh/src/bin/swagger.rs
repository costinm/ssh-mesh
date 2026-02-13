use axum::Router;
use clap::Parser;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use utoipa::openapi::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the OpenAPI JSON file
    #[arg(short, long, default_value = "web/openapi.json")]
    file: PathBuf,

    /// Port to serve on
    #[arg(short, long, default_value = "3000")]
    port: u16,

    /// Base URL path for Swagger UI
    #[arg(short, long, default_value = "/swagger-ui")]
    base_url: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    println!("Reading OpenAPI schema from {:?}", args.file);
    // Read the OpenAPI JSON file
    let json_content = match fs::read_to_string(&args.file) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("Failed to read file {:?}: {}", args.file, e);
            std::process::exit(1);
        }
    };

    // Deserialize into utoipa::openapi::OpenApi struct
    // We need to use serde_json to deserialize it into the OpenApi struct
    let openapi: OpenApi = match serde_json::from_str(&json_content) {
        Ok(api) => api,
        Err(e) => {
            eprintln!("Failed to parse OpenAPI JSON: {}", e);
            std::process::exit(1);
        }
    };

    let app = Router::new()
        .merge(SwaggerUi::new(args.base_url.clone()).url("/api-doc/openapi.json", openapi));

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    println!("Swagger UI available at http://{}{}", addr, args.base_url);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
