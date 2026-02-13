use ssh_mesh::handlers::ApiDoc;
use std::fs;
use std::path::Path;
use utoipa::OpenApi;

use pmond::handlers::ApiDoc as PmondApiDoc;

fn main() {
    println!("Generating OpenAPI schema...");

    // Generate the OpenAPI schema from the ApiDoc struct
    let mut openapi = ApiDoc::openapi();

    println!("Including pmond schema...");
    let pmond_openapi = PmondApiDoc::openapi();
    openapi.merge(pmond_openapi);

    // Convert to pretty JSON
    let json = openapi
        .to_pretty_json()
        .expect("Failed to serialize OpenAPI schema");

    // Ensure web directory exists
    let web_dir = Path::new("web");
    if !web_dir.exists() {
        fs::create_dir_all(web_dir).expect("Failed to create web directory");
    }

    // Write to file
    let path = web_dir.join("openapi.json");
    fs::write(&path, json).expect("Failed to write openapi.json");

    println!("OpenAPI schema successfully written to {:?}", path);
}
