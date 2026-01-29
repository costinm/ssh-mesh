use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ssh_mesh::auth;
use std::path::Path;

#[derive(Parser)]
#[command(name = "meshkeys")]
#[command(about = "SSH Mesh Key Management Utility", long_about = None)]
struct Cli {
    /// Directory for CA keys and certificates
    #[arg(short = 'c', long = "cadir", default_value = "./ca")]
    cadir: String,

    /// Domain name for certificates
    #[arg(short = 'd', long = "domain", default_value = "test.m")]
    domain: String,

    /// Directory for node keys and certificates
    #[arg(short = 'n', long = "nodedir", default_value = "./")]
    nodedir: String,

    /// Name of the node
    #[arg(short = 'm', long = "name")]
    name: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate CA components
    Genca,
    /// Generate node keys and self-signed certificate
    Gen,
    /// Sign node certificate and SSH certificates using CA
    Sign,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Genca => {
            auth::generate_ca(Path::new(&cli.cadir), &cli.domain)?;
        }
        Commands::Gen => {
            auth::generate_node(
                Path::new(&cli.nodedir),
                cli.name.as_deref().unwrap_or("node"),
                &cli.domain,
            )?;
        }
        Commands::Sign => {
            let name = cli
                .name
                .context("Node name (--name) is required for signing")?;
            auth::sign_node(
                Path::new(&cli.cadir),
                Path::new(&cli.nodedir),
                &name,
                &cli.domain,
            )?;
        }
    }

    Ok(())
}
