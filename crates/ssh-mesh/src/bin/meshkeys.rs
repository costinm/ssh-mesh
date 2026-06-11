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

    /// Comma-separated host certificate principals for signing.
    #[arg(long = "host-principals")]
    host_principals: Option<String>,

    /// Comma-separated user certificate principals for signing.
    #[arg(long = "user-principals")]
    user_principals: Option<String>,

    /// OpenSSH certificate valid-after time as Unix seconds. Defaults to now minus one day.
    #[arg(long = "valid-after")]
    valid_after: Option<u64>,

    /// OpenSSH certificate valid-before time as Unix seconds. Defaults to ten years from now.
    #[arg(long = "valid-before")]
    valid_before: Option<u64>,

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
            auth::sign_node_with_options(
                Path::new(&cli.cadir),
                Path::new(&cli.nodedir),
                &name,
                &cli.domain,
                cli.host_principals.as_deref().map(split_principals),
                cli.user_principals.as_deref().map(split_principals),
                cli.valid_after,
                cli.valid_before,
            )?;
        }
    }

    Ok(())
}

fn split_principals(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}
