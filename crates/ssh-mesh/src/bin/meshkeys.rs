use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ssh_mesh::auth;
use std::path::{Path, PathBuf};

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
    /// Print the HTTP API key (`ID:SECRET`) for an ID, derived from the master
    /// secret. Nothing is stored: ssh-mesh recomputes it to check a request. Use
    /// it as `Authorization: Bearer ID:SECRET`, as a Basic user and password,
    /// or at the login page.
    Apikey {
        /// Who the key is for: 1-64 characters from [A-Za-z0-9._@-]
        id: String,
        /// Directory holding the master secret `mesh_secret`, next to the host key
        /// (default: $SSH_BASEDIR, else ./)
        #[arg(long)]
        keydir: Option<PathBuf>,
    },
    /// ACME (Let's Encrypt) certificates: renew or add domains
    Acme {
        #[command(subcommand)]
        command: AcmeCommands,
    },
}

#[derive(Subcommand)]
enum AcmeCommands {
    /// Renew certificates listed in the config (no-op without a config)
    Renew {
        #[command(flatten)]
        common: AcmeCommon,
        /// Renew regardless of expiry
        #[arg(long)]
        force: bool,
        /// Print what would be renewed and exit
        #[arg(long)]
        dry_run: bool,
    },
    /// Add domains to the config and issue their certificates now
    Add {
        /// Domain names (no wildcards)
        #[arg(required = true, value_name = "DOMAIN")]
        domains: Vec<String>,
        #[command(flatten)]
        common: AcmeCommon,
    },
}

#[derive(clap::Args)]
struct AcmeCommon {
    /// Home directory (default: $HOME)
    #[arg(long)]
    home: Option<PathBuf>,
    /// Config file (default: <home>/etc/mesh-acme.toml)
    #[arg(long)]
    config: Option<PathBuf>,
    /// Use the Let's Encrypt staging directory
    #[arg(long)]
    staging: bool,
}

impl AcmeCommon {
    fn options(self, force: bool, dry_run: bool) -> Result<mesh_acme::Options> {
        let home = self
            .home
            .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
            .context("no --home and $HOME is not set")?;
        Ok(mesh_acme::Options {
            config: self
                .config
                .unwrap_or_else(|| mesh_acme::default_config_path(&home)),
            home,
            staging: self.staging,
            force,
            dry_run,
        })
    }
}

/// Run an acme subcommand; returns the process exit code.
fn run_acme(command: AcmeCommands) -> std::process::ExitCode {
    use std::process::ExitCode;
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let res = (|| -> Result<usize> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        match command {
            AcmeCommands::Renew {
                common,
                force,
                dry_run,
            } => {
                let opts = common.options(force, dry_run)?;
                rt.block_on(mesh_acme::run(&opts))
            }
            AcmeCommands::Add { domains, common } => {
                let opts = common.options(false, false)?;
                rt.block_on(mesh_acme::add_domains(&opts, &domains))
            }
        }
    })();
    match res {
        Ok(0) => ExitCode::SUCCESS,
        Ok(n) => {
            log::error!("{n} domain(s) failed");
            ExitCode::FAILURE
        }
        Err(e) => {
            log::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> Result<std::process::ExitCode> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Acme { command } => return Ok(run_acme(command)),
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
        Commands::Apikey { id, keydir } => {
            let dir = keydir
                .or_else(|| std::env::var_os("SSH_BASEDIR").map(PathBuf::from))
                .unwrap_or_else(|| PathBuf::from("."));
            // Reads only: a secret created here would belong to the wrong user,
            // and the server must be the one that generates it.
            let master = auth::MasterSecret::load(&dir)?;
            let secrets = ssh_mesh::httpauth::Secrets::from_master(&master);
            println!("{}", secrets.api_key(&id)?);
        }
    }

    Ok(std::process::ExitCode::SUCCESS)
}

fn split_principals(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}
