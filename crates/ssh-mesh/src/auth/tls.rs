// TLS server runtime

use anyhow::Result;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use log::{info, warn};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::debug;
use x509_parser::prelude::*;

pub struct TlsServer {
    pub acceptor: TlsAcceptor,
    pub addr: String,
}

impl TlsServer {
    pub fn new(
        server_cert_path: &Path,
        server_key_path: &Path,
        ca_cert_path: Option<&Path>,
        listen_addr: &str,
    ) -> Result<Self> {
        let certs = load_certs(server_cert_path)?;
        let key = load_key(server_key_path)?;

        let mut config = if let Some(ca_path) = ca_cert_path {
            let ca_certs = load_certs(ca_path)?;
            let mut root_cert_store = rustls::RootCertStore::empty();
            for cert in ca_certs {
                root_cert_store.add(cert)?;
            }

            let verifier = WebPkiClientVerifier::builder(Arc::new(root_cert_store)).build()?;

            rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)?
        } else {
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)?
        };

        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            addr: listen_addr.to_string(),
        })
    }

    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(&self.addr).await?;
        info!("TLS server listening on {}", self.addr);

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let acceptor = self.acceptor.clone();

            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        debug!("Accepted TLS connection from {}", peer_addr);
                        if let Err(e) = handle_tls_connection(tls_stream).await {
                            warn!("Error handling TLS connection from {}: {}", peer_addr, e);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to accept TLS connection from {}: {}", peer_addr, e);
                    }
                }
            });
        }
    }
}

async fn handle_tls_connection(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Result<()> {
    let (_inner, connection) = stream.get_mut();

    let client_identity = if let Some(certs) = connection.peer_certificates() {
        if !certs.is_empty() {
            let cert_der = &certs[0];
            match X509Certificate::from_der(cert_der) {
                Ok((_, cert)) => cert.subject().to_string(),
                Err(_) => "unknown-cert".to_string(),
            }
        } else {
            "no-cert".to_string()
        }
    } else {
        "anonymous".to_string()
    };

    info!("Handling connection from client: {}", client_identity);

    let mut buf = [0u8; 1024];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        let msg = String::from_utf8_lossy(&buf[..n]);
        debug!("Received: {}", msg);

        let response = format!("Echo: {} (Identity: {})\n", msg, client_identity);
        stream.write_all(response.as_bytes()).await?;
    }

    Ok(())
}

pub async fn run_axum_https_server(
    port: u16,
    acceptor: TlsAcceptor,
    app: axum::Router,
) -> Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    info!("HTTPS server listening on {}", addr);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("TLS handshake failed from {}: {}", peer_addr, e);
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);

            if let Err(err) = auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, hyper_util::service::TowerToHyperService::new(app))
                .await
            {
                warn!("Error serving HTTPS connection from {}: {}", peer_addr, err);
            }
        });
    }
}

pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

pub fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);

    loop {
        match rustls_pemfile::read_one(&mut reader)? {
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(PrivateKeyDer::Sec1(key)),
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(PrivateKeyDer::Pkcs1(key)),
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(PrivateKeyDer::Pkcs8(key)),
            None => break,
            _ => continue,
        }
    }

    Err(anyhow::anyhow!("No private key found in {:?}", path))
}
