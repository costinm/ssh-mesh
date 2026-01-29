use anyhow::Result;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

#[tokio::test]
async fn test_mtls_server() -> Result<()> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let testdata_dir = manifest_dir.join("tests/testdata");

    // Server setup: Bob acts as server
    let server_cert = testdata_dir.join("bob/id_ecdsa.crt");
    let server_key = testdata_dir.join("bob/id_ecdsa");
    let ca_cert = testdata_dir.join("ca/id_ecdsa.crt");

    let server = ssh_mesh::auth::TlsServer::new(
        &server_cert,
        &server_key,
        Some(&ca_cert), // Enable mTLS
        "127.0.0.1:0",
    )?;

    let addr = server.addr.clone();
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    let actual_addr = listener.local_addr()?;

    // Spawn server
    let acceptor = server.acceptor.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls_stream = acceptor.accept(stream).await.unwrap();
                let mut buf = [0u8; 1024];
                let n = tls_stream.read(&mut buf).await.unwrap();
                let msg = String::from_utf8_lossy(&buf[..n]);
                let response = format!("Echo: {}", msg);
                tls_stream.write_all(response.as_bytes()).await.unwrap();
            });
        }
    });

    // Client setup: Alice acts as client
    let alice_cert = testdata_dir.join("alice/id_ecdsa.crt");
    let alice_key = testdata_dir.join("alice/id_ecdsa");

    let mut root_store = rustls::RootCertStore::empty();
    let ca_certs = load_certs(&ca_cert)?;
    for cert in ca_certs {
        root_store.add(cert)?;
    }

    let client_certs = load_certs(&alice_cert)?;
    let client_key = load_key(&alice_key)?;

    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)?;

    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let connector = TlsConnector::from(Arc::new(client_config));
    let stream = tokio::net::TcpStream::connect(actual_addr).await?;
    let domain = "bob.test.m".try_into()?;
    let mut tls_stream = connector.connect(domain, stream).await?;

    let msg = "Hello mTLS!";
    tls_stream.write_all(msg.as_bytes()).await?;

    let mut buf = [0u8; 1024];
    let n = tls_stream.read(&mut buf).await?;
    let response = String::from_utf8_lossy(&buf[..n]);

    assert!(response.contains("Hello mTLS!"));

    Ok(())
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
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
    Err(anyhow::anyhow!("No key found"))
}
