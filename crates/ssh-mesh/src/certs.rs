//! Certificates this host terminates, and the ACME HTTP-01 challenges that
//! obtain them.
//!
//! Certificates are obtained and renewed by a separate tool, run from cron
//! as its own user, which keeps everything under that user's home
//! ([`DEFAULT_ACME_HOME`]). ssh-mesh only reads it:
//!
//! - `<acme_home>/www/.well-known/acme-challenge/<token>` is served at
//!   `/.well-known/acme-challenge/<token>` on the plain HTTP listener, so no
//!   other process needs port 80;
//! - every certificate in `cert_dir` names domains this host terminates: TLS
//!   and routing end here. The default, `<acme_home>/.local/share/caddy/
//!   certificates`, is Caddy's layout (`<issuer>/<name>/<name>.crt` and
//!   `.key`), so an existing Caddy data directory can be copied in;
//!   `fullchain` with a sibling `privkey` is also read.
//! - [`tls_acceptor`] serves those certificates on 443, chosen by SNI.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Default home of the ACME tool's user (`meshkeys acme`).
pub const DEFAULT_ACME_HOME: &str = "/home/acme";

/// The ACME home, `<acme_home>/www` (the web root) and the certificate
/// directory, from the optional config values.
pub fn acme_paths(
    acme_home: Option<&Path>,
    cert_dir: Option<&Path>,
) -> (PathBuf, PathBuf, PathBuf) {
    let home = acme_home
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_ACME_HOME));
    let certs = cert_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| home.join(".local/share/caddy/certificates"));
    let www = home.join("www");
    (home, www, certs)
}

/// Files read as certificates: `*.crt`, `*.pem`, `*.cer` and `fullchain`.
fn is_cert_file(path: &Path) -> bool {
    match path.file_name().and_then(|n| n.to_str()) {
        Some("fullchain") => true,
        Some(name) => [".crt", ".pem", ".cer"]
            .iter()
            .any(|ext| name.ends_with(ext)),
        None => false,
    }
}

/// DNS names in the subject alternative names of the first certificate in
/// a PEM file. Keys, chains without a leaf and unparsable files give none.
fn pem_dns_names(bytes: &[u8]) -> Vec<String> {
    let Ok((_, pem)) = x509_parser::pem::parse_x509_pem(bytes) else {
        return Vec::new();
    };
    if pem.label != "CERTIFICATE" {
        return Vec::new();
    }
    let Ok(cert) = pem.parse_x509() else {
        return Vec::new();
    };
    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return Vec::new();
    };
    san.value
        .general_names
        .iter()
        .filter_map(|name| match name {
            x509_parser::extensions::GeneralName::DNSName(dns) => Some(dns.to_ascii_lowercase()),
            _ => None,
        })
        .collect()
}

/// Domain names of every certificate under `dir`, searched up to three
/// levels deep so any tool's layout works (`live/<name>/fullchain`,
/// `<issuer>/<name>/<name>.crt`, flat files). Missing directories give none.
pub fn cert_dir_names(dir: &Path) -> Vec<String> {
    fn walk(dir: &Path, depth: u8, names: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if depth > 0 {
                    walk(&path, depth - 1, names);
                }
            } else if is_cert_file(&path)
                && let Ok(bytes) = std::fs::read(&path)
            {
                names.extend(pem_dns_names(&bytes));
            }
        }
    }
    let mut names = Vec::new();
    walk(dir, 3, &mut names);
    names.sort();
    names.dedup();
    names
}

/// Whether `host` is one of `names`: an exact name, or `*.x` covering one
/// label under `x`, as a TLS wildcard certificate does.
pub fn is_local_name(names: &[String], host: &str) -> bool {
    names.iter().any(|n| match n.strip_prefix("*.") {
        Some(suffix) => host
            .len()
            .checked_sub(suffix.len() + 1)
            .filter(|&cut| cut > 0)
            .is_some_and(|cut| {
                host.as_bytes()[cut] == b'.'
                    && host[cut + 1..].eq_ignore_ascii_case(suffix)
                    && !host[..cut].contains('.')
            }),
        None => n.eq_ignore_ascii_case(host),
    })
}

/// The private key file paired with a certificate file: `<stem>.key` next to
/// `<stem>.crt` (Caddy), or `privkey` next to `fullchain`.
fn key_file_for(cert: &Path) -> Option<PathBuf> {
    let name = cert.file_name()?.to_str()?;
    let key = match name {
        "fullchain" => cert.with_file_name("privkey"),
        _ => cert.with_extension("key"),
    };
    key.is_file().then_some(key)
}

/// One certificate with its key, ready for rustls.
fn load_certified_key(cert: &Path, key: &Path) -> anyhow::Result<rustls::sign::CertifiedKey> {
    let chain = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(cert)?))
        .collect::<Result<Vec<_>, _>>()?;
    anyhow::ensure!(!chain.is_empty(), "no certificate in {}", cert.display());
    let der = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(key)?))?
        .ok_or_else(|| anyhow::anyhow!("no private key in {}", key.display()))?;
    let signing = rustls::crypto::ring::sign::any_supported_type(&der)?;
    let certified = rustls::sign::CertifiedKey::new(chain, signing);
    certified.keys_match()?;
    Ok(certified)
}

/// Picks a certificate by SNI: exact name first, then a `*.x` wildcard for
/// one label under `x`.
#[derive(Debug, Default)]
pub struct SniResolver {
    files: Vec<PathBuf>,
    exact: HashMap<String, Arc<rustls::sign::CertifiedKey>>,
    wildcard: HashMap<String, Arc<rustls::sign::CertifiedKey>>,
}

impl SniResolver {
    /// Every certificate with a key under `dir` (searched like
    /// [`cert_dir_names`]). Unreadable pairs are logged and skipped.
    pub fn load(dir: &Path) -> Self {
        fn walk(dir: &Path, depth: u8, out: &mut SniResolver) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if depth > 0 {
                        walk(&path, depth - 1, out);
                    }
                    continue;
                }
                if !is_cert_file(&path) {
                    continue;
                }
                let Some(key) = key_file_for(&path) else {
                    continue;
                };
                if let Err(e) = out.add_file(&path, &key) {
                    log::warn!("skipping certificate {}: {e:#}", path.display());
                }
            }
        }
        let mut out = Self::default();
        walk(dir, 3, &mut out);
        out
    }

    fn add_file(&mut self, cert: &Path, key: &Path) -> anyhow::Result<()> {
        let names = pem_dns_names(&std::fs::read(cert)?);
        anyhow::ensure!(!names.is_empty(), "no DNS names in {}", cert.display());
        let ck = Arc::new(load_certified_key(cert, key)?);
        for name in names {
            match name.strip_prefix("*.") {
                Some(rest) => self.wildcard.insert(rest.to_owned(), ck.clone()),
                None => self.exact.insert(name, ck.clone()),
            };
        }
        self.files.push(cert.to_owned());
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard.is_empty()
    }

    /// The certificate for a server name.
    pub fn cert_for(&self, name: &str) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let name = name.to_ascii_lowercase();
        if let Some(ck) = self.exact.get(&name) {
            return Some(ck.clone());
        }
        let (_, rest) = name.split_once('.')?;
        self.wildcard.get(rest).cloned()
    }
}

impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.cert_for(client_hello.server_name()?)
    }
}

/// A TLS acceptor serving the certificates in `cert_dir` by SNI, with h2 and
/// http/1.1. `None` when the directory has no usable certificate.
pub fn tls_acceptor(cert_dir: &Path) -> Option<tokio_rustls::TlsAcceptor> {
    let resolver = SniResolver::load(cert_dir);
    if resolver.is_empty() {
        return None;
    }
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Some(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// The active certificate set shared by the TLS listener and local admin API.
/// Directories are discovered only at startup. Reload reads known or explicitly
/// supplied certificate paths, validates every pair, and replaces the set atomically.
#[derive(Debug)]
pub struct ReloadableCertificates {
    active: RwLock<SniResolver>,
}

impl ReloadableCertificates {
    /// Discover the initial certificate files under `dir`.
    pub fn load(dir: &Path) -> Self {
        Self {
            active: RwLock::new(SniResolver::load(dir)),
        }
    }

    /// Whether there are any active certificates.
    pub fn is_empty(&self) -> bool {
        self.active.read().unwrap().is_empty()
    }

    /// Reload known files, or replace them with `certificates` when supplied.
    /// No directories are scanned. An empty set or any invalid pair returns an
    /// error and leaves the active set untouched. Returns the loaded file count.
    pub fn reload(&self, certificates: Option<Vec<PathBuf>>) -> anyhow::Result<usize> {
        let mut active = self.active.write().unwrap();
        let files = certificates.unwrap_or_else(|| active.files.clone());
        anyhow::ensure!(
            !files.is_empty(),
            "no certificate paths; supply certificates explicitly"
        );
        let mut next = SniResolver::default();
        for cert in &files {
            let key = key_file_for(cert)
                .ok_or_else(|| anyhow::anyhow!("no private key for {}", cert.display()))?;
            next.add_file(cert, &key)?;
        }
        let count = next.files.len();
        *active = next;
        Ok(count)
    }

    /// Create a TLS acceptor sharing this set. If supplied, the legacy TLS
    /// configuration supplies a fallback certificate until the first successful
    /// reload. Its client verification policy stays in force across reloads.
    /// Existing connections stay open.
    pub fn acceptor(
        self: &Arc<Self>,
        fallback: Option<tokio_rustls::TlsAcceptor>,
    ) -> tokio_rustls::TlsAcceptor {
        let (mut config, fallback) = match fallback {
            Some(acceptor) => {
                let config = acceptor.config().as_ref().clone();
                let resolver = Some(config.cert_resolver.clone());
                (config, resolver)
            }
            None => (
                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_cert_resolver(self.clone()),
                None,
            ),
        };
        config.cert_resolver = Arc::new(ReloadingResolver {
            certificates: self.clone(),
            fallback,
        });
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
    }
}

impl rustls::server::ResolvesServerCert for ReloadableCertificates {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.active.read().unwrap().cert_for(hello.server_name()?)
    }
}

#[derive(Debug)]
struct ReloadingResolver {
    certificates: Arc<ReloadableCertificates>,
    fallback: Option<Arc<dyn rustls::server::ResolvesServerCert>>,
}

impl rustls::server::ResolvesServerCert for ReloadingResolver {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let active = self.certificates.active.read().unwrap();
        if active.is_empty() {
            return self.fallback.as_ref()?.resolve(hello);
        }
        active.cert_for(hello.server_name()?)
    }
}

/// An ACME token: base64url characters only, so it can never name a path
/// outside the challenge directory.
fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 256
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Serve `GET /.well-known/acme-challenge/<token>` from
/// `<www>/.well-known/acme-challenge/<token>`.
pub fn acme_challenge_routes(www: PathBuf) -> axum::Router {
    let chall_dir = www.join(".well-known/acme-challenge");
    axum::Router::new()
        .route(
            "/.well-known/acme-challenge/:token",
            axum::routing::get(acme_challenge),
        )
        .with_state(chall_dir)
}

async fn acme_challenge(
    State(chall_dir): State<PathBuf>,
    AxumPath(token): AxumPath<String>,
) -> Response {
    if !valid_token(&token) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match tokio::fs::read(chall_dir.join(&token)).await {
        Ok(body) => (
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            body,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("certs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cert_pem(names: &[&str]) -> String {
        let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        rcgen::generate_simple_self_signed(names)
            .unwrap()
            .cert
            .pem()
    }

    #[test]
    fn names_from_certificates_in_any_layout() {
        let root = temp_dir("names");
        // acme-redirect style: live/<name>/fullchain.
        std::fs::create_dir_all(root.join("live/node1")).unwrap();
        std::fs::write(
            root.join("live/node1/fullchain"),
            cert_pem(&["Node1.example.m", "api.example.m"]),
        )
        .unwrap();
        // <issuer>/<name>/<name>.crt, with a wildcard.
        let issuer = root.join("acme-v02/apps");
        std::fs::create_dir_all(&issuer).unwrap();
        std::fs::write(issuer.join("apps.crt"), cert_pem(&["*.apps.example.m"])).unwrap();
        // Keys and unrelated files are ignored.
        std::fs::write(root.join("live/node1/privkey"), "not a cert").unwrap();
        std::fs::write(root.join("bad.pem"), "garbage").unwrap();

        assert_eq!(
            cert_dir_names(&root),
            vec!["*.apps.example.m", "api.example.m", "node1.example.m"]
        );
        let names = cert_dir_names(&root);
        assert!(is_local_name(&names, "NODE1.example.m"));
        assert!(is_local_name(&names, "a.apps.example.m"));
        assert!(!is_local_name(&names, "apps.example.m"));
        assert!(!is_local_name(&names, "a.b.apps.example.m"));
        assert!(cert_dir_names(&root.join("missing")).is_empty());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn acme_paths_defaults() {
        let (home, www, certs) = acme_paths(None, None);
        assert_eq!(home, PathBuf::from("/home/acme"));
        assert_eq!(www, PathBuf::from("/home/acme/www"));
        assert_eq!(
            certs,
            PathBuf::from("/home/acme/.local/share/caddy/certificates")
        );
        let (_, _, certs) = acme_paths(Some(Path::new("/srv/a")), Some(Path::new("/c")));
        assert_eq!(certs, PathBuf::from("/c"));
    }

    #[test]
    fn sni_resolver_reads_caddy_layout() {
        let root = temp_dir("sni");
        let issuer = root.join("acme-v02.api.letsencrypt.org-directory");
        for (dir, names) in [
            ("dev1.example.m", vec!["dev1.example.m".to_string()]),
            (
                "wildcard_.apps.example.m",
                vec!["*.apps.example.m".to_string()],
            ),
        ] {
            let d = issuer.join(dir);
            std::fs::create_dir_all(&d).unwrap();
            let ck = rcgen::generate_simple_self_signed(names).unwrap();
            std::fs::write(d.join(format!("{dir}.crt")), ck.cert.pem()).unwrap();
            std::fs::write(d.join(format!("{dir}.key")), ck.signing_key.serialize_pem()).unwrap();
        }
        // A certificate without its key is not served.
        let lone = issuer.join("nokey.example.m");
        std::fs::create_dir_all(&lone).unwrap();
        std::fs::write(
            lone.join("nokey.example.m.crt"),
            cert_pem(&["nokey.example.m"]),
        )
        .unwrap();

        let r = SniResolver::load(&root);
        assert!(r.cert_for("DEV1.example.m").is_some());
        assert!(r.cert_for("a.apps.example.m").is_some());
        assert!(r.cert_for("a.b.apps.example.m").is_none());
        assert!(r.cert_for("nokey.example.m").is_none());
        assert!(tls_acceptor(&root).is_some());
        assert!(tls_acceptor(&root.join("missing")).is_none());
        std::fs::remove_dir_all(&root).unwrap();
    }

    fn write_test_pair(path: &Path, names: &[&str]) -> rustls::pki_types::CertificateDer<'static> {
        let ck = rcgen::generate_simple_self_signed(
            names.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        std::fs::write(path, ck.cert.pem()).unwrap();
        std::fs::write(path.with_extension("key"), ck.signing_key.serialize_pem()).unwrap();
        ck.cert.der().clone()
    }

    #[test]
    fn reload_is_explicit_atomic_and_does_not_discover_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("one.crt");
        let old = write_test_pair(&path, &["one.example.org"]);
        let certs = ReloadableCertificates::load(dir.path());
        let new = write_test_pair(&path, &["one.example.org", "alias.example.org"]);
        assert_eq!(
            certs
                .active
                .read()
                .unwrap()
                .cert_for("one.example.org")
                .unwrap()
                .cert[0],
            old
        );
        let extra = dir.path().join("extra.crt");
        write_test_pair(&extra, &["extra.example.org"]);
        assert_eq!(certs.reload(None).unwrap(), 1);
        let active = certs.active.read().unwrap();
        assert_eq!(active.cert_for("one.example.org").unwrap().cert[0], new);
        assert!(active.cert_for("alias.example.org").is_some());
        assert!(active.cert_for("extra.example.org").is_none());
        drop(active);
        // Partial failure must not install the otherwise valid extra cert.
        std::fs::write(&path, "broken certificate").unwrap();
        assert!(
            certs
                .reload(Some(vec![extra.clone(), path.clone()]))
                .is_err()
        );
        assert!(
            certs
                .active
                .read()
                .unwrap()
                .cert_for("extra.example.org")
                .is_none()
        );
        assert_eq!(
            certs
                .active
                .read()
                .unwrap()
                .cert_for("one.example.org")
                .unwrap()
                .cert[0],
            new
        );
        // A valid certificate with the previous key must also be rejected.
        let saved_key = std::fs::read(path.with_extension("key")).unwrap();
        write_test_pair(&path, &["one.example.org"]);
        std::fs::write(path.with_extension("key"), saved_key).unwrap();
        assert!(certs.reload(None).is_err());
        assert!(certs.reload(Some(vec![])).is_err());
        assert_eq!(certs.reload(Some(vec![extra])).unwrap(), 1);
        assert!(
            certs
                .active
                .read()
                .unwrap()
                .cert_for("one.example.org")
                .is_none()
        );
    }

    #[tokio::test]
    async fn same_listener_serves_reloaded_certificates_and_keeps_connections() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("one.crt");
        let old = write_test_pair(&path, &["one.example.org"]);
        let certs = Arc::new(ReloadableCertificates::load(dir.path()));
        let acceptor = certs.acceptor(None);
        let new = write_test_pair(&path, &["one.example.org"]);
        let mut roots = rustls::RootCertStore::empty();
        roots.add(old.clone()).unwrap();
        roots.add(new.clone()).unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let mut stream = acceptor.accept(stream).await.unwrap();
                    let mut byte = [0];
                    if stream.read_exact(&mut byte).await.is_ok() {
                        stream.write_all(&byte).await.unwrap();
                    }
                });
            }
        });
        let connect = || async {
            connector
                .connect(
                    "one.example.org".try_into().unwrap(),
                    tokio::net::TcpStream::connect(addr).await.unwrap(),
                )
                .await
                .unwrap()
        };
        let mut first = connect().await;
        assert_eq!(first.get_ref().1.peer_certificates().unwrap()[0], old);
        certs.reload(None).unwrap();
        let second = connect().await;
        assert_eq!(second.get_ref().1.peer_certificates().unwrap()[0], new);
        first.write_all(b"x").await.unwrap();
        let mut byte = [0];
        first.read_exact(&mut byte).await.unwrap();
        assert_eq!(&byte, b"x");
        server.abort();
    }

    #[test]
    fn explicit_first_install_works_with_an_existing_acceptor() {
        let dir = tempfile::tempdir().unwrap();
        let certs = Arc::new(ReloadableCertificates::load(dir.path()));
        let _acceptor = certs.acceptor(None);
        assert!(certs.reload(None).is_err());
        let path = dir.path().join("first.crt");
        write_test_pair(&path, &["first.example.org"]);
        assert_eq!(certs.reload(Some(vec![path])).unwrap(), 1);
        assert!(!certs.is_empty());
    }

    #[test]
    fn token_validation() {
        assert!(valid_token("abc-DEF_123"));
        assert!(!valid_token(""));
        assert!(!valid_token(".."));
        assert!(!valid_token("a/b"));
        assert!(!valid_token("a.b"));
    }

    #[tokio::test]
    async fn serves_challenge_files_only() {
        let www = temp_dir("www");
        let dir = www.join(".well-known/acme-challenge");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("tok-1"), "tok-1.thumbprint").unwrap();
        std::fs::write(www.join(".well-known/outside-secret"), "x").unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, acme_challenge_routes(www))
                .await
                .unwrap()
        });
        let base = format!("http://{addr}/.well-known/acme-challenge");

        let ok = reqwest::get(format!("{base}/tok-1")).await.unwrap();
        assert_eq!(ok.status(), 200);
        assert_eq!(ok.text().await.unwrap(), "tok-1.thumbprint");
        assert_eq!(
            reqwest::get(format!("{base}/missing"))
                .await
                .unwrap()
                .status(),
            404
        );
        assert_eq!(
            reqwest::get(format!("{base}/..%2Foutside-secret"))
                .await
                .unwrap()
                .status(),
            404
        );
    }
}
