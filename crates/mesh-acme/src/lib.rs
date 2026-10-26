//! mesh-acme: a small pure-Rust ACME client that stores its state in Caddy's
//! (certmagic's) on-disk layout, so an existing Caddy data dir can be reused.

use anyhow::{Context, Result, anyhow, bail};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, Key, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use p256::SecretKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const LE_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LE_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
pub const DEFAULT_RENEW_DAYS: u32 = 30;

pub const ACME_DIR_MODE: u32 = 0o700;
pub const ACME_FILE_MODE: u32 = 0o600;
pub const CERT_DIR_MODE: u32 = 0o750;
pub const CERT_FILE_MODE: u32 = 0o640;
pub const CHALLENGE_DIR_MODE: u32 = 0o755;
pub const CHALLENGE_FILE_MODE: u32 = 0o644;

// ---------------------------------------------------------------- config

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub email: Option<String>,
    pub directory: Option<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    pub renew_days: Option<u32>,
}

impl Config {
    pub fn renew_days(&self) -> u32 {
        self.renew_days.unwrap_or(DEFAULT_RENEW_DAYS)
    }
    pub fn directory_url(&self) -> &str {
        self.directory.as_deref().unwrap_or(LE_PRODUCTION)
    }
}

pub fn parse_config(text: &str) -> Result<Config> {
    toml::from_str(text).context("invalid config")
}

/// Ok(None) when the file does not exist.
pub fn load_config(path: &Path) -> Result<Option<Config>> {
    match fs::read_to_string(path) {
        Ok(t) => Ok(Some(
            parse_config(&t).with_context(|| path.display().to_string())?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| path.display().to_string()),
    }
}

pub fn default_config_path(home: &Path) -> PathBuf {
    home.join("etc/mesh-acme.toml")
}

// ---------------------------------------------------------------- naming

/// certmagic's `KeyBuilder.Safe`.
pub fn safe_key(s: &str) -> String {
    let s = s.to_lowercase();
    let s = s
        .trim()
        .replace(' ', "_")
        .replace('+', "_plus_")
        .replace('*', "wildcard_")
        .replace(':', "-")
        .replace("..", "");
    s.chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '_' | '@' | '.' | '-'))
        .collect()
}

/// certmagic's `issuerKey` (host incl. port, plus path with slashes turned
/// into hyphens), passed through `Safe` (which turns `:` into `-`).
pub fn issuer_dir(directory_url: &str) -> String {
    let rest = directory_url
        .split_once("://")
        .map_or(directory_url, |(_, r)| r);
    let (authority, tail) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let path = tail.split(['?', '#']).next().unwrap_or("");
    let path = path.replace(['/', '\\'], "-");
    let path = path.trim_matches('-');
    let mut key = host.to_string();
    if !path.is_empty() {
        key.push('-');
        key.push_str(path);
    }
    safe_key(&key)
}

/// Directory / file stem for a domain (`*.x` -> `wildcard_.x`).
pub fn cert_dir_name(domain: &str) -> String {
    safe_key(domain)
}

// ---------------------------------------------------------------- paths

pub fn caddy_dir(home: &Path) -> PathBuf {
    home.join(".local/share/caddy")
}
pub fn cert_dir(home: &Path, issuer: &str, domain: &str) -> PathBuf {
    caddy_dir(home)
        .join("certificates")
        .join(issuer)
        .join(cert_dir_name(domain))
}
fn cert_file(home: &Path, issuer: &str, domain: &str, ext: &str) -> PathBuf {
    let n = cert_dir_name(domain);
    cert_dir(home, issuer, domain).join(format!("{n}.{ext}"))
}
pub fn cert_path(home: &Path, issuer: &str, domain: &str) -> PathBuf {
    cert_file(home, issuer, domain, "crt")
}
pub fn key_path(home: &Path, issuer: &str, domain: &str) -> PathBuf {
    cert_file(home, issuer, domain, "key")
}
pub fn meta_path(home: &Path, issuer: &str, domain: &str) -> PathBuf {
    cert_file(home, issuer, domain, "json")
}

/// (user dir name, user name): email and the part before `@`, or `default`.
pub fn account_names(email: Option<&str>) -> (String, String) {
    match email.map(str::trim).filter(|e| !e.is_empty()) {
        Some(e) => {
            let user = e.split('@').next().unwrap_or(e);
            let user = if user.is_empty() { "default" } else { user };
            (safe_key(e), safe_key(user))
        }
        None => ("default".into(), "default".into()),
    }
}
pub fn account_dir(home: &Path, issuer: &str, email: Option<&str>) -> PathBuf {
    let (d, _) = account_names(email);
    caddy_dir(home)
        .join("acme")
        .join(issuer)
        .join("users")
        .join(d)
}
pub fn account_key_path(home: &Path, issuer: &str, email: Option<&str>) -> PathBuf {
    let (_, u) = account_names(email);
    account_dir(home, issuer, email).join(format!("{u}.key"))
}
pub fn account_json_path(home: &Path, issuer: &str, email: Option<&str>) -> PathBuf {
    let (_, u) = account_names(email);
    account_dir(home, issuer, email).join(format!("{u}.json"))
}
pub fn challenge_dir(home: &Path) -> PathBuf {
    home.join("www/.well-known/acme-challenge")
}
pub fn challenge_path(home: &Path, token: &str) -> PathBuf {
    challenge_dir(home).join(token)
}

// ---------------------------------------------------------------- account record

/// Caddy's account record (`USERNAME.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccountRecord {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub contact: Vec<String>,
    #[serde(default)]
    pub terms_of_service_agreed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

impl AccountRecord {
    pub fn new(email: Option<&str>, location: &str) -> Self {
        AccountRecord {
            status: "valid".into(),
            contact: email
                .filter(|e| !e.is_empty())
                .map(|e| vec![format!("mailto:{e}")])
                .unwrap_or_default(),
            terms_of_service_agreed: true,
            location: Some(location.to_string()),
        }
    }
    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
    /// Account URL, if present and non-empty.
    pub fn location(&self) -> Option<&str> {
        self.location.as_deref().filter(|l| !l.is_empty())
    }
}

// ---------------------------------------------------------------- keys

/// Parse an EC key in `EC PRIVATE KEY` (SEC1) or `PRIVATE KEY` (PKCS#8) PEM.
pub fn load_key(pem: &str) -> Result<SecretKey> {
    if pem.contains("BEGIN EC PRIVATE KEY") {
        SecretKey::from_sec1_pem(pem).map_err(|e| anyhow!("bad SEC1 key: {e}"))
    } else if pem.contains("BEGIN PRIVATE KEY") {
        SecretKey::from_pkcs8_pem(pem).map_err(|e| anyhow!("bad PKCS#8 key: {e}"))
    } else {
        bail!("unsupported key PEM (expected EC PRIVATE KEY or PRIVATE KEY, P-256)")
    }
}

/// PKCS#8 DER of a SEC1 or PKCS#8 PEM key.
pub fn key_pem_to_pkcs8_der(pem: &str) -> Result<Vec<u8>> {
    let k = load_key(pem)?;
    Ok(k.to_pkcs8_der()
        .map_err(|e| anyhow!("pkcs8 encode: {e}"))?
        .as_bytes()
        .to_vec())
}

pub fn pkcs8_der_to_pem(der: &[u8]) -> Result<String> {
    let k = SecretKey::from_pkcs8_der(der).map_err(|e| anyhow!("bad PKCS#8 key: {e}"))?;
    Ok(k.to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| anyhow!("pkcs8 pem: {e}"))?
        .to_string())
}

/// Normalize any supported key PEM to a PKCS#8 PEM.
pub fn key_pem_to_pkcs8_pem(pem: &str) -> Result<String> {
    pkcs8_der_to_pem(&key_pem_to_pkcs8_der(pem)?)
}

// ---------------------------------------------------------------- renewal

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// not_after (unix seconds) of the first (leaf) certificate in a PEM chain.
pub fn leaf_not_after(cert_pem: &[u8]) -> Result<i64> {
    for pem in x509_parser::pem::Pem::iter_from_buffer(cert_pem) {
        let pem = pem.map_err(|e| anyhow!("bad PEM: {e}"))?;
        if pem.label != "CERTIFICATE" {
            continue;
        }
        let cert = pem
            .parse_x509()
            .map_err(|e| anyhow!("bad certificate: {e}"))?;
        return Ok(cert.validity().not_after.timestamp());
    }
    bail!("no certificate in PEM")
}

/// True when the cert is unparseable or has `renew_days` or fewer days left.
pub fn needs_renewal(cert_pem: &[u8], now: i64, renew_days: u32) -> bool {
    match leaf_not_after(cert_pem) {
        Ok(na) => na - now <= i64::from(renew_days) * 86400,
        Err(_) => true,
    }
}

// ---------------------------------------------------------------- files

/// Create `path` and any missing parents below (not including) `base`, giving
/// newly created directories `mode`. Parents at or above `base` use defaults.
pub fn mkdirs(base: &Path, path: &Path, mode: u32) -> Result<()> {
    fs::create_dir_all(base)?;
    let mut todo = vec![];
    let mut p = path;
    while p != base && p.starts_with(base) {
        todo.push(p);
        match p.parent() {
            Some(q) => p = q,
            None => break,
        }
    }
    for d in todo.into_iter().rev() {
        if !d.exists() {
            fs::create_dir(d).with_context(|| d.display().to_string())?;
            fs::set_permissions(d, fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}

/// Write via a tmp file in the same directory, fsync, rename; final mode set.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let dir = path.parent().ok_or_else(|| anyhow!("no parent dir"))?;
    let name = path.file_name().ok_or_else(|| anyhow!("no file name"))?;
    let tmp = dir.join(format!(
        ".{}.tmp{}",
        name.to_string_lossy(),
        std::process::id()
    ));
    let res = (|| -> Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        f.set_permissions(fs::Permissions::from_mode(mode))?; // ignore umask
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res.with_context(|| path.display().to_string())
}

// ---------------------------------------------------------------- certificate store

#[derive(Serialize)]
struct CertMeta<'a> {
    sans: Vec<&'a str>,
    issuer_data: IssuerData<'a>,
}
#[derive(Serialize)]
struct IssuerData<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
}

pub fn store_certificate(
    home: &Path,
    issuer: &str,
    domain: &str,
    cert_pem: &str,
    key_pem: &str,
    cert_url: Option<&str>,
) -> Result<()> {
    let base = caddy_dir(home);
    mkdirs(&base, &cert_dir(home, issuer, domain), CERT_DIR_MODE)?;
    let san = domain.to_lowercase();
    let meta = serde_json::to_vec(&CertMeta {
        sans: vec![san.as_str()],
        issuer_data: IssuerData { url: cert_url },
    })?;
    // key first, so a present .crt implies a present .key
    write_atomic(
        &key_path(home, issuer, domain),
        key_pem.as_bytes(),
        CERT_FILE_MODE,
    )?;
    write_atomic(
        &cert_path(home, issuer, domain),
        cert_pem.as_bytes(),
        CERT_FILE_MODE,
    )?;
    write_atomic(&meta_path(home, issuer, domain), &meta, CERT_FILE_MODE)?;
    Ok(())
}

// ---------------------------------------------------------------- ACME

fn store_account(
    home: &Path,
    issuer: &str,
    email: Option<&str>,
    key_pem: Option<&str>,
    rec: &AccountRecord,
) -> Result<()> {
    let base = caddy_dir(home);
    mkdirs(&base, &account_dir(home, issuer, email), ACME_DIR_MODE)?;
    if let Some(k) = key_pem {
        write_atomic(
            &account_key_path(home, issuer, email),
            k.as_bytes(),
            ACME_FILE_MODE,
        )?;
    }
    write_atomic(
        &account_json_path(home, issuer, email),
        rec.to_json()?.as_bytes(),
        ACME_FILE_MODE,
    )
}

/// Load the Caddy account if present (reusing it), else create and store one.
pub async fn load_or_create_account(
    home: &Path,
    directory_url: &str,
    email: Option<&str>,
) -> Result<Account> {
    let issuer = issuer_dir(directory_url);
    let email = email.map(str::trim).filter(|e| !e.is_empty());
    let key_file = account_key_path(home, &issuer, email);
    let json_file = account_json_path(home, &issuer, email);
    let builder = || Account::builder().map_err(|e| anyhow!("acme client: {e}"));

    if let Ok(pem) = fs::read_to_string(&key_file) {
        let der = key_pem_to_pkcs8_der(&pem).with_context(|| key_file.display().to_string())?;
        let rec = fs::read_to_string(&json_file)
            .ok()
            .and_then(|s| AccountRecord::from_json(&s).ok());
        if let Some(loc) = rec.as_ref().and_then(|r| r.location()) {
            log::info!("reusing account {loc}");
            return builder()?
                .from_parts(
                    loc.to_string(),
                    der.as_slice().into(),
                    directory_url.to_string(),
                )
                .await
                .map_err(|e| anyhow!("restore account: {e}"));
        }
        // key but no location: look the account up by key, else register with it
        let mk = || -> Result<_> {
            Ok((
                Key::from_pkcs8_der(der.as_slice().into()).map_err(|e| anyhow!("key: {e}"))?,
                rustls_pki_types::PrivateKeyDer::Pkcs8(der.clone().into()),
            ))
        };
        let account = match builder()?.from_key(mk()?, directory_url.to_string()).await {
            Ok((a, _)) => {
                log::info!("found existing account for key: {}", a.id());
                a
            }
            Err(e) => {
                log::info!("no existing account for key ({e}); registering with it");
                let (a, _) = builder()?
                    .create_from_key(mk()?, directory_url.to_string())
                    .await
                    .map_err(|e| anyhow!("register account: {e}"))?;
                if let Some(em) = email {
                    let c = format!("mailto:{em}");
                    a.update_contacts(&[c.as_str()])
                        .await
                        .map_err(|e| anyhow!("set contact: {e}"))?;
                }
                a
            }
        };
        store_account(
            home,
            &issuer,
            email,
            None,
            &AccountRecord::new(email, account.id()),
        )?;
        return Ok(account);
    }

    log::info!("creating new account on {directory_url}");
    let contact: Vec<String> = email
        .map(|e| vec![format!("mailto:{e}")])
        .unwrap_or_default();
    let contact_refs: Vec<&str> = contact.iter().map(String::as_str).collect();
    let (account, creds) = builder()?
        .create(
            &NewAccount {
                contact: &contact_refs,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url.to_string(),
            None,
        )
        .await
        .map_err(|e| anyhow!("create account: {e}"))?;
    let pem = pkcs8_der_to_pem(creds.private_key().secret_pkcs8_der())?;
    store_account(
        home,
        &issuer,
        email,
        Some(&pem),
        &AccountRecord::new(email, account.id()),
    )?;
    Ok(account)
}

/// Removes the challenge files when dropped.
struct ChallengeFiles(Vec<PathBuf>);
impl Drop for ChallengeFiles {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = fs::remove_file(p);
        }
    }
}

/// Obtain and store a certificate for one domain via HTTP-01.
pub async fn issue(home: &Path, account: &Account, issuer: &str, domain: &str) -> Result<()> {
    if domain.contains('*') {
        bail!("wildcard names need DNS-01, which mesh-acme does not support");
    }
    let mut files = ChallengeFiles(vec![]);
    let res = issue_inner(home, account, issuer, domain, &mut files).await;
    drop(files);
    res
}

async fn issue_inner(
    home: &Path,
    account: &Account,
    issuer: &str,
    domain: &str,
    files: &mut ChallengeFiles,
) -> Result<()> {
    let ids = [Identifier::Dns(domain.to_string())];
    let mut order = account
        .new_order(&NewOrder::new(&ids))
        .await
        .map_err(|e| anyhow!("new order: {e}"))?;
    mkdirs(home, &challenge_dir(home), CHALLENGE_DIR_MODE)?;

    let mut authzs = order.authorizations();
    while let Some(a) = authzs.next().await {
        let mut authz = a.map_err(|e| anyhow!("authorization: {e}"))?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            s => bail!("authorization is {s:?}"),
        }
        let mut ch = authz
            .challenge(ChallengeType::Http01)
            .ok_or_else(|| anyhow!("no http-01 challenge offered"))?;
        let p = challenge_path(home, &ch.token);
        write_atomic(
            &p,
            ch.key_authorization().as_str().as_bytes(),
            CHALLENGE_FILE_MODE,
        )?;
        files.0.push(p);
        ch.set_ready()
            .await
            .map_err(|e| anyhow!("set ready: {e}"))?;
    }

    let status = order
        .poll_ready(&RetryPolicy::default().timeout(std::time::Duration::from_secs(120)))
        .await
        .map_err(|e| anyhow!("waiting for order: {e}"))?;
    if status != OrderStatus::Ready {
        bail!("unexpected order status {status:?}");
    }
    let key_pem = order
        .finalize()
        .await
        .map_err(|e| anyhow!("finalize: {e}"))?; // rcgen P-256
    let cert_pem = order
        .poll_certificate(&RetryPolicy::default().timeout(std::time::Duration::from_secs(120)))
        .await
        .map_err(|e| anyhow!("waiting for certificate: {e}"))?;
    let url = order.state().certificate.clone();
    let key_pem = key_pem_to_pkcs8_pem(&key_pem).unwrap_or(key_pem);
    store_certificate(home, issuer, domain, &cert_pem, &key_pem, url.as_deref())
}

// ---------------------------------------------------------------- run

pub struct Options {
    pub home: PathBuf,
    pub config: PathBuf,
    pub staging: bool,
    pub force: bool,
    pub dry_run: bool,
}

/// Returns the number of failed domains.
pub async fn run(opts: &Options) -> Result<usize> {
    let Some(cfg) = load_config(&opts.config)? else {
        log::info!("{} not found; nothing to do", opts.config.display());
        return Ok(0);
    };
    if cfg.domains.is_empty() {
        log::info!("no domains configured; nothing to do");
        return Ok(0);
    }
    let directory = if opts.staging {
        LE_STAGING
    } else {
        cfg.directory_url()
    };
    let issuer = issuer_dir(directory);
    let now = unix_now();

    let mut due = vec![];
    for d in &cfg.domains {
        let d = d.trim().to_lowercase();
        let renew = opts.force
            || match fs::read(cert_path(&opts.home, &issuer, &d)) {
                Ok(pem) => needs_renewal(&pem, now, cfg.renew_days()),
                Err(_) => true,
            };
        if renew {
            due.push(d);
        } else {
            log::info!(
                "{d}: certificate is valid for more than {} days",
                cfg.renew_days()
            );
        }
    }
    if due.is_empty() {
        return Ok(0);
    }
    if opts.dry_run {
        for d in &due {
            println!("would renew {d} via {directory}");
        }
        return Ok(0);
    }

    let account = load_or_create_account(&opts.home, directory, cfg.email.as_deref()).await?;
    let mut failed = 0;
    for d in &due {
        log::info!("{d}: requesting certificate");
        match issue(&opts.home, &account, &issuer, d).await {
            Ok(()) => log::info!("{d}: certificate stored"),
            Err(e) => {
                log::error!("{d}: {e:#}");
                failed += 1;
            }
        }
    }
    Ok(failed)
}

// ---------------------------------------------------------------- add

/// Validate a name for `acme add`: lower-cased, no wildcard, a DNS name with
/// at least two labels (so not a bare word and not an IP address).
pub fn validate_domain(name: &str) -> Result<String> {
    let d = name.trim().to_lowercase();
    if d.contains('*') {
        bail!("{name}: wildcard names need DNS-01, which is not supported yet");
    }
    if d.is_empty() || d.len() > 253 {
        bail!("{name}: invalid DNS name (length)");
    }
    let labels: Vec<&str> = d.trim_end_matches('.').split('.').collect();
    if labels.len() < 2 {
        bail!("{name}: invalid DNS name (need a fully qualified name)");
    }
    for l in &labels {
        let ok = !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        if !ok {
            bail!("{name}: invalid DNS name (bad label {l:?})");
        }
    }
    if labels
        .last()
        .is_some_and(|l| l.chars().all(|c| c.is_ascii_digit()))
    {
        bail!("{name}: IP addresses are not supported, use a DNS name");
    }
    Ok(d.trim_end_matches('.').to_string())
}

/// Add `domains` to the `domains` array of the config text, returning the new
/// text and the names actually added. Edits the TOML in place with `toml_edit`,
/// so comments, ordering and all other keys are preserved byte for byte.
/// Empty text (a missing file) yields a fresh `domains = [...]`.
pub fn add_domains_to_config(text: &str, domains: &[String]) -> Result<(String, Vec<String>)> {
    let mut doc: toml_edit::DocumentMut = text.parse().context("invalid config")?;
    let mut added: Vec<String> = vec![];
    let item = doc
        .entry("domains")
        .or_insert_with(|| toml_edit::value(toml_edit::Array::new()));
    let arr = item
        .as_array_mut()
        .ok_or_else(|| anyhow!("config key `domains` is not an array"))?;
    let existing: Vec<String> = arr
        .iter()
        .filter_map(|v| v.as_str())
        .map(|s| s.trim().to_lowercase())
        .collect();
    for d in domains {
        if !existing.contains(d) && !added.contains(d) {
            added.push(d.clone());
        }
    }
    for d in &added {
        arr.push(d.as_str());
    }
    if !added.is_empty() {
        arr.fmt();
    }
    Ok((doc.to_string(), added))
}

/// Validate `domains`, add the new ones to the config file (creating it), and
/// issue a certificate for each name now. Returns the number of names whose
/// issuance failed; the names stay in the config so `run` retries them.
pub async fn add_domains(opts: &Options, domains: &[String]) -> Result<usize> {
    let names = domains
        .iter()
        .map(|d| validate_domain(d))
        .collect::<Result<Vec<_>>>()?;
    let text = match fs::read_to_string(&opts.config) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| opts.config.display().to_string()),
    };
    let (new_text, added) = add_domains_to_config(&text, &names)?;
    if !added.is_empty() {
        // Make sure the result still parses before touching the file.
        parse_config(&new_text)?;
        if let Some(dir) = opts.config.parent() {
            fs::create_dir_all(dir).with_context(|| dir.display().to_string())?;
        }
        fs::write(&opts.config, new_text).with_context(|| opts.config.display().to_string())?;
        log::info!("added {} to {}", added.join(", "), opts.config.display());
    }
    let cfg = load_config(&opts.config)?.context("config vanished")?;
    let directory = if opts.staging {
        LE_STAGING
    } else {
        cfg.directory_url()
    };
    let issuer = issuer_dir(directory);
    let account = load_or_create_account(&opts.home, directory, cfg.email.as_deref()).await?;
    let mut failed = 0;
    for d in &names {
        log::info!("{d}: requesting certificate");
        match issue(&opts.home, &account, &issuer, d).await {
            Ok(()) => println!("{}", cert_path(&opts.home, &issuer, d).display()),
            Err(e) => {
                log::error!("{d}: {e:#}");
                failed += 1;
            }
        }
    }
    Ok(failed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};
    use time::{Duration, OffsetDateTime};

    #[test]
    fn issuer_names() {
        assert_eq!(
            issuer_dir(LE_PRODUCTION),
            "acme-v02.api.letsencrypt.org-directory"
        );
        assert_eq!(
            issuer_dir(LE_STAGING),
            "acme-staging-v02.api.letsencrypt.org-directory"
        );
        assert_eq!(
            issuer_dir("https://localhost:14000/dir"),
            "localhost-14000-dir"
        );
        assert_eq!(issuer_dir("https://ca.example/a/b/"), "ca.example-a-b");
        assert_eq!(issuer_dir("https://ca.example"), "ca.example");
    }

    #[test]
    fn wildcard_and_domain_names() {
        assert_eq!(cert_dir_name("*.Example.COM"), "wildcard_.example.com");
        assert_eq!(cert_dir_name("Dev1.H.webinf.info"), "dev1.h.webinf.info");
    }

    #[test]
    fn path_builders() {
        let h = Path::new("/home/acme");
        let i = "acme-v02.api.letsencrypt.org-directory";
        let d = "/home/acme/.local/share/caddy";
        assert_eq!(caddy_dir(h), Path::new(d));
        assert_eq!(
            cert_path(h, i, "*.x.com"),
            Path::new(&format!(
                "{d}/certificates/{i}/wildcard_.x.com/wildcard_.x.com.crt"
            ))
        );
        assert_eq!(
            key_path(h, i, "a.com"),
            Path::new(&format!("{d}/certificates/{i}/a.com/a.com.key"))
        );
        assert_eq!(
            meta_path(h, i, "a.com"),
            Path::new(&format!("{d}/certificates/{i}/a.com/a.com.json"))
        );
        assert_eq!(
            account_key_path(h, i, None),
            Path::new(&format!("{d}/acme/{i}/users/default/default.key"))
        );
        assert_eq!(
            account_json_path(h, i, Some("admin@example.m")),
            Path::new(&format!("{d}/acme/{i}/users/admin@example.m/admin.json"))
        );
        assert_eq!(
            account_key_path(h, i, Some("admin@example.m")),
            Path::new(&format!("{d}/acme/{i}/users/admin@example.m/admin.key"))
        );
        assert_eq!(
            challenge_dir(h),
            Path::new("/home/acme/www/.well-known/acme-challenge")
        );
        assert_eq!(
            challenge_path(h, "tok"),
            Path::new("/home/acme/www/.well-known/acme-challenge/tok")
        );
        assert_eq!(
            default_config_path(h),
            Path::new("/home/acme/etc/mesh-acme.toml")
        );
    }

    #[test]
    fn keys_sec1_and_pkcs8() {
        let kp = KeyPair::generate().unwrap();
        let pkcs8_pem = kp.serialize_pem();
        assert!(pkcs8_pem.contains("BEGIN PRIVATE KEY"));
        let sk = load_key(&pkcs8_pem).unwrap();
        let sec1 = sk.to_sec1_pem(LineEnding::LF).unwrap();
        assert!(sec1.contains("BEGIN EC PRIVATE KEY"));
        let sk2 = load_key(&sec1).unwrap();
        assert_eq!(sk.to_bytes(), sk2.to_bytes());
        // both normalise to the same PKCS#8, which ring (instant-acme) accepts
        let a = key_pem_to_pkcs8_der(&pkcs8_pem).unwrap();
        let b = key_pem_to_pkcs8_der(&sec1).unwrap();
        assert_eq!(a, b);
        Key::from_pkcs8_der(a.as_slice().into()).expect("ring accepts converted key");
        assert!(
            key_pem_to_pkcs8_pem(&sec1)
                .unwrap()
                .contains("BEGIN PRIVATE KEY")
        );
        assert!(
            load_key("-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----")
                .is_err()
        );
    }

    fn cert_pem(not_after: OffsetDateTime) -> String {
        let mut p = CertificateParams::new(vec!["a.example".into()]).unwrap();
        p.not_before = not_after - Duration::days(90);
        p.not_after = not_after;
        let kp = KeyPair::generate().unwrap();
        p.self_signed(&kp).unwrap().pem()
    }

    #[test]
    fn renewal() {
        let now = OffsetDateTime::now_utc();
        let ts = now.unix_timestamp();
        let far = cert_pem(now + Duration::days(60));
        let near = cert_pem(now + Duration::days(10));
        let gone = cert_pem(now - Duration::days(1));
        assert!(!needs_renewal(far.as_bytes(), ts, 30));
        assert!(needs_renewal(far.as_bytes(), ts, 70));
        assert!(needs_renewal(near.as_bytes(), ts, 30));
        assert!(!needs_renewal(near.as_bytes(), ts, 5));
        assert!(needs_renewal(gone.as_bytes(), ts, 0));
        assert!(needs_renewal(b"garbage", ts, 30));
        // chain: leaf is first
        let chain = format!("{near}{far}");
        assert!(needs_renewal(chain.as_bytes(), ts, 30));
    }

    #[test]
    fn config_parsing() {
        let c = parse_config(
            "email='a@b.c'\ndomains=['x.y','z.y']\nrenew_days=10\ndirectory='https://d/e'\n",
        )
        .unwrap();
        assert_eq!(c.renew_days(), 10);
        assert_eq!(c.directory_url(), "https://d/e");
        assert_eq!(c.domains.len(), 2);
        let c = parse_config("domains=['x.y']").unwrap();
        assert_eq!(c.renew_days(), 30);
        assert_eq!(c.directory_url(), LE_PRODUCTION);
        assert!(c.email.is_none());
        assert!(parse_config("domains=[]\nbogus=1").is_err());
        assert!(parse_config("").unwrap().domains.is_empty());
    }

    #[test]
    fn config_missing_file() {
        let t = tempfile::tempdir().unwrap();
        assert!(load_config(&t.path().join("nope.toml")).unwrap().is_none());
        let p = t.path().join("c.toml");
        fs::write(&p, "domains=['a.b']").unwrap();
        assert_eq!(load_config(&p).unwrap().unwrap().domains, vec!["a.b"]);
    }

    #[tokio::test]
    async fn run_without_config_is_ok() {
        let t = tempfile::tempdir().unwrap();
        let o = Options {
            home: t.path().into(),
            config: default_config_path(t.path()),
            staging: false,
            force: false,
            dry_run: false,
        };
        assert_eq!(run(&o).await.unwrap(), 0);
    }

    #[test]
    fn account_record_roundtrip() {
        let caddy = r#"{"status":"valid","contact":["mailto:admin@example.m"],"termsOfServiceAgreed":true,"location":"https://acme-v02.api.letsencrypt.org/acme/acct/12345","extra":1}"#;
        let r = AccountRecord::from_json(caddy).unwrap();
        assert_eq!(
            r.location(),
            Some("https://acme-v02.api.letsencrypt.org/acme/acct/12345")
        );
        assert_eq!(r.contact, vec!["mailto:admin@example.m"]);
        assert!(r.terms_of_service_agreed);
        let back = AccountRecord::from_json(&r.to_json().unwrap()).unwrap();
        assert_eq!(r, back);
        let v: serde_json::Value = serde_json::from_str(&r.to_json().unwrap()).unwrap();
        assert_eq!(v["termsOfServiceAgreed"], true);
        assert_eq!(v["status"], "valid");
        let n = AccountRecord::new(Some("a@b.c"), "https://x/acct/1");
        assert_eq!(n.contact, vec!["mailto:a@b.c"]);
        assert_eq!(AccountRecord::new(None, "u").contact.len(), 0);
        // no location
        assert!(
            AccountRecord::from_json(r#"{"status":"valid"}"#)
                .unwrap()
                .location()
                .is_none()
        );
    }

    #[test]
    fn atomic_write_mode() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("f.key");
        write_atomic(&p, b"one", 0o640).unwrap();
        write_atomic(&p, b"two", 0o600).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let names: Vec<_> = fs::read_dir(t.path()).unwrap().collect();
        assert_eq!(names.len(), 1, "no tmp file left behind");
        write_atomic(&t.path().join("g"), b"x", 0o640).unwrap();
        assert_eq!(
            fs::metadata(t.path().join("g"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
    }

    #[test]
    fn store_layout_and_modes() {
        let t = tempfile::tempdir().unwrap();
        let h = t.path();
        let i = issuer_dir(LE_STAGING);
        store_certificate(h, &i, "A.example", "CERT", "KEY", Some("https://c/1")).unwrap();
        let m = |p: PathBuf| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(m(cert_dir(h, &i, "a.example")), 0o750);
        assert_eq!(m(caddy_dir(h).join("certificates")), 0o750);
        assert_eq!(m(key_path(h, &i, "a.example")), 0o640);
        assert_eq!(m(cert_path(h, &i, "a.example")), 0o640);
        let j: serde_json::Value =
            serde_json::from_slice(&fs::read(meta_path(h, &i, "a.example")).unwrap()).unwrap();
        assert_eq!(j["sans"][0], "a.example");
        assert_eq!(j["issuer_data"]["url"], "https://c/1");
        store_account(h, &i, None, Some("K"), &AccountRecord::new(None, "L")).unwrap();
        assert_eq!(m(account_dir(h, &i, None)), 0o700);
        assert_eq!(m(caddy_dir(h).join("acme")), 0o700);
        assert_eq!(m(account_key_path(h, &i, None)), 0o600);
        assert_eq!(m(account_json_path(h, &i, None)), 0o600);
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn add_keeps_comments_and_keys() {
        let t = "# my config\nemail = \"a@b.c\"  # contact\n\n# the names\ndomains = [\"x.example.com\"] # trailing\nrenew_days = 20\n";
        let (out, added) = add_domains_to_config(t, &s(&["y.example.com"])).unwrap();
        assert_eq!(added, s(&["y.example.com"]));
        assert!(out.contains("# my config"));
        assert!(out.contains("# contact"));
        assert!(out.contains("# the names"));
        assert!(out.contains("# trailing"));
        let c = parse_config(&out).unwrap();
        assert_eq!(c.domains, s(&["x.example.com", "y.example.com"]));
        assert_eq!(c.email.as_deref(), Some("a@b.c"));
        assert_eq!(c.renew_days, Some(20));
    }

    #[test]
    fn add_does_not_duplicate() {
        let t = "domains = [\"x.example.com\"]\n";
        let (out, added) =
            add_domains_to_config(t, &s(&["x.example.com", "n.example.com", "n.example.com"]))
                .unwrap();
        assert_eq!(added, s(&["n.example.com"]));
        let (out2, added2) = add_domains_to_config(&out, &s(&["n.example.com"])).unwrap();
        assert!(added2.is_empty());
        assert_eq!(out, out2);
        assert_eq!(
            parse_config(&out).unwrap().domains,
            s(&["x.example.com", "n.example.com"])
        );
    }

    #[test]
    fn add_creates_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let opts = Options {
            home: dir.path().to_path_buf(),
            config: dir.path().join("etc/mesh-acme.toml"),
            staging: true,
            force: false,
            dry_run: false,
        };
        // Invalid names fail before any file or network access.
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        assert!(
            rt.block_on(add_domains(&opts, &s(&["*.example.com"])))
                .is_err()
        );
        assert!(!opts.config.exists());
        let (out, added) = add_domains_to_config("", &s(&["a.example.com"])).unwrap();
        assert_eq!(added.len(), 1);
        assert_eq!(parse_config(&out).unwrap().domains, s(&["a.example.com"]));
        assert!(out.contains("domains = [\"a.example.com\"]"));
    }

    #[test]
    fn add_to_file_without_domains_key() {
        let t = "# only email\nemail = \"a@b.c\"\n";
        let (out, _) = add_domains_to_config(t, &s(&["a.example.com"])).unwrap();
        assert!(out.starts_with("# only email\nemail = \"a@b.c\"\n"));
        assert_eq!(parse_config(&out).unwrap().domains, s(&["a.example.com"]));
        assert!(add_domains_to_config("domains = 3\n", &s(&["a.example.com"])).is_err());
    }

    #[test]
    fn validate_domain_cases() {
        assert_eq!(
            validate_domain(" Dev1.Example.COM ").unwrap(),
            "dev1.example.com"
        );
        for bad in [
            "*.example.com",
            "bad*name",
            "localhost",
            "a..b.com",
            "-a.com",
            "a_b.com",
            "1.2.3.4",
            "",
            "a b.com",
        ] {
            assert!(validate_domain(bad).is_err(), "{bad}");
        }
    }
}
