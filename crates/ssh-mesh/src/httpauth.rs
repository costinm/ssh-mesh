//! Authentication of HTTP(S) listeners, done by the gateway.
//!
//! There is nothing to store. Credentials are derived from the master secret
//! ([`MasterSecret`], `<SSH_BASEDIR>/mesh_secret`, generated on first start):
//!
//! - an **API key** is `ID:SECRET`, where `SECRET` is
//!   `HMAC(apikey_key, ID)`. Whoever can read the master secret mints a key for
//!   any ID with `meshkeys apikey ID`; the server checks one by recomputing
//!   it. The same pair works as a Basic-auth user and password, and is meant
//!   to work as an SSH user and password too ([`Secrets::verify_password`]);
//! - a **session token** is a JWT (HS256) signed with a second derived key.
//!
//! A credential is accepted from `Authorization: Bearer` (a token, or an
//! `ID:SECRET` key), `Authorization: Basic`, `X-Api-Key`, or the
//! `mesh_session` cookie. The cookie carries the same token as the header, so
//! the two are equivalent.
//!
//! A listener has a mode ([`AuthMode`]): `none` (nothing is checked),
//! `apikey` (401 without a valid credential) or `login` (a browser navigation
//! is redirected to `/_m/login`, which exchanges an API key for the cookie;
//! other clients get 401). The login page, the ACME challenges and the SSH
//! entry points (which authenticate themselves) are exempt.
//!
//! Revoking one key is not possible without storage. Replacing the master
//! secret revokes all of them. Session expiry is optional and configured per listener.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Form, Router};
use ring::hmac;
use serde::{Deserialize, Serialize};

use crate::auth::MasterSecret;

pub const SESSION_COOKIE: &str = "mesh_session";
pub const LOGIN_PATH: &str = "/_m/login";
pub const LOGOUT_PATH: &str = "/_m/logout";

/// Paths that are never authenticated: well-known metadata and ACME are public, the
/// login page has to be reachable to log in, and the SSH entry points run the
/// SSH handshake, which authenticates the peer itself.
pub const BUILTIN_EXEMPT: &[&str] = &[
    "/.well-known/",
    LOGIN_PATH,
    LOGOUT_PATH,
    "/_m/_ssh",
    "/_m/_ws/_ssh",
];

/// Failed logins allowed per minute before login answers 429.
const MAX_FAILURES_PER_MINUTE: usize = 10;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// Nothing is checked.
    #[default]
    None,
    /// A valid credential is required; otherwise 401.
    ApiKey,
    /// Like `apikey`, and a browser navigation is redirected to the login page.
    Login,
}

/// Configuration, under `http_auth` in the node config.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct HttpAuthConfig {
    /// Mode of listeners not named in `listeners`.
    pub default: AuthMode,
    /// Mode per listener: `http` (plain, `http`/`h2c`), `mesh` (the mesh
    /// H2/mTLS listener), `admin`, `https` (the public TLS web listener).
    /// The `:80` listener serves ACME challenges and is not authenticated.
    pub listeners: HashMap<String, AuthMode>,
    /// Exact virtual host overrides on the HTTPS web listener (without ports).
    pub hosts: HashMap<String, AuthMode>,
    /// More paths that skip authentication: a prefix ending in `/`, or an
    /// exact path (and what is below it).
    pub exempt: Vec<String>,
    /// Inactivity lifetime in seconds, renewed on use; zero means no expiry.
    pub session_ttl_secs: u64,
}

impl Default for HttpAuthConfig {
    fn default() -> Self {
        Self {
            default: AuthMode::None,
            listeners: HashMap::new(),
            hosts: HashMap::new(),
            exempt: Vec::new(),
            session_ttl_secs: 0,
        }
    }
}

impl HttpAuthConfig {
    pub fn mode_for(&self, listener: &str) -> AuthMode {
        self.listeners
            .get(listener)
            .copied()
            .unwrap_or(self.default)
    }
}

// ----------------------------------------------------------------- encoding

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64url without padding.
fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 4).div_ceil(3));
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18 & 63) as usize] as char);
        out.push(B64[(n >> 12 & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64[(n >> 6 & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64[(n & 63) as usize] as char);
        }
    }
    out
}

/// Base64, either alphabet, padding optional.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (bits < 6).then_some(out)
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Where to go after login: a local absolute path only, never another site.
fn sanitize_next(next: &str) -> String {
    let ok = next.starts_with('/')
        && !next.starts_with("//")
        && !next.contains('\\')
        && !matches!(
            next.split(['?', '#']).next(),
            Some(LOGIN_PATH | LOGOUT_PATH)
        )
        && next.len() <= 2048
        && next.bytes().all(|b| (0x21..0x7f).contains(&b));
    if ok { next.to_owned() } else { "/".to_owned() }
}

// ------------------------------------------------------------------ secrets

/// An ID in an API key: `[A-Za-z0-9._@-]`, 1 to 64 characters. No `:`, which
/// separates the ID from the secret.
pub fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b'-'))
}

/// The keys derived from the host key. Cloning is cheap.
#[derive(Clone)]
pub struct Secrets {
    apikey: hmac::Key,
    session: hmac::Key,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    iat: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exp: Option<u64>,
}

fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

impl Secrets {
    /// Derive the keys from the master secret. These labels are a
    /// compatibility promise: changing one invalidates every issued key.
    pub fn from_master(master: &MasterSecret) -> Self {
        let derive = |label: &str| hmac::Key::new(hmac::HMAC_SHA256, &master.prf(label, b""));
        Self {
            apikey: derive("ssh-mesh/http/apikey"),
            session: derive("ssh-mesh/http/session"),
        }
    }

    /// The API key for `id`, as `ID:SECRET`.
    pub fn api_key(&self, id: &str) -> Result<String> {
        anyhow::ensure!(
            valid_id(id),
            "an ID is 1-64 characters from [A-Za-z0-9._@-]"
        );
        let tag = hmac::sign(&self.apikey, id.as_bytes());
        Ok(format!("{id}:{}", b64_encode(tag.as_ref())))
    }

    /// The ID of a valid `ID:SECRET` key. The comparison is constant time.
    pub fn verify_api_key(&self, key: &str) -> Option<String> {
        let (id, secret) = key.split_once(':')?;
        self.verify_password(id, secret).then(|| id.to_owned())
    }

    /// Whether `password` is the secret of `user`. This is what a Basic login
    /// or an SSH password login checks.
    pub fn verify_password(&self, user: &str, password: &str) -> bool {
        if !valid_id(user) {
            return false;
        }
        let Some(tag) = b64_decode(password) else {
            return false;
        };
        hmac::verify(&self.apikey, user.as_bytes(), &tag).is_ok()
    }

    /// A session token for `sub`, valid for `ttl` from `now`; zero means no expiry.
    pub fn issue_token(&self, sub: &str, ttl: Duration, now: SystemTime) -> String {
        let claims = Claims {
            sub: sub.to_owned(),
            iat: unix(now),
            exp: (!ttl.is_zero()).then(|| unix(now).saturating_add(ttl.as_secs())),
        };
        let header = b64_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = b64_encode(&serde_json::to_vec(&claims).expect("claims serialize"));
        let input = format!("{header}.{payload}");
        let sig = hmac::sign(&self.session, input.as_bytes());
        format!("{input}.{}", b64_encode(sig.as_ref()))
    }

    /// The subject of a valid, unexpired token. Only HS256 is accepted.
    pub fn verify_token(&self, token: &str, now: SystemTime) -> Option<String> {
        let mut parts = token.split('.');
        let (header, payload, sig) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        let head: serde_json::Value = serde_json::from_slice(&b64_decode(header)?).ok()?;
        if head.get("alg").and_then(|a| a.as_str()) != Some("HS256") {
            return None;
        }
        let input = format!("{header}.{payload}");
        hmac::verify(&self.session, input.as_bytes(), &b64_decode(sig)?).ok()?;
        let claims: Claims = serde_json::from_slice(&b64_decode(payload)?).ok()?;
        (claims.exp.is_none_or(|exp| exp > unix(now)) && !claims.sub.is_empty())
            .then_some(claims.sub)
    }
}

// ----------------------------------------------------------------- identity

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    ApiKey,
    Session,
}

/// The authenticated caller; added to the request extensions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub name: String,
    pub method: AuthMethod,
}

/// Headers verified as gateway credentials, rather than application credentials.
#[derive(Clone, Copy, Default)]
pub(crate) struct GatewayCredentials {
    pub authorization: bool,
    pub api_key: bool,
    cookie: bool,
}

/// Public web hosts bypass gateway auth only for their HTTP upstream, not stream RPC.
#[derive(Clone, Copy)]
pub(crate) struct PublicWebHost;

fn header_str(headers: &HeaderMap, name: impl header::AsHeaderName) -> Option<&str> {
    headers.get(name)?.to_str().ok()
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    // HTTP/2 permits Cookie to be split across multiple header fields.
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|part| {
            let (n, v) = part.trim().split_once('=')?;
            (n == name).then_some(v)
        })
}

// ------------------------------------------------------------------- state

struct Inner {
    secrets: Secrets,
    mode: AuthMode,
    hosts: HashMap<String, AuthMode>,
    exempt: Vec<String>,
    ttl: Duration,
    secure_cookie: bool,
    fail_delay: Duration,
    failures: Mutex<VecDeque<Instant>>,
}

/// The authentication of one listener.
#[derive(Clone)]
pub struct HttpAuth {
    inner: Arc<Inner>,
    login_command: String,
}

fn path_matches(path: &str, pattern: &str) -> bool {
    if pattern.ends_with('/') {
        path.starts_with(pattern)
    } else {
        path == pattern
            || path
                .strip_prefix(pattern)
                .is_some_and(|rest| rest.starts_with('/'))
    }
}

impl HttpAuth {
    /// `secure_cookie` adds `Secure` to the cookie; set it for TLS listeners.
    pub fn new(
        secrets: Secrets,
        mode: AuthMode,
        config: &HttpAuthConfig,
        secure_cookie: bool,
    ) -> Self {
        Self {
            login_command: "meshkeys apikey YOUR_ID --keydir /path/to/ssh-mesh/etc".to_string(),
            inner: Arc::new(Inner {
                secrets,
                mode,
                hosts: config
                    .hosts
                    .iter()
                    .map(|(host, mode)| (host.trim_end_matches('.').to_ascii_lowercase(), *mode))
                    .collect(),
                exempt: config.exempt.clone(),
                ttl: Duration::from_secs(config.session_ttl_secs),
                secure_cookie,
                fail_delay: Duration::from_millis(250),
                failures: Mutex::new(VecDeque::new()),
            }),
        }
    }

    /// Replace the delay after a failed login (tests use zero).
    pub fn with_fail_delay(self, delay: Duration) -> Self {
        let inner = &*self.inner;
        Self {
            login_command: self.login_command.clone(),
            inner: Arc::new(Inner {
                secrets: inner.secrets.clone(),
                mode: inner.mode,
                hosts: inner.hosts.clone(),
                exempt: inner.exempt.clone(),
                ttl: inner.ttl,
                secure_cookie: inner.secure_cookie,
                fail_delay: delay,
                failures: Mutex::new(VecDeque::new()),
            }),
        }
    }

    /// Set the host-specific command shown on the login page (HTML escaped).
    pub fn with_login_command(mut self, command: String) -> Self {
        self.login_command = command;
        self
    }

    pub fn mode(&self) -> AuthMode {
        self.inner.mode
    }

    fn is_exempt(&self, path: &str) -> bool {
        BUILTIN_EXEMPT
            .iter()
            .copied()
            .chain(self.inner.exempt.iter().map(String::as_str))
            .any(|pattern| path_matches(path, pattern))
    }

    /// The caller named by the request credentials, if they are valid.
    pub fn authenticate(&self, headers: &HeaderMap, now: SystemTime) -> Option<Identity> {
        self.authenticate_request(headers, now)
            .map(|(identity, _)| identity)
    }

    fn authenticate_request(
        &self,
        headers: &HeaderMap,
        now: SystemTime,
    ) -> Option<(Identity, GatewayCredentials)> {
        let secrets = &self.inner.secrets;
        let api_key = |key: &str| {
            secrets.verify_api_key(key).map(|name| Identity {
                name,
                method: AuthMethod::ApiKey,
            })
        };
        let token = |token: &str| {
            secrets.verify_token(token, now).map(|name| Identity {
                name,
                method: AuthMethod::Session,
            })
        };

        let authorization = if let Some((scheme, value)) =
            header_str(headers, header::AUTHORIZATION).and_then(|v| v.split_once(' '))
        {
            let value = value.trim();
            if scheme.eq_ignore_ascii_case("bearer") {
                // An API key has a ':'; a JWT never does.
                if value.contains(':') {
                    api_key(value)
                } else {
                    token(value)
                }
            } else if scheme.eq_ignore_ascii_case("basic")
                && let Some(decoded) = b64_decode(value).and_then(|b| String::from_utf8(b).ok())
                && let Some(found) = api_key(&decoded)
            {
                Some(found)
            } else {
                None
            }
        } else {
            None
        };
        let key = header_str(headers, "x-api-key").and_then(|k| api_key(k.trim()));
        let cookie = cookie_value(headers, SESSION_COOKIE).and_then(token);
        let credentials = GatewayCredentials {
            authorization: authorization.is_some(),
            api_key: key.is_some(),
            cookie: authorization.is_none() && key.is_none() && cookie.is_some(),
        };
        authorization
            .or(key)
            .or(cookie)
            .map(|identity| (identity, credentials))
    }

    /// Wrap `router` with this authentication, and add the login page. With
    /// mode `none` the router is returned unchanged.
    pub fn apply(&self, router: Router) -> Router {
        self.apply_with_exemptions(router, false)
    }

    /// Authenticate a web backend, exempting only the gateway login/logout pages.
    /// Transport and metadata exclusions must not expose upstream application paths.
    pub fn apply_web(&self, router: Router) -> Router {
        self.apply_with_exemptions(router, true)
    }

    fn apply_with_exemptions(&self, router: Router, web: bool) -> Router {
        if self.inner.mode == AuthMode::None
            && (!web
                || self
                    .inner
                    .hosts
                    .values()
                    .all(|mode| *mode == AuthMode::None))
        {
            return router;
        }
        let login = Router::new()
            .route(LOGIN_PATH, get(login_page).post(login_submit))
            .route(LOGOUT_PATH, get(logout).post(logout))
            .with_state(self.clone());
        router
            .merge(login)
            .layer(axum::middleware::from_fn_with_state(
                (self.clone(), web),
                require_auth,
            ))
    }

    fn session_cookie(&self, token: &str, max_age: u64) -> String {
        // Browsers bound persistent-cookie retention. Non-expiring sessions use
        // a year-long cookie and renew that retention window whenever used.
        let max_age = if max_age == 0 && !token.is_empty() {
            365 * 24 * 3600
        } else {
            max_age
        };
        format!(
            "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
            if self.inner.secure_cookie {
                "; Secure"
            } else {
                ""
            }
        )
    }

    fn too_many_failures(&self) -> bool {
        let mut failures = self.inner.failures.lock().expect("failures lock");
        let now = Instant::now();
        while failures
            .front()
            .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60))
        {
            failures.pop_front();
        }
        failures.len() >= MAX_FAILURES_PER_MINUTE
    }

    fn record_failure(&self) {
        self.inner
            .failures
            .lock()
            .expect("failures lock")
            .push_back(Instant::now());
    }

    fn web_mode(&self, request: &Request) -> AuthMode {
        let authority = request.uri().authority().cloned().or_else(|| {
            header_str(request.headers(), header::HOST)?
                .parse::<axum::http::uri::Authority>()
                .ok()
        });
        authority
            .and_then(|authority| {
                self.inner
                    .hosts
                    .get(&authority.host().trim_end_matches('.').to_ascii_lowercase())
                    .copied()
            })
            .unwrap_or(self.inner.mode)
    }

    fn reject(&self, req: &Request, mode: AuthMode) -> Response {
        let browser = matches!(*req.method(), Method::GET | Method::HEAD)
            && header_str(req.headers(), header::ACCEPT).is_some_and(|a| a.contains("text/html"));
        if mode == AuthMode::Login && browser {
            let target = req.uri().path_and_query().map_or("/", |pq| pq.as_str());
            return Redirect::to(&format!(
                "{LOGIN_PATH}?next={}",
                percent_encode(&sanitize_next(target))
            ))
            .into_response();
        }
        let mut response = (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response();
        let headers = response.headers_mut();
        headers.append(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"ssh-mesh\""),
        );
        // Login-mode API requests must not open a browser's native password
        // dialog when the session expires. Navigation uses the login form.
        if mode == AuthMode::ApiKey {
            headers.append(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"ssh-mesh\", charset=\"UTF-8\""),
            );
        }
        response
    }
}

async fn require_auth(
    State((auth, web)): State<(HttpAuth, bool)>,
    mut req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path();
    let mode = if web {
        auth.web_mode(&req)
    } else {
        auth.inner.mode
    };
    if mode == AuthMode::None {
        if web {
            req.extensions_mut().insert(PublicWebHost);
        }
        return next.run(req).await;
    }
    if (web && matches!(path, LOGIN_PATH | LOGOUT_PATH)) || (!web && auth.is_exempt(path)) {
        return next.run(req).await;
    }
    match auth.authenticate_request(req.headers(), SystemTime::now()) {
        Some((identity, credentials)) => {
            let renewed_cookie = credentials.cookie.then(|| {
                let token = auth.inner.secrets.issue_token(
                    &identity.name,
                    auth.inner.ttl,
                    SystemTime::now(),
                );
                auth.session_cookie(&token, auth.inner.ttl.as_secs())
            });
            req.extensions_mut().insert(identity);
            req.extensions_mut().insert(credentials);
            let mut response = next.run(req).await;
            // Login/logout bypass this branch and manage their own cookies.
            if let Some(cookie) = renewed_cookie
                && let Ok(cookie) = HeaderValue::from_str(&cookie)
            {
                response.headers_mut().append(header::SET_COOKIE, cookie);
            }
            response
        }
        None => auth.reject(&req, mode),
    }
}

// -------------------------------------------------------------- login pages

const LOGIN_HTML: &str = r#"<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>ssh-mesh login</title>
<style>
body { font: 16px system-ui, sans-serif; max-width: 22rem; margin: 20vh auto; padding: 0 1rem; }
input, button { font: inherit; width: 100%; box-sizing: border-box; margin: .4rem 0; padding: .5rem; }
.err { color: #b42318; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; font-size: .85rem; }
</style>
<h1>ssh-mesh</h1>
{{ERR}}
<p>Generate a mesh API key on this server:</p>
<pre>{{COMMAND}}</pre>
<p>Replace YOUR_ID with your user name. Paste the full <code>ID:SECRET</code>
output below. This is separate from an application's password.</p>
<form method="post" action="/_m/login" autocomplete="off">
<input type="hidden" name="next" value="{{NEXT}}">
<label>Gateway account
<input type="text" name="username" value="ssh-mesh" autocomplete="username" readonly></label>
<label>API key (ID:SECRET)
<input type="password" name="key" autocomplete="off" autofocus required></label>
<button>Sign in</button>
</form>
"#;

fn login_html(auth: &HttpAuth, next: &str, error: Option<&str>) -> Html<String> {
    let err = error.map_or(String::new(), |e| {
        format!("<p class=\"err\">{}</p>", html_escape(e))
    });
    Html(
        LOGIN_HTML
            .replace("{{COMMAND}}", &html_escape(&auth.login_command))
            .replace("{{ERR}}", &err)
            .replace("{{NEXT}}", &html_escape(&sanitize_next(next))),
    )
}

#[derive(Deserialize)]
struct LoginQuery {
    next: Option<String>,
    check: Option<u8>,
}

async fn login_page(
    State(auth): State<HttpAuth>,
    Query(query): Query<LoginQuery>,
    headers: HeaderMap,
) -> Response {
    let next = sanitize_next(query.next.as_deref().unwrap_or("/"));
    if cookie_value(&headers, SESSION_COOKIE)
        .and_then(|token| auth.inner.secrets.verify_token(token, SystemTime::now()))
        .is_some()
    {
        let mut response = Redirect::to(&next).into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return response;
    }
    let error = if query.check == Some(1) {
        Some(
            "Sign-in succeeded, but the browser did not return a valid session cookie. Allow cookies for this site and try again.",
        )
    } else {
        None
    };
    let mut response = login_html(&auth, &next, error).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[derive(Deserialize)]
struct LoginForm {
    key: String,
    #[serde(default)]
    next: String,
}

async fn login_submit(State(auth): State<HttpAuth>, Form(form): Form<LoginForm>) -> Response {
    if auth.too_many_failures() {
        let mut response = login_html(
            &auth,
            &form.next,
            Some("Too many failed logins. Wait a minute and try again."),
        )
        .into_response();
        *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return response;
    }
    match auth.inner.secrets.verify_api_key(form.key.trim()) {
        Some(id) => {
            let token = auth
                .inner
                .secrets
                .issue_token(&id, auth.inner.ttl, SystemTime::now());
            let cookie = auth.session_cookie(&token, auth.inner.ttl.as_secs());
            // Verify cookie acceptance before entering the application, so a
            // rejected cookie produces an error instead of a silent login loop.
            let mut response = Redirect::to(&format!(
                "{LOGIN_PATH}?next={}&check=1",
                percent_encode(&sanitize_next(&form.next))
            ))
            .into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            if let Ok(value) = HeaderValue::from_str(&cookie) {
                response.headers_mut().insert(header::SET_COOKIE, value);
            }
            response
        }
        None => {
            auth.record_failure();
            tokio::time::sleep(auth.inner.fail_delay).await;
            let mut response = login_html(&auth, &form.next, Some("Invalid API key. Paste the full ID:SECRET output of the command above; an application password will not work here.")).into_response();
            *response.status_mut() = StatusCode::UNAUTHORIZED;
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
    }
}

async fn logout(State(auth): State<HttpAuth>) -> Response {
    let mut response = Redirect::to(LOGIN_PATH).into_response();
    if let Ok(value) = HeaderValue::from_str(&auth.session_cookie("", 0)) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master(byte: u8) -> MasterSecret {
        MasterSecret::from_bytes([byte; 32])
    }

    fn secrets() -> Secrets {
        Secrets::from_master(&master(1))
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn auth(mode: AuthMode) -> HttpAuth {
        HttpAuth::new(secrets(), mode, &HttpAuthConfig::default(), false)
    }

    #[test]
    fn base64_round_trips_and_accepts_both_alphabets() {
        for data in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"\xff\xfe\xfd\xfc\xfb",
        ] {
            assert_eq!(b64_decode(&b64_encode(data)).unwrap(), data);
        }
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"f"), "Zg");
        // Standard alphabet and padding, as Basic auth sends it.
        assert_eq!(b64_decode("+/8=").unwrap(), [0xfb, 0xff]);
        assert_eq!(b64_decode("-_8").unwrap(), [0xfb, 0xff]);
        assert!(b64_decode("a").is_none());
        assert!(b64_decode("a b").is_none());
    }

    /// Computed with Python's `hmac` from the master secret 00 01 .. 1f. If
    /// this fails, every API key already issued stops working.
    #[test]
    fn issued_keys_are_frozen() {
        let master = MasterSecret::from_bytes(std::array::from_fn(|i| i as u8));
        let s = Secrets::from_master(&master);
        assert_eq!(
            s.api_key("alice").unwrap(),
            "alice:NhVTYRFnloorwXLWAb5wbgl2A9MljFS8Aha27M6J7AQ"
        );
        assert_eq!(
            s.verify_api_key("alice:NhVTYRFnloorwXLWAb5wbgl2A9MljFS8Aha27M6J7AQ")
                .as_deref(),
            Some("alice")
        );
    }

    #[test]
    fn api_keys_are_derived_not_stored() {
        let s = secrets();
        let key = s.api_key("alice@example.m").unwrap();
        assert_eq!(key, secrets().api_key("alice@example.m").unwrap());
        assert_eq!(s.verify_api_key(&key).as_deref(), Some("alice@example.m"));
        // Another master secret gives other keys.
        let other = Secrets::from_master(&master(2));
        assert!(other.verify_api_key(&key).is_none());
        assert_ne!(other.api_key("alice@example.m").unwrap(), key);
        // A key is for its ID only, and any change breaks it.
        let (_, secret) = key.split_once(':').unwrap();
        assert!(s.verify_api_key(&format!("bob:{secret}")).is_none());
        assert!(
            s.verify_api_key(&format!("alice@example.m:{secret}x"))
                .is_none()
        );
        assert!(s.verify_api_key("alice@example.m:").is_none());
        assert!(s.verify_api_key("no-colon").is_none());
        // The same pair is a user name and password.
        assert!(s.verify_password("alice@example.m", secret));
        assert!(!s.verify_password("alice@example.m", "wrong"));
        // IDs are restricted.
        for bad in ["", "a:b", "a b", &"x".repeat(65), "a/b"] {
            assert!(s.api_key(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn non_expiring_sessions_remain_signed_and_split_cookies_authenticate() {
        let s = secrets();
        let token = s.issue_token("alice", Duration::ZERO, at(1000));
        assert_eq!(
            s.verify_token(&token, at(10_000_000_000)).as_deref(),
            Some("alice")
        );
        assert!(
            Secrets::from_master(&master(2))
                .verify_token(&token, at(1000))
                .is_none()
        );
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, HeaderValue::from_static("app=value"));
        headers.append(
            header::COOKIE,
            HeaderValue::from_str(&format!("{SESSION_COOKIE}={token}")).unwrap(),
        );
        assert_eq!(
            auth(AuthMode::Login)
                .authenticate(&headers, at(1000))
                .unwrap()
                .name,
            "alice"
        );
    }

    #[test]
    fn session_tokens_expire_and_resist_forgery() {
        let s = secrets();
        let token = s.issue_token("alice", Duration::from_secs(60), at(1000));
        assert_eq!(s.verify_token(&token, at(1000)).as_deref(), Some("alice"));
        assert_eq!(s.verify_token(&token, at(1059)).as_deref(), Some("alice"));
        assert!(s.verify_token(&token, at(1060)).is_none(), "expired");
        assert!(
            Secrets::from_master(&master(2))
                .verify_token(&token, at(1000))
                .is_none()
        );

        // A changed payload does not verify.
        let parts: Vec<&str> = token.split('.').collect();
        let forged = b64_encode(br#"{"sub":"root","iat":0,"exp":99999999999}"#);
        assert!(
            s.verify_token(&format!("{}.{forged}.{}", parts[0], parts[2]), at(1000))
                .is_none()
        );
        // alg none, and other algorithms, are refused even with a valid signature input.
        for alg in ["none", "HS512", "RS256"] {
            let head = b64_encode(format!(r#"{{"alg":"{alg}","typ":"JWT"}}"#).as_bytes());
            let input = format!("{head}.{}", parts[1]);
            let sig = b64_encode(hmac::sign(&s.session, input.as_bytes()).as_ref());
            assert!(
                s.verify_token(&format!("{input}.{sig}"), at(1000))
                    .is_none(),
                "{alg}"
            );
            assert!(
                s.verify_token(&format!("{input}."), at(1000)).is_none(),
                "{alg}"
            );
        }
        for junk in ["", "a.b", "a.b.c.d", "...", "x.y.z"] {
            assert!(s.verify_token(junk, at(1000)).is_none(), "{junk:?}");
        }
        // An API key is not a token, and the keys are separate.
        let key = s.api_key("alice").unwrap();
        assert!(s.verify_token(&key, at(1000)).is_none());
    }

    #[test]
    fn credentials_from_every_carrier() {
        let a = auth(AuthMode::ApiKey);
        let s = secrets();
        let key = s.api_key("alice").unwrap();
        let token = s.issue_token("alice", Duration::from_secs(60), at(1000));
        let with = |name: &'static str, value: String| {
            let mut h = HeaderMap::new();
            h.insert(name, HeaderValue::from_str(&value).unwrap());
            h
        };
        let basic = format!("Basic {}", b64_encode(key.as_bytes()));
        let cases = [
            ("authorization", format!("Bearer {key}"), AuthMethod::ApiKey),
            ("authorization", format!("bearer {key}"), AuthMethod::ApiKey),
            ("authorization", basic, AuthMethod::ApiKey),
            (
                "authorization",
                format!("Bearer {token}"),
                AuthMethod::Session,
            ),
            ("x-api-key", key.clone(), AuthMethod::ApiKey),
            (
                "cookie",
                format!("a=b; {SESSION_COOKIE}={token}; c=d"),
                AuthMethod::Session,
            ),
        ];
        for (name, value, method) in cases {
            let id = a.authenticate(&with(name, value.clone()), at(1000));
            assert_eq!(
                id,
                Some(Identity {
                    name: "alice".into(),
                    method
                }),
                "{name}: {value}"
            );
        }
        for (name, value) in [
            ("authorization", "Bearer nonsense".to_string()),
            ("authorization", "Basic !!!".to_string()),
            ("authorization", format!("Digest {key}")),
            ("x-api-key", "alice:wrong".to_string()),
            ("cookie", format!("{SESSION_COOKIE}=nonsense")),
            ("cookie", format!("other={token}")),
        ] {
            assert_eq!(
                a.authenticate(&with(name, value.clone()), at(1000)),
                None,
                "{value}"
            );
        }
        assert_eq!(a.authenticate(&HeaderMap::new(), at(1000)), None);
        // The cookie token expires.
        assert_eq!(
            a.authenticate(
                &with("cookie", format!("{SESSION_COOKIE}={token}")),
                at(2000)
            ),
            None
        );
    }

    #[test]
    fn redirect_targets_stay_on_this_site() {
        for ok in ["/", "/_m/adm/", "/a?b=1&c=%2F", "/x#y"] {
            assert_eq!(sanitize_next(ok), ok);
        }
        for bad in [
            "",
            "x",
            "//evil.example",
            "/\\evil.example",
            "http://evil.example/",
            "javascript:alert(1)",
            "/a\r\nSet-Cookie: x=y",
            "/a b",
            "/_m/login",
            "/_m/login?next=%2F",
            "/_m/logout",
            &format!("/{}", "x".repeat(2100)),
        ] {
            assert_eq!(sanitize_next(bad), "/", "{bad:?}");
        }
        assert_eq!(
            percent_encode("/_m/x?a=1&b=é"),
            "%2F_m%2Fx%3Fa%3D1%26b%3D%C3%A9"
        );
        assert_eq!(
            html_escape(r#""><script>&"#),
            "&quot;&gt;&lt;script&gt;&amp;"
        );
    }

    #[test]
    fn exempt_paths() {
        let a = auth(AuthMode::Login);
        for p in [
            "/.well-known/acme-challenge/tok",
            "/.well-known/openid-configuration",
            "/_m/login",
            "/_m/logout",
            "/_m/_ssh",
            "/_m/_ssh/x",
            "/_m/_ws/_ssh",
        ] {
            assert!(a.is_exempt(p), "{p}");
        }
        for p in [
            "/",
            "/_m/adm/",
            "/_m/_exec/ls",
            "/_m/_sshx",
            "/_m/loginx",
            "/.well-known-other/metadata",
            "/a/_m/login",
        ] {
            assert!(!a.is_exempt(p), "{p}");
        }
        let config = HttpAuthConfig {
            exempt: vec!["/public/".into(), "/status".into()],
            ..Default::default()
        };
        let a = HttpAuth::new(secrets(), AuthMode::Login, &config, false);
        assert!(a.is_exempt("/public/x"));
        assert!(a.is_exempt("/status"));
        assert!(a.is_exempt("/status/detail"));
        assert!(!a.is_exempt("/statuses"));
    }

    #[test]
    fn config_modes_per_listener() {
        let config: HttpAuthConfig = serde_json::from_str(
            r#"{"default":"login","listeners":{"admin":"apikey","http":"none"}}"#,
        )
        .unwrap();
        assert_eq!(config.mode_for("admin"), AuthMode::ApiKey);
        assert_eq!(config.mode_for("http"), AuthMode::None);
        assert_eq!(config.mode_for("https"), AuthMode::Login);
        assert_eq!(
            HttpAuthConfig::default().mode_for("anything"),
            AuthMode::None
        );
        assert_eq!(HttpAuthConfig::default().session_ttl_secs, 0);
    }
}
