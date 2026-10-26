//! HTTP authentication at the gateway: modes, credentials, the login page and
//! the session cookie, against a served router.

use std::time::Duration;

use axum::{Extension, Router, routing::get};
use reqwest::{Client, StatusCode, redirect::Policy};
use ssh_mesh::auth::MasterSecret;
use ssh_mesh::httpauth::{AuthMode, HttpAuth, HttpAuthConfig, Identity, Secrets};

fn secrets() -> Secrets {
    Secrets::from_master(&MasterSecret::from_bytes([7; 32]))
}

fn client() -> Client {
    Client::builder().redirect(Policy::none()).build().unwrap()
}

/// A router with a protected page, an exempt ACME path, an exempt SSH entry
/// point, and an echo of the authenticated identity.
fn app() -> Router {
    Router::new()
        .route("/_m/secret", get(|| async { "secret" }))
        .route("/_m/_exec/ls", get(|| async { "exec" }))
        .route("/_m/_ssh", get(|| async { "ssh" }))
        .route("/.well-known/acme-challenge/tok", get(|| async { "tok" }))
        .route(
            "/.well-known/openid-configuration",
            get(|| async { "metadata" }),
        )
        .route("/.well-known-other/metadata", get(|| async { "private" }))
        .route(
            "/_m/whoami",
            get(|Extension(id): Extension<Identity>| async move { format!("{}", id.name) }),
        )
}

async fn serve(mode: AuthMode, secure_cookie: bool) -> String {
    let auth = HttpAuth::new(secrets(), mode, &HttpAuthConfig::default(), secure_cookie)
        .with_fail_delay(Duration::ZERO);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = auth.apply(app());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{addr}")
}

const HTML: &str = "text/html,application/xhtml+xml";

#[tokio::test]
async fn mode_none_checks_nothing_and_has_no_login_page() {
    let base = serve(AuthMode::None, false).await;
    let c = client();
    assert_eq!(
        c.get(format!("{base}/_m/secret"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        c.get(format!("{base}/_m/login"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}

#[tokio::test]
async fn apikey_mode_accepts_every_carrier_and_exempts_some_paths() {
    let base = serve(AuthMode::ApiKey, false).await;
    let c = client();
    let key = secrets().api_key("alice").unwrap();
    let (user, password) = key.split_once(':').unwrap();

    let res = c.get(format!("{base}/_m/secret")).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let challenges: Vec<_> = res.headers().get_all("www-authenticate").iter().collect();
    assert_eq!(challenges.len(), 2, "Bearer and Basic");

    let url = format!("{base}/_m/whoami");
    let ok = |req: reqwest::RequestBuilder| async move {
        let res = req.send().await.unwrap();
        (res.status(), res.text().await.unwrap())
    };
    for (name, req) in [
        ("bearer", c.get(&url).bearer_auth(&key)),
        ("basic", c.get(&url).basic_auth(user, Some(password))),
        ("x-api-key", c.get(&url).header("x-api-key", &key)),
    ] {
        assert_eq!(
            ok(req).await,
            (StatusCode::OK, "alice".to_string()),
            "{name}"
        );
    }
    for req in [
        c.get(&url).bearer_auth("alice:wrong"),
        c.get(&url).basic_auth("alice", Some("wrong")),
        c.get(&url).bearer_auth("nonsense"),
    ] {
        assert_eq!(req.send().await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }

    for path in [
        "/.well-known/acme-challenge/tok",
        "/.well-known/openid-configuration",
        "/_m/_ssh",
    ] {
        assert_eq!(
            c.get(format!("{base}{path}"))
                .send()
                .await
                .unwrap()
                .status(),
            200,
            "{path}"
        );
    }
    assert_eq!(
        c.get(format!("{base}/_m/_exec/ls"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        c.get(format!("{base}/.well-known-other/metadata"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // Browsers get 401 in this mode, not a redirect.
    let res = c
        .get(format!("{base}/_m/secret"))
        .header("accept", HTML)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_mode_redirects_browsers_and_sets_a_session_cookie() {
    let base = serve(AuthMode::Login, false).await;
    let c = client();
    let key = secrets().api_key("alice").unwrap();

    // A browser navigation is sent to the login page, remembering where to return.
    let res = c
        .get(format!("{base}/_m/secret?a=1"))
        .header("accept", HTML)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        res.headers()["location"],
        "/_m/login?next=%2F_m%2Fsecret%3Fa%3D1"
    );
    // Other clients get 401, and a POST is never redirected.
    let res = c.get(format!("{base}/_m/secret")).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let res = c
        .post(format!("{base}/_m/secret"))
        .header("accept", HTML)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // The login page shows the (escaped) return path.
    let res = c
        .get(format!("{base}/_m/login?next=%2F%22%3E%3Cb%3E"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let page = res.text().await.unwrap();
    assert!(page.contains("name=\"key\""));
    assert!(!page.contains("<b>"), "next is escaped");

    // A wrong key is refused and sets nothing.
    let res = c
        .post(format!("{base}/_m/login"))
        .form(&[("key", "alice:wrong"), ("next", "/_m/secret")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert!(res.headers().get("set-cookie").is_none());

    // The right key sets the cookie and returns to the page.
    let res = c
        .post(format!("{base}/_m/login"))
        .form(&[("key", key.as_str()), ("next", "/_m/secret")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers()["location"], "/_m/secret");
    let cookie = res.headers()["set-cookie"].to_str().unwrap().to_owned();
    for attr in [
        "mesh_session=",
        "HttpOnly",
        "SameSite=Strict",
        "Path=/",
        "Max-Age=43200",
    ] {
        assert!(cookie.contains(attr), "{attr} in {cookie}");
    }
    assert!(!cookie.contains("Secure"), "plain listener");
    let session = cookie.split(';').next().unwrap().to_owned();

    // The cookie is equivalent to the Authorization header.
    let res = c
        .get(format!("{base}/_m/whoami"))
        .header("cookie", &session)
        .send()
        .await
        .unwrap();
    assert_eq!(
        (res.status(), res.text().await.unwrap()),
        (StatusCode::OK, "alice".into())
    );
    let res = c
        .get(format!("{base}/_m/secret"))
        .header("cookie", "mesh_session=forged")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Logout clears it.
    let res = c.get(format!("{base}/_m/logout")).send().await.unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let cleared = res.headers()["set-cookie"].to_str().unwrap();
    assert!(
        cleared.contains("mesh_session=;") && cleared.contains("Max-Age=0"),
        "{cleared}"
    );
}

#[tokio::test]
async fn login_never_redirects_to_another_site() {
    let base = serve(AuthMode::Login, false).await;
    let key = secrets().api_key("alice").unwrap();
    for next in [
        "//evil.example",
        "https://evil.example/",
        "/\\evil.example",
        "",
    ] {
        let res = client()
            .post(format!("{base}/_m/login"))
            .form(&[("key", key.as_str()), ("next", next)])
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER, "{next:?}");
        assert_eq!(res.headers()["location"], "/", "{next:?}");
    }
}

#[tokio::test]
async fn tls_listeners_set_secure_cookies() {
    let base = serve(AuthMode::Login, true).await;
    let key = secrets().api_key("alice").unwrap();
    let res = client()
        .post(format!("{base}/_m/login"))
        .form(&[("key", key.as_str())])
        .send()
        .await
        .unwrap();
    assert!(
        res.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .ends_with("; Secure")
    );
}

#[tokio::test]
async fn repeated_failed_logins_are_limited() {
    let base = serve(AuthMode::Login, false).await;
    let c = client();
    let bad = |c: &Client| {
        c.post(format!("{base}/_m/login"))
            .form(&[("key", "alice:wrong")])
            .send()
    };
    for _ in 0..10 {
        assert_eq!(bad(&c).await.unwrap().status(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        bad(&c).await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    // A correct key is refused too while limited: no oracle for guessing.
    let key = secrets().api_key("alice").unwrap();
    let res = c
        .post(format!("{base}/_m/login"))
        .form(&[("key", key.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
}

/// The key printed by `meshkeys apikey` is the one the running server
/// derives from the same master secret file: nothing is stored between them.
#[test]
fn meshkeys_apikey_matches_the_servers_derivation() {
    let dir = tempfile::tempdir().unwrap();
    // What ssh-mesh does at start: generate and save the master secret.
    let server = Secrets::from_master(&MasterSecret::load_or_generate(dir.path()).unwrap());

    let run = |id: &str| {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_meshkeys"))
            .args(["apikey", id, "--keydir"])
            .arg(dir.path())
            .output()
            .unwrap();
        (out.status.success(), String::from_utf8(out.stdout).unwrap())
    };
    let (ok, printed) = run("alice@example.m");
    assert!(ok);
    assert_eq!(printed.trim(), server.api_key("alice@example.m").unwrap());
    assert_eq!(
        server.verify_api_key(printed.trim()).as_deref(),
        Some("alice@example.m")
    );

    // A restart loads the secret from the file and derives the same keys.
    let reloaded = Secrets::from_master(&MasterSecret::load_or_generate(dir.path()).unwrap());
    assert_eq!(
        reloaded.verify_api_key(printed.trim()).as_deref(),
        Some("alice@example.m")
    );
    // The SSH host key is not involved: replacing it changes nothing.
    ssh_mesh::auth::load_or_generate_keys_save(dir.path());
    std::fs::remove_file(dir.path().join("id_ecdsa")).unwrap();
    ssh_mesh::auth::load_or_generate_keys_save(dir.path());
    assert_eq!(run("alice@example.m").1.trim(), printed.trim());

    // A bad ID is refused, and a missing secret is not created by the tool.
    assert!(!run("bad id").0);
    let empty = tempfile::tempdir().unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_meshkeys"))
        .args(["apikey", "alice", "--keydir"])
        .arg(empty.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no master secret"));
    assert!(!MasterSecret::path(empty.path()).exists());
}
