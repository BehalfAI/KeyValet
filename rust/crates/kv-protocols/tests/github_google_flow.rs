// Unix-only for now: these tests assert POSIX mode bits / unix-specific behaviors. The Windows
// equivalents (DACLs) land with W2/W3; the crate itself builds cross-platform.
#![cfg(unix)]
//! End-to-end token-fetch tests against a real (mock) HTTP server for GitHub App and Google
//! service account credentials.

use kv_protocols::github_app::{github_app_token, validate_github_app_setup, GitHubAppTokenParams};
use kv_protocols::google_sa::{
    service_account_token, validate_service_account_setup, ServiceAccountTokenParams,
};
use kv_protocols::http::allow_insecure_loopback_for_tests;
use kv_vault::{Kind, SetProtocolParams, Vault};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// `allow_insecure_loopback_for_tests` flips a crate-global flag; tests in this file run on
// separate OS threads in parallel by default, so they'd otherwise race on it (one test's `false`
// at teardown landing while another is still mid-flight). Serialize access to it here.
static LOOPBACK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn with_insecure_loopback() -> impl Drop {
    struct Guard<'a>(#[allow(dead_code)] std::sync::MutexGuard<'a, ()>);
    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            allow_insecure_loopback_for_tests(false);
        }
    }
    let guard = LOOPBACK_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    allow_insecure_loopback_for_tests(true);
    Guard(guard)
}

fn new_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("vault");
    let vault = Vault::new(&dir);
    vault.prepare().unwrap();
    if !vault.dir.join("master.key").exists() {
        // Explicit legacy fixture: production code never creates this file.
        std::fs::write(vault.dir.join("master.key"), [7u8; 32]).unwrap();
        std::fs::set_permissions(
            vault.dir.join("master.key"),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .unwrap();
    }
    vault.init_legacy().unwrap();
    (tmp, vault)
}

fn rsa_pem() -> String {
    use rsa::pkcs8::EncodePrivateKey;
    let key = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
    key.to_pkcs8_pem(Default::default()).unwrap().to_string()
}

#[tokio::test]
async fn github_app_fetches_and_caches_an_installation_token() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, vault) = new_vault();
    let (cfg, secrets) = validate_github_app_setup(
        &json!({"app_id": "123456", "api_base_url": format!("http://{}", server.address())}),
        &json!({"private_key": rsa_pem()}),
    )
    .unwrap();
    vault
        .set_protocol(SetProtocolParams {
            r#type: "github_app".into(),
            name: "bot".into(),
            kind: Kind::GithubApp,
            config: serde_json::to_value(&cfg).unwrap(),
            secrets,
            description: None,
            type_description: None,
            overwrite: false,
        })
        .unwrap();

    Mock::given(method("GET"))
        .and(path("/app/installations"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([{"id": 42, "account": {"login": "acme"}}])),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/app/installations/42/access_tokens"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({"token": "ghs_abc", "expires_at": "2099-01-01T00:00:00Z"})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let out = github_app_token(
        &vault,
        "github_app",
        "bot",
        GitHubAppTokenParams {
            repositories: vec![],
            permissions: None,
            force: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(out["access_token"], "ghs_abc");

    server.reset().await; // cached: the second call must not hit the network again
    let out2 = github_app_token(
        &vault,
        "github_app",
        "bot",
        GitHubAppTokenParams {
            repositories: vec![],
            permissions: None,
            force: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(out2["access_token"], "ghs_abc");
}

#[tokio::test]
async fn github_app_narrowed_scope_is_not_cached_and_hits_the_network_every_time() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, vault) = new_vault();
    let (cfg, secrets) = validate_github_app_setup(&json!({"app_id": "123456", "installation_id": "42", "api_base_url": format!("http://{}", server.address())}), &json!({"private_key": rsa_pem()})).unwrap();
    vault
        .set_protocol(SetProtocolParams {
            r#type: "github_app".into(),
            name: "bot".into(),
            kind: Kind::GithubApp,
            config: serde_json::to_value(&cfg).unwrap(),
            secrets,
            description: None,
            type_description: None,
            overwrite: false,
        })
        .unwrap();

    Mock::given(method("POST"))
        .and(path("/app/installations/42/access_tokens"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(
                json!({"token": "ghs_narrow", "expires_at": "2099-01-01T00:00:00Z"}),
            ),
        )
        .expect(2)
        .mount(&server)
        .await;
    for _ in 0..2 {
        let out = github_app_token(
            &vault,
            "github_app",
            "bot",
            GitHubAppTokenParams {
                repositories: vec!["repo-a".into()],
                permissions: None,
                force: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(out["access_token"], "ghs_narrow");
    }
}

#[tokio::test]
async fn google_service_account_fetches_a_jwt_bearer_token() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, vault) = new_vault();
    let key_json = json!({"type": "service_account", "client_email": "sa@proj.iam.gserviceaccount.com", "private_key": rsa_pem(), "token_uri": format!("http://{}/token", server.address())}).to_string();
    let (cfg, secrets) =
        validate_service_account_setup(&json!({}), &json!({"key_json": key_json})).unwrap();
    vault
        .set_protocol(SetProtocolParams {
            r#type: "google_service_account".into(),
            name: "svc".into(),
            kind: Kind::GoogleServiceAccount,
            config: serde_json::to_value(&cfg).unwrap(),
            secrets,
            description: None,
            type_description: None,
            overwrite: false,
        })
        .unwrap();

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"access_token": "ya29.abc", "expires_in": 3600})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let out = service_account_token(
        &vault,
        "google_service_account",
        "svc",
        ServiceAccountTokenParams {
            scopes: vec![],
            force: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(out["access_token"], "ya29.abc");

    server.reset().await; // cached by scope set: no second network call
    let out2 = service_account_token(
        &vault,
        "google_service_account",
        "svc",
        ServiceAccountTokenParams {
            scopes: vec![],
            force: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(out2["access_token"], "ya29.abc");
}
