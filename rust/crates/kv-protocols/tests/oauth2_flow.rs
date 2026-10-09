//! End-to-end OAuth2 flow tests against a real (mock) HTTP server via `wiremock` -- not just
//! validation-logic unit tests, but the actual token-exchange/refresh/device-code network paths.

use kv_protocols::http::allow_insecure_loopback_for_tests;
use kv_protocols::index::{access_token, setup_protocol, AccessTokenParams, SetupProtocolParams};
use kv_protocols::oauth2::{device_poll, device_start, exchange_code, DevicePollResult};
use kv_vault::{Kind, Vault};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// `allow_insecure_loopback_for_tests` flips a crate-global flag; tests in this file run on
// separate OS threads in parallel by default, so they'd otherwise race on it. Serialize access.
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

async fn setup(vault: &Vault, server: &MockServer, extra_config: serde_json::Value) {
    let mut config = json!({
        "client_id": "client-123",
        "token_url": format!("http://{}/token", server.address()),
        "authorization_url": format!("http://{}/auth", server.address()),
    });
    kv_merge(&mut config, extra_config);
    setup_protocol(
        vault,
        SetupProtocolParams {
            r#type: "oauth2".into(),
            name: "svc".into(),
            kind: Kind::Oauth2,
            config,
            secrets: json!({"client_secret": "s3cret-enough-chars"}),
            description: None,
            type_description: None,
            overwrite: false,
            reuse_client_secret: false,
        },
    )
    .unwrap();
}

fn kv_merge(base: &mut serde_json::Value, extra: serde_json::Value) {
    if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            b.insert(k.clone(), v.clone());
        }
    }
}

#[tokio::test]
async fn authorization_code_exchange_then_cached_then_refresh() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, vault) = new_vault();
    setup(&vault, &server, json!({})).await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "at-1", "refresh_token": "rt-1", "token_type": "Bearer", "expires_in": 3600, "scope": "read"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let result = exchange_code(
        &vault,
        "oauth2",
        "svc",
        "the-code",
        "verifier",
        &json!("http://127.0.0.1:9999/callback"),
    )
    .await
    .unwrap();
    assert_eq!(result["refresh_token"], true);
    assert_eq!(result["scope"], "read");

    server.reset().await;
    // Cached access token: a second call must NOT hit the network at all (no mock registered now).
    let out = access_token(
        &vault,
        "oauth2",
        "svc",
        AccessTokenParams {
            scopes: vec![],
            repositories: vec![],
            permissions: None,
            force: false,
            via_proxy: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(out["access_token"], "at-1");

    // Force a refresh: must use the refresh token, not the authorization code.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"access_token": "at-2", "token_type": "Bearer", "expires_in": 3600}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    let out2 = access_token(
        &vault,
        "oauth2",
        "svc",
        AccessTokenParams {
            scopes: vec![],
            repositories: vec![],
            permissions: None,
            force: true,
            via_proxy: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(out2["access_token"], "at-2");
}

#[tokio::test]
async fn invalid_grant_on_refresh_marks_needs_reauth() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, vault) = new_vault();
    setup(&vault, &server, json!({})).await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"access_token": "at-1", "refresh_token": "rt-1", "expires_in": 1}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    exchange_code(
        &vault,
        "oauth2",
        "svc",
        "code",
        "verifier",
        &json!("http://127.0.0.1:9999/callback"),
    )
    .await
    .unwrap();

    server.reset().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_grant"})))
        .mount(&server)
        .await;
    let err = access_token(
        &vault,
        "oauth2",
        "svc",
        AccessTokenParams {
            scopes: vec![],
            repositories: vec![],
            permissions: None,
            force: true,
            via_proxy: false,
        },
    )
    .await
    .unwrap_err();
    assert!(err.0.contains("重新授权") || err.0.contains("re-authorize"));

    let (_, _, record) = vault.get_record("oauth2", "svc").unwrap();
    assert_eq!(
        kv_protocols::oauth2::public_state(&record)["needs_reauth"],
        true
    );
}

#[tokio::test]
async fn device_code_flow_pending_then_done() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, vault) = new_vault();
    setup(&vault, &server, json!({"flow": "device_code", "device_authorization_url": format!("http://{}/device", server.address())})).await;

    Mock::given(method("POST"))
        .and(path("/device"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"device_code": "dc-1", "user_code": "ABCD-EFGH", "verification_uri": "https://example.com/verify", "interval": 1, "expires_in": 600})))
        .mount(&server)
        .await;
    let start = device_start(&vault, "oauth2", "svc").await.unwrap();
    assert_eq!(start.user_code, "ABCD-EFGH");

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(json!({"error": "authorization_pending"})),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    let pending = device_poll(&vault, "oauth2", "svc", &start.device_code)
        .await
        .unwrap();
    assert!(matches!(pending, DevicePollResult::Pending));

    server.reset().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"access_token": "at-device", "expires_in": 3600})),
        )
        .mount(&server)
        .await;
    let done = device_poll(&vault, "oauth2", "svc", &start.device_code)
        .await
        .unwrap();
    assert!(matches!(done, DevicePollResult::Done { .. }));
}
