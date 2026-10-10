//! Regression: the gateway must not outlive its session. A `tokio::spawn`ed listener used to run
//! forever holding `Arc<Vault>`; `Gateway::shutdown` revokes every token (in-flight requests stop
//! at the next epoch check) and aborts the listener, taking its connection tasks with it.

use kv_protocols::http::allow_insecure_loopback_for_tests;
use kv_proxy::gateway::Gateway;
use kv_proxy::manage::{configure_http, ConfigureHttpParams};
use kv_vault::{SetParams, Vault};
use serde_json::json;
use std::sync::Arc;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct AlwaysApprove;
impl kv_platform::Confirmer for AlwaysApprove {
    async fn confirm(&self, _message: &str, _ok_label: &str) -> bool {
        true
    }
}

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

async fn new_gateway_with_credential(
    _server: &MockServer,
    api_key: &str,
) -> (tempfile::TempDir, Arc<Vault>, Gateway) {
    let tmp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::new(tmp.path().join("vault")));
    vault.prepare().unwrap();
    if !vault.dir.join("master.key").exists() {
        std::fs::write(vault.dir.join("master.key"), [7u8; 32]).unwrap();
        std::fs::set_permissions(
            vault.dir.join("master.key"),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .unwrap();
    }
    vault.init_legacy().unwrap();
    vault
        .set(SetParams {
            r#type: "api_key".into(),
            name: "svc".into(),
            value: Some(api_key.into()),
            ..Default::default()
        })
        .unwrap();
    let inject = json!({"headers": {"Authorization": "Bearer {{value}}"}});
    configure_http(
        &vault,
        ConfigureHttpParams {
            r#type: "api_key",
            name: "svc",
            purpose: "test",
            remove: false,
            inject: Some(&inject),
            allowed_hosts: Some(&json!(["127.0.0.1"])),
            proxy_only: None,
            test: None,
        },
        &AlwaysApprove,
    )
    .await
    .unwrap();
    let gateway = Gateway::new(vault.clone(), Arc::new(|_| {}), None);
    (tmp, vault, gateway)
}

#[tokio::test]
async fn shutdown_revokes_tokens_and_closes_the_listener() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/models"))
        .and(header("authorization", "Bearer sk-live"))
        .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
        .mount(&server)
        .await;

    let (_tmp, _vault, gateway) = new_gateway_with_credential(&server, "sk-live").await;
    let open = gateway.open("api_key", "svc", None).await.unwrap();
    let client = reqwest::Client::new();
    let url = format!(
        "{}/127.0.0.1:{}/v1/models",
        open.base,
        server.address().port()
    );

    let ok = client
        .get(&url)
        .header("authorization", format!("Bearer {}", open.token))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);

    gateway.shutdown();

    // The token is revoked: an already-connected client gets 401/connection refused.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let after = client
        .get(&url)
        .header("authorization", format!("Bearer {}", open.token))
        .send()
        .await;
    if let Ok(resp) = after {
        assert_eq!(resp.status(), 401, "revoked token must not be served");
    } // connection refused (listener aborted) is also correct

    // And the port must not accept fresh connections at all.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let refused = std::net::TcpStream::connect(format!("127.0.0.1:{}", open.port));
    assert!(
        refused.is_err(),
        "the listener must be closed after shutdown"
    );
}
