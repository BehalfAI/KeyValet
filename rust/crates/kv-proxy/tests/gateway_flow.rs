//! End-to-end tests against a real listening gateway server: a client that only speaks HTTP (no
//! MCP, no vault access) sends the gateway token as its API key and gets the upstream's response,
//! with the real credential injected and the response redacted -- mirroring how an SDK or script
//! would actually use `credential_gateway`.

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
        // Explicit legacy fixture: production code never creates this file.
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
async fn a_bearer_token_client_gets_the_upstream_response_with_the_real_credential_injected() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, _vault, gateway) = new_gateway_with_credential(&server, "sk-real-secret-999").await;

    Mock::given(method("GET"))
        .and(path("/v1/ping"))
        .and(header("authorization", "Bearer sk-real-secret-999"))
        .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
        .expect(1)
        .mount(&server)
        .await;

    let opened = gateway.open("api_key", "svc", Some("test")).await.unwrap();
    let client = reqwest::Client::new();
    let upstream_host = format!("127.0.0.1:{}", server.address().port());
    let resp = client
        .get(format!("{}/{upstream_host}/v1/ping", opened.base))
        .bearer_auth(&opened.token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "pong");
}

#[tokio::test]
async fn a_request_without_the_gateway_token_is_rejected() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, _vault, gateway) = new_gateway_with_credential(&server, "sk-real-secret-999").await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let opened = gateway.open("api_key", "svc", Some("test")).await.unwrap();
    let client = reqwest::Client::new();
    let upstream_host = format!("127.0.0.1:{}", server.address().port());
    let resp = client
        .get(format!("{}/{upstream_host}/v1/ping", opened.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn a_request_claiming_a_foreign_host_header_is_rejected_as_misdirected() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, _vault, gateway) = new_gateway_with_credential(&server, "sk-real-secret-999").await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let opened = gateway.open("api_key", "svc", Some("test")).await.unwrap();
    let client = reqwest::Client::new();
    let upstream_host = format!("127.0.0.1:{}", server.address().port());
    let resp = client
        .get(format!("{}/{upstream_host}/v1/ping", opened.base))
        .bearer_auth(&opened.token)
        .header("host", "evil.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 421);
}

#[tokio::test]
async fn a_browser_style_request_carrying_sec_fetch_site_is_rejected() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, _vault, gateway) = new_gateway_with_credential(&server, "sk-real-secret-999").await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let opened = gateway.open("api_key", "svc", Some("test")).await.unwrap();
    let client = reqwest::Client::new();
    let upstream_host = format!("127.0.0.1:{}", server.address().port());
    let resp = client
        .get(format!("{}/{upstream_host}/v1/ping", opened.base))
        .bearer_auth(&opened.token)
        .header("sec-fetch-site", "cross-site")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn a_secret_echoed_back_in_the_response_is_redacted_end_to_end() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, _vault, gateway) = new_gateway_with_credential(&server, "sk-real-secret-999").await;

    Mock::given(method("GET"))
        .and(path("/v1/echo"))
        .respond_with(|req: &wiremock::Request| {
            let auth = req
                .headers
                .get("authorization")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            ResponseTemplate::new(200).set_body_json(json!({"you_sent": auth}))
        })
        .expect(1)
        .mount(&server)
        .await;

    let opened = gateway.open("api_key", "svc", Some("test")).await.unwrap();
    let client = reqwest::Client::new();
    let upstream_host = format!("127.0.0.1:{}", server.address().port());
    let resp = client
        .get(format!("{}/{upstream_host}/v1/echo", opened.base))
        .bearer_auth(&opened.token)
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();
    assert!(!body.contains("sk-real-secret-999"));
    assert!(body.contains("[REDACTED]"));
}

#[tokio::test]
async fn a_host_outside_the_credentials_allowlist_is_rejected_before_any_request_is_sent() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, _vault, gateway) = new_gateway_with_credential(&server, "sk-real-secret-999").await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let opened = gateway.open("api_key", "svc", Some("test")).await.unwrap();
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/evil.example.com/steal", opened.base))
        .bearer_auth(&opened.token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn revoking_gateway_tokens_rejects_subsequent_requests() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, _vault, gateway) = new_gateway_with_credential(&server, "synthetic-key").await;
    let entry = gateway.open("api_key", "svc", Some("test")).await.unwrap();
    gateway.revoke_all();
    let response = reqwest::Client::new()
        .get(format!("{}/{}/resource", entry.base, server.address()))
        .bearer_auth(entry.token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert!(server.received_requests().await.unwrap().is_empty());
}
