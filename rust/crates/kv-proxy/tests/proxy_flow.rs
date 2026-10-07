//! End-to-end proxy_request tests against a real (mock) HTTP server: credential injection, and
//! secret redaction in the response (including a secret that bounces back to us, and one split
//! across an SSE stream's chunk boundaries).

use kv_protocols::http::allow_insecure_loopback_for_tests;
use kv_proxy::manage::{configure_http, ConfigureHttpParams};
use kv_proxy::proxy::{proxy_request, ProxyInput};
use kv_vault::{SetParams, Vault};
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

struct AlwaysApprove;
impl kv_platform::Confirmer for AlwaysApprove {
    async fn confirm(&self, _message: &str, _ok_label: &str) -> bool {
        true
    }
}

// Tests in this file run on separate OS threads in parallel by default and all flip the same
// crate-global "allow insecure loopback" flag -- serialize them (same pattern as kv-protocols'
// tests for the same reason).
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

async fn setup_static_credential(vault: &Vault, server: &MockServer, api_key: &str) {
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
        vault,
        ConfigureHttpParams {
            r#type: "api_key",
            name: "svc",
            purpose: "test",
            remove: false,
            inject: Some(&inject),
            allowed_hosts: Some(&json!([server.address().ip().to_string()])),
            proxy_only: None,
            test: None,
        },
        &AlwaysApprove,
    )
    .await
    .unwrap();
}

fn new_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("vault");
    let vault = Vault::new(&dir);
    vault.init().unwrap();
    (tmp, vault)
}

#[tokio::test]
async fn injects_the_credential_and_the_agent_never_sees_it_in_the_request_it_sent() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, vault) = new_vault();
    setup_static_credential(&vault, &server, "sk-real-secret-999").await;

    Mock::given(method("GET"))
        .and(path("/v1/ping"))
        .and(header("authorization", "Bearer sk-real-secret-999"))
        .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
        .expect(1)
        .mount(&server)
        .await;

    // The agent's own request carries no Authorization header at all -- the helper injects it.
    let url = format!("http://{}/v1/ping", server.address());
    let out = proxy_request(
        &vault,
        "api_key",
        "svc",
        ProxyInput {
            method: Some("GET".into()),
            url,
            headers: Default::default(),
            query: Default::default(),
            body: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(out.status, 200);
    assert_eq!(out.body, "pong");
}

#[tokio::test]
async fn a_secret_echoed_back_in_the_response_is_redacted() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, vault) = new_vault();
    setup_static_credential(&vault, &server, "sk-real-secret-999").await;

    Mock::given(method("GET"))
        .and(path("/v1/echo"))
        .respond_with(|req: &Request| {
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

    let url = format!("http://{}/v1/echo", server.address());
    let out = proxy_request(
        &vault,
        "api_key",
        "svc",
        ProxyInput {
            method: Some("GET".into()),
            url,
            headers: Default::default(),
            query: Default::default(),
            body: None,
        },
    )
    .await
    .unwrap();
    assert!(
        !out.body.contains("sk-real-secret-999"),
        "the real secret must never appear in what's returned to the agent"
    );
    assert!(out.body.contains("[REDACTED]"));
}

#[tokio::test]
async fn an_agent_supplied_authorization_header_is_dropped_in_favor_of_the_injected_one() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, vault) = new_vault();
    setup_static_credential(&vault, &server, "sk-real-secret-999").await;

    Mock::given(method("GET"))
        .and(path("/v1/ping"))
        .and(header("authorization", "Bearer sk-real-secret-999"))
        .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
        .expect(1)
        .mount(&server)
        .await;

    let url = format!("http://{}/v1/ping", server.address());
    let headers = [(
        "Authorization".to_string(),
        "Bearer forged-by-agent".to_string(),
    )]
    .into();
    let out = proxy_request(
        &vault,
        "api_key",
        "svc",
        ProxyInput {
            method: Some("GET".into()),
            url,
            headers,
            query: Default::default(),
            body: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(out.status, 200, "the mock only answers 200 if it saw OUR injected header, proving the agent's forged one didn't reach it");
}

#[tokio::test]
async fn an_unlisted_host_is_rejected_before_any_request_is_sent() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, vault) = new_vault();
    setup_static_credential(&vault, &server, "sk-real-secret-999").await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let err = proxy_request(
        &vault,
        "api_key",
        "svc",
        ProxyInput {
            method: Some("GET".into()),
            url: "https://evil.example.com/steal".into(),
            headers: Default::default(),
            query: Default::default(),
            body: None,
        },
    )
    .await
    .unwrap_err();
    assert!(err.0.contains("不在") || err.0.to_lowercase().contains("not allowed"));
}

#[tokio::test]
async fn sse_deltas_split_across_two_response_chunks_still_assemble_and_redact() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, vault) = new_vault();
    setup_static_credential(&vault, &server, "sk-real-secret-999").await;

    // The secret appears split across the delta text itself (a pathological but real case: an
    // upstream that echoes part of the Authorization header back into streamed content).
    let sse_body = "data: {\"choices\":[{\"delta\":{\"content\":\"key is sk-real-\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"secret-999 ok\"}}]}\n\ndata: [DONE]\n\n";
    Mock::given(method("GET"))
        .and(path("/v1/stream"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(sse_body.as_bytes().to_vec(), "text/event-stream"),
        )
        .mount(&server)
        .await;

    let url = format!("http://{}/v1/stream", server.address());
    let out = proxy_request(
        &vault,
        "api_key",
        "svc",
        ProxyInput {
            method: Some("GET".into()),
            url,
            headers: Default::default(),
            query: Default::default(),
            body: None,
        },
    )
    .await
    .unwrap();
    let stream = out
        .stream
        .expect("an event-stream response must be recognized as such");
    assert_eq!(stream.text.as_deref(), Some("key is [REDACTED] ok"));
}
