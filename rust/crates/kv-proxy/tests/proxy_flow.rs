// Unix-only for now: these tests assert POSIX mode bits / unix-specific behaviors. The Windows
// equivalents (DACLs) land with W2/W3; the crate itself builds cross-platform.
#![cfg(unix)]
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

#[tokio::test]
async fn network_errors_exclude_the_url_with_injected_short_query_secrets() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, vault) = new_vault();
    setup_static_credential(&vault, &server, "xy").await;
    let inject = json!({"query":{"api_key":"{{value}}"}});
    configure_http(
        &vault,
        ConfigureHttpParams {
            r#type: "api_key",
            name: "svc",
            purpose: "test query error redaction",
            remove: false,
            inject: Some(&inject),
            allowed_hosts: None,
            proxy_only: None,
            test: None,
        },
        &AlwaysApprove,
    )
    .await
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        use tokio::io::AsyncReadExt;
        stream.read_exact(&mut [0u8; 1]).await.unwrap();
        // Close without sending HTTP headers, producing a real reqwest error with a URL.
    });
    let error = proxy_request(
        &vault,
        "api_key",
        "svc",
        ProxyInput {
            url: format!("http://{address}/private-route"),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    peer.await.unwrap();
    assert!(!error.0.contains("api_key="), "{}", error.0);
    assert!(!error.0.contains("/private-route"), "{}", error.0);
    assert!(!error.0.contains("xy"), "{}", error.0);
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
    assert_eq!(
        out.body, "[REDACTED]",
        "raw SSE must not expose reconstructable secret fragments"
    );
    let stream = out
        .stream
        .expect("an event-stream response must be recognized as such");
    assert_eq!(stream.text.as_deref(), Some("key is [REDACTED] ok"));
}

#[tokio::test]
async fn unicode_escaped_sse_secrets_are_not_returned_in_raw_events() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, vault) = new_vault();
    setup_static_credential(&vault, &server, "sk-real-secret-999").await;
    let sse = "data: {\"choices\":[{\"delta\":{\"content\":\"key is \\u0073k-real-secret-999 ok\"}}]}\n\n";
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(sse, "text/event-stream"))
        .mount(&server)
        .await;
    let out = proxy_request(
        &vault,
        "api_key",
        "svc",
        ProxyInput {
            method: Some("GET".into()),
            url: server.uri(),
            headers: Default::default(),
            query: Default::default(),
            body: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(out.body, "[REDACTED]");
    assert_eq!(
        out.stream.unwrap().text.as_deref(),
        Some("key is [REDACTED] ok")
    );
}
