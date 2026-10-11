// Unix-only for now: these tests assert POSIX mode bits / unix-specific behaviors. The Windows
// equivalents (DACLs) land with W2/W3; the crate itself builds cross-platform.
#![cfg(unix)]
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

#[tokio::test]
async fn dropping_the_gateway_closes_connections_and_releases_the_session_vault() {
    let server = MockServer::start().await;
    let (_tmp, vault, gateway) = new_gateway_with_credential(&server, "synthetic-secret").await;
    let weak = Arc::downgrade(&vault);
    let opened = gateway
        .open("api_key", "svc", Some("test shutdown"))
        .await
        .unwrap();
    let mut idle = tokio::net::TcpStream::connect(("127.0.0.1", opened.port))
        .await
        .unwrap();
    drop(gateway);
    drop(vault);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(tokio::net::TcpStream::connect(("127.0.0.1", opened.port))
        .await
        .is_err());
    use tokio::io::AsyncReadExt;
    let read = tokio::time::timeout(std::time::Duration::from_secs(1), idle.read(&mut [0u8; 1]))
        .await
        .unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
}

#[tokio::test]
async fn shutdown_cancels_an_upstream_request_and_prevents_reopening() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, vault, gateway) = new_gateway_with_credential(&server, "synthetic-secret").await;
    let weak = Arc::downgrade(&vault);
    Mock::given(method("GET"))
        .and(path("/slow"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(60)))
        .expect(1)
        .mount(&server)
        .await;
    let opened = gateway
        .open("api_key", "svc", Some("test shutdown"))
        .await
        .unwrap();
    let url = format!("{}/127.0.0.1:{}/slow", opened.base, server.address().port());
    let request = tokio::spawn(async move {
        reqwest::Client::new()
            .get(url)
            .bearer_auth(opened.token)
            .send()
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while server.received_requests().await.unwrap().is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), gateway.shutdown())
        .await
        .unwrap();
    assert!(gateway.open("api_key", "svc", None).await.is_err());
    let result = tokio::time::timeout(std::time::Duration::from_secs(1), request)
        .await
        .unwrap()
        .unwrap();
    // Shutdown may deliver a revocation response before closing the connection.
    if let Ok(response) = result {
        assert_eq!(response.status(), 401);
    }
    drop(gateway);
    drop(vault);
    assert!(weak.upgrade().is_none());
}

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

#[tokio::test]
async fn wildcard_host_policy_rejects_domains_without_the_label_boundary() {
    let server = MockServer::start().await;
    let (_tmp, vault, gateway) = new_gateway_with_credential(&server, "synthetic-key").await;
    configure_http(
        &vault,
        ConfigureHttpParams {
            r#type: "api_key",
            name: "svc",
            purpose: "test wildcard boundary",
            remove: false,
            inject: None,
            allowed_hosts: Some(&json!(["*.example.com"])),
            proxy_only: None,
            test: None,
        },
        &AlwaysApprove,
    )
    .await
    .unwrap();
    let entry = gateway.open("api_key", "svc", None).await.unwrap();
    let response = reqwest::Client::new()
        .get(format!("{}/evil-example.com/resource", entry.base))
        .bearer_auth(entry.token)
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn query_injection_overrides_client_values_and_redacts_the_response() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, vault, gateway) = new_gateway_with_credential(&server, "synthetic-key").await;
    let inject = json!({"query":{"api_key":"{{value}}"}});
    configure_http(
        &vault,
        ConfigureHttpParams {
            r#type: "api_key",
            name: "svc",
            purpose: "test",
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
    Mock::given(method("GET"))
        .respond_with(|request: &wiremock::Request| {
            let keys = request
                .url
                .query_pairs()
                .filter(|(k, _)| k == "api_key")
                .map(|(_, v)| v.into_owned())
                .collect::<Vec<_>>();
            assert_eq!(keys, ["synthetic-key"]);
            assert!(request
                .url
                .query_pairs()
                .any(|(k, v)| k == "page" && v == "2"));
            ResponseTemplate::new(200).set_body_string(keys[0].clone())
        })
        .expect(1)
        .mount(&server)
        .await;
    let entry = gateway.open("api_key", "svc", None).await.unwrap();
    let response = reqwest::Client::new()
        .get(format!(
            "{}/{}/resource?api_key=client&page=2&api_key=other",
            entry.base,
            server.address()
        ))
        .bearer_auth(entry.token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "[REDACTED]");
}

#[tokio::test]
async fn an_oversized_content_length_is_rejected_without_waiting_for_the_body() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, _vault, gateway) = new_gateway_with_credential(&server, "synthetic-key").await;
    let entry = gateway.open("api_key", "svc", None).await.unwrap();
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", entry.port))
        .await
        .unwrap();
    client.write_all(format!(
        "POST /{}/upload HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n\r\n",
        server.address(), entry.port, entry.token, 20 * 1024 * 1024 + 1,
    ).as_bytes()).await.unwrap();
    let mut status = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        BufReader::new(client).read_line(&mut status),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(status.starts_with("HTTP/1.1 413"), "{status}");
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_chunked_upload_is_limited_before_the_sender_finishes() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, _vault, gateway) = new_gateway_with_credential(&server, "synthetic-key").await;
    let entry = gateway.open("api_key", "svc", None).await.unwrap();
    use futures_util::{stream, StreamExt};
    let chunk = bytes::Bytes::from(vec![b'x'; 1024 * 1024]);
    let chunks = stream::iter((0..21).map(move |_| Ok::<_, std::io::Error>(chunk.clone())))
        .chain(stream::pending());
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        reqwest::Client::new()
            .post(format!("{}/{}/upload", entry.base, server.address()))
            .bearer_auth(entry.token)
            .body(reqwest::Body::wrap_stream(chunks))
            .send(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), 413);
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn revocation_interrupts_a_request_waiting_for_upstream_headers() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let (_tmp, _vault, gateway) = new_gateway_with_credential(&server, "synthetic-key").await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(60)))
        .expect(1)
        .mount(&server)
        .await;
    let entry = gateway.open("api_key", "svc", None).await.unwrap();
    let url = format!("{}/{}/slow", entry.base, server.address());
    let request = tokio::spawn(async move {
        reqwest::Client::new()
            .get(url)
            .bearer_auth(entry.token)
            .send()
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while server.received_requests().await.unwrap().is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    gateway.revoke_all();
    let response = tokio::time::timeout(std::time::Duration::from_secs(1), request)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), 401);
}

/// Sends one chunk, then stalls until the gateway closes the upstream connection.
/// Owning the JoinSet ensures the test leaves no detached listening or connection tasks.
async fn stalled_stream_server() -> (std::net::SocketAddr, tokio::task::JoinSet<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut server = tokio::task::JoinSet::new();
    server.spawn(async move {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            connections.spawn(async move {
                let (read, mut write) = stream.into_split();
                let mut read = BufReader::new(read);
                loop {
                    let mut line = String::new();
                    if read.read_line(&mut line).await.unwrap() == 0 {
                        return;
                    }
                    if line == "\r\n" {
                        break;
                    }
                }
                write.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nping\r\n",
                ).await.unwrap();
                let _ = read.read_to_end(&mut Vec::new()).await;
            });
        }
    });
    (address, server)
}

#[tokio::test]
async fn revocation_interrupts_a_response_stalled_between_chunks() {
    let _guard = with_insecure_loopback();
    let fixture = MockServer::start().await;
    let (_tmp, _vault, gateway) = new_gateway_with_credential(&fixture, "synthetic-key").await;
    let (upstream, _server) = stalled_stream_server().await;
    let entry = gateway.open("api_key", "svc", None).await.unwrap();
    let mut response = reqwest::Client::new()
        .get(format!("{}/{upstream}/stream", entry.base))
        .bearer_auth(entry.token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.chunk().await.unwrap().unwrap(), "ping");
    gateway.revoke_all();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), response.text())
            .await
            .unwrap()
            .is_err()
    );
}

#[tokio::test]
async fn streaming_requests_keep_their_permits_and_revocation_releases_them() {
    let _guard = with_insecure_loopback();
    let fixture = MockServer::start().await;
    let (_tmp, _vault, gateway) = new_gateway_with_credential(&fixture, "synthetic-key").await;
    let (upstream, _server) = stalled_stream_server().await;
    let entry = gateway.open("api_key", "svc", None).await.unwrap();
    let client = reqwest::Client::new();
    let url = format!("{}/{upstream}/stream", entry.base);
    let mut responses = Vec::new();
    for _ in 0..16 {
        let response = client
            .get(&url)
            .bearer_auth(&entry.token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        responses.push(response);
    }
    assert_eq!(
        client
            .get(&url)
            .bearer_auth(&entry.token)
            .send()
            .await
            .unwrap()
            .status(),
        429
    );
    gateway.revoke_all();
    let reopened = gateway.open("api_key", "svc", None).await.unwrap();
    let response = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let response = client
                .get(&url)
                .bearer_auth(&reopened.token)
                .send()
                .await
                .unwrap();
            if response.status() != 429 {
                break response;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(response.status(), 200);
    drop(responses);
    gateway.shutdown().await;
}
