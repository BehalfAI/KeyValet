//! Integration tests mirroring src/test/grants.test.ts and the "dispatch" describe block of
//! src/test/vault.test.ts -- the existing TS suites are the behavioral spec for this port.
//! Run with KEYVALET_LANG=zh so assertions against Chinese prompt/error text are deterministic.

use kv_core::{dispatch, resolve_hint, ClientContext, GrantMode, JsonMap, SessionAuth, Settings};
use kv_core::{is_loosening, stricter};
use kv_ipc::{request_digest, Response, GRANT_REQUIRED_PREFIX};
use kv_vault::{SetParams, Vault};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Test double for `AuthorizeGate`: answers are consumed in order (`true` = approved), and every
/// reason string shown to the "user" is recorded for assertions -- mirrors grants.test.ts's
/// `touchIdAnswers`/`reasons` fixtures exactly, including bypassing the auth-gate cooldown entirely
/// (that's tested directly, and independently, in auth_gate.rs's own tests -- these tests are about
/// grant-mode logic, not cooldown). `Arc<Mutex<_>>` (not `Rc<RefCell<_>>`): `AuthorizeGate` requires
/// `Send` futures for the real multi-threaded daemon, so the test double must satisfy that too.
struct FakeAuthInner {
    answers: Mutex<VecDeque<bool>>,
    reasons: Mutex<Vec<String>>,
}
#[derive(Clone)]
struct FakeAuth(Arc<FakeAuthInner>);
impl FakeAuth {
    fn new() -> Self {
        Self(Arc::new(FakeAuthInner {
            answers: Mutex::new(VecDeque::new()),
            reasons: Mutex::new(Vec::new()),
        }))
    }
    fn push(&self, answer: bool) {
        self.0.answers.lock().unwrap().push_back(answer);
    }
    fn push_many(&self, n: usize, answer: bool) {
        for _ in 0..n {
            self.push(answer);
        }
    }
    fn reasons(&self) -> Vec<String> {
        self.0.reasons.lock().unwrap().clone()
    }
}
impl kv_core::AuthorizeGate for FakeAuth {
    async fn authorize(&self, reason: &str) -> Result<(), String> {
        self.0.reasons.lock().unwrap().push(reason.to_string());
        if self.0.answers.lock().unwrap().pop_front().unwrap_or(false) {
            Ok(())
        } else {
            Err("Touch ID authentication failed".to_string())
        }
    }
}

/// grants.test.ts sets a confirmer that panics if ever called: with `auth` present, loosening
/// settings must go through Touch ID, never a confirmation dialog.
struct PanicConfirmer;
impl kv_core::Confirmer for PanicConfirmer {
    async fn confirm(&self, _message: &str, _ok_label: &str) -> bool {
        panic!("Loosening settings should use Touch ID, not a confirmation dialog");
    }
}

fn new_vault() -> (tempfile::TempDir, Vault) {
    // Pin the language deterministically: these tests assert on Chinese prompt/error text, and
    // `kv_i18n::lang()` otherwise falls back to whatever locale happens to be ambient (OS
    // preference, LANG/LC_ALL, or none of the above on a CI runner) -- `set_lang` is an
    // unconditional overwrite, so it's safe to call from every test even under thread interleaving
    // since every caller sets the same target value.
    kv_i18n::set_lang("zh");
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
    vault
        .set(SetParams {
            r#type: "api_key".into(),
            name: "openai".into(),
            value: Some("sk-openai-123".into()),
            ..Default::default()
        })
        .unwrap();
    vault
        .set(SetParams {
            r#type: "api_key".into(),
            name: "github".into(),
            value: Some("ghp-456789".into()),
            ..Default::default()
        })
        .unwrap();
    (tmp, vault)
}

/// Gives an existing static credential a proxy configuration for `hosts`.
fn allow_hosts(vault: &Vault, name: &str, hosts: &[&str]) {
    vault
        .update_http("api_key", name, |_| {
            Some(kv_vault::HttpConfig {
                inject: None,
                allowed_hosts: hosts.iter().map(|h| h.to_string()).collect(),
                proxy_only: false,
                test: None,
            })
        })
        .unwrap();
}

fn params(extra: Value) -> JsonMap {
    let mut p = json!({"purpose": "test"});
    merge(&mut p, extra);
    p.as_object().unwrap().clone()
}
fn merge(base: &mut Value, extra: Value) {
    if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            b.insert(k.clone(), v.clone());
        }
    }
}

fn ctx() -> ClientContext {
    ClientContext {
        session: Some("s".into()),
        cwd: Some("/proj".into()),
        ..Default::default()
    }
}

async fn call(
    vault: &Vault,
    auth: &mut SessionAuth<FakeAuth>,
    confirmer: &PanicConfirmer,
    op: &str,
    extra: Value,
) -> Response {
    dispatch(vault, 1, op, params(extra), &ctx(), Some(auth), confirmer).await
}

fn is_ok(r: &Response) -> bool {
    matches!(r, Response::Ok { .. })
}
fn error_of(r: &Response) -> Option<&str> {
    match r {
        Response::Err { error, .. } => Some(error),
        _ => None,
    }
}
fn result_of(r: Response) -> Value {
    match r {
        Response::Ok { result, .. } => result,
        Response::Err { error, .. } => panic!("expected ok, got error: {error}"),
    }
}

fn session_auth(_vault: &Vault, mode: GrantMode, auth: FakeAuth) -> SessionAuth<FakeAuth> {
    let mut s = SessionAuth::new(auth);
    s.mode = Some(mode);
    s
}

#[tokio::test]
async fn per_credential_unauthorized_denied_then_usable_after_grant_but_only_for_that_credential() {
    let (_tmp, vault) = new_vault();
    let fake = FakeAuth::new();
    let mut auth = session_auth(&vault, GrantMode::PerCredential, fake.clone());
    let confirmer = PanicConfirmer;

    let denied = call(
        &vault,
        &mut auth,
        &confirmer,
        "get",
        json!({"type": "api_key", "name": "openai"}),
    )
    .await;
    assert_eq!(
        error_of(&denied),
        Some(format!("{GRANT_REQUIRED_PREFIX}api_key/openai").as_str())
    );

    fake.push(true);
    let g = call(
        &vault,
        &mut auth,
        &confirmer,
        "grant",
        json!({"type": "api_key", "name": "openai", "purpose": "Call OpenAI"}),
    )
    .await;
    assert_eq!(
        result_of(g),
        json!({"granted": "api_key/openai", "already": false, "single_use": false})
    );
    assert_eq!(
        fake.reasons()[0],
        "使用 openai（本会话）\n可读取明文凭证（AI 可见）"
    );

    assert!(is_ok(
        &call(
            &vault,
            &mut auth,
            &confirmer,
            "get",
            json!({"type": "api_key", "name": "openai"})
        )
        .await
    ));
    assert!(
        is_ok(
            &call(
                &vault,
                &mut auth,
                &confirmer,
                "get",
                json!({"type": "api_key", "name": "openai"})
            )
            .await
        ),
        "reusable within this session"
    );
    assert!(
        !is_ok(
            &call(
                &vault,
                &mut auth,
                &confirmer,
                "get",
                json!({"type": "api_key", "name": "github"})
            )
            .await
        ),
        "authorizing one credential doesn't authorize all of them"
    );
}

/// Session approval covers the credential, not an individual HTTP endpoint. Both bound and
/// unbound session grants stay concise; agent-provided purpose and hints stay out of the prompt.
#[tokio::test]
async fn session_grant_shows_the_credential_scope_and_keeps_purpose_in_the_audit() {
    let (_tmp, vault) = new_vault();
    let fake = FakeAuth::new();
    let mut auth = session_auth(&vault, GrantMode::PerCredential, fake.clone());
    let confirmer = PanicConfirmer;

    fake.push(true);
    call(
        &vault,
        &mut auth,
        &confirmer,
        "grant",
        json!({
            "type": "api_key",
            "name": "openai",
            "purpose": "Summarize meeting notes",
            "request_hint": "GET attacker.example/forged",
            "operation": "httpRequest",
            "request": {"type": "api_key", "name": "openai", "method": "POST", "url": "https://api.openai.com/v1/chat/completions?private=query-value#fragment-value"},
        }),
    )
    .await;
    let reason = &fake.reasons()[0];
    assert_eq!(reason, "使用 openai（本会话）\n可读取明文凭证（AI 可见）");
    assert!(!reason.contains("attacker.example"));
    assert!(!reason.contains("query-value"));
    assert!(!reason.contains("fragment-value"));
    assert!(!reason.contains("Summarize meeting notes"));
    assert!(!reason.contains("/proj"));
    let audit = std::fs::read_to_string(vault.dir.join("audit.log")).unwrap();
    let last: Value = serde_json::from_str(audit.lines().last().unwrap()).unwrap();
    assert_eq!(last["purpose"], "Summarize meeting notes");
    assert_eq!(last["client"]["cwd"], "/proj");

    fake.push(true);
    call(
        &vault,
        &mut auth,
        &confirmer,
        "grant",
        json!({"type": "api_key", "name": "github", "purpose": "Create a repo"}),
    )
    .await;
    let plain_reason = &fake.reasons()[1];
    assert_eq!(
        plain_reason,
        "使用 github（本会话）\n可读取明文凭证（AI 可见）"
    );
}

/// One-shot approval still exposes the helper-derived operation, never the agent's display hint.
/// Session approval also keeps the disclosure warning when the operation returns the secret.
#[tokio::test]
async fn operation_details_remain_for_per_use_approval_and_plaintext_disclosure() {
    let (_tmp, vault) = new_vault();
    allow_hosts(&vault, "openai", &["api.openai.com"]);
    let fake = FakeAuth::new();
    let confirmer = PanicConfirmer;
    let mut auth = session_auth(&vault, GrantMode::PerUse, fake.clone());
    fake.push(true);
    assert!(is_ok(&call(
        &vault,
        &mut auth,
        &confirmer,
        "grant",
        json!({
            "type": "api_key", "name": "openai", "purpose": "Just list models",
            "request_hint": "GET attacker.example/forged", "operation": "httpRequest",
            "request": {"type": "api_key", "name": "openai", "method": "DELETE", "url": "https://api.openai.com/v1/files/file-123?private=query-value#fragment-value"},
        }),
    ).await));
    let reason = &fake.reasons()[0];
    // Everything the approval is bound to is shown; the fragment is never sent, so it isn't.
    assert_eq!(
        reason,
        "使用 openai（仅此一次）\nDELETE api.openai.com/v1/files/file-123\n?private=query-value"
    );

    let mut auth = session_auth(&vault, GrantMode::PerCredential, fake.clone());
    fake.push(true);
    assert!(is_ok(
        &call(
            &vault,
            &mut auth,
            &confirmer,
            "grant",
            json!({
                "type": "api_key", "name": "openai", "purpose": "Just list models",
                "operation": "get", "request": {"type": "api_key", "name": "openai"},
            }),
        )
        .await
    ));
    let reason = &fake.reasons()[1];
    assert_eq!(reason, "使用 openai（本会话）\n可读取明文凭证（AI 可见）");
    assert!(!reason.contains("sk-openai-123"));
}

#[tokio::test]
async fn failed_touch_id_denies_grant_but_new_credentials_are_auto_authorized_and_metadata_ops_are_free(
) {
    let (_tmp, vault) = new_vault();
    let fake = FakeAuth::new();
    let mut auth = session_auth(&vault, GrantMode::PerCredential, fake.clone());
    let confirmer = PanicConfirmer;

    fake.push(false);
    assert!(!is_ok(
        &call(
            &vault,
            &mut auth,
            &confirmer,
            "grant",
            json!({"type": "api_key", "name": "openai"})
        )
        .await
    ));
    assert!(is_ok(
        &call(
            &vault,
            &mut auth,
            &confirmer,
            "set",
            json!({"type": "api_key", "name": "new", "value": "v-111111"})
        )
        .await
    ));
    assert!(is_ok(
        &call(
            &vault,
            &mut auth,
            &confirmer,
            "get",
            json!({"type": "api_key", "name": "new"})
        )
        .await
    ));
    for op in [
        "list",
        "listTypes",
        "info",
        "exists",
        "auditQuery",
        "sessionInfo",
    ] {
        assert!(
            is_ok(
                &call(
                    &vault,
                    &mut auth,
                    &confirmer,
                    op,
                    json!({"type": "api_key", "name": "openai"})
                )
                .await
            ),
            "{op}"
        );
    }
}

#[tokio::test]
async fn per_use_one_touch_id_buys_exactly_one_use() {
    let (_tmp, vault) = new_vault();
    let fake = FakeAuth::new();
    let mut auth = session_auth(&vault, GrantMode::PerUse, fake.clone());
    let confirmer = PanicConfirmer;

    fake.push_many(2, true);
    assert!(is_ok(
        &call(
            &vault,
            &mut auth,
            &confirmer,
            "grant",
            json!({"type": "api_key", "name": "openai", "operation": "get", "request": {"type": "api_key", "name": "openai"}})
        )
        .await
    ));
    assert!(fake.reasons()[0].contains("仅此一次"));
    assert!(fake.reasons()[0].contains("读取明文凭证（AI 可见）"));
    assert!(!fake.reasons()[0].contains("sk-openai-123"));
    assert!(is_ok(
        &call(
            &vault,
            &mut auth,
            &confirmer,
            "get",
            json!({"type": "api_key", "name": "openai"})
        )
        .await
    ));
    assert!(
        !is_ok(
            &call(
                &vault,
                &mut auth,
                &confirmer,
                "get",
                json!({"type": "api_key", "name": "openai"})
            )
            .await
        ),
        "a second use requires authenticating again"
    );

    assert!(
        is_ok(
            &call(
                &vault,
                &mut auth,
                &confirmer,
                "grant",
                json!({"type": "api_key", "name": "openai", "operation": "get", "request": {"type": "api_key", "name": "openai"}})
            )
            .await
        ),
        "re-authorizing is not treated as already authorized"
    );
    assert!(is_ok(
        &call(
            &vault,
            &mut auth,
            &confirmer,
            "get",
            json!({"type": "api_key", "name": "openai"})
        )
        .await
    ));
    assert!(is_ok(
        &call(
            &vault,
            &mut auth,
            &confirmer,
            "set",
            json!({"type": "api_key", "name": "new", "value": "v-111111"})
        )
        .await
    ));
    assert!(
        !is_ok(
            &call(
                &vault,
                &mut auth,
                &confirmer,
                "get",
                json!({"type": "api_key", "name": "new"})
            )
            .await
        ),
        "newly created credentials are not auto-authorized in per_use either"
    );
}

async fn http_credential(
    vault: &Vault,
    auth: &mut SessionAuth<FakeAuth>,
    confirmer: &PanicConfirmer,
    server_addr: std::net::SocketAddr,
) {
    let set = call(
        vault,
        auth,
        confirmer,
        "set",
        json!({
            "type": "api_key", "name": "svc", "value": "sk-abc",
            "http": {"inject": {"headers": {"Authorization": "Bearer {{value}}"}}, "allowed_hosts": [server_addr.ip().to_string()]},
        }),
    )
    .await;
    assert!(is_ok(&set), "{:?}", error_of(&set));
}

#[tokio::test]
async fn per_use_grant_matching_the_exact_request_executes_it_exactly_once() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/charge"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;

    let (_tmp, vault) = new_vault();
    let fake = FakeAuth::new();
    let mut auth = session_auth(&vault, GrantMode::PerUse, fake.clone());
    let confirmer = PanicConfirmer;
    http_credential(&vault, &mut auth, &confirmer, *server.address()).await;

    let req = json!({"type": "api_key", "name": "svc", "method": "POST", "url": format!("http://{}/v1/charge", server.address()), "body": {"amount": 100}});

    fake.push(true);
    assert!(is_ok(
        &call(
            &vault,
            &mut auth,
            &confirmer,
            "grant",
            json!({"type": "api_key", "name": "svc", "operation": "httpRequest", "request": req}),
        )
        .await
    ));

    let r = call(&vault, &mut auth, &confirmer, "httpRequest", req.clone()).await;
    assert!(is_ok(&r), "{:?}", error_of(&r));

    let replay = call(&vault, &mut auth, &confirmer, "httpRequest", req).await;
    assert!(
        !is_ok(&replay),
        "one approval is exactly one use, even for a replay of the identical request"
    );
}

#[tokio::test]
async fn per_use_grant_does_not_cover_a_request_that_differs_from_the_one_it_was_shown_for() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/charge"))
        .and(wiremock::matchers::body_json(json!({"amount": 100_000})))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(0) // the request that was actually sent must never reach the network unapproved
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/charge"))
        .and(wiremock::matchers::body_json(json!({"amount": 100})))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1) // the approved request runs exactly once
        .mount(&server)
        .await;

    let (_tmp, vault) = new_vault();
    let fake = FakeAuth::new();
    let mut auth = session_auth(&vault, GrantMode::PerUse, fake.clone());
    let confirmer = PanicConfirmer;
    http_credential(&vault, &mut auth, &confirmer, *server.address()).await;

    let shown = json!({"type": "api_key", "name": "svc", "method": "POST", "url": format!("http://{}/v1/charge", server.address()), "body": {"amount": 100}});

    fake.push(true);
    assert!(is_ok(
        &call(
            &vault,
            &mut auth,
            &confirmer,
            "grant",
            json!({"type": "api_key", "name": "svc", "operation": "httpRequest", "request": shown}),
        )
        .await
    ));

    // What actually executes has a different body than what the Touch ID prompt showed.
    let actually_sent = json!({"type": "api_key", "name": "svc", "method": "POST", "url": format!("http://{}/v1/charge", server.address()), "body": {"amount": 100_000}});
    let r = call(&vault, &mut auth, &confirmer, "httpRequest", actually_sent).await;
    assert!(
        !is_ok(&r),
        "a request that doesn't match the approved digest must not execute"
    );
    assert!(error_of(&r).unwrap().starts_with(GRANT_REQUIRED_PREFIX));

    // A mismatched request neither runs nor consumes the approval of the request that was
    // shown; that one still runs exactly once, as approved.
    let approved = call(&vault, &mut auth, &confirmer, "httpRequest", shown.clone()).await;
    assert!(is_ok(&approved), "{:?}", error_of(&approved));
    let replay_of_shown = call(&vault, &mut auth, &confirmer, "httpRequest", shown).await;
    assert!(
        !is_ok(&replay_of_shown),
        "a used approval cannot be reused, even for the exact request it was shown for"
    );
}

#[tokio::test]
async fn session_prompt_text_comes_from_the_record_not_the_client_operation() {
    let (_tmp, vault) = new_vault();
    let fake = FakeAuth::new();
    let mut auth = session_auth(&vault, GrantMode::PerCredential, fake.clone());
    let confirmer = PanicConfirmer;
    // A direct client misstates the operation to hide the plaintext disclosure warning.
    fake.push(true);
    let misstated = call(
        &vault,
        &mut auth,
        &confirmer,
        "grant",
        json!({"type": "api_key", "name": "openai", "operation": "totp", "request": {"type": "api_key", "name": "openai"}}),
    )
    .await;
    assert!(
        !is_ok(&misstated),
        "an operation the credential can't perform is refused"
    );
    assert!(fake.reasons().is_empty(), "refused before any prompt");
    let unsafe_methods = [("httpRequest", "https://api.openai.com/v1/models")];
    for (op, url) in unsafe_methods {
        fake.push(true);
        let r = call(
            &vault,
            &mut auth,
            &confirmer,
            "grant",
            json!({"type": "api_key", "name": "openai", "operation": op, "request": {"type": "api_key", "name": "openai", "url": url}}),
        )
        .await;
        assert!(is_ok(&r), "{:?}", error_of(&r));
    }
    assert_eq!(
        fake.reasons()[0],
        "使用 openai（本会话）\n可读取明文凭证（AI 可见）",
        "even a session grant requested for a proxied call warns that plaintext is readable"
    );
    // Proxy-only credentials say so instead.
    vault
        .update_http("api_key", "github", |_| {
            Some(kv_vault::HttpConfig {
                inject: None,
                allowed_hosts: vec!["api.github.com".into()],
                proxy_only: true,
                test: None,
            })
        })
        .unwrap();
    fake.push(true);
    assert!(is_ok(
        &call(
            &vault,
            &mut auth,
            &confirmer,
            "grant",
            json!({"type": "api_key", "name": "github"}),
        )
        .await
    ));
    assert_eq!(
        fake.reasons()[1],
        "使用 github（本会话）\n仅代理请求（AI 看不到明文）"
    );
}

#[tokio::test]
async fn per_use_refuses_invalid_methods_and_hosts_before_prompting() {
    let (_tmp, vault) = new_vault();
    allow_hosts(&vault, "openai", &["api.openai.com"]);
    let fake = FakeAuth::new();
    let mut auth = session_auth(&vault, GrantMode::PerUse, fake.clone());
    let confirmer = PanicConfirmer;
    for request in [
        json!({"type": "api_key", "name": "openai", "method": "GET\n\u{202e}Scope: all", "url": "https://api.openai.com/v1/models"}),
        json!({"type": "api_key", "name": "openai", "method": "GET", "url": "https://attacker.example/v1/models"}),
        json!({"type": "api_key", "name": "openai", "method": "GET", "url": "http://api.openai.com/v1/models"}),
    ] {
        let r = call(
            &vault,
            &mut auth,
            &confirmer,
            "grant",
            json!({"type": "api_key", "name": "openai", "operation": "httpRequest", "request": request}),
        )
        .await;
        assert!(!is_ok(&r));
    }
    assert!(
        fake.reasons().is_empty(),
        "no prompt for a request that would be refused"
    );
}

#[tokio::test]
async fn concurrent_per_use_approvals_for_one_credential_do_not_overwrite_each_other() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(2)
        .mount(&server)
        .await;
    let (_tmp, vault) = new_vault();
    let fake = FakeAuth::new();
    let mut auth = session_auth(&vault, GrantMode::PerUse, fake.clone());
    let confirmer = PanicConfirmer;
    http_credential(&vault, &mut auth, &confirmer, *server.address()).await;
    let first = json!({"type": "api_key", "name": "svc", "method": "GET", "url": format!("http://{}/a", server.address())});
    let second = json!({"type": "api_key", "name": "svc", "method": "GET", "url": format!("http://{}/b", server.address())});
    for request in [&first, &second] {
        fake.push(true);
        assert!(is_ok(
            &call(
                &vault,
                &mut auth,
                &confirmer,
                "grant",
                json!({"type": "api_key", "name": "svc", "operation": "httpRequest", "request": request}),
            )
            .await
        ));
    }
    for request in [second, first] {
        let r = call(&vault, &mut auth, &confirmer, "httpRequest", request).await;
        assert!(is_ok(&r), "{:?}", error_of(&r));
    }
}

#[tokio::test]
async fn a_mode_tightened_elsewhere_applies_to_a_live_session() {
    let (_tmp, vault) = new_vault();
    let fake = FakeAuth::new();
    let settings = |grant_mode| kv_core::settings::Settings {
        grant_mode,
        remember_hours: 8.0,
        remember_until: None,
    };
    kv_core::write_settings(&vault.dir, &settings(GrantMode::PerSession)).unwrap();
    let mut auth = SessionAuth::new(fake.clone());
    auth.apply_mode(&settings(GrantMode::PerSession));
    let confirmer = PanicConfirmer;
    let get = json!({"type": "api_key", "name": "openai"});
    assert!(is_ok(
        &call(&vault, &mut auth, &confirmer, "get", get.clone()).await
    ));
    // E.g. `keyvalet grant-mode per-use` in a terminal while this session is running.
    kv_core::write_settings(&vault.dir, &settings(GrantMode::PerUse)).unwrap();
    let r = call(&vault, &mut auth, &confirmer, "get", get).await;
    assert!(error_of(&r).unwrap().starts_with(GRANT_REQUIRED_PREFIX));
    assert_eq!(auth.mode, Some(GrantMode::PerUse));
}

#[tokio::test]
async fn loosening_requires_touch_id_and_takes_effect_immediately() {
    let (_tmp, vault) = new_vault();
    let fake = FakeAuth::new();
    let mut auth = session_auth(&vault, GrantMode::PerCredential, fake.clone());
    let confirmer = PanicConfirmer;

    assert_eq!(
        kv_core::read_settings(&vault.dir).grant_mode,
        GrantMode::PerCredential
    );
    fake.push(false);
    assert!(!is_ok(
        &call(
            &vault,
            &mut auth,
            &confirmer,
            "settings",
            json!({"grant_mode": "per_session"})
        )
        .await
    ));
    assert_eq!(
        kv_core::read_settings(&vault.dir).grant_mode,
        GrantMode::PerCredential
    );

    fake.push(true);
    assert!(is_ok(
        &call(
            &vault,
            &mut auth,
            &confirmer,
            "settings",
            json!({"grant_mode": "per_session"})
        )
        .await
    ));
    assert!(fake
        .reasons()
        .last()
        .unwrap()
        .contains("本会话可使用全部凭证，新会话需解锁"));
    assert_eq!(
        kv_core::read_settings(&vault.dir).grant_mode,
        GrantMode::PerSession
    );
    assert!(
        is_ok(
            &call(
                &vault,
                &mut auth,
                &confirmer,
                "get",
                json!({"type": "api_key", "name": "github"})
            )
            .await
        ),
        "all credentials are immediately usable in the current session"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(vault.dir.join("settings.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[tokio::test]
async fn tightening_is_immediate_and_revokes_the_current_sessions_authorization() {
    let (_tmp, vault) = new_vault();
    let fake = FakeAuth::new();
    let mut auth = session_auth(&vault, GrantMode::PerSession, fake.clone());
    auth.grant_all = true;
    let confirmer = PanicConfirmer;
    kv_core::write_settings(
        &vault.dir,
        &Settings {
            grant_mode: GrantMode::PerSession,
            remember_hours: 8.0,
            remember_until: None,
        },
    )
    .unwrap();

    assert!(is_ok(
        &call(
            &vault,
            &mut auth,
            &confirmer,
            "settings",
            json!({"grant_mode": "per_use"})
        )
        .await
    ));
    assert_eq!(
        fake.reasons().len(),
        0,
        "tightening needs no authentication"
    );
    assert_eq!(auth.mode, Some(GrantMode::PerUse));
    assert!(!is_ok(
        &call(
            &vault,
            &mut auth,
            &confirmer,
            "get",
            json!({"type": "api_key", "name": "openai"})
        )
        .await
    ));
}

#[tokio::test]
async fn remember_mode_lifecycle() {
    let (_tmp, vault) = new_vault();
    let fake = FakeAuth::new();
    let mut auth = session_auth(&vault, GrantMode::PerCredential, fake.clone());
    let confirmer = PanicConfirmer;

    fake.push(true);
    let r = call(
        &vault,
        &mut auth,
        &confirmer,
        "settings",
        json!({"grant_mode": "remember", "remember_hours": 8}),
    )
    .await;
    assert!(is_ok(&r), "{r:?}");
    let s = kv_core::read_settings(&vault.dir);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as f64;
    assert!(kv_core::remember_active(&s, now));
    assert!((s.remember_until.unwrap() - (now + 8.0 * 3_600_000.0)).abs() < 5000.0);

    fake.push(false);
    assert!(
        !is_ok(
            &call(
                &vault,
                &mut auth,
                &confirmer,
                "settings",
                json!({"remember_hours": 0})
            )
            .await
        ),
        "changing it to forever requires Touch ID"
    );
    assert!(
        is_ok(
            &call(
                &vault,
                &mut auth,
                &confirmer,
                "settings",
                json!({"remember_hours": 1})
            )
            .await
        ),
        "shortening it doesn't"
    );
    let now2 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as f64;
    assert!(
        kv_core::read_settings(&vault.dir).remember_until.unwrap() <= now2 + 3_600_000.0 + 5000.0,
        "shortening the duration also shortens the current window"
    );

    assert!(is_ok(
        &call(
            &vault,
            &mut auth,
            &confirmer,
            "settings",
            json!({"forget": true})
        )
        .await
    ));
    assert!(!kv_core::remember_active(
        &kv_core::read_settings(&vault.dir),
        now2
    ));
    let info = result_of(call(&vault, &mut auth, &confirmer, "sessionInfo", json!({})).await);
    assert_eq!(info["remembered_until"], Value::Null);
}

#[test]
fn a_client_can_only_tighten() {
    assert_eq!(
        stricter(GrantMode::Remember, Some(GrantMode::PerUse)),
        GrantMode::PerUse
    );
    assert_eq!(
        stricter(GrantMode::PerUse, Some(GrantMode::Remember)),
        GrantMode::PerUse
    );
    assert_eq!(
        stricter(GrantMode::PerCredential, None),
        GrantMode::PerCredential
    );

    let (_tmp, vault) = new_vault();
    let mut auth = session_auth(&vault, GrantMode::PerSession, FakeAuth::new());
    auth.requested = Some(GrantMode::PerUse);
    auth.apply_mode(&Settings {
        grant_mode: GrantMode::PerSession,
        remember_hours: 8.0,
        remember_until: None,
    });
    assert_eq!(auth.mode, Some(GrantMode::PerUse));
    assert!(!auth.grant_all);
}

#[test]
fn is_loosening_determination() {
    let s = |grant_mode: GrantMode, remember_hours: f64| Settings {
        grant_mode,
        remember_hours,
        remember_until: None,
    };
    assert!(is_loosening(
        &s(GrantMode::PerCredential, 8.0),
        &s(GrantMode::PerSession, 8.0)
    ));
    assert!(!is_loosening(
        &s(GrantMode::PerCredential, 8.0),
        &s(GrantMode::PerUse, 8.0)
    ));
    assert!(is_loosening(
        &s(GrantMode::Remember, 8.0),
        &s(GrantMode::Remember, 24.0)
    ));
    assert!(is_loosening(
        &s(GrantMode::Remember, 8.0),
        &s(GrantMode::Remember, 0.0)
    ));
    assert!(!is_loosening(
        &s(GrantMode::Remember, 0.0),
        &s(GrantMode::Remember, 8.0)
    ));
    assert!(!is_loosening(
        &s(GrantMode::Remember, 8.0),
        &s(GrantMode::PerSession, 8.0)
    ));
}

#[test]
fn backward_compatible_with_the_old_all_setting_and_hints_match_uniquely_by_name() {
    let (_tmp, vault) = new_vault();
    std::fs::write(vault.dir.join("settings.json"), r#"{"grant_mode":"all"}"#).unwrap();
    assert_eq!(
        kv_core::read_settings(&vault.dir).grant_mode,
        GrantMode::PerSession
    );

    let hint = |ty: Option<&str>, name: &str| kv_ipc::CredentialHint {
        r#type: ty.map(String::from),
        name: name.to_string(),
    };
    assert_eq!(
        resolve_hint(&vault, Some(&hint(Some("api_key"), "openai"))),
        Some("api_key/openai".to_string())
    );
    assert_eq!(
        resolve_hint(&vault, Some(&hint(None, "github"))),
        Some("api_key/github".to_string())
    );
    assert_eq!(resolve_hint(&vault, Some(&hint(None, "nope"))), None);
}

#[tokio::test]
async fn unknown_op_and_missing_purpose_are_rejected_cleanly() {
    // Mirrors src/test/vault.test.ts's "dispatch" describe block, which calls `dispatch` with no
    // `auth` at all: omitted means full authorization is assumed (tests / the root CLI only) --
    // this test is about op validation and vault-level errors, not grant checks.
    let (_tmp, vault) = new_vault();
    let confirmer = PanicConfirmer;
    let no_auth: Option<&mut SessionAuth<FakeAuth>> = None;

    let r = dispatch(
        &vault,
        2,
        "rm -rf",
        JsonMap::new(),
        &ctx(),
        no_auth,
        &confirmer,
    )
    .await;
    assert!(!is_ok(&r));

    let no_auth: Option<&mut SessionAuth<FakeAuth>> = None;
    let r2 = dispatch(
        &vault,
        1,
        "get",
        json!({"type": "nope", "name": "x", "purpose": "test"})
            .as_object()
            .unwrap()
            .clone(),
        &ctx(),
        no_auth,
        &confirmer,
    )
    .await;
    assert_eq!(error_of(&r2), Some("凭证类型 \"nope\" 不存在"));
}

// Tests below race on the same crate-global "allow insecure loopback" flag in kv-protocols --
// serialize them (same pattern as kv-protocols' and kv-proxy's own tests for the same reason).
static LOOPBACK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn with_insecure_loopback() -> impl Drop {
    struct Guard<'a>(#[allow(dead_code)] std::sync::MutexGuard<'a, ()>);
    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            kv_protocols::http::allow_insecure_loopback_for_tests(false);
        }
    }
    let guard = LOOPBACK_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    kv_protocols::http::allow_insecure_loopback_for_tests(true);
    Guard(guard)
}

#[tokio::test]
async fn setup_protocol_then_totp_auto_grants_and_returns_a_code() {
    let (_tmp, vault) = new_vault();
    let auth_double = FakeAuth::new(); // never answered: Set/SetupProtocol need no grant, and totp is auto-granted by the setup itself
    let mut auth = session_auth(&vault, GrantMode::PerCredential, auth_double);
    let confirmer = PanicConfirmer;

    let setup = call(
        &vault,
        &mut auth,
        &confirmer,
        "setupProtocol",
        json!({"type": "totp", "name": "github", "kind": "totp", "secrets": {"secret": "JBSWY3DPEHPK3PXP"}}),
    )
    .await;
    assert!(is_ok(&setup), "{:?}", error_of(&setup));

    let r = call(
        &vault,
        &mut auth,
        &confirmer,
        "totp",
        json!({"type": "totp", "name": "github"}),
    )
    .await;
    let v = result_of(r);
    let code = v["code"].as_str().unwrap();
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
}

#[tokio::test]
async fn set_with_inline_http_then_http_request_injects_the_credential() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/ping"))
        .and(header("authorization", "Bearer sk-abc"))
        .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
        .expect(1)
        .mount(&server)
        .await;

    let (_tmp, vault) = new_vault();
    let auth_double = FakeAuth::new(); // Set needs no grant, and HttpRequest is auto-granted by the Set that created it
    let mut auth = session_auth(&vault, GrantMode::PerCredential, auth_double);
    let confirmer = PanicConfirmer; // the inline-http path on `set` is implicit-consent: must never prompt

    let set = call(
        &vault,
        &mut auth,
        &confirmer,
        "set",
        json!({
            "type": "api_key", "name": "svc", "value": "sk-abc",
            "http": {"inject": {"headers": {"Authorization": "Bearer {{value}}"}}, "allowed_hosts": ["127.0.0.1"]},
        }),
    )
    .await;
    assert!(is_ok(&set), "{:?}", error_of(&set));

    let r = call(
        &vault,
        &mut auth,
        &confirmer,
        "httpRequest",
        json!({"type": "api_key", "name": "svc", "method": "GET", "url": format!("http://{}/v1/ping", server.address())}),
    )
    .await;
    let v = result_of(r);
    assert_eq!(v["status"], 200);
    assert_eq!(v["body"], "pong");
}

#[tokio::test]
async fn a_get_with_a_null_body_is_the_same_as_no_body_and_reaches_the_upstream() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/ping"))
        .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
        .expect(1)
        .mount(&server)
        .await;

    let (_tmp, vault) = new_vault();
    let auth_double = FakeAuth::new(); // Set needs no grant, and HttpRequest is auto-granted by the Set
    let mut auth = session_auth(&vault, GrantMode::PerCredential, auth_double);
    let confirmer = PanicConfirmer;
    http_credential(&vault, &mut auth, &confirmer, *server.address()).await;

    // Clients that serialize the omitted body as JSON null (the MCP server used to) must
    // behave exactly like clients that leave it out.
    let r = call(
        &vault,
        &mut auth,
        &confirmer,
        "httpRequest",
        json!({"type": "api_key", "name": "svc", "method": "GET", "url": format!("http://{}/v1/ping", server.address()), "body": null}),
    )
    .await;
    let v = result_of(r);
    assert_eq!(v["status"], 200);
    assert_eq!(v["body"], "pong");

    // A real body on GET is still rejected -- before anything reaches the network.
    let r = call(
        &vault,
        &mut auth,
        &confirmer,
        "httpRequest",
        json!({"type": "api_key", "name": "svc", "method": "GET", "url": format!("http://{}/v1/ping", server.address()), "body": {"x": 1}}),
    )
    .await;
    assert!(
        error_of(&r).unwrap().contains("不能带请求体"),
        "a real body on GET is still rejected: {:?}",
        error_of(&r)
    );
}

#[tokio::test]
async fn a_per_use_approval_for_a_get_is_not_broken_by_toggling_null_and_absent_body() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/ping"))
        .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
        .expect(2)
        .mount(&server)
        .await;

    let (_tmp, vault) = new_vault();
    let fake = FakeAuth::new();
    let mut auth = session_auth(&vault, GrantMode::PerUse, fake.clone());
    let confirmer = PanicConfirmer;
    http_credential(&vault, &mut auth, &confirmer, *server.address()).await;

    let url = format!("http://{}/v1/ping", server.address());
    let with_null =
        json!({"type": "api_key", "name": "svc", "method": "GET", "url": url, "body": null});
    let without = json!({"type": "api_key", "name": "svc", "method": "GET", "url": url});

    // Approve with `body: null`, execute with the key absent: the same request.
    fake.push(true);
    assert!(is_ok(
        &call(
            &vault,
            &mut auth,
            &confirmer,
            "grant",
            json!({"type": "api_key", "name": "svc", "operation": "httpRequest", "request": with_null}),
        )
        .await
    ));
    let r = call(
        &vault,
        &mut auth,
        &confirmer,
        "httpRequest",
        without.clone(),
    )
    .await;
    assert!(is_ok(&r), "{:?}", error_of(&r));

    // And the other direction: approve with the key absent, execute with `body: null`.
    fake.push(true);
    assert!(is_ok(
        &call(
            &vault,
            &mut auth,
            &confirmer,
            "grant",
            json!({"type": "api_key", "name": "svc", "operation": "httpRequest", "request": without}),
        )
        .await
    ));
    let r = call(&vault, &mut auth, &confirmer, "httpRequest", with_null).await;
    assert!(is_ok(&r), "{:?}", error_of(&r));
}

#[tokio::test]
async fn gateway_open_fails_cleanly_when_no_gateway_is_attached_to_the_session() {
    let (_tmp, vault) = new_vault();
    let mut auth = session_auth(&vault, GrantMode::PerCredential, FakeAuth::new());
    assert!(auth.gateway.is_none());
    let confirmer = PanicConfirmer;

    call(&vault, &mut auth, &confirmer, "set", json!({"type": "api_key", "name": "svc", "value": "sk-abc", "http": {"inject": {"headers": {"Authorization": "Bearer {{value}}"}}, "allowed_hosts": ["api.example.com"]}})).await;
    let r = call(
        &vault,
        &mut auth,
        &confirmer,
        "gatewayOpen",
        json!({"type": "api_key", "name": "svc"}),
    )
    .await;
    assert!(
        error_of(&r).unwrap().contains("未启用网关")
            || error_of(&r)
                .unwrap()
                .to_lowercase()
                .contains("not available")
    );
}

#[tokio::test]
async fn gateway_open_and_policy_tightening_through_a_real_listening_gateway() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/ping"))
        .and(header("authorization", "Bearer sk-abc"))
        .respond_with(ResponseTemplate::new(200).set_body_string("pong"))
        .expect(1)
        .mount(&server)
        .await;

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
    kv_i18n::set_lang("zh");

    let mut auth = session_auth(&vault, GrantMode::PerSession, FakeAuth::new());
    kv_core::write_settings(
        &vault.dir,
        &Settings {
            grant_mode: GrantMode::PerSession,
            remember_hours: 8.0,
            remember_until: None,
        },
    )
    .unwrap();
    auth.gateway = Some(Arc::new(kv_proxy::gateway::Gateway::new(
        vault.clone(),
        Arc::new(|_| {}),
        None,
    )));
    let confirmer = PanicConfirmer;

    let set = call(
        &vault,
        &mut auth,
        &confirmer,
        "set",
        json!({"type": "api_key", "name": "svc", "value": "sk-abc", "http": {"inject": {"headers": {"Authorization": "Bearer {{value}}"}}, "allowed_hosts": ["127.0.0.1"]}}),
    )
    .await;
    assert!(is_ok(&set), "{:?}", error_of(&set));

    let r = call(
        &vault,
        &mut auth,
        &confirmer,
        "gatewayOpen",
        json!({"type": "api_key", "name": "svc"}),
    )
    .await;
    let v = result_of(r);
    let base = v["base"].as_str().unwrap().to_string();
    let token = v["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("kv_"));

    let upstream_host = format!("127.0.0.1:{}", server.address().port());
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/{upstream_host}/v1/ping"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "pong");

    let tightened = call(
        &vault,
        &mut auth,
        &confirmer,
        "settings",
        json!({"grant_mode": "per_credential"}),
    )
    .await;
    assert!(is_ok(&tightened));
    let revoked = client
        .get(format!("{base}/{upstream_host}/v1/ping"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        revoked.status(),
        401,
        "an existing gateway must obey the tightened policy"
    );
}

#[tokio::test]
async fn info_on_a_protocol_credential_includes_its_config() {
    // Regression test for a real bug found by live-testing credential_imap_test against a real
    // oauth2 credential: info() for a non-static credential omitted `config` entirely, while
    // kv-mcp's credential_imap_test and credential_oauth_login's re-authorization path both
    // deserialize `info.config.*` (provider, client_id, scopes, ...) -- matching the original
    // TS's `publicView`, which spreads `record.config` into the response under that same key.
    // Without it, those tools failed outright with "missing field `config`", not just a
    // less-complete response.
    let (_tmp, vault) = new_vault();
    vault
        .set_protocol(kv_vault::SetProtocolParams {
            r#type: "oauth2".into(),
            name: "work".into(),
            kind: kv_vault::Kind::Oauth2,
            config: json!({"provider": "google", "client_id": "abc123"}),
            secrets: Default::default(),
            description: None,
            type_description: None,
            overwrite: false,
        })
        .unwrap();
    let mut auth = SessionAuth::new(FakeAuth::new());
    let confirmer = PanicConfirmer;
    let r = call(
        &vault,
        &mut auth,
        &confirmer,
        "info",
        json!({"type": "oauth2", "name": "work"}),
    )
    .await;
    assert!(is_ok(&r));
    let v = result_of(r);
    assert_eq!(v["config"]["provider"], "google");
    assert_eq!(v["config"]["client_id"], "abc123");
}

#[tokio::test]
async fn per_use_rejects_legacy_digest_and_cross_operation_secret_reads() {
    let (_tmp, vault) = new_vault();
    allow_hosts(&vault, "openai", &["example.com"]);
    let fake = FakeAuth::new();
    let mut auth = session_auth(&vault, GrantMode::PerUse, fake.clone());
    let confirmer = PanicConfirmer;
    let req = json!({"type": "api_key", "name": "openai", "method": "GET", "url": "https://example.com/status"});
    let digest = request_digest(req.as_object().unwrap()).unwrap();
    let legacy = call(&vault, &mut auth, &confirmer, "grant", json!({"type": "api_key", "name": "openai", "request_hint": "GET example.com/status", "request_digest": digest})).await;
    assert!(!is_ok(&legacy));
    assert!(fake.reasons().is_empty());
    fake.push(true);
    assert!(is_ok(
        &call(
            &vault,
            &mut auth,
            &confirmer,
            "grant",
            json!({"type": "api_key", "name": "openai", "operation": "httpRequest", "request": req})
        )
        .await
    ));
    let stolen = call(&vault, &mut auth, &confirmer, "get", req.clone()).await;
    assert!(error_of(&stolen)
        .unwrap()
        .starts_with(GRANT_REQUIRED_PREFIX));
    assert!(!is_ok(
        &call(&vault, &mut auth, &confirmer, "httpRequest", req).await
    ));
}

#[tokio::test]
async fn per_use_gateway_is_rejected_before_prompt() {
    let (_tmp, vault) = new_vault();
    let fake = FakeAuth::new();
    let mut auth = session_auth(&vault, GrantMode::PerUse, fake.clone());
    let confirmer = PanicConfirmer;
    let grant = call(&vault, &mut auth, &confirmer, "grant", json!({"type": "api_key", "name": "openai", "operation": "gatewayOpen", "request": {"type": "api_key", "name": "openai"}})).await;
    assert!(!is_ok(&grant));
    assert!(fake.reasons().is_empty());
}

#[tokio::test]
async fn per_use_test_approval_is_invalidated_by_stored_configuration_changes() {
    let (_tmp, vault) = new_vault();
    let config = serde_json::from_value(json!({
        "inject": {"headers": {"Authorization": "Bearer {{value}}"}},
        "allowed_hosts": ["example.com"], "proxy_only": true,
        "test": {"method": "GET", "url": "https://example.com/approved"}
    }))
    .unwrap();
    vault
        .update_http("api_key", "openai", |_| Some(config))
        .unwrap();
    let fake = FakeAuth::new();
    fake.push(true);
    let mut auth = session_auth(&vault, GrantMode::PerUse, fake.clone());
    let confirmer = PanicConfirmer;
    let request = json!({"type": "api_key", "name": "openai"});
    let grant = call(
        &vault,
        &mut auth,
        &confirmer,
        "grant",
        json!({
            "type": "api_key", "name": "openai", "operation": "httpTest", "request": request
        }),
    )
    .await;
    assert!(is_ok(&grant));
    assert!(fake.reasons()[0].contains("GET example.com/approved"));
    vault
        .update_http("api_key", "openai", |record| {
            let mut config = record.http.clone().unwrap();
            config.test.as_mut().unwrap().url = "https://example.com/replaced".into();
            Some(config)
        })
        .unwrap();
    let result = call(&vault, &mut auth, &confirmer, "httpTest", request).await;
    assert!(error_of(&result)
        .unwrap()
        .starts_with(GRANT_REQUIRED_PREFIX));
}

#[tokio::test]
async fn oauth_error_diagnostics_never_reach_the_response_or_audit_reader() {
    let _guard = with_insecure_loopback();
    let server = MockServer::start().await;
    let secret = "synthetic-client-secret-012345";
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(
            json!({"error": "invalid_client", "error_description": format!("Rejected {secret}")}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    let (_tmp, vault) = new_vault();
    kv_protocols::index::setup_protocol(&vault, kv_protocols::index::SetupProtocolParams {
        r#type: "oauth2".into(), name: "review".into(), kind: kv_vault::Kind::Oauth2,
        config: json!({"flow": "client_credentials", "client_id": "review", "token_url": format!("{}/token", server.uri())}),
        secrets: json!({"client_secret": secret}), description: None, type_description: None, overwrite: false, reuse_client_secret: false,
    }).unwrap();
    let fake = FakeAuth::new();
    let mut auth = session_auth(&vault, GrantMode::PerCredential, fake);
    auth.grants.insert("oauth2/review".into());
    let confirmer = PanicConfirmer;
    let response = call(
        &vault,
        &mut auth,
        &confirmer,
        "accessToken",
        json!({"type": "oauth2", "name": "review"}),
    )
    .await;
    assert!(!is_ok(&response));
    assert!(!error_of(&response).unwrap().contains(secret));
    assert!(error_of(&response).unwrap().contains("invalid_client"));
    let mut ungranted = session_auth(&vault, GrantMode::PerCredential, FakeAuth::new());
    let audit = result_of(
        call(
            &vault,
            &mut ungranted,
            &confirmer,
            "auditQuery",
            json!({"limit": 10}),
        )
        .await,
    );
    assert!(!audit.to_string().contains(secret));
    assert!(!std::fs::read_to_string(vault.dir.join("audit.log"))
        .unwrap()
        .contains(secret));
}
