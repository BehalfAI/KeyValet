//! Integration tests mirroring src/test/grants.test.ts and the "dispatch" describe block of
//! src/test/vault.test.ts -- the existing TS suites are the behavioral spec for this port.
//! Run with KEYVALET_LANG=zh so assertions against Chinese prompt/error text are deterministic.

use kv_core::{dispatch, resolve_hint, ClientContext, GrantMode, JsonMap, SessionAuth, Settings};
use kv_core::{is_loosening, stricter};
use kv_ipc::{Response, GRANT_REQUIRED_PREFIX};
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
    vault.init().unwrap();
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
    assert!(fake.reasons()[0].contains("授权本次 AI 会话使用凭证：api_key/openai"));

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
            json!({"type": "api_key", "name": "openai"})
        )
        .await
    ));
    assert!(fake.reasons()[0].contains("仅此一次"));
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
                json!({"type": "api_key", "name": "openai"})
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
        .contains("每个会话按一次 Touch ID"));
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
async fn gateway_open_end_to_end_through_a_real_listening_gateway() {
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
    vault.init().unwrap();
    kv_i18n::set_lang("zh");

    let mut auth = session_auth(&vault, GrantMode::PerCredential, FakeAuth::new());
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
}
