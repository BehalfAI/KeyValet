//! Integration tests for configure_http, mirroring the intent of src/helper/http-manage.ts:
//! expanding exposure needs confirmation (including the very first setup -- an empty "previously
//! allowed hosts" set means everything is new -- `credential_set`'s template flow is the separate,
//! implicit-consent path for a credential's *initial* proxy config), tightening doesn't, and a
//! config that changed underneath a pending confirmation is detected rather than silently overwritten.

use kv_platform::Confirmer;
use kv_proxy::manage::{configure_http, ConfigureHttpParams};
use kv_vault::{SetParams, Vault};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct FakeConfirmer {
    answer: bool,
    calls: Arc<AtomicUsize>,
}
impl Confirmer for FakeConfirmer {
    async fn confirm(&self, _message: &str, _ok_label: &str) -> bool {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.answer
    }
}

/// Always approves, without incrementing any counter a test asserts on -- for setup steps that
/// aren't themselves what the test is checking.
struct AlwaysApprove;
impl Confirmer for AlwaysApprove {
    async fn confirm(&self, _message: &str, _ok_label: &str) -> bool {
        true
    }
}

fn new_vault_with_credential() -> (tempfile::TempDir, Vault) {
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
            name: "svc".into(),
            value: Some("sk-abc".into()),
            ..Default::default()
        })
        .unwrap();
    (tmp, vault)
}

#[tokio::test]
async fn first_time_setup_still_requires_confirmation() {
    // Not an oversight: an empty "previously allowed" set means every host counts as newly
    // exposed. `credential_set`'s template flow (not this function) is the implicit-consent path
    // for a credential's initial proxy config.
    let (_tmp, vault) = new_vault_with_credential();
    let calls = Arc::new(AtomicUsize::new(0));
    let confirmer = FakeConfirmer {
        answer: true,
        calls: calls.clone(),
    };
    let inject = json!({"headers": {"Authorization": "Bearer {{value}}"}});
    let hosts = json!(["api.example.com"]);
    let out = configure_http(
        &vault,
        ConfigureHttpParams {
            r#type: "api_key",
            name: "svc",
            purpose: "test",
            remove: false,
            inject: Some(&inject),
            allowed_hosts: Some(&hosts),
            proxy_only: None,
            test: None,
        },
        &confirmer,
    )
    .await
    .unwrap();
    assert_eq!(out["http"]["allowed_hosts"], json!(["api.example.com"]));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn adding_a_host_requires_confirmation_and_is_rejected_if_denied() {
    let (_tmp, vault) = new_vault_with_credential();
    let inject = json!({"headers": {"Authorization": "Bearer {{value}}"}});
    configure_http(
        &vault,
        ConfigureHttpParams {
            r#type: "api_key",
            name: "svc",
            purpose: "test",
            remove: false,
            inject: Some(&inject),
            allowed_hosts: Some(&json!(["api.example.com"])),
            proxy_only: None,
            test: None,
        },
        &AlwaysApprove,
    )
    .await
    .unwrap();

    let calls = Arc::new(AtomicUsize::new(0));
    let confirmer = FakeConfirmer {
        answer: false,
        calls: calls.clone(),
    };
    let err = configure_http(
        &vault,
        ConfigureHttpParams {
            r#type: "api_key",
            name: "svc",
            purpose: "test",
            remove: false,
            inject: None,
            allowed_hosts: Some(&json!(["api.example.com", "api2.example.com"])),
            proxy_only: None,
            test: None,
        },
        &confirmer,
    )
    .await
    .unwrap_err();
    assert!(err.0.contains("拒绝") || err.0.to_lowercase().contains("denied"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn adding_a_host_is_applied_once_approved() {
    let (_tmp, vault) = new_vault_with_credential();
    let inject = json!({"headers": {"Authorization": "Bearer {{value}}"}});
    configure_http(
        &vault,
        ConfigureHttpParams {
            r#type: "api_key",
            name: "svc",
            purpose: "test",
            remove: false,
            inject: Some(&inject),
            allowed_hosts: Some(&json!(["api.example.com"])),
            proxy_only: None,
            test: None,
        },
        &AlwaysApprove,
    )
    .await
    .unwrap();

    let out = configure_http(
        &vault,
        ConfigureHttpParams {
            r#type: "api_key",
            name: "svc",
            purpose: "test",
            remove: false,
            inject: None,
            allowed_hosts: Some(&json!(["api.example.com", "api2.example.com"])),
            proxy_only: None,
            test: None,
        },
        &AlwaysApprove,
    )
    .await
    .unwrap();
    let hosts: Vec<String> = out["http"]["allowed_hosts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        hosts,
        vec![
            "api.example.com".to_string(),
            "api2.example.com".to_string()
        ]
    );
}

#[tokio::test]
async fn removing_the_same_set_of_hosts_is_not_a_loosening_and_needs_no_confirmation() {
    let (_tmp, vault) = new_vault_with_credential();
    let inject = json!({"headers": {"Authorization": "Bearer {{value}}"}});
    configure_http(
        &vault,
        ConfigureHttpParams {
            r#type: "api_key",
            name: "svc",
            purpose: "test",
            remove: false,
            inject: Some(&inject),
            allowed_hosts: Some(&json!(["api.example.com", "api2.example.com"])),
            proxy_only: None,
            test: None,
        },
        &AlwaysApprove,
    )
    .await
    .unwrap();

    // Narrowing to a subset of already-allowed hosts: no NEW host is introduced, so a confirmer
    // that would reject must not even be consulted.
    let calls = Arc::new(AtomicUsize::new(0));
    let confirmer = FakeConfirmer {
        answer: false,
        calls: calls.clone(),
    };
    let out = configure_http(
        &vault,
        ConfigureHttpParams {
            r#type: "api_key",
            name: "svc",
            purpose: "test",
            remove: false,
            inject: None,
            allowed_hosts: Some(&json!(["api.example.com"])),
            proxy_only: None,
            test: None,
        },
        &confirmer,
    )
    .await
    .unwrap();
    assert_eq!(out["http"]["allowed_hosts"], json!(["api.example.com"]));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn removing_the_proxy_config_requires_confirmation() {
    let (_tmp, vault) = new_vault_with_credential();
    let inject = json!({"headers": {"Authorization": "Bearer {{value}}"}});
    configure_http(
        &vault,
        ConfigureHttpParams {
            r#type: "api_key",
            name: "svc",
            purpose: "test",
            remove: false,
            inject: Some(&inject),
            allowed_hosts: Some(&json!(["api.example.com"])),
            proxy_only: None,
            test: None,
        },
        &AlwaysApprove,
    )
    .await
    .unwrap();

    let calls = Arc::new(AtomicUsize::new(0));
    let confirmer = FakeConfirmer {
        answer: true,
        calls: calls.clone(),
    };
    let out = configure_http(
        &vault,
        ConfigureHttpParams {
            r#type: "api_key",
            name: "svc",
            purpose: "test",
            remove: true,
            inject: None,
            allowed_hosts: None,
            proxy_only: None,
            test: None,
        },
        &confirmer,
    )
    .await
    .unwrap();
    assert_eq!(out["http"], serde_json::Value::Null);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let (_, _, record) = vault.get_record("api_key", "svc").unwrap();
    assert!(record.http.is_none());
}

#[tokio::test]
async fn a_config_change_during_confirmation_is_detected_not_overwritten() {
    let (_tmp, vault) = new_vault_with_credential();
    let inject = json!({"headers": {"Authorization": "Bearer {{value}}"}});
    configure_http(
        &vault,
        ConfigureHttpParams {
            r#type: "api_key",
            name: "svc",
            purpose: "test",
            remove: false,
            inject: Some(&inject),
            allowed_hosts: Some(&json!(["api.example.com"])),
            proxy_only: None,
            test: None,
        },
        &AlwaysApprove,
    )
    .await
    .unwrap();

    // Simulate someone else changing the config concurrently, between reading `prev` and the
    // (approving) confirmation landing, by driving a confirmer that mutates the vault mid-dialog.
    struct SneakyConfirmer<'a> {
        vault: &'a Vault,
    }
    impl Confirmer for SneakyConfirmer<'_> {
        async fn confirm(&self, _message: &str, _ok_label: &str) -> bool {
            self.vault
                .update_http("api_key", "svc", |_rec| {
                    Some(kv_vault::HttpConfig {
                        inject: None,
                        allowed_hosts: vec!["sneaky.example.com".to_string()],
                        proxy_only: false,
                        test: None,
                    })
                })
                .unwrap();
            true
        }
    }
    let err = configure_http(
        &vault,
        ConfigureHttpParams {
            r#type: "api_key",
            name: "svc",
            purpose: "test",
            remove: false,
            inject: None,
            allowed_hosts: Some(&json!(["api.example.com", "api2.example.com"])),
            proxy_only: None,
            test: None,
        },
        &SneakyConfirmer { vault: &vault },
    )
    .await
    .unwrap_err();
    assert!(err.0.contains("重试") || err.0.to_lowercase().contains("retry"));

    // The sneaky concurrent write must survive untouched -- the stale confirmation must not overwrite it.
    let (_, _, record) = vault.get_record("api_key", "svc").unwrap();
    assert_eq!(
        record.http.clone().unwrap().allowed_hosts,
        vec!["sneaky.example.com".to_string()]
    );
}
