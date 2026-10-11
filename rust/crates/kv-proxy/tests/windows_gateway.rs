//! Real TCP/SID authorization without an installed service, administrator token or Hello UI.
#![cfg(windows)]

use base64::{engine::general_purpose::STANDARD, Engine};
use kv_proxy::{
    gateway::Gateway,
    manage::{configure_http, ConfigureHttpParams},
};
use kv_vault::{
    EnclaveKey, EnclaveMetadata, HelloMetadata, MasterKey, MasterKeyProvider, Result, SetParams,
    Vault,
};
use serde_json::json;
use std::{sync::Arc, time::Duration};
use wiremock::{
    matchers::{header, method},
    Mock, MockServer, ResponseTemplate,
};

struct TestHello;
impl MasterKeyProvider for TestHello {
    fn create(&self, _: &str) -> Result<EnclaveKey> {
        Ok(EnclaveKey {
            key: MasterKey::new([7u8; 32]),
            metadata: EnclaveMetadata::windows_hello(
                &HelloMetadata {
                    key_name: format!("keyvalet.vault.{:032x}", 7),
                    public_key: STANDARD.encode([7u8; 294]),
                    tpm_backed: None,
                },
                &[7u8; 32],
            )?,
        })
    }
    fn unlock(&self, _: &EnclaveMetadata, _: &str) -> Result<MasterKey> {
        Ok(MasterKey::new([7u8; 32]))
    }
}
struct Approve;
impl kv_platform::Confirmer for Approve {
    async fn confirm(&self, _: &str, _: &str) -> bool {
        true
    }
}

#[tokio::test]
async fn gateway_checks_the_client_sid_before_injecting_a_credential() {
    kv_protocols::http::allow_insecure_loopback_for_tests(true);
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            kv_protocols::http::allow_insecure_loopback_for_tests(false);
        }
    }
    let _restore = Restore;
    let temp = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::new(temp.path().join("vault")));
    vault
        .initialize_enclave(&TestHello, "synthetic recovery words", "test")
        .unwrap();
    vault
        .set(SetParams {
            r#type: "api_key".into(),
            name: "svc".into(),
            value: Some("synthetic-private-key".into()),
            ..Default::default()
        })
        .unwrap();
    configure_http(
        &vault,
        ConfigureHttpParams {
            r#type: "api_key",
            name: "svc",
            purpose: "test",
            remove: false,
            inject: Some(&json!({"headers":{"Authorization":"Bearer {{value}}"}})),
            allowed_hosts: Some(&json!(["127.0.0.1"])),
            proxy_only: None,
            test: None,
        },
        &Approve,
    )
    .await
    .unwrap();
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(header("Authorization", "Bearer synthetic-private-key"))
        .respond_with(ResponseTemplate::new(200).set_body_string("safe-response"))
        .expect(1)
        .mount(&upstream)
        .await;
    let me = kv_platform::peer::self_identity().unwrap().sid;
    let allowed = Gateway::new(vault.clone(), Arc::new(|_| {}), Some(me.clone()));
    let opened = allowed.open("api_key", "svc", Some("test")).await.unwrap();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let url = |base: &str| format!("{base}/127.0.0.1:{}/v1/ping", upstream.address().port());
    let response = client
        .get(url(&opened.base))
        .bearer_auth(&opened.token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "safe-response");
    // A valid bearer token cannot override the wrong owner SID. This checks the real TCP
    // lookup rather than driving a fake peer resolver or requiring a second local account.
    let other = kv_platform::peer::sid_from_string("S-1-5-19").unwrap();
    assert!(!kv_platform::peer::sid_equal(&me, &other));
    let denied = Gateway::new(vault, Arc::new(|_| {}), Some(other));
    let opened = denied.open("api_key", "svc", Some("test")).await.unwrap();
    assert!(client
        .get(url(&opened.base))
        .bearer_auth(&opened.token)
        .send()
        .await
        .is_err());
    upstream.verify().await;
}
