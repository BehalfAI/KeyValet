//! Portable request policy; fake backends exercise every decision without an installed
//! service, desktop session or Windows Hello device. OS calls stay in the real backend.
use base64::{engine::general_purpose::STANDARD, Engine};
use kv_ipc::agent as wire;
use kv_vault::{EnclaveKey, EnclaveMetadata};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub type Result<T> = std::result::Result<T, String>;
pub type Reply = (
    Value,
    Option<(wire::EnclavePayload, usize)>,
    Option<EnclaveMetadata>,
);
pub const REQUEST_BUDGET: Duration = Duration::from_secs(120);

pub struct Budget(Instant);
impl Budget {
    pub fn new() -> Self {
        Self(Instant::now() + REQUEST_BUDGET)
    }
    pub fn remaining(&self, cap: Duration) -> Result<Duration> {
        self.0
            .checked_duration_since(Instant::now())
            .map(|remaining| remaining.min(cap))
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| "Windows Hello timed out".into())
    }
}

/// Own cleanup as soon as creation succeeds, including failures reading the new credential
/// or its public key. Only a complete usable key commits the creation.
pub struct CreationGuard<F: FnOnce()>(Option<F>);
impl<F: FnOnce()> CreationGuard<F> {
    pub fn new(cleanup: F) -> Self {
        Self(Some(cleanup))
    }
    pub fn commit(mut self) {
        self.0.take();
    }
}
impl<F: FnOnce()> Drop for CreationGuard<F> {
    fn drop(&mut self) {
        if let Some(cleanup) = self.0.take() {
            cleanup();
        }
    }
}

pub trait Backend {
    fn supported(&mut self, budget: &Budget) -> Result<bool>;
    fn confirm(&mut self, message: &str, label: &str, budget: &Budget) -> bool;
    fn create(&mut self, budget: &Budget) -> Result<EnclaveKey>;
    fn derive(&mut self, metadata: EnclaveMetadata, budget: &Budget) -> Result<EnclaveKey>;
    fn verify(&mut self, metadata: &EnclaveMetadata, budget: &Budget) -> Result<()>;
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
enum Request {
    Confirm {
        id: u64,
        message: String,
        ok_label: String,
    },
    Authenticate {
        id: u64,
        reason: String,
        #[serde(default)]
        cancel: String,
    },
    Enclave {
        id: u64,
        operation: String,
        reason: String,
        #[serde(default)]
        cancel: String,
        metadata: Option<EnclaveMetadata>,
    },
}
fn valid_text(text: &str) -> bool {
    text.len() <= 32 * 1024 && !text.contains('\0')
}

pub fn deny(id: u64, message: impl Into<String>) -> Reply {
    (
        wire::reply(
            id,
            &[("ok", json!(false)), ("error", json!(message.into()))],
        ),
        None,
        None,
    )
}

pub fn handle(
    request: &Value,
    active: Option<&EnclaveMetadata>,
    backend: &mut impl Backend,
) -> Reply {
    let id = request["id"].as_u64().unwrap_or(0);
    let request = match serde_json::from_value::<Request>(request.clone()) {
        Ok(request) => request,
        Err(_) => return deny(id, "invalid agent request"),
    };
    let budget = Budget::new();
    match request {
        Request::Confirm {
            id,
            message,
            ok_label,
        } => {
            if !valid_text(&message) || !valid_text(&ok_label) {
                return deny(id, "invalid confirmation text");
            }
            let approved = approve(active, &message, &ok_label, &budget, backend);
            (
                wire::reply(id, &[("confirmed", json!(approved))]),
                None,
                None,
            )
        }
        Request::Authenticate { id, reason, cancel } => {
            if !valid_text(&reason) || !valid_text(&cancel) {
                return deny(id, "invalid authentication text");
            }
            let approved = approve(
                active,
                &reason,
                &kv_i18n::t("验证并允许", "Verify and allow"),
                &budget,
                backend,
            );
            (
                wire::reply(
                    id,
                    &[(
                        "outcome",
                        json!(if approved { "approved" } else { "denied" }),
                    )],
                ),
                None,
                None,
            )
        }
        Request::Enclave {
            id,
            operation,
            reason,
            cancel,
            metadata,
        } => {
            if !valid_text(&reason) || !valid_text(&cancel) {
                return deny(id, "invalid hardware request text");
            }
            let metadata = match (operation.as_str(), metadata) {
                ("create", None) => None,
                ("derive", Some(metadata)) => {
                    if validate_metadata(&metadata).is_err() {
                        return deny(id, "invalid Windows Hello metadata");
                    }
                    Some(metadata)
                }
                _ => return deny(id, "invalid hardware operation"),
            };
            match backend.supported(&budget) {
                Ok(true) => (),
                Ok(false) => return deny(
                    id,
                    kv_i18n::t(
                        "请先在 Windows 设置中启用 Windows Hello；不会使用文件密钥",
                        "Enable Windows Hello in Windows Settings first; file keys are disabled",
                    ),
                ),
                Err(e) => return deny(id, e),
            }
            if !backend.confirm(
                &reason,
                &kv_i18n::t("使用 Windows Hello", "Use Windows Hello"),
                &budget,
            ) {
                return deny(id, "Windows Hello cancelled");
            }
            let expected = metadata.clone();
            let output = match metadata {
                Some(metadata) => backend.derive(metadata, &budget),
                None => backend.create(&budget),
            };
            match output {
                Ok(output)
                    if expected
                        .as_ref()
                        .is_some_and(|metadata| *metadata != output.metadata) =>
                {
                    deny(id, "Hello metadata changed during derivation")
                }
                Ok(output) => encode_output(id, output),
                Err(e) => deny(id, e),
            }
        }
    }
}

fn validate_metadata(metadata: &EnclaveMetadata) -> Result<()> {
    let (info, _) = metadata
        .hello()
        .map_err(|_| "invalid Hello metadata".to_owned())?;
    let public = STANDARD
        .decode(info.public_key)
        .map_err(|_| "invalid Hello public key".to_owned())?;
    crate::hello_crypto::public_key(&public)?;
    Ok(())
}

fn approve(
    active: Option<&EnclaveMetadata>,
    message: &str,
    label: &str,
    budget: &Budget,
    backend: &mut impl Backend,
) -> bool {
    active.is_some_and(|metadata| {
        validate_metadata(metadata).is_ok()
            && backend.confirm(message, label, budget)
            && backend.verify(metadata, budget).is_ok()
    })
}

fn encode_output(id: u64, output: EnclaveKey) -> Reply {
    if validate_metadata(&output.metadata).is_err() {
        return deny(id, "invalid Windows Hello output");
    }
    let metadata = match serde_json::to_vec(&output.metadata) {
        Ok(metadata) => metadata,
        Err(_) => return deny(id, "invalid Hello metadata"),
    };
    let len = 32 + metadata.len();
    if len > wire::MAX_ENCLAVE_PAYLOAD {
        return deny(id, "Hello metadata too large");
    }
    let mut payload: wire::EnclavePayload = Zeroizing::new([0; wire::MAX_ENCLAVE_PAYLOAD + 1]);
    payload[..32].copy_from_slice(&output.key[..]);
    payload[32..len].copy_from_slice(&metadata);
    (
        wire::reply(id, &[("ok", json!(true)), ("len", json!(len))]),
        Some((payload, len)),
        Some(output.metadata),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use kv_vault::{HelloMetadata, MasterKey};
    use std::{cell::Cell, sync::OnceLock};

    fn metadata() -> EnclaveMetadata {
        static METADATA: OnceLock<EnclaveMetadata> = OnceLock::new();
        METADATA
            .get_or_init(|| {
                let (_, public, challenge, _) = crate::hello_crypto::tests::fixture();
                EnclaveMetadata::windows_hello(
                    &HelloMetadata {
                        key_name: "keyvalet.vault.0123456789abcdef0123456789abcdef".into(),
                        public_key: STANDARD.encode(public),
                        tpm_backed: None,
                    },
                    &challenge,
                )
                .unwrap()
            })
            .clone()
    }
    struct Fake {
        calls: Vec<&'static str>,
        supported: bool,
        confirm: bool,
        failure: Option<&'static str>,
        result: EnclaveMetadata,
        budgets: Vec<Instant>,
        prompts: Vec<(String, String)>,
        keys: Vec<EnclaveMetadata>,
    }
    impl Default for Fake {
        fn default() -> Self {
            Self {
                calls: Vec::new(),
                supported: true,
                confirm: true,
                failure: None,
                result: metadata(),
                budgets: Vec::new(),
                prompts: Vec::new(),
                keys: Vec::new(),
            }
        }
    }
    impl Fake {
        fn call(&mut self, name: &'static str, budget: &Budget) -> Result<()> {
            self.calls.push(name);
            self.budgets.push(budget.0);
            if self.failure == Some(name) {
                Err("synthetic backend failure".into())
            } else {
                Ok(())
            }
        }
        fn output(&self) -> EnclaveKey {
            EnclaveKey {
                key: MasterKey::new([0xa7; 32]),
                metadata: self.result.clone(),
            }
        }
    }
    impl Backend for Fake {
        fn supported(&mut self, budget: &Budget) -> Result<bool> {
            self.call("supported", budget)?;
            Ok(self.supported)
        }
        fn confirm(&mut self, message: &str, label: &str, budget: &Budget) -> bool {
            self.prompts.push((message.into(), label.into()));
            self.call("confirm", budget).is_ok() && self.confirm
        }
        fn create(&mut self, budget: &Budget) -> Result<EnclaveKey> {
            self.call("create", budget)?;
            Ok(self.output())
        }
        fn derive(&mut self, metadata: EnclaveMetadata, budget: &Budget) -> Result<EnclaveKey> {
            self.keys.push(metadata);
            self.call("derive", budget)?;
            Ok(self.output())
        }
        fn verify(&mut self, metadata: &EnclaveMetadata, budget: &Budget) -> Result<()> {
            self.keys.push(metadata.clone());
            self.call("verify", budget)
        }
    }
    fn enclave(operation: &str, metadata: Option<EnclaveMetadata>) -> Value {
        wire::request(
            17,
            "enclave",
            &[
                ("operation", json!(operation)),
                ("reason", json!("unit test")),
                ("cancel", json!("Cancel")),
                ("metadata", json!(metadata)),
            ],
        )
    }
    fn assert_denied(reply: Reply) {
        assert_eq!(reply.0["ok"], false);
        assert!(reply.1.is_none());
        assert!(reply.2.is_none());
    }

    #[test]
    fn malformed_requests_never_call_the_backend() {
        let mut fake = Fake::default();
        for request in [
            Value::Null,
            json!({}),
            json!({"id":17,"op":"unknown"}),
            json!({"id":-1,"op":"confirm","message":"x","ok_label":"x"}),
            json!({"id":1.5,"op":"confirm","message":"x","ok_label":"x"}),
            json!({"op":"confirm","message":"x","ok_label":"x"}),
            json!({"id":17,"op":"confirm","message":false,"ok_label":"x"}),
            json!({"id":17,"op":"confirm","message":"x","ok_label":"x","environment":{}}),
            json!({"id":17,"op":"authenticate","reason":"x","cancel":null}),
            json!({"id":17,"op":"enclave","operation":"derive","reason":"x","metadata":{}}),
        ] {
            assert_denied(handle(&request, None, &mut fake));
        }
        assert!(fake.calls.is_empty());
    }

    #[test]
    fn invalid_operations_and_metadata_are_rejected_before_any_prompt() {
        let mut fake = Fake::default();
        let mut corrupt = metadata();
        corrupt.peer_public_key = STANDARD.encode([1u8; 31]);
        let mut malformed_public = metadata();
        let (mut info, challenge) = malformed_public.hello().unwrap();
        info.public_key = STANDARD.encode(b"not a public key");
        malformed_public = EnclaveMetadata::windows_hello(&info, &challenge).unwrap();
        for request in [
            enclave("delete", None),
            enclave("derive", None),
            enclave("create", Some(metadata())),
            enclave("derive", Some(corrupt)),
            enclave("derive", Some(malformed_public)),
            enclave("derive", Some(EnclaveMetadata::software(&[0; 32]))),
        ] {
            assert_denied(handle(&request, None, &mut fake));
        }
        assert!(fake.calls.is_empty());
    }

    #[test]
    fn oversized_or_nul_prompt_text_never_reaches_ui() {
        let mut fake = Fake::default();
        for reason in ["x".repeat(32 * 1024 + 1), "embedded\0nul".into()] {
            let mut request = enclave("create", None);
            request["reason"] = json!(reason);
            assert_denied(handle(&request, None, &mut fake));
            let request = json!({"id":17,"op":"authenticate","reason":reason});
            assert_denied(handle(&request, Some(&metadata()), &mut fake));
            let request = json!({"id":17,"op":"confirm","message":reason,"ok_label":"ok"});
            assert_denied(handle(&request, Some(&metadata()), &mut fake));
        }
        assert!(fake.calls.is_empty());
    }

    #[test]
    fn unavailable_hello_has_no_ui_or_software_fallback() {
        let mut fake = Fake {
            supported: false,
            ..Default::default()
        };
        assert_denied(handle(&enclave("create", None), None, &mut fake));
        assert_eq!(fake.calls, ["supported"]);
        fake.calls.clear();
        fake.failure = Some("supported");
        assert_denied(handle(&enclave("create", None), None, &mut fake));
        assert_eq!(fake.calls, ["supported"]);
    }

    #[test]
    fn cancelled_confirmation_never_creates_or_derives_keys() {
        for request in [enclave("create", None), enclave("derive", Some(metadata()))] {
            let mut fake = Fake {
                confirm: false,
                ..Default::default()
            };
            assert_denied(handle(&request, None, &mut fake));
            assert_eq!(fake.calls, ["supported", "confirm"]);
        }
    }

    #[test]
    fn hardware_failure_has_no_key_payload_or_new_active_key() {
        for operation in ["create", "derive"] {
            let mut fake = Fake {
                failure: Some(operation),
                ..Default::default()
            };
            let request = enclave(operation, (operation == "derive").then(metadata));
            assert_denied(handle(&request, None, &mut fake));
            assert_eq!(fake.calls, ["supported", "confirm", operation]);
        }
    }

    #[test]
    fn success_only_transmits_key_in_the_bounded_raw_payload() {
        for operation in ["create", "derive"] {
            let mut fake = Fake::default();
            let request = enclave(operation, (operation == "derive").then(metadata));
            let (header, payload, active) = handle(&request, None, &mut fake);
            assert_eq!(
                header,
                json!({"id":17,"ok":true,"len":32 + serde_json::to_vec(&metadata()).unwrap().len()})
            );
            let (bytes, len) = payload.unwrap();
            assert_eq!(&bytes[..32], &[0xa7; 32]);
            assert_eq!(
                serde_json::from_slice::<EnclaveMetadata>(&bytes[32..len]).unwrap(),
                metadata()
            );
            assert!(bytes[len..].iter().all(|byte| *byte == 0));
            assert_eq!(active, Some(metadata()));
            assert!(fake
                .budgets
                .iter()
                .all(|deadline| *deadline == fake.budgets[0]));
        }
    }

    #[test]
    fn backend_cannot_replace_pinned_metadata_during_derivation() {
        let mut fake = Fake::default();
        fake.result.peer_public_key = STANDARD.encode([99; 32]);
        assert_denied(handle(
            &enclave("derive", Some(metadata())),
            None,
            &mut fake,
        ));
    }

    #[test]
    fn corrupt_backend_output_is_not_returned_as_a_key() {
        let mut fake = Fake::default();
        fake.result.version = 999;
        assert_denied(handle(&enclave("create", None), None, &mut fake));
    }

    #[test]
    fn approvals_need_both_an_active_pinned_key_and_os_verification() {
        for request in [
            json!({"id":17,"op":"confirm","message":"test","ok_label":"ok"}),
            json!({"id":17,"op":"authenticate","reason":"test"}),
        ] {
            let mut fake = Fake::default();
            let reply = handle(&request, None, &mut fake);
            assert!(reply.0["confirmed"] == false || reply.0["outcome"] == "denied");
            assert!(fake.calls.is_empty());
            fake.confirm = false;
            let reply = handle(&request, Some(&metadata()), &mut fake);
            assert!(reply.0["confirmed"] == false || reply.0["outcome"] == "denied");
            assert_eq!(fake.calls, ["confirm"]);
            fake.calls.clear();
            fake.confirm = true;
            fake.failure = Some("verify");
            let reply = handle(&request, Some(&metadata()), &mut fake);
            assert!(reply.0["confirmed"] == false || reply.0["outcome"] == "denied");
            assert_eq!(fake.calls, ["confirm", "verify"]);
            fake.calls.clear();
            fake.failure = None;
            let reply = handle(&request, Some(&metadata()), &mut fake);
            assert!(reply.0["confirmed"] == true || reply.0["outcome"] == "approved");
            assert!(reply.1.is_none());
            assert!(reply.2.is_none());
            assert_eq!(fake.calls, ["confirm", "verify"]);
        }
    }

    #[test]
    fn corrupted_active_metadata_cannot_trigger_a_confirmation() {
        let mut fake = Fake::default();
        let mut corrupt = metadata();
        corrupt.key_blob.clear();
        let reply = handle(
            &json!({"id":17,"op":"confirm","message":"x","ok_label":"x"}),
            Some(&corrupt),
            &mut fake,
        );
        assert_eq!(reply.0["confirmed"], false);
        assert!(fake.calls.is_empty());
    }

    #[test]
    fn all_operations_share_a_budget_and_expired_budget_is_rejected() {
        let budget = Budget::new();
        assert!(budget.remaining(Duration::from_secs(90)).unwrap() <= Duration::from_secs(90));
        assert!(budget.remaining(Duration::from_secs(300)).unwrap() <= REQUEST_BUDGET);
        assert!(Budget(Instant::now() - Duration::from_secs(1))
            .remaining(Duration::from_secs(1))
            .is_err());
        assert!(Budget(Instant::now()).remaining(Duration::ZERO).is_err());
    }

    #[test]
    fn failed_creation_cleanup_runs_on_every_early_return_and_unwind() {
        let cleaned = Cell::new(0);
        for failure_stage in 0..4 {
            let result: Result<()> = (|| {
                let guard = CreationGuard::new(|| cleaned.set(cleaned.get() + 1));
                for stage in 0..4 {
                    if stage == failure_stage {
                        return Err("synthetic failure".into());
                    }
                }
                guard.commit();
                Ok(())
            })();
            assert!(result.is_err());
        }
        assert_eq!(cleaned.get(), 4);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = CreationGuard::new(|| cleaned.set(cleaned.get() + 1));
            panic!("synthetic backend panic");
        }));
        assert!(result.is_err());
        assert_eq!(cleaned.get(), 5);
    }

    #[test]
    fn successful_creation_commits_without_deleting_the_key() {
        let cleaned = Cell::new(false);
        CreationGuard::new(|| cleaned.set(true)).commit();
        assert!(!cleaned.get());
    }

    #[test]
    fn every_prompt_field_rejects_nul_and_oversized_utf8_before_any_backend_call() {
        let requests = [
            (
                json!({"id":17,"op":"confirm","message":"test","ok_label":"OK"}),
                "ok_label",
            ),
            (
                json!({"id":17,"op":"authenticate","reason":"test","cancel":"Cancel"}),
                "cancel",
            ),
            (enclave("create", None), "cancel"),
            (enclave("derive", Some(metadata())), "cancel"),
        ];
        for (request, field) in requests {
            for invalid in [
                "embedded\0nul".to_owned(),
                "x".repeat(32 * 1024 + 1),
                "中".repeat(10_923),
            ] {
                let mut request = request.clone();
                request[field] = json!(invalid);
                let mut backend = Fake::default();
                let reply = handle(&request, Some(&metadata()), &mut backend);
                assert_eq!(reply.0["id"], 17);
                assert_denied(reply);
                assert!(backend.calls.is_empty());
                assert!(backend.prompts.is_empty());
            }
        }
    }

    #[test]
    fn maximum_size_utf8_confirmation_reaches_the_backend_verbatim() {
        let message = "中".repeat(10_922) + "ab";
        assert_eq!(message.len(), 32 * 1024);
        let mut backend = Fake::default();
        let reply = handle(
            &json!({"id":17,"op":"confirm","message":message,"ok_label":"允许"}),
            Some(&metadata()),
            &mut backend,
        );
        assert_eq!(reply.0, json!({"id":17,"confirmed":true}));
        assert_eq!(backend.prompts, [(message, "允许".into())]);
        assert_eq!(backend.keys, [metadata()]);
        assert!(reply.1.is_none());
        assert!(reply.2.is_none());
    }

    #[test]
    fn failed_purpose_dialog_never_reaches_hello_or_returns_key_material() {
        for request in [
            json!({"id":17,"op":"confirm","message":"test","ok_label":"OK"}),
            json!({"id":17,"op":"authenticate","reason":"test"}),
            enclave("create", None),
            enclave("derive", Some(metadata())),
        ] {
            let mut backend = Fake {
                failure: Some("confirm"),
                ..Default::default()
            };
            let reply = handle(&request, Some(&metadata()), &mut backend);
            assert!(
                reply.0["confirmed"] == false
                    || reply.0["outcome"] == "denied"
                    || reply.0["ok"] == false
            );
            assert!(reply.1.is_none());
            assert!(reply.2.is_none());
            assert_eq!(backend.calls.last(), Some(&"confirm"));
            assert!(backend.keys.is_empty());
        }
    }

    #[test]
    fn derivation_cannot_substitute_key_name_challenge_or_attestation_metadata() {
        let original = metadata();
        let (info, challenge) = original.hello().unwrap();
        let mut renamed = info.clone();
        renamed.key_name = "keyvalet.vault.ffffffffffffffffffffffffffffffff".into();
        let mut attestation = info.clone();
        attestation.tpm_backed = Some(true);
        for replacement in [
            EnclaveMetadata::windows_hello(&renamed, &challenge).unwrap(),
            EnclaveMetadata::windows_hello(&attestation, &challenge).unwrap(),
            EnclaveMetadata::windows_hello(&info, &[99; 32]).unwrap(),
        ] {
            assert_ne!(replacement, original);
            validate_metadata(&replacement).unwrap();
            let mut backend = Fake {
                result: replacement,
                ..Default::default()
            };
            assert_denied(handle(
                &enclave("derive", Some(original.clone())),
                None,
                &mut backend,
            ));
            assert_eq!(backend.keys.as_slice(), std::slice::from_ref(&original));
        }
    }

    #[test]
    fn malformed_backend_public_key_cannot_become_an_active_hello_key() {
        let (mut info, challenge) = metadata().hello().unwrap();
        info.public_key = STANDARD.encode(b"synthetic non-DER public key");
        let mut backend = Fake {
            result: EnclaveMetadata::windows_hello(&info, &challenge).unwrap(),
            ..Default::default()
        };
        assert_denied(handle(&enclave("create", None), None, &mut backend));
        assert_eq!(backend.calls, ["supported", "confirm", "create"]);
    }

    #[test]
    fn approvals_use_the_requested_purpose_and_exact_active_key() {
        let active = metadata();
        let purpose = "访问项目：C:\\项目\n用途：调用 \"example\"";
        for request in [
            json!({"id":17,"op":"confirm","message":purpose,"ok_label":"允许"}),
            json!({"id":17,"op":"authenticate","reason":purpose}),
        ] {
            let mut backend = Fake::default();
            backend.result.peer_public_key = STANDARD.encode([99; 32]);
            let reply = handle(&request, Some(&active), &mut backend);
            assert!(reply.0["confirmed"] == true || reply.0["outcome"] == "approved");
            assert_eq!(backend.prompts[0].0, purpose);
            assert_eq!(backend.keys.as_slice(), std::slice::from_ref(&active));
            assert_eq!(backend.calls, ["confirm", "verify"]);
            assert!(backend
                .budgets
                .iter()
                .all(|deadline| *deadline == backend.budgets[0]));
            assert!(reply.1.is_none());
            assert!(reply.2.is_none());
        }
    }

    #[test]
    fn reply_ids_are_preserved_at_both_u64_limits_on_success_and_failure() {
        for id in [0, u64::MAX] {
            let mut request = enclave("create", None);
            request["id"] = json!(id);
            for supported in [true, false] {
                let mut backend = Fake {
                    supported,
                    ..Default::default()
                };
                let reply = handle(&request, None, &mut backend);
                assert_eq!(reply.0["id"].as_u64(), Some(id));
                assert_eq!(reply.0["ok"], supported);
                assert_eq!(reply.1.is_some(), supported);
                assert_eq!(reply.2.is_some(), supported);
            }
            request["op"] = json!("unknown");
            let mut backend = Fake::default();
            let reply = handle(&request, None, &mut backend);
            assert_eq!(reply.0["id"].as_u64(), Some(id));
            assert_denied(reply);
            assert!(backend.calls.is_empty());
        }
    }

    #[test]
    fn invalid_active_public_key_and_wrong_provider_deny_both_approval_operations() {
        let (mut info, challenge) = metadata().hello().unwrap();
        info.public_key = STANDARD.encode(b"invalid key");
        let malformed = EnclaveMetadata::windows_hello(&info, &challenge).unwrap();
        for active in [malformed, EnclaveMetadata::software(&[42; 32])] {
            for request in [
                json!({"id":17,"op":"confirm","message":"test","ok_label":"OK"}),
                json!({"id":17,"op":"authenticate","reason":"test"}),
            ] {
                let mut backend = Fake::default();
                let reply = handle(&request, Some(&active), &mut backend);
                assert!(reply.0["confirmed"] == false || reply.0["outcome"] == "denied");
                assert!(reply.1.is_none());
                assert!(reply.2.is_none());
                assert!(backend.calls.is_empty());
            }
        }
    }
}
