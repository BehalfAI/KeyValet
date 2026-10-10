// Unix-only for now: these tests assert POSIX mode bits / unix-specific behaviors. The Windows
// equivalents (DACLs) land with W2/W3; the crate itself builds cross-platform.
#![cfg(unix)]
//! Integration tests mirroring the "Vault" describe block from the original TypeScript
//! implementation's test suite (now removed, having been superseded by this Rust rewrite -- that
//! suite was the behavioral spec this port was built against; see the rewrite plan's "Test
//! Strategy" section). Run with KEYVALET_LANG=zh so error-message assertions against the Chinese
//! text are deterministic regardless of this machine's locale.

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::{general_purpose::STANDARD, Engine};
use kv_vault::{HttpConfig, SetParams, Vault, VaultError};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;

fn new_vault() -> (tempfile::TempDir, Vault) {
    // `set_lang` is an unconditional overwrite, so every test calling this is safe to race on it:
    // whichever thread runs first or last, they're all setting the same target value ("zh"),
    // pinning it deterministically instead of falling back to this machine's ambient locale.
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
    (tmp, vault)
}

fn set(v: &Vault, ty: &str, name: &str, value: &str) -> kv_vault::SetResult {
    v.set(SetParams {
        r#type: ty.into(),
        name: name.into(),
        value: Some(value.into()),
        ..Default::default()
    })
    .unwrap()
}

#[test]
fn creates_directory_and_master_key_with_owner_only_permissions() {
    let (tmp, vault) = new_vault();
    let dir = tmp.path().join("vault");
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let key_path = dir.join("master.key");
    assert_eq!(
        std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(std::fs::read(&key_path).unwrap().len(), 32);
    let _ = vault; // keep the vault alive for the duration of the test
}

#[test]
fn creates_the_type_first_when_missing_then_writes_the_value() {
    let (_tmp, vault) = new_vault();
    assert!(!vault.type_exists("api_key").unwrap());
    let r1 = vault
        .set(SetParams {
            r#type: "api_key".into(),
            name: "openai".into(),
            value: Some("sk-1".into()),
            type_description: Some("API Key".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        (
            r1.r#type.as_str(),
            r1.name.as_str(),
            r1.type_created,
            r1.replaced
        ),
        ("api_key", "openai", true, false)
    );
    assert!(vault.type_exists("api_key").unwrap());
    assert_eq!(vault.list_types()[0].description, "API Key");

    let r2 = set(&vault, "api_key", "anthropic", "sk-2");
    assert!(!r2.type_created);
    assert_eq!(vault.list_types()[0].count, 2);
}

#[test]
fn existing_credential_needs_explicit_overwrite() {
    let (_tmp, vault) = new_vault();
    set(&vault, "password", "db", "a");
    assert!(vault
        .set(SetParams {
            r#type: "password".into(),
            name: "db".into(),
            value: Some("b".into()),
            ..Default::default()
        })
        .is_err());
    assert_eq!(vault.get("password", "db").unwrap().value, "a");
    let r = vault
        .set(SetParams {
            r#type: "password".into(),
            name: "db".into(),
            value: Some("b".into()),
            overwrite: true,
            ..Default::default()
        })
        .unwrap();
    assert!(r.replaced);
    assert_eq!(vault.get("password", "db").unwrap().value, "b");
}

#[test]
fn type_and_name_are_case_insensitive() {
    let (_tmp, vault) = new_vault();
    set(&vault, "API_Key", "OpenAI", "sk");
    assert_eq!(vault.get("api_key", "openai").unwrap().value, "sk");
    assert_eq!(vault.list_types().len(), 1);
}

#[test]
fn list_omits_values_and_preserves_attributes() {
    let (_tmp, vault) = new_vault();
    let mut attrs = HashMap::new();
    attrs.insert("username".to_string(), "me".to_string());
    vault
        .set(SetParams {
            r#type: "password".into(),
            name: "github".into(),
            value: Some("secret!".into()),
            attributes: Some(attrs.clone()),
            ..Default::default()
        })
        .unwrap();
    let items = vault.list(None).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].attributes, attrs);
}

#[test]
fn stored_on_disk_as_ciphertext() {
    let (tmp, vault) = new_vault();
    set(&vault, "api_key", "x", "PLAINTEXT-MARKER-12345");
    let raw = std::fs::read_to_string(tmp.path().join("vault").join("vault.enc")).unwrap();
    assert!(!raw.contains("PLAINTEXT-MARKER"));
    assert!(!raw.contains("api_key"));
}

#[test]
fn refuses_to_read_tampered_ciphertext() {
    let (tmp, vault) = new_vault();
    set(&vault, "api_key", "x", "v");
    let data_path = tmp.path().join("vault").join("vault.enc");
    let mut file: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&data_path).unwrap()).unwrap();
    let mut ct = STANDARD.decode(file["ct"].as_str().unwrap()).unwrap();
    ct[0] ^= 1;
    file["ct"] = serde_json::Value::String(STANDARD.encode(ct));
    std::fs::write(&data_path, serde_json::to_string(&file).unwrap()).unwrap();
    let err = vault.get("api_key", "x").unwrap_err();
    assert!(err.0.contains("解密失败"), "unexpected message: {}", err.0);
}

#[test]
fn refuses_to_operate_when_permissions_are_too_broad() {
    let (tmp, vault) = new_vault();
    let dir = tmp.path().join("vault");
    let key_path = dir.join("master.key");
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(Vault::new(&dir).init_legacy(), Err(VaultError(m)) if m.contains("权限过宽")));
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(Vault::new(&dir).init_legacy(), Err(VaultError(m)) if m.contains("权限过宽")));
    let _ = vault;
}

#[test]
fn a_symlinked_key_file_is_rejected() {
    let (tmp, vault) = new_vault();
    let dir = tmp.path().join("vault");
    let key_path = dir.join("master.key");
    let real = tmp.path().join("evil.key");
    std::fs::write(&real, [0u8; 32]).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::remove_file(&key_path).unwrap();
    std::os::unix::fs::symlink(&real, &key_path).unwrap();
    assert!(matches!(Vault::new(&dir).init_legacy(), Err(VaultError(m)) if m.contains("符号链接")));
    let _ = vault;
}

#[test]
fn names_that_look_like_prototype_properties_are_just_names() {
    let (_tmp, vault) = new_vault();
    assert!(!vault.type_exists("constructor").unwrap());
    set(&vault, "constructor", "tostring", "v");
    assert_eq!(vault.get("constructor", "tostring").unwrap().value, "v");
    assert!(vault.get("api_key", "constructor").is_err());
}

#[test]
fn rejects_invalid_names() {
    let (_tmp, vault) = new_vault();
    for bad in ["", "../x", "__proto__", "a b", "x/y", &"a".repeat(65)] {
        assert!(
            vault
                .set(SetParams {
                    r#type: bad.into(),
                    name: "n".into(),
                    value: Some("v".into()),
                    ..Default::default()
                })
                .is_err(),
            "{bad}"
        );
    }
    assert!(vault
        .set(SetParams {
            r#type: "t".into(),
            name: "n".into(),
            value: Some("".into()),
            ..Default::default()
        })
        .is_err());
}

#[test]
fn a_non_empty_type_cannot_be_deleted() {
    let (_tmp, vault) = new_vault();
    set(&vault, "token", "a", "v");
    let err = vault.delete_type("token").unwrap_err();
    assert!(
        err.0.contains("还有 1 个凭证"),
        "unexpected message: {}",
        err.0
    );
    vault.delete("token", "a").unwrap();
    vault.delete_type("token").unwrap();
    assert_eq!(vault.list_types().len(), 0);
}

#[test]
fn compatible_with_data_encrypted_before_the_rename() {
    let (tmp, vault) = new_vault();
    let dir = tmp.path().join("vault");
    let data_path = dir.join("vault.enc");
    let key_path = dir.join("master.key");
    let key_bytes = std::fs::read(&key_path).unwrap();

    // Simulate a vault written by the pre-rename (credential-mcp) version: an independent AES-GCM
    // writer under the legacy AAD, not a call into this crate's own encrypt path.
    let legacy_data = serde_json::json!({
        "version": 1,
        "types": {"api_key": {"description": "", "createdAt": "t", "updatedAt": "t"}},
        "credentials": {"api_key": {"old": {"value": "legacy-secret", "description": "", "attributes": {}, "createdAt": "t", "updatedAt": "t"}}},
    });
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let mut nonce_bytes = [0u8; 12];
    aes_gcm::aead::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let combined = cipher
        .encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: legacy_data.to_string().as_bytes(),
                aad: b"credential-mcp/vault/v1",
            },
        )
        .unwrap();
    let (ct, tag) = combined.split_at(combined.len() - 16);
    let file = serde_json::json!({"v": 1, "alg": "aes-256-gcm", "iv": STANDARD.encode(nonce_bytes), "tag": STANDARD.encode(tag), "ct": STANDARD.encode(ct)});
    std::fs::write(&data_path, serde_json::to_string(&file).unwrap()).unwrap();
    std::fs::set_permissions(&data_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let reopened = Vault::new(&dir);
    reopened.init_legacy().unwrap();
    assert_eq!(
        reopened.get("api_key", "old").unwrap().value,
        "legacy-secret"
    );

    vault
        .set(SetParams {
            r#type: "api_key".into(),
            name: "new".into(),
            value: Some("v".into()),
            ..Default::default()
        })
        .unwrap();
    let rewritten: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&data_path).unwrap()).unwrap();
    let ct2 = STANDARD.decode(rewritten["ct"].as_str().unwrap()).unwrap();
    let tag2 = STANDARD.decode(rewritten["tag"].as_str().unwrap()).unwrap();
    let nonce2 = STANDARD.decode(rewritten["iv"].as_str().unwrap()).unwrap();
    let mut combined2 = ct2;
    combined2.extend_from_slice(&tag2);
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&nonce2),
            aes_gcm::aead::Payload {
                msg: &combined2,
                aad: b"keyvalet/vault/v1",
            },
        )
        .unwrap();
    let plain: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(
        plain["credentials"]["api_key"]["old"]["value"], "legacy-secret",
        "old data is preserved and re-encrypted under the new identifier"
    );
}

#[test]
fn multiple_instances_read_and_write_the_same_vault() {
    let (tmp, vault) = new_vault();
    let dir = tmp.path().join("vault");
    let other = Vault::new(&dir);
    other.init_legacy().unwrap();
    set(&vault, "api_key", "a", "1");
    set(&other, "api_key", "b", "2");
    assert_eq!(vault.list(None).unwrap().len(), 2);
}

#[test]
fn http_config_round_trips_through_a_credential() {
    let (_tmp, vault) = new_vault();
    let mut headers = HashMap::new();
    headers.insert("Authorization".to_string(), "Bearer {{token}}".to_string());
    let http = HttpConfig {
        inject: Some(kv_vault::InjectRule {
            headers: Some(headers),
            query: None,
            basic: None,
        }),
        allowed_hosts: vec!["api.example.com".to_string()],
        proxy_only: false,
        test: None,
    };
    vault
        .set(SetParams {
            r#type: "token".into(),
            name: "svc".into(),
            value: Some("tok".into()),
            http: Some(http.clone()),
            ..Default::default()
        })
        .unwrap();
    let items = vault.list(None).unwrap();
    assert_eq!(items[0].http.as_ref().unwrap(), &http);
}
