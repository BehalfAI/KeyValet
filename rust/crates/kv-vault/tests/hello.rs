//! Synthetic Hello providers test the portable vault format on clean macOS and Windows CI.
use base64::{engine::general_purpose::STANDARD, Engine};
use kv_vault::{
    EnclaveKey, EnclaveMetadata, HelloMetadata, MasterKey, MasterKeyProvider, Result, SetParams,
    Vault, VaultError,
};
use std::{cell::RefCell, path::PathBuf};
use zeroize::Zeroizing;

const RECOVERY: &str = "separate offline Windows test recovery phrase";

fn copy_private_fixture(source: &std::path::Path, destination: &std::path::Path) {
    std::fs::copy(source, destination).unwrap();
    // Windows copies file attributes, but a newly created file keeps its default DACL.
    // Copy the fixture's private DACL too, so the test reaches key recovery validation.
    #[cfg(windows)]
    unsafe {
        use std::os::windows::ffi::OsStrExt;
        use windows::core::{PCWSTR, PWSTR};
        use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL};
        use windows::Win32::Security::Authorization::{
            GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
        };
        use windows::Win32::Security::{
            ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR,
        };

        let source: Vec<u16> = source.as_os_str().encode_wide().chain([0]).collect();
        let destination: Vec<u16> = destination.as_os_str().encode_wide().chain([0]).collect();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let status = GetNamedSecurityInfoW(
            PCWSTR(source.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut descriptor,
        );
        struct Descriptor(*mut core::ffi::c_void);
        impl Drop for Descriptor {
            fn drop(&mut self) {
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(self.0 as _)));
                }
            }
        }
        let _descriptor = Descriptor(descriptor.0);
        assert_eq!(status, ERROR_SUCCESS);
        assert!(!dacl.is_null());
        let status = SetNamedSecurityInfoW(
            PWSTR(destination.as_ptr() as _),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        );
        assert_eq!(status, ERROR_SUCCESS);
    }
}

struct Hello(u8);
impl Hello {
    fn metadata(&self) -> EnclaveMetadata {
        EnclaveMetadata::windows_hello(
            &HelloMetadata {
                key_name: format!("keyvalet.vault.{:032x}", self.0),
                public_key: STANDARD.encode([self.0; 294]),
                tpm_backed: Some(true),
            },
            &[self.0; 32],
        )
        .unwrap()
    }
}
impl MasterKeyProvider for Hello {
    fn create(&self, _: &str) -> Result<EnclaveKey> {
        Ok(EnclaveKey {
            key: MasterKey::new([self.0; 32]),
            metadata: self.metadata(),
        })
    }
    fn unlock(&self, metadata: &EnclaveMetadata, _: &str) -> Result<MasterKey> {
        if *metadata != self.metadata() {
            return Err(VaultError("key unavailable".into()));
        }
        Ok(MasterKey::new([self.0; 32]))
    }
}

#[test]
fn hello_vault_unlock_recovery_rotation_and_provider_tampering() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("vault");
    let vault = Vault::new(&path);
    let old = "separate offline recovery words";
    let new = "a new separate recovery phrase";
    vault.initialize_enclave(&Hello(1), old, "test").unwrap();
    assert_eq!(vault.protection().unwrap().provider, "windows_hello");
    assert_eq!(vault.protection().unwrap().tpm_backed, Some(true));
    assert!(vault.protection().unwrap().device_binding);
    assert!(!path.join("master.key").exists());
    vault
        .set(SetParams {
            r#type: "api_key".into(),
            name: "example".into(),
            value: Some("synthetic-secret".into()),
            ..Default::default()
        })
        .unwrap();
    let reopened = Vault::new(&path);
    assert!(reopened.init_with_provider(&Hello(2), "test").is_err());
    assert!(reopened.get("api_key", "example").is_err());
    reopened.init_with_provider(&Hello(1), "test").unwrap();
    assert!(reopened.get("api_key", "example").unwrap().value == "synthetic-secret");
    reopened.rotate_enclave(&Hello(2), new, "test").unwrap();
    assert!(
        vault.get("api_key", "example").is_err(),
        "old session must be revoked"
    );
    let recovered = Vault::new(&path);
    assert!(recovered.open_recovery_read_only(old).is_err());
    assert_eq!(recovered.open_recovery_read_only(new).unwrap(), 1);
    assert!(recovered.delete("api_key", "example").is_err());
    recovered.recover_enclave(&Hello(3), new, "test").unwrap();
    recovered.init_with_provider(&Hello(3), "test").unwrap();
    let bytes = std::fs::read(path.join("vault.enc")).unwrap();
    let mut data: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    data["master_key"]["provider"] = serde_json::json!("secure_enclave");
    std::fs::write(path.join("vault.enc"), serde_json::to_vec(&data).unwrap()).unwrap();
    assert!(Vault::new(&path).protection().is_err());
    assert!(Vault::new(&path).open_recovery_read_only(new).is_err());
}

#[test]
fn hello_metadata_is_bounded_and_cannot_select_arbitrary_keys() {
    let valid = Hello(8).metadata();
    let (mut info, challenge) = valid.hello().unwrap();
    assert_eq!(valid.provider().unwrap().as_str(), "windows_hello");
    info.key_name = "another-app-key".into();
    assert!(EnclaveMetadata::windows_hello(&info, &challenge).is_err());
    let mut broken = valid.clone();
    broken.peer_public_key = STANDARD.encode([0u8; 31]);
    assert!(broken.decode().is_err());
    broken = valid;
    broken.version = 3;
    assert!(broken.decode().is_err());
}

#[derive(Clone, Copy)]
enum Failure {
    Create,
    Unlock,
    WrongRestoredKey,
}

struct ProbeHello {
    inner: Hello,
    failure: Failure,
    calls: RefCell<Vec<&'static str>>,
}
impl ProbeHello {
    fn new(failure: Failure) -> Self {
        Self {
            inner: Hello(2),
            failure,
            calls: RefCell::new(Vec::new()),
        }
    }
}
impl MasterKeyProvider for ProbeHello {
    fn create(&self, reason: &str) -> Result<EnclaveKey> {
        self.calls.borrow_mut().push("create");
        if matches!(self.failure, Failure::Create) {
            return Err(VaultError("synthetic Hello creation cancelled".into()));
        }
        self.inner.create(reason)
    }
    fn unlock(&self, metadata: &EnclaveMetadata, reason: &str) -> Result<MasterKey> {
        self.calls.borrow_mut().push("unlock");
        if matches!(self.failure, Failure::Unlock) {
            return Err(VaultError("synthetic Hello verification cancelled".into()));
        }
        let key = self.inner.unlock(metadata, reason)?;
        if matches!(self.failure, Failure::WrongRestoredKey) {
            Ok(MasterKey::new([99; 32]))
        } else {
            Ok(key)
        }
    }
}

fn hello_fixture() -> (tempfile::TempDir, Vault) {
    let temp = tempfile::tempdir().unwrap();
    let vault = Vault::new(temp.path().join("vault"));
    vault
        .initialize_enclave(&Hello(1), RECOVERY, "synthetic test setup")
        .unwrap();
    vault
        .set(SetParams {
            r#type: "api_key".into(),
            name: "example".into(),
            value: Some("synthetic-secret".into()),
            ..Default::default()
        })
        .unwrap();
    (temp, vault)
}

fn binding_files(vault: &Vault) -> Vec<PathBuf> {
    let mut paths: Vec<_> = std::fs::read_dir(&vault.dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("device-binding")
        })
        .collect();
    paths.sort();
    paths
}

#[test]
fn cancelled_or_inconsistent_hello_setup_never_persists_a_key_or_vault() {
    for failure in [Failure::Create, Failure::Unlock, Failure::WrongRestoredKey] {
        let temp = tempfile::tempdir().unwrap();
        let vault = Vault::new(temp.path().join("vault"));
        let provider = ProbeHello::new(failure);
        assert!(vault
            .initialize_enclave(&provider, RECOVERY, "test")
            .is_err());
        assert!(!vault.dir.join("vault.enc").exists());
        assert!(!vault.dir.join("master.key").exists());
        assert!(binding_files(&vault).is_empty());
        assert!(vault.list(None).is_err());
        assert_eq!(
            *provider.calls.borrow(),
            if matches!(failure, Failure::Create) {
                vec!["create"]
            } else {
                vec!["create", "unlock"]
            }
        );
        assert_eq!(vault.protection().unwrap().provider, "uninitialized");
    }
}

#[test]
fn setup_refuses_existing_hello_or_legacy_state_before_calling_hello() {
    let (_temp, vault) = hello_fixture();
    let bytes = std::fs::read(vault.dir.join("vault.enc")).unwrap();
    let bindings = binding_files(&vault);
    let provider = ProbeHello::new(Failure::Create);
    assert!(vault
        .initialize_enclave(&provider, RECOVERY, "test")
        .is_err());
    assert!(provider.calls.borrow().is_empty());
    assert_eq!(std::fs::read(vault.dir.join("vault.enc")).unwrap(), bytes);
    assert_eq!(binding_files(&vault), bindings);
    assert!(vault.get("api_key", "example").unwrap().value == "synthetic-secret");

    let temp = tempfile::tempdir().unwrap();
    let legacy = Vault::new(temp.path().join("legacy"));
    legacy.prepare().unwrap();
    std::fs::write(legacy.dir.join("master.key"), [7; 32]).unwrap();
    assert!(legacy
        .initialize_enclave(&provider, RECOVERY, "test")
        .is_err());
    assert!(provider.calls.borrow().is_empty());
    assert_eq!(
        std::fs::read(legacy.dir.join("master.key")).unwrap(),
        [7; 32]
    );
    assert!(!legacy.dir.join("vault.enc").exists());
}

#[test]
fn wrong_recovery_phrase_and_cancelled_creation_preserve_hello_vault_and_binding() {
    let (_temp, vault) = hello_fixture();
    let bytes = std::fs::read(vault.dir.join("vault.enc")).unwrap();
    let bindings = binding_files(&vault);
    let provider = ProbeHello::new(Failure::Create);
    let recovering = Vault::new(&vault.dir);
    assert!(recovering
        .recover_enclave(&provider, "wrong offline recovery phrase", "test")
        .is_err());
    assert!(provider.calls.borrow().is_empty());
    assert!(recovering.get("api_key", "example").is_err());
    assert!(recovering
        .recover_enclave(&provider, RECOVERY, "test")
        .is_err());
    assert_eq!(*provider.calls.borrow(), ["create"]);
    assert_eq!(std::fs::read(vault.dir.join("vault.enc")).unwrap(), bytes);
    assert_eq!(binding_files(&vault), bindings);
    assert!(!vault.dir.join("master.key").exists());
    assert!(vault.get("api_key", "example").unwrap().value == "synthetic-secret");
}

#[test]
fn failed_hello_verification_during_recovery_keeps_the_original_vault_usable() {
    let (_temp, vault) = hello_fixture();
    let bytes = std::fs::read(vault.dir.join("vault.enc")).unwrap();
    let bindings = binding_files(&vault);
    for failure in [Failure::Unlock, Failure::WrongRestoredKey] {
        let provider = ProbeHello::new(failure);
        let recovering = Vault::new(&vault.dir);
        assert!(recovering
            .recover_enclave(&provider, RECOVERY, "test")
            .is_err());
        assert_eq!(*provider.calls.borrow(), ["create", "unlock"]);
        assert!(recovering.get("api_key", "example").is_err());
        assert_eq!(std::fs::read(vault.dir.join("vault.enc")).unwrap(), bytes);
        assert_eq!(binding_files(&vault), bindings);
        recovering.init_with_provider(&Hello(1), "test").unwrap();
        assert!(recovering.get("api_key", "example").unwrap().value == "synthetic-secret");
    }
}

#[test]
fn cancelled_hello_rotation_and_short_passphrases_never_change_the_live_key() {
    let (_temp, vault) = hello_fixture();
    let bytes = std::fs::read(vault.dir.join("vault.enc")).unwrap();
    let bindings = binding_files(&vault);
    let provider = ProbeHello::new(Failure::Create);
    assert!(vault.rotate_enclave(&provider, "short", "test").is_err());
    assert!(provider.calls.borrow().is_empty());
    for failure in [Failure::Create, Failure::Unlock, Failure::WrongRestoredKey] {
        let provider = ProbeHello::new(failure);
        assert!(vault.rotate_enclave(&provider, RECOVERY, "test").is_err());
        assert_eq!(
            *provider.calls.borrow(),
            if matches!(failure, Failure::Create) {
                vec!["create"]
            } else {
                vec!["create", "unlock"]
            }
        );
        assert_eq!(std::fs::read(vault.dir.join("vault.enc")).unwrap(), bytes);
        assert_eq!(binding_files(&vault), bindings);
        assert!(vault.get("api_key", "example").unwrap().value == "synthetic-secret");
    }
    let reopened = Vault::new(&vault.dir);
    reopened.init_with_provider(&Hello(1), "test").unwrap();
    assert!(reopened.get("api_key", "example").unwrap().value == "synthetic-secret");
}

#[test]
fn damaged_or_missing_binding_is_rejected_before_any_hello_prompt() {
    let (_temp, vault) = hello_fixture();
    let before = std::fs::read(vault.dir.join("vault.enc")).unwrap();
    let binding = binding_files(&vault).pop().unwrap();
    let original = Zeroizing::new(std::fs::read(&binding).unwrap());
    let missing_backup = binding.with_extension("fixture-backup");
    for damage in [
        None,
        Some(vec![]),
        Some(vec![7; 31]),
        Some(vec![7; 33]),
        Some(vec![7; 32]),
    ] {
        match damage {
            Some(bytes) => std::fs::write(&binding, bytes).unwrap(),
            None => std::fs::rename(&binding, &missing_backup).unwrap(),
        }
        let provider = ProbeHello::new(Failure::Unlock);
        let reopened = Vault::new(&vault.dir);
        assert!(reopened.init_with_provider(&provider, "test").is_err());
        assert!(provider.calls.borrow().is_empty());
        assert!(reopened.get("api_key", "example").is_err());
        assert_eq!(std::fs::read(vault.dir.join("vault.enc")).unwrap(), before);
        assert!(!vault.dir.join("master.key").exists());
        if missing_backup.exists() {
            // Renaming back preserves both Unix mode bits and the Windows private DACL.
            std::fs::rename(&missing_backup, &binding).unwrap();
        } else {
            std::fs::write(&binding, &*original).unwrap();
        }
    }
    Vault::new(&vault.dir)
        .init_with_provider(&Hello(1), "test")
        .unwrap();
}

#[test]
fn copied_hello_vault_requires_binding_but_supports_read_only_recovery_and_rebind() {
    let (temp, original) = hello_fixture();
    let copied = Vault::new(temp.path().join("copy"));
    copied.prepare().unwrap();
    copy_private_fixture(
        &original.dir.join("vault.enc"),
        &copied.dir.join("vault.enc"),
    );
    let before = std::fs::read(copied.dir.join("vault.enc")).unwrap();
    let provider = ProbeHello::new(Failure::Unlock);
    assert!(copied.init_with_provider(&provider, "test").is_err());
    assert!(provider.calls.borrow().is_empty());
    assert_eq!(copied.open_recovery_read_only(RECOVERY).unwrap(), 1);
    assert!(copied.get("api_key", "example").unwrap().value == "synthetic-secret");
    assert!(copied.delete("api_key", "example").is_err());
    assert_eq!(std::fs::read(copied.dir.join("vault.enc")).unwrap(), before);
    assert!(binding_files(&copied).is_empty());
    assert!(!copied.dir.join("master.key").exists());
    copied.recover_enclave(&Hello(2), RECOVERY, "test").unwrap();
    let reopened = Vault::new(&copied.dir);
    reopened.init_with_provider(&Hello(2), "test").unwrap();
    assert!(reopened.get("api_key", "example").unwrap().value == "synthetic-secret");
    assert_eq!(binding_files(&copied).len(), 1);
    assert!(!copied.dir.join("master.key").exists());
    assert!(original.get("api_key", "example").unwrap().value == "synthetic-secret");
}

#[test]
fn valid_hello_metadata_edits_are_authenticated_even_if_a_backend_returns_the_old_key() {
    // Deliberately omit provider-side pinning: this isolates ciphertext authentication from
    // the real Hello backend's separate public-key/metadata verification.
    struct UnpinnedTestKey;
    impl MasterKeyProvider for UnpinnedTestKey {
        fn create(&self, _: &str) -> Result<EnclaveKey> {
            Err(VaultError("unused test operation".into()))
        }
        fn unlock(&self, _: &EnclaveMetadata, _: &str) -> Result<MasterKey> {
            Ok(MasterKey::new([1; 32]))
        }
    }
    let (_temp, vault) = hello_fixture();
    let path = vault.dir.join("vault.enc");
    let before = std::fs::read(&path).unwrap();
    let (info, challenge) = Hello(1).metadata().hello().unwrap();
    let mut renamed = info.clone();
    renamed.key_name = "keyvalet.vault.ffffffffffffffffffffffffffffffff".into();
    let mut attestation = info.clone();
    attestation.tpm_backed = None;
    for metadata in [
        EnclaveMetadata::windows_hello(&renamed, &challenge).unwrap(),
        EnclaveMetadata::windows_hello(&attestation, &challenge).unwrap(),
        EnclaveMetadata::windows_hello(&info, &[99; 32]).unwrap(),
    ] {
        let mut file: serde_json::Value = serde_json::from_slice(&before).unwrap();
        file["master_key"]["enclave"] = serde_json::json!(metadata);
        let changed = serde_json::to_vec(&file).unwrap();
        std::fs::write(&path, &changed).unwrap();
        let reopened = Vault::new(&vault.dir);
        assert_eq!(reopened.protection().unwrap().provider, "windows_hello");
        assert!(reopened
            .init_with_provider(&UnpinnedTestKey, "test")
            .is_err());
        assert!(reopened.get("api_key", "example").is_err());
        assert!(reopened.open_recovery_read_only(RECOVERY).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), changed);
        assert!(!vault.dir.join("master.key").exists());
        std::fs::write(&path, &before).unwrap();
    }
}
