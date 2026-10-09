//! Synthetic providers exercise rotation and recovery without hardware or a real vault.
use base64::{engine::general_purpose::STANDARD, Engine};
use kv_vault::{
    EnclaveKey, EnclaveMetadata, MasterKey, MasterKeyProvider, Result, SetParams, Vault,
    VaultError, WrappedMasterKey,
};
use std::{cell::Cell, os::unix::fs::PermissionsExt};

const PASSWORD: &str = "a separate offline recovery passphrase";

struct Hardware {
    identity: u8,
    fail_create: Cell<bool>,
    fail_unlock: Cell<bool>,
    creates: Cell<usize>,
    unlocks: Cell<usize>,
}

impl Hardware {
    fn new(identity: u8) -> Self {
        Self {
            identity,
            fail_create: Cell::new(false),
            fail_unlock: Cell::new(false),
            creates: Cell::new(0),
            unlocks: Cell::new(0),
        }
    }
    fn metadata(&self) -> EnclaveMetadata {
        let mut peer = [self.identity; 65];
        peer[0] = 4;
        EnclaveMetadata {
            version: 1,
            key_blob: STANDARD.encode([self.identity]),
            peer_public_key: STANDARD.encode(peer),
        }
    }
}

impl MasterKeyProvider for Hardware {
    fn create(&self, _reason: &str) -> Result<EnclaveKey> {
        self.creates.set(self.creates.get() + 1);
        if self.fail_create.get() {
            return Err(VaultError::new("已取消", "Cancelled"));
        }
        Ok(EnclaveKey {
            key: MasterKey::new([self.identity; 32]),
            metadata: self.metadata(),
        })
    }
    fn unlock(&self, metadata: &EnclaveMetadata, _reason: &str) -> Result<MasterKey> {
        self.unlocks.set(self.unlocks.get() + 1);
        if self.fail_unlock.get() || metadata != &self.metadata() {
            return Err(VaultError::new(
                "设备密钥不可用或已取消",
                "Device key unavailable or cancelled",
            ));
        }
        Ok(MasterKey::new([self.identity; 32]))
    }
}

fn fixture() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().unwrap();
    let vault = Vault::new(tmp.path().join("vault"));
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
            name: "example".into(),
            value: Some("test-secret-never-on-disk".into()),
            ..Default::default()
        })
        .unwrap();
    (tmp, vault)
}

#[test]
fn preparing_a_helper_session_does_not_create_or_load_a_master_key() {
    let tmp = tempfile::tempdir().unwrap();
    let vault = Vault::new(tmp.path().join("vault"));
    vault.prepare().unwrap();
    assert!(!vault.dir.join("master.key").exists());
    assert!(!vault.dir.join("vault.enc").exists());
    assert!(vault.list(None).is_err());
}

#[test]
fn normal_sessions_reject_legacy_and_uninitialized_vaults_without_creating_file_keys() {
    let (_tmp, legacy) = fixture();
    let hardware = Hardware::new(82);
    let bytes = std::fs::read(legacy.dir.join("vault.enc")).unwrap();
    let reopened = Vault::new(&legacy.dir);
    assert!(reopened.init_with_provider(&hardware, "test").is_err());
    assert!(reopened.get("api_key", "example").is_err());
    assert_eq!(std::fs::read(legacy.dir.join("vault.enc")).unwrap(), bytes);
    assert_eq!(legacy.protection().unwrap().provider, "migration_required");
    let tmp = tempfile::tempdir().unwrap();
    let fresh = Vault::new(tmp.path().join("vault"));
    assert!(fresh.init_with_provider(&hardware, "test").is_err());
    assert_eq!(fresh.protection().unwrap().provider, "uninitialized");
    assert!(!fresh.dir.join("master.key").exists());
    assert!(fresh.init_legacy().is_err());
    assert!(!fresh.dir.join("master.key").exists());
    assert_eq!(hardware.creates.get(), 0);
    assert_eq!(hardware.unlocks.get(), 0);
}

#[test]
fn fresh_vault_initializes_directly_with_hardware_and_never_overwrites_existing_data() {
    let tmp = tempfile::tempdir().unwrap();
    let vault = Vault::new(tmp.path().join("vault"));
    let hardware = Hardware::new(83);
    hardware.fail_unlock.set(true);
    assert!(vault
        .initialize_enclave(&hardware, PASSWORD, "test")
        .is_err());
    assert!(!vault.dir.join("master.key").exists());
    assert!(!vault.dir.join("vault.enc").exists());
    hardware.fail_unlock.set(false);
    vault
        .initialize_enclave(&hardware, PASSWORD, "test")
        .unwrap();
    assert_eq!(vault.protection().unwrap().provider, "secure_enclave");
    assert!(vault.protection().unwrap().hardware_required);
    assert!(!vault.dir.join("master.key").exists());
    assert!(vault.list(None).unwrap().is_empty());
    let bytes = std::fs::read(vault.dir.join("vault.enc")).unwrap();
    assert!(vault
        .initialize_enclave(&hardware, PASSWORD, "test")
        .is_err());
    assert_eq!(bytes, std::fs::read(vault.dir.join("vault.enc")).unwrap());
    let reopened = Vault::new(&vault.dir);
    reopened.init_with_provider(&hardware, "test").unwrap();
    let (_tmp, legacy) = fixture();
    assert!(legacy
        .initialize_enclave(&hardware, PASSWORD, "test")
        .is_err());
    legacy.get("api_key", "example").unwrap();
}

struct ConcurrentWrite<'a> {
    vault: &'a Vault,
    hardware: Hardware,
}

impl MasterKeyProvider for ConcurrentWrite<'_> {
    fn create(&self, reason: &str) -> Result<EnclaveKey> {
        // Models another session writing while a system authentication prompt is open.
        self.vault.set(SetParams {
            r#type: "api_key".into(),
            name: "example".into(),
            value: Some("concurrent-update".into()),
            overwrite: true,
            ..Default::default()
        })?;
        self.hardware.create(reason)
    }
    fn unlock(&self, metadata: &EnclaveMetadata, reason: &str) -> Result<MasterKey> {
        self.hardware.unlock(metadata, reason)
    }
}

#[test]
fn writes_during_prompts_are_preserved_and_recovery_refuses_a_changed_snapshot() {
    let (_tmp, vault) = fixture();
    let migrating = ConcurrentWrite {
        vault: &vault,
        hardware: Hardware::new(80),
    };
    vault
        .migrate_to_enclave(&migrating, PASSWORD, "test")
        .unwrap();
    assert_eq!(
        vault.get("api_key", "example").unwrap().value,
        "concurrent-update"
    );
    vault
        .set(SetParams {
            r#type: "api_key".into(),
            name: "example".into(),
            value: Some("before-recovery".into()),
            overwrite: true,
            ..Default::default()
        })
        .unwrap();
    let racing = ConcurrentWrite {
        vault: &vault,
        hardware: Hardware::new(81),
    };
    let recovered = Vault::new(&vault.dir);
    assert!(recovered
        .recover_enclave(&racing, PASSWORD, "test")
        .is_err());
    assert_eq!(
        vault.get("api_key", "example").unwrap().value,
        "concurrent-update"
    );
    assert!(Vault::new(&vault.dir)
        .init_with_provider(&racing.hardware, "test")
        .is_err());
    Vault::new(&vault.dir)
        .init_with_provider(&migrating.hardware, "test")
        .unwrap();
}

#[test]
fn migration_rotates_key_preserves_secrets_and_reloads_with_one_hardware_unlock() {
    let (_tmp, vault) = fixture();
    let hardware = Hardware::new(91);
    let stale = Vault::new(&vault.dir);
    stale.init_legacy().unwrap();
    let old_key = std::fs::read(vault.dir.join("master.key")).unwrap();
    vault
        .migrate_to_enclave(&hardware, PASSWORD, "test")
        .unwrap();
    let status = vault.protection().unwrap();
    assert_eq!(status.provider, "secure_enclave");
    assert!(status.recovery_configured);
    assert!(!status.legacy_key_present);
    assert!(!status.migration_backup_present);
    let bytes = std::fs::read(vault.dir.join("vault.enc")).unwrap();
    // Migration no longer keeps a byte-identical snapshot of the new vault.
    assert!(!vault.dir.join("vault.migration-backup.enc").exists());
    assert!(!String::from_utf8_lossy(&bytes).contains("test-secret-never-on-disk"));
    assert!(!bytes.windows(32).any(|window| window == old_key));
    assert_eq!(
        vault.get("api_key", "example").unwrap().value,
        "test-secret-never-on-disk"
    );
    assert!(stale
        .set(SetParams {
            r#type: "api_key".into(),
            name: "stale".into(),
            value: Some("lost-update".into()),
            ..Default::default()
        })
        .is_err());
    assert_eq!(bytes, std::fs::read(vault.dir.join("vault.enc")).unwrap());
    let reopened = Vault::new(&vault.dir);
    let before = hardware.unlocks.get();
    reopened.init_with_provider(&hardware, "test").unwrap();
    reopened.get("api_key", "example").unwrap();
    reopened.list(None).unwrap();
    assert_eq!(hardware.unlocks.get(), before + 1);
    assert!(Vault::new(&vault.dir).init_legacy().is_err());
}

#[test]
fn cancelled_creation_or_failed_restoration_never_touches_the_original_vault() {
    let (_tmp, vault) = fixture();
    let hardware = Hardware::new(92);
    let bytes = std::fs::read(vault.dir.join("vault.enc")).unwrap();
    let key = std::fs::read(vault.dir.join("master.key")).unwrap();
    hardware.fail_create.set(true);
    assert!(vault
        .migrate_to_enclave(&hardware, PASSWORD, "test")
        .is_err());
    hardware.fail_create.set(false);
    hardware.fail_unlock.set(true);
    assert!(vault
        .migrate_to_enclave(&hardware, PASSWORD, "test")
        .is_err());
    assert_eq!(bytes, std::fs::read(vault.dir.join("vault.enc")).unwrap());
    assert_eq!(key, std::fs::read(vault.dir.join("master.key")).unwrap());
    assert!(!vault.dir.join("vault.migration-backup.enc").exists());
    assert_eq!(
        vault.get("api_key", "example").unwrap().value,
        "test-secret-never-on-disk"
    );
}

#[test]
fn a_leftover_file_key_never_becomes_a_hardware_fallback() {
    let (_tmp, vault) = fixture();
    let hardware = Hardware::new(93);
    let old_key = std::fs::read(vault.dir.join("master.key")).unwrap();
    vault
        .migrate_to_enclave(&hardware, PASSWORD, "test")
        .unwrap();
    let key_path = vault.dir.join("master.key");
    std::fs::write(&key_path, old_key).unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(vault.protection().unwrap().legacy_key_present);
    hardware.fail_unlock.set(true);
    let reopened = Vault::new(&vault.dir);
    assert!(reopened.init_with_provider(&hardware, "test").is_err());
    assert!(reopened.get("api_key", "example").is_err());
    assert!(reopened.init_legacy().is_err());
    assert!(key_path.exists());
    hardware.fail_unlock.set(false);
    reopened.init_with_provider(&hardware, "test").unwrap();
    reopened.remove_legacy_key().unwrap();
    assert!(!key_path.exists());
}

#[test]
fn password_recovery_rebinds_to_new_device_and_invalidates_old_sessions() {
    let (_tmp, vault) = fixture();
    let first = Hardware::new(94);
    vault.migrate_to_enclave(&first, PASSWORD, "test").unwrap();
    let second = Hardware::new(95);
    let recovered = Vault::new(&vault.dir);
    assert!(recovered.init_with_provider(&second, "test").is_err());
    recovered
        .recover_enclave(&second, PASSWORD, "test")
        .unwrap();
    assert_eq!(
        recovered.get("api_key", "example").unwrap().value,
        "test-secret-never-on-disk"
    );
    assert!(vault.get("api_key", "example").is_err());
    assert!(Vault::new(&vault.dir)
        .init_with_provider(&first, "test")
        .is_err());
    Vault::new(&vault.dir)
        .init_with_provider(&second, "test")
        .unwrap();
}

#[test]
fn wrong_password_and_cancelled_recovery_leave_ciphertext_unchanged() {
    let (_tmp, vault) = fixture();
    let first = Hardware::new(96);
    vault.migrate_to_enclave(&first, PASSWORD, "test").unwrap();
    let bytes = std::fs::read(vault.dir.join("vault.enc")).unwrap();
    let second = Hardware::new(97);
    let recovered = Vault::new(&vault.dir);
    assert!(recovered
        .recover_enclave(&second, "wrong password", "test")
        .is_err());
    assert_eq!(second.creates.get(), 0);
    second.fail_create.set(true);
    assert!(recovered
        .recover_enclave(&second, PASSWORD, "test")
        .is_err());
    assert_eq!(bytes, std::fs::read(vault.dir.join("vault.enc")).unwrap());
    vault.get("api_key", "example").unwrap();
}

#[test]
fn metadata_is_authenticated_and_malformed_metadata_never_prompts_or_creates_a_file_key() {
    let (_tmp, vault) = fixture();
    let hardware = Hardware::new(98);
    vault
        .migrate_to_enclave(&hardware, PASSWORD, "test")
        .unwrap();
    let path = vault.dir.join("vault.enc");
    let bytes = std::fs::read(&path).unwrap();
    let mut file: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    file["master_key"]["recovery"]["salt"] = serde_json::json!(STANDARD.encode([8u8; 16]));
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    let reopened = Vault::new(&vault.dir);
    assert!(reopened.init_with_provider(&hardware, "test").is_err());
    assert!(reopened.get("api_key", "example").is_err());
    file["master_key"]["enclave"]["version"] = serde_json::json!(2);
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    let before = hardware.unlocks.get();
    assert!(reopened.init_with_provider(&hardware, "test").is_err());
    assert_eq!(hardware.unlocks.get(), before);
    assert!(!vault.dir.join("master.key").exists());
    file.as_object_mut().unwrap().remove("master_key");
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    assert!(reopened.init_legacy().is_err());
    assert!(!vault.dir.join("master.key").exists());
}

#[test]
fn invalid_password_is_rejected_before_authentication_and_migration_removes_a_stale_backup() {
    let (_tmp, vault) = fixture();
    let hardware = Hardware::new(99);
    assert!(vault
        .migrate_to_enclave(&hardware, "short", "test")
        .is_err());
    assert_eq!(hardware.creates.get(), 0);
    let path = vault.dir.join("vault.migration-backup.enc");
    std::fs::write(&path, b"existing backup").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(vault.protection().unwrap().migration_backup_present);
    vault
        .migrate_to_enclave(&hardware, PASSWORD, "test")
        .unwrap();
    assert!(!path.exists());
    assert!(!vault.protection().unwrap().migration_backup_present);
}

#[test]
fn rotation_removes_a_stale_migration_backup() {
    let (_tmp, vault) = fixture();
    let first = Hardware::new(96);
    vault.migrate_to_enclave(&first, PASSWORD, "test").unwrap();
    let path = vault.dir.join("vault.migration-backup.enc");
    std::fs::write(&path, b"stale snapshot").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(vault.protection().unwrap().migration_backup_present);
    vault
        .rotate_enclave(&Hardware::new(97), "a new recovery passphrase", "test")
        .unwrap();
    assert!(!path.exists());
    assert!(!vault.protection().unwrap().migration_backup_present);
}

#[test]
fn missing_legacy_key_is_an_error_without_creating_a_replacement() {
    let (_tmp, vault) = fixture();
    let path = vault.dir.join("master.key");
    std::fs::remove_file(&path).unwrap();
    assert!(Vault::new(&vault.dir).init_legacy().is_err());
    assert!(!path.exists());
}

#[test]
fn recovery_wrapping_rejects_tampering_and_unsupported_versions() {
    let mut wrapped = WrappedMasterKey::wrap(&[42u8; 32], PASSWORD).unwrap();
    assert_eq!(*wrapped.open(PASSWORD).unwrap(), [42u8; 32]);
    let mut ct = STANDARD.decode(&wrapped.ciphertext).unwrap();
    ct[0] ^= 1;
    wrapped.ciphertext = STANDARD.encode(ct);
    assert!(wrapped.open(PASSWORD).is_err());
    wrapped.version = 2;
    assert!(wrapped.open(PASSWORD).is_err());
}

#[test]
fn recovery_passphrase_reads_without_hardware_and_never_writes() {
    let (_tmp, vault) = fixture();
    let hardware = Hardware::new(100);
    vault
        .migrate_to_enclave(&hardware, PASSWORD, "test")
        .unwrap();
    let path = vault.dir.join("vault.enc");
    let bytes = std::fs::read(&path).unwrap();
    let (creates, unlocks) = (hardware.creates.get(), hardware.unlocks.get());
    let emergency = Vault::new(&vault.dir);
    assert!(emergency
        .open_recovery_read_only("wrong recovery passphrase")
        .is_err());
    assert!(emergency.get("api_key", "example").is_err());
    assert_eq!(emergency.open_recovery_read_only(PASSWORD).unwrap(), 1);
    assert_eq!(
        emergency.get("api_key", "example").unwrap().value,
        "test-secret-never-on-disk"
    );
    assert_eq!(emergency.list(None).unwrap().len(), 1);
    assert!(emergency
        .set(SetParams {
            r#type: "api_key".into(),
            name: "added".into(),
            value: Some("must-not-be-written".into()),
            ..Default::default()
        })
        .is_err());
    assert!(emergency.delete("api_key", "example").is_err());
    assert!(emergency.remove_legacy_key().is_err());
    assert_eq!(bytes, std::fs::read(&path).unwrap());
    assert_eq!(hardware.creates.get(), creates);
    assert_eq!(hardware.unlocks.get(), unlocks);
    // A later hardware unlock of the same handle restores normal operation.
    emergency.init_with_provider(&hardware, "test").unwrap();
    emergency
        .set(SetParams {
            r#type: "api_key".into(),
            name: "added".into(),
            value: Some("written-after-hardware-unlock".into()),
            ..Default::default()
        })
        .unwrap();
}

#[test]
fn recovery_read_requires_a_hardware_vault_and_never_uses_the_file_key() {
    let (_tmp, legacy) = fixture();
    let reopened = Vault::new(&legacy.dir);
    assert!(reopened.open_recovery_read_only(PASSWORD).is_err());
    assert!(reopened.get("api_key", "example").is_err());
    let tmp = tempfile::tempdir().unwrap();
    assert!(Vault::new(tmp.path().join("vault"))
        .open_recovery_read_only(PASSWORD)
        .is_err());
}

/// Every file in `dir` that holds a device binding secret: the legacy name or a digest-named
/// `device-binding-<id>.key`.
fn binding_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            let name = p.file_name().unwrap().to_str().unwrap();
            name == "device-binding.key"
                || (name.starts_with("device-binding-") && name.ends_with(".key"))
        })
        .collect();
    files.sort();
    files
}

#[test]
fn a_vault_copy_needs_the_device_binding_file_and_recovery_rebinds_without_it() {
    let (_tmp, vault) = fixture();
    let hardware = Hardware::new(101);
    vault
        .migrate_to_enclave(&hardware, PASSWORD, "test")
        .unwrap();
    assert!(vault.protection().unwrap().device_binding);
    let bindings = binding_files(&vault.dir);
    assert_eq!(bindings.len(), 1);
    assert_ne!(bindings[0].file_name().unwrap(), "device-binding.key");
    assert_eq!(
        std::fs::metadata(&bindings[0])
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let original_name = bindings[0].file_name().unwrap().to_owned();
    let original = std::fs::read(&bindings[0]).unwrap();

    // Replaced or missing binding: refused before any hardware prompt.
    std::fs::write(&bindings[0], [9u8; 32]).unwrap();
    let before = hardware.unlocks.get();
    assert!(Vault::new(&vault.dir)
        .init_with_provider(&hardware, "test")
        .is_err());
    std::fs::remove_file(&bindings[0]).unwrap();
    assert!(Vault::new(&vault.dir)
        .init_with_provider(&hardware, "test")
        .is_err());
    assert_eq!(hardware.unlocks.get(), before);

    // The recovery passphrase still works, and recovery creates a fresh binding.
    let emergency = Vault::new(&vault.dir);
    emergency.open_recovery_read_only(PASSWORD).unwrap();
    assert_eq!(
        emergency.get("api_key", "example").unwrap().value,
        "test-secret-never-on-disk"
    );
    let second = Hardware::new(102);
    Vault::new(&vault.dir)
        .recover_enclave(&second, PASSWORD, "test")
        .unwrap();
    let bindings = binding_files(&vault.dir);
    assert_eq!(bindings.len(), 1);
    assert_ne!(bindings[0].file_name().unwrap(), original_name);
    assert_ne!(std::fs::read(&bindings[0]).unwrap(), original);
    let reopened = Vault::new(&vault.dir);
    reopened.init_with_provider(&second, "test").unwrap();
    assert_eq!(
        reopened.get("api_key", "example").unwrap().value,
        "test-secret-never-on-disk"
    );
}

#[test]
fn rotation_replaces_the_binding_so_older_vault_copies_need_the_recovery_passphrase() {
    let (_tmp, vault) = fixture();
    let first = Hardware::new(103);
    vault.migrate_to_enclave(&first, PASSWORD, "test").unwrap();
    let old_vault_bytes = std::fs::read(vault.dir.join("vault.enc")).unwrap();
    let old_bindings = binding_files(&vault.dir);
    assert_eq!(old_bindings.len(), 1);
    let old_name = old_bindings[0].file_name().unwrap().to_owned();
    let old_contents = std::fs::read(&old_bindings[0]).unwrap();

    let second = Hardware::new(104);
    vault
        .rotate_enclave(&second, "a brand new recovery passphrase", "test")
        .unwrap();
    let bindings = binding_files(&vault.dir);
    assert_eq!(bindings.len(), 1);
    assert_ne!(bindings[0].file_name().unwrap(), old_name);
    assert_ne!(std::fs::read(&bindings[0]).unwrap(), old_contents);
    assert!(!vault.dir.join(&old_name).exists());
    Vault::new(&vault.dir)
        .init_with_provider(&second, "test")
        .unwrap();

    // A pre-rotation copy of vault.enc references the deleted binding, so opening it is
    // rejected before any hardware prompt.
    std::fs::write(vault.dir.join("vault.enc"), &old_vault_bytes).unwrap();
    let before = first.unlocks.get();
    assert!(Vault::new(&vault.dir)
        .init_with_provider(&first, "test")
        .is_err());
    assert_eq!(first.unlocks.get(), before);
}

#[test]
fn a_legacy_named_binding_still_opens_and_rotation_replaces_it() {
    let (_tmp, vault) = fixture();
    let first = Hardware::new(105);
    vault.migrate_to_enclave(&first, PASSWORD, "test").unwrap();
    let bindings = binding_files(&vault.dir);
    assert_eq!(bindings.len(), 1);
    // What earlier versions wrote: the fixed name instead of the digest-named file.
    std::fs::rename(&bindings[0], vault.dir.join("device-binding.key")).unwrap();
    Vault::new(&vault.dir)
        .init_with_provider(&first, "test")
        .unwrap();

    // An orphan left by a crashed key change is cleaned up by the next successful one.
    let orphan = vault
        .dir
        .join("device-binding-00000000000000000000000000000000.key");
    std::fs::write(&orphan, [0u8; 32]).unwrap();
    std::fs::set_permissions(&orphan, std::fs::Permissions::from_mode(0o600)).unwrap();

    let second = Hardware::new(106);
    vault
        .rotate_enclave(&second, "a brand new recovery passphrase", "test")
        .unwrap();
    assert!(!vault.dir.join("device-binding.key").exists());
    assert!(!orphan.exists());
    let bindings = binding_files(&vault.dir);
    assert_eq!(bindings.len(), 1);
    assert_ne!(bindings[0].file_name().unwrap(), "device-binding.key");
    Vault::new(&vault.dir)
        .init_with_provider(&second, "test")
        .unwrap();
}

#[test]
fn rotation_replaces_the_hardware_key_and_passphrase_together() {
    let (_tmp, vault) = fixture();
    let first = Hardware::new(103);
    vault.migrate_to_enclave(&first, PASSWORD, "test").unwrap();
    let rotated = Hardware::new(104);
    let session = Vault::new(&vault.dir);
    session.init_with_provider(&first, "test").unwrap();
    session
        .rotate_enclave(&rotated, "a brand new recovery passphrase", "test")
        .unwrap();
    assert!(Vault::new(&vault.dir)
        .init_with_provider(&first, "test")
        .is_err());
    Vault::new(&vault.dir)
        .init_with_provider(&rotated, "test")
        .unwrap();
    assert!(Vault::new(&vault.dir)
        .open_recovery_read_only(PASSWORD)
        .is_err());
    assert_eq!(
        Vault::new(&vault.dir)
            .open_recovery_read_only("a brand new recovery passphrase")
            .unwrap(),
        1
    );
    // A cancelled rotation leaves everything as it was.
    let bytes = std::fs::read(vault.dir.join("vault.enc")).unwrap();
    let again = Vault::new(&vault.dir);
    again.init_with_provider(&rotated, "test").unwrap();
    let cancelled = Hardware::new(105);
    cancelled.fail_create.set(true);
    assert!(again.rotate_enclave(&cancelled, PASSWORD, "test").is_err());
    assert_eq!(bytes, std::fs::read(vault.dir.join("vault.enc")).unwrap());
    again.get("api_key", "example").unwrap();
}
