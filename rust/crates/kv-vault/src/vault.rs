use crate::crypto::{self, AAD, KEY_BYTES, LEGACY_AAD, NONCE_BYTES};
use crate::error::{Result, VaultError};
use crate::types::{CredentialRecord, HttpConfig, Kind, TypeRecord, VaultData, KINDS};
use crate::validate::{
    check_attributes, check_description, check_value, normalize_name, normalize_type,
    MAX_PROTOCOL_BYTES,
};
use crate::{
    DeviceBinding, EnclaveKey, MasterKey, MasterKeyMetadata, MasterKeyProvider, ProviderId,
    WrappedMasterKey, DEVICE_BINDING_BYTES,
};
use aes_gcm::aead::{rand_core::RngCore, OsRng};
use serde::Serialize;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const LOCK_TIMEOUT: Duration = Duration::from_millis(10_000);
const LOCK_STALE: Duration = Duration::from_millis(30_000);

pub struct Vault {
    pub dir: PathBuf,
    key_path: PathBuf,
    binding_path: PathBuf,
    data_path: PathBuf,
    audit_path: PathBuf,
    lock_path: PathBuf,
    key: std::sync::Mutex<Option<Zeroizing<[u8; KEY_BYTES]>>>,
    metadata: std::sync::Mutex<Option<MasterKeyMetadata>>,
    /// Set only by `open_recovery_read_only`; any newly installed key clears it.
    read_only: AtomicBool,
}

#[derive(Debug, Serialize)]
pub struct ProtectionStatus {
    pub provider: &'static str,
    pub recovery_configured: bool,
    /// The vault key also depends on the root-only device binding secret.
    pub device_binding: bool,
    /// A `vault.migration-backup.enc` snapshot left by an older version is still in the directory.
    pub migration_backup_present: bool,
    pub legacy_key_present: bool,
    pub hardware_required: bool,
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Mirrors `own()` in vault.ts: a named helper only so call sites read the same way; `HashMap::get`
/// already doesn't walk a prototype chain the way plain JS property access would.
fn own<'a, V>(map: &'a HashMap<String, V>, key: &str) -> Option<&'a V> {
    map.get(key)
}

impl Vault {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        Self {
            key_path: dir.join("master.key"),
            binding_path: dir.join("device-binding.key"),
            data_path: dir.join("vault.enc"),
            audit_path: dir.join("audit.log"),
            lock_path: dir.join(".lock"),
            dir,
            key: std::sync::Mutex::new(None),
            metadata: std::sync::Mutex::new(None),
            read_only: AtomicBool::new(false),
        }
    }

    /// Creates/checks the directory without loading any key. Refuses directory or file
    /// permissions are wrong, rather than "fixing" them.
    pub fn prepare(&self) -> Result<()> {
        if !self.dir.exists() {
            std::fs::create_dir(&self.dir)?;
            std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))?;
        }
        self.assert_private(&self.dir, true)?;
        if self.data_path.symlink_metadata().is_ok() {
            self.assert_private(&self.data_path, false)?;
        }
        Ok(())
    }

    fn disk_metadata(&self) -> Result<Option<MasterKeyMetadata>> {
        if !self.data_path.exists() {
            return Ok(None);
        }
        self.assert_private(&self.data_path, false)?;
        let file: crate::types::EncryptedFile =
            serde_json::from_slice(&std::fs::read(&self.data_path)?)?;
        if let Some(m) = &file.master_key {
            m.enclave.decode()?;
        }
        Ok(file.master_key)
    }

    pub fn protection(&self) -> Result<ProtectionStatus> {
        self.prepare()?;
        let metadata = self.disk_metadata()?;
        let protected = metadata.is_some();
        Ok(ProtectionStatus {
            device_binding: metadata.is_some_and(|m| m.device_binding.is_some()),
            provider: if protected {
                "secure_enclave"
            } else if self.data_path.exists() || self.key_path.symlink_metadata().is_ok() {
                "migration_required"
            } else {
                "uninitialized"
            },
            recovery_configured: protected,
            migration_backup_present: self
                .dir
                .join("vault.migration-backup.enc")
                .symlink_metadata()
                .is_ok(),
            legacy_key_present: self.key_path.symlink_metadata().is_ok(),
            hardware_required: true,
        })
    }

    pub fn init_with_provider(&self, provider: &dyn MasterKeyProvider, reason: &str) -> Result<()> {
        self.clear_key();
        self.prepare()?;
        match self.disk_metadata()? {
            None => Err(VaultError::new("macOS 凭证库必须使用 Secure Enclave；请运行 keyvalet setup-enclave 完成初始化或迁移", "macOS vaults require Secure Enclave; run keyvalet setup-enclave to initialize or migrate")),
            Some(metadata) => {
                // Check the binding file before prompting: a missing or replaced one can't
                // succeed anyway.
                let secret = match &metadata.device_binding {
                    Some(binding) => Some(self.load_binding_secret(binding)?),
                    None => None,
                };
                let hardware = provider.unlock(&metadata.enclave, reason)?;
                let key = match (&metadata.device_binding, secret) {
                    (Some(binding), Some(secret)) => binding.bind(&hardware, &secret)?,
                    _ => hardware,
                };
                self.set_key(key, Some(metadata));
                if let Err(error) = self.read() {
                    self.clear_key();
                    return Err(error);
                }
                Ok(())
            }
        }
    }

    /// Loads an existing file key for explicit legacy import; never creates a file key.
    /// The macOS helper and ordinary CLI operations must use `init_with_provider`.
    pub fn init_legacy(&self) -> Result<()> {
        self.clear_key();
        self.prepare()?;
        if self.disk_metadata()?.is_some() {
            return Err(VaultError::new(
                "凭证库需要硬件解锁；禁止文件密钥降级",
                "Vault requires hardware unlock; file-key fallback is disabled",
            ));
        }

        if !self.key_path.exists() {
            return Err(VaultError::new(
                "旧主密钥文件缺失；不会生成文件密钥，请初始化硬件 vault 或恢复",
                "Legacy master key is missing; file keys are no longer generated. Initialize a hardware vault or recover",
            ));
        }
        self.assert_private(&self.key_path, false)?;
        let raw = Zeroizing::new(std::fs::read(&self.key_path)?);
        if raw.len() != KEY_BYTES {
            return Err(VaultError::new(
                "主密钥文件已损坏（长度不对）",
                "Master key file is corrupted (wrong length)",
            ));
        }
        let mut key: MasterKey = Default::default();
        key.copy_from_slice(&raw);
        self.set_key(key, None);

        if self.data_path.exists() {
            self.read()?; // fail fast if the key and data don't match
        }
        Ok(())
    }

    /// Emergency read-only access with the recovery passphrase, for when Secure Enclave is
    /// unusable on this Mac. The passphrase is already an independent decryption path; this only
    /// reads through it. No hardware is used, writes and key removal are rejected, and the next
    /// hardware unlock of this `Vault` restores normal operation. Returns the credential count.
    pub fn open_recovery_read_only(&self, password: &str) -> Result<usize> {
        self.clear_key();
        self.prepare()?;
        let file: crate::types::EncryptedFile =
            serde_json::from_slice(&std::fs::read(&self.data_path)?)?;
        let metadata = file.master_key.clone().ok_or_else(|| {
            VaultError::new(
                "此凭证库没有硬件恢复信息",
                "This vault has no hardware recovery information",
            )
        })?;
        metadata.enclave.decode()?;
        let key = metadata.recovery.open(password)?;
        let data = Self::decrypt_file(&file, &key)?;
        self.install_key(key, Some(metadata), true);
        Ok(data.credentials.values().map(HashMap::len).sum())
    }

    fn require_writable(&self) -> Result<()> {
        if self.read_only.load(Ordering::SeqCst) {
            return Err(VaultError::new(
                "恢复口令访问为只读；修改请用硬件解锁，或运行 keyvalet recover-vault",
                "Recovery-passphrase access is read-only; unlock with hardware or run keyvalet recover-vault to make changes",
            ));
        }
        Ok(())
    }

    /// The digest-named path (`device-binding-<hex of the first 16 digest bytes>.key`) for a
    /// binding. The name ties the file to the digest stored in the vault metadata.
    fn binding_path_for(&self, binding: &DeviceBinding) -> Result<PathBuf> {
        let digest = base64_decode(&binding.digest).map_err(|_| {
            VaultError::new(
                "凭证库元数据已损坏（设备绑定摘要无效）",
                "Vault metadata is corrupt (invalid device binding digest)",
            )
        })?;
        // A SHA-256 digest, not the 32-byte secret length it happens to coincide with.
        if digest.len() != 32 {
            return Err(VaultError::new(
                "凭证库元数据已损坏（设备绑定摘要无效）",
                "Vault metadata is corrupt (invalid device binding digest)",
            ));
        }
        let id: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
        Ok(self.dir.join(format!("device-binding-{id}.key")))
    }

    /// Reads the root-only device binding secret: the digest-named file first, then the legacy
    /// `device-binding.key` name written by earlier versions.
    fn load_binding_secret(
        &self,
        binding: &DeviceBinding,
    ) -> Result<Zeroizing<[u8; DEVICE_BINDING_BYTES]>> {
        let named = self.binding_path_for(binding)?;
        let path = if named.symlink_metadata().is_ok() {
            named
        } else if self.binding_path.symlink_metadata().is_ok() {
            self.binding_path.clone()
        } else {
            return Err(VaultError::new(
                "设备绑定密钥缺失；请运行 keyvalet recover-vault 用恢复口令重新绑定",
                "The device binding key is missing; run keyvalet recover-vault to rebind with the recovery passphrase",
            ));
        };
        self.assert_private(&path, false)?;
        let raw = Zeroizing::new(std::fs::read(&path)?);
        if raw.len() != DEVICE_BINDING_BYTES {
            return Err(VaultError::new(
                "设备绑定密钥已损坏",
                "The device binding key is corrupted",
            ));
        }
        let mut secret = Zeroizing::new([0u8; DEVICE_BINDING_BYTES]);
        secret.copy_from_slice(&raw);
        if DeviceBinding::for_secret(&secret) != *binding {
            return Err(VaultError::new(
                "设备绑定密钥与凭证库不匹配；请运行 keyvalet recover-vault 用恢复口令重新绑定",
                "The device binding key does not match this vault; run keyvalet recover-vault to rebind with the recovery passphrase",
            ));
        }
        Ok(secret)
    }

    /// Creates a fresh random binding secret in its digest-named file (create_new: never
    /// overwritten). The Time Machine exclusion is set while the file is still empty, so a
    /// backup can never pick up the secret itself. On a write/sync error the partial file is
    /// removed.
    fn create_binding_secret(
        &self,
    ) -> Result<(
        Zeroizing<[u8; DEVICE_BINDING_BYTES]>,
        DeviceBinding,
        PathBuf,
    )> {
        let mut secret = Zeroizing::new([0u8; DEVICE_BINDING_BYTES]);
        OsRng.fill_bytes(secret.as_mut());
        let binding = DeviceBinding::for_secret(&secret);
        let path = self.binding_path_for(&binding)?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let result = (|| -> Result<()> {
            exclude_from_backups(&path);
            f.write_all(secret.as_ref())?;
            f.sync_all()?;
            std::fs::File::open(&self.dir)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&path);
        }
        result?;
        Ok((secret, binding, path))
    }

    /// Deletes every binding file in the vault directory (legacy `device-binding.key` and
    /// digest-named `device-binding-*.key`) except `keep`. Called only after the new vault that
    /// references `keep` has committed, so older vault copies can no longer be opened with a
    /// stale binding.
    fn remove_stale_bindings(&self, keep: &Path) -> Result<()> {
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let is_binding = name == "device-binding.key"
                || (name.starts_with("device-binding-") && name.ends_with(".key"));
            if is_binding && entry.path() != keep {
                std::fs::remove_file(entry.path())?;
            }
        }
        std::fs::File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// Removes the encrypted migration snapshot written by versions that kept one. Reached via
    /// `remove_legacy_key` (migrate / recover / finish-enclave-migration) and directly at the
    /// end of `rotate_enclave`.
    fn remove_migration_backup(&self) -> Result<()> {
        let path = self.dir.join("vault.migration-backup.enc");
        if path.symlink_metadata().is_ok() {
            std::fs::remove_file(&path)?;
            std::fs::File::open(&self.dir)?.sync_all()?;
        }
        Ok(())
    }

    /// Whether the current device binding file is excluded from Time Machine, per
    /// `tmutil isexcluded`. `Ok(None)` when the vault metadata has no device binding (or not on
    /// macOS); `Ok(Some(false))` also covers a missing binding file or a failed check.
    pub fn binding_backup_exclusion(&self) -> Result<Option<bool>> {
        let Some(binding) = self
            .disk_metadata()?
            .and_then(|metadata| metadata.device_binding)
        else {
            return Ok(None);
        };
        #[cfg(not(target_os = "macos"))]
        {
            let _ = binding;
            Ok(None)
        }
        #[cfg(target_os = "macos")]
        {
            let named = self.binding_path_for(&binding)?;
            let path = if named.symlink_metadata().is_ok() {
                named
            } else if self.binding_path.symlink_metadata().is_ok() {
                self.binding_path.clone()
            } else {
                return Ok(Some(false));
            };
            let excluded = std::process::Command::new("/usr/bin/tmutil")
                .arg("isexcluded")
                .arg(&path)
                .env_clear()
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .output()
                .map(|out| {
                    out.status.success()
                        && String::from_utf8_lossy(&out.stdout).contains("[Excluded]")
                })
                .unwrap_or(false);
            Ok(Some(excluded))
        }
    }

    /// Turns a freshly created and verified hardware key into the vault key and its metadata:
    /// a new random binding secret for every key change, with the recovery passphrase wrapping
    /// the final key. Must be called under the write lock so the new binding file can't be
    /// cleaned up as "stale" by a concurrent rotation.
    fn bound_key(
        &self,
        created: EnclaveKey,
        password: &str,
    ) -> Result<(MasterKey, MasterKeyMetadata, PathBuf)> {
        let (secret, binding, path) = self.create_binding_secret()?;
        let key = binding.bind(&created.key, &secret)?;
        let metadata = MasterKeyMetadata {
            provider: ProviderId::SecureEnclave,
            enclave: created.metadata,
            recovery: WrappedMasterKey::wrap(&key, password)?,
            device_binding: Some(binding),
        };
        Ok((key, metadata, path))
    }

    /// Encrypts `data` under the new bound key, commits it atomically, installs the key, then
    /// removes every other binding file. If the commit fails, the just-created binding file is
    /// removed -- but only when the on-disk vault doesn't reference it: `atomic_write` can fail
    /// on the post-rename directory fsync after `vault.enc` already points at the new binding,
    /// and deleting it there would leave the vault recoverable only by passphrase (an orphan
    /// from a real pre-commit failure is cleaned up here, one from a crash by the next
    /// successful key change).
    fn commit_bound_key(
        &self,
        data: &VaultData,
        created: EnclaveKey,
        password: &str,
    ) -> Result<()> {
        let (key, metadata, binding_path) = self.bound_key(created, password)?;
        let result = Self::encrypt_file(data, &key, Some(metadata.clone()))
            .and_then(|bytes| self.atomic_write(&bytes));
        if let Err(error) = result {
            // Unreadable on-disk state counts as "maybe committed": an orphan is harmless.
            let uncommitted = matches!(
                self.disk_metadata(),
                Ok(on_disk) if on_disk.as_ref().and_then(|m| m.device_binding.as_ref())
                    != metadata.device_binding.as_ref()
            );
            if uncommitted {
                let _ = std::fs::remove_file(&binding_path);
            }
            return Err(error);
        }
        self.set_key(key, Some(metadata));
        self.remove_stale_bindings(&binding_path)
    }

    fn set_key(&self, key: MasterKey, metadata: Option<MasterKeyMetadata>) {
        self.install_key(key, metadata, false);
    }

    fn install_key(&self, key: MasterKey, metadata: Option<MasterKeyMetadata>, read_only: bool) {
        let mut guard = self.key.lock().unwrap();
        self.read_only.store(read_only, Ordering::SeqCst);
        *guard = Some(key);
        *self.metadata.lock().unwrap() = metadata;
        // Best-effort: ask the OS to never swap out the page(s) holding the master key, so it
        // can't end up on disk in a swap file if this machine's swap isn't encrypted. Failure
        // (e.g. a locked-memory rlimit) isn't fatal -- this is defense in depth on top of the
        // zeroize-on-drop handling, not the only thing standing between the key and disk.
        if let Some(k) = guard.as_ref() {
            unsafe {
                libc::mlock(k.as_ptr() as *const libc::c_void, KEY_BYTES);
            }
        }
    }

    fn clear_key(&self) {
        *self.key.lock().unwrap() = None;
        *self.metadata.lock().unwrap() = None;
        self.read_only.store(false, Ordering::SeqCst);
    }

    fn assert_private(&self, p: &Path, is_dir: bool) -> Result<()> {
        let st = std::fs::symlink_metadata(p)?;
        if st.file_type().is_symlink() {
            return Err(VaultError::new(
                &format!("{} 不能是符号链接", p.display()),
                &format!("{} must not be a symbolic link", p.display()),
            ));
        }
        if is_dir != st.is_dir() {
            return Err(VaultError::new(
                &format!("{} 类型不对", p.display()),
                &format!("{} has the wrong file type", p.display()),
            ));
        }
        if st.uid() != unsafe { libc::getuid() } {
            return Err(VaultError::new(
                &format!("{} 的属主不是当前用户（应为 root）", p.display()),
                &format!(
                    "{} is not owned by the current user (should be root)",
                    p.display()
                ),
            ));
        }
        if st.mode() & 0o077 != 0 {
            return Err(VaultError::new(
                &format!("{} 权限过宽（{:o}），必须只有属主可访问", p.display(), st.mode() & 0o777),
                &format!("{} has overly broad permissions ({:o}); it must be accessible only by its owner", p.display(), st.mode() & 0o777),
            ));
        }
        Ok(())
    }

    fn require_key(&self) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
        self.key
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| VaultError::new("凭证库未初始化", "Vault is not initialized"))
    }

    fn read(&self) -> Result<VaultData> {
        let key = self.require_key()?;
        self.check_epoch()?;
        if !self.data_path.exists() {
            return Ok(VaultData::empty());
        }
        let file: crate::types::EncryptedFile =
            serde_json::from_slice(&std::fs::read(&self.data_path)?)?;
        Self::decrypt_file(&file, &key)
    }

    fn check_epoch(&self) -> Result<()> {
        if self.disk_metadata()? != *self.metadata.lock().unwrap() {
            return Err(VaultError::new(
                "凭证库密钥已更换，请重新开启会话",
                "Vault key has changed; start a new session",
            ));
        }
        Ok(())
    }

    fn decrypt_file(
        file: &crate::types::EncryptedFile,
        key: &[u8; KEY_BYTES],
    ) -> Result<VaultData> {
        if file.v != 1 || file.alg != "aes-256-gcm" {
            return Err(VaultError::new(
                "不支持的凭证库格式",
                "Unsupported vault format",
            ));
        }
        let decode_err = || {
            VaultError::new("凭证库解密失败：数据被篡改或主密钥不匹配", "Failed to decrypt vault: data has been tampered with or the master key does not match")
        };
        let nonce_v = base64_decode(&file.iv).map_err(|_| decode_err())?;
        let tag_v = base64_decode(&file.tag).map_err(|_| decode_err())?;
        let ct = base64_decode(&file.ct).map_err(|_| decode_err())?;
        let nonce: [u8; NONCE_BYTES] = nonce_v.try_into().map_err(|_| decode_err())?;
        let tag: [u8; crate::crypto::TAG_BYTES] = tag_v.try_into().map_err(|_| decode_err())?;

        let mut plain: Option<Zeroizing<Vec<u8>>> = None;
        let bound_aad = Self::encryption_aad(file.master_key.as_ref())?;
        let aads: Vec<&[u8]> = if file.master_key.is_some() {
            vec![&bound_aad]
        } else {
            vec![AAD, LEGACY_AAD]
        };
        for aad in aads {
            if let Ok(p) = crypto::decrypt(key, &nonce, aad, &ct, &tag) {
                plain = Some(Zeroizing::new(p));
                break;
            }
        }
        let plain = plain.ok_or_else(decode_err)?;
        let data: VaultData = serde_json::from_slice(&plain)?;
        if data.version != 1 {
            return Err(VaultError::new(
                "不支持的凭证库版本",
                "Unsupported vault version",
            ));
        }
        Ok(data)
    }

    fn write(&self, data: &VaultData) -> Result<()> {
        self.require_writable()?;
        self.check_epoch()?;
        let key = self.require_key()?;
        let metadata = self.metadata.lock().unwrap().clone();
        self.atomic_write(&Self::encrypt_file(data, &key, metadata)?)
    }

    fn encryption_aad(metadata: Option<&MasterKeyMetadata>) -> Result<Vec<u8>> {
        let mut aad = AAD.to_vec();
        if let Some(metadata) = metadata {
            aad.extend_from_slice(b"/secure-enclave/v1/");
            aad.extend_from_slice(&serde_json::to_vec(metadata)?);
        }
        Ok(aad)
    }

    fn encrypt_file(
        data: &VaultData,
        key: &[u8; KEY_BYTES],
        metadata: Option<MasterKeyMetadata>,
    ) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let plain = Zeroizing::new(serde_json::to_vec(data)?);
        let (ct, tag) = crypto::split_tag(crypto::encrypt(
            key,
            &nonce,
            &Self::encryption_aad(metadata.as_ref())?,
            &plain,
        ));
        let file = crate::types::EncryptedFile {
            v: 1,
            alg: "aes-256-gcm".to_string(),
            iv: base64_encode(nonce),
            tag: base64_encode(tag),
            ct: base64_encode(&ct),
            master_key: metadata,
        };
        let bytes = serde_json::to_vec(&file)?;
        // Verify the candidate before it can replace the only current vault.
        Self::decrypt_file(&file, key)?;
        Ok(bytes)
    }

    fn atomic_write(&self, bytes: &[u8]) -> Result<()> {
        // Atomic write: temp file + fsync + rename, so a crash never leaves a half-written file.
        let mut tmp_name = self.data_path.clone().into_os_string();
        tmp_name.push(format!(".tmp-{}-{}", std::process::id(), random_hex(4)));
        let tmp = PathBuf::from(tmp_name);
        let result = (|| -> Result<()> {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.data_path)?;
            std::fs::File::open(&self.dir)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    /// A fresh production vault starts with hardware protection, without ever creating master.key.
    pub fn initialize_enclave(
        &self,
        provider: &dyn MasterKeyProvider,
        password: &str,
        reason: &str,
    ) -> Result<()> {
        self.prepare()?;
        self.require_empty_directory_state()?;
        WrappedMasterKey::validate_password(password)?;
        let created = provider.create(reason)?;
        created.metadata.decode()?;
        let restored = provider.unlock(&created.metadata, reason)?;
        if *restored != *created.key {
            return Err(VaultError::new(
                "新硬件密钥无法重新载入，初始化已取消",
                "New hardware key could not be restored; initialization cancelled",
            ));
        }
        let _guard = self.lock()?;
        self.require_empty_directory_state()?;
        self.commit_bound_key(&VaultData::empty(), created, password)
    }

    fn require_empty_directory_state(&self) -> Result<()> {
        if self.data_path.symlink_metadata().is_ok() || self.key_path.symlink_metadata().is_ok() {
            return Err(VaultError::new("凭证库已有数据或旧密钥，请迁移或恢复，不能重新初始化", "Vault contains data or a legacy key; migrate or recover instead of initializing again"));
        }
        Ok(())
    }

    /// Rotation is committed by one rename containing both ciphertext and its key metadata.
    /// Hardware prompts happen before acquiring the short-lived cross-process write lock.
    pub fn migrate_to_enclave(
        &self,
        provider: &dyn MasterKeyProvider,
        password: &str,
        reason: &str,
    ) -> Result<()> {
        self.check_epoch()?;
        if self.metadata.lock().unwrap().is_some() {
            return Err(VaultError::new(
                "已启用 Secure Enclave",
                "Secure Enclave is already enabled",
            ));
        }
        self.require_key()?;
        // Reject an invalid passphrase before opening the authentication dialog.
        WrappedMasterKey::validate_password(password)?;
        let created = provider.create(reason)?;
        created.metadata.decode()?;
        let restored = provider.unlock(&created.metadata, reason)?;
        if *restored != *created.key {
            return Err(VaultError::new(
                "新硬件密钥无法重新载入，迁移已取消",
                "New hardware key could not be restored; migration cancelled",
            ));
        }
        let _guard = self.lock()?;
        let data = self.read()?;
        self.commit_bound_key(&data, created, password)?;
        // Also removes a `vault.migration-backup.enc` left by an older version.
        self.remove_legacy_key()
    }

    /// Password recovery rotates to a fresh device key without using the old Enclave.
    pub fn recover_enclave(
        &self,
        provider: &dyn MasterKeyProvider,
        password: &str,
        reason: &str,
    ) -> Result<()> {
        self.prepare()?;
        let original = std::fs::read(&self.data_path)?;
        let file: crate::types::EncryptedFile = serde_json::from_slice(&original)?;
        let metadata = file.master_key.as_ref().ok_or_else(|| {
            VaultError::new(
                "此凭证库没有硬件恢复信息",
                "This vault has no hardware recovery information",
            )
        })?;
        metadata.enclave.decode()?;
        let old_key = metadata.recovery.open(password)?;
        let data = Self::decrypt_file(&file, &old_key)?;
        let created = provider.create(reason)?;
        created.metadata.decode()?;
        let restored = provider.unlock(&created.metadata, reason)?;
        if *restored != *created.key {
            return Err(VaultError::new(
                "新硬件密钥无法重新载入，恢复已取消",
                "New hardware key could not be restored; recovery cancelled",
            ));
        }
        let _guard = self.lock()?;
        if std::fs::read(&self.data_path)? != original {
            return Err(VaultError::new(
                "恢复期间凭证库发生变化，请重试",
                "Vault changed during recovery; retry",
            ));
        }
        self.commit_bound_key(&data, created, password)?;
        self.remove_legacy_key()
    }

    /// Replaces the hardware key, the vault key and the recovery passphrase together, after a
    /// hardware unlock of the current key; also adds device binding to an older unbound vault.
    /// Rotating the vault key is what revokes the old passphrase for the current vault: a
    /// rewrapped old key would stay decryptable by anyone who had already opened the old
    /// wrapper. Earlier copies of `vault.enc` remain decryptable with their old passphrase.
    pub fn rotate_enclave(
        &self,
        provider: &dyn MasterKeyProvider,
        password: &str,
        reason: &str,
    ) -> Result<()> {
        self.require_writable()?;
        self.check_epoch()?;
        if self.metadata.lock().unwrap().is_none() {
            return Err(VaultError::new(
                "尚未启用 Secure Enclave",
                "Secure Enclave is not enabled",
            ));
        }
        self.require_key()?;
        WrappedMasterKey::validate_password(password)?;
        let created = provider.create(reason)?;
        created.metadata.decode()?;
        let restored = provider.unlock(&created.metadata, reason)?;
        if *restored != *created.key {
            return Err(VaultError::new(
                "新硬件密钥无法重新载入，更换已取消",
                "New hardware key could not be restored; rotation cancelled",
            ));
        }
        let _guard = self.lock()?;
        let data = self.read()?;
        self.commit_bound_key(&data, created, password)?;
        self.remove_migration_backup()
    }

    pub fn remove_legacy_key(&self) -> Result<()> {
        self.require_writable()?;
        self.check_epoch()?;
        self.read()?; // Require a successful hardware/recovery unlock before removing anything.
        if self.metadata.lock().unwrap().is_none() {
            return Err(VaultError::new(
                "尚未启用 Secure Enclave，不能删除主密钥",
                "Enable Secure Enclave before removing the master key",
            ));
        }
        if self.key_path.symlink_metadata().is_ok() {
            self.assert_private(&self.key_path, false)?;
            std::fs::remove_file(&self.key_path)?;
            std::fs::File::open(&self.dir)?.sync_all()?;
        }
        self.remove_migration_backup()
    }

    /// Read-modify-write, holding the cross-process write lock.
    fn mutate<T>(&self, f: impl FnOnce(&mut VaultData) -> Result<T>) -> Result<T> {
        let _guard = self.lock()?;
        let mut data = self.read()?;
        let result = f(&mut data)?;
        self.write(&data)?;
        Ok(result)
    }

    fn lock(&self) -> Result<LockGuard<'_>> {
        let deadline = Instant::now() + LOCK_TIMEOUT;
        loop {
            match std::fs::create_dir(&self.lock_path) {
                Ok(()) => return Ok(LockGuard { vault: self }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
            match std::fs::metadata(&self.lock_path).and_then(|m| m.modified()) {
                Ok(modified) => {
                    if modified.elapsed().unwrap_or_default() > LOCK_STALE {
                        let _ = std::fs::remove_dir(&self.lock_path); // the lock holder crashed
                        continue;
                    }
                }
                Err(_) => continue, // the lock was just released
            }
            if Instant::now() > deadline {
                return Err(VaultError::new(
                    "凭证库正忙（获取写锁超时）",
                    "Vault is busy (timed out acquiring write lock)",
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn unlock(&self) {
        let _ = std::fs::remove_dir(&self.lock_path);
    }

    /// Reads the tail (at most `max_bytes`) of the audit log, as complete lines.
    pub fn read_audit_tail(&self, max_bytes: u64) -> Vec<String> {
        use std::io::{Read, Seek, SeekFrom};
        let Ok(mut f) = std::fs::File::open(&self.audit_path) else {
            return Vec::new();
        };
        let Ok(size) = f.metadata().map(|m| m.len()) else {
            return Vec::new();
        };
        let len = size.min(max_bytes);
        if f.seek(SeekFrom::Start(size - len)).is_err() {
            return Vec::new();
        }
        let mut buf = Vec::with_capacity(len as usize);
        if f.read_to_end(&mut buf).is_err() {
            return Vec::new();
        }
        let text = String::from_utf8_lossy(&buf);
        let mut lines: Vec<&str> = text.split('\n').collect();
        if len < size {
            lines.remove(0); // the first line may be incomplete
        }
        lines
            .into_iter()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    }

    pub fn audit(&self, mut entry: serde_json::Map<String, serde_json::Value>) -> Result<()> {
        entry.insert("ts".to_string(), serde_json::Value::String(now_iso()));
        entry.insert(
            "pid".to_string(),
            serde_json::Value::Number(std::process::id().into()),
        );
        let mut line = serde_json::to_string(&serde_json::Value::Object(entry))?;
        line.push('\n');
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&self.audit_path)?;
        f.write_all(line.as_bytes())?;
        drop(f);
        // Rotate once past 10MB (keeping the previous one), so it never grows unbounded.
        if let Ok(meta) = std::fs::metadata(&self.audit_path) {
            if meta.len() > 10 * 1024 * 1024 {
                let rotated = self.audit_path.with_extension("log.1");
                let _ = std::fs::rename(&self.audit_path, rotated);
            }
        }
        Ok(())
    }

    // ---------- operations ----------

    pub fn list_types(&self) -> Vec<ListTypesEntry> {
        let data = self.read().unwrap_or_else(|_| VaultData::empty());
        let mut names: Vec<&String> = data.types.keys().collect();
        names.sort();
        names
            .into_iter()
            .map(|name| {
                let rec = &data.types[name];
                let count = data.credentials.get(name).map(|c| c.len()).unwrap_or(0);
                ListTypesEntry {
                    name: name.clone(),
                    description: rec.description.clone(),
                    count,
                    created_at: rec.created_at.clone(),
                }
            })
            .collect()
    }

    pub fn type_exists(&self, ty: &str) -> Result<bool> {
        let ty = normalize_type(ty)?;
        Ok(own(&self.read()?.types, &ty).is_some())
    }

    pub fn create_type(&self, name: &str, description: Option<&str>) -> Result<CreateTypeResult> {
        let name = normalize_type(name)?;
        let description = check_description(description)?;
        self.mutate(|data| {
            if own(&data.types, &name).is_some() {
                return Ok(CreateTypeResult {
                    name: name.clone(),
                    created: false,
                });
            }
            let now = now_iso();
            data.types.insert(
                name.clone(),
                TypeRecord {
                    description: description.clone(),
                    created_at: now.clone(),
                    updated_at: now,
                },
            );
            data.credentials.insert(name.clone(), HashMap::new());
            Ok(CreateTypeResult {
                name: name.clone(),
                created: true,
            })
        })
    }

    pub fn delete_type(&self, name: &str) -> Result<String> {
        let name = normalize_type(name)?;
        self.mutate(|data| {
            if own(&data.types, &name).is_none() {
                return Err(VaultError::new(&format!("凭证类型 \"{name}\" 不存在"), &format!("Credential type \"{name}\" not found")));
            }
            let count = data.credentials.get(&name).map(|c| c.len()).unwrap_or(0);
            if count > 0 {
                return Err(VaultError::new(
                    &format!("凭证类型 \"{name}\" 下还有 {count} 个凭证，请先删除它们"),
                    &format!("Credential type \"{name}\" still has {count} credential(s); delete them first"),
                ));
            }
            data.types.remove(&name);
            data.credentials.remove(&name);
            Ok(name.clone())
        })
    }

    pub fn list(&self, ty: Option<&str>) -> Result<Vec<ListEntry>> {
        let data = self.read()?;
        let mut types: Vec<String> = match ty {
            None | Some("") => {
                let mut t: Vec<String> = data.types.keys().cloned().collect();
                t.sort();
                t
            }
            Some(ty) => {
                let ty = normalize_type(ty)?;
                if own(&data.types, &ty).is_none() {
                    return Err(VaultError::new(
                        &format!("凭证类型 \"{ty}\" 不存在"),
                        &format!("Credential type \"{ty}\" not found"),
                    ));
                }
                vec![ty]
            }
        };
        types.sort();
        let mut out = Vec::new();
        for ty in types.drain(..) {
            let Some(creds) = data.credentials.get(&ty) else {
                continue;
            };
            let mut names: Vec<&String> = creds.keys().collect();
            names.sort();
            for name in names {
                let c = &creds[name];
                out.push(ListEntry {
                    r#type: ty.clone(),
                    name: name.clone(),
                    kind: c.kind_or_static(),
                    description: c.description.clone(),
                    attributes: c.attributes.clone(),
                    template: c.template.clone(),
                    http: c.http.clone(),
                    updated_at: c.updated_at.clone(),
                });
            }
        }
        Ok(out)
    }

    pub fn exists(&self, ty: &str, name: &str) -> Result<bool> {
        let ty = normalize_type(ty)?;
        let name = normalize_name(name)?;
        Ok(self
            .read()?
            .credentials
            .get(&ty)
            .map(|c| c.contains_key(&name))
            .unwrap_or(false))
    }

    /// Full record (including secrets), deep-cloned. For the root helper's internal protocol
    /// implementations and the root CLI only.
    pub fn get_record(&self, ty: &str, name: &str) -> Result<(String, String, CredentialRecord)> {
        let ty = normalize_type(ty)?;
        let name = normalize_name(name)?;
        let data = self.read()?;
        if own(&data.types, &ty).is_none() {
            return Err(VaultError::new(
                &format!("凭证类型 \"{ty}\" 不存在"),
                &format!("Credential type \"{ty}\" not found"),
            ));
        }
        let rec = data
            .credentials
            .get(&ty)
            .and_then(|c| c.get(&name))
            .ok_or_else(|| {
                VaultError::new(
                    &format!("凭证 \"{ty}/{name}\" 不存在"),
                    &format!("Credential \"{ty}/{name}\" not found"),
                )
            })?;
        Ok((ty, name, rec.clone()))
    }

    /// Reads a static credential's value. A protocol-based credential's secrets cannot be read this way.
    pub fn get(&self, ty: &str, name: &str) -> Result<GetResult> {
        let (ty, name, mut c) = self.get_record(ty, name)?;
        if c.kind.is_some() && c.kind != Some(Kind::Static) {
            let kind = c.kind_or_static().as_str();
            return Err(VaultError::new(
                &format!("\"{ty}/{name}\" 是 {kind} 协议凭证，其长期秘密不能直接读取"),
                &format!("\"{ty}/{name}\" is a {kind} protocol credential; its long-term secrets cannot be read directly"),
            ));
        }
        if c.http.as_ref().is_some_and(|h| h.proxy_only) {
            return Err(VaultError::new(
                &format!("\"{ty}/{name}\" 设置为只能代理调用，不能读出秘密；请用 credential_http_request"),
                &format!("\"{ty}/{name}\" is proxy-only; its secret cannot be read. Use credential_http_request instead"),
            ));
        }
        // `c` implements Drop (to scrub its secret fields when it goes out of scope), which means
        // a field can't be moved out of it directly -- std::mem::take moves the value out and
        // leaves an empty default behind instead, same effect as a move without actually cloning
        // the secret into a second allocation first.
        Ok(GetResult {
            r#type: ty,
            name,
            value: std::mem::take(&mut c.value),
            fields: std::mem::take(&mut c.secrets),
            description: std::mem::take(&mut c.description),
            attributes: std::mem::take(&mut c.attributes),
            updated_at: std::mem::take(&mut c.updated_at),
        })
    }

    /// Writes a credential: creates the type first if missing, then writes the value. Both steps
    /// happen under the same write lock and in the same flush, so there's no "type created but
    /// value not written" intermediate state.
    pub fn set(&self, params: SetParams) -> Result<SetResult> {
        let ty = normalize_type(&params.r#type)?;
        let name = normalize_name(&params.name)?;
        let secrets = params.secrets.filter(|s| !s.is_empty());
        let value = if secrets.is_some() && params.value.as_deref().unwrap_or("").is_empty() {
            String::new()
        } else {
            check_value(params.value.as_deref())?
        };
        if let Some(s) = &secrets {
            if serde_json::to_vec(s)?.len() > MAX_PROTOCOL_BYTES {
                return Err(VaultError::new(
                    "秘密字段过大",
                    "Secret fields are too large",
                ));
            }
        }
        let description = check_description(params.description.as_deref())?;
        let attributes = check_attributes(params.attributes.as_ref())?;
        let type_description = check_description(params.type_description.as_deref())?;
        let overwrite = params.overwrite;

        self.mutate(|data| {
            let now = now_iso();
            let mut type_created = false;
            if own(&data.types, &ty).is_none() {
                data.types.insert(ty.clone(), TypeRecord { description: type_description.clone(), created_at: now.clone(), updated_at: now.clone() });
                type_created = true;
            }
            let creds = data.credentials.entry(ty.clone()).or_default();
            let existing = creds.get(&name).cloned();
            if existing.is_some() && !overwrite {
                return Err(VaultError::new(
                    &format!("凭证 \"{ty}/{name}\" 已存在；如需替换请设置 overwrite=true"),
                    &format!("Credential \"{ty}/{name}\" already exists; set overwrite=true to replace it"),
                ));
            }
            creds.insert(
                name.clone(),
                CredentialRecord {
                    kind: None,
                    value,
                    secrets,
                    http: params.http.clone(),
                    template: params.template.clone(),
                    description: if !description.is_empty() { description } else { existing.as_ref().map(|e| e.description.clone()).unwrap_or_default() },
                    attributes: if !attributes.is_empty() { attributes } else { existing.as_ref().map(|e| e.attributes.clone()).unwrap_or_default() },
                    created_at: existing.as_ref().map(|e| e.created_at.clone()).unwrap_or_else(|| now.clone()),
                    updated_at: now.clone(),
                    config: None,
                    state: None,
                    generation: None,
                },
            );
            data.types.get_mut(&ty).unwrap().updated_at = now;
            Ok(SetResult { r#type: ty.clone(), name: name.clone(), type_created, replaced: existing.is_some() })
        })
    }

    /// Writes a protocol-based credential. Same shape as `set`: creates the type first if missing.
    /// `config`/`secrets` are validated by the caller (the protocols crate).
    pub fn set_protocol(&self, params: SetProtocolParams) -> Result<SetResult> {
        let ty = normalize_type(&params.r#type)?;
        let name = normalize_name(&params.name)?;
        let description = check_description(params.description.as_deref())?;
        let type_description = check_description(params.type_description.as_deref())?;
        if params.kind == Kind::Static || !KINDS.contains(&params.kind) {
            return Err(VaultError::new(
                &format!("非法的协议种类 {:?}", params.kind),
                &format!("Invalid protocol kind {:?}", params.kind),
            ));
        }
        if serde_json::to_vec(&(&params.config, &params.secrets))?.len() > MAX_PROTOCOL_BYTES {
            return Err(VaultError::new(
                "协议凭证数据过大",
                "Protocol credential data is too large",
            ));
        }
        self.mutate(|data| {
            let now = now_iso();
            let mut type_created = false;
            if own(&data.types, &ty).is_none() {
                data.types.insert(ty.clone(), TypeRecord { description: type_description.clone(), created_at: now.clone(), updated_at: now.clone() });
                type_created = true;
            }
            let creds = data.credentials.entry(ty.clone()).or_default();
            let existing = creds.get(&name).cloned();
            if existing.is_some() && !params.overwrite {
                return Err(VaultError::new(
                    &format!("凭证 \"{ty}/{name}\" 已存在；如需替换请设置 overwrite=true"),
                    &format!("Credential \"{ty}/{name}\" already exists; set overwrite=true to replace it"),
                ));
            }
            creds.insert(
                name.clone(),
                CredentialRecord {
                    kind: Some(params.kind),
                    value: String::new(),
                    config: Some(params.config.clone()),
                    secrets: Some(params.secrets.clone()),
                    state: Some(serde_json::Value::Object(Default::default())),
                    generation: Some(random_hex(12)),
                    description: if !description.is_empty() { description } else { existing.as_ref().map(|e| e.description.clone()).unwrap_or_default() },
                    attributes: HashMap::new(),
                    created_at: existing.as_ref().map(|e| e.created_at.clone()).unwrap_or_else(|| now.clone()),
                    updated_at: now.clone(),
                    http: None,
                    template: None,
                },
            );
            data.types.get_mut(&ty).unwrap().updated_at = now;
            Ok(SetResult { r#type: ty.clone(), name: name.clone(), type_created, replaced: existing.is_some() })
        })
    }

    /// Modifies a protocol credential's state/secrets (e.g. a refreshed token) under the write lock.
    /// `generation` must match what was read: the credential being replaced during the operation
    /// (even to the same kind) is rejected, so a refreshed refresh-token can't be written back into
    /// a config the agent just swapped in behind our back.
    pub fn patch_record(
        &self,
        ty: &str,
        name: &str,
        kind: Kind,
        generation: Option<&str>,
        f: impl FnOnce(&mut CredentialRecord),
    ) -> Result<()> {
        let ty = normalize_type(ty)?;
        let name = normalize_name(name)?;
        self.mutate(|data| {
            let creds = data.credentials.get_mut(&ty);
            let rec = creds.and_then(|c| c.get_mut(&name));
            let Some(rec) = rec else {
                return Err(VaultError::new(&format!("凭证 \"{ty}/{name}\" 不存在"), &format!("Credential \"{ty}/{name}\" not found")));
            };
            if rec.kind_or_static() != kind || rec.generation.as_deref() != generation {
                return Err(VaultError::new(
                    &format!("凭证 \"{ty}/{name}\" 在操作期间被修改，已放弃写入，请重试"),
                    &format!("Credential \"{ty}/{name}\" was modified during the operation; write aborted, please retry"),
                ));
            }
            f(rec);
            rec.updated_at = now_iso();
            Ok(())
        })
    }

    /// Modifies the proxy configuration of any kind of credential. `f` returns the new
    /// configuration; validation is the caller's responsibility.
    pub fn update_http(
        &self,
        ty: &str,
        name: &str,
        f: impl FnOnce(CredentialRecord) -> Option<HttpConfig>,
    ) -> Result<()> {
        let ty = normalize_type(ty)?;
        let name = normalize_name(name)?;
        self.mutate(|data| {
            let rec = data
                .credentials
                .get(&ty)
                .and_then(|c| c.get(&name))
                .cloned();
            let Some(rec) = rec else {
                return Err(VaultError::new(
                    &format!("凭证 \"{ty}/{name}\" 不存在"),
                    &format!("Credential \"{ty}/{name}\" not found"),
                ));
            };
            let next = f(rec);
            let slot = data
                .credentials
                .get_mut(&ty)
                .unwrap()
                .get_mut(&name)
                .unwrap();
            slot.http = next;
            slot.updated_at = now_iso();
            Ok(())
        })
    }

    pub fn delete(&self, ty: &str, name: &str) -> Result<(String, String)> {
        let ty = normalize_type(ty)?;
        let name = normalize_name(name)?;
        self.mutate(|data| {
            let removed = data
                .credentials
                .get_mut(&ty)
                .map(|c| c.remove(&name))
                .unwrap_or(None);
            if removed.is_none() {
                return Err(VaultError::new(
                    &format!("凭证 \"{ty}/{name}\" 不存在"),
                    &format!("Credential \"{ty}/{name}\" not found"),
                ));
            }
            Ok((ty.clone(), name.clone()))
        })
    }
}

/// Best effort: keep the device binding secret out of Time Machine (a sticky exclusion that
/// survives copies), so a backup of `vault.enc` and this secret don't travel together. Restoring
/// such a backup elsewhere uses the recovery passphrase instead.
fn exclude_from_backups(path: &Path) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("/usr/bin/tmutil")
            .arg("addexclusion")
            .arg(path)
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    #[cfg(not(target_os = "macos"))]
    let _ = path;
}

struct LockGuard<'a> {
    vault: &'a Vault,
}

impl Drop for LockGuard<'_> {
    fn drop(&mut self) {
        self.vault.unlock();
    }
}

fn base64_encode(b: impl AsRef<[u8]>) -> String {
    use base64::engine::{general_purpose::STANDARD, Engine};
    STANDARD.encode(b)
}

fn base64_decode(s: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    use base64::engine::{general_purpose::STANDARD, Engine};
    STANDARD.decode(s)
}

#[derive(Debug, Clone, Serialize)]
pub struct ListTypesEntry {
    pub name: String,
    pub description: String,
    pub count: usize,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateTypeResult {
    pub name: String,
    pub created: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListEntry {
    pub r#type: String,
    pub name: String,
    pub kind: Kind,
    pub description: String,
    pub attributes: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpConfig>,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GetResult {
    pub r#type: String,
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<HashMap<String, String>>,
    pub description: String,
    pub attributes: HashMap<String, String>,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SetResult {
    pub r#type: String,
    pub name: String,
    #[serde(rename = "typeCreated")]
    pub type_created: bool,
    pub replaced: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SetParams {
    pub r#type: String,
    pub name: String,
    pub value: Option<String>,
    pub secrets: Option<HashMap<String, String>>,
    pub http: Option<HttpConfig>,
    pub template: Option<String>,
    pub description: Option<String>,
    pub attributes: Option<HashMap<String, String>>,
    pub type_description: Option<String>,
    pub overwrite: bool,
}

#[derive(Debug, Clone)]
pub struct SetProtocolParams {
    pub r#type: String,
    pub name: String,
    pub kind: Kind,
    pub config: serde_json::Value,
    pub secrets: HashMap<String, String>,
    pub description: Option<String>,
    pub type_description: Option<String>,
    pub overwrite: bool,
}

#[cfg(test)]
mod device_binding_tests {
    use super::*;
    use crate::EnclaveMetadata;
    use base64::{engine::general_purpose::STANDARD, Engine};

    const PASSWORD: &str = "a separate offline recovery passphrase";
    const NEW_PASSWORD: &str = "another separate recovery passphrase";

    fn enclave_metadata() -> EnclaveMetadata {
        let mut peer = [5u8; 65];
        peer[0] = 4;
        EnclaveMetadata {
            version: 1,
            key_blob: STANDARD.encode([5u8]),
            peer_public_key: STANDARD.encode(peer),
        }
    }

    struct Fixed;
    impl MasterKeyProvider for Fixed {
        fn create(&self, _reason: &str) -> Result<EnclaveKey> {
            Ok(EnclaveKey {
                key: MasterKey::new([5u8; 32]),
                metadata: enclave_metadata(),
            })
        }
        fn unlock(&self, metadata: &EnclaveMetadata, _reason: &str) -> Result<MasterKey> {
            assert_eq!(metadata, &enclave_metadata());
            Ok(MasterKey::new([5u8; 32]))
        }
    }

    #[test]
    fn unbound_vaults_from_earlier_versions_open_and_rotation_binds_them() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = Vault::new(tmp.path().join("vault"));
        vault.prepare().unwrap();
        // Exactly what the previous version wrote: the vault key is the hardware key itself.
        let metadata = MasterKeyMetadata {
            provider: ProviderId::SecureEnclave,
            enclave: enclave_metadata(),
            recovery: WrappedMasterKey::wrap(&[5u8; 32], PASSWORD).unwrap(),
            device_binding: None,
        };
        let bytes = Vault::encrypt_file(&VaultData::empty(), &[5u8; 32], Some(metadata)).unwrap();
        vault.atomic_write(&bytes).unwrap();

        let old = Vault::new(&vault.dir);
        old.init_with_provider(&Fixed, "test").unwrap();
        assert!(!old.protection().unwrap().device_binding);
        old.set(SetParams {
            r#type: "api_key".into(),
            name: "example".into(),
            value: Some("kept-through-rotation".into()),
            ..Default::default()
        })
        .unwrap();

        let stale = Vault::new(&vault.dir);
        stale.init_with_provider(&Fixed, "test").unwrap();
        old.rotate_enclave(&Fixed, NEW_PASSWORD, "test").unwrap();
        let status = old.protection().unwrap();
        assert!(status.device_binding);
        let binding = std::fs::read_dir(&vault.dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .find(|n| n.starts_with("device-binding-") && n.ends_with(".key"))
            .expect("rotation creates a digest-named binding file");
        assert_eq!(
            std::fs::metadata(vault.dir.join(binding)).unwrap().mode() & 0o777,
            0o600
        );
        assert!(
            stale.get("api_key", "example").is_err(),
            "older sessions are invalidated"
        );

        let reopened = Vault::new(&vault.dir);
        reopened.init_with_provider(&Fixed, "test").unwrap();
        assert_eq!(
            reopened.get("api_key", "example").unwrap().value,
            "kept-through-rotation"
        );
        // The hardware key alone (what any process reading a vault copy can derive after one
        // approved prompt) no longer decrypts.
        let file: crate::types::EncryptedFile =
            serde_json::from_slice(&std::fs::read(vault.dir.join("vault.enc")).unwrap()).unwrap();
        assert!(Vault::decrypt_file(&file, &[5u8; 32]).is_err());
        // The old passphrase no longer opens the current vault; the new one does.
        assert!(Vault::new(&vault.dir)
            .open_recovery_read_only(PASSWORD)
            .is_err());
        assert_eq!(
            Vault::new(&vault.dir)
                .open_recovery_read_only(NEW_PASSWORD)
                .unwrap(),
            1
        );
    }

    #[test]
    fn read_only_or_unprotected_handles_cannot_rotate() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = Vault::new(tmp.path().join("vault"));
        vault.initialize_enclave(&Fixed, PASSWORD, "test").unwrap();
        let emergency = Vault::new(&vault.dir);
        emergency.open_recovery_read_only(PASSWORD).unwrap();
        assert!(emergency
            .rotate_enclave(&Fixed, NEW_PASSWORD, "test")
            .is_err());
        assert!(Vault::new(&vault.dir)
            .rotate_enclave(&Fixed, NEW_PASSWORD, "test")
            .is_err());
        assert!(vault.rotate_enclave(&Fixed, "short", "test").is_err());
    }
}
