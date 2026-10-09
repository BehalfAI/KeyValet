//! A fixed, trusted subprocess performs the cryptographic authentication as the login user.
use crate::{paths::TOUCHID_BIN, trust::untrusted_reason};
use kv_vault::{EnclaveKey, EnclaveMetadata, MasterKey, MasterKeyProvider, Result, VaultError};
use std::{
    io::{Read, Write},
    os::unix::process::CommandExt,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub struct EnclaveMasterKeyProvider;

impl EnclaveMasterKeyProvider {
    fn run(
        &self,
        operation: &str,
        metadata: Option<&EnclaveMetadata>,
        reason: &str,
    ) -> Result<EnclaveKey> {
        Self::run_at(Path::new(TOUCHID_BIN), operation, metadata, reason)
    }

    fn run_at(
        program: &Path,
        operation: &str,
        metadata: Option<&EnclaveMetadata>,
        reason: &str,
    ) -> Result<EnclaveKey> {
        if let Some(bad) = untrusted_reason(program) {
            return Err(VaultError::new(
                &format!("硬件密钥程序不可信（{bad}），请重新安装"),
                &format!("Hardware key program is untrusted ({bad}); reinstall KeyValet"),
            ));
        }
        let Some((uid, gid)) = crate::user::invoking_user() else {
            return Err(VaultError::new(
                "无法确定硬件密钥所属用户（SUDO_UID / SUDO_GID）",
                "Cannot determine the hardware key owner (SUDO_UID / SUDO_GID)",
            ));
        };
        let input = metadata
            .map(serde_json::to_vec)
            .transpose()?
            .unwrap_or_default();
        let mut cmd = Command::new(program);
        cmd.args([
            "--enclave",
            operation,
            reason,
            &kv_i18n::t("取消", "Cancel"),
        ])
        .current_dir("/")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
        // Not `CommandExt::uid/gid`: std calls setgroups(0, NULL) after setgid, which on macOS
        // leaves the child with effective gid 0 (wheel). `user::drop_to` installs exactly the
        // invoking user's uid/gid and a single-group list instead.
        unsafe {
            cmd.pre_exec(crate::user::drop_to(uid, gid));
        }
        let mut child = cmd.spawn()?;
        if let Err(e) = child.stdin.take().unwrap().write_all(&input) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e.into());
        }
        let mut stdout = child.stdout.take().unwrap();
        // A fixed buffer: a growing Vec would leave unzeroed copies of the key behind on realloc.
        let reader = std::thread::spawn(move || -> std::io::Result<Zeroizing<Vec<u8>>> {
            let mut buf = Zeroizing::new([0u8; 8193]);
            let mut len = 0;
            while len < buf.len() {
                match stdout.read(&mut buf[len..]) {
                    Ok(0) => break,
                    Ok(n) => len += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(Zeroizing::new(buf[..len].to_vec()))
        });
        let deadline = Instant::now() + Duration::from_secs(120);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return Err(VaultError::new(
                        "硬件密钥操作超时或失败",
                        "Hardware key operation timed out or failed",
                    ));
                }
            }
        };
        let output = reader
            .join()
            .map_err(|_| VaultError::new("读取硬件密钥失败", "Failed to read hardware key"))??;
        if !status.success() || output.len() <= 32 || output.len() > 8192 {
            return Err(VaultError::new(
                "硬件解锁失败或已取消；不会改用文件密钥",
                "Hardware unlock failed or was cancelled; file-key fallback is disabled",
            ));
        }
        Self::decode_output(&output, metadata)
    }

    fn decode_output(output: &[u8], metadata: Option<&EnclaveMetadata>) -> Result<EnclaveKey> {
        if output.len() <= 32 || output.len() > 8192 {
            return Err(VaultError::new(
                "硬件密钥响应长度不对",
                "Invalid hardware key response length",
            ));
        }
        let restored: EnclaveMetadata = serde_json::from_slice(&output[32..])?;
        restored.decode()?;
        if metadata.is_some_and(|expected| expected != &restored) {
            return Err(VaultError::new(
                "硬件密钥响应不匹配",
                "Hardware key response does not match",
            ));
        }
        let mut key: MasterKey = Default::default();
        key.copy_from_slice(&output[..32]);
        Ok(EnclaveKey {
            key,
            metadata: restored,
        })
    }
}

impl MasterKeyProvider for EnclaveMasterKeyProvider {
    fn create(&self, reason: &str) -> Result<EnclaveKey> {
        self.run("create", None, reason)
    }
    fn unlock(&self, metadata: &EnclaveMetadata, reason: &str) -> Result<MasterKey> {
        metadata.decode()?;
        Ok(self.run("derive", Some(metadata), reason)?.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    fn metadata() -> EnclaveMetadata {
        let mut peer = [0u8; 65];
        peer[0] = 4;
        EnclaveMetadata {
            version: 1,
            key_blob: STANDARD.encode([1u8]),
            peer_public_key: STANDARD.encode(peer),
        }
    }

    #[test]
    fn truncated_oversized_and_mismatched_responses_are_rejected() {
        let expected = metadata();
        let mut output = vec![8u8; 32];
        assert!(EnclaveMasterKeyProvider::decode_output(&output, None).is_err());
        output.extend_from_slice(&serde_json::to_vec(&expected).unwrap());
        assert_eq!(
            *EnclaveMasterKeyProvider::decode_output(&output, Some(&expected))
                .unwrap()
                .key,
            [8u8; 32]
        );
        let mut other = expected.clone();
        other.key_blob = STANDARD.encode([2u8]);
        assert!(EnclaveMasterKeyProvider::decode_output(&output, Some(&other)).is_err());
        assert!(EnclaveMasterKeyProvider::decode_output(&[0u8; 8193], None).is_err());
        output[32] = 0;
        assert!(EnclaveMasterKeyProvider::decode_output(&output, None).is_err());
    }

    // Deliberately unavailable from the production provider: this fixed staging path is only
    // used by an explicitly requested root test, never an environment-based binary override.
    struct Probe;
    impl MasterKeyProvider for Probe {
        fn create(&self, reason: &str) -> Result<EnclaveKey> {
            EnclaveMasterKeyProvider::run_at(
                Path::new("/usr/local/lib/keyvalet-enclave-probe/bin/kv-touchid"),
                "create",
                None,
                reason,
            )
        }
        fn unlock(&self, metadata: &EnclaveMetadata, reason: &str) -> Result<MasterKey> {
            Ok(EnclaveMasterKeyProvider::run_at(
                Path::new("/usr/local/lib/keyvalet-enclave-probe/bin/kv-touchid"),
                "derive",
                Some(metadata),
                reason,
            )?
            .key)
        }
    }

    #[test]
    #[ignore = "Interactive macOS hardware test: run the staged root-owned test binary as root with SUDO_UID and SUDO_GID"]
    fn hardware_vault_roundtrip_as_root() {
        assert_eq!(unsafe { libc::getuid() }, 0);
        // Key material must never appear in a test assertion or panic message.
        unsafe {
            libc::umask(0o077);
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            libc::setrlimit(libc::RLIMIT_CORE, &limit);
        }
        let tmp = tempfile::tempdir().unwrap();
        let vault = kv_vault::Vault::new(tmp.path().join("vault"));
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
            .set(kv_vault::SetParams {
                r#type: "test".into(),
                name: "probe".into(),
                value: Some("disposable-test-value".into()),
                ..Default::default()
            })
            .unwrap();
        let reason = "KeyValet development test: authenticate a disposable vault key";
        let password = "temporary test passphrase; never used with a real vault";
        vault.migrate_to_enclave(&Probe, password, reason).unwrap();
        assert!(!vault.dir.join("master.key").exists());
        let reopened = kv_vault::Vault::new(&vault.dir);
        reopened.init_with_provider(&Probe, reason).unwrap();
        assert!(reopened.get("test", "probe").unwrap().value == "disposable-test-value");
        let recovered = kv_vault::Vault::new(&vault.dir);
        recovered.recover_enclave(&Probe, password, reason).unwrap();
        let verified = kv_vault::Vault::new(&vault.dir);
        verified.init_with_provider(&Probe, reason).unwrap();
        assert!(verified.get("test", "probe").unwrap().value == "disposable-test-value");
        assert!(reopened.get("test", "probe").is_err());
    }
}
