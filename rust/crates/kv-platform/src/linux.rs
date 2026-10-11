//! Linux service identities, independent polkit approvals and TPM-backed vault keys.
//! TPM tools use a fixed device TCTI and trusted absolute executables. A TPM failure
//! never falls back to the explicitly selected software provider.
use crate::paths::{OWNER_UID_FILE, PKCHECK_BIN, SERVICE_USER, VAULT_DIR};
use crate::{AuthOutcome, Authenticator, Confirmer};
use base64::{engine::general_purpose::STANDARD, Engine};
use kv_vault::{
    EnclaveKey, EnclaveMetadata, MasterKey, MasterKeyProvider, ProviderId, Result, TpmMetadata,
    VaultError,
};
use sha2::{Digest, Sha256};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

type PasswdLookup = unsafe extern "C" fn(
    *const libc::c_char,
    *mut libc::passwd,
    *mut libc::c_char,
    usize,
    *mut *mut libc::passwd,
) -> libc::c_int;
type Chown = unsafe extern "C" fn(libc::c_int, libc::uid_t, libc::gid_t) -> libc::c_int;

/// Fixed production paths and OS operations. Keeping them together lets tests
/// exercise startup and root-management policy against isolated fixtures.
pub struct LinuxHost {
    service_user: std::ffi::CString,
    owner_file: PathBuf,
    vault_directory: PathBuf,
    passwd_lookup: PasswdLookup,
    check_trust: fn(&Path) -> Option<String>,
    uid: unsafe extern "C" fn() -> libc::uid_t,
    chown: Chown,
}

impl LinuxHost {
    pub fn system() -> Self {
        Self {
            service_user: std::ffi::CString::new(SERVICE_USER).unwrap(),
            owner_file: OWNER_UID_FILE.into(),
            vault_directory: VAULT_DIR.into(),
            passwd_lookup: libc::getpwnam_r,
            check_trust: crate::trust::untrusted_reason,
            uid: libc::getuid,
            chown: libc::fchown,
        }
    }

    pub fn service_identity(&self) -> io::Result<(u32, u32)> {
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0u8; 16384];
        let rc = unsafe {
            (self.passwd_lookup)(
                self.service_user.as_ptr(),
                &mut entry,
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                &mut result,
            )
        };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        if result.is_null() || entry.pw_uid == 0 || entry.pw_gid == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "non-root keyvalet service account is missing; reinstall KeyValet",
            ));
        }
        Ok((entry.pw_uid, entry.pw_gid))
    }

    pub fn owner_uid(&self) -> std::result::Result<u32, String> {
        if let Some(reason) = (self.check_trust)(&self.owner_file) {
            return Err(reason);
        }
        let raw = std::fs::read_to_string(&self.owner_file).map_err(|e| e.to_string())?;
        parse_owner_uid(&raw, self.service_identity().map_err(|e| e.to_string())?.0)
    }

    pub fn verify_vault_owner(&self) -> std::result::Result<u32, String> {
        let uid = self.service_identity().map_err(|e| e.to_string())?.0;
        private_path(&self.vault_directory, uid, true).map_err(|e| e.to_string())?;
        let parent = self
            .vault_directory
            .parent()
            .ok_or("missing vault parent")?;
        if let Some(reason) = (self.check_trust)(parent) {
            return Err(reason);
        }
        Ok(uid)
    }

    fn inherit_private_owner(&self, path: &Path) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        if unsafe { (self.uid)() } != 0 {
            return Ok(());
        }
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("missing parent"))?;
        let st = std::fs::symlink_metadata(parent)?;
        if !st.is_dir() || st.file_type().is_symlink() || st.mode() & 0o077 != 0 {
            return Err(io::Error::other("parent directory must be private"));
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        if unsafe { (self.chown)(file.as_raw_fd(), st.uid(), u32::MAX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// New root-management files retain the service directory's owner. An open
/// descriptor and O_NOFOLLOW keep symlinks out of the ownership change.
pub fn inherit_private_owner(path: &Path) -> io::Result<()> {
    LinuxHost::system().inherit_private_owner(path)
}

fn parse_owner_uid(raw: &str, service_uid: u32) -> std::result::Result<u32, String> {
    let uid = raw.trim().parse::<u32>().map_err(|_| "invalid owner uid")?;
    if raw.len() > 32 || uid == 0 || uid == service_uid {
        return Err("owner must be a regular user, not root or the service account".into());
    }
    Ok(uid)
}

fn private_path(path: &Path, uid: u32, directory: bool) -> io::Result<()> {
    let st = std::fs::symlink_metadata(path)?;
    if st.file_type().is_symlink()
        || st.is_dir() != directory
        || (!directory && !st.is_file())
        || st.uid() != uid
        || st.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} must be private and owned by uid {uid}", path.display()),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Polkit {
    uid: u32,
    pid: u32,
    start_time: u64,
    active: std::sync::Arc<std::sync::atomic::AtomicBool>,
    executable: String,
    command: fn(&str) -> std::result::Result<Command, String>,
    wait: fn(
        Command,
        Duration,
        Option<&std::sync::atomic::AtomicBool>,
    ) -> io::Result<std::process::ExitStatus>,
}

impl Polkit {
    pub fn for_peer(peer: crate::peer::PeerCredentials) -> io::Result<Self> {
        if peer.uid == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "root is a control client, not an approval subject",
            ));
        }
        Ok(Self {
            uid: peer.uid,
            pid: peer.pid,
            start_time: crate::peer::process_start_time(peer.pid)?,
            active: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            executable: PKCHECK_BIN.into(),
            command: trusted_command,
            wait: wait_command,
        })
    }

    pub fn cancel(&self) {
        self.active
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    fn check(&self, action: &str, message: &str) -> std::result::Result<(), String> {
        self.check_with(action, message, |action, subject, message, active| {
            let mut command = (self.command)(&self.executable)?;
            command.args([
                "--action-id",
                action,
                "--process",
                subject,
                "--allow-user-interaction",
                "--detail",
                "polkit.message",
                message,
            ]);
            (self.wait)(command, Duration::from_secs(120), Some(active)).map_err(|e| e.to_string())
        })
    }

    fn check_with(
        &self,
        action: &str,
        message: &str,
        run: impl FnOnce(
            &str,
            &str,
            &str,
            &std::sync::atomic::AtomicBool,
        ) -> std::result::Result<std::process::ExitStatus, String>,
    ) -> std::result::Result<(), String> {
        if !self.active.load(std::sync::atomic::Ordering::SeqCst)
            || crate::peer::process_start_time(self.pid).ok() != Some(self.start_time)
        {
            return Err("approval subject has exited".into());
        }
        let status = run(
            action,
            &format!("{},{},{}", self.pid, self.start_time, self.uid),
            message,
            &self.active,
        )?;
        if status.success()
            && self.active.load(std::sync::atomic::Ordering::SeqCst)
            && crate::peer::process_start_time(self.pid).ok() == Some(self.start_time)
        {
            return Ok(());
        }
        Err(kv_i18n::t(
            "polkit 认证未通过（拒绝、取消、超时或没有认证代理）。桌面会话请运行 polkit 代理；SSH 请在用户终端运行 keyvalet approve。",
            "polkit authentication failed (denied, canceled, timed out, or no agent). Run a desktop polkit agent, or keyvalet approve in your SSH terminal.",
        ))
    }

    async fn check_async(&self, action: &'static str, message: &str) -> AuthOutcome {
        let subject = self.clone();
        let message = message.to_owned();
        match tokio::task::spawn_blocking(move || subject.check(action, &message)).await {
            Ok(Ok(())) => AuthOutcome::Approved,
            Ok(Err(e)) => AuthOutcome::Error(e),
            Err(e) => AuthOutcome::Error(e.to_string()),
        }
    }
}

impl Authenticator for Polkit {
    fn peer_identity(&self) -> Option<(u32, u32)> {
        Some((self.uid, self.pid))
    }
    async fn authenticate(&self, reason: &str, _deny_label: &str) -> AuthOutcome {
        self.check_async("dev.keyvalet.use", reason).await
    }
}

impl Confirmer for Polkit {
    async fn confirm(&self, message: &str, _ok_label: &str) -> bool {
        self.check_async("dev.keyvalet.modify", message).await == AuthOutcome::Approved
    }
}

fn trusted_command(path: &str) -> std::result::Result<Command, String> {
    if let Some(reason) = crate::trust::untrusted_reason(Path::new(path)) {
        return Err(reason);
    }
    let mut command = Command::new(path);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Ok(command)
}

fn wait_command(
    mut command: Command,
    timeout: Duration,
    active: Option<&std::sync::atomic::AtomicBool>,
) -> io::Result<std::process::ExitStatus> {
    let mut child = command.spawn()?;
    wait_child(&mut child, timeout, active)
}

fn wait_child(
    child: &mut impl ChildProcess,
    timeout: Duration,
    active: Option<&std::sync::atomic::AtomicBool>,
) -> io::Result<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if active.is_some_and(|flag| !flag.load(std::sync::atomic::Ordering::SeqCst)) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "session was revoked",
            ));
        }
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "authentication or TPM command timed out",
                ));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        }
    }
}

trait ChildProcess {
    fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>>;
    fn kill(&mut self) -> io::Result<()>;
    fn wait(&mut self) -> io::Result<std::process::ExitStatus>;
}

impl ChildProcess for std::process::Child {
    fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        self.try_wait()
    }
    fn kill(&mut self) -> io::Result<()> {
        self.kill()
    }
    fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
        self.wait()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyMode {
    Tpm2,
    Software,
}

/// Creation mode is an explicit CLI choice; unlock mode always comes from the
/// authenticated vault metadata, never from TPM availability or an environment flag.
pub struct LinuxMasterKeyProvider {
    directory: PathBuf,
    owner: u32,
    mode: KeyMode,
    approval: Option<Polkit>,
    device: TpmDevice,
    command: fn(&str) -> std::result::Result<Command, String>,
    uid: unsafe extern "C" fn() -> libc::uid_t,
    write: fn(&Path, &[u8], u32) -> io::Result<()>,
    tpm_timeout: Duration,
    runner: Option<std::sync::Arc<dyn TpmRunner>>,
}

pub struct TpmDevice {
    version_file: PathBuf,
    resource_manager: PathBuf,
}
impl TpmDevice {
    pub fn system() -> Self {
        Self {
            version_file: "/sys/class/tpm/tpm0/tpm_version_major".into(),
            resource_manager: "/dev/tpmrm0".into(),
        }
    }
    pub fn available(&self) -> bool {
        std::fs::read_to_string(&self.version_file).is_ok_and(|v| v.trim() == "2")
            && self.resource_manager.exists()
    }
}

/// Keep executable trust and hardware access in the real runner. Tests drive
/// the same metadata and workspace handling with an isolated command fixture.
trait TpmRunner: Send + Sync {
    fn run(&self, name: &str, args: &[&str], directory: &Path) -> Result<Zeroizing<Vec<u8>>>;
}

impl TpmRunner for LinuxMasterKeyProvider {
    fn run(&self, name: &str, args: &[&str], directory: &Path) -> Result<Zeroizing<Vec<u8>>> {
        if let Some(runner) = &self.runner {
            return runner.run(name, args, directory);
        }
        self.tpm(name, args, directory)
    }
}

impl LinuxMasterKeyProvider {
    pub fn for_service(approval: Polkit) -> Self {
        Self::new(
            VAULT_DIR.into(),
            unsafe { libc::getuid() },
            KeyMode::Tpm2,
            Some(approval),
        )
    }

    fn new(directory: PathBuf, owner: u32, mode: KeyMode, approval: Option<Polkit>) -> Self {
        Self {
            directory,
            owner,
            mode,
            approval,
            device: TpmDevice::system(),
            command: trusted_command,
            uid: libc::getuid,
            write: write_private,
            tpm_timeout: Duration::from_secs(30),
            runner: None,
        }
    }

    /// Only the verified, sudo-launched management CLI may bypass polkit.
    pub fn for_root_cli(mode: KeyMode) -> Result<Self> {
        Self::for_root_cli_with(mode, &LinuxHost::system())
    }

    fn for_root_cli_with(mode: KeyMode, host: &LinuxHost) -> Result<Self> {
        if unsafe { (host.uid)() } != 0 {
            return Err(error("management requires root"));
        }
        let owner = host.verify_vault_owner().map_err(error)?;
        Ok(Self::new(host.vault_directory.clone(), owner, mode, None))
    }

    /// Invoke only after the vault's new metadata was committed and validated.
    pub fn cleanup_software_keys(&self, current: &EnclaveMetadata) -> Result<()> {
        private_path(&self.directory, self.owner, true)?;
        let keep = if current.provider()? == ProviderId::SoftwareKey {
            Some(self.software_path(&current.decode()?.0))
        } else {
            None
        };
        for entry in std::fs::read_dir(&self.directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(id) = name
                .to_str()
                .and_then(|n| n.strip_prefix("software-"))
                .and_then(|n| n.strip_suffix(".key"))
            else {
                continue;
            };
            if id.len() != 64
                || !id.bytes().all(|b| b.is_ascii_hexdigit())
                || keep.as_ref() == Some(&entry.path())
            {
                continue;
            }
            private_path(&entry.path(), self.owner, false)?;
            std::fs::remove_file(entry.path())?;
        }
        Ok(())
    }

    fn authorize(&self, reason: &str) -> Result<()> {
        if let Some(approval) = &self.approval {
            approval.check("dev.keyvalet.unlock", reason).map_err(error)
        } else if unsafe { (self.uid)() } == 0 {
            Ok(())
        } else {
            Err(error("polkit approval subject is required"))
        }
    }

    fn workspace(&self) -> Result<tempfile::TempDir> {
        private_path(&self.directory, self.owner, true)?;
        let temp = tempfile::Builder::new()
            .prefix(".tpm-")
            .tempdir_in(&self.directory)?;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))?;
        Ok(temp)
    }

    fn tpm(&self, name: &str, args: &[&str], directory: &Path) -> Result<Zeroizing<Vec<u8>>> {
        if !self.device.available() {
            return Err(error("TPM 2.0 resource manager is unavailable; hardware vaults never fall back to software"));
        }
        let mut command = (self.command)(&format!("/usr/bin/tpm2_{name}")).map_err(error)?;
        let tcti = format!("device:{}", self.device.resource_manager.display());
        command
            .current_dir(directory)
            .args(["-T", &tcti, "-Q"])
            .args(args);
        command.stdout(Stdio::piped());
        let mut child = command.spawn()?;
        let status = wait_child(
            &mut child,
            self.tpm_timeout,
            self.approval.as_ref().map(|p| p.active.as_ref()),
        )?;
        if !status.success() {
            return Err(error(format!("tpm2_{name} failed ({status}); check TPM access, tpm2-tools and hierarchy authorization. No software fallback was used")));
        }
        use std::io::Read;
        let mut output = Zeroizing::new(Vec::with_capacity(4096));
        child
            .stdout
            .take()
            .unwrap()
            .take(4096)
            .read_to_end(&mut output)?;
        Ok(output)
    }

    fn primary(tpm: &impl TpmRunner, directory: &Path) -> Result<()> {
        tpm.run(
            "createprimary",
            &["-C", "o", "-G", "ecc", "-g", "sha256", "-c", "parent.ctx"],
            directory,
        )
        .map(|_| ())
    }

    fn create_tpm(&self) -> Result<EnclaveKey> {
        self.create_tpm_with(self)
    }

    fn create_tpm_with(&self, tpm: &impl TpmRunner) -> Result<EnclaveKey> {
        let temp = self.workspace()?;
        let dir = temp.path();
        Self::primary(tpm, dir)?;
        tpm.run(
            "create",
            &[
                "-C",
                "parent.ctx",
                "-G",
                "ecc256:ecdh",
                "-u",
                "key.pub",
                "-r",
                "key.priv",
                "-a",
                "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|noda",
            ],
            dir,
        )?;
        tpm.run(
            "load",
            &[
                "-C",
                "parent.ctx",
                "-u",
                "key.pub",
                "-r",
                "key.priv",
                "-c",
                "key.ctx",
            ],
            dir,
        )?;
        // The derived secret travels over an anonymous pipe, never a temporary disk file.
        let secret = tpm.run(
            "ecdhkeygen",
            &["-c", "key.ctx", "-u", "peer.point", "-o", "/dev/stdout"],
            dir,
        )?;
        let info = TpmMetadata {
            public_blob: STANDARD.encode(std::fs::read(dir.join("key.pub"))?),
            private_blob: STANDARD.encode(std::fs::read(dir.join("key.priv"))?),
        };
        let peer = std::fs::read(dir.join("peer.point"))?;
        let metadata = EnclaveMetadata::tpm2(&info, &peer)?;
        let key = derived_secret(&secret)?;
        Ok(EnclaveKey { key, metadata })
    }

    fn unlock_tpm(&self, metadata: &EnclaveMetadata) -> Result<MasterKey> {
        self.unlock_tpm_with(metadata, self)
    }

    fn unlock_tpm_with(
        &self,
        metadata: &EnclaveMetadata,
        tpm: &impl TpmRunner,
    ) -> Result<MasterKey> {
        let (blob, peer) = metadata.decode()?;
        let info: TpmMetadata = serde_json::from_slice(&blob)?;
        let temp = self.workspace()?;
        let dir = temp.path();
        (self.write)(
            &dir.join("key.pub"),
            &STANDARD
                .decode(info.public_blob)
                .map_err(|_| error("invalid TPM public blob"))?,
            unsafe { libc::getuid() },
        )?;
        (self.write)(
            &dir.join("key.priv"),
            &STANDARD
                .decode(info.private_blob)
                .map_err(|_| error("invalid TPM private blob"))?,
            unsafe { libc::getuid() },
        )?;
        (self.write)(&dir.join("peer.point"), &peer, unsafe { libc::getuid() })?;
        Self::primary(tpm, dir)?;
        tpm.run(
            "load",
            &[
                "-C",
                "parent.ctx",
                "-u",
                "key.pub",
                "-r",
                "key.priv",
                "-c",
                "key.ctx",
            ],
            dir,
        )?;
        let secret = tpm.run(
            "ecdhzgen",
            &["-c", "key.ctx", "-u", "peer.point", "-o", "/dev/stdout"],
            dir,
        )?;
        derived_secret(&secret)
    }

    fn software_path(&self, digest: &[u8]) -> PathBuf {
        self.directory.join(format!(
            "software-{}.key",
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ))
    }

    fn create_software(&self) -> Result<EnclaveKey> {
        private_path(&self.directory, self.owner, true)?;
        let mut key = MasterKey::default();
        // Reuse the vault's OS entropy source without introducing a second RNG backend.
        let mut entropy = std::fs::File::open("/dev/urandom")?;
        use std::io::Read;
        entropy.read_exact(key.as_mut())?;
        let digest: [u8; 32] = Sha256::digest(key.as_ref()).into();
        let path = self.software_path(&digest);
        (self.write)(&path, key.as_ref(), self.owner)?;
        Ok(EnclaveKey {
            key,
            metadata: EnclaveMetadata::software(&digest),
        })
    }

    fn unlock_software(&self, metadata: &EnclaveMetadata) -> Result<MasterKey> {
        let (digest, _) = metadata.decode()?;
        let path = self.software_path(&digest);
        private_path(&self.directory, self.owner, true)?;
        if let Err(e) = private_path(&path, self.owner, false) {
            if e.kind() == io::ErrorKind::NotFound {
                return Err(error("software key is missing; use recover-vault --software on a machine without TPM"));
            }
            return Err(e.into());
        }
        let raw = Zeroizing::new(std::fs::read(path)?);
        if raw.len() != 32 || Sha256::digest(raw.as_slice()).as_slice() != digest {
            return Err(error("software key does not match; use recover-vault"));
        }
        let mut key = MasterKey::default();
        key.copy_from_slice(&raw);
        Ok(key)
    }
}

impl MasterKeyProvider for LinuxMasterKeyProvider {
    fn create(&self, reason: &str) -> Result<EnclaveKey> {
        self.authorize(reason)?;
        match self.mode {
            KeyMode::Tpm2 => self.create_tpm(),
            KeyMode::Software => self.create_software(),
        }
    }

    fn unlock(&self, metadata: &EnclaveMetadata, reason: &str) -> Result<MasterKey> {
        let provider = metadata.provider()?;
        if matches!(provider, ProviderId::Tpm2 | ProviderId::SoftwareKey) {
            self.authorize(reason)?;
        }
        let key = match provider {
            ProviderId::Tpm2 => self.unlock_tpm(metadata),
            ProviderId::SoftwareKey => self.unlock_software(metadata),
            _ => {
                return Err(error(
                    "vault belongs to another platform; recover it explicitly",
                ))
            }
        }?;
        if self
            .approval
            .as_ref()
            .is_some_and(|p| !p.active.load(std::sync::atomic::Ordering::SeqCst))
        {
            return Err(error("session was revoked"));
        }
        Ok(key)
    }
}

fn derived_secret(secret: &[u8]) -> Result<MasterKey> {
    // The command writes a TPM2B_ECC_POINT (P-256).
    if secret.len() != 70 || secret[..4] != [0, 0x44, 0, 0x20] || secret[36..38] != [0, 0x20] {
        return Err(error("invalid TPM ECDH result"));
    }
    let mut key = MasterKey::default();
    hkdf::Hkdf::<Sha256>::new(None, &secret[4..36])
        .expand(b"keyvalet/master-key/tpm2-ecdh/v1", key.as_mut())
        .expect("32-byte output is within the HKDF-SHA256 limit");
    Ok(key)
}

fn write_private(path: &Path, bytes: &[u8], owner: u32) -> io::Result<()> {
    write_private_with(path, bytes, owner, unsafe { libc::getuid() }, libc::fchown)
}

fn write_private_with(
    path: &Path,
    bytes: &[u8],
    owner: u32,
    caller_uid: u32,
    chown: Chown,
) -> io::Result<()> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if caller_uid == 0 && unsafe { chown(file.as_raw_fd(), owner, u32::MAX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    file.write_all(bytes)?;
    file.sync_all()
}

fn error(message: impl AsRef<str>) -> VaultError {
    VaultError::new(message.as_ref(), message.as_ref())
}

#[cfg(test)]
mod tests;
