//! Explicit credential exports and gateway environment files. Raw tool results are never cached
//! on disk. Private files are created relative to verified directory descriptors, without following
//! symlinks; locking, expiry and helper disconnect revoke writes and remove this session's files.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

struct State {
    active: bool,
    files: Vec<(File, CString)>,
}
static CREATED: Mutex<State> = Mutex::new(State {
    active: false,
    files: Vec::new(),
});

struct PrivateDir {
    fd: File,
    path: PathBuf,
}
impl PrivateDir {
    fn open(home: &Path) -> io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        // HOME itself may legitimately be a symlink (it is the user's own setting, not an
        // attacker-controlled path); everything KeyValet creates below it is opened without
        // following symlinks and ownership-checked.
        let home_fd = File::options()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(home)?;
        let parent = Self::child(&home_fd, ".keyvalet")?;
        let fd = Self::child(&parent, "run")?;
        Ok(Self {
            fd,
            path: home.join(".keyvalet/run"),
        })
    }
    fn child(parent: &File, name: &str) -> io::Result<File> {
        let name = CString::new(name).unwrap();
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::AlreadyExists {
                return Err(e);
            }
        }
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { File::from_raw_fd(raw) };
        if fd.metadata()?.uid() != unsafe { libc::getuid() } {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Private directory owner mismatch",
            ));
        }
        fd.set_permissions(std::fs::Permissions::from_mode(0o700))?;
        Ok(fd)
    }
    fn write(&self, name: &str, content: &[u8]) -> io::Result<(PathBuf, CString)> {
        let name = CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid filename"))?;
        let raw = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut fd = unsafe { File::from_raw_fd(raw) };
        if let Err(e) = fd.write_all(content) {
            self.remove(&name);
            return Err(e);
        }
        Ok((self.path.join(name.to_str().unwrap()), name))
    }
    fn remove(&self, name: &CString) {
        unsafe {
            libc::unlinkat(self.fd.as_raw_fd(), name.as_ptr(), 0);
        }
    }
    fn purge_legacy(&self) -> io::Result<()> {
        for entry in std::fs::read_dir(&self.path)?.flatten() {
            let filename = entry.file_name();
            let suffix = entry.path().extension().map(|e| e.to_os_string());
            let dead_creator = filename
                .to_str()
                .and_then(|name| name.split_once('-'))
                .is_some_and(|(tag, _)| creator_gone(tag));
            if suffix.as_deref().is_some_and(|e| e == "redact")
                || (dead_creator && suffix.as_deref().is_some_and(|e| e == "key" || e == "env"))
            {
                if let Ok(name) = CString::new(entry.file_name().as_encoded_bytes()) {
                    self.remove(&name);
                }
            }
        }
        Ok(())
    }
}

/// Kernel start time of `pid` in microseconds, to tell a process apart from a later one that
/// reuses its PID. `None` where unavailable (e.g. another user's process).
#[cfg(target_os = "macos")]
fn start_time(pid: i32) -> Option<u64> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        )
    };
    (n == size).then(|| info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
}
#[cfg(not(target_os = "macos"))]
fn start_time(_pid: i32) -> Option<u64> {
    None
}

/// The creator tag at the start of every file this process writes: `pid.start`, or `pid` where
/// the start time is unavailable.
fn own_tag() -> &'static str {
    static TAG: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TAG.get_or_init(|| {
        let pid = std::process::id();
        match start_time(pid as i32) {
            Some(start) => format!("{pid}.{start}"),
            None => pid.to_string(),
        }
    })
}

/// Whether the session that wrote a file is gone. Fails toward keeping files: only a process
/// that no longer exists, or whose PID now belongs to a process started at a different time,
/// counts as gone. Files from versions that named them by a 12-hex session ID predate this
/// cleanup and are always removed (the installer stops older sessions before upgrading).
fn creator_gone(tag: &str) -> bool {
    if tag.len() == 12 && tag.bytes().all(|b| b.is_ascii_hexdigit()) {
        return true;
    }
    let (pid, start) = match tag.split_once('.') {
        Some((pid, start)) => (pid, Some(start)),
        None => (tag, None),
    };
    let Some(pid) = pid.parse::<i32>().ok().filter(|pid| *pid > 0) else {
        return false;
    };
    if unsafe { libc::kill(pid, 0) } != 0 {
        return io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
    }
    match (start.and_then(|s| s.parse::<u64>().ok()), start_time(pid)) {
        (Some(recorded), Some(actual)) => recorded != actual,
        _ => false,
    }
}

fn private_dir() -> io::Result<PrivateDir> {
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Missing home directory"))?;
    PrivateDir::open(Path::new(&home))
}

pub fn purge_legacy_records() {
    if let Ok(dir) = private_dir() {
        let _ = dir.purge_legacy();
    }
}
pub fn activate_session_files() {
    CREATED.lock().unwrap().active = true;
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | ':' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}
/// POSIX shell single-quoting.
pub fn quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', r"'\''"))
}

fn write_private(label: &str, suffix: &str, content: &[u8]) -> io::Result<PathBuf> {
    let mut state = CREATED.lock().unwrap();
    if !state.active {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Credential session is locked",
        ));
    }
    let dir = private_dir()?;
    // Long type/name/field combinations must not exceed the 255-byte filename limit; the random
    // suffix keeps shortened names unique.
    let label: String = sanitize(label).chars().take(120).collect();
    let name = format!(
        "{}-{label}-{:016x}.{suffix}",
        own_tag(),
        rand::random::<u64>()
    );
    let directory = dir.fd.try_clone()?;
    let (path, name) = dir.write(&name, content)?;
    state.files.push((directory, name));
    Ok(path)
}

pub fn write_gateway_env(
    session: &str,
    ty: &str,
    name: &str,
    env: &[(String, String)],
) -> io::Result<PathBuf> {
    let body = zeroize::Zeroizing::new(
        env.iter()
            .map(|(k, v)| format!("export {k}={}\n", quote(v)))
            .collect::<String>(),
    );
    write_private(&format!("{session}-{ty}-{name}"), "env", body.as_bytes())
}

pub fn write_secret_file(
    session: &str,
    ty: &str,
    name: &str,
    field: Option<&str>,
    content: &str,
) -> io::Result<PathBuf> {
    let suffix = field.map(|f| format!("-{f}")).unwrap_or_default();
    write_private(
        &format!("{session}-{ty}-{name}{suffix}"),
        "key",
        content.as_bytes(),
    )
}

pub fn cleanup_gateway_env() {
    let mut state = CREATED.lock().unwrap();
    revoke(&mut state);
}

fn revoke(state: &mut State) {
    state.active = false;
    for (dir, name) in state.files.drain(..) {
        unsafe {
            libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    #[test]
    fn private_exports_reject_symlinks_and_existing_files_without_touching_targets() {
        let home = tempfile::tempdir().unwrap();
        let dir = PrivateDir::open(home.path()).unwrap();
        let target = home.path().join("target");
        std::fs::write(&target, "original").unwrap();
        symlink(&target, dir.path.join("credential.key")).unwrap();
        assert!(dir.write("credential.key", b"secret").is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "original");
        let (path, _) = dir.write("new.key", b"synthetic-password").unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(dir.write("new.key", b"replacement").is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"synthetic-password");
    }
    #[test]
    fn creator_tags_survive_pid_reuse_and_legacy_names_are_removed() {
        assert!(!creator_gone(own_tag()), "this process is alive");
        let pid = std::process::id();
        if let Some(start) = start_time(pid as i32) {
            assert!(
                creator_gone(&format!("{pid}.{}", start + 1)),
                "same PID, different start time: a reused PID"
            );
        }
        assert!(creator_gone("2147483647.1"));
        assert!(creator_gone("0123456789ab"), "pre-upgrade session-ID names");
        assert!(!creator_gone("other"), "unknown names are kept");
    }
    #[test]
    fn long_labels_still_fit_a_filename_and_a_symlinked_home_works() {
        let real = tempfile::tempdir().unwrap();
        let links = tempfile::tempdir().unwrap();
        let home = links.path().join("home");
        symlink(real.path(), &home).unwrap();
        let dir = PrivateDir::open(&home).unwrap();
        let label: String = sanitize(&"x".repeat(400)).chars().take(120).collect();
        let name = format!("{}-{label}-{:016x}.key", own_tag(), 1u64);
        assert!(name.len() < 255);
        dir.write(&name, b"synthetic").unwrap();
        assert!(real.path().join(".keyvalet/run").join(&name).exists());
    }
    #[test]
    fn private_directory_rejects_symlinked_ancestors() {
        let home = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        symlink(target.path(), home.path().join(".keyvalet")).unwrap();
        assert!(PrivateDir::open(home.path()).is_err());
        assert!(!target.path().join("run").exists());
    }
    #[test]
    fn legacy_plaintext_records_are_unlinked_without_following_symlinks() {
        let home = tempfile::tempdir().unwrap();
        let dir = PrivateDir::open(home.path()).unwrap();
        let target = home.path().join("target");
        std::fs::write(&target, "original").unwrap();
        symlink(&target, dir.path.join("old.redact")).unwrap();
        dir.write("other.env", b"token").unwrap();
        dir.write("2147483647-test.key", b"synthetic-password")
            .unwrap();
        dir.purge_legacy().unwrap();
        assert!(!dir.path.join("old.redact").exists());
        assert!(dir.path.join("other.env").exists());
        assert!(!dir.path.join("2147483647-test.key").exists());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "original");
    }
    #[tokio::test]
    async fn locking_removes_files_and_rejects_late_writes() {
        let home = tempfile::tempdir().unwrap();
        let dir = PrivateDir::open(home.path()).unwrap();
        let (path, name) = dir.write("test.key", b"synthetic-password").unwrap();
        {
            let mut state = CREATED.lock().unwrap();
            state.active = true;
            state.files.push((dir.fd.try_clone().unwrap(), name));
        }
        crate::session::HelperSession::new(std::time::Duration::ZERO)
            .lock()
            .await;
        assert!(!path.exists());
        assert!(
            write_secret_file("test", "api_key", "review", None, "synthetic-password").is_err()
        );
    }
    #[test]
    fn sanitize_and_quote_are_safe() {
        assert_eq!(sanitize("user@host:/path"), "user@host:_path");
        assert_eq!(quote("it's"), r"'it'\''s'");
    }
}
