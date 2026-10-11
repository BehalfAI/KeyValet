//! Windows session files are created with protected owner-only DACLs. Directory handles pin
//! every private ancestor; file handles make revocation target the created object, not its name.

use kv_platform::fs::{delete_open_file, UserPrivateDir};
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;

pub use crate::windows_script::quote;

struct State {
    active: bool,
    files: Vec<(UserPrivateDir, std::fs::File)>,
}
static CREATED: Mutex<State> = Mutex::new(State {
    active: false,
    files: Vec::new(),
});

pub fn purge_legacy_records() {
    if let Some(home) = std::env::var_os("USERPROFILE") {
        if let Ok(dir) = UserPrivateDir::open(std::path::Path::new(&home)) {
            let _ = dir.purge_dead_files();
        }
    }
}
pub fn activate_session_files() {
    CREATED.lock().unwrap().active = true;
}
pub fn cleanup_gateway_env() {
    let mut state = CREATED.lock().unwrap();
    state.active = false;
    for (_, file) in state.files.drain(..) {
        let _ = delete_open_file(&file);
    }
}

fn write_private(label: &str, suffix: &str, content: &[u8]) -> io::Result<PathBuf> {
    let mut state = CREATED.lock().unwrap();
    if !state.active {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Credential session is locked",
        ));
    }
    let home = std::env::var_os("USERPROFILE")
        .ok_or_else(|| io::Error::other("USERPROFILE is missing"))?;
    let directory = UserPrivateDir::open(std::path::Path::new(&home))?;
    let label: String = label
        .chars()
        .take(100)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let pid = std::process::id();
    let birth = kv_platform::peer::process_start_time(pid)?;
    let name = format!(
        "{pid}.{birth}-{label}-{:016x}.{suffix}",
        rand::random::<u64>()
    );
    let (path, file) = directory.write_new(&name, content)?;
    state.files.push((directory, file));
    Ok(path)
}

pub fn write_gateway_env(
    session: &str,
    ty: &str,
    name: &str,
    env: &[(String, String)],
) -> io::Result<PathBuf> {
    let body = crate::windows_script::render_env(env)?;
    write_private(&format!("{session}-{ty}-{name}"), "ps1", body.as_bytes())
}

pub fn write_secret_file(
    session: &str,
    ty: &str,
    name: &str,
    field: Option<&str>,
    content: &str,
) -> io::Result<PathBuf> {
    write_private(
        &format!("{session}-{ty}-{name}-{}", field.unwrap_or("value")),
        "key",
        content.as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_files_reject_existing_names_and_delete_the_original_object() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = UserPrivateDir::open(tmp.path()).unwrap();
        let (path, file) = dir.write_new("123-test.key", b"synthetic").unwrap();
        assert!(dir.write_new("123-test.key", b"replacement").is_err());
        assert!(dir.write_new("123-test.key:stream", b"secret").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"synthetic");
        let moved = path.with_file_name("123-moved.key");
        std::fs::rename(&path, &moved).unwrap();
        let (_, replacement) = dir.write_new("123-test.key", b"replacement").unwrap();
        delete_open_file(&file).unwrap();
        drop(file);
        assert!(!moved.exists());
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        drop(replacement);
    }
    #[test]
    fn locking_blocks_late_exports_before_touching_the_filesystem() {
        cleanup_gateway_env();
        let error = write_secret_file("session", "api_key", "test", None, "synthetic").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}
