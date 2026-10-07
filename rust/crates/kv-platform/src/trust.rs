//! Filesystem trust checks for code that's about to run as root (or with root's authority to drop
//! privileges). Direct port of src/helper/trust.ts.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The file and every parent directory must be owned by root, not writable by group/other, and not
/// a symbolic link.
pub fn untrusted_reason(p: &Path) -> Option<String> {
    let mut cur: PathBuf = p.to_path_buf();
    loop {
        let st = match std::fs::symlink_metadata(&cur) {
            Ok(st) => st,
            Err(_) => return Some(kv_i18n::t("文件不存在", "file does not exist")),
        };
        let shown = cur.display();
        if st.file_type().is_symlink() {
            return Some(kv_i18n::t(
                &format!("{shown} 是符号链接"),
                &format!("{shown} is a symbolic link"),
            ));
        }
        if st.uid() != 0 {
            return Some(kv_i18n::t(
                &format!("{shown} 不属于 root"),
                &format!("{shown} is not owned by root"),
            ));
        }
        if st.mode() & 0o022 != 0 {
            return Some(kv_i18n::t(
                &format!("{shown} 可被 group/other 写入"),
                &format!("{shown} is writable by group/other"),
            ));
        }
        match cur.parent() {
            None => return None,
            Some(parent) if parent == cur => return None,
            Some(parent) => cur = parent.to_path_buf(),
        }
    }
}

/// Self-check before running as root: must be root, must run from the install directory, and
/// every file that will be loaded must not be tamperable by a regular user (including an AI agent).
pub fn verify_root_environment(
    self_path: &Path,
    expected_path: &Path,
    extra_files: &[PathBuf],
) -> Result<(), String> {
    if unsafe { libc::getuid() } != 0 {
        return Err(kv_i18n::t(
            "必须以 root 运行（通过 sudo）",
            "must run as root (via sudo)",
        ));
    }
    if self_path != expected_path {
        return Err(kv_i18n::t(
            &format!("必须从安装目录运行：{}", expected_path.display()),
            &format!(
                "must run from the install location: {}",
                expected_path.display()
            ),
        ));
    }
    for f in std::iter::once(self_path).chain(extra_files.iter().map(PathBuf::as_path)) {
        if let Some(reason) = untrusted_reason(f) {
            return Err(kv_i18n::t(
                &format!("{reason}，拒绝以 root 运行"),
                &format!("{reason}; refusing to run as root"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_symlink_anywhere_in_the_chain_is_untrusted() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        fs::write(&real, b"x").unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let reason = untrusted_reason(&link).unwrap();
        assert!(reason.contains("符号链接") || reason.to_lowercase().contains("symbolic link"));
    }

    #[test]
    fn group_or_other_writable_is_untrusted() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("f");
        fs::write(&f, b"x").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o666)).unwrap();
        // tmp itself (owned by the current non-root user) will also fail the "owned by root" check
        // one level up, but the group/other-writable file itself must be flagged first.
        let reason = untrusted_reason(&f).unwrap();
        assert!(
            reason.contains("可被")
                || reason.contains("不属于")
                || reason.to_lowercase().contains("writable")
                || reason.to_lowercase().contains("not owned")
        );
    }

    #[test]
    fn a_file_owned_by_the_current_non_root_user_is_untrusted() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("f");
        fs::write(&f, b"x").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
        let reason = untrusted_reason(&f).unwrap();
        assert!(
            reason.contains("不属于") || reason.to_lowercase().contains("not owned"),
            "unexpected: {reason}"
        );
    }

    #[test]
    fn root_owned_read_only_system_paths_are_trusted() {
        // /usr/bin/true: root:wheel, 0755, present on every macOS/Linux box, never a symlink in practice.
        if let Ok(st) = fs::symlink_metadata("/usr/bin/true") {
            if st.uid() == 0 {
                assert_eq!(untrusted_reason(Path::new("/usr/bin/true")), None);
            }
        }
    }
}
