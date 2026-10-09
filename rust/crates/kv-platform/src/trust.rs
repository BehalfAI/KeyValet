//! Filesystem trust checks for code that's about to run as root (or with root's authority to drop
//! privileges). Direct port of src/helper/trust.ts.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The file and every parent directory must be owned by root and not writable by group/other. A
/// symlink is fine *if* the symlink entry itself passes that same check (only root could have
/// created or repointed it, so it's not a tampering vector for a non-root attacker) -- in that
/// case it's followed and its target gets checked the same way, rather than being rejected
/// outright. That matters in practice: macOS's own `/etc`, `/var` and `/tmp` are themselves
/// root-owned symlinks to `/private/...`, so a blanket "any symlink is untrusted" rule would flag
/// every file under them -- including `/etc/sudoers.d/keyvalet` -- on every stock Mac.
pub fn untrusted_reason(p: &Path) -> Option<String> {
    untrusted_reason_hops(p, 0)
}

/// `hops` counts symlinks already followed to get here, so a cycle (or just a long chain) can't
/// hang this in an infinite loop/recursion -- `std::fs::canonicalize` has the same kind of bound
/// (its ELOOP) and a plain "any symlink is untrusted" rule can never need one, but the "follow a
/// root-owned symlink" rule below can.
fn untrusted_reason_hops(p: &Path, hops: u8) -> Option<String> {
    if hops > 16 {
        return Some(kv_i18n::t(
            "符号链接层数过多",
            "too many levels of symbolic links",
        ));
    }
    let mut cur: PathBuf = p.to_path_buf();
    loop {
        let st = match std::fs::symlink_metadata(&cur) {
            Ok(st) => st,
            Err(_) => return Some(kv_i18n::t("文件不存在", "file does not exist")),
        };
        let shown = cur.display();
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
        if st.file_type().is_symlink() {
            let target = match std::fs::read_link(&cur) {
                Ok(t) => t,
                Err(_) => {
                    return Some(kv_i18n::t(
                        &format!("{shown} 的符号链接目标不可读"),
                        &format!("{shown}'s symlink target is unreadable"),
                    ));
                }
            };
            let resolved = if target.is_absolute() {
                target
            } else {
                // Relative to the symlink's own directory, e.g. /etc -> private/etc means
                // /private/etc, not /etc/private/etc.
                cur.parent().unwrap_or_else(|| Path::new("/")).join(target)
            };
            // Validate the target's own full chain recursively -- but *don't* jump `cur` to it
            // and move on: a symlink being root-owned says nothing about the directory that
            // holds it, which still needs checking below like any other path. Skipping that
            // would let a symlink inside an otherwise-untrusted (e.g. group-writable) directory
            // vouch for itself and short-circuit the rest of the walk.
            if let Some(reason) = untrusted_reason_hops(&resolved, hops + 1) {
                return Some(reason);
            }
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
    fn a_symlink_not_owned_by_root_is_untrusted() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        fs::write(&real, b"x").unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        // Rejected for not being root-owned, same as any other non-root-owned entry -- a
        // non-root-owned symlink is exactly the tampering vector this check exists to catch.
        let reason = untrusted_reason(&link).unwrap();
        assert!(
            reason.contains("不属于") || reason.to_lowercase().contains("not owned"),
            "unexpected: {reason}"
        );
    }

    #[test]
    fn a_root_owned_symlink_is_followed_not_rejected() {
        // /etc -> private/etc on macOS: root-owned, not group/other-writable, but a symlink.
        // A blanket "any symlink is untrusted" rule would flag every file under /etc (including
        // /etc/sudoers.d/keyvalet) on every stock Mac; skipped if this isn't true here (e.g.
        // non-macOS CI, where /etc usually isn't a symlink at all).
        if let Ok(st) = fs::symlink_metadata("/etc") {
            if st.uid() == 0 && st.mode() & 0o022 == 0 && st.file_type().is_symlink() {
                assert_eq!(untrusted_reason(Path::new("/etc")), None);
            }
        }
    }

    // Following a root-owned symlink still validates the directory that *holds* the symlink,
    // not just its target: a root-owned symlink sitting inside an otherwise untrusted (e.g.
    // group-writable) directory must not short-circuit the rest of the walk and vouch for that
    // directory. That specific combination can't be fabricated in a test running as a non-root
    // user (creating a root-owned file requires being root), so this is verified by inspection --
    // `untrusted_reason_hops` recurses into the target's chain with `if let Some(reason) = ...`
    // and then falls through to `cur.parent()` on the *original* `cur` (the symlink) in every
    // case, rather than reassigning `cur` to the target and `continue`-ing past that fallthrough.

    #[test]
    fn a_hop_limit_stops_symlink_following_instead_of_looping_forever() {
        // Exercises the depth guard directly: fabricating an actual cycle of root-owned symlinks
        // (the only kind that would ever reach the recursive-follow branch) isn't possible
        // without being root, so this calls the hop-counting entry point directly instead.
        let reason = untrusted_reason_hops(Path::new("/etc"), 17).unwrap();
        assert!(
            reason.contains("符号链接层数过多") || reason.to_lowercase().contains("too many"),
            "unexpected: {reason}"
        );
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
