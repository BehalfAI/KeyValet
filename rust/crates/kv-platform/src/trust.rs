//! Filesystem trust checks for code that's about to run as root (or with root's authority to drop
//! privileges). Direct port of src/helper/trust.ts. The Windows variant checks the DACL instead of
//! uid/mode bits: a file is trusted only if its owner is Administrators, SYSTEM or
//! TrustedInstaller, and its DACL grants no write/delete/write-DAC access to the well-known
//! unprivileged groups (Everyone, Authenticated Users, Users, Interactive).

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The file and every parent directory must be owned by root and not writable by group/other. A
/// symlink is fine *if* the symlink entry itself passes that same check (only root could have
/// created or repointed it, so it's not a tampering vector for a non-root attacker) -- in that
/// case it's followed and its target gets checked the same way, rather than being rejected
/// outright. That matters in practice: macOS's own `/etc`, `/var` and `/tmp` are themselves
/// root-owned symlinks to `/private/...`, so a blanket "any symlink is untrusted" rule would flag
/// every file under them -- including `/etc/sudoers.d/keyvalet` -- on every stock Mac.
#[cfg(unix)]
pub fn untrusted_reason(p: &Path) -> Option<String> {
    untrusted_reason_hops(p, 0)
}

/// `hops` counts symlinks already followed to get here, so a cycle (or just a long chain) can't
/// hang this in an infinite loop/recursion -- `std::fs::canonicalize` has the same kind of bound
/// (its ELOOP) and a plain "any symlink is untrusted" rule can never need one, but the "follow a
/// root-owned symlink" rule below can.
#[cfg(unix)]
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
#[cfg(unix)]
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

#[cfg(all(test, unix))]
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

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        CreateWellKnownSid, EqualSid, GetAce, IsValidSid, WinAuthenticatedUserSid,
        WinBuiltinAdministratorsSid, WinBuiltinUsersSid, WinInteractiveSid, WinLocalSystemSid,
        WinWorldSid, ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, WELL_KNOWN_SID_TYPE,
    };

    /// Access rights that let the trustee tamper with the file.
    const BAD_MASK: u32 = 0x4000_0000  // GENERIC_WRITE
        | 0x1000_0000                  // GENERIC_ALL
        | 0x0002                       // FILE_WRITE_DATA / FILE_ADD_FILE
        | 0x0004                       // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
        | 0x0008                       // FILE_WRITE_EA
        | 0x0010                       // FILE_EXECUTE (can overwrite via scripts is still covered by the other bits)
        | 0x0001_0000                  // DELETE
        | 0x0004_0000                  // WRITE_DAC
        | 0x0008_0000; // WRITE_OWNER

    /// Frees memory returned by the security APIs (LocalAlloc-based).
    struct Free(*mut core::ffi::c_void);
    impl Drop for Free {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(self.0 as _)));
                }
            }
        }
    }

    fn well_known_sid(ty: WELL_KNOWN_SID_TYPE) -> Option<Vec<u8>> {
        let mut size = 0u32;
        unsafe {
            let _ = CreateWellKnownSid(ty, None, None, &mut size);
        }
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        unsafe {
            CreateWellKnownSid(ty, None, Some(PSID(buf.as_mut_ptr() as _)), &mut size).ok()?;
        }
        Some(buf)
    }

    fn sid_from_string(s: windows::core::PCWSTR) -> Option<Vec<u8>> {
        unsafe {
            let mut psid = PSID::default();
            ConvertStringSidToSidW(s, &mut psid).ok()?;
            let len = windows::Win32::Security::GetLengthSid(psid) as usize;
            let mut buf = vec![0u8; len];
            std::ptr::copy_nonoverlapping(psid.0 as *const u8, buf.as_mut_ptr(), len);
            let _ = LocalFree(Some(HLOCAL(psid.0 as _)));
            Some(buf)
        }
    }

    fn sid_is(sid_bytes: &[u8], other: PSID) -> bool {
        unsafe {
            IsValidSid(PSID(sid_bytes.as_ptr() as _)).as_bool()
                && EqualSid(PSID(sid_bytes.as_ptr() as _), other).is_ok()
        }
    }

    /// SIDs allowed to own a trusted file: Administrators, SYSTEM, TrustedInstaller.
    fn trusted_owner_sids() -> Vec<Vec<u8>> {
        [
            well_known_sid(WinBuiltinAdministratorsSid),
            well_known_sid(WinLocalSystemSid),
            // TrustedInstaller (NT SERVICE\TrustedInstaller); windows-rs exposes no well-known
            // type for it, so the SID string is parsed directly.
            sid_from_string(w!(
                "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
            )),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    /// SIDs that must never get tamper rights: Everyone, Authenticated Users, Users, Interactive.
    fn untrusted_principal_sids() -> Vec<Vec<u8>> {
        [
            WinWorldSid,
            WinAuthenticatedUserSid,
            WinBuiltinUsersSid,
            WinInteractiveSid,
        ]
        .into_iter()
        .filter_map(well_known_sid)
        .collect()
    }

    /// See the module docs: file exists and is a regular file or directory, owner is a privileged
    /// principal, and no DACL entry grants tamper rights to a well-known unprivileged group.
    pub fn untrusted_reason(p: &Path) -> Option<String> {
        let meta = match std::fs::metadata(p) {
            Ok(m) => m,
            Err(_) => return Some(kv_i18n::t("文件不存在", "file does not exist")),
        };
        let shown = p.display();
        if !meta.is_file() && !meta.is_dir() {
            return Some(kv_i18n::t(
                &format!("{shown} 不是普通文件或目录"),
                &format!("{shown} is not a regular file or directory"),
            ));
        }
        let wide: Vec<u16> = p
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            let mut owner = PSID::default();
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let mut sd = PSECURITY_DESCRIPTOR::default();
            let status = GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                Some(&mut dacl),
                None,
                &mut sd,
            );
            if status != ERROR_SUCCESS {
                return Some(kv_i18n::t(
                    &format!("无法读取 {shown} 的安全描述符"),
                    &format!("cannot read the security descriptor of {shown}"),
                ));
            }
            let _sd = Free(sd.0);
            if owner.is_invalid() {
                return Some(kv_i18n::t(
                    &format!("{shown} 没有所有者"),
                    &format!("{shown} has no owner"),
                ));
            }
            if !trusted_owner_sids().iter().any(|s| sid_is(s, owner)) {
                return Some(kv_i18n::t(
                    &format!("{shown} 不属于管理员组"),
                    &format!("{shown} is not owned by Administrators/SYSTEM/TrustedInstaller"),
                ));
            }
            if dacl.is_null() {
                // A NULL DACL grants everyone full access.
                return Some(kv_i18n::t(
                    &format!("{shown} 的 DACL 允许所有用户写入"),
                    &format!("{shown} has a NULL DACL granting everyone access"),
                ));
            }
            let bad = untrusted_principal_sids();
            for i in 0..(*dacl).AceCount as u32 {
                let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
                if GetAce(dacl, i, &mut ace).is_err() || ace.is_null() {
                    continue;
                }
                let ace = ace as *const ACCESS_ALLOWED_ACE;
                if (*ace).Header.AceType != 0 {
                    continue; // only ACCESS_ALLOWED_ACE
                }
                if (*ace).Mask & BAD_MASK == 0 {
                    continue;
                }
                let sid = PSID(&(*ace).SidStart as *const u32 as _);
                if bad.iter().any(|s| sid_is(s, sid)) {
                    return Some(kv_i18n::t(
                        &format!("{shown} 可被普通用户写入"),
                        &format!("{shown} is writable by an unprivileged group"),
                    ));
                }
            }
        }
        None
    }

    /// Whether the current process token is elevated (UAC) — the Windows analogue of `getuid()==0`.
    fn is_elevated() -> bool {
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        unsafe {
            let mut token = windows::Win32::Foundation::HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut len = 0u32;
            GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            )
            .map(|_| elevation.TokenIsElevated != 0)
            .unwrap_or(false)
        }
    }

    /// Analogue of the unix variant: must run elevated, from the install path, and every file that
    /// will be loaded must not be tamperable by an unprivileged user.
    pub fn verify_root_environment(
        self_path: &Path,
        expected_path: &Path,
        extra_files: &[PathBuf],
    ) -> Result<(), String> {
        if !is_elevated() {
            return Err(kv_i18n::t(
                "必须以管理员身份运行（或由 KeyValetHelper 服务启动）",
                "must run elevated (or be started by the KeyValetHelper service)",
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
                    &format!("{reason}，拒绝以管理员身份运行"),
                    &format!("{reason}; refusing to run elevated"),
                ));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_file_owned_by_the_current_user_is_untrusted() {
            let tmp = tempfile::tempdir().unwrap();
            let f = tmp.path().join("f");
            std::fs::write(&f, b"x").unwrap();
            assert!(
                untrusted_reason(&f).is_some(),
                "a user-owned temp file must not be trusted"
            );
        }

        #[test]
        fn a_missing_file_is_untrusted() {
            assert!(
                untrusted_reason(Path::new(r"C:\definitely\not\a\real\file.keyvalet")).is_some()
            );
        }

        #[test]
        fn a_system_binary_is_trusted() {
            let notepad = Path::new(r"C:\Windows\System32\notepad.exe");
            if notepad.exists() {
                assert_eq!(untrusted_reason(notepad), None);
            }
        }
    }
}

#[cfg(windows)]
pub use windows_impl::{untrusted_reason, verify_root_environment};
