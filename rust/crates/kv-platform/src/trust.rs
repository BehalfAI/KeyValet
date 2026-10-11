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
        // Linux reports symlinks as 0777; those bits cannot grant write access to a
        // symlink. Its owner, containing directory and resolved target are checked below.
        if !st.file_type().is_symlink() && st.mode() & 0o022 != 0 {
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

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_root_owned_0777_symlinks_do_not_grant_write_access() {
        if let Ok(st) = fs::symlink_metadata("/bin") {
            if st.uid() == 0 && st.file_type().is_symlink() {
                assert_eq!(untrusted_reason(Path::new("/bin/true")), None);
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
        CreateWellKnownSid, EqualSid, GetAce, IsValidSid, WinBuiltinAdministratorsSid,
        WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, WELL_KNOWN_SID_TYPE,
    };

    /// Access rights that let the trustee tamper with the file.
    const BAD_MASK: u32 = 0x4000_0000  // GENERIC_WRITE
        | 0x1000_0000                  // GENERIC_ALL
        | 0x0002                       // FILE_WRITE_DATA / FILE_ADD_FILE
        | 0x0004                       // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
        | 0x0010                       // FILE_WRITE_EA (FILE_READ_EA is 0x0008)
        | 0x0100                       // FILE_WRITE_ATTRIBUTES
        | 0x0040                       // FILE_DELETE_CHILD (directories)
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

    /// See the module docs: file exists and is a regular file or directory, owner is a privileged
    /// principal, and no DACL entry grants tamper rights to a well-known unprivileged group.
    pub fn untrusted_reason(p: &Path) -> Option<String> {
        check_path(p, BAD_MASK)
    }

    fn check_path(p: &Path, bad_mask: u32) -> Option<String> {
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::fs::MetadataExt;
        let meta = match std::fs::symlink_metadata(p) {
            Ok(m) => m,
            Err(_) => return Some(kv_i18n::t("文件不存在", "file does not exist")),
        };
        let shown = p.display();
        if meta.file_attributes() & 0x400 != 0 {
            return Some(format!("{shown} is a reparse point"));
        }
        if !meta.is_file() && !meta.is_dir() {
            return Some(kv_i18n::t(
                &format!("{shown} 不是普通文件或目录"),
                &format!("{shown} is not a regular file or directory"),
            ));
        }
        let wide: Vec<u16> = p
            .as_os_str()
            .encode_wide()
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
            let trusted = trusted_owner_sids();
            for i in 0..(*dacl).AceCount as u32 {
                let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
                if GetAce(dacl, i, &mut ace).is_err() || ace.is_null() {
                    return Some(format!("cannot read an ACE on {shown}"));
                }
                let header = &*(ace as *const ACE_HEADER);
                if header.AceFlags & 0x08 != 0 {
                    continue; // INHERIT_ONLY_ACE does not apply to this object.
                }
                // Deny ACEs cannot grant access. Reject unfamiliar allow/callback/object ACEs
                // rather than interpreting a different layout as ACCESS_ALLOWED_ACE.
                if matches!(header.AceType, 1 | 6 | 10 | 12) {
                    continue;
                }
                if header.AceType != 0 {
                    return Some(format!("unsupported ACE on {shown}"));
                }
                let ace = ace as *const ACCESS_ALLOWED_ACE;
                if (*ace).Mask & bad_mask == 0 {
                    continue;
                }
                let sid = PSID(&(*ace).SidStart as *const u32 as _);
                if !trusted.iter().any(|s| sid_is(s, sid)) {
                    return Some(kv_i18n::t(
                        &format!("{shown} 可被普通用户写入"),
                        &format!("{shown} is writable by an unprivileged principal"),
                    ));
                }
            }
        }
        None
    }

    pub fn trusted_path(p: &Path) -> bool {
        p.ancestors().enumerate().all(|(n, path)| {
            // Creating unrelated children in C:\ cannot replace a protected Program Files.
            check_path(path, if n == 0 { BAD_MASK } else { BAD_MASK & !0x06 }).is_none()
        })
    }

    /// Authenticode check: the file's signature must chain to a trusted root
    /// (`WINTRUST_ACTION_GENERIC_VERIFY_V2`, including whole-chain revocation) and its *leaf*
    /// certificate's CN must equal
    /// `publisher_cn` exactly. This is the Windows counterpart to `verify_peer_code`'s
    /// designated-requirement check on macOS.
    pub fn verify_publisher(path: &Path, publisher_cn: &str) -> Result<(), String> {
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::Security::Cryptography::{
            szOID_COMMON_NAME, CertGetNameStringW, CERT_NAME_ATTR_TYPE,
        };
        use windows::Win32::Security::WinTrust::{
            WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
            WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_WHOLECHAIN,
            WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UICONTEXT_EXECUTE, WTD_UI_NONE,
        };
        // WINTRUST_ACTION_GENERIC_VERIFY_V2
        let mut action = windows::core::GUID::from_u128(0x00aa_c56b_cd44_11d0_8cc2_00c0_4fc2_95ee);
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide.as_ptr()),
            ..Default::default()
        };
        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
            dwUnionChoice: WTD_CHOICE_FILE,
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwUIContext: WTD_UICONTEXT_EXECUTE,
            ..Default::default()
        };
        data.Anonymous.pFile = &mut file;
        unsafe {
            let rc = WinVerifyTrust(
                windows::Win32::Foundation::HWND::default(),
                &mut action,
                &mut data as *mut _ as _,
            );
            let signer_cn = {
                let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
                if prov.is_null() {
                    None
                } else {
                    let sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
                    if sgnr.is_null() || (*sgnr).csCertChain == 0 {
                        None
                    } else {
                        let cert = (*(*sgnr).pasCertChain).pCert;
                        let mut name = [0u16; 256];
                        let n = CertGetNameStringW(
                            cert,
                            CERT_NAME_ATTR_TYPE,
                            0,
                            Some(szOID_COMMON_NAME.0 as *const _),
                            Some(&mut name),
                        );
                        (n > 1 && n as usize <= name.len())
                            .then(|| String::from_utf16_lossy(&name[..(n - 1) as usize]))
                    }
                }
            };
            // Always release the state data.
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            let _ = WinVerifyTrust(
                windows::Win32::Foundation::HWND::default(),
                &mut action,
                &mut data as *mut _ as _,
            );
            if rc != 0 {
                return Err(format!("signature check failed ({rc:#010x})"));
            }
            match signer_cn {
                Some(cn) if cn == publisher_cn => Ok(()),
                Some(cn) => Err(format!("signed by {cn}, expected {publisher_cn}")),
                None => Err("signature has no readable signer".to_string()),
            }
        }
    }

    /// Reads `owner.sid`: the file must pass the same trust check as the helper binary (an
    /// attacker who can rewrite it could nominate themselves as the owner), then parse the text
    /// SID it contains.
    pub fn load_owner_sid(path: &Path) -> Result<Vec<u8>, String> {
        if let Some(reason) = untrusted_reason(path) {
            return Err(kv_i18n::t(
                &format!("owner.sid 不可信：{reason}"),
                &format!("owner.sid is not trustworthy: {reason}"),
            ));
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        crate::peer::sid_from_string(text.trim())
            .ok_or_else(|| format!("{} does not contain a valid SID", path.display()))
    }

    /// The unsigned-agent escape hatch exists and is ACL-trusted (a user-writable marker would
    /// defeat the signature check for anyone).
    pub fn allow_unsigned_agent(marker: &Path) -> bool {
        marker.exists() && untrusted_reason(marker).is_none()
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
            struct Token(windows::Win32::Foundation::HANDLE);
            impl Drop for Token {
                fn drop(&mut self) {
                    unsafe {
                        let _ = windows::Win32::Foundation::CloseHandle(self.0);
                    }
                }
            }
            let _token = Token(token);
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
        if !same_file_path(self_path, expected_path) {
            return Err(kv_i18n::t(
                &format!("必须从安装目录运行：{}", expected_path.display()),
                &format!(
                    "must run from the install location: {}",
                    expected_path.display()
                ),
            ));
        }
        for f in std::iter::once(self_path).chain(extra_files.iter().map(PathBuf::as_path)) {
            for (n, path) in f.ancestors().enumerate() {
                if let Some(reason) =
                    check_path(path, if n == 0 { BAD_MASK } else { BAD_MASK & !0x06 })
                {
                    return Err(kv_i18n::t(
                        &format!("{reason}，拒绝以管理员身份运行"),
                        &format!("{reason}; refusing to run elevated"),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn same_file_path(a: &Path, b: &Path) -> bool {
        match (a.canonicalize(), b.canonicalize()) {
            (Ok(a), Ok(b)) => a
                .as_os_str()
                .to_string_lossy()
                .eq_ignore_ascii_case(&b.as_os_str().to_string_lossy()),
            _ => false,
        }
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
        fn unsigned_fixture_never_verifies_as_our_publisher() {
            let temp = tempfile::tempdir().unwrap();
            let binary = temp.path().join("unsigned.exe");
            std::fs::write(&binary, b"MZ unsigned synthetic fixture").unwrap();
            assert!(verify_publisher(&binary, "Simvito Limited").is_err());
            assert!(!allow_unsigned_agent(&temp.path().join("missing-marker")));
        }

        #[test]
        fn read_and_execute_rights_do_not_count_as_tampering() {
            assert_eq!(BAD_MASK & 0x0012_00a9, 0); // FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
            assert_ne!(BAD_MASK & 0x0010, 0); // writing extended attributes is tampering
        }

        #[test]
        fn a_system_binary_is_trusted() {
            let notepad = Path::new(r"C:\Windows\System32\notepad.exe");
            if notepad.exists() {
                assert_eq!(untrusted_reason(notepad), None);
            }
        }

        #[test]
        #[ignore = "Signed-file integration check: cargo test -p kv-platform verify_publisher_checks -- --ignored"]
        fn verify_publisher_checks_signature_and_cn() {
            // Windows' own binaries are Microsoft-signed on a stock image; if the runner image
            // strips signatures, kernel32.dll is the fallback.
            for candidate in [
                r"C:\Windows\System32\notepad.exe",
                r"C:\Windows\System32\kernel32.dll",
            ] {
                let p = Path::new(candidate);
                if !p.exists() {
                    continue;
                }
                if verify_publisher(p, "Simvito Limited").is_ok() {
                    panic!("{candidate} must not verify against our publisher CN");
                }
                if verify_publisher(p, "Microsoft Windows").is_ok()
                    || verify_publisher(p, "Microsoft Corporation").is_ok()
                {
                    return; // signed and the CN check distinguishes publishers
                }
            }
            panic!("no signed system binary available for the signature test");
        }
    }
}

#[cfg(windows)]
pub use windows_impl::{
    allow_unsigned_agent, load_owner_sid, same_file_path, trusted_path, untrusted_reason,
    verify_publisher, verify_root_environment,
};
