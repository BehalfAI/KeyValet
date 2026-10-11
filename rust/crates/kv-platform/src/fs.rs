//! Filesystem permission seams: same "only the owner may touch this file" guarantee, expressed as
//! mode bits on Unix and as an owner-only DACL (protected from inheritance) on Windows.

use std::io;
use std::path::Path;

/// Restrict `path` to owner-only read/write. Callers use this on secret-bearing files (private
/// keys, import material) immediately after creating them.
#[cfg(unix)]
pub fn set_private_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// A protected owner-only descriptor, used at creation so there is no permissive interval.
#[cfg(windows)]
pub(crate) struct UserSecurity(windows::Win32::Security::PSECURITY_DESCRIPTOR);
#[cfg(windows)]
impl UserSecurity {
    pub(crate) fn new() -> io::Result<Self> {
        use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
        let me = crate::peer::self_identity()
            .ok_or_else(|| io::Error::other("cannot identify current user"))?;
        let sid = crate::peer::sid_to_string(&me.sid)
            .ok_or_else(|| io::Error::other("invalid user SID"))?;
        let sddl: Vec<u16> = format!("O:{sid}D:P(A;OICI;FA;;;{sid})")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut sd = windows::Win32::Security::PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                windows::core::PCWSTR(sddl.as_ptr()),
                1,
                &mut sd,
                None,
            )
        }
        .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(Self(sd))
    }
    pub(crate) fn attributes(&self) -> windows::Win32::Security::SECURITY_ATTRIBUTES {
        windows::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0 .0,
            bInheritHandle: windows::core::BOOL::default(),
        }
    }
}
#[cfg(windows)]
impl Drop for UserSecurity {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::LocalFree(Some(
                windows::Win32::Foundation::HLOCAL(self.0 .0),
            ));
        }
    }
}

/// User-owned directory anchors prevent rename/replacement while private files are written.
#[cfg(windows)]
pub struct UserPrivateDir {
    pub path: std::path::PathBuf,
    _anchors: Vec<std::fs::File>,
}
#[cfg(windows)]
impl UserPrivateDir {
    pub fn purge_dead_files(&self) -> io::Result<()> {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        for entry in std::fs::read_dir(&self.path)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some((tag, _)) = name.split_once('-') else {
                continue;
            };
            let Some((pid, start)) = tag.split_once('.') else {
                continue;
            };
            let (Ok(pid), Ok(start)) = (pid.parse::<u32>(), start.parse::<u64>()) else {
                continue;
            };
            let dead = match crate::peer::process_start_time(pid) {
                Ok(actual) => actual != start,
                Err(e) => e.raw_os_error() == Some(87),
            };
            if !dead || !(name.ends_with(".key") || name.ends_with(".ps1")) {
                continue;
            }
            let file = std::fs::OpenOptions::new()
                .access_mode(0x0001_0000 | 0x0002_0000 | 0x80)
                .share_mode(7)
                .custom_flags(0x0020_0000)
                .open(entry.path())?;
            let meta = file.metadata()?;
            if meta.is_file() && meta.file_attributes() & 0x400 == 0 && user_only(&file)? {
                delete_open_file(&file)?;
            }
        }
        Ok(())
    }
    pub fn open(home: &Path) -> io::Result<Self> {
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        use windows::Win32::Storage::FileSystem::CreateDirectoryW;
        let security = UserSecurity::new()?;
        let attrs = security.attributes();
        let mut path = home.to_path_buf();
        let mut anchors = Vec::new();
        for name in [".keyvalet", "run"] {
            path.push(name);
            let wide: Vec<u16> = path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            if let Err(e) =
                unsafe { CreateDirectoryW(windows::core::PCWSTR(wide.as_ptr()), Some(&attrs)) }
            {
                if e.code().0 & 0xffff != 183 {
                    return Err(io::Error::other(e.to_string()));
                }
            }
            let dir = std::fs::OpenOptions::new()
                .read(true)
                .share_mode(3)
                .custom_flags(0x0200_0000 | 0x0020_0000)
                .open(&path)?;
            if !dir.metadata()?.is_dir()
                || dir.metadata()?.file_attributes() & 0x400 != 0
                || !user_only(&dir)?
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private directory owner/DACL/reparse check failed",
                ));
            }
            anchors.push(dir);
        }
        Ok(Self {
            path,
            _anchors: anchors,
        })
    }

    pub fn write_new(
        &self,
        name: &str,
        content: &[u8],
    ) -> io::Result<(std::path::PathBuf, std::fs::File)> {
        use std::io::Write;
        use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, CREATE_NEW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE,
        };
        // Windows has alternate data streams and special device names; accept only our own
        // generated filename alphabet and require a numeric creator prefix.
        if name.len() > 240
            || !name.starts_with(|c: char| c.is_ascii_digit())
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid private filename",
            ));
        }
        let path = self.path.join(name);
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let security = UserSecurity::new()?;
        let attrs = security.attributes();
        let handle = unsafe {
            CreateFileW(
                windows::core::PCWSTR(wide.as_ptr()),
                0x4000_0000 | 0x0001_0000,
                FILE_SHARE_MODE(7),
                Some(&attrs),
                CREATE_NEW,
                FILE_FLAGS_AND_ATTRIBUTES(0x0020_0000),
                None,
            )
        }
        .map_err(|e| io::Error::from_raw_os_error(e.code().0 & 0xffff))?;
        let mut file = unsafe { std::fs::File::from_raw_handle(handle.0) };
        if let Err(e) = file.write_all(content) {
            let _ = delete_open_file(&file);
            return Err(e);
        }
        Ok((path, file))
    }
}

#[cfg(windows)]
fn user_only(file: &std::fs::File) -> io::Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        EqualSid, GetAce, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };
    let me = crate::peer::self_identity()
        .ok_or_else(|| io::Error::other("cannot identify current user"))?;
    unsafe {
        let mut owner = PSID::default();
        let mut acl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        let rc = GetSecurityInfo(
            windows::Win32::Foundation::HANDLE(file.as_raw_handle() as _),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut acl),
            None,
            Some(&mut sd),
        );
        if rc.0 != 0 {
            return Err(io::Error::from_raw_os_error(rc.0 as i32));
        }
        let _sd = UserSecurity(sd);
        if !EqualSid(PSID(me.sid.as_ptr() as _), owner).is_ok() || acl.is_null() {
            return Ok(false);
        }
        for i in 0..(*acl).AceCount as u32 {
            let mut ptr = std::ptr::null_mut();
            GetAce(acl, i, &mut ptr).map_err(|e| io::Error::other(e.to_string()))?;
            let header = &*(ptr as *const ACE_HEADER);
            if header.AceFlags & 0x08 != 0 || header.AceType == 1 {
                continue;
            }
            if header.AceType != 0 {
                return Ok(false);
            }
            let ace = &*(ptr as *const ACCESS_ALLOWED_ACE);
            if ace.Mask != 0
                && !EqualSid(
                    PSID(me.sid.as_ptr() as _),
                    PSID(&ace.SidStart as *const _ as _),
                )
                .is_ok()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Delete the exact file this process created, never a replacement at its old pathname.
#[cfg(windows)]
pub fn delete_open_file(file: &std::fs::File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Storage::FileSystem::{
        FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    unsafe {
        SetFileInformationByHandle(
            windows::Win32::Foundation::HANDLE(file.as_raw_handle() as _),
            FileDispositionInfo,
            &info as *const _ as _,
            std::mem::size_of_val(&info) as u32,
        )
    }
    .map_err(|e| io::Error::other(e.to_string()))
}

/// Windows counterpart: replace the DACL with a single allow-ACE for the file's current owner,
/// protected from parent inheritance (a directory-wide "Users: read" grant must not leak down to
/// a secret file).
#[cfg(windows)]
pub fn set_private_permissions(path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL};
    use windows::Win32::Security::Authorization::{
        GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
        GRANT_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSID,
    };

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let mut owner = PSID::default();
        let mut sd = windows::Win32::Security::PSECURITY_DESCRIPTOR::default();
        let status = GetNamedSecurityInfoW(
            windows::core::PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            &mut sd,
        );
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        struct Sd(*mut core::ffi::c_void);
        impl Drop for Sd {
            fn drop(&mut self) {
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(self.0 as _)));
                };
            }
        }
        let _sd = Sd(sd.0);

        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: 0x001F_01FF, // FILE_ALL_ACCESS
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: windows::Win32::Security::ACE_FLAGS(0),
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: windows::core::PWSTR(owner.0 as _),
                ..Default::default()
            },
        };
        let mut acl: *mut ACL = std::ptr::null_mut();
        let status = SetEntriesInAclW(Some(&[entry]), None, &mut acl);
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        struct Acl(*mut ACL);
        impl Drop for Acl {
            fn drop(&mut self) {
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(self.0 as _)));
                };
            }
        }
        let _acl = Acl(acl);
        let status = SetNamedSecurityInfoW(
            windows::core::PWSTR(wide.as_ptr() as _),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(acl),
            None,
        );
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        Ok(())
    }
}

/// Ensures a directory exists and is private: on unix owner-only (0700, owned by the caller);
/// on Windows a DACL restricted to SYSTEM + Administrators with no unprivileged access at all —
/// vault contents are secret, not just tamper-sensitive, so even read access by the well-known
/// unprivileged groups fails the check.
pub fn ensure_private_dir(path: &std::path::Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        match std::fs::metadata(path) {
            Ok(meta) => {
                if !meta.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("{} exists and is not a directory", path.display()),
                    ));
                }
                if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("{} must be owner-only (0700)", path.display()),
                    ));
                }
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                std::fs::create_dir_all(path)?;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            }
            Err(e) => Err(e),
        }
    }
    #[cfg(windows)]
    {
        if path.exists() {
            if !path.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a directory", path.display()),
                ));
            }
            if let Some(reason) = crate::trust::untrusted_reason(path) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("{} is not trusted: {reason}", path.display()),
                ));
            }
            if imp::dacl_allows_unprivileged(path)? {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("{} grants access to an unprivileged group", path.display()),
                ));
            }
            Ok(())
        } else {
            std::fs::create_dir_all(path)?;
            imp::set_system_admin_dacl(path)
        }
    }
}

/// Windows internals for `ensure_private_dir`.
#[cfg(windows)]
mod imp {
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL};
    use windows::Win32::Security::Authorization::{
        GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
        GRANT_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_GROUP, TRUSTEE_IS_SID, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        CreateWellKnownSid, GetAce, WinBuiltinAdministratorsSid, WinLocalSystemSid,
        ACCESS_ALLOWED_ACE, ACE_FLAGS, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, WELL_KNOWN_SID_TYPE,
    };

    struct Free(*mut core::ffi::c_void);
    impl Drop for Free {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = windows::Win32::Foundation::LocalFree(Some(HLOCAL(self.0 as _)));
                }
            }
        }
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn well_known(ty: WELL_KNOWN_SID_TYPE) -> io::Result<Vec<u8>> {
        let mut size = 0u32;
        unsafe {
            let _ = CreateWellKnownSid(ty, None, None, &mut size);
        }
        if size == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u8; size as usize];
        unsafe {
            CreateWellKnownSid(ty, None, Some(PSID(buf.as_mut_ptr() as _)), &mut size)
                .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        }
        Ok(buf)
    }

    fn allow(sid: &[u8], mask: u32, inherit: u32) -> EXPLICIT_ACCESS_W {
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: mask,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: ACE_FLAGS(inherit),
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_GROUP,
                ptstrName: PWSTR(sid.as_ptr() as _),
                ..Default::default()
            },
        }
    }

    /// Protected DACL granting SYSTEM + Administrators full control (inherited by files and
    /// subdirs created below), nothing else. Only used on a directory the service just created.
    pub fn set_system_admin_dacl(path: &Path) -> io::Result<()> {
        const FILE_ALL: u32 = 0x001F_01FF;
        const INHERIT: u32 = 0x03; // OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        let system = well_known(WinLocalSystemSid)?;
        let admins = well_known(WinBuiltinAdministratorsSid)?;
        let entries = [
            allow(&system, FILE_ALL, INHERIT),
            allow(&admins, FILE_ALL, INHERIT),
        ];
        let w = wide(path);
        unsafe {
            let mut acl: *mut ACL = std::ptr::null_mut();
            let status = SetEntriesInAclW(Some(&entries), None, &mut acl);
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status.0 as i32));
            }
            let _acl = Free(acl as _);
            let status = SetNamedSecurityInfoW(
                windows::core::PCWSTR(w.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(acl),
                None,
            );
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status.0 as i32));
            }
            Ok(())
        }
    }

    /// Whether the path's DACL grants ANY access right to any unprivileged principal
    /// (including individual user SIDs) — stricter than the tamper check
    /// in trust.rs, because a vault directory's *read* contents are secret too.
    pub fn dacl_allows_unprivileged(path: &Path) -> io::Result<bool> {
        let trusted = [WinLocalSystemSid, WinBuiltinAdministratorsSid]
            .into_iter()
            .map(well_known)
            .collect::<io::Result<Vec<_>>>()?;
        let w = wide(path);
        unsafe {
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let mut sd = PSECURITY_DESCRIPTOR::default();
            let status = GetNamedSecurityInfoW(
                windows::core::PCWSTR(w.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                &mut sd,
            );
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status.0 as i32));
            }
            let _sd = Free(sd.0);
            if dacl.is_null() {
                return Ok(true); // NULL DACL = everyone, full access
            }
            for i in 0..(*dacl).AceCount as u32 {
                let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
                if GetAce(dacl, i, &mut ace).is_err() || ace.is_null() {
                    return Ok(true);
                }
                let header = &*(ace as *const ACE_HEADER);
                if header.AceFlags & 0x08 != 0 || matches!(header.AceType, 1 | 6 | 10 | 12) {
                    continue;
                }
                if header.AceType != 0 {
                    return Ok(true);
                }
                let ace = ace as *const ACCESS_ALLOWED_ACE;
                let sid = PSID(&(*ace).SidStart as *const u32 as _);
                if (*ace).Mask != 0
                    && !trusted.iter().any(|b| {
                        windows::Win32::Security::EqualSid(PSID(b.as_ptr() as _), sid).is_ok()
                    })
                {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn export_cleanup_preserves_live_creators_and_rejects_reused_pids() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = super::UserPrivateDir::open(tmp.path()).unwrap();
        let pid = std::process::id();
        let start = crate::peer::process_start_time(pid).unwrap();
        let (live, file) = dir
            .write_new(&format!("{pid}.{start}-live.key"), b"synthetic")
            .unwrap();
        drop(file);
        let (stale, file) = dir
            .write_new(&format!("{pid}.{}-stale.ps1", start + 1), b"synthetic")
            .unwrap();
        drop(file);
        dir.purge_dead_files().unwrap();
        assert!(live.exists());
        assert!(!stale.exists());
    }

    #[test]
    fn private_export_directory_refuses_an_unprivileged_read_grant() {
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
        use windows::Win32::Security::{
            SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR,
        };
        let tmp = tempfile::tempdir().unwrap();
        let dir = super::UserPrivateDir::open(tmp.path()).unwrap();
        let private = dir.path.parent().unwrap().to_path_buf();
        drop(dir);
        let sid = crate::peer::sid_to_string(&crate::peer::self_identity().unwrap().sid).unwrap();
        let sddl: Vec<_> = format!("O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FR;;;BU)")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let path: Vec<_> = private.as_os_str().encode_wide().chain(Some(0)).collect();
        unsafe {
            let mut sd = PSECURITY_DESCRIPTOR::default();
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                windows::core::PCWSTR(sddl.as_ptr()),
                1,
                &mut sd,
                None,
            )
            .unwrap();
            let _sd = super::UserSecurity(sd);
            SetFileSecurityW(
                windows::core::PCWSTR(path.as_ptr()),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                sd,
            )
            .unwrap();
        }
        assert!(super::UserPrivateDir::open(tmp.path()).is_err());
    }

    #[test]
    #[ignore = "Requires an elevated Windows shell; cargo test -p kv-platform ensure_private_dir -- --ignored"]
    fn ensure_private_dir_rejects_unprivileged_access() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("private");
        super::ensure_private_dir(&dir).unwrap();
        // The fresh DACL must not contain any unprivileged ACE -- the same check the helper
        // runs at service start.
        assert!(!super::imp::dacl_allows_unprivileged(&dir).unwrap());
        assert!(crate::trust::untrusted_reason(&dir).is_none());
        assert!(super::ensure_private_dir(&dir).is_ok());
    }
}
