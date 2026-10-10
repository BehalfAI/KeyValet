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
