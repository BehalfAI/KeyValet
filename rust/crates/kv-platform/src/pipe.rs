//! Named-pipe server construction with an explicit security descriptor. Every KeyValet pipe
//! gets the same DACL: the owner user may read/write/synchronize; SYSTEM and Administrators
//! additionally get server-instance rights for the service and elevated development tools.
//! Nothing else, and nothing inherited. Remote clients are rejected
//! unconditionally.

use std::io;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows::core::PWSTR;
use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL};
use windows::Win32::Security::Authorization::{
    SetEntriesInAclW, EXPLICIT_ACCESS_W, GRANT_ACCESS, TRUSTEE_IS_GROUP, TRUSTEE_IS_SID,
    TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows::Win32::Security::{
    CreateWellKnownSid, InitializeSecurityDescriptor, MakeSelfRelativeSD,
    SetSecurityDescriptorDacl, WinBuiltinAdministratorsSid, WinLocalSystemSid, ACE_FLAGS, ACL,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, WELL_KNOWN_SID_TYPE,
};

// FILE_GENERIC_READ | FILE_GENERIC_WRITE, with FILE_CREATE_PIPE_INSTANCE removed. Generic
// write includes that bit and would let an ordinary client impersonate a service instance.
const CLIENT_ACCESS: u32 = 0x0012_019b;
const SERVER_ACCESS: u32 = 0x001f_01ff;
#[cfg(test)]
const FILE_CREATE_PIPE_INSTANCE: u32 = 0x0000_0004;

fn well_known_sid(ty: WELL_KNOWN_SID_TYPE) -> io::Result<Vec<u8>> {
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

fn grant(sid: &[u8], group: bool, mask: u32) -> EXPLICIT_ACCESS_W {
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: mask,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: ACE_FLAGS(0),
        Trustee: TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: if group {
                TRUSTEE_IS_GROUP
            } else {
                TRUSTEE_IS_USER
            },
            ptstrName: PWSTR(sid.as_ptr() as _),
            ..Default::default()
        },
    }
}

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

/// The self-relative security descriptor for the pipe DACL. Kept alive inside `PipeFactory`:
/// `create_with_security_attributes_raw` only forwards a raw pointer.
fn build_sd(owner_sid: &[u8]) -> io::Result<Vec<u8>> {
    let system = well_known_sid(WinLocalSystemSid)?;
    let admins = well_known_sid(WinBuiltinAdministratorsSid)?;
    let entries = [
        grant(owner_sid, false, CLIENT_ACCESS),
        grant(&system, true, SERVER_ACCESS),
        grant(&admins, true, SERVER_ACCESS),
    ];
    unsafe {
        let mut acl: *mut ACL = std::ptr::null_mut();
        let status = SetEntriesInAclW(Some(&entries), None, &mut acl);
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status.0 as i32));
        }
        let _acl = Free(acl as _);
        let mut sd: SECURITY_DESCRIPTOR = std::mem::zeroed();
        InitializeSecurityDescriptor(PSECURITY_DESCRIPTOR(&mut sd as *mut _ as _), 1)
            .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        SetSecurityDescriptorDacl(
            PSECURITY_DESCRIPTOR(&mut sd as *mut _ as _),
            true,
            Some(acl),
            false,
        )
        .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        let mut len = 0u32;
        let _ = MakeSelfRelativeSD(PSECURITY_DESCRIPTOR(&mut sd as *mut _ as _), None, &mut len);
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut out = vec![0u8; len as usize];
        MakeSelfRelativeSD(
            PSECURITY_DESCRIPTOR(&mut sd as *mut _ as _),
            Some(PSECURITY_DESCRIPTOR(out.as_mut_ptr() as _)),
            &mut len,
        )
        .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        Ok(out)
    }
}

/// Server-side factory. Wraps `ServerOptions` rather than returning it bare because the
/// security attributes must stay alive across every `create` call (tokio forwards a raw
/// pointer at `CreateNamedPipe` time).
pub struct PipeFactory {
    name: String,
    sd: Vec<u8>,
}

impl PipeFactory {
    /// One listening instance. `first` marks the first-ever instance so a foreign process cannot
    /// squat the pipe name ahead of the service.
    pub fn create(&self, first: bool) -> io::Result<NamedPipeServer> {
        let mut opts = ServerOptions::new();
        opts.first_pipe_instance(first).reject_remote_clients(true);
        let mut attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.sd.as_ptr() as _,
            bInheritHandle: windows::core::BOOL::default(),
        };
        unsafe { opts.create_with_security_attributes_raw(&self.name, &mut attrs as *mut _ as _) }
    }
}

/// Pipe server options for `name`: owner / SYSTEM / Administrators may connect; nobody else.
pub fn server_options(name: &str, owner_sid: &[u8]) -> io::Result<PipeFactory> {
    Ok(PipeFactory {
        name: name.to_string(),
        sd: build_sd(owner_sid)?,
    })
}

/// Open with individual data rights and identification-only impersonation. Tokio's default
/// client requests GENERIC_WRITE, which includes the forbidden server-instance right.
pub fn open_client(name: &str) -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use std::os::windows::io::{FromRawHandle, IntoRawHandle, OwnedHandle};
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, OPEN_EXISTING,
    };
    let name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let handle = unsafe {
        CreateFileW(
            PCWSTR(name.as_ptr()),
            CLIENT_ACCESS,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0x4000_0000 | 0x0010_0000 | 0x0001_0000),
            None,
        )
        .map_err(|e| io::Error::from_raw_os_error(e.code().0 & 0xffff))?
    };
    let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };
    unsafe {
        tokio::net::windows::named_pipe::NamedPipeClient::from_raw_handle(handle.into_raw_handle())
    }
}

/// Retry PIPE_BUSY while preserving a deadline; verify the service before returning a channel.
pub async fn connect_service(
    name: &str,
) -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use std::os::windows::io::AsRawHandle;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match open_client(name) {
                Ok(pipe) => {
                    // Certificate verification can retrieve revocation information. The
                    // deadline must also cover that work; keep it off the async executor.
                    return tokio::task::spawn_blocking(move || {
                        crate::peer::verify_server(pipe.as_raw_handle())?;
                        Ok(pipe)
                    })
                    .await
                    .map_err(io::Error::other)?;
                }
                Err(e) if e.raw_os_error() == Some(231) => {
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await
                }
                Err(e) => return Err(e),
            }
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "KeyValet pipe is busy"))?
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// In-process pipe round trip: the client connects, the server accepts, bytes flow, and
    /// `accept_client` reports the current process's SID and exe path.
    #[tokio::test]
    async fn pipe_round_trip_identifies_the_client() {
        let owner = crate::peer::self_identity().unwrap().sid;
        let name = format!(r"\\.\pipe\keyvalet-test-{}", std::process::id());
        let factory = server_options(&name, &owner).unwrap();
        let mut server = factory.create(true).unwrap();
        let client_task = tokio::spawn({
            let name = name.clone();
            async move { open_client(&name) }
        });
        let (client_result, connect_result) = tokio::join!(client_task, server.connect());
        connect_result.unwrap();
        let mut client = client_result.unwrap().unwrap();

        let identity = crate::peer::accept_client(&server).await.unwrap();
        assert!(crate::peer::sid_equal(&identity.sid, &owner));
        let current = std::env::current_exe()
            .unwrap()
            .canonicalize()
            .unwrap_or_else(|_| std::env::current_exe().unwrap());
        let reported = identity
            .exe_path
            .canonicalize()
            .unwrap_or_else(|_| identity.exe_path.clone());
        assert_eq!(reported, current);

        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        // First-instance protection refuses a second server claiming the same name.
        assert!(factory.create(true).is_err());
        // A user-created test pipe must never pass the production SYSTEM/path check.
        assert!(crate::peer::verify_server(client.as_raw_handle()).is_err());
    }

    #[test]
    fn client_access_never_includes_instance_creation() {
        assert_eq!(CLIENT_ACCESS & FILE_CREATE_PIPE_INSTANCE, 0);
        assert_ne!(SERVER_ACCESS & FILE_CREATE_PIPE_INSTANCE, 0);
    }
}
