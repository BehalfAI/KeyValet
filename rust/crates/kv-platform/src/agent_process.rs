//! The SYSTEM service creates protected interactive workers for approvals and MCP secret input.
//! Authenticode alone identifies a file, not whether a same-user launcher retained an invasive
//! process handle. Process/thread descriptors are assigned before its first instruction.
use crate::paths::{AGENT_BIN, MCP_BIN};
use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::{
    DuplicateTokenEx, GetSecurityDescriptorDacl, SecurityImpersonation, SetTokenInformation,
    TokenDefaultDacl, TokenPrimary, ACL, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    TOKEN_ALL_ACCESS, TOKEN_DEFAULT_DACL,
};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::JobObjects::{
    CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::RemoteDesktop::WTSQueryUserToken;
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
    TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW,
    CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_JOB_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    STARTUPINFOEXW, STARTUPINFOW,
};

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Descriptor {
    fn new(text: &str) -> io::Result<Self> {
        let text = wide(text);
        let mut sd = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(text.as_ptr()),
                1,
                &mut sd,
                None,
            )
        }
        .map_err(error)?;
        Ok(Self(sd))
    }
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0 .0,
            bInheritHandle: false.into(),
        }
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0 .0)));
        }
    }
}
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}
fn error(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}
unsafe fn owned(handle: HANDLE) -> OwnedHandle {
    OwnedHandle::from_raw_handle(handle.0)
}

fn worker_descriptors(owner: &str) -> io::Result<[Descriptor; 4]> {
    Ok([
        Descriptor::new(&format!(
            "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00101000;;;{owner})"
        ))?,
        Descriptor::new("O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)")?,
        Descriptor::new(&format!(
            "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0002001e;;;{owner})"
        ))?,
        // TokenDefaultDacl applies to many object types. Do not reuse PROCESS_QUERY_LIMITED_
        // INFORMATION (0x1000): on a thread that bit grants THREAD_RESUME. Only standard
        // READ_CONTROL + SYNCHRONIZE are allowed, and OWNER RIGHTS removes implicit WRITE_DAC.
        Descriptor::new(&format!(
            "O:{owner}G:{owner}D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;RC;;;OW)(A;;0x00120000;;;{owner})"
        ))?,
    ])
}

fn service_descriptors(owner: &str) -> io::Result<[Descriptor; 2]> {
    Ok([
        Descriptor::new(&format!(
            "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00001000;;;{owner})"
        ))?,
        Descriptor::new(&format!(
            "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00000008;;;{owner})"
        ))?,
    ])
}

/// Allow only the install owner to inspect the service identity. OpenProcessToken checks
/// the token's DACL independently of the process DACL; default SYSTEM permissions can deny
/// an ordinary client's TOKEN_QUERY and make authenticated connections impossible.
pub fn expose_service_identity(owner_sid: &[u8]) -> io::Result<()> {
    use windows::Win32::Security::{
        SetKernelObjectSecurity, DACL_SECURITY_INFORMATION, TOKEN_WRITE_DAC,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let owner = crate::peer::sid_to_string(owner_sid).ok_or_else(|| error("invalid owner SID"))?;
    let [process_sd, token_sd] = service_descriptors(&owner)?;
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_WRITE_DAC, &mut token).map_err(error)?;
        let _token = owned(token);
        SetKernelObjectSecurity(token, DACL_SECURITY_INFORMATION, token_sd.0).map_err(error)?;
        SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, process_sd.0)
            .map_err(error)?;
    }
    Ok(())
}

struct Attributes {
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
    _storage: Vec<usize>,
    policy: Box<u64>,
    jobs: Box<[HANDLE; 1]>,
}
impl Attributes {
    fn mitigations(policy: u64, job: HANDLE) -> io::Result<Self> {
        unsafe {
            let mut bytes = 0;
            let _ = InitializeProcThreadAttributeList(None, 2, None, &mut bytes);
            if bytes == 0 {
                return Err(error("cannot size process attributes"));
            }
            let mut storage = vec![0usize; bytes.div_ceil(std::mem::size_of::<usize>())];
            let list = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr() as _);
            InitializeProcThreadAttributeList(Some(list), 2, None, &mut bytes).map_err(error)?;
            let attributes = Self {
                list,
                _storage: storage,
                policy: Box::new(policy),
                jobs: Box::new([job]),
            };
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
                Some(attributes.policy.as_ref() as *const _ as _),
                std::mem::size_of::<u64>(),
                None,
                None,
            )
            .map_err(error)?;
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                Some(attributes.jobs.as_ptr() as _),
                std::mem::size_of::<HANDLE>(),
                None,
                None,
            )
            .map_err(error)?;
            Ok(attributes)
        }
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.list);
        }
    }
}

pub struct ProtectedProcess {
    handle: OwnedHandle,
    // Never inherited or named. Kernel cleanup also kills descendants if the helper crashes.
    _job: OwnedHandle,
    pub pid: u32,
}
impl ProtectedProcess {
    pub fn running(&self) -> bool {
        unsafe {
            WaitForSingleObject(HANDLE(self.handle.as_raw_handle() as _), 0)
                == windows::Win32::Foundation::WAIT_TIMEOUT
        }
    }
    pub fn matches(&self, pid: u32) -> bool {
        self.pid == pid && self.running()
    }
    pub fn terminate(&self) -> io::Result<()> {
        unsafe { TerminateProcess(HANDLE(self.handle.as_raw_handle() as _), 0) }.map_err(error)
    }

    /// The requested interactive session comes from the kernel-identified launcher's process,
    /// never from a JSON parameter. Its WTS token must belong to the install owner.
    pub fn launch(session: u32, owner_sid: &[u8]) -> io::Result<Self> {
        Self::launch_program(session, owner_sid, AGENT_BIN, "--serve")
    }

    pub fn launch_mcp(session: u32, owner_sid: &[u8], channel: &str) -> io::Result<Self> {
        if !kv_ipc::mcp_worker::valid_channel(channel) {
            return Err(error("invalid MCP worker channel"));
        }
        Self::launch_program(
            session,
            owner_sid,
            MCP_BIN,
            &format!("--worker --channel \"{channel}\""),
        )
    }

    pub fn launch_cleanup(session: u32, owner_sid: &[u8]) -> io::Result<Self> {
        Self::launch_program(session, owner_sid, MCP_BIN, "--cleanup-stale")
    }

    fn launch_program(
        session: u32,
        owner_sid: &[u8],
        binary: &str,
        args: &str,
    ) -> io::Result<Self> {
        if session == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "agent needs an interactive session",
            ));
        }
        let owner =
            crate::peer::sid_to_string(owner_sid).ok_or_else(|| error("invalid owner SID"))?;
        // The worker needs token queries/duplication for WinRT, but another same-user process
        // must not change its token default DACL and thereby expose subsequently created threads.
        // New worker threads inherit this protected default. OWNER RIGHTS overrides the
        // ordinary owner's implicit WRITE_DAC, preventing a same-user process from granting
        // itself thread-context/VM access after launch.
        let [process_sd, thread_sd, token_sd, default_sd] = worker_descriptors(&owner)?;
        unsafe {
            let mut raw = HANDLE::default();
            WTSQueryUserToken(session, &mut raw).map_err(error)?;
            let token = owned(raw);
            let sid = kv_vault::winbuf::token_user_sid(raw)?;
            if !crate::peer::sid_equal(&sid, owner_sid) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "interactive token is not the vault owner",
                ));
            }
            let mut elevation = windows::Win32::Security::TOKEN_ELEVATION::default();
            let mut size = 0;
            windows::Win32::Security::GetTokenInformation(
                raw,
                windows::Win32::Security::TokenElevation,
                Some(&mut elevation as *mut _ as _),
                std::mem::size_of_val(&elevation) as u32,
                &mut size,
            )
            .map_err(error)?;
            if elevation.TokenIsElevated != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "interactive workers require an unelevated user token; enable UAC",
                ));
            }
            let mut primary = HANDLE::default();
            DuplicateTokenEx(
                HANDLE(token.as_raw_handle() as _),
                TOKEN_ALL_ACCESS,
                Some(&token_sd.attributes()),
                SecurityImpersonation,
                TokenPrimary,
                &mut primary,
            )
            .map_err(error)?;
            let primary_handle = owned(primary);
            let mut acl: *mut ACL = std::ptr::null_mut();
            let mut present = windows::core::BOOL::default();
            let mut defaulted = windows::core::BOOL::default();
            GetSecurityDescriptorDacl(default_sd.0, &mut present, &mut acl, &mut defaulted)
                .map_err(error)?;
            let defaults = TOKEN_DEFAULT_DACL { DefaultDacl: acl };
            SetTokenInformation(
                primary,
                TokenDefaultDacl,
                &defaults as *const _ as _,
                std::mem::size_of_val(&defaults) as u32,
            )
            .map_err(error)?;
            let mut env = std::ptr::null_mut();
            CreateEnvironmentBlock(&mut env, Some(primary), false).map_err(error)?;
            struct Environment(*mut core::ffi::c_void);
            impl Drop for Environment {
                fn drop(&mut self) {
                    unsafe {
                        let _ = DestroyEnvironmentBlock(self.0);
                    }
                }
            }
            let _env = Environment(env);
            let application = wide(binary);
            let mut command = wide(&format!("\"{binary}\" {args}"));
            let directory = wide(r"C:\Program Files\KeyValet\bin");
            let mut desktop = wide(r"winsta0\default");
            // DACLs do not block GUI hook DLLs or per-user COM registration hijacks. Apply
            // these from creation, before third-party extension code can enter the worker.
            // Win32 PROCESS_CREATION_MITIGATION_POLICY_*_ALWAYS_ON, per Microsoft SDK:
            let policy = (1u64 << 32) // EXTENSION_POINT_DISABLE (global hooks/AppInit/LSP/legacy IME)
                | (1u64 << 36)        // PROHIBIT_DYNAMIC_CODE
                | (1u64 << 44); // BLOCK_NON_MICROSOFT_BINARIES (DLLs)
            let job = worker_job()?;
            let attributes = Attributes::mitigations(policy, HANDLE(job.as_raw_handle() as _))?;
            let startup = STARTUPINFOEXW {
                StartupInfo: STARTUPINFOW {
                    cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                    lpDesktop: PWSTR(desktop.as_mut_ptr()),
                    ..Default::default()
                },
                lpAttributeList: attributes.list,
            };
            let mut process = PROCESS_INFORMATION::default();
            CreateProcessAsUserW(
                Some(HANDLE(primary_handle.as_raw_handle() as _)),
                PCWSTR(application.as_ptr()),
                Some(PWSTR(command.as_mut_ptr())),
                Some(&process_sd.attributes()),
                Some(&thread_sd.attributes()),
                false,
                CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                Some(env),
                PCWSTR(directory.as_ptr()),
                &startup.StartupInfo,
                &mut process,
            )
            .map_err(error)?;
            let handle = owned(process.hProcess);
            let _thread = owned(process.hThread);
            Ok(Self {
                handle,
                _job: job,
                pid: process.dwProcessId,
            })
        }
    }
}

fn worker_job() -> io::Result<OwnedHandle> {
    unsafe {
        let job = CreateJobObjectW(None, PCWSTR::null()).map_err(error)?;
        let handle = owned(job);
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &limits as *const _ as _,
            std::mem::size_of_val(&limits) as u32,
        )
        .map_err(error)?;
        Ok(handle)
    }
}

pub fn new_mcp_channel() -> io::Result<String> {
    use windows::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };
    let mut random = [0u8; 16];
    unsafe { BCryptGenRandom(None, &mut random, BCRYPT_USE_SYSTEM_PREFERRED_RNG) }
        .ok()
        .map_err(error)?;
    Ok(format!(
        "{}{}",
        kv_ipc::mcp_worker::CHANNEL_PREFIX,
        random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
}
impl Drop for ProtectedProcess {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Security::{
        AccessCheck, CreateRestrictedToken, DuplicateToken, GetSecurityDescriptorControl,
        DISABLE_MAX_PRIVILEGE, GENERIC_MAPPING, PSID, SE_DACL_PROTECTED, SID_AND_ATTRIBUTES,
        TOKEN_DUPLICATE, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    fn ordinary_token() -> (OwnedHandle, String) {
        unsafe {
            let mut raw = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw).unwrap();
            let _original = owned(raw);
            let sid = kv_vault::winbuf::token_user_sid(raw).unwrap();
            let owner = crate::peer::sid_to_string(&sid).unwrap();
            let mut admin = crate::peer::sid_from_string("S-1-5-32-544").unwrap();
            let disable = [SID_AND_ATTRIBUTES {
                Sid: PSID(admin.as_mut_ptr() as _),
                Attributes: 0,
            }];
            let mut filtered = HANDLE::default();
            // CI may run elevated. Test the same DACL with administrator authority and all
            // optional privileges removed, rather than accidentally exercising its BA ACE.
            CreateRestrictedToken(
                raw,
                DISABLE_MAX_PRIVILEGE,
                Some(&disable),
                None,
                None,
                &mut filtered,
            )
            .unwrap();
            let _filtered = owned(filtered);
            let mut impersonation = HANDLE::default();
            DuplicateToken(filtered, SecurityImpersonation, &mut impersonation).unwrap();
            (owned(impersonation), owner)
        }
    }
    fn allowed(descriptor: &Descriptor, token: &OwnedHandle, access: u32) -> bool {
        unsafe {
            let mapping = GENERIC_MAPPING::default();
            let mut privileges = kv_vault::winbuf::AlignedBuffer::new(1024);
            let mut len = 1024;
            let mut granted = 0;
            let mut status = windows::core::BOOL::default();
            AccessCheck(
                descriptor.0,
                HANDLE(token.as_raw_handle() as _),
                access,
                &mapping,
                Some(privileges.as_mut_ptr() as _),
                &mut len,
                &mut granted,
                &mut status,
            )
            .unwrap();
            status.as_bool() && granted & access == access
        }
    }
    #[test]
    fn worker_descriptors_deny_invasive_access_to_an_ordinary_owner() {
        let (token, owner) = ordinary_token();
        let [process, thread, token_sd, defaults] = worker_descriptors(&owner).unwrap();
        assert!(allowed(&process, &token, 0x00101000)); // Query limited + wait.
        for access in [
            0x0001, 0x0002, 0x0008, 0x0010, 0x0020, 0x0200, 0x0400, 0x40000, 0x80000,
        ] {
            assert!(
                !allowed(&process, &token, access),
                "process unexpectedly grants {access:#x}"
            );
        }
        for access in [
            0x0001, 0x0002, 0x0008, 0x0010, 0x0020, 0x0080, 0x1000, 0x40000, 0x80000,
        ] {
            assert!(
                !allowed(&thread, &token, access),
                "initial thread unexpectedly grants {access:#x}"
            );
            assert!(
                !allowed(&defaults, &token, access),
                "default thread unexpectedly grants {access:#x}"
            );
        }
        assert!(allowed(&defaults, &token, 0x00120000)); // Read control + wait only.
        assert!(allowed(&token_sd, &token, 0x0002001e)); // WinRT query/duplicate/impersonate.
        for access in [0x0001, 0x0020, 0x0040, 0x0080, 0x0100, 0x40000, 0x80000] {
            assert!(
                !allowed(&token_sd, &token, access),
                "token unexpectedly grants {access:#x}"
            );
        }
    }
    #[test]
    fn worker_dacls_are_protected_from_parent_inheritance() {
        for descriptor in worker_descriptors("S-1-5-21-11-22-33-1001").unwrap() {
            let mut control = 0;
            let mut revision = 0;
            unsafe {
                GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision).unwrap();
            }
            assert_ne!(control & SE_DACL_PROTECTED.0, 0);
            assert_eq!(revision, 1);
        }
    }
    #[test]
    fn ordinary_owner_can_query_service_identity_but_not_duplicate_its_system_token() {
        let (token, owner) = ordinary_token();
        let [process, system_token] = service_descriptors(&owner).unwrap();
        assert!(allowed(&process, &token, 0x1000));
        assert!(allowed(&system_token, &token, 0x0008));
        for access in [
            0x0001, 0x0002, 0x0008, 0x0010, 0x0020, 0x0400, 0x40000, 0x80000,
        ] {
            assert!(!allowed(&process, &token, access));
        }
        for access in [
            0x0001, 0x0002, 0x0004, 0x0010, 0x0020, 0x0040, 0x0080, 0x0100, 0x40000, 0x80000,
        ] {
            assert!(!allowed(&system_token, &token, access));
        }
    }
    #[test]
    fn worker_channel_is_unpredictable_and_in_the_private_namespace() {
        let first = new_mcp_channel().unwrap();
        let second = new_mcp_channel().unwrap();
        assert!(kv_ipc::mcp_worker::valid_channel(&first));
        assert!(kv_ipc::mcp_worker::valid_channel(&second));
        assert_ne!(first, second);
    }

    #[test]
    fn closing_the_service_owned_job_terminates_its_child() {
        use windows::Win32::System::{JobObjects::IsProcessInJob, Threading::CreateProcessW};
        unsafe {
            let job = worker_job().unwrap();
            let attributes = Attributes::mitigations(0, HANDLE(job.as_raw_handle() as _)).unwrap();
            let program = std::env::current_exe().unwrap();
            let application = wide(program.to_str().unwrap());
            let mut command = wide(&format!(
                "\"{}\" --ignored --exact agent_process::tests::job_child_fixture",
                program.display()
            ));
            let startup = STARTUPINFOEXW {
                StartupInfo: STARTUPINFOW {
                    cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                    ..Default::default()
                },
                lpAttributeList: attributes.list,
            };
            let mut info = PROCESS_INFORMATION::default();
            CreateProcessW(
                PCWSTR(application.as_ptr()),
                Some(PWSTR(command.as_mut_ptr())),
                None,
                None,
                false,
                CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                None,
                PCWSTR::null(),
                &startup.StartupInfo,
                &mut info,
            )
            .unwrap();
            let child = owned(info.hProcess);
            let _thread = owned(info.hThread);
            let mut member = windows::core::BOOL::default();
            IsProcessInJob(
                info.hProcess,
                Some(HANDLE(job.as_raw_handle() as _)),
                &mut member,
            )
            .unwrap();
            assert!(
                member.as_bool(),
                "the child must enter its job during creation"
            );
            assert_eq!(
                WaitForSingleObject(info.hProcess, 0),
                windows::Win32::Foundation::WAIT_TIMEOUT
            );
            drop(attributes);
            drop(job);
            assert_eq!(
                WaitForSingleObject(HANDLE(child.as_raw_handle() as _), 5000),
                windows::Win32::Foundation::WAIT_OBJECT_0
            );
        }
    }

    #[test]
    #[ignore = "Child fixture, started only by closing_the_service_owned_job_terminates_its_child"]
    fn job_child_fixture() {
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
}
