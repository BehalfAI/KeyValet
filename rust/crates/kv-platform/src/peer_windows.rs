//! Peer identification for named-pipe and loopback connections, mirroring the unix peer module:
//! who connected (token user SID), whether they are elevated, and which executable they are.
//! `GetNamedPipeClientProcessId` gives the kernel's answer for the pipe peer; for loopback TCP
//! `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` maps the client-side port to its owning PID.
//! Both then walk the same OpenProcess -> OpenProcessToken -> TokenUser path.

use std::io;
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenElevation, PSID, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Identity the gateway compares a loopback client against: the owner's user SID.
pub type GatewayPeer = Vec<u8>;

/// Who is on the other end of a connection.
pub struct PeerIdentity {
    /// The peer process token's user SID, as binary SID bytes.
    pub sid: Vec<u8>,
    /// The peer's token is elevated (UAC) — the Windows analogue of "running as root".
    pub elevated: bool,
    /// Full path of the peer executable (empty when it could not be read).
    pub exe_path: PathBuf,
    /// Kernel-provided process id of the peer.
    pub pid: u32,
    pub session_id: u32,
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// SID of `pid`'s primary token, plus elevation state.
fn token_identity(pid: u32) -> io::Result<(Vec<u8>, bool)> {
    unsafe {
        let process = Handle(
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
                .map_err(|e| io::Error::from_raw_os_error(e.code().0))?,
        );
        let mut token = HANDLE::default();
        OpenProcessToken(process.0, TOKEN_QUERY, &mut token)
            .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        let _token = Handle(token);

        let sid = kv_vault::winbuf::token_user_sid(token)?;

        let mut len = 0u32;
        let mut elevation = TOKEN_ELEVATION::default();
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
        .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        Ok((sid, elevation.TokenIsElevated != 0))
    }
}

fn exe_path(pid: u32) -> PathBuf {
    unsafe {
        let Ok(process) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return PathBuf::new();
        };
        let _process = Handle(process);
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        if QueryFullProcessImageNameW(
            process,
            windows::Win32::System::Threading::PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
        .is_err()
        {
            return PathBuf::new();
        }
        PathBuf::from(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// Peer identity from a process id (shared by the pipe and loopback lookups).
pub fn identity_for_pid(pid: u32) -> io::Result<PeerIdentity> {
    let (sid, elevated) = token_identity(pid)?;
    let mut session_id = 0;
    unsafe { windows::Win32::System::RemoteDesktop::ProcessIdToSessionId(pid, &mut session_id) }
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(PeerIdentity {
        sid,
        elevated,
        exe_path: exe_path(pid),
        pid,
        session_id,
    })
}

/// The client on the other end of a connected `NamedPipeServer`.
pub fn peer_identity(
    pipe: &tokio::net::windows::named_pipe::NamedPipeServer,
) -> io::Result<PeerIdentity> {
    let mut pid = 0u32;
    unsafe {
        GetNamedPipeClientProcessId(HANDLE(pipe.as_raw_handle() as _), &mut pid)
            .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
    }
    identity_for_pid(pid)
}

/// `accept_client` is the daemon's entry point: who connected to our pipe.
pub async fn accept_client(
    pipe: &tokio::net::windows::named_pipe::NamedPipeServer,
) -> io::Result<PeerIdentity> {
    peer_identity(pipe)
}

/// Whether two binary SIDs are equal (structure-aware, not just bytes).
pub fn sid_equal(a: &[u8], b: &[u8]) -> bool {
    valid_sid_bytes(a) && valid_sid_bytes(b) && a == b
}

fn valid_sid_bytes(sid: &[u8]) -> bool {
    sid.len() >= 8 && sid[0] == 1 && sid[1] <= 15 && sid.len() == 8 + 4 * usize::from(sid[1])
}

/// Verify the server before sending any request or key material. A pipe name alone is not an
/// identity: another process can bind it while the service is stopped.
pub fn verify_server(raw: std::os::windows::io::RawHandle) -> io::Result<()> {
    let mut pid = 0;
    unsafe {
        GetNamedPipeServerProcessId(HANDLE(raw as _), &mut pid)
            .map_err(|e| io::Error::other(e.to_string()))?;
    }
    let peer = identity_for_pid(pid)?;
    let system =
        sid_from_string("S-1-5-18").ok_or_else(|| io::Error::other("invalid SYSTEM SID"))?;
    if !sid_equal(&peer.sid, &system)
        || !crate::trust::same_file_path(
            &peer.exe_path,
            std::path::Path::new(crate::paths::HELPER_BIN),
        )
        || !crate::trust::trusted_path(&peer.exe_path)
        || !(crate::trust::verify_publisher(&peer.exe_path, crate::paths::AGENT_PUBLISHER).is_ok()
            || crate::trust::allow_unsigned_agent(std::path::Path::new(
                crate::paths::ALLOW_UNSIGNED_AGENT,
            )))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untrusted KeyValet pipe server",
        ));
    }
    Ok(())
}

/// Parse a text SID ("S-1-5-…") into binary form.
pub fn sid_from_string(text: &str) -> Option<Vec<u8>> {
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
    let wide: Vec<u16> = text
        .trim()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let mut psid = PSID::default();
        ConvertStringSidToSidW(windows::core::PCWSTR(wide.as_ptr()), &mut psid).ok()?;
        let len = windows::Win32::Security::GetLengthSid(psid) as usize;
        let mut buf = vec![0u8; len];
        std::ptr::copy_nonoverlapping(psid.0 as *const u8, buf.as_mut_ptr(), len);
        let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
            psid.0 as _,
        )));
        Some(buf)
    }
}

/// Binary SID back to its text form (for audit records and tests).
pub fn sid_to_string(sid: &[u8]) -> Option<String> {
    if !valid_sid_bytes(sid) {
        return None;
    }
    unsafe {
        let mut text = windows::core::PWSTR::null();
        windows::Win32::Security::Authorization::ConvertSidToStringSidW(
            PSID(sid.as_ptr() as _),
            &mut text,
        )
        .ok()?;
        let s = text.to_string().ok();
        let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
            text.0 as _,
        )));
        s
    }
}

/// The current process's own identity (used by tests and by callers that compare "peer == me").
pub fn self_identity() -> Option<PeerIdentity> {
    identity_for_pid(std::process::id()).ok()
}

/// Kernel creation time, used to distinguish a live creator from a reused PID in export files.
pub fn process_start_time(pid: u32) -> io::Result<u64> {
    unsafe {
        let process = Handle(
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
                .map_err(|e| io::Error::from_raw_os_error(e.code().0 & 0xffff))?,
        );
        let mut created = windows::Win32::Foundation::FILETIME::default();
        let mut exited = windows::Win32::Foundation::FILETIME::default();
        let mut kernel = windows::Win32::Foundation::FILETIME::default();
        let mut user = windows::Win32::Foundation::FILETIME::default();
        windows::Win32::System::Threading::GetProcessTimes(
            process.0,
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
        .map_err(|e| io::Error::other(e.to_string()))?;
        Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }
}

/// Who owns the local (client) end of a TCP connection on loopback port `port`: the process
/// whose local source port matches the accepted socket's peer port.
pub fn loopback_client(port: u16) -> Option<PeerIdentity> {
    unsafe {
        let mut size = 0u32;
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            windows::Win32::Networking::WinSock::AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if size == 0 {
            return None;
        }
        let mut buf = kv_vault::winbuf::AlignedBuffer::new(size as usize);
        if GetExtendedTcpTable(
            Some(buf.as_mut_ptr()),
            &mut size,
            false,
            windows::Win32::Networking::WinSock::AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        ) != 0
        {
            return None;
        }
        let count = buf.read_copy::<u32>(0, size as usize)? as usize;
        let offset = std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
        let row_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
        let row_bytes = count.checked_mul(row_size)?;
        buf.bytes(offset, row_bytes, size as usize)?;
        // The caller passes the *source* port of an accepted loopback connection. From the
        // client's side that is dwLocalPort. Never accept the listener-side dwRemotePort:
        // doing so identifies the privileged gateway rather than its actual caller.
        // Ports in the table are network byte order packed into a u32.
        const LOOPBACK: u32 = 0x0100_007F; // 127.0.0.1 in table byte order
        let port_be = u32::from(port.to_be());
        for index in 0..count {
            let row =
                buf.read_copy::<MIB_TCPROW_OWNER_PID>(offset + index * row_size, size as usize)?;
            let is_client = row.dwLocalAddr == LOOPBACK
                && row.dwRemoteAddr == LOOPBACK
                && row.dwLocalPort == port_be;
            if !is_client {
                continue;
            }
            return identity_for_pid(row.dwOwningPid).ok();
        }
        None
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn loopback_lookup_can_identify_a_client_in_our_own_process() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let peer = loopback_client(client.local_addr().unwrap().port()).unwrap();
        assert_eq!(peer.pid, std::process::id());
        assert!(sid_equal(&peer.sid, &self_identity().unwrap().sid));
    }

    #[test]
    fn sid_strings_round_trip() {
        let sid = sid_from_string("S-1-5-18").unwrap();
        assert_eq!(sid_to_string(&sid).unwrap(), "S-1-5-18");
        assert!(sid_equal(&sid, &sid_from_string("S-1-5-18").unwrap()));
        assert!(!sid_equal(&sid, &sid_from_string("S-1-5-32-544").unwrap()));
    }

    #[test]
    fn invalid_sid_strings_do_not_parse() {
        assert!(sid_from_string("not a sid").is_none());
        assert!(sid_from_string("").is_none());
        assert!(!sid_equal(&[], &[]));
        assert!(!sid_equal(
            &[1, 15, 0, 0, 0, 0, 0, 5],
            &sid_from_string("S-1-5-18").unwrap()
        ));
        assert!(sid_to_string(&[]).is_none());
    }
}
