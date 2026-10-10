//! Peer identity for Unix-socket connections, and code-signature verification of the connecting
//! process via Security.framework. The daemon uses this to know it is talking to OUR signed
//! `kv-touchid` agent, not just any process running as the same user (a same-user process could
//! otherwise impersonate the agent and answer "approved" to every prompt).

use std::ffi::c_void;
use std::io;
use std::os::unix::io::RawFd;

/// `SOL_LOCAL` on macOS; `LOCAL_PEERTOKEN` returns the 32-byte audit token of the socket peer.
const SOL_LOCAL: i32 = 0;
const LOCAL_PEERTOKEN: i32 = 0x006;

extern "C" {
    fn getpeereid(s: libc::c_int, uid: *mut libc::uid_t, gid: *mut libc::gid_t) -> libc::c_int;
}

/// The real uid of the process on the other end of a connected Unix socket.
pub fn peer_uid(fd: RawFd) -> io::Result<u32> {
    unsafe {
        let (mut uid, mut gid) = (0u32, 0u32);
        if getpeereid(fd, &mut uid, &mut gid) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(uid)
    }
}

/// The audit token of the process on the other end: `token[5]` is its pid. This is what
/// `SecCodeCopyGuestWithAttributes` consumes to validate the peer's code identity -- unlike
/// asking the peer for its own pid, the kernel fills this in and it cannot be forged.
pub fn peer_audit_token(fd: RawFd) -> io::Result<[u32; 8]> {
    unsafe {
        let mut token = [0u32; 8];
        let mut len = 32u32;
        if libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            token.as_mut_ptr() as *mut c_void,
            &mut len,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(token)
    }
}

type CFTypeRef = core_foundation_sys::base::CFTypeRef;
type SecCodeRef = *const c_void;
type SecRequirementRef = *const c_void;

#[link(name = "Security", kind = "framework")]
extern "C" {
    /// The guest-attribute key that carries a process's audit token (a `CFData` of the 32-byte
    /// kernel-provided token) to `SecCodeCopyGuestWithAttributes`.
    static kSecGuestAttributeAudit: CFTypeRef;

    fn SecCodeCopyGuestWithAttributes(
        host: SecCodeRef,
        attributes: CFTypeRef,
        flags: u32,
        guest: *mut SecCodeRef,
    ) -> i32;
    fn SecRequirementCreateWithString(
        text: CFTypeRef,
        flags: u32,
        requirement: *mut SecRequirementRef,
    ) -> i32;
    fn SecCodeCheckValidity(code: SecCodeRef, flags: u32, requirement: SecRequirementRef) -> i32;
    fn SecCodeCopyStaticCode(code: SecCodeRef, flags: u32, static_code: *mut SecCodeRef) -> i32;
    fn SecCodeCopyPath(code: SecCodeRef, flags: u32, path: *mut CFTypeRef) -> i32;
}

/// Length-counted, never C-string APIs: `&str` is not NUL-terminated, and `CFStringCreateWithCString`
/// on it would read out of bounds.
fn cfstr(s: &str) -> core_foundation_sys::string::CFStringRef {
    unsafe {
        core_foundation_sys::string::CFStringCreateWithBytes(
            std::ptr::null(),
            s.as_ptr(),
            s.len() as isize,
            core_foundation_sys::string::kCFStringEncodingUTF8,
            0,
        )
    }
}

struct Release(CFTypeRef);
impl Drop for Release {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { core_foundation_sys::base::CFRelease(self.0) };
        }
    }
}

/// Verifies that the peer identified by `token` satisfies `requirement` (a `codesign`
/// designated-requirement string) AND that its on-disk path is exactly `expected_path`. The
/// path check stops a signed-but-moved binary from satisfying the identifier requirement.
pub fn verify_peer_code(
    token: &[u32; 8],
    requirement: &str,
    expected_path: &str,
) -> Result<(), String> {
    unsafe {
        let audit_data = Release(core_foundation_sys::data::CFDataCreate(
            std::ptr::null(),
            token.as_ptr() as *const u8,
            32,
        ) as CFTypeRef);
        if audit_data.0.is_null() {
            return Err("could not build audit token data".into());
        }
        let keys: [*const c_void; 1] = [kSecGuestAttributeAudit];
        let values: [*const c_void; 1] = [audit_data.0];
        let attrs = Release(core_foundation_sys::dictionary::CFDictionaryCreate(
            std::ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            1,
            &core_foundation_sys::dictionary::kCFTypeDictionaryKeyCallBacks,
            &core_foundation_sys::dictionary::kCFTypeDictionaryValueCallBacks,
        ) as CFTypeRef);
        if attrs.0.is_null() {
            return Err("could not build guest attributes".into());
        }
        let mut code: SecCodeRef = std::ptr::null();
        let status = SecCodeCopyGuestWithAttributes(std::ptr::null(), attrs.0, 0, &mut code);
        if status != 0 || code.is_null() {
            return Err(format!("SecCodeCopyGuestWithAttributes failed ({status})"));
        }
        let _code = Release(code);
        let req_str = Release(cfstr(requirement) as CFTypeRef);
        let mut req: SecRequirementRef = std::ptr::null();
        if SecRequirementCreateWithString(req_str.0, 0, &mut req) != 0 || req.is_null() {
            return Err("invalid designated requirement".into());
        }
        let _req = Release(req);
        let status = SecCodeCheckValidity(code, 0, req);
        if status != 0 {
            return Err(format!(
                "peer code signature does not satisfy the requirement ({status})"
            ));
        }
        let mut static_code: SecCodeRef = std::ptr::null();
        if SecCodeCopyStaticCode(code, 0, &mut static_code) != 0 || static_code.is_null() {
            return Err("could not get static code for the peer".into());
        }
        let _static_code = Release(static_code);
        let mut url: core_foundation_sys::url::CFURLRef = std::ptr::null();
        if SecCodeCopyPath(static_code, 0, &mut url as *mut _ as *mut CFTypeRef) != 0
            || url.is_null()
        {
            return Err("could not get the peer's code path".into());
        }
        let _url = Release(url as CFTypeRef);
        let mut buf = [0u8; 4096];
        if core_foundation_sys::url::CFURLGetFileSystemRepresentation(
            url,
            1,
            buf.as_mut_ptr(),
            buf.len() as isize,
        ) == 0
        {
            return Err("could not resolve the peer's code path".into());
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let path = String::from_utf8_lossy(&buf[..end]);
        if path != expected_path {
            return Err(format!("peer runs from {path}, expected {expected_path}"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::{AGENT_REQUIREMENT, TOUCHID_BIN};

    #[test]
    fn unix_socket_peers_report_their_own_identity() {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        use std::os::unix::io::AsRawFd;
        for fd in [a.as_raw_fd(), b.as_raw_fd()] {
            assert_eq!(peer_uid(fd).unwrap(), unsafe { libc::getuid() });
            let token = peer_audit_token(fd).unwrap();
            assert_eq!(token[5] as i64, std::process::id() as i64, "token pid");
        }
    }

    /// Positive check: our own (linker/ad-hoc signed) test binary satisfies its own designated
    /// requirement (`cdhash H"..."`) -- this proves the Sec* FFI actually works end to end; the
    /// negative test alone would pass even if the FFI were broken.
    #[test]
    fn verify_peer_code_accepts_the_calling_binary_against_its_own_requirement() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        use std::os::unix::io::AsRawFd;
        let token = peer_audit_token(a.as_raw_fd()).unwrap();
        let exe = std::env::current_exe().unwrap();
        let exe = exe.canonicalize().unwrap_or(exe);
        let out = std::process::Command::new("/usr/bin/codesign")
            .args(["-d", "-r-"])
            .arg(&exe)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string()
            + &String::from_utf8_lossy(&out.stderr);
        // "designated => cdhash H"..."" (ad-hoc) or "designated => identifier ..."
        let marker = "designated => ";
        let designated = text
            .lines()
            .find_map(|l| l.find(marker).map(|i| l[i + marker.len()..].to_string()))
            .expect("codesign -d -r- printed no designated requirement");
        let path = exe.to_str().unwrap();
        assert!(
            verify_peer_code(&token, &designated, path).is_ok(),
            "own requirement must verify"
        );
        assert!(
            verify_peer_code(&token, &designated, "/usr/bin/true").is_err(),
            "the path check must reject a different expected path"
        );
    }

    #[test]
    fn our_own_test_binary_is_rejected_by_the_agent_requirement() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        use std::os::unix::io::AsRawFd;
        let token = peer_audit_token(a.as_raw_fd()).unwrap();
        // The test binary is linker-signed (ad-hoc, no Apple anchor): it must fail.
        assert!(verify_peer_code(&token, AGENT_REQUIREMENT, TOUCHID_BIN).is_err());
    }
}
