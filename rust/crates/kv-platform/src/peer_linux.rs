//! Kernel identities for Linux Unix sockets and loopback TCP clients.
use std::io;
use std::os::fd::RawFd;

pub type GatewayPeer = u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCredentials {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

pub fn peer_credentials(fd: RawFd) -> io::Result<PeerCredentials> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    validate_credentials(cred, len)
}

fn validate_credentials(cred: libc::ucred, len: libc::socklen_t) -> io::Result<PeerCredentials> {
    if len as usize != std::mem::size_of_val(&cred) || cred.pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid peer credentials",
        ));
    }
    Ok(PeerCredentials {
        uid: cred.uid,
        gid: cred.gid,
        pid: cred.pid as u32,
    })
}

pub fn peer_uid(fd: RawFd) -> io::Result<u32> {
    peer_credentials(fd).map(|c| c.uid)
}

/// /proc stat field 22, in clock ticks since boot. The command field may itself
/// contain whitespace and parentheses, so splitting the whole line is unsafe.
pub fn process_start_time(pid: u32) -> io::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_start_time(&stat)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid process stat"))
}

fn parse_start_time(stat: &str) -> Option<u64> {
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// The gateway binds IPv4 loopback. Read the kernel's connection table, selecting
/// the client's local port, rather than running lsof with a platform-specific path.
/// Ambiguous ownership fails closed (a port can appear in several TCP tuples).
pub fn loopback_client(port: u16) -> Option<GatewayPeer> {
    tcp_client_uid(&std::fs::read_to_string("/proc/net/tcp").ok()?, port)
}

fn tcp_client_uid(table: &str, port: u16) -> Option<u32> {
    let mut found = None;
    for line in table.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 8 || fields[3] != "01" {
            continue;
        }
        let (local_addr, local_port) = fields[1].split_once(':')?;
        let (remote_addr, _) = fields[2].split_once(':')?;
        if local_addr != "0100007F"
            || remote_addr != "0100007F"
            || u16::from_str_radix(local_port, 16).ok()? != port
        {
            continue;
        }
        let uid = fields[7].parse().ok()?;
        if found.is_some_and(|previous| previous != uid) {
            return None;
        }
        found = Some(uid);
    }
    found
}

#[cfg(test)]
#[path = "peer_linux/tests.rs"]
mod tests;
