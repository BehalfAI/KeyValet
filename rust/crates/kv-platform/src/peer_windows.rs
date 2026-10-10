//! Peer identification for named-pipe connections. The unix daemon distinguishes the owner user
//! from root via `getpeereid`; on Windows the equivalent is the connecting process's session/user
//! SID read off the pipe (`GetNamedPipeClientProcessId` + token user SID), landing in W2 together
//! with the pipe DACLs. Until then the seam fails closed: every client is refused.

use std::io;

/// Who is on the other end of a HELPER_PIPE connection. The `sid` is the token user SID of the
/// peer process; `elevated` is its token elevation state (root-equivalent).
pub struct PeerIdentity {
    pub sid: Vec<u8>,
    pub elevated: bool,
}

/// W2 will fill this in with the real pipe-peer lookup. Refusing every connection keeps the
/// service safe by default: a helper that cannot identify its caller must not start a session.
pub async fn accept_client<S>(_: &S) -> io::Result<PeerIdentity> {
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        kv_i18n::t(
            "尚不支持：Windows 上对端身份识别将在 W2 实现",
            "peer identification is not implemented on Windows yet",
        ),
    ))
}
