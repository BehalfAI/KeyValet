//! Per-session private files (gateway env exports, secret file hand-offs). The unix version
//! relies on fd-relative `openat`/`unlinkat` inside a 0700 directory; the Windows version lands
//! with W3 alongside the agent. Until then writes fail with a clear error and lifecycle hooks
//! are no-ops -- no secret is ever placed where a weaker ACL could leak it.

use std::io;
use std::path::PathBuf;

pub fn purge_legacy_records() {}
pub fn activate_session_files() {}
pub fn cleanup_gateway_env() {}

/// POSIX single-quoting, kept because it renders into usage text shown to the user (who may run
/// it under Git Bash / WSL even on Windows).
pub fn quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', r"'\''"))
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        kv_i18n::t(
            "暂不支持：Windows 的会话私有文件将在 W3 实现",
            "not supported yet: per-session private files land with the W3 agent",
        ),
    )
}

pub fn write_gateway_env(
    _session: &str,
    _ty: &str,
    _name: &str,
    _env: &[(String, String)],
) -> io::Result<PathBuf> {
    Err(unsupported())
}

pub fn write_secret_file(
    _session: &str,
    _ty: &str,
    _name: &str,
    _field: Option<&str>,
    _content: &str,
) -> io::Result<PathBuf> {
    Err(unsupported())
}
