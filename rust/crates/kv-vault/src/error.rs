use kv_i18n::t;
use std::fmt;

/// Direct port of vault.ts's `VaultError`: a message already resolved to the process's current
/// language (same `t(zh, en)` mechanism as the TS helper), so error text matches byte-for-byte.
#[derive(Debug)]
pub struct VaultError(pub String);

impl VaultError {
    pub fn new(zh: &str, en: &str) -> Self {
        Self(t(zh, en))
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::new(&format!("内部错误：{e}"), &format!("Internal error: {e}"))
    }
}

impl From<serde_json::Error> for VaultError {
    fn from(e: serde_json::Error) -> Self {
        VaultError::new(&format!("内部错误：{e}"), &format!("Internal error: {e}"))
    }
}

pub type Result<T> = std::result::Result<T, VaultError>;
