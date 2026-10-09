//! Touch ID gate: the helper starts as root (sudoers only allows running the helper itself without
//! a password), and must pass device-owner authentication before providing any service.
//!
//! This is a port of src/helper/auth-gate.ts's cooldown/lock bookkeeping, which is platform-independent
//! (plain filesystem state). The actual biometric prompt is NOT platform-independent -- in TS it spawns
//! a separate Swift-compiled `touchid` binary with dropped privileges; here it's whatever concrete
//! `Authenticator` the caller provides (the macOS implementation, in kv-platform, drops privileges via
//! setuid/seteuid in-process and calls LocalAuthentication directly through objc2 -- see the rewrite
//! plan's "Open Questions" / kv-platform interface).

use kv_platform::{AuthOutcome, Authenticator};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const AUTH_TIMEOUT: Duration = Duration::from_millis(120_000);
/// Cooldown after a failed authentication: recorded in the root-only vault directory, so even
/// launching the helper directly (bypassing the MCP server) can't trigger repeated prompts.
const FAILURE_COOLDOWN: Duration = Duration::from_millis(30_000);

/// Approved, or denied with a reason to show the caller. Mirrors TS's `GateResult`.
pub type GateResult = std::result::Result<(), String>;

fn failure_file(vault_dir: &Path) -> PathBuf {
    vault_dir.join("auth-failure")
}

pub fn cooldown_remaining(vault_dir: &Path) -> Duration {
    let Ok(raw) = std::fs::read_to_string(failure_file(vault_dir)) else {
        return Duration::ZERO;
    };
    let Ok(last_ms) = raw.trim().parse::<u64>() else {
        return Duration::ZERO;
    };
    let last = SystemTime::UNIX_EPOCH + Duration::from_millis(last_ms);
    let deadline = last + FAILURE_COOLDOWN;
    deadline
        .duration_since(SystemTime::now())
        .unwrap_or(Duration::ZERO)
}

fn record_failure(vault_dir: &Path) {
    let now_ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let _ = std::fs::write(failure_file(vault_dir), now_ms.to_string());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            failure_file(vault_dir),
            std::fs::Permissions::from_mode(0o600),
        );
    }
}

fn clear_failure(vault_dir: &Path) {
    let _ = std::fs::remove_file(failure_file(vault_dir));
}

fn auth_lock_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join(".auth-lock")
}

/// Only one authentication prompt is allowed at a time (when multiple helpers start concurrently,
/// each could otherwise trigger its own prompt before the cooldown check runs). Returns a release
/// guard; dropping it releases the lock (RAII, so it's released even if the caller panics or an
/// early return is taken -- the TS version relies on `finally` for the same guarantee).
pub struct AuthLockGuard(PathBuf);
impl Drop for AuthLockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn acquire_auth_lock(vault_dir: &Path) -> Option<AuthLockGuard> {
    let lock = auth_lock_path(vault_dir);
    match std::fs::create_dir(&lock) {
        Ok(()) => return Some(AuthLockGuard(lock)),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return None,
    }
    let stale = std::fs::metadata(&lock)
        .and_then(|m| m.modified())
        .map(|m| m.elapsed().unwrap_or_default() >= AUTH_TIMEOUT + Duration::from_millis(10_000))
        .unwrap_or(false);
    if !stale {
        return None;
    }
    let _ = std::fs::remove_dir_all(&lock); // the lock-holding process has exited
    std::fs::create_dir(&lock)
        .ok()
        .map(|()| AuthLockGuard(lock))
}

pub async fn touch_id_gate(
    vault_dir: &Path,
    reason: &str,
    deny_label: &str,
    auth: &impl Authenticator,
) -> GateResult {
    let Some(_guard) = acquire_auth_lock(vault_dir) else {
        return Err(kv_i18n::t(
            "已有另一个解锁请求正在等待认证，请稍后再试",
            "Another unlock request is already waiting for authentication; please try again later",
        ));
    };
    gate(vault_dir, reason, deny_label, auth).await
}

async fn gate(
    vault_dir: &Path,
    reason: &str,
    deny_label: &str,
    auth: &impl Authenticator,
) -> GateResult {
    let wait = cooldown_remaining(vault_dir);
    if !wait.is_zero() {
        let secs = wait.as_millis().div_ceil(1000);
        return Err(kv_i18n::t(
            &format!("上次认证未通过，请 {secs} 秒后再试"),
            &format!("The last authentication failed; please try again in {secs} seconds"),
        ));
    }
    match auth.authenticate(reason, deny_label).await {
        AuthOutcome::Approved => {
            clear_failure(vault_dir);
            Ok(())
        }
        AuthOutcome::Unsupported => {
            record_failure(vault_dir);
            Err(kv_i18n::t(
                "本机不支持设备所有者认证（Touch ID / 登录密码）",
                "This Mac does not support device owner authentication (Touch ID / login password)",
            ))
        }
        AuthOutcome::Denied => {
            record_failure(vault_dir);
            Err(kv_i18n::t(
                "Touch ID 认证未通过（已拒绝、取消或超时）",
                "Touch ID authentication failed (denied, canceled, or timed out)",
            ))
        }
        AuthOutcome::Error(message) => {
            record_failure(vault_dir);
            Err(message)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fake(AuthOutcome, AtomicUsize);
    impl Authenticator for Fake {
        async fn authenticate(&self, _reason: &str, _deny_label: &str) -> AuthOutcome {
            self.1.fetch_add(1, Ordering::SeqCst);
            self.0.clone()
        }
    }

    #[tokio::test]
    async fn approved_clears_any_prior_failure() {
        let dir = tempfile::tempdir().unwrap();
        // A STALE failure (well past the cooldown window), so this call isn't itself blocked by
        // it -- a fresh one would be, which is exactly what the next test checks.
        let stale_ms = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            - 60_000;
        std::fs::write(failure_file(dir.path()), stale_ms.to_string()).unwrap();
        assert_eq!(
            cooldown_remaining(dir.path()),
            Duration::ZERO,
            "a stale failure shouldn't itself cause a cooldown"
        );

        let auth = Fake(AuthOutcome::Approved, AtomicUsize::new(0));
        assert!(touch_id_gate(dir.path(), "test", "Deny", &auth)
            .await
            .is_ok());
        assert!(
            !failure_file(dir.path()).exists(),
            "a successful auth should clear the stale failure marker"
        );
    }

    #[tokio::test]
    async fn denied_starts_a_cooldown_that_blocks_the_next_attempt_without_prompting_again() {
        let dir = tempfile::tempdir().unwrap();
        let auth = Fake(AuthOutcome::Denied, AtomicUsize::new(0));
        assert!(touch_id_gate(dir.path(), "test", "Deny", &auth)
            .await
            .is_err());
        assert!(!cooldown_remaining(dir.path()).is_zero());
        // Still in cooldown: the second call must fail WITHOUT calling the authenticator again.
        let err = touch_id_gate(dir.path(), "test", "Deny", &auth)
            .await
            .unwrap_err();
        assert!(err.contains("请") || err.to_lowercase().contains("try again"));
        assert_eq!(
            auth.1.load(Ordering::SeqCst),
            1,
            "the authenticator must not be invoked again during cooldown"
        );
    }

    #[tokio::test]
    async fn concurrent_gates_serialize_on_the_auth_lock() {
        let dir = tempfile::tempdir().unwrap();
        let _held = acquire_auth_lock(dir.path()).unwrap();
        let auth = Fake(AuthOutcome::Approved, AtomicUsize::new(0));
        let err = touch_id_gate(dir.path(), "test", "Deny", &auth)
            .await
            .unwrap_err();
        assert_eq!(
            auth.1.load(Ordering::SeqCst),
            0,
            "the authenticator must not run while another request holds the lock"
        );
        drop(err);
    }

    #[tokio::test]
    async fn unsupported_also_starts_a_cooldown() {
        let dir = tempfile::tempdir().unwrap();
        let auth = Fake(AuthOutcome::Unsupported, AtomicUsize::new(0));
        assert!(touch_id_gate(dir.path(), "test", "Deny", &auth)
            .await
            .is_err());
        assert!(!cooldown_remaining(dir.path()).is_zero());
    }
}
