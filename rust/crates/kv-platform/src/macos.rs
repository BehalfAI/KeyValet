//! Concrete macOS implementations of `Authenticator`/`Confirmer`: Touch ID via a separately
//! spawned, hardened-signed `kv-touchid` binary, and confirmation dialogs via `/usr/bin/osascript`
//! -- both spawned with privileges dropped to the user who invoked sudo (a biometric prompt or a
//! dialog can't reach the user's Aqua session while running as root). Direct port of the spawn half
//! of src/helper/auth-gate.ts and of src/helper/user-dialog.ts.

use crate::paths::{OSASCRIPT_BIN, TOUCHID_BIN};
use crate::trust::untrusted_reason;
use crate::user;
use crate::{AuthOutcome, Authenticator, Confirmer};
use std::path::Path;
use std::time::Duration;

const AUTH_TIMEOUT: Duration = Duration::from_millis(120_000);
const CONFIRM_TIMEOUT: Duration = Duration::from_millis(130_000);

/// Builds a `program` invocation with privileges dropped to the invoking user. Never
/// `CommandExt::uid/gid`: on macOS that sequence resets the effective gid to 0 (wheel) --
/// see `user::drop_to`.
fn dropped_command(
    program: &str,
    args: &[&str],
    uid: u32,
    gid: u32,
    capture_stdout: bool,
) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .kill_on_drop(true)
        .current_dir("/")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(std::process::Stdio::null())
        .stdout(if capture_stdout {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stderr(std::process::Stdio::null());
    unsafe {
        cmd.pre_exec(user::drop_to(uid, gid));
    }
    cmd
}

/// Runs `program` with privileges dropped to the invoking user, waiting up to `timeout` and
/// killing it if that elapses. `None` means the process could not be spawned at all.
async fn run_dropped(
    program: &str,
    args: &[&str],
    uid: u32,
    gid: u32,
    timeout: Duration,
    capture_stdout: bool,
) -> Option<(Option<i32>, String)> {
    run_with_timeout(
        dropped_command(program, args, uid, gid, capture_stdout),
        timeout,
        capture_stdout,
    )
    .await
}

/// Spawns `cmd` and waits up to `timeout`, killing it if that elapses. `None` means the process
/// could not be spawned at all, or never produced an exit status in time.
async fn run_with_timeout(
    mut cmd: tokio::process::Command,
    timeout: Duration,
    capture_stdout: bool,
) -> Option<(Option<i32>, String)> {
    let mut child = cmd.spawn().ok()?;
    let wait = async {
        let out = if capture_stdout {
            child.wait_with_output().await.ok()
        } else {
            child.wait().await.ok().map(|status| std::process::Output {
                status,
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        };
        out
    };
    match tokio::time::timeout(timeout, wait).await {
        Ok(Some(out)) => Some((
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).to_string(),
        )),
        _ => None, // timed out, or we never got an exit status -- either way, treat as failed
    }
}

pub struct TouchIdAuthenticator;

impl Authenticator for TouchIdAuthenticator {
    async fn authenticate(&self, reason: &str, deny_label: &str) -> AuthOutcome {
        if let Some(bad) = untrusted_reason(Path::new(TOUCHID_BIN)) {
            return AuthOutcome::Error(kv_i18n::t(
                &format!("Touch ID 程序不可信（{bad}），请重新安装"),
                &format!("The Touch ID program is untrusted ({bad}); please reinstall"),
            ));
        }
        let Some((uid, gid)) = user::invoking_user() else {
            return AuthOutcome::Error(kv_i18n::t(
                "无法确定发起请求的用户（SUDO_UID）",
                "Cannot determine the requesting user (SUDO_UID)",
            ));
        };
        match run_dropped(
            TOUCHID_BIN,
            &[reason, deny_label],
            uid,
            gid,
            AUTH_TIMEOUT,
            false,
        )
        .await
        {
            Some((Some(0), _)) => AuthOutcome::Approved,
            Some((Some(2), _)) => AuthOutcome::Unsupported,
            _ => AuthOutcome::Denied,
        }
    }
}

pub struct RootUserDialogConfirmer;

impl Confirmer for RootUserDialogConfirmer {
    async fn confirm(&self, message: &str, ok_label: &str) -> bool {
        let Some((uid, gid)) = user::invoking_user() else {
            return false;
        };
        let script = r#"on run argv
  set r to display dialog (item 1 of argv) with title (item 2 of argv) buttons {(item 4 of argv), (item 3 of argv)} default button (item 4 of argv) cancel button (item 4 of argv) with icon caution giving up after 120
  if gave up of r then error number -128
  return button returned of r
end run"#;
        let title = kv_i18n::t("KeyValet · 安全确认", "KeyValet · Security Confirmation");
        let deny = kv_i18n::t("拒绝", "Deny");
        let args = ["-e", script, "--", message, &title, ok_label, &deny];
        match run_dropped(OSASCRIPT_BIN, &args, uid, gid, CONFIRM_TIMEOUT, true).await {
            Some((Some(0), out)) => out.trim() == ok_label,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn timed_out_dialog_processes_are_terminated() {
        let dir = tempfile::tempdir().unwrap();
        for capture_stdout in [false, true] {
            let pid_file = dir.path().join(format!("pid-{capture_stdout}"));
            let args = [
                "-c",
                r#"echo $$ > "$1"; exec /bin/sleep 60"#,
                "keyvalet-dialog-timeout-test",
                pid_file.to_str().unwrap(),
            ];
            let mut cmd = tokio::process::Command::new("/bin/sh");
            cmd.args(args)
                .kill_on_drop(true)
                .current_dir("/")
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .stdin(std::process::Stdio::null())
                .stdout(if capture_stdout {
                    std::process::Stdio::piped()
                } else {
                    std::process::Stdio::null()
                })
                .stderr(std::process::Stdio::null());
            // Plain un-dropped command: as non-root, `user::drop_to` would fail with EPERM.
            let result = run_with_timeout(cmd, Duration::from_millis(250), capture_stdout).await;
            assert!(result.is_none());
            let pid: libc::pid_t = std::fs::read_to_string(pid_file)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            let reaped = tokio::time::timeout(Duration::from_secs(2), async {
                while unsafe { libc::kill(pid, 0) } == 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await;
            if reaped.is_err() {
                // Keep a failed regression test from leaving its disposable child running.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
            assert!(reaped.is_ok(), "a timed-out dialog must not stay open");
        }
    }
}
