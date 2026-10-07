//! Native macOS dialogs. All text is passed to AppleScript via argv to avoid script injection;
//! only validated type/name values and fixed strings ever appear in the dialog -- no long text
//! that an agent could freely control is ever shown, preventing an agent from using a forged
//! prompt to trick the user into entering their sudo password or similar.
//! Direct port of src/server/dialog.ts.

use kv_platform::paths::OSASCRIPT_BIN;
use std::time::Duration;
use tokio::io::AsyncReadExt;

const TITLE: &str = "KeyValet";

async fn run_applescript(script: &str, args: &[&str], timeout: Duration) -> Option<String> {
    let mut cmd = tokio::process::Command::new(OSASCRIPT_BIN);
    cmd.arg("-e").arg(script).arg("--");
    cmd.args(args);
    cmd.env_clear().env("PATH", "/usr/bin:/bin");
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let mut child = cmd.spawn().ok()?;
    let mut stdout = child.stdout.take()?;
    let read = async {
        let mut buf = Vec::new();
        stdout.read_to_end(&mut buf).await.ok()?;
        Some(buf)
    };
    match tokio::time::timeout(timeout, read).await {
        Ok(Some(buf)) => {
            let status = child.wait().await.ok()?;
            if status.success() {
                Some(String::from_utf8_lossy(&buf).to_string())
            } else {
                None
            }
        }
        _ => {
            let _ = child.start_kill();
            None
        }
    }
}

/// Shows a hidden-input dialog so the user can type a credential value directly (never passing
/// through the AI context). Returns `None` on cancel or timeout.
/// Deliberately distinguished from the sudo password prompt (different title, icon, fixed warning)
/// so users don't accidentally type their login password here.
pub async fn prompt_secret(message: &str) -> Option<String> {
    let script = r#"on run argv
  set r to display dialog (item 1 of argv) with title (item 2 of argv) default answer "" with hidden answer buttons {(item 3 of argv), (item 4 of argv)} default button (item 4 of argv) cancel button (item 3 of argv) with icon note giving up after 300
  if gave up of r then error number -128
  return text returned of r
end run"#;
    let full = kv_i18n::t(
        &format!("【保存秘密】{message}\n\n⚠️ 这里不是 Mac 登录密码 / sudo 密码，请勿在此输入登录密码。"),
        &format!("[Save secret] {message}\n\n⚠️ This is NOT your Mac login / sudo password. Do not enter your login password here."),
    );
    let title = format!("{TITLE} · {}", kv_i18n::t("保存秘密", "Save Secret"));
    let cancel = kv_i18n::t("取消", "Cancel");
    let save = kv_i18n::t("保存", "Save");
    let out = run_applescript(
        script,
        &[&full, &title, &cancel, &save],
        Duration::from_millis(310_000),
    )
    .await?;
    let value = out.strip_suffix('\n').unwrap_or(&out);
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Confirmation dialog; the default button is "Cancel".
pub async fn confirm(message: &str, ok_label: &str) -> bool {
    let script = r#"on run argv
  set r to display dialog (item 1 of argv) with title (item 2 of argv) buttons {(item 4 of argv), (item 3 of argv)} default button (item 4 of argv) cancel button (item 4 of argv) with icon caution giving up after 120
  if gave up of r then error number -128
  return button returned of r
end run"#;
    let cancel = kv_i18n::t("取消", "Cancel");
    match run_applescript(
        script,
        &[message, TITLE, ok_label, &cancel],
        Duration::from_millis(130_000),
    )
    .await
    {
        Some(out) => out.trim() == ok_label,
        None => false,
    }
}

/// Prompt dialog: the default button performs the action (Enter triggers it), "Cancel" is the
/// cancel button. Returns whether the action button was clicked.
pub async fn ask(message: &str, ok_label: &str) -> bool {
    let script = r#"on run argv
  set r to display dialog (item 1 of argv) with title (item 2 of argv) buttons {(item 4 of argv), (item 3 of argv)} default button 2 cancel button 1 with icon note giving up after 600
  if gave up of r then error number -128
  return button returned of r
end run"#;
    let cancel = kv_i18n::t("取消", "Cancel");
    match run_applescript(
        script,
        &[message, TITLE, ok_label, &cancel],
        Duration::from_millis(610_000),
    )
    .await
    {
        Some(out) => out.trim() == ok_label,
        None => false,
    }
}

/// Non-blocking notice dialog (e.g., for showing a device code); has no default button (so Enter
/// won't dismiss it accidentally); returns a handle whose drop closes it.
pub struct Notice(tokio::process::Child);
impl Drop for Notice {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

pub fn show_notice(message: &str, timeout_sec: u64) -> Option<Notice> {
    let script = format!(
        "on run argv\n  display dialog (item 1 of argv) with title (item 2 of argv) buttons {{(item 3 of argv)}} giving up after {timeout_sec}\nend run"
    );
    let ok_label = kv_i18n::t("好", "OK");
    let mut cmd = tokio::process::Command::new(OSASCRIPT_BIN);
    cmd.arg("-e")
        .arg(&script)
        .arg("--")
        .arg(message)
        .arg(TITLE)
        .arg(&ok_label);
    cmd.env_clear().env("PATH", "/usr/bin:/bin");
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    cmd.spawn().ok().map(Notice)
}
