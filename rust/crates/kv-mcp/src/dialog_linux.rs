//! User input on Linux. Desktop dialogs and /dev/tty never consume MCP stdin.
//! These collect values/confirm local imports; authorization remains in helper-side polkit.
use std::time::Duration;

fn zenity() -> Option<tokio::process::Command> {
    if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
        return None;
    }
    let path = std::path::Path::new("/usr/bin/zenity");
    if kv_platform::trust::untrusted_reason(path).is_some() {
        return None;
    }
    let mut command = tokio::process::Command::new(path);
    command
        .args(["--title=KeyValet", "--no-markup"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    Some(command)
}

pub async fn prompt_secret(message: &str) -> Option<String> {
    let full = kv_i18n::t(&format!("【保存秘密】{message}\n这里不是 Linux 登录密码或 sudo 密码，请勿在此输入登录密码。"), &format!("[Save secret] {message}\nThis is not a Linux login or sudo password prompt. Do not enter your login password here."));
    if let Some(mut command) = zenity() {
        let output = tokio::time::timeout(
            Duration::from_secs(310),
            command
                .args(["--entry", "--hide-text", "--timeout=300", "--text", &full])
                .output(),
        )
        .await
        .ok()?
        .ok()?;
        if !output.status.success() {
            return None;
        }
        let value = String::from_utf8(output.stdout)
            .ok()?
            .trim_end_matches('\n')
            .to_owned();
        return (!value.is_empty()).then_some(value);
    }
    tokio::task::spawn_blocking(move || {
        rpassword::prompt_password(format!("{full}\nSecret (hidden): "))
            .ok()
            .filter(|s| !s.is_empty())
    })
    .await
    .ok()?
}

pub async fn confirm(message: &str, ok_label: &str) -> bool {
    if let Some(mut command) = zenity() {
        return matches!(tokio::time::timeout(Duration::from_secs(130), command.args(["--question", "--default-cancel", "--timeout=120", "--text", message, "--ok-label", ok_label]).status()).await, Ok(Ok(status)) if status.success());
    }
    let message = format!("{message}\n{ok_label}: type yes to confirm [default: cancel]: ");
    tokio::task::spawn_blocking(move || {
        use std::io::{BufRead, Write};
        let Ok(mut tty) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
        else {
            return false;
        };
        if write!(tty, "{message}").and_then(|_| tty.flush()).is_err() {
            return false;
        }
        let mut answer = String::new();
        std::io::BufReader::new(tty).read_line(&mut answer).is_ok() && answer.trim() == "yes"
    })
    .await
    .unwrap_or(false)
}

pub async fn ask(message: &str, ok_label: &str) -> bool {
    confirm(message, ok_label).await
}

pub struct Notice(tokio::process::Child);
impl Drop for Notice {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

pub fn show_notice(message: &str, timeout_sec: u64) -> Option<Notice> {
    if let Some(mut command) = zenity() {
        command
            .args([
                "--info",
                "--text",
                message,
                &format!("--timeout={timeout_sec}"),
            ])
            .stdout(std::process::Stdio::null());
        command.spawn().ok().map(Notice)
    } else {
        eprintln!("KeyValet: {message}");
        None
    }
}
