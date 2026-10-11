//! UI runs in this interactive MCP process. Authoritative approvals still come from the
//! signed agent through the helper, so a client cannot self-authorize a vault operation.

/// Collect application secrets in a hidden native input field.
pub async fn prompt_secret(message: &str) -> Option<String> {
    let message = message.to_owned();
    tokio::task::spawn_blocking(move || {
        kv_platform::windows::prompt_secret(&message).map(|s| (*s).clone())
    })
    .await
    .ok()
    .flatten()
}

/// Cancellation and failures deny the request.
pub async fn confirm(message: &str, ok_label: &str) -> bool {
    let message = message.to_owned();
    let label = ok_label.to_owned();
    tokio::task::spawn_blocking(move || kv_platform::windows::confirm(&message, &label))
        .await
        .unwrap_or(false)
}

/// The default button remains Cancel.
pub async fn ask(message: &str, ok_label: &str) -> bool {
    confirm(message, ok_label).await
}

/// Device-code and other notices close on timeout or when the handle is dropped.
pub type Notice = kv_platform::windows::Notice;

pub fn show_notice(message: &str, timeout_sec: u64) -> Option<Notice> {
    Some(kv_platform::windows::show_notice(message, timeout_sec))
}
