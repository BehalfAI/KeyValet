//! Native dialogs on Windows go through the per-user agent (kv-agent, W3) because the helper
//! service runs in session 0 and cannot show UI. Until then every entry point behaves as a
//! declined/absent prompt -- callers already treat None/false as "the user didn't confirm".

/// Returns `None`: there is no dialog channel on Windows yet (W3).
pub async fn prompt_secret(_message: &str) -> Option<String> {
    None
}

/// Returns `false`: without a dialog channel the safe answer to a confirm prompt is "no".
pub async fn confirm(_message: &str, _ok_label: &str) -> bool {
    false
}

/// Returns `false` for the same reason as `confirm`.
pub async fn ask(_message: &str, _ok_label: &str) -> bool {
    false
}

/// Placeholder for the non-blocking notice dialog (device codes etc.); `None` until W3.
pub struct Notice;
impl Drop for Notice {
    fn drop(&mut self) {}
}

pub fn show_notice(_message: &str, _timeout_sec: u64) -> Option<Notice> {
    None
}
