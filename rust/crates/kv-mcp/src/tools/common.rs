//! Shared helpers for tool implementations. Direct port of src/server/tools/common.ts.

use crate::dialog::confirm;
use crate::files::{read_secret_file, resolve_secret_file};
use crate::session::{HelperSession, Requester, SessionError};
use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::{Map, Value};
use std::future::Future;
use std::sync::LazyLock;

pub fn ok(text: impl Into<String>) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(text.into())])
}

pub fn ok_data(text: impl Into<String>, data: impl serde::Serialize) -> CallToolResult {
    let body = serde_json::to_string_pretty(&data).unwrap_or_default();
    CallToolResult::success(vec![ContentBlock::text(format!("{}\n{body}", text.into()))])
}

pub fn fail(text: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(text.into())])
}

/// Runs a tool body, converting any error into a `fail()` result -- mirrors TS's `wrap()`.
pub async fn wrap(fut: impl Future<Output = Result<CallToolResult, String>>) -> CallToolResult {
    match fut.await {
        Ok(r) => r,
        Err(e) => fail(kv_i18n::t(&format!("错误：{e}"), &format!("Error: {e}"))),
    }
}

impl From<SessionError> for String {
    fn from(e: SessionError) -> Self {
        e.0
    }
}

pub fn norm(s: &str) -> String {
    s.trim().to_lowercase()
}

/// Required purpose string: shown in the Touch ID prompt (when unlocking is needed) and recorded
/// in the audit log.
pub fn purpose_desc() -> String {
    kv_i18n::t(
        "本次操作的目的（必填）：需要解锁时会显示在 Touch ID 弹窗中，并记入审计日志。例如\u{201c}读取订单 #6 的测试邮件\u{201d}",
        "Purpose of this operation (required): shown in the Touch ID prompt when unlocking is needed, and recorded in the audit log. E.g. \"Read the test email for order #6\"",
    )
}

pub fn optional_purpose_desc() -> String {
    kv_i18n::t("本次操作的目的（可选）：需要解锁时显示在 Touch ID 弹窗中", "Purpose of this operation (optional): shown in the Touch ID prompt when unlocking is needed")
}

pub fn type_field_desc() -> String {
    kv_i18n::t("凭证类型，如 api_key、password、token、ssh_key（小写，不存在时自动创建）", "Credential type, e.g. api_key, password, token, ssh_key (lowercase; created automatically if missing)")
}

pub fn name_field_desc() -> String {
    kv_i18n::t(
        "凭证名，如 openai、github、aws-prod（小写）",
        "Credential name, e.g. openai, github, aws-prod (lowercase)",
    )
}

pub static CLIENT_ID_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[A-Za-z0-9._@:/-]{1,200}$").unwrap());

/// A value that will appear in a native dialog: must match a strict format, to prevent an agent
/// from injecting misleading text.
pub fn safe_display(v: &str, re: &regex::Regex, what: &str) -> Result<String, String> {
    if !re.is_match(v) {
        return Err(kv_i18n::t(
            &format!("{what} 格式不对"),
            &format!("{what} has an invalid format"),
        ));
    }
    Ok(v.to_string())
}

pub fn https_host(url: &str, what: &str) -> Result<String, String> {
    let bad = || {
        kv_i18n::t(
            &format!("{what} 必须是 https URL"),
            &format!("{what} must be an https URL"),
        )
    };
    let u = url::Url::parse(url).map_err(|_| bad())?;
    if u.scheme() != "https" {
        return Err(bad());
    }
    let host = u.host_str().ok_or_else(bad)?;
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        return Err(bad());
    }
    Ok(match u.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    })
}

pub struct ImportedFile {
    pub content: String,
    pub path: String,
}

/// Ask the user to confirm before importing a secret from a file: this prevents an agent from
/// using this tool to read an arbitrary user file (e.g. ~/.ssh/id_ed25519) and store it as a
/// readable credential, bypassing the client's file-access restrictions on the agent.
pub async fn import_file(p: &str, label: &str) -> Result<ImportedFile, String> {
    let abs = resolve_secret_file(p)?;
    let abs_str = abs.display().to_string();
    if abs_str
        .chars()
        .any(|c| matches!(c, '\u{0000}'..='\u{001f}' | '\u{007f}'))
        || abs_str.len() > 500
    {
        return Err(kv_i18n::t(
            "文件路径包含非法字符",
            "File path contains invalid characters",
        ));
    }
    let message = kv_i18n::t(&format!("AI agent 请求从以下文件导入秘密：\n\n{abs_str}\n\n保存为凭证：{label}"), &format!("An AI agent wants to import a secret from this file:\n\n{abs_str}\n\nSave as credential: {label}"));
    if !confirm(&message, &kv_i18n::t("允许导入", "Allow import")).await {
        return Err(kv_i18n::t(
            "用户拒绝了文件导入。",
            "The user declined the file import.",
        ));
    }
    let content = read_secret_file(&abs)?;
    Ok(ImportedFile {
        content,
        path: abs_str,
    })
}

/// Ask for confirmation again before deleting the original file after import (separate from the
/// import confirmation): deletion is irreversible, so the user must see the exact path before
/// agreeing.
pub async fn confirm_delete_source_file(abs: &str) -> bool {
    let message = kv_i18n::t(&format!("AI agent 请求删除刚刚导入的原文件：\n\n{abs}\n\n此操作不可恢复。"), &format!("An AI agent wants to delete the original file it just imported from:\n\n{abs}\n\nThis cannot be undone."));
    if !confirm(&message, &kv_i18n::t("确认删除", "Delete")).await {
        return false;
    }
    std::fs::remove_file(abs).is_ok()
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct CredentialInfo {
    pub r#type: String,
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub config: Option<Map<String, Value>>,
}

pub async fn try_info(
    s: &Requester<'_>,
    ty: &str,
    name: &str,
) -> Result<Option<CredentialInfo>, SessionError> {
    let mut p = Map::new();
    p.insert("type".into(), Value::String(ty.to_string()));
    p.insert("name".into(), Value::String(name.to_string()));
    let exists: bool = s.request("exists", p.clone()).await?;
    if !exists {
        return Ok(None);
    }
    Ok(Some(s.request("info", p).await?))
}

/// When only `name` is given, look up the type by name among credentials of the given kinds.
/// Returns it if exactly one match is found; otherwise errors, asking the caller to specify type.
pub async fn resolve_type(
    s: &Requester<'_>,
    name: &str,
    ty: Option<&str>,
    kinds: &[&str],
) -> Result<String, SessionError> {
    if let Some(t) = ty {
        return Ok(t.to_string());
    }
    #[derive(serde::Deserialize)]
    struct Entry {
        r#type: String,
        name: String,
        kind: String,
    }
    let all: Vec<Entry> = s.request("list", Map::new()).await?;
    let want = norm(name);
    let hits: Vec<&Entry> = all
        .iter()
        .filter(|c| c.name == want && kinds.contains(&c.kind.as_str()))
        .collect();
    match hits.as_slice() {
        [one] => Ok(one.r#type.clone()),
        [] => Err(SessionError(kv_i18n::t(
            &format!("找不到名为 \"{want}\" 的 {} 凭证", kinds.join("/")),
            &format!("No {} credential named \"{want}\" found", kinds.join("/")),
        ))),
        many => {
            let types: Vec<&str> = many.iter().map(|h| h.r#type.as_str()).collect();
            Err(SessionError(kv_i18n::t(
                &format!(
                    "有多个名为 \"{want}\" 的凭证（{}），请指定 type",
                    types.join("、")
                ),
                &format!(
                    "Multiple credentials are named \"{want}\" ({}); please specify type",
                    types.join(", ")
                ),
            )))
        }
    }
}

/// If it already exists: errors unless `overwrite` is set. Returns whether it already existed.
/// The overwrite confirmation dialog is shown by the root helper at write time (the server does
/// not show it again).
pub async fn guard_overwrite(
    s: &Requester<'_>,
    ty: &str,
    name: &str,
    overwrite: Option<bool>,
) -> Result<bool, SessionError> {
    let mut p = Map::new();
    p.insert("type".into(), Value::String(ty.to_string()));
    p.insert("name".into(), Value::String(name.to_string()));
    let exists: bool = s.request("exists", p).await?;
    if !exists {
        return Ok(false);
    }
    if overwrite != Some(true) {
        return Err(SessionError(kv_i18n::t(
            &format!("凭证 \"{}/{}\" 已存在。如需替换，请设置 overwrite=true（会弹窗请用户确认）。", norm(ty), norm(name)),
            &format!("Credential \"{}/{}\" already exists. To replace it, set overwrite=true (the user will be asked to confirm).", norm(ty), norm(name)),
        )));
    }
    Ok(true)
}

#[allow(dead_code)]
pub type Session = HelperSession;
