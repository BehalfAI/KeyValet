//! Request dispatch: routes one `Request` to a `kv_vault::Vault` operation, enforcing purpose/grant
//! requirements and writing the audit log. Direct port of src/helper/dispatch.ts.

use crate::auth_gate::touch_id_gate;
use crate::settings::{
    is_loosening, parse_mode, read_settings, remember_active, remember_until, stricter,
    write_settings, GrantMode, Settings, GRANT_MODES,
};
use kv_ipc::{clean_purpose, Op, Response};
use kv_platform::{Authenticator, Confirmer};
use kv_protocols::{aws, oauth2, totp};
use kv_proxy::{gateway::Gateway, manage, proxy};
use kv_vault::{
    normalize_name, normalize_type, CredentialRecord, Kind, SetParams, Vault, VaultError,
};
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

/// The full "raise Touch ID and get an answer" capability, as injected into a `SessionAuth`. This is
/// deliberately a *separate*, simpler seam than `Authenticator` (the raw biometric prompt): in
/// production, `TouchIdSessionGate` composes this out of `touch_id_gate` (cooldown/lock bookkeeping)
/// plus a real `Authenticator`; tests can instead supply a bare fake with no cooldown at all, which is
/// what src/test/grants.test.ts's `auth.authorize` fixture does (cooldown behavior itself is already
/// covered directly by auth_gate.rs's own tests, independent of grant-mode logic).
pub trait AuthorizeGate {
    fn authorize(
        &self,
        reason: &str,
    ) -> impl std::future::Future<Output = Result<(), String>> + Send;
}

/// The production `AuthorizeGate`: wraps `touch_id_gate` (cooldown/lock) around a real `Authenticator`.
pub struct TouchIdSessionGate<A> {
    pub vault_dir: PathBuf,
    pub authenticator: A,
    pub deny_label: String,
}
impl<A: Authenticator + Sync> AuthorizeGate for TouchIdSessionGate<A> {
    async fn authorize(&self, reason: &str) -> Result<(), String> {
        touch_id_gate(
            &self.vault_dir,
            reason,
            &self.deny_label,
            &self.authenticator,
        )
        .await
    }
}

pub type JsonMap = Map<String, Value>;

fn get_str(p: &JsonMap, key: &str) -> Option<String> {
    p.get(key).and_then(Value::as_str).map(str::to_string)
}
fn get_bool(p: &JsonMap, key: &str) -> bool {
    p.get(key).and_then(Value::as_bool).unwrap_or(false)
}
fn get_f64(p: &JsonMap, key: &str) -> Option<f64> {
    p.get(key).and_then(Value::as_f64)
}
fn get_str_map(p: &JsonMap, key: &str) -> Option<std::collections::HashMap<String, String>> {
    let obj = p.get(key)?.as_object()?;
    Some(
        obj.iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect(),
    )
}
fn clip(s: &str) -> String {
    s.chars().take(200).collect()
}

/// Request/response context supplied by the caller (the MCP server, in production): who's asking,
/// from where. Embedded into the audit log verbatim (as `client`), alongside `session` at top level,
/// matching the TS shape exactly (redundant but intentional -- see dispatch.ts).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ClientContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// Random ID of the MCP server process (i.e. one agent session).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

pub fn cred_key(ty: &str, name: &str) -> kv_vault::Result<String> {
    Ok(format!("{}/{}", normalize_type(ty)?, normalize_name(name)?))
}

/// Handshake credential hint -> credential key (only recognizes existing credentials; when only
/// `name` is given, matches uniquely by name across all types).
pub fn resolve_hint(vault: &Vault, hint: Option<&kv_ipc::CredentialHint>) -> Option<String> {
    let hint = hint?;
    if let Some(ty) = &hint.r#type {
        return vault
            .exists(ty, &hint.name)
            .ok()
            .filter(|&e| e)
            .and_then(|_| cred_key(ty, &hint.name).ok());
    }
    let name = normalize_name(&hint.name).ok()?;
    let hits: Vec<_> = vault
        .list(None)
        .ok()?
        .into_iter()
        .filter(|c| c.name == name)
        .collect();
    match hits.as_slice() {
        [one] => Some(format!("{}/{}", one.r#type, one.name)),
        _ => None,
    }
}

/// The session's authorization state (never written to the audit log).
pub struct SessionAuth<G> {
    pub grant_all: bool,
    pub grants: HashSet<String>,
    /// The grant mode in effect for this session (the stricter of the global setting and the client
    /// request); `None` means per_credential.
    pub mode: Option<GrantMode>,
    /// The mode requested by the client (can only tighten it); used to recompute after a settings change.
    pub requested: Option<GrantMode>,
    /// per_use mode: a single-use grant that has been authenticated but not yet used.
    pub one_shot: Option<HashSet<String>>,
    /// This session's local gateway. `None` in every test and in the root CLI; the main helper
    /// program sets it once, right after authentication succeeds (mirrors TS's `auth.gateway`).
    pub gateway: Option<Arc<Gateway>>,
    gate: G,
}

/// A snapshot of the fields `settings_view`/audit need, taken by value so it doesn't borrow
/// `SessionAuth` for longer than a single statement.
struct AuthSnapshot {
    mode: Option<GrantMode>,
    requested: Option<GrantMode>,
    grant_all: bool,
    grants: Vec<String>,
}

impl<G: AuthorizeGate> SessionAuth<G> {
    pub fn new(gate: G) -> Self {
        Self {
            grant_all: false,
            grants: HashSet::new(),
            mode: None,
            requested: None,
            one_shot: None,
            gateway: None,
            gate,
        }
    }

    /// Raises Touch ID for `reason` (cooldown/lock bookkeeping, if any, is the gate's responsibility).
    pub async fn authorize(&self, reason: &str) -> Result<(), String> {
        self.gate.authorize(reason).await
    }

    /// Updates the current session's authorization state per settings (takes effect immediately
    /// after a settings change).
    pub fn apply_mode(&mut self, s: &Settings) {
        self.mode = Some(stricter(s.grant_mode, self.requested));
        match self.mode {
            Some(GrantMode::PerUse) => {
                self.grant_all = false;
                self.grants.clear();
                self.one_shot = Some(HashSet::new());
            }
            Some(GrantMode::PerCredential) => {
                self.grant_all = false;
            }
            _ => {
                self.grant_all = true; // per_session / remember: all credentials can be used this session
            }
        }
    }

    fn snapshot(&self) -> AuthSnapshot {
        let mut grants: Vec<String> = self.grants.iter().cloned().collect();
        grants.sort();
        AuthSnapshot {
            mode: self.mode,
            requested: self.requested,
            grant_all: self.grant_all,
            grants,
        }
    }

    /// `true` if `key` may be used right now under this session's mode, consuming a one-shot grant
    /// if that's what applies. Mirrors the `GRANT_REQUIRED_OPS` check in TS's `dispatch()`.
    fn consume_grant(&mut self, key: &str) -> bool {
        if self.mode == Some(GrantMode::PerUse) {
            self.one_shot.get_or_insert_with(HashSet::new).remove(key)
        } else {
            self.grant_all || self.grants.contains(key)
        }
    }
}

async fn grant_credential<G: AuthorizeGate>(
    vault: &Vault,
    p: &JsonMap,
    ctx: &ClientContext,
    auth: &mut SessionAuth<G>,
) -> kv_vault::Result<Value> {
    let (ty, name, _) = vault.get_record(
        &get_str(p, "type").unwrap_or_default(),
        &get_str(p, "name").unwrap_or_default(),
    )?;
    let key = format!("{ty}/{name}");
    let per_use = auth.mode == Some(GrantMode::PerUse);
    if !per_use && (auth.grant_all || auth.grants.contains(&key)) {
        return Ok(json!({"granted": key, "already": true}));
    }
    let purpose = clean_purpose(get_str(p, "purpose").as_deref()).unwrap_or_default();
    let where_ = kv_i18n::t(
        &format!(
            "目的：{purpose}\n来源目录（agent 提供）：{}",
            ctx.cwd.as_deref().unwrap_or("未知")
        ),
        &format!(
            "Purpose: {purpose}\nWorking directory (reported by agent): {}",
            ctx.cwd.as_deref().unwrap_or("unknown")
        ),
    );
    let reason = if per_use {
        kv_i18n::t(
            &format!("授权本次使用凭证（仅此一次）：{key}\n{where_}"),
            &format!("Authorize a single use of credential: {key}\n{where_}"),
        )
    } else {
        kv_i18n::t(
            &format!("授权本次 AI 会话使用凭证：{key}\n{where_}"),
            &format!("Authorize this AI session to use credential: {key}\n{where_}"),
        )
    };
    auth.authorize(&reason).await.map_err(VaultError)?;
    if per_use {
        auth.one_shot
            .get_or_insert_with(HashSet::new)
            .insert(key.clone());
    } else {
        auth.grants.insert(key.clone());
    }
    Ok(json!({"granted": key, "already": false, "single_use": per_use}))
}

fn settings_view(s: &Settings, auth: Option<&AuthSnapshot>) -> Value {
    let now = now_ms();
    let remembered_until = if remember_active(s, now) {
        match s.remember_until {
            Some(u) if u == crate::settings::MAX_SAFE_INTEGER => json!("forever"),
            Some(u) => json!(chrono::DateTime::<chrono::Utc>::from(
                std::time::UNIX_EPOCH + std::time::Duration::from_millis(u as u64)
            )
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
            None => Value::Null,
        }
    } else {
        Value::Null
    };
    json!({
        "grant_mode": s.grant_mode.as_str(),
        "remember_hours": s.remember_hours,
        "remembered_until": remembered_until,
        "session": auth.map(|a| json!({
            "effective_mode": a.mode.unwrap_or(GrantMode::PerCredential).as_str(),
            "requested_mode": a.requested.map(|m| m.as_str()),
            "grants_all": a.grant_all,
            "granted": a.grants,
        })),
    })
}

fn describe_settings(s: &Settings) -> String {
    let hours = if s.remember_hours == 0.0 {
        kv_i18n::t("永久", "forever")
    } else {
        kv_i18n::t(
            &format!("{} 小时", s.remember_hours),
            &format!("{} hours", s.remember_hours),
        )
    };
    match s.grant_mode {
        GrantMode::PerUse => kv_i18n::t(
            "每次使用凭证都要 Touch ID",
            "Touch ID for every use of a credential",
        ),
        GrantMode::PerCredential => kv_i18n::t(
            "每个会话中，每个凭证按一次 Touch ID",
            "Touch ID once per credential per session",
        ),
        GrantMode::PerSession => kv_i18n::t(
            "每个会话按一次 Touch ID，之后可使用全部凭证",
            "Touch ID once per session, then all credentials",
        ),
        GrantMode::Remember => kv_i18n::t(
            &format!("按一次 Touch ID，{hours}内所有会话都不再需要认证"),
            &format!("Touch ID once, then no authentication for any session for {hours}"),
        ),
    }
}

fn now_ms() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as f64
}

/// Views/modifies authorization settings. Loosening (a looser mode, a longer remember duration)
/// must be confirmed by the user via Touch ID -- a fingerprint can't be forged by a script, whereas
/// a confirmation dialog could be clicked by a script if the terminal has "Accessibility" permission.
/// Tightening takes effect immediately without authentication.
async fn settings_op<G: AuthorizeGate, C: Confirmer>(
    vault: &Vault,
    p: &JsonMap,
    mut auth: Option<&mut SessionAuth<G>>,
    confirmer: &C,
) -> kv_vault::Result<Value> {
    let current = read_settings(&vault.dir);
    if get_bool(p, "forget") {
        let next = Settings {
            grant_mode: current.grant_mode,
            remember_hours: current.remember_hours,
            remember_until: None,
        };
        write_settings(&vault.dir, &next)?;
        if let Some(a) = auth.as_deref_mut() {
            a.apply_mode(&next);
        }
        let mut v = settings_view(&next, auth.as_deref().map(SessionAuth::snapshot).as_ref());
        merge_note(
            &mut v,
            kv_i18n::t(
                "已清除\u{201c}记住\u{201d}状态",
                "Cleared the remembered authorization",
            ),
        );
        return Ok(v);
    }
    if p.get("grant_mode").is_none() && p.get("remember_hours").is_none() {
        return Ok(settings_view(
            &current,
            auth.as_deref().map(SessionAuth::snapshot).as_ref(),
        ));
    }

    let mode = match get_str(p, "grant_mode") {
        None => Some(current.grant_mode),
        Some(v) => parse_mode(&v),
    };
    let Some(mode) = mode else {
        let names = GRANT_MODES
            .iter()
            .map(GrantMode::as_str)
            .collect::<Vec<_>>()
            .join(" / ");
        return Err(VaultError(kv_i18n::t(
            &format!("grant_mode 只能是 {names}"),
            &format!("grant_mode must be one of {names}"),
        )));
    };
    let mut hours = current.remember_hours;
    if let Some(h) = get_f64(p, "remember_hours") {
        if !h.is_finite() || !(0.0..=8760.0).contains(&h) {
            return Err(VaultError(kv_i18n::t(
                "remember_hours 必须在 0~8760 之间（0 表示永久）",
                "remember_hours must be between 0 and 8760 (0 = forever)",
            )));
        }
        hours = h;
    }
    let mut next = Settings {
        grant_mode: mode,
        remember_hours: hours,
        remember_until: None,
    };
    if mode == GrantMode::Remember && remember_active(&current, now_ms()) {
        next.remember_until = current.remember_until;
    }

    if is_loosening(&current, &next) {
        let purpose = clean_purpose(get_str(p, "purpose").as_deref()).unwrap_or_default();
        let truncated = clip(&purpose);
        let msg = kv_i18n::t(
            &format!(
                "修改 KeyValet 授权设置为：{}\n目的：{truncated}",
                describe_settings(&next)
            ),
            &format!(
                "Change KeyValet authorization to: {}\nPurpose: {truncated}",
                describe_settings(&next)
            ),
        );
        let approved = match auth.as_deref() {
            Some(a) => a.authorize(&msg).await.is_ok(),
            None => {
                confirmer
                    .confirm(&msg, &kv_i18n::t("允许修改", "Allow Change"))
                    .await
            }
        };
        if !approved {
            return Err(VaultError(kv_i18n::t(
                "用户拒绝了该修改",
                "The user denied this change",
            )));
        }
        if mode == GrantMode::Remember {
            next.remember_until = Some(remember_until(hours, now_ms())); // this Touch ID starts the remember period
        }
    } else if let Some(u) = next.remember_until {
        next.remember_until = Some(u.min(remember_until(hours, now_ms()))); // shortening the duration also shortens the current window
    }
    write_settings(&vault.dir, &next)?;
    if let Some(a) = auth.as_deref_mut() {
        a.apply_mode(&next);
    }
    let mut v = settings_view(&next, auth.as_deref().map(SessionAuth::snapshot).as_ref());
    merge_note(
        &mut v,
        kv_i18n::t(
            "已生效（包括当前会话）",
            "In effect now, including this session",
        ),
    );
    Ok(v)
}

fn merge_note(v: &mut Value, note: String) {
    v.as_object_mut()
        .unwrap()
        .insert("note".to_string(), Value::String(note));
}

pub fn http_summary(h: &kv_vault::HttpConfig) -> Value {
    let inject = match &h.inject {
        Some(r) => {
            let mut v: Vec<String> = Vec::new();
            if let Some(headers) = &r.headers {
                v.extend(headers.keys().map(|k| format!("header:{k}")));
            }
            if let Some(query) = &r.query {
                v.extend(query.keys().map(|k| format!("query:{k}")));
            }
            if r.basic.is_some() {
                v.push("basic".to_string());
            }
            json!(v)
        }
        None => json!(["Authorization: Bearer <access token>"]),
    };
    json!({"allowed_hosts": h.allowed_hosts, "proxy_only": h.proxy_only, "inject": inject, "can_test": h.test.is_some()})
}

fn info(vault: &Vault, p: &JsonMap) -> kv_vault::Result<Value> {
    let (ty, name, record) = vault.get_record(
        &get_str(p, "type").unwrap_or_default(),
        &get_str(p, "name").unwrap_or_default(),
    )?;
    if record.kind_or_static() != Kind::Static {
        // Full protocol metadata (publicView in TS) lands with kv-protocols; a minimal, honest subset for now.
        let mut v = json!({"type": ty, "name": name, "kind": record.kind_or_static(), "description": record.description, "updatedAt": record.updated_at});
        if let Some(http) = &record.http {
            v.as_object_mut()
                .unwrap()
                .insert("http".to_string(), http_summary(http));
        }
        return Ok(v);
    }
    let mut v = json!({
        "type": ty, "name": name, "kind": "static",
        "description": record.description, "attributes": record.attributes,
        "secret_fields": record.secrets.as_ref().map(|s| s.keys().cloned().collect::<Vec<_>>()).unwrap_or_else(|| vec!["value".to_string()]),
        "updatedAt": record.updated_at,
    });
    if let Some(t) = &record.template {
        v.as_object_mut()
            .unwrap()
            .insert("template".to_string(), json!(t));
    }
    if let Some(h) = &record.http {
        v.as_object_mut()
            .unwrap()
            .insert("http".to_string(), http_summary(h));
    }
    Ok(v)
}

/// Before overwriting/deleting an existing credential, the helper itself raises a confirmation
/// dialog (independent of the MCP server), preventing a user's credential from being silently
/// replaced or deleted when the server is bypassed and the helper is driven directly.
async fn confirm_destructive<C: Confirmer>(
    vault: &Vault,
    p: &JsonMap,
    overwrite: bool,
    confirmer: &C,
) -> kv_vault::Result<()> {
    let ty = get_str(p, "type").unwrap_or_default();
    let name = get_str(p, "name").unwrap_or_default();
    if !vault.exists(&ty, &name).unwrap_or(false) {
        return Ok(());
    }
    let label = format!(
        "{}/{}",
        ty.trim().to_lowercase(),
        name.trim().to_lowercase()
    );
    let purpose = clean_purpose(get_str(p, "purpose").as_deref()).unwrap_or_default();
    let truncated = clip(&purpose);
    let tail = if overwrite {
        kv_i18n::t(
            "旧的值和配置将被永久替换。",
            "The existing value and configuration will be permanently replaced.",
        )
    } else {
        kv_i18n::t("此操作不可恢复。", "This cannot be undone.")
    };
    let (action_zh, action_en) = if overwrite {
        ("覆盖", "overwrite")
    } else {
        ("删除", "delete")
    };
    let message = kv_i18n::t(
        &format!("AI 会话请求{action_zh}凭证：\n\n{label}\n\n{tail}\n目的：{truncated}"),
        &format!("An AI session is requesting to {action_en} a credential:\n\n{label}\n\n{tail}\nPurpose: {truncated}"),
    );
    let ok_label = kv_i18n::t(
        &format!("确认{action_zh}"),
        if overwrite { "Overwrite" } else { "Delete" },
    );
    if !confirmer.confirm(&message, &ok_label).await {
        return Err(VaultError(kv_i18n::t(
            &format!("用户拒绝了{action_zh}操作"),
            &format!("The user denied the {action_en} operation"),
        )));
    }
    Ok(())
}

fn field_key_ok(k: &str) -> bool {
    !k.is_empty()
        && k.len() <= 64
        && k.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// The multiple secret fields of a template credential.
fn check_secrets(
    p: &JsonMap,
) -> kv_vault::Result<Option<std::collections::HashMap<String, String>>> {
    let Some(v) = p.get("secrets") else {
        return Ok(None);
    };
    let Some(obj) = v.as_object() else {
        return Err(VaultError(kv_i18n::t(
            "secrets 必须是对象",
            "secrets must be an object",
        )));
    };
    if obj.len() > 30 {
        return Err(VaultError(kv_i18n::t(
            "secrets 最多 30 项",
            "secrets may have at most 30 entries",
        )));
    }
    let mut out = std::collections::HashMap::new();
    for (k, x) in obj {
        if !field_key_ok(k) {
            return Err(VaultError(kv_i18n::t(
                &format!("非法的字段名 \"{k}\""),
                &format!("Invalid field name \"{k}\""),
            )));
        }
        let bad_value = || {
            VaultError(kv_i18n::t(
                &format!("秘密字段 {k} 必须是 1~65536 字符的字符串"),
                &format!("Secret field {k} must be a string of 1-65536 characters"),
            ))
        };
        let s = x.as_str().ok_or_else(bad_value)?;
        if s.is_empty() || s.encode_utf16().count() > 64 * 1024 {
            return Err(bad_value());
        }
        out.insert(k.clone(), s.to_string());
    }
    Ok(if out.is_empty() { None } else { Some(out) })
}

/// Writes a static credential. When a template is given, also writes multiple secret fields and
/// the proxy configuration (the secrets of a new credential were just entered by the user, so the
/// domains need no further confirmation -- this is the implicit-consent path; see
/// `kv_proxy::manage::configure_http` for the explicit, confirmation-gated path used afterwards).
fn set_static(vault: &Vault, p: &JsonMap) -> kv_vault::Result<Value> {
    let ty = get_str(p, "type").unwrap_or_default();
    let name = get_str(p, "name").unwrap_or_default();
    let secrets = check_secrets(p)?;
    let value = get_str(p, "value");
    let http = match p.get("http") {
        None | Some(Value::Null) => None,
        Some(raw) => {
            let given = get_str_map(p, "attributes").unwrap_or_default();
            let attributes = if !given.is_empty() || !vault.exists(&ty, &name).unwrap_or(false) {
                given
            } else {
                vault.get_record(&ty, &name)?.2.attributes
            };
            let synthetic = CredentialRecord {
                kind: Some(Kind::Static),
                value: value.clone().unwrap_or_default(),
                secrets: secrets.clone(),
                attributes,
                ..Default::default()
            };
            Some(kv_proxy::config::validate_http_config(
                raw,
                &synthetic,
                kv_proxy::config::ValidateOpts {
                    allow_secrets_in_test: true,
                    prev_test: None,
                },
            )?)
        }
    };
    let template = get_str(p, "template").filter(|t| {
        t.len() <= 100
            && t.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    });
    let r = vault.set(SetParams {
        r#type: ty,
        name,
        value,
        secrets,
        http,
        template,
        description: get_str(p, "description"),
        attributes: get_str_map(p, "attributes"),
        type_description: get_str(p, "type_description"),
        overwrite: get_bool(p, "overwrite"),
    })?;
    Ok(serde_json::to_value(r).unwrap())
}

fn parse_kind(s: &str) -> Option<Kind> {
    match s {
        "oauth2" => Some(Kind::Oauth2),
        "google_service_account" => Some(Kind::GoogleServiceAccount),
        "github_app" => Some(Kind::GithubApp),
        "jwt" => Some(Kind::Jwt),
        "totp" => Some(Kind::Totp),
        "aws" => Some(Kind::Aws),
        _ => None,
    }
}

fn setup_protocol_op(vault: &Vault, p: &JsonMap) -> kv_vault::Result<Value> {
    let kind_str = get_str(p, "kind").unwrap_or_default();
    let Some(kind) = parse_kind(&kind_str) else {
        return Err(VaultError(kv_i18n::t(
            &format!("未知的协议种类 {kind_str}"),
            &format!("Unknown protocol kind {kind_str}"),
        )));
    };
    let r = kv_protocols::index::setup_protocol(
        vault,
        kv_protocols::index::SetupProtocolParams {
            r#type: get_str(p, "type").unwrap_or_default(),
            name: get_str(p, "name").unwrap_or_default(),
            kind,
            config: p.get("config").cloned().unwrap_or(Value::Null),
            secrets: p.get("secrets").cloned().unwrap_or(Value::Null),
            description: get_str(p, "description"),
            type_description: get_str(p, "type_description"),
            overwrite: get_bool(p, "overwrite"),
            reuse_client_secret: get_bool(p, "reuseClientSecret"),
        },
    )?;
    Ok(serde_json::to_value(r).unwrap())
}

fn str_array(p: &JsonMap, key: &str) -> Vec<String> {
    p.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

async fn access_token_op(vault: &Vault, p: &JsonMap) -> kv_vault::Result<Value> {
    let ty = get_str(p, "type").unwrap_or_default();
    let name = get_str(p, "name").unwrap_or_default();
    kv_protocols::index::access_token(
        vault,
        &ty,
        &name,
        kv_protocols::index::AccessTokenParams {
            scopes: str_array(p, "scopes"),
            repositories: str_array(p, "repositories"),
            permissions: p.get("permissions").cloned(),
            force: get_bool(p, "force"),
            via_proxy: false, // set only internally by the proxy layer, never from an external request
        },
    )
    .await
}

fn totp_op(vault: &Vault, p: &JsonMap) -> kv_vault::Result<Value> {
    let r = totp::totp_code(
        vault,
        &get_str(p, "type").unwrap_or_default(),
        &get_str(p, "name").unwrap_or_default(),
    )?;
    Ok(serde_json::to_value(r).unwrap())
}

async fn aws_op(vault: &Vault, p: &JsonMap) -> kv_vault::Result<Value> {
    let r = aws::aws_credentials(
        vault,
        &get_str(p, "type").unwrap_or_default(),
        &get_str(p, "name").unwrap_or_default(),
        get_f64(p, "duration_seconds").map(|d| d as i64),
        get_bool(p, "force"),
    )
    .await?;
    Ok(serde_json::to_value(r).unwrap())
}

async fn oauth_exchange_op(vault: &Vault, p: &JsonMap) -> kv_vault::Result<Value> {
    oauth2::exchange_code(
        vault,
        &get_str(p, "type").unwrap_or_default(),
        &get_str(p, "name").unwrap_or_default(),
        &get_str(p, "code").unwrap_or_default(),
        &get_str(p, "code_verifier").unwrap_or_default(),
        p.get("redirect_uri").unwrap_or(&Value::Null),
    )
    .await
}

async fn oauth_device_start_op(vault: &Vault, p: &JsonMap) -> kv_vault::Result<Value> {
    let r = oauth2::device_start(
        vault,
        &get_str(p, "type").unwrap_or_default(),
        &get_str(p, "name").unwrap_or_default(),
    )
    .await?;
    Ok(serde_json::to_value(r).unwrap())
}

async fn oauth_device_poll_op(vault: &Vault, p: &JsonMap) -> kv_vault::Result<Value> {
    let r = oauth2::device_poll(
        vault,
        &get_str(p, "type").unwrap_or_default(),
        &get_str(p, "name").unwrap_or_default(),
        &get_str(p, "device_code").unwrap_or_default(),
    )
    .await?;
    Ok(serde_json::to_value(r).unwrap())
}

async fn http_configure_op<C: Confirmer>(
    vault: &Vault,
    p: &JsonMap,
    confirmer: &C,
) -> kv_vault::Result<Value> {
    let ty = get_str(p, "type").unwrap_or_default();
    let name = get_str(p, "name").unwrap_or_default();
    let purpose = clean_purpose(get_str(p, "purpose").as_deref()).unwrap_or_default();
    manage::configure_http(
        vault,
        manage::ConfigureHttpParams {
            r#type: &ty,
            name: &name,
            purpose: &purpose,
            remove: get_bool(p, "remove"),
            inject: p.get("inject"),
            allowed_hosts: p.get("allowed_hosts"),
            proxy_only: p.get("proxy_only").and_then(Value::as_bool),
            test: p.get("test"),
        },
        confirmer,
    )
    .await
}

async fn http_request_op(vault: &Vault, p: &JsonMap) -> kv_vault::Result<Value> {
    let ty = get_str(p, "type").unwrap_or_default();
    let name = get_str(p, "name").unwrap_or_default();
    let r = proxy::proxy_request(
        vault,
        &ty,
        &name,
        proxy::ProxyInput {
            method: get_str(p, "method"),
            url: get_str(p, "url").unwrap_or_default(),
            headers: get_str_map(p, "headers").unwrap_or_default(),
            query: get_str_map(p, "query").unwrap_or_default(),
            body: p.get("body").cloned(),
        },
    )
    .await?;
    Ok(serde_json::to_value(r).unwrap())
}

async fn http_test_op(vault: &Vault, p: &JsonMap) -> kv_vault::Result<Value> {
    let r = proxy::test_credential(
        vault,
        &get_str(p, "type").unwrap_or_default(),
        &get_str(p, "name").unwrap_or_default(),
    )
    .await?;
    Ok(serde_json::to_value(r).unwrap())
}

async fn gateway_open_op<G: AuthorizeGate>(
    vault: &Vault,
    p: &JsonMap,
    auth: Option<&SessionAuth<G>>,
) -> kv_vault::Result<Value> {
    let (ty, name, record) = vault.get_record(
        &get_str(p, "type").unwrap_or_default(),
        &get_str(p, "name").unwrap_or_default(),
    )?;
    let Some(http) = &record.http else {
        return Err(VaultError::new(
            &format!("\"{ty}/{name}\" 没有配置代理调用，请先用 credential_configure_http 设置允许的域名"),
            &format!("\"{ty}/{name}\" has no proxy configuration; set the allowed hosts with credential_configure_http first"),
        ));
    };
    let gateway = auth.and_then(|a| a.gateway.clone()).ok_or_else(|| {
        VaultError::new(
            "本会话未启用网关",
            "The gateway is not available in this session",
        )
    })?;
    let purpose = clean_purpose(get_str(p, "purpose").as_deref());
    let g = gateway
        .open(&ty, &name, purpose.as_deref())
        .await
        .map_err(|e| {
            VaultError::new(
                &format!("网关启动失败：{e}"),
                &format!("Failed to start the gateway: {e}"),
            )
        })?;
    // The token is handed to the MCP server to write into a user-readable-only env file; it is
    // never put in the URL or returned to the agent.
    let base_urls: Map<String, Value> = http
        .allowed_hosts
        .iter()
        .filter(|h| !h.starts_with("*."))
        .map(|h| (h.clone(), json!(format!("{}/{h}", g.base))))
        .collect();
    Ok(json!({
        "type": ty, "name": name, "base": g.base, "token": g.token,
        "template": record.template, "allowed_hosts": http.allowed_hosts, "base_urls": base_urls,
    }))
}

async fn run<G: AuthorizeGate, C: Confirmer>(
    vault: &Vault,
    op: Op,
    p: &JsonMap,
    ctx: &ClientContext,
    mut auth: Option<&mut SessionAuth<G>>,
    confirmer: &C,
) -> kv_vault::Result<Value> {
    match op {
        Op::ListTypes => Ok(serde_json::to_value(vault.list_types()).unwrap()),
        Op::CreateType => Ok(serde_json::to_value(vault.create_type(
            &get_str(p, "name").unwrap_or_default(),
            get_str(p, "description").as_deref(),
        )?)
        .unwrap()),
        Op::DeleteType => {
            Ok(json!({"name": vault.delete_type(&get_str(p, "name").unwrap_or_default())?}))
        }
        Op::List => Ok(serde_json::to_value(vault.list(get_str(p, "type").as_deref())?).unwrap()),
        Op::Exists => Ok(json!(vault.exists(
            &get_str(p, "type").unwrap_or_default(),
            &get_str(p, "name").unwrap_or_default()
        )?)),
        Op::Info => info(vault, p),
        Op::Get => {
            let (_, _, record) = vault.get_record(
                &get_str(p, "type").unwrap_or_default(),
                &get_str(p, "name").unwrap_or_default(),
            )?;
            if record.kind_or_static() == Kind::Static {
                Ok(serde_json::to_value(vault.get(
                    &get_str(p, "type").unwrap_or_default(),
                    &get_str(p, "name").unwrap_or_default(),
                )?)
                .unwrap())
            } else {
                info(vault, p)
            }
        }
        Op::Set => {
            if get_bool(p, "overwrite") {
                confirm_destructive(vault, p, true, confirmer).await?;
            }
            set_static(vault, p)
        }
        Op::Delete => {
            confirm_destructive(vault, p, false, confirmer).await?;
            let (ty, name) = vault.delete(
                &get_str(p, "type").unwrap_or_default(),
                &get_str(p, "name").unwrap_or_default(),
            )?;
            Ok(json!({"type": ty, "name": name}))
        }
        Op::Grant => match auth.as_deref_mut() {
            None => Ok(
                json!({"granted": cred_key(&get_str(p, "type").unwrap_or_default(), &get_str(p, "name").unwrap_or_default())?, "already": true}),
            ),
            Some(a) => grant_credential(vault, p, ctx, a).await,
        },
        Op::Settings => settings_op(vault, p, auth, confirmer).await,
        Op::SessionInfo => Ok(settings_view(
            &read_settings(&vault.dir),
            auth.as_deref().map(SessionAuth::snapshot).as_ref(),
        )),
        Op::AuditQuery => Ok(audit_query(vault, p, ctx)),
        Op::SetupProtocol => {
            if get_bool(p, "overwrite") {
                confirm_destructive(vault, p, true, confirmer).await?;
            }
            setup_protocol_op(vault, p)
        }
        Op::OauthExchange => oauth_exchange_op(vault, p).await,
        Op::OauthDeviceStart => oauth_device_start_op(vault, p).await,
        Op::OauthDevicePoll => oauth_device_poll_op(vault, p).await,
        Op::AccessToken => access_token_op(vault, p).await,
        Op::Totp => totp_op(vault, p),
        Op::Aws => aws_op(vault, p).await,
        Op::HttpConfigure => http_configure_op(vault, p, confirmer).await,
        Op::HttpRequest => http_request_op(vault, p).await,
        Op::HttpTest => http_test_op(vault, p).await,
        Op::GatewayOpen => gateway_open_op(vault, p, auth.as_deref()).await,
    }
}

/// Audit log query: newest first; never contains any credential value (the log never has one to begin with).
fn audit_query(vault: &Vault, p: &JsonMap, ctx: &ClientContext) -> Value {
    let limit = get_f64(p, "limit")
        .map(|l| l as i64)
        .unwrap_or(50)
        .clamp(1, 500) as usize;
    let want = |k: &str| {
        get_str(p, k)
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
    };
    let ty = want("type");
    let name = want("name");
    let op = want("op");
    let session = if get_bool(p, "this_session") {
        ctx.session.clone()
    } else {
        want("session")
    };
    let since = get_str(p, "since")
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
        .map(|d| d.timestamp_millis());

    let mut out = Vec::new();
    let lines = vault.read_audit_tail(4 * 1024 * 1024);
    for line in lines.iter().rev() {
        if out.len() >= limit {
            break;
        }
        let Ok(e): Result<Value, _> = serde_json::from_str(line) else {
            continue;
        };
        let client = e.get("client").cloned().unwrap_or(Value::Null);
        let entry_session = e
            .get("session")
            .and_then(Value::as_str)
            .or_else(|| client.get("session").and_then(Value::as_str));
        if ty
            .as_deref()
            .is_some_and(|t| e.get("type").and_then(Value::as_str) != Some(t))
        {
            continue;
        }
        if name
            .as_deref()
            .is_some_and(|n| e.get("name").and_then(Value::as_str) != Some(n))
        {
            continue;
        }
        if op
            .as_deref()
            .is_some_and(|o| e.get("op").and_then(Value::as_str) != Some(o))
        {
            continue;
        }
        if session.as_deref().is_some_and(|s| entry_session != Some(s)) {
            continue;
        }
        if let Some(since) = since {
            let ts = e
                .get("ts")
                .and_then(Value::as_str)
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.timestamp_millis());
            if ts.is_none_or(|ts| ts < since) {
                continue;
            }
        }
        out.push(json!({
            "ts": e.get("ts").cloned().unwrap_or(Value::Null),
            "session": entry_session,
            "op": e.get("op").cloned().unwrap_or(Value::Null),
            "type": e.get("type").cloned().unwrap_or(Value::Null),
            "name": e.get("name").cloned().unwrap_or(Value::Null),
            "kind": e.get("kind").cloned().unwrap_or(Value::Null),
            "purpose": e.get("purpose").cloned().unwrap_or(Value::Null),
            "ok": e.get("ok").cloned().unwrap_or(Value::Null),
            "error": e.get("error").cloned().unwrap_or(Value::Null),
            "cwd": client.get("cwd").cloned().unwrap_or(Value::Null),
            "via": client.get("client").cloned().unwrap_or(Value::Null),
        }));
    }
    json!({"current_session": ctx.session, "count": out.len(), "entries": out})
}

const QUIET_OPS: [Op; 5] = [
    Op::Exists,
    Op::Info,
    Op::OauthDevicePoll,
    Op::AuditQuery,
    Op::SessionInfo,
];

/// Handles one request. The audit log records only the operation and its target, never a credential
/// value or secret.
///
/// `auth` mirrors TS's optional `SessionAuth`: omitted means full authorization is assumed (used
/// only for tests and the root CLI); the main helper program always passes in the session's state.
pub async fn dispatch<G: AuthorizeGate, C: Confirmer>(
    vault: &Vault,
    id: u64,
    op_str: &str,
    mut params: JsonMap,
    ctx: &ClientContext,
    mut auth: Option<&mut SessionAuth<G>>,
    confirmer: &C,
) -> Response {
    params.remove("viaProxy"); // a flag for the helper's internal use only; external requests must not carry it
    let is_type_op = op_str == "createType" || op_str == "deleteType";
    let purpose = clean_purpose(get_str(&params, "purpose").as_deref());

    let audit = |ok: bool, error: Option<&str>, quiet: bool| {
        if quiet && ok {
            return; // read-only metadata queries aren't logged, to avoid flooding the log (errors are always logged)
        }
        let type_field = if is_type_op {
            get_str(&params, "name")
        } else {
            get_str(&params, "type")
        }
        .map(|s| clip(&s).trim().to_lowercase());
        let name_field = if is_type_op {
            None
        } else {
            get_str(&params, "name").map(|s| clip(&s).trim().to_lowercase())
        };
        let mut entry = Map::new();
        entry.insert("op".to_string(), json!(op_str));
        entry.insert("type".to_string(), json!(type_field));
        entry.insert("name".to_string(), json!(name_field));
        entry.insert(
            "kind".to_string(),
            json!(get_str(&params, "kind").map(|s| clip(&s))),
        );
        entry.insert("purpose".to_string(), json!(purpose));
        entry.insert("session".to_string(), json!(ctx.session));
        entry.insert("client".to_string(), serde_json::to_value(ctx).unwrap());
        entry.insert("ok".to_string(), json!(ok));
        if let Some(e) = error {
            entry.insert("error".to_string(), json!(clip(e)));
        }
        let _ = vault.audit(entry); // a failure to write the audit log (e.g. disk full) must not crash the helper
    };

    let Some(op) = Op::parse(op_str) else {
        let message = kv_i18n::t(
            &format!("未知操作 {op_str}"),
            &format!("Unknown operation {op_str}"),
        );
        audit(false, Some(&message), true);
        return Response::err(id, message);
    };
    let quiet = QUIET_OPS.contains(&op)
        || (op == Op::Settings
            && params.get("grant_mode").is_none()
            && params.get("remember_hours").is_none()
            && !get_bool(&params, "forget"));

    if op.purpose_required() && purpose.is_none() {
        let message = kv_i18n::t(
            "必须说明本次操作的目的（purpose）",
            "A purpose is required for this operation",
        );
        audit(false, Some(&message), quiet);
        return Response::err(id, message);
    }
    if op.grant_required() {
        if let Some(a) = auth.as_deref_mut() {
            let key = match cred_key(
                &get_str(&params, "type").unwrap_or_default(),
                &get_str(&params, "name").unwrap_or_default(),
            ) {
                Ok(k) => k,
                Err(e) => {
                    audit(false, Some(&e.0), quiet);
                    return Response::err(id, e.0);
                }
            };
            if !a.consume_grant(&key) {
                let message = format!("{}{key}", kv_ipc::GRANT_REQUIRED_PREFIX);
                audit(false, Some(&message), quiet);
                return Response::err(id, message);
            }
        }
    }

    match run(vault, op, &params, ctx, auth.as_deref_mut(), confirmer).await {
        Ok(result) => {
            // A credential newly created/overwritten (and confirmed) this session: the secret was
            // just supplied by the user, so grant it automatically.
            if let Some(a) = auth {
                if a.mode != Some(GrantMode::PerUse) && matches!(op, Op::Set | Op::SetupProtocol) {
                    if let (Some(t), Some(n)) = (
                        result.get("type").and_then(Value::as_str),
                        result.get("name").and_then(Value::as_str),
                    ) {
                        a.grants.insert(format!("{t}/{n}"));
                    }
                }
            }
            audit(true, None, quiet);
            Response::ok(id, result)
        }
        Err(e) => {
            audit(false, Some(&e.0), quiet);
            Response::err(id, e.0)
        }
    }
}
