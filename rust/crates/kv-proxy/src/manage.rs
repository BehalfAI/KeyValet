//! Modifies the proxy configuration of an existing credential. Changes that expand the exposure
//! surface (adding domains, changing injection rules, turning off "proxy only", deleting the
//! configuration) are confirmed by the helper itself via a dialog as the user -- independent of the
//! MCP server's confirmation, so bypassing the server to drive the helper directly has no effect.
//! Direct port of src/helper/http-manage.ts.

use crate::config::{validate_http_config, ValidateOpts};
use kv_platform::Confirmer;
use kv_vault::{HttpConfig, Kind, Vault, VaultError};
use serde_json::{json, Value};

fn summarize_inject(c: Option<&HttpConfig>) -> String {
    let Some(r) = c.and_then(|c| c.inject.as_ref()) else {
        return kv_i18n::t(
            "（自动注入 access token）",
            "(access token injected automatically)",
        );
    };
    let mut parts: Vec<String> = Vec::new();
    if let Some(h) = &r.headers {
        let mut ks: Vec<&String> = h.keys().collect();
        ks.sort();
        parts.extend(
            ks.iter()
                .map(|k| kv_i18n::t(&format!("请求头 {k}"), &format!("header {k}"))),
        );
    }
    if let Some(q) = &r.query {
        let mut ks: Vec<&String> = q.keys().collect();
        ks.sort();
        parts.extend(
            ks.iter()
                .map(|k| kv_i18n::t(&format!("查询参数 {k}"), &format!("query parameter {k}"))),
        );
    }
    if r.basic.is_some() {
        parts.push(kv_i18n::t("Basic 认证", "Basic auth"));
    }
    parts.join(&kv_i18n::t("、", ", "))
}

fn clip(s: &str) -> String {
    s.chars().take(200).collect()
}

pub struct ConfigureHttpParams<'a> {
    pub r#type: &'a str,
    pub name: &'a str,
    pub purpose: &'a str,
    pub remove: bool,
    pub inject: Option<&'a Value>,
    pub allowed_hosts: Option<&'a Value>,
    pub proxy_only: Option<bool>,
    pub test: Option<&'a Value>,
}

pub async fn configure_http<C: Confirmer>(
    vault: &Vault,
    p: ConfigureHttpParams<'_>,
    confirmer: &C,
) -> kv_vault::Result<Value> {
    let (ty, name, record) = vault.get_record(p.r#type, p.name)?;
    let prev = record.http.clone();
    let label = format!("{ty}/{name}");
    let purpose = clip(p.purpose);

    if p.remove {
        let Some(prev) = prev else {
            return Ok(json!({"type": ty, "name": name, "http": null}));
        };
        let unlock_note = if prev.proxy_only {
            kv_i18n::t(
                "（之后可以读出原始秘密）",
                " (the raw secret will then be readable)",
            )
        } else {
            String::new()
        };
        let message = kv_i18n::t(
            &format!("AI 会话请求删除凭证 {label} 的代理调用配置{unlock_note}。\n\n目的：{purpose}"),
            &format!("An AI session is requesting to remove the proxy configuration of credential {label}{unlock_note}.\n\nPurpose: {purpose}"),
        );
        if !confirmer
            .confirm(&message, &kv_i18n::t("允许删除", "Allow Removal"))
            .await
        {
            return Err(VaultError::new(
                "用户拒绝了该修改",
                "The user denied this change",
            ));
        }
        let prev_json = serde_json::to_value(&prev).unwrap();
        vault.update_http(&ty, &name, move |rec| {
            let current = rec.http.clone();
            let current_json = current.as_ref().map(|h| serde_json::to_value(h).unwrap());
            if current_json.as_ref() != Some(&prev_json) {
                current // precondition no longer holds: leave it alone (don't apply a stale "remove")
            } else {
                None // precondition held: actually remove it
            }
        })?;
        // `update_http`'s closure can't itself raise an error (its return type IS the new config, not
        // a Result), so the conflict above was handled by leaving the record unchanged rather than
        // aborting; re-check after the fact and surface a clear error so the caller retries instead
        // of believing a removal happened that didn't.
        if vault.get_record(&ty, &name)?.2.http.is_some() {
            return Err(VaultError::new(
                "配置在确认期间被修改，请重试",
                "The configuration was modified during confirmation; please retry",
            ));
        }
        return Ok(json!({"type": ty, "name": name, "http": null}));
    }

    let merged = json!({
        "inject": p.inject.cloned().unwrap_or_else(|| prev.as_ref().and_then(|h| h.inject.as_ref()).map(|i| serde_json::to_value(i).unwrap()).unwrap_or(Value::Null)),
        "allowed_hosts": p.allowed_hosts.cloned().unwrap_or_else(|| prev.as_ref().map(|h| json!(h.allowed_hosts)).unwrap_or(Value::Null)),
        "proxy_only": p.proxy_only.unwrap_or_else(|| prev.as_ref().is_some_and(|h| h.proxy_only)),
        "test": p.test.cloned().unwrap_or_else(|| prev.as_ref().and_then(|h| h.test.as_ref()).map(|t| serde_json::to_value(t).unwrap()).unwrap_or(Value::Null)),
    });
    let next = validate_http_config(
        &merged,
        &record,
        ValidateOpts {
            allow_secrets_in_test: false,
            prev_test: prev.as_ref().and_then(|h| h.test.as_ref()),
        },
    )?;

    let prev_hosts: Vec<String> = prev
        .as_ref()
        .map(|h| h.allowed_hosts.clone())
        .unwrap_or_default();
    let new_hosts: Vec<&String> = next
        .allowed_hosts
        .iter()
        .filter(|h| !prev_hosts.contains(h))
        .collect();
    let inject_changed = serde_json::to_value(&next.inject).unwrap()
        != prev
            .as_ref()
            .map(|h| serde_json::to_value(&h.inject).unwrap())
            .unwrap_or(Value::Null);
    let unlocking = prev.as_ref().is_some_and(|h| h.proxy_only) && !next.proxy_only;
    if !new_hosts.is_empty() || inject_changed || unlocking {
        let mut lines = vec![kv_i18n::t(&format!("AI 会话请求修改凭证 {label} 的代理调用配置："), &format!("An AI session is requesting to change the proxy configuration of credential {label}:")), String::new()];
        if !new_hosts.is_empty() {
            let joined = new_hosts
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(&kv_i18n::t("、", ", "));
            lines.push(kv_i18n::t(
                &format!("• 新增允许发往的域名：{joined}"),
                &format!("• New allowed hosts: {joined}"),
            ));
        }
        if inject_changed {
            lines.push(kv_i18n::t(
                &format!("• 注入方式：{}", summarize_inject(Some(&next))),
                &format!("• Injection: {}", summarize_inject(Some(&next))),
            ));
        }
        if unlocking {
            lines.push(kv_i18n::t(
                "• 关闭「只能代理调用」：之后可以读出原始秘密",
                "• Turn off \"proxy only\": the raw secret will then be readable",
            ));
        }
        lines.push(String::new());
        lines.push(kv_i18n::t(
            &format!("目的：{purpose}"),
            &format!("Purpose: {purpose}"),
        ));
        if !confirmer
            .confirm(&lines.join("\n"), &kv_i18n::t("允许", "Allow"))
            .await
        {
            return Err(VaultError::new(
                "用户拒绝了该修改",
                "The user denied this change",
            ));
        }
    }

    let prev_json = prev.as_ref().map(|h| serde_json::to_value(h).unwrap());
    let next_clone = next.clone();
    vault.update_http(&ty, &name, move |rec| {
        let current_json = rec.http.as_ref().map(|h| serde_json::to_value(h).unwrap());
        if current_json != prev_json {
            // Can't raise an error from here (`update_http`'s closure returns the new config, not a
            // Result); leave the record unchanged instead of applying a stale confirmation, and let
            // the post-check below turn this into a "please retry" error for the caller.
            return rec.http.clone();
        }
        Some(next_clone.clone())
    })?;
    let final_http = vault.get_record(&ty, &name)?.2.http.clone();
    if final_http
        .as_ref()
        .map(|h| serde_json::to_value(h).unwrap())
        != Some(serde_json::to_value(&next).unwrap())
    {
        return Err(VaultError::new(
            "配置在确认期间被修改，请重试",
            "The configuration was modified during confirmation; please retry",
        ));
    }

    Ok(json!({
        "type": ty, "name": name,
        "http": {"allowed_hosts": next.allowed_hosts, "proxy_only": next.proxy_only, "inject": summarize_inject(Some(&next)), "can_test": next.test.is_some()},
    }))
}

pub fn kind_supports_proxy(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::Static | Kind::Oauth2 | Kind::GoogleServiceAccount | Kind::GithubApp | Kind::Jwt
    )
}
