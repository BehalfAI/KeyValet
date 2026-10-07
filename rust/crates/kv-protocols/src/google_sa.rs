//! Google service account: sign a JWT with the private key and exchange it for an access token
//! (RFC 7523 JWT bearer grant). Direct port of src/helper/protocols/google-sa.ts.

use crate::check::{now_sec, opt_str, str_list, str_req};
use crate::http::{assert_https_url, obj, post_form, remote_error};
use crate::jwt::sign_jwt;
use kv_vault::{Kind, Vault, VaultError};
use serde_json::{json, Value};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SaConfig {
    pub client_email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    pub token_uri: String,
    pub scopes: Vec<String>,
    /// The user impersonated for domain-wide delegation; can only be set during setup, not changed
    /// when the agent fetches a token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CachedToken {
    access_token: String,
    expires_at: i64,
}

const DEFAULT_SCOPES: &str = "https://www.googleapis.com/auth/cloud-platform";
const MAX_CACHE: usize = 20;

/// Parse and validate the service account JSON key file.
pub fn validate_service_account_setup(
    config: &Value,
    secrets: &Value,
) -> kv_vault::Result<(SaConfig, std::collections::HashMap<String, String>)> {
    let raw = str_req(
        secrets.get("key_json"),
        &kv_i18n::t("服务账号密钥文件", "Service account key file"),
        20_000,
    )?;
    let key: Value = serde_json::from_str(&raw).map_err(|_| {
        VaultError::new(
            "服务账号密钥文件不是合法 JSON",
            "Service account key file is not valid JSON",
        )
    })?;
    if key.get("type").and_then(Value::as_str) != Some("service_account") {
        return Err(VaultError::new(
            "密钥文件的 type 不是 \"service_account\"",
            "The key file's type is not \"service_account\"",
        ));
    }
    let private_key = crate::jwt::check_jwt_key(
        "RS256",
        &str_req(key.get("private_key"), "private_key", 10_000)?,
    )?;
    let scopes = str_list(config.get("scopes"), "scopes", 50)?;
    let token_uri = assert_https_url(
        key.get("token_uri")
            .and_then(Value::as_str)
            .unwrap_or("https://oauth2.googleapis.com/token"),
        "token_uri",
    )?;
    let cfg = SaConfig {
        client_email: str_req(key.get("client_email"), "client_email", 300)?,
        project_id: opt_str(key.get("project_id"), "project_id", 200)?,
        token_uri,
        scopes: if scopes.is_empty() {
            vec![DEFAULT_SCOPES.to_string()]
        } else {
            scopes
        },
        subject: opt_str(config.get("subject"), "subject", 300)?,
    };
    let private_key_id =
        opt_str(key.get("private_key_id"), "private_key_id", 200)?.unwrap_or_default();
    Ok((
        cfg,
        [
            ("private_key".to_string(), private_key),
            ("private_key_id".to_string(), private_key_id),
        ]
        .into(),
    ))
}

pub struct ServiceAccountTokenParams {
    pub scopes: Vec<String>,
    pub force: bool,
}

pub async fn service_account_token(
    vault: &Vault,
    ty: &str,
    name: &str,
    p: ServiceAccountTokenParams,
) -> kv_vault::Result<Value> {
    let (ty, name, record) = vault.get_record(ty, name)?;
    if record.kind_or_static() != Kind::GoogleServiceAccount {
        return Err(VaultError::new(
            &format!("\"{ty}/{name}\" 不是 Google 服务账号凭证"),
            &format!("\"{ty}/{name}\" is not a Google service account credential"),
        ));
    }
    let cfg: SaConfig =
        serde_json::from_value(record.config.clone().unwrap_or_default()).map_err(|_| {
            VaultError::new(
                "服务账号配置已损坏",
                "Service account configuration is corrupted",
            )
        })?;
    // Only allow requesting a subset of the scopes configured at setup time (especially important
    // with domain-wide delegation).
    let extra: Vec<&String> = p
        .scopes
        .iter()
        .filter(|s| !cfg.scopes.contains(s))
        .collect();
    if !extra.is_empty() {
        let extra_s = extra
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let allowed_s = cfg.scopes.join(" ");
        return Err(VaultError::new(
            &format!("请求的 scope 不在该凭证允许的范围内：{extra_s}（允许：{allowed_s}）"),
            &format!("Requested scopes are not allowed for this credential: {extra_s} (allowed: {allowed_s})"),
        ));
    }
    let mut scopes: Vec<String> = if p.scopes.is_empty() {
        cfg.scopes.clone()
    } else {
        p.scopes.clone()
    };
    scopes.sort();
    scopes.dedup();
    let cache_key = scopes.join(" ");

    let cache: std::collections::HashMap<String, CachedToken> = record
        .state
        .as_ref()
        .and_then(|s| s.get("tokens"))
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    if let Some(hit) = cache.get(&cache_key) {
        if !p.force && (hit.expires_at - 60_000) > now_ms() {
            return Ok(serde_json::to_value(out(hit, &cache_key, &cfg)).unwrap());
        }
    }

    let iat = now_sec();
    let mut claims = json!({"iss": cfg.client_email, "scope": cache_key, "aud": cfg.token_uri, "iat": iat, "exp": iat + 3600});
    if let Some(sub) = &cfg.subject {
        claims
            .as_object_mut()
            .unwrap()
            .insert("sub".into(), json!(sub));
    }
    let mut header = serde_json::Map::new();
    if let Some(kid) = record
        .secrets
        .as_ref()
        .and_then(|s| s.get("private_key_id"))
        .filter(|s| !s.is_empty())
    {
        header.insert("kid".into(), json!(kid));
    }
    let private_key = record
        .secrets
        .as_ref()
        .and_then(|s| s.get("private_key"))
        .map(String::as_str)
        .unwrap_or("");
    let assertion = sign_jwt("RS256", private_key, claims.as_object().unwrap(), &header)?;
    let r = post_form(
        &cfg.token_uri,
        &[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &assertion),
        ],
        &[],
    )
    .await?;
    let j = obj(&r);
    let host = url::Url::parse(&cfg.token_uri)
        .map(|u| u.host_str().unwrap_or_default().to_string())
        .unwrap_or_default();
    let Some(access_token) = j.get("access_token").and_then(Value::as_str) else {
        return Err(remote_error(&host, &r));
    };
    if r.status >= 300 {
        return Err(remote_error(&host, &r));
    }
    let expires_in = j
        .get("expires_in")
        .and_then(Value::as_f64)
        .filter(|v| v.is_finite() && *v > 0.0)
        .unwrap_or(3600.0);
    let tok = CachedToken {
        access_token: access_token.to_string(),
        expires_at: now_ms() + (expires_in * 1000.0) as i64,
    };

    let gen = record.generation.clone();
    let cache_key_clone = cache_key.clone();
    let tok_clone = tok.clone();
    vault.patch_record(
        &ty,
        &name,
        Kind::GoogleServiceAccount,
        gen.as_deref(),
        move |rec| {
            let mut tokens: std::collections::HashMap<String, CachedToken> = rec
                .state
                .as_ref()
                .and_then(|s| s.get("tokens"))
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            tokens.insert(cache_key_clone, tok_clone);
            if tokens.len() > MAX_CACHE {
                // Drop the oldest entries by insertion order isn't tracked in a HashMap; approximate by
                // dropping arbitrary extras down to MAX_CACHE (matches the TS intent -- bound the cache
                // size -- without claiming a specific eviction order that was never guaranteed either way,
                // since TS's plain object also has engine-defined "insertion order" that isn't meaningfully
                // observable here).
                let excess = tokens.len() - MAX_CACHE;
                let drop_keys: Vec<String> = tokens.keys().take(excess).cloned().collect();
                for k in drop_keys {
                    tokens.remove(&k);
                }
            }
            let mut state = rec
                .state
                .clone()
                .unwrap_or(json!({}))
                .as_object()
                .cloned()
                .unwrap_or_default();
            state.insert("tokens".into(), serde_json::to_value(&tokens).unwrap());
            rec.state = Some(Value::Object(state));
        },
    )?;
    Ok(serde_json::to_value(out(&tok, &cache_key, &cfg)).unwrap())
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[derive(Debug, Clone, serde::Serialize)]
struct SaTokenOut {
    access_token: String,
    token_type: &'static str,
    expires_at: String,
    scope: String,
    account: String,
}

fn out(tok: &CachedToken, scope: &str, cfg: &SaConfig) -> SaTokenOut {
    SaTokenOut {
        access_token: tok.access_token.clone(),
        token_type: "Bearer",
        expires_at: chrono::DateTime::<chrono::Utc>::from(
            std::time::UNIX_EPOCH + std::time::Duration::from_millis(tok.expires_at.max(0) as u64),
        )
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        scope: scope.to_string(),
        account: cfg
            .subject
            .clone()
            .unwrap_or_else(|| cfg.client_email.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_json() -> String {
        use rsa::pkcs8::EncodePrivateKey;
        let key = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
        let pem = key.to_pkcs8_pem(Default::default()).unwrap().to_string();
        json!({"type": "service_account", "client_email": "sa@proj.iam.gserviceaccount.com", "private_key": pem, "project_id": "proj", "private_key_id": "k1"}).to_string()
    }

    #[test]
    fn validate_rejects_non_service_account_json_and_defaults_scope() {
        assert!(validate_service_account_setup(
            &json!({}),
            &json!({"key_json": "{\"type\":\"authorized_user\"}"})
        )
        .is_err());
        let (cfg, secrets) =
            validate_service_account_setup(&json!({}), &json!({"key_json": key_json()})).unwrap();
        assert_eq!(cfg.scopes, vec![DEFAULT_SCOPES.to_string()]);
        assert_eq!(cfg.client_email, "sa@proj.iam.gserviceaccount.com");
        assert_eq!(secrets["private_key_id"], "k1");
    }
}
