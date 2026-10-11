//! GitHub App: sign a JWT with the App's private key and exchange it for an installation access
//! token valid for 1 hour. Direct port of src/helper/protocols/github-app.ts.

use crate::check::{now_sec, str_req};
use crate::expiry::{is_fresh, iso_millis, now_ms};
use crate::http::{assert_https_url, http_request, obj, remote_error, Method};
use crate::jwt::sign_jwt;
use kv_vault::{Kind, Vault, VaultError};
use serde_json::{json, Value};
use std::sync::LazyLock;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GitHubAppConfig {
    pub app_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installation_id: Option<String>,
    pub api_base_url: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct CachedToken {
    token: Zeroizing<String>,
    expires_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    permissions: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repository_selection: Option<Value>,
}

fn app_id_re() -> &'static regex::Regex {
    static RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"^(\d+|Iv[0-9A-Za-z.]+)$").unwrap());
    &RE
}

pub fn validate_github_app_setup(
    config: &Value,
    secrets: &Value,
) -> kv_vault::Result<(GitHubAppConfig, std::collections::HashMap<String, String>)> {
    let app_id = config
        .get("app_id")
        .map(|v| {
            if let Value::String(s) = v {
                s.clone()
            } else {
                v.to_string()
            }
        })
        .unwrap_or_default();
    if !app_id_re().is_match(&app_id) {
        return Err(VaultError::new(
            "app_id 应为数字 App ID 或 Client ID（Iv 开头）",
            "app_id must be a numeric App ID or a Client ID (starting with Iv)",
        ));
    }
    let inst = config
        .get("installation_id")
        .filter(|v| !v.is_null() && v.as_str() != Some(""))
        .map(|v| {
            if let Value::String(s) = v {
                s.clone()
            } else {
                v.to_string()
            }
        });
    if let Some(i) = &inst {
        if !i.chars().all(|c| c.is_ascii_digit()) || i.is_empty() {
            return Err(VaultError::new(
                "installation_id 必须是数字",
                "installation_id must be numeric",
            ));
        }
    }
    let api_base_url = assert_https_url(
        config
            .get("api_base_url")
            .and_then(Value::as_str)
            .unwrap_or("https://api.github.com"),
        "api_base_url",
    )?;
    let api_base_url = api_base_url.trim_end_matches('/').to_string();
    let key = crate::jwt::check_jwt_key(
        "RS256",
        &str_req(secrets.get("private_key"), "private_key", 10_000)?,
    )?;
    Ok((
        GitHubAppConfig {
            app_id,
            installation_id: inst,
            api_base_url,
        },
        [("private_key".to_string(), key)].into(),
    ))
}

fn gh_headers(jwt: &str) -> Vec<(String, String)> {
    vec![
        ("Accept".into(), "application/vnd.github+json".into()),
        ("Authorization".into(), format!("Bearer {jwt}")),
        ("X-GitHub-Api-Version".into(), "2022-11-28".into()),
    ]
}

pub struct GitHubAppTokenParams {
    pub repositories: Vec<String>,
    pub permissions: Option<Value>,
    pub force: bool,
}

pub async fn github_app_token(
    vault: &Vault,
    ty: &str,
    name: &str,
    p: GitHubAppTokenParams,
) -> kv_vault::Result<Value> {
    let (ty, name, record) = vault.get_record(ty, name)?;
    if record.kind_or_static() != Kind::GithubApp {
        return Err(VaultError::new(
            &format!("\"{ty}/{name}\" 不是 GitHub App 凭证"),
            &format!("\"{ty}/{name}\" is not a GitHub App credential"),
        ));
    }
    let cfg: GitHubAppConfig = serde_json::from_value(record.config.clone().unwrap_or_default())
        .map_err(|_| {
            VaultError::new(
                "GitHub App 配置已损坏",
                "GitHub App configuration is corrupted",
            )
        })?;
    if let Some(perm) = &p.permissions {
        if !perm.is_object() {
            return Err(VaultError::new(
                "permissions 必须是对象，如 {\"contents\": \"read\"}",
                "permissions must be an object, e.g. {\"contents\": \"read\"}",
            ));
        }
    }
    let narrowed = !p.repositories.is_empty() || p.permissions.is_some();

    let cached = record
        .state
        .as_ref()
        .and_then(|s| s.get("token"))
        .and_then(|v| <CachedToken as serde::Deserialize>::deserialize(v).ok());
    if !narrowed {
        if let Some(c) = &cached {
            if !p.force && is_fresh(c.expires_at, 5 * 60_000) {
                return Ok(serde_json::to_value(out(c, &cfg)).unwrap());
            }
        }
    }

    let iat = now_sec() - 60; // tolerate clock skew
    let claims = json!({"iat": iat, "exp": iat + 600, "iss": cfg.app_id});
    let jwt = Zeroizing::new(sign_jwt(
        "RS256",
        record
            .secrets
            .as_ref()
            .and_then(|s| s.get("private_key"))
            .map(String::as_str)
            .unwrap_or(""),
        claims.as_object().unwrap(),
        &Default::default(),
    )?);

    let mut installation_id = cfg.installation_id.clone();
    if installation_id.is_none() {
        let headers = Zeroizing::new(gh_headers(&jwt));
        let header_refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let r = http_request(
            &format!("{}/app/installations", cfg.api_base_url),
            Method::Get,
            &header_refs,
            None,
        )
        .await?;
        let host = url::Url::parse(&cfg.api_base_url)
            .map(|u| u.host_str().unwrap_or_default().to_string())
            .unwrap_or_default();
        let Some(list) = r.json.as_array() else {
            return Err(remote_error(&host, &r));
        };
        if r.status >= 300 {
            return Err(remote_error(&host, &r));
        }
        if list.len() != 1 {
            let desc = list
                .iter()
                .map(|i| {
                    let id = i.get("id").map(|v| v.to_string()).unwrap_or_default();
                    let login = i
                        .get("account")
                        .and_then(|a| a.get("login"))
                        .and_then(Value::as_str)
                        .unwrap_or("?");
                    kv_i18n::t(&format!("{id}（{login}）"), &format!("{id} ({login})"))
                })
                .collect::<Vec<_>>()
                .join(&kv_i18n::t("、", ", "));
            let desc = if desc.is_empty() {
                kv_i18n::t("无", "none")
            } else {
                desc
            };
            return Err(VaultError::new(
                &format!("该 App 有 {} 个 installation：{desc}。请重新设置并指定 installation_id。", list.len()),
                &format!("This App has {} installation(s): {desc}. Set it up again and specify installation_id.", list.len()),
            ));
        }
        installation_id = Some(list[0].get("id").map(|v| v.to_string()).unwrap_or_default());
    }

    let mut body = serde_json::Map::new();
    if !p.repositories.is_empty() {
        body.insert("repositories".into(), json!(p.repositories));
    }
    if let Some(perm) = &p.permissions {
        body.insert("permissions".into(), perm.clone());
    }
    let mut headers = Zeroizing::new(gh_headers(&jwt));
    headers.push(("Content-Type".into(), "application/json".into()));
    let header_refs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let url = format!(
        "{}/app/installations/{}/access_tokens",
        cfg.api_base_url,
        installation_id.as_deref().unwrap_or_default()
    );
    let r = http_request(
        &url,
        Method::Post,
        &header_refs,
        Some(serde_json::to_string(&body).unwrap()),
    )
    .await?;
    let j = obj(&r);
    let host = url::Url::parse(&cfg.api_base_url)
        .map(|u| u.host_str().unwrap_or_default().to_string())
        .unwrap_or_default();
    let Some(token) = j.get("token").and_then(Value::as_str) else {
        return Err(remote_error(&host, &r));
    };
    if r.status >= 300 {
        return Err(remote_error(&host, &r));
    }
    let tok = CachedToken {
        token: Zeroizing::new(token.to_string()),
        expires_at: j
            .get("expires_at")
            .and_then(Value::as_str)
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.timestamp_millis())
            .unwrap_or_else(|| now_ms() + 3_600_000),
        permissions: j.get("permissions").cloned(),
        repository_selection: j.get("repository_selection").cloned(),
    };
    if iso_millis(tok.expires_at).is_none() {
        return Err(VaultError::new(
            "token 响应的 expires_at 无效",
            "Token response expires_at is invalid",
        ));
    }
    if !narrowed {
        let gen = record.generation.clone();
        let inst = installation_id.clone();
        vault.patch_record(&ty, &name, Kind::GithubApp, gen.as_deref(), |rec| {
            rec.set_state_field("token", serde_json::to_value(&tok).unwrap());
            if let Some(i) = &inst {
                rec.set_state_field("installation_id", json!(i));
            }
        })?;
    }
    Ok(serde_json::to_value(out(&tok, &cfg)).unwrap())
}

#[derive(Debug, Clone, serde::Serialize)]
struct GitHubAppTokenOut {
    access_token: String,
    token_type: &'static str,
    expires_at: Option<String>,
    permissions: Value,
    repository_selection: Value,
    api_base_url: String,
}

impl Drop for GitHubAppTokenOut {
    fn drop(&mut self) {
        self.access_token.zeroize();
    }
}

fn out(tok: &CachedToken, cfg: &GitHubAppConfig) -> GitHubAppTokenOut {
    GitHubAppTokenOut {
        access_token: tok.token.to_string(),
        token_type: "token",
        expires_at: iso_millis(tok.expires_at),
        permissions: tok.permissions.clone().unwrap_or(Value::Null),
        repository_selection: tok.repository_selection.clone().unwrap_or(Value::Null),
        api_base_url: cfg.api_base_url.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_checks_app_id_and_installation_id_formats() {
        assert!(validate_github_app_setup(
            &json!({"app_id": "not valid"}),
            &json!({"private_key": rsa_pem()})
        )
        .is_err());
        assert!(validate_github_app_setup(
            &json!({"app_id": "123456", "installation_id": "abc"}),
            &json!({"private_key": rsa_pem()})
        )
        .is_err());
        let (cfg, _) = validate_github_app_setup(
            &json!({"app_id": "123456"}),
            &json!({"private_key": rsa_pem()}),
        )
        .unwrap();
        assert_eq!(cfg.api_base_url, "https://api.github.com");
    }

    fn rsa_pem() -> String {
        use rsa::pkcs8::EncodePrivateKey;
        let key = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
        key.to_pkcs8_pem(Default::default()).unwrap().to_string()
    }
}
