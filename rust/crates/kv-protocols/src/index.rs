//! Orchestration across protocol kinds: create/replace a protocol credential, the unified
//! "get a short-lived token" entry point, and the agent-facing public view. Direct port of
//! src/helper/protocols/index.ts.

use crate::{aws, github_app, google_sa, jwt_kind, oauth2, totp};
use kv_vault::{Kind, SetProtocolParams, Vault, VaultError};
use serde_json::{json, Value};

const SECRET_REBIND_MARK: &str = "[SECRET_REBIND]";

fn as_map(v: &Value) -> serde_json::Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}

pub struct SetupProtocolParams {
    pub r#type: String,
    pub name: String,
    pub kind: Kind,
    pub config: Value,
    pub secrets: Value,
    pub description: Option<String>,
    pub type_description: Option<String>,
    pub overwrite: bool,
    /// Reuse the previously saved client secret when only non-binding fields (scope, etc.) change;
    /// rejected if the endpoint or client changed (see `SECRET_REBIND_MARK`). Only valid for oauth2.
    pub reuse_client_secret: bool,
}

/// Create/replace a protocol credential. If the credential type doesn't exist yet, it's created
/// first (consistent with static credentials).
pub fn setup_protocol(
    vault: &Vault,
    p: SetupProtocolParams,
) -> kv_vault::Result<kv_vault::SetResult> {
    if p.kind == Kind::Static {
        return Err(VaultError::new(
            &format!("未知的协议种类 {:?}", p.kind),
            &format!("Unknown protocol kind {:?}", p.kind),
        ));
    }
    let mut in_secrets = as_map(&p.secrets);
    let mut previous = None;
    if p.reuse_client_secret {
        if p.kind != Kind::Oauth2 {
            return Err(VaultError::new(
                "只有 oauth2 凭证可以沿用 client secret",
                "Only oauth2 credentials can reuse the client secret",
            ));
        }
        let (_, _, record) = vault.get_record(&p.r#type, &p.name)?;
        if record.kind_or_static() != Kind::Oauth2 {
            return Err(VaultError::new(
                "已有凭证不是 oauth2，不能沿用 client secret",
                "The existing credential is not oauth2; cannot reuse the client secret",
            ));
        }
        if let Some(cs) = record.secrets.as_ref().and_then(|s| s.get("client_secret")) {
            in_secrets.insert("client_secret".into(), json!(cs));
        }
        previous = Some(record);
    }
    let in_secrets_v = Value::Object(in_secrets);
    let (config, secrets): (Value, std::collections::HashMap<String, String>) = match p.kind {
        Kind::Oauth2 => {
            let (c, s) = oauth2::validate_oauth2_setup(&p.config, &in_secrets_v)?;
            (serde_json::to_value(c).unwrap(), s)
        }
        Kind::GoogleServiceAccount => {
            let (c, s) = google_sa::validate_service_account_setup(&p.config, &in_secrets_v)?;
            (serde_json::to_value(c).unwrap(), s)
        }
        Kind::GithubApp => {
            let (c, s) = github_app::validate_github_app_setup(&p.config, &in_secrets_v)?;
            (serde_json::to_value(c).unwrap(), s)
        }
        Kind::Jwt => {
            let (c, s) = jwt_kind::validate_jwt_setup(&p.config, &in_secrets_v)?;
            (serde_json::to_value(c).unwrap(), s)
        }
        Kind::Totp => {
            let (c, s) = totp::validate_totp_setup(&p.config, &in_secrets_v)?;
            (serde_json::to_value(c).unwrap(), s)
        }
        Kind::Aws => {
            let (c, s) = aws::validate_aws_setup(&p.config, &in_secrets_v)?;
            (serde_json::to_value(c).unwrap(), s)
        }
        Kind::Static => unreachable!(),
    };
    let mut config_map = as_map(&config);
    if let Some(previous) = &previous {
        let prev_cfg = previous.config.clone().unwrap_or_default();
        for k in [
            "client_id",
            "token_url",
            "authorization_url",
            "device_authorization_url",
            "token_auth_method",
        ] {
            if prev_cfg.get(k) != config_map.get(k) {
                return Err(VaultError::new(
                    &format!("{SECRET_REBIND_MARK} {k} 已变化，不能沿用旧的 client secret，请重新输入"),
                    &format!("{SECRET_REBIND_MARK} {k} has changed; the old client secret cannot be reused, please enter it again"),
                ));
            }
        }
    }
    if p.kind == Kind::Aws {
        if let Some(mfa_totp) = config_map.get("mfa_totp").cloned() {
            let r#type = mfa_totp
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let name = mfa_totp
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let (target_ty, target_name, target_record) = vault.get_record(r#type, name)?;
            if target_record.kind_or_static() != Kind::Totp {
                return Err(VaultError::new(
                    &format!("mfa_totp 指向的 \"{target_ty}/{target_name}\" 不是 TOTP 凭证"),
                    &format!("\"{target_ty}/{target_name}\" referenced by mfa_totp is not a TOTP credential"),
                ));
            }
            config_map.insert(
                "mfa_totp".into(),
                json!({"type": target_ty, "name": target_name}),
            );
        }
    }
    vault.set_protocol(SetProtocolParams {
        r#type: p.r#type,
        name: p.name,
        kind: p.kind,
        config: Value::Object(config_map),
        secrets,
        description: p.description,
        type_description: p.type_description,
        overwrite: p.overwrite,
    })
}

/// The view shown to the agent: config and status, without any secrets or cached tokens.
pub fn public_view(
    ty: &str,
    name: &str,
    rec: &kv_vault::CredentialRecord,
) -> kv_vault::Result<Value> {
    let kind = rec.kind_or_static();
    let cfg = rec.config.clone().unwrap_or(json!({}));
    let base = json!({"type": ty, "name": name, "kind": kind, "description": rec.description, "updatedAt": rec.updated_at});
    let mut v = match kind {
        Kind::Oauth2 => {
            json!({"config": cfg, "status": oauth2::public_state(rec), "how_to_use": kv_i18n::t("调用 credential_access_token 获取 access token", "Call credential_access_token to get an access token")})
        }
        Kind::GoogleServiceAccount | Kind::GithubApp | Kind::Jwt => {
            json!({"config": cfg, "how_to_use": kv_i18n::t("调用 credential_access_token 获取短期 token", "Call credential_access_token to get a short-lived token")})
        }
        Kind::Totp => {
            json!({"config": cfg, "how_to_use": kv_i18n::t("调用 credential_totp_code 获取当前验证码", "Call credential_totp_code to get the current code")})
        }
        Kind::Aws => {
            json!({"config": cfg, "how_to_use": kv_i18n::t("调用 credential_aws_credentials 获取临时凭证", "Call credential_aws_credentials to get temporary credentials")})
        }
        Kind::Static => {
            return Err(VaultError::new(
                "static 凭证请使用 get",
                "Use get for static credentials",
            ))
        }
    };
    for (k, val) in base.as_object().unwrap() {
        v.as_object_mut().unwrap().insert(k.clone(), val.clone());
    }
    Ok(v)
}

pub struct AccessTokenParams {
    pub scopes: Vec<String>,
    pub repositories: Vec<String>,
    pub permissions: Option<Value>,
    pub force: bool,
    /// Proxy-only credential: the token is only used internally by the proxy and is never returned
    /// to the caller (only the proxy implementation may set this -- see kv-proxy/kv-core dispatch).
    pub via_proxy: bool,
}

/// Unified "get a short-lived token" entry point: oauth2 / google_service_account / github_app / jwt.
pub async fn access_token(
    vault: &Vault,
    ty: &str,
    name: &str,
    p: AccessTokenParams,
) -> kv_vault::Result<Value> {
    let (ty, name, record) = vault.get_record(ty, name)?;
    if record.http.as_ref().is_some_and(|h| h.proxy_only) && !p.via_proxy {
        return Err(VaultError::new(
            &format!("\"{ty}/{name}\" 设置为只能代理调用，不能取出 access token；请用 credential_http_request"),
            &format!("\"{ty}/{name}\" is proxy-only; its access token cannot be retrieved. Use credential_http_request instead"),
        ));
    }
    match record.kind_or_static() {
        Kind::Oauth2 => oauth2::access_token(vault, &ty, &name, p.force).await,
        Kind::GoogleServiceAccount => {
            google_sa::service_account_token(
                vault,
                &ty,
                &name,
                google_sa::ServiceAccountTokenParams {
                    scopes: p.scopes,
                    force: p.force,
                },
            )
            .await
        }
        Kind::GithubApp => {
            github_app::github_app_token(
                vault,
                &ty,
                &name,
                github_app::GitHubAppTokenParams {
                    repositories: p.repositories,
                    permissions: p.permissions,
                    force: p.force,
                },
            )
            .await
        }
        Kind::Jwt => Ok(serde_json::to_value(jwt_kind::jwt_token(vault, &ty, &name)?).unwrap()),
        other => Err(VaultError::new(
            &format!(
                "\"{ty}/{name}\" 是 {} 凭证，不能用于获取 access token",
                other.as_str()
            ),
            &format!(
                "\"{ty}/{name}\" is a {} credential and cannot be used to get an access token",
                other.as_str()
            ),
        )),
    }
}
