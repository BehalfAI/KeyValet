//! OAuth 2.0: authorization code + PKCE (RFC 6749/7636), device code (RFC 8628), client
//! credentials. The client secret and refresh token exist only in the root helper; the agent can
//! only get a short-lived access token. Direct port of src/helper/protocols/oauth2.ts.

use crate::check::{int, one_of, opt_str, str_list, str_record, str_req};
use crate::http::{assert_https_url, obj, post_form, remote_error, HttpResult};
use crate::jwt::decode_jwt_payload;
use kv_vault::{Kind, Vault, VaultError};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const OAUTH_FLOWS: [&str; 3] = ["authorization_code", "device_code", "client_credentials"];
const AUTH_METHODS: [&str; 3] = ["client_secret_post", "client_secret_basic", "none"];
/// Parameters controlled by this program; must not be overridden via `extra_auth_params`.
const RESERVED_AUTH_PARAMS: [&str; 7] = [
    "client_id",
    "redirect_uri",
    "state",
    "code_challenge",
    "code_challenge_method",
    "response_type",
    "scope",
];

const EXPIRY_MARGIN_MS: i64 = 60_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OAuth2Config {
    pub provider: String,
    pub flow: String,
    pub client_id: String,
    pub token_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_authorization_url: Option<String>,
    pub scopes: Vec<String>,
    pub extra_auth_params: std::collections::HashMap<String, String>,
    pub token_auth_method: String,
    /// A fixed redirect URI (some providers require an exact port match); if unset, a
    /// random-port http://127.0.0.1:<port>/callback is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct OAuth2State {
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorized_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    needs_reauth: Option<bool>,
}

pub fn validate_redirect_uri(raw: &Value) -> kv_vault::Result<String> {
    let s = str_req(Some(raw), "redirect_uri", 300)?;
    let u = url::Url::parse(&s).map_err(|_| {
        VaultError::new(
            "redirect_uri 必须是本机回环地址，如 http://127.0.0.1:8765/callback",
            "redirect_uri must be a local loopback address, e.g. http://127.0.0.1:8765/callback",
        )
    })?;
    let host_ok = matches!(
        u.host_str(),
        Some("127.0.0.1") | Some("localhost") | Some("[::1]")
    );
    if u.scheme() != "http" || !host_ok {
        return Err(VaultError::new(
            "redirect_uri 必须是本机回环地址，如 http://127.0.0.1:8765/callback",
            "redirect_uri must be a local loopback address, e.g. http://127.0.0.1:8765/callback",
        ));
    }
    Ok(u.to_string())
}

pub fn validate_oauth2_setup(
    config: &Value,
    secrets: &Value,
) -> kv_vault::Result<(OAuth2Config, std::collections::HashMap<String, String>)> {
    let flow = one_of(
        config.get("flow"),
        "flow",
        &OAUTH_FLOWS,
        "authorization_code",
    )?
    .to_string();
    let client_secret = opt_str(secrets.get("client_secret"), "client_secret", 2000)?;
    let default_auth_method = if client_secret.is_some() {
        "client_secret_post"
    } else {
        "none"
    };
    let mut cfg = OAuth2Config {
        provider: config
            .get("provider")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or("custom")
            .to_string(),
        flow: flow.clone(),
        client_id: str_req(config.get("client_id"), "client_id", 500)?,
        token_url: assert_https_url(
            &str_req(config.get("token_url"), "token_url", 2000)?,
            "token_url",
        )?,
        authorization_url: None,
        device_authorization_url: None,
        scopes: str_list(config.get("scopes"), "scopes", 50)?,
        extra_auth_params: str_record(config.get("extra_auth_params"), "extra_auth_params", 20)?,
        token_auth_method: one_of(
            config.get("token_auth_method"),
            "token_auth_method",
            &AUTH_METHODS,
            default_auth_method,
        )?
        .to_string(),
        redirect_uri: None,
    };
    if cfg.token_auth_method != "none" && client_secret.is_none() {
        return Err(VaultError::new(
            &format!("{} 需要 client_secret", cfg.token_auth_method),
            &format!("{} requires client_secret", cfg.token_auth_method),
        ));
    }
    if flow == "authorization_code" {
        cfg.authorization_url = Some(assert_https_url(
            &str_req(config.get("authorization_url"), "authorization_url", 2000)?,
            "authorization_url",
        )?);
        if config.get("redirect_uri").is_some_and(|v| !v.is_null()) {
            cfg.redirect_uri = Some(validate_redirect_uri(config.get("redirect_uri").unwrap())?);
        }
    }
    if flow == "device_code" {
        cfg.device_authorization_url = Some(assert_https_url(
            &str_req(
                config.get("device_authorization_url"),
                "device_authorization_url",
                2000,
            )?,
            "device_authorization_url",
        )?);
    }
    if flow == "client_credentials" && client_secret.is_none() {
        return Err(VaultError::new(
            "client_credentials 流程需要 client_secret",
            "The client_credentials flow requires client_secret",
        ));
    }
    for k in RESERVED_AUTH_PARAMS {
        if cfg.extra_auth_params.contains_key(k) {
            return Err(VaultError::new(
                &format!("extra_auth_params 不能包含 {k}"),
                &format!("extra_auth_params must not contain {k}"),
            ));
        }
    }
    let secrets_out = client_secret
        .map(|s| [("client_secret".to_string(), s)].into())
        .unwrap_or_default();
    Ok((cfg, secrets_out))
}

type Loaded = (
    String,
    String,
    kv_vault::CredentialRecord,
    OAuth2Config,
    std::collections::HashMap<String, String>,
    OAuth2State,
);

fn load(vault: &Vault, ty: &str, name: &str) -> kv_vault::Result<Loaded> {
    let (ty, name, record) = vault.get_record(ty, name)?;
    if record.kind_or_static() != Kind::Oauth2 {
        return Err(VaultError::new(
            &format!("\"{ty}/{name}\" 不是 OAuth 2.0 凭证"),
            &format!("\"{ty}/{name}\" is not an OAuth 2.0 credential"),
        ));
    }
    let cfg: OAuth2Config = serde_json::from_value(record.config.clone().unwrap_or_default())
        .map_err(|_| VaultError::new("OAuth2 配置已损坏", "OAuth2 configuration is corrupted"))?;
    let secrets = record.secrets.clone().unwrap_or_default();
    let state: OAuth2State = record
        .state
        .as_ref()
        .and_then(|s| serde_json::from_value(s.clone()).ok())
        .unwrap_or_default();
    Ok((ty, name, record, cfg, secrets, state))
}

type FormAndHeaders = (Vec<(String, String)>, Vec<(String, String)>);

/// Client authentication: put it in the form body or the Basic header.
fn client_auth(
    cfg: &OAuth2Config,
    secrets: &std::collections::HashMap<String, String>,
) -> FormAndHeaders {
    let empty = String::new();
    let secret = secrets.get("client_secret").unwrap_or(&empty);
    match cfg.token_auth_method.as_str() {
        "client_secret_basic" => {
            use base64::engine::{general_purpose::STANDARD, Engine};
            let enc =
                |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
            let basic = STANDARD.encode(format!("{}:{}", enc(&cfg.client_id), enc(secret)));
            (
                vec![],
                vec![("Authorization".to_string(), format!("Basic {basic}"))],
            )
        }
        "client_secret_post" => (
            vec![
                ("client_id".to_string(), cfg.client_id.clone()),
                ("client_secret".to_string(), secret.clone()),
            ],
            vec![],
        ),
        _ => (
            vec![("client_id".to_string(), cfg.client_id.clone())],
            vec![],
        ),
    }
}

async fn token_request(
    cfg: &OAuth2Config,
    secrets: &std::collections::HashMap<String, String>,
    mut form: Vec<(String, String)>,
) -> kv_vault::Result<HttpResult> {
    let (auth_form, auth_headers) = client_auth(cfg, secrets);
    form.extend(auth_form);
    let form_refs: Vec<(&str, &str)> = form.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let header_refs: Vec<(&str, &str)> = auth_headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    post_form(&cfg.token_url, &form_refs, &header_refs).await
}

/// Write the token response into the credential: access token goes into state, refresh token goes
/// into secrets. `fresh=true` means a brand-new authorization: discard the old refresh token and
/// state (which may belong to a different account).
fn save_tokens(
    vault: &Vault,
    ty: &str,
    name: &str,
    gen: Option<&str>,
    r: &HttpResult,
    fresh: bool,
) -> kv_vault::Result<(OAuth2State, bool)> {
    let j = obj(r);
    let access_token = j
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            VaultError::new(
                "token 响应缺少 access_token",
                "Token response is missing access_token",
            )
        })?;
    let expires_in = j.get("expires_in").and_then(Value::as_f64);
    let next = OAuth2State {
        access_token: Some(access_token.to_string()),
        token_type: Some(
            j.get("token_type")
                .and_then(Value::as_str)
                .unwrap_or("Bearer")
                .to_string(),
        ),
        expires_at: expires_in
            .filter(|e| e.is_finite() && *e > 0.0)
            .map(|e| now_ms() + (e * 1000.0) as i64),
        scope: j.get("scope").and_then(Value::as_str).map(String::from),
        account: None,
        authorized_at: None,
        needs_reauth: Some(false),
    };
    let claims = j
        .get("id_token")
        .and_then(Value::as_str)
        .and_then(decode_jwt_payload);
    let account = claims
        .as_ref()
        .and_then(|c| {
            c.get("email")
                .or_else(|| c.get("preferred_username"))
                .or_else(|| c.get("upn"))
        })
        .and_then(Value::as_str)
        .map(String::from);
    let got_refresh_token = j.get("refresh_token").and_then(Value::as_str).is_some();
    let account_clone = account.clone();
    let next_clone = next.clone();
    let refresh_token = j
        .get("refresh_token")
        .and_then(Value::as_str)
        .map(String::from);
    vault.patch_record(ty, name, Kind::Oauth2, gen, move |rec| {
        if fresh {
            rec.state = Some(json!({}));
            if let Some(s) = &mut rec.secrets {
                s.remove("refresh_token");
            }
        }
        let prev: OAuth2State = rec
            .state
            .as_ref()
            .and_then(|s| serde_json::from_value(s.clone()).ok())
            .unwrap_or_default();
        let merged = OAuth2State {
            access_token: next_clone.access_token.clone(),
            token_type: next_clone.token_type.clone(),
            expires_at: next_clone.expires_at,
            scope: next_clone.scope.clone().or(prev.scope),
            account: account_clone.clone().or(prev.account),
            authorized_at: Some(prev.authorized_at.unwrap_or_else(now_iso)),
            needs_reauth: Some(false),
        };
        rec.state = Some(serde_json::to_value(&merged).unwrap());
        if let Some(rt) = &refresh_token {
            rec.secrets
                .get_or_insert_with(Default::default)
                .insert("refresh_token".to_string(), rt.clone()); // supports refresh token rotation
        }
    })?;
    Ok((OAuth2State { account, ..next }, got_refresh_token))
}

fn is_token_response(r: &HttpResult) -> bool {
    (200..300).contains(&r.status) && obj(r).get("access_token").and_then(Value::as_str).is_some()
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
fn host_of(url_str: &str) -> String {
    url::Url::parse(url_str)
        .map(|u| u.host_str().unwrap_or_default().to_string())
        .unwrap_or_default()
}

/// Exchange the authorization code for a token (the last step of the browser flow).
pub async fn exchange_code(
    vault: &Vault,
    ty: &str,
    name: &str,
    code: &str,
    code_verifier: &str,
    redirect_uri: &Value,
) -> kv_vault::Result<Value> {
    let (ty, name, record, cfg, secrets, _state) = load(vault, ty, name)?;
    if cfg.flow != "authorization_code" {
        return Err(VaultError::new(
            &format!("\"{ty}/{name}\" 不是授权码流程"),
            &format!("\"{ty}/{name}\" does not use the authorization code flow"),
        ));
    }
    let form = vec![
        ("grant_type".to_string(), "authorization_code".to_string()),
        (
            "code".to_string(),
            str_req(Some(&json!(code)), "code", 4000)?,
        ),
        (
            "code_verifier".to_string(),
            str_req(Some(&json!(code_verifier)), "code_verifier", 200)?,
        ),
        (
            "redirect_uri".to_string(),
            validate_redirect_uri(redirect_uri)?,
        ),
    ];
    let r = token_request(&cfg, &secrets, form).await?;
    if !is_token_response(&r) {
        return Err(remote_error(&host_of(&cfg.token_url), &r));
    }
    let (s, got_refresh) = save_tokens(vault, &ty, &name, record.generation.as_deref(), &r, true)?;
    Ok(summary(&s, got_refresh))
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DeviceStartResult {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: Option<String>,
    pub verification_uri_complete: Option<String>,
    pub interval: i64,
    pub expires_in: i64,
}

/// Device code flow step one: request a `user_code` from the provider.
pub async fn device_start(
    vault: &Vault,
    ty: &str,
    name: &str,
) -> kv_vault::Result<DeviceStartResult> {
    let (ty, name, _record, cfg, _secrets, _state) = load(vault, ty, name)?;
    let Some(device_url) = &cfg.device_authorization_url else {
        return Err(VaultError::new(
            &format!("\"{ty}/{name}\" 不是设备码流程"),
            &format!("\"{ty}/{name}\" does not use the device code flow"),
        ));
    };
    if cfg.flow != "device_code" {
        return Err(VaultError::new(
            &format!("\"{ty}/{name}\" 不是设备码流程"),
            &format!("\"{ty}/{name}\" does not use the device code flow"),
        ));
    }
    let mut form = vec![("client_id".to_string(), cfg.client_id.clone())];
    if !cfg.scopes.is_empty() {
        form.push(("scope".to_string(), cfg.scopes.join(" ")));
    }
    let form_refs: Vec<(&str, &str)> = form.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let r = post_form(device_url, &form_refs, &[]).await?;
    let j = obj(&r);
    let (device_code, user_code) = (
        j.get("device_code").and_then(Value::as_str),
        j.get("user_code").and_then(Value::as_str),
    );
    if r.status >= 300 || device_code.is_none() || user_code.is_none() {
        return Err(remote_error(&host_of(device_url), &r));
    }
    let verification = j
        .get("verification_uri")
        .or_else(|| j.get("verification_url"))
        .and_then(Value::as_str); // Google uses verification_url
    Ok(DeviceStartResult {
        device_code: device_code.unwrap().to_string(),
        user_code: user_code.unwrap().to_string(),
        verification_uri: verification
            .map(|v| assert_https_url(v, "verification_uri"))
            .transpose()?,
        verification_uri_complete: j
            .get("verification_uri_complete")
            .and_then(Value::as_str)
            .map(|v| assert_https_url(v, "verification_uri_complete"))
            .transpose()?,
        interval: int(j.get("interval"), "interval", 1, 60, 5)?,
        expires_in: int(j.get("expires_in"), "expires_in", 30, 3600, 600)?,
    })
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "status")]
pub enum DevicePollResult {
    #[serde(rename = "done")]
    Done {
        account: Option<String>,
        scope: Option<String>,
        expires_at: Option<String>,
        refresh_token: bool,
    },
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "slow_down")]
    SlowDown,
    #[serde(rename = "denied")]
    Denied,
    #[serde(rename = "expired")]
    Expired,
}

/// Device code flow step two: poll once.
pub async fn device_poll(
    vault: &Vault,
    ty: &str,
    name: &str,
    device_code: &str,
) -> kv_vault::Result<DevicePollResult> {
    let (ty, name, record, cfg, secrets, _state) = load(vault, ty, name)?;
    if cfg.flow != "device_code" {
        return Err(VaultError::new(
            &format!("\"{ty}/{name}\" 不是设备码流程"),
            &format!("\"{ty}/{name}\" does not use the device code flow"),
        ));
    }
    let form = vec![
        (
            "grant_type".to_string(),
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        ),
        (
            "device_code".to_string(),
            str_req(Some(&json!(device_code)), "device_code", 2000)?,
        ),
    ];
    let r = token_request(&cfg, &secrets, form).await?;
    if is_token_response(&r) {
        let (s, got_refresh) =
            save_tokens(vault, &ty, &name, record.generation.as_deref(), &r, true)?;
        let sm = summary(&s, got_refresh);
        return Ok(DevicePollResult::Done {
            account: sm.get("account").and_then(Value::as_str).map(String::from),
            scope: sm.get("scope").and_then(Value::as_str).map(String::from),
            expires_at: sm
                .get("expires_at")
                .and_then(Value::as_str)
                .map(String::from),
            refresh_token: got_refresh,
        });
    }
    match obj(&r).get("error").and_then(Value::as_str) {
        Some("authorization_pending") => Ok(DevicePollResult::Pending),
        Some("slow_down") => Ok(DevicePollResult::SlowDown),
        Some("access_denied") => Ok(DevicePollResult::Denied),
        Some("expired_token") => Ok(DevicePollResult::Expired),
        _ => Err(remote_error(&host_of(&cfg.token_url), &r)),
    }
}

fn token_out(s: &OAuth2State) -> Value {
    json!({
        "access_token": s.access_token,
        "token_type": s.token_type.clone().unwrap_or_else(|| "Bearer".to_string()),
        "expires_at": s.expires_at.map(|e| chrono::DateTime::<chrono::Utc>::from(std::time::UNIX_EPOCH + std::time::Duration::from_millis(e.max(0) as u64)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        "scope": s.scope,
        "account": s.account,
    })
}

fn summary(s: &OAuth2State, got_refresh_token: bool) -> Value {
    json!({
        "account": s.account,
        "scope": s.scope,
        "expires_at": s.expires_at.map(|e| chrono::DateTime::<chrono::Utc>::from(std::time::UNIX_EPOCH + std::time::Duration::from_millis(e.max(0) as u64)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        "refresh_token": got_refresh_token,
    })
}

static MS_TOKEN_URL: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^https://login\.microsoftonline\.com/").unwrap());

/// Get a valid access token: return the cached one directly if still valid, otherwise refresh.
pub async fn access_token(
    vault: &Vault,
    ty: &str,
    name: &str,
    force: bool,
) -> kv_vault::Result<Value> {
    let (ty, name, record, cfg, secrets, state) = load(vault, ty, name)?;
    let gen = record.generation.clone();
    let valid = state.access_token.is_some()
        && state
            .expires_at
            .is_none_or(|e| e - EXPIRY_MARGIN_MS > now_ms());
    if valid && !force {
        return Ok(token_out(&state));
    }

    if cfg.flow == "client_credentials" {
        let mut form = vec![("grant_type".to_string(), "client_credentials".to_string())];
        if !cfg.scopes.is_empty() {
            form.push(("scope".to_string(), cfg.scopes.join(" ")));
        }
        let r = token_request(&cfg, &secrets, form).await?;
        if !is_token_response(&r) {
            return Err(remote_error(&host_of(&cfg.token_url), &r));
        }
        let (mut s, _) = save_tokens(vault, &ty, &name, gen.as_deref(), &r, false)?;
        s.account = state.account;
        return Ok(token_out(&s));
    }

    if let Some(refresh_token) = secrets.get("refresh_token") {
        let mut form = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token.clone()),
        ];
        // Microsoft v2 endpoints require scope on refresh; other providers omit it (optional per RFC 6749).
        if MS_TOKEN_URL.is_match(&cfg.token_url) && !cfg.scopes.is_empty() {
            form.push(("scope".to_string(), cfg.scopes.join(" ")));
        }
        let r = token_request(&cfg, &secrets, form).await?;
        if is_token_response(&r) {
            let (mut s, _) = save_tokens(vault, &ty, &name, gen.as_deref(), &r, false)?;
            s.account = state.account;
            return Ok(token_out(&s));
        }
        if obj(&r).get("error").and_then(Value::as_str) == Some("invalid_grant") {
            vault.patch_record(&ty, &name, Kind::Oauth2, gen.as_deref(), |rec| {
                let mut st = rec
                    .state
                    .clone()
                    .unwrap_or(json!({}))
                    .as_object()
                    .cloned()
                    .unwrap_or_default();
                st.insert("needs_reauth".into(), json!(true));
                st.remove("access_token");
                rec.state = Some(Value::Object(st));
            })?;
            let google_note = if cfg.provider == "google" {
                kv_i18n::t(
                    "；Testing 状态的 Google 应用 7 天过期",
                    "; Google apps in Testing status expire after 7 days",
                )
            } else {
                String::new()
            };
            return Err(VaultError::new(
                &format!("\"{ty}/{name}\" 的授权已失效（refresh token 被撤销或过期{google_note}）。请调用 credential_oauth_login 重新授权。"),
                &format!("Authorization for \"{ty}/{name}\" is no longer valid (the refresh token was revoked or expired{google_note}). Call credential_oauth_login to re-authorize."),
            ));
        }
        return Err(remote_error(&host_of(&cfg.token_url), &r));
    }

    // Tokens that never expire (e.g. GitHub OAuth App classic tokens).
    if state.access_token.is_some() && state.expires_at.is_none() {
        return Ok(token_out(&state));
    }
    Err(VaultError::new(&format!("\"{ty}/{name}\" 尚未授权或授权已过期，请调用 credential_oauth_login 授权。"), &format!("\"{ty}/{name}\" is not authorized or its authorization has expired; call credential_oauth_login to authorize.")))
}

pub fn public_state(record: &kv_vault::CredentialRecord) -> Value {
    let s: OAuth2State = record
        .state
        .as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    json!({
        "authorized": (s.access_token.is_some() || record.secrets.as_ref().is_some_and(|sec| sec.contains_key("refresh_token"))) && !s.needs_reauth.unwrap_or(false),
        "needs_reauth": s.needs_reauth.unwrap_or(false),
        "has_refresh_token": record.secrets.as_ref().is_some_and(|sec| sec.contains_key("refresh_token")),
        "account": s.account,
        "scope": s.scope,
        "access_token_expires_at": s.expires_at.map(|e| chrono::DateTime::<chrono::Utc>::from(std::time::UNIX_EPOCH + std::time::Duration::from_millis(e.max(0) as u64)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        "authorized_at": s.authorized_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uri_must_be_loopback() {
        assert!(validate_redirect_uri(&json!("http://127.0.0.1:8765/callback")).is_ok());
        assert!(validate_redirect_uri(&json!("http://localhost:8765/callback")).is_ok());
        assert!(
            validate_redirect_uri(&json!("https://127.0.0.1:8765/callback")).is_err(),
            "must be http, not https"
        );
        assert!(validate_redirect_uri(&json!("http://example.com/callback")).is_err());
    }

    #[test]
    fn validate_requires_client_secret_for_confidential_methods_and_client_credentials() {
        let base = json!({"client_id": "id", "token_url": "https://example.com/token", "authorization_url": "https://example.com/auth"});
        assert!(
            validate_oauth2_setup(&base, &json!({})).is_ok(),
            "public client with no secret is fine for authorization_code"
        );

        let cc = json!({"client_id": "id", "token_url": "https://example.com/token", "flow": "client_credentials"});
        assert!(
            validate_oauth2_setup(&cc, &json!({})).is_err(),
            "client_credentials requires a secret"
        );
        assert!(validate_oauth2_setup(&cc, &json!({"client_secret": "s"})).is_ok());
    }

    #[test]
    fn validate_rejects_reserved_extra_auth_params() {
        let cfg = json!({"client_id": "id", "token_url": "https://example.com/token", "authorization_url": "https://example.com/auth", "extra_auth_params": {"client_id": "sneaky"}});
        assert!(validate_oauth2_setup(&cfg, &json!({})).is_err());
    }

    #[test]
    fn device_code_flow_requires_a_device_authorization_url() {
        let cfg = json!({"client_id": "id", "token_url": "https://example.com/token", "flow": "device_code"});
        assert!(validate_oauth2_setup(&cfg, &json!({})).is_err());
    }
}
