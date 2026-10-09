//! Direct port of src/server/tools/protocols.ts.

use super::common::{
    fail, guard_overwrite, import_file, norm, ok, ok_data, purpose_desc, resolve_type,
    safe_display, wrap, CLIENT_ID_RE,
};
use crate::oauth_flow::{
    copy_to_clipboard, discover_oidc, open_in_browser, run_browser_flow, RunBrowserFlowOpts,
};
use crate::server::Server;
use crate::session::CredentialTarget;
use crate::templates::resolve_oauth_provider;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::tool;
use rmcp::tool_router;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Map, Value};

const SECRET_REBIND_MARK: &str = "[SECRET_REBIND]";
const SECRET_BINDING_KEYS: [&str; 5] = [
    "client_id",
    "token_url",
    "authorization_url",
    "device_authorization_url",
    "token_auth_method",
];

fn setup_result(r: &Value, what_zh: &str, what_en: &str) -> String {
    let ty = r.get("type").and_then(Value::as_str).unwrap_or_default();
    let name = r.get("name").and_then(Value::as_str).unwrap_or_default();
    let type_created = r
        .get("typeCreated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let replaced = r.get("replaced").and_then(Value::as_bool).unwrap_or(false);
    let mut steps = Vec::new();
    if type_created {
        steps.push(kv_i18n::t(
            &format!("凭证类型 \"{ty}\" 不存在，已先创建"),
            &format!("Credential type \"{ty}\" did not exist and was created"),
        ));
    }
    steps.push(kv_i18n::t(
        &format!(
            "{} {what_zh} \"{ty}/{name}\"",
            if replaced { "已替换" } else { "已保存" }
        ),
        &format!(
            "{} {what_en} \"{ty}/{name}\"",
            if replaced { "Replaced" } else { "Saved" }
        ),
    ));
    steps.join(&kv_i18n::t("；", "; "))
}

#[derive(Deserialize, JsonSchema)]
pub struct OauthLoginArgs {
    #[schemars(description = purpose_desc())]
    pub purpose: String,
    #[schemars(description = kv_i18n::t("凭证名（小写），如 google-work、github-bot", "Credential name (lowercase), e.g. google-work, github-bot"))]
    pub name: String,
    #[schemars(description = kv_i18n::t("凭证类型，默认 \"oauth2\"（不存在时自动创建）", "Credential type, default \"oauth2\" (created automatically if missing)"))]
    pub r#type: Option<String>,
    #[schemars(description = kv_i18n::t("服务商：内置预设（google、github、microsoft、outlook、outlook_graph、gitlab、dropbox）或模板库中的 OAuth2 模板 id；自定义服务省略", "Provider: a built-in preset (google, github, microsoft, outlook, outlook_graph, gitlab, dropbox) or an OAuth2 template id from the template library; omit for custom services"))]
    pub provider: Option<String>,
    pub flow: Option<String>,
    #[schemars(description = kv_i18n::t("OAuth client ID（新建时必填）", "OAuth client ID (required when creating)"))]
    pub client_id: Option<String>,
    #[schemars(description = kv_i18n::t("公共客户端（无 client secret，仅靠 PKCE）", "Public client (no client secret, PKCE only)"))]
    pub public_client: Option<bool>,
    #[schemars(description = kv_i18n::t("授权范围，如 [\"https://www.googleapis.com/auth/gmail.readonly\"]", "Scopes, e.g. [\"https://www.googleapis.com/auth/gmail.readonly\"]"))]
    pub scopes: Option<Vec<String>>,
    #[schemars(description = kv_i18n::t("Microsoft 租户 ID 或域名，默认 common", "Microsoft tenant ID or domain, default common"))]
    pub tenant: Option<String>,
    #[schemars(description = kv_i18n::t("OIDC issuer URL，用于自动发现端点", "OIDC issuer URL, used to discover endpoints automatically"))]
    pub issuer: Option<String>,
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub device_authorization_url: Option<String>,
    #[schemars(description = kv_i18n::t("固定回调地址（必须是本机回环地址）；默认随机端口 http://127.0.0.1:<port>/callback", "Fixed redirect URI (must be a local loopback address); default is a random port http://127.0.0.1:<port>/callback"))]
    pub redirect_uri: Option<String>,
    #[schemars(description = kv_i18n::t("授权请求附加参数", "Extra parameters for the authorization request"))]
    pub extra_auth_params: Option<std::collections::HashMap<String, String>>,
    pub token_auth_method: Option<String>,
    pub description: Option<String>,
}

#[tool_router(router = protocols_tool_router, vis = "pub")]
impl Server {
    #[tool(description = kv_i18n::t(
        "配置并完成 OAuth 2.0 授权，refresh token 加密保存，之后用 credential_access_token 获取 access token（agent 拿不到 refresh token 和 client secret）。flow：authorization_code（默认，打开浏览器，本地回调 + PKCE）、device_code（显示验证码让用户在浏览器输入）、client_credentials（机器对机器，无需用户交互）。client secret 不要通过参数传入，省略即可，会弹窗让用户输入。已存在的凭证：只传 name 即可重新授权（沿用已保存的配置）；传入新的 scopes 等参数会更新配置。",
        "Configure and complete OAuth 2.0 authorization. The refresh token is stored encrypted; afterwards use credential_access_token to get access tokens (the agent never sees the refresh token or client secret). flow: authorization_code (default; opens the browser, local callback + PKCE), device_code (shows a code for the user to enter in the browser), client_credentials (machine-to-machine, no user interaction). Do not pass the client secret as a parameter; omit it and the user will be prompted for it in a dialog. Existing credential: pass just name to re-authorize (reusing the saved configuration); passing new scopes or other parameters updates the configuration.",
    ))]
    async fn credential_oauth_login(
        &self,
        Parameters(a): Parameters<OauthLoginArgs>,
    ) -> CallToolResult {
        wrap(oauth_login_impl(self, a)).await
    }

    #[tool(description = kv_i18n::t(
        "获取短期 access token，适用于 oauth2（自动刷新）、google_service_account、github_app（installation token）、jwt（按模板签发）。返回的 token 有效期通常为 1 小时以内；长期秘密不会返回。",
        "Get a short-lived access token for oauth2 (auto-refreshed), google_service_account, github_app (installation token), or jwt (signed from the template). Returned tokens are usually valid for at most 1 hour; long-term secrets are never returned.",
    ))]
    async fn credential_access_token(
        &self,
        Parameters(a): Parameters<AccessTokenArgs>,
    ) -> CallToolResult {
        wrap(async {
            let target = CredentialTarget { r#type: a.r#type.clone(), name: Some(a.name.clone()) };
            let s = self.session.scoped(a.purpose, Some(target));
            let ty = resolve_type(&s, &a.name, a.r#type.as_deref(), &["oauth2", "google_service_account", "github_app", "jwt"]).await?;
            let mut p = Map::new();
            p.insert("type".into(), json!(ty));
            p.insert("name".into(), json!(a.name));
            p.insert("scopes".into(), json!(a.scopes));
            p.insert("repositories".into(), json!(a.repositories));
            p.insert("permissions".into(), json!(a.permissions));
            p.insert("force".into(), json!(a.force_refresh == Some(true)));
            #[derive(Deserialize, serde::Serialize)]
            struct R {
                access_token: String,
                account: Option<String>,
                #[serde(flatten)]
                rest: Map<String, Value>,
            }
            let r: R = s.request("accessToken", p).await?;
            if a.format.as_deref() == Some("xoauth2") {
                let Some(username) = a.username.clone().or_else(|| r.account.clone()) else {
                    return Ok(fail(kv_i18n::t("无法确定邮箱地址：请传 username，或在授权 scope 中包含 openid email。", "Cannot determine the email address: pass username, or include openid email in the authorization scopes.")));
                };
                let x = crate::mail::xoauth2(&username, &r.access_token);
                let mut data = r.rest.clone();
                data.insert("access_token".into(), json!(r.access_token));
                data.insert("account".into(), json!(r.account));
                data.insert("username".into(), json!(username));
                data.insert("xoauth2".into(), json!(x));
                return Ok(ok_data(kv_i18n::t("access token（含 XOAUTH2）：", "access token (with XOAUTH2):"), data));
            }
            let mut data = r.rest.clone();
            data.insert("access_token".into(), json!(r.access_token));
            data.insert("account".into(), json!(r.account));
            Ok(ok_data(kv_i18n::t("access token：", "access token:"), data))
        })
        .await
    }

    #[tool(description = kv_i18n::t(
        "导入 Google 服务账号 JSON 密钥文件（内容不会进入 AI 上下文）。之后用 credential_access_token 获取 access token。",
        "Import a Google service account JSON key file (its contents never enter the AI context). Afterwards use credential_access_token to get access tokens.",
    ))]
    async fn credential_setup_google_service_account(
        &self,
        Parameters(a): Parameters<SetupGsaArgs>,
    ) -> CallToolResult {
        wrap(async {
            let ty = a
                .r#type
                .clone()
                .unwrap_or_else(|| "google_service_account".to_string());
            let target = CredentialTarget {
                r#type: Some(ty.clone()),
                name: Some(a.name.clone()),
            };
            let s = self.session.scoped(a.purpose.clone(), Some(target));
            let exists = guard_overwrite(&s, &ty, &a.name, a.overwrite).await?;
            let label = format!("{}/{}", norm(&ty), norm(&a.name));
            let f = import_file(&a.key_file, &label).await?;
            let mut p = Map::new();
            p.insert("kind".into(), json!("google_service_account"));
            p.insert("type".into(), json!(ty));
            p.insert("name".into(), json!(a.name));
            p.insert(
                "config".into(),
                json!({"scopes": a.scopes, "subject": a.subject}),
            );
            p.insert("secrets".into(), json!({"key_json": f.content}));
            p.insert("description".into(), json!(a.description));
            p.insert(
                "typeDescription".into(),
                json!(kv_i18n::t("Google 服务账号", "Google service account")),
            );
            p.insert("overwrite".into(), json!(exists));
            let r: Value = s.request("setupProtocol", p).await?;
            let mut tp = Map::new();
            tp.insert("type".into(), json!(ty));
            tp.insert("name".into(), json!(a.name));
            tp.insert("force".into(), json!(true));
            #[derive(Deserialize)]
            struct Tok {
                account: Option<String>,
            }
            let verify = match s.request::<Tok>("accessToken", tp).await {
                Ok(tok) => {
                    let account = tok.account.unwrap_or_default();
                    kv_i18n::t(
                        &format!("已验证可以获取 token（{account}）"),
                        &format!("verified that a token can be obtained ({account})"),
                    )
                }
                Err(e) => kv_i18n::t(
                    &format!("⚠️ 已保存，但获取 token 失败：{}", e.0),
                    &format!("⚠️ saved, but getting a token failed: {}", e.0),
                ),
            };
            Ok(ok(kv_i18n::t(
                &format!(
                    "{}；{verify}。建议删除原密钥文件 {}。",
                    setup_result(&r, "Google 服务账号", "Google service account"),
                    f.path
                ),
                &format!(
                    "{}; {verify}. Consider deleting the original key file {}.",
                    setup_result(&r, "Google 服务账号", "Google service account"),
                    f.path
                ),
            )))
        })
        .await
    }

    #[tool(description = kv_i18n::t(
        "设置 GitHub App（私钥从 .pem 文件导入）。之后用 credential_access_token 获取 1 小时有效的 installation token。",
        "Set up a GitHub App (private key imported from a .pem file). Afterwards use credential_access_token to get installation tokens valid for 1 hour.",
    ))]
    async fn credential_setup_github_app(
        &self,
        Parameters(a): Parameters<SetupGithubAppArgs>,
    ) -> CallToolResult {
        wrap(async {
            let ty = a.r#type.clone().unwrap_or_else(|| "github_app".to_string());
            let target = CredentialTarget { r#type: Some(ty.clone()), name: Some(a.name.clone()) };
            let s = self.session.scoped(a.purpose.clone(), Some(target));
            let exists = guard_overwrite(&s, &ty, &a.name, a.overwrite).await?;
            let label = format!("{}/{}", norm(&ty), norm(&a.name));
            let f = import_file(&a.private_key_file, &label).await?;
            let mut p = Map::new();
            p.insert("kind".into(), json!("github_app"));
            p.insert("type".into(), json!(ty));
            p.insert("name".into(), json!(a.name));
            p.insert("config".into(), json!({"app_id": a.app_id, "installation_id": a.installation_id, "api_base_url": a.api_base_url}));
            p.insert("secrets".into(), json!({"private_key": f.content}));
            p.insert("description".into(), json!(a.description));
            p.insert("typeDescription".into(), json!("GitHub App"));
            p.insert("overwrite".into(), json!(exists));
            let r: Value = s.request("setupProtocol", p).await?;
            let mut tp = Map::new();
            tp.insert("type".into(), json!(ty));
            tp.insert("name".into(), json!(a.name));
            tp.insert("force".into(), json!(true));
            let verify = match s.request::<Value>("accessToken", tp).await {
                Ok(_) => kv_i18n::t("已验证可以获取 installation token", "verified that an installation token can be obtained"),
                Err(e) => kv_i18n::t(&format!("⚠️ 已保存，但获取 token 失败：{}", e.0), &format!("⚠️ saved, but getting a token failed: {}", e.0)),
            };
            Ok(ok(kv_i18n::t(
                &format!("{}；{verify}。建议删除原私钥文件 {}。", setup_result(&r, "GitHub App", "GitHub App"), f.path),
                &format!("{}; {verify}. Consider deleting the original private key file {}.", setup_result(&r, "GitHub App", "GitHub App"), f.path),
            )))
        })
        .await
    }

    #[tool(description = kv_i18n::t(
        "设置 JWT 签发模板（如 App Store Connect API：algorithm=ES256, issuer=Issuer ID, key_id=Key ID, audience=appstoreconnect-v1）。私钥从文件导入；HS* 算法的密钥由用户在弹窗输入。之后用 credential_access_token 获取签好的短期 JWT。",
        "Set up a JWT signing template (e.g. App Store Connect API: algorithm=ES256, issuer=Issuer ID, key_id=Key ID, audience=appstoreconnect-v1). Private keys are imported from a file; for HS* algorithms the user enters the key in a dialog. Afterwards use credential_access_token to get signed short-lived JWTs.",
    ))]
    async fn credential_setup_jwt(
        &self,
        Parameters(a): Parameters<SetupJwtArgs>,
    ) -> CallToolResult {
        wrap(async {
            let ty = a.r#type.clone().unwrap_or_else(|| "jwt".to_string());
            let target = CredentialTarget { r#type: Some(ty.clone()), name: Some(a.name.clone()) };
            let s = self.session.scoped(a.purpose.clone(), Some(target));
            let exists = guard_overwrite(&s, &ty, &a.name, a.overwrite).await?;
            let (key, source) = if a.algorithm.starts_with("HS") {
                let prompted = crate::dialog::prompt_secret(&kv_i18n::t(&format!("请输入 JWT 签名密钥（{}）：\n\n凭证：{}/{}", a.algorithm, norm(&ty), norm(&a.name)), &format!("Enter the JWT signing key ({}):\n\nCredential: {}/{}", a.algorithm, norm(&ty), norm(&a.name)))).await;
                match prompted {
                    Some(k) => (k, String::new()),
                    None => return Ok(fail(kv_i18n::t("用户取消了输入，未保存。", "Input cancelled by the user; nothing was saved."))),
                }
            } else {
                let Some(key_file) = &a.key_file else {
                    return Ok(fail(kv_i18n::t(&format!("{} 需要 key_file（私钥文件）。", a.algorithm), &format!("{} requires key_file (private key file).", a.algorithm))));
                };
                let f = import_file(key_file, &format!("{}/{}", norm(&ty), norm(&a.name))).await?;
                (f.content, f.path)
            };
            let mut p = Map::new();
            p.insert("kind".into(), json!("jwt"));
            p.insert("type".into(), json!(ty));
            p.insert("name".into(), json!(a.name));
            p.insert("config".into(), json!({"algorithm": a.algorithm, "issuer": a.issuer, "subject": a.subject, "audience": a.audience, "key_id": a.key_id, "lifetime_seconds": a.lifetime_seconds, "claims": a.claims, "header": a.header}));
            p.insert("secrets".into(), json!({"key": key}));
            p.insert("description".into(), json!(a.description));
            p.insert("typeDescription".into(), json!(kv_i18n::t("JWT 签发", "JWT signing")));
            p.insert("overwrite".into(), json!(exists));
            let r: Value = s.request("setupProtocol", p).await?;
            let tail = if source.is_empty() { String::new() } else { kv_i18n::t(&format!("建议删除原私钥文件 {source}。"), &format!(" Consider deleting the original private key file {source}.")) };
            Ok(ok(kv_i18n::t(&format!("{}。{tail}", setup_result(&r, "JWT 模板", "JWT template")), &format!("{}.{tail}", setup_result(&r, "JWT 模板", "JWT template")))))
        })
        .await
    }

    #[tool(description = kv_i18n::t(
        "保存两步验证（TOTP）种子：用户在弹窗中粘贴 Base32 密钥或 otpauth:// 链接。之后用 credential_totp_code 获取当前验证码。",
        "Save a two-factor (TOTP) seed: the user pastes the Base32 key or otpauth:// link into a dialog. Afterwards use credential_totp_code to get the current code.",
    ))]
    async fn credential_setup_totp(
        &self,
        Parameters(a): Parameters<SetupTotpArgs>,
    ) -> CallToolResult {
        wrap(async {
            let ty = a.r#type.clone().unwrap_or_else(|| "totp".to_string());
            let target = CredentialTarget { r#type: Some(ty.clone()), name: Some(a.name.clone()) };
            let s = self.session.scoped(a.purpose.clone(), Some(target));
            let exists = guard_overwrite(&s, &ty, &a.name, a.overwrite).await?;
            let prompted = crate::dialog::prompt_secret(&kv_i18n::t(&format!("请粘贴两步验证密钥（Base32）或 otpauth:// 链接：\n\n凭证：{}/{}", norm(&ty), norm(&a.name)), &format!("Paste the two-factor key (Base32) or otpauth:// link:\n\nCredential: {}/{}", norm(&ty), norm(&a.name)))).await;
            let Some(secret) = prompted else {
                return Ok(fail(kv_i18n::t("用户取消了输入，未保存。", "Input cancelled by the user; nothing was saved.")));
            };
            let mut p = Map::new();
            p.insert("kind".into(), json!("totp"));
            p.insert("type".into(), json!(ty));
            p.insert("name".into(), json!(a.name));
            p.insert("config".into(), json!({"issuer": a.issuer, "account": a.account, "digits": a.digits, "period": a.period, "algorithm": a.algorithm}));
            p.insert("secrets".into(), json!({"secret": secret}));
            p.insert("description".into(), json!(a.description));
            p.insert("typeDescription".into(), json!(kv_i18n::t("两步验证（TOTP）", "Two-factor authentication (TOTP)")));
            p.insert("overwrite".into(), json!(exists));
            let r: Value = s.request("setupProtocol", p).await?;
            let mut tp = Map::new();
            tp.insert("type".into(), json!(ty));
            tp.insert("name".into(), json!(a.name));
            #[derive(Deserialize)]
            struct Code {
                code: String,
                remaining_seconds: i64,
            }
            let code: Code = s.request("totp", tp).await?;
            Ok(ok(kv_i18n::t(
                &format!("{}。当前验证码 {}（{} 秒后刷新），可与验证器 App 对照确认。", setup_result(&r, "TOTP", "TOTP"), code.code, code.remaining_seconds),
                &format!("{}. Current code {} (refreshes in {} s); compare it with your authenticator app to confirm.", setup_result(&r, "TOTP", "TOTP"), code.code, code.remaining_seconds),
            )))
        })
        .await
    }

    #[tool(description = kv_i18n::t("获取 TOTP 当前验证码（以及剩余有效秒数；即将过期时附带下一个验证码）", "Get the current TOTP code (plus remaining seconds of validity; includes the next code when it is about to expire)"))]
    async fn credential_totp_code(
        &self,
        Parameters(a): Parameters<TotpCodeArgs>,
    ) -> CallToolResult {
        wrap(async {
            let target = CredentialTarget {
                r#type: a.r#type.clone(),
                name: Some(a.name.clone()),
            };
            let s = self.session.scoped(a.purpose, Some(target));
            let ty = resolve_type(&s, &a.name, a.r#type.as_deref(), &["totp"]).await?;
            let mut p = Map::new();
            p.insert("type".into(), json!(ty));
            p.insert("name".into(), json!(a.name));
            #[derive(Deserialize, serde::Serialize)]
            struct R {
                code: String,
                next_code: Option<String>,
                #[serde(flatten)]
                rest: Map<String, Value>,
            }
            let r: R = s.request("totp", p).await?;
            Ok(ok_data(kv_i18n::t("验证码：", "Code:"), &r))
        })
        .await
    }

    #[tool(description = kv_i18n::t(
        "保存 AWS 长期 access key（secret key 由用户在弹窗输入），之后用 credential_aws_credentials 通过 STS 获取临时凭证。可配置 role_arn 以 AssumeRole；可关联一个 TOTP 凭证自动完成 MFA。",
        "Save a long-term AWS access key (the user enters the secret key in a dialog); afterwards use credential_aws_credentials to get temporary credentials via STS. Optionally set role_arn to AssumeRole, and link a TOTP credential to complete MFA automatically.",
    ))]
    async fn credential_setup_aws(
        &self,
        Parameters(a): Parameters<SetupAwsArgs>,
    ) -> CallToolResult {
        wrap(async {
            let ty = a.r#type.clone().unwrap_or_else(|| "aws".to_string());
            let target = CredentialTarget { r#type: Some(ty.clone()), name: Some(a.name.clone()) };
            let s = self.session.scoped(a.purpose.clone(), Some(target));
            let exists = guard_overwrite(&s, &ty, &a.name, a.overwrite).await?;
            let mfa_totp = match &a.mfa_totp_name {
                Some(n) => Some(json!({"type": resolve_type(&s, n, None, &["totp"]).await?, "name": n})),
                None => None,
            };
            let region = safe_display(a.region.as_deref().unwrap_or("us-east-1"), &regex::Regex::new(r"^[a-z]{2}(-gov)?-[a-z]+-\d$").unwrap(), "region")?;
            let access_key_id = safe_display(&a.access_key_id, &regex::Regex::new(r"^AKIA[A-Z0-9]{12,124}$").unwrap(), &kv_i18n::t("access_key_id（应为 AKIA 开头的长期密钥）", "access_key_id (must be a long-term key starting with AKIA)"))?;
            let secret = match &a.secret_access_key {
                Some(s) if !s.is_empty() => Some(s.clone()),
                _ => {
                    crate::dialog::prompt_secret(&kv_i18n::t(
                        &format!("请输入 AWS secret access key：\n\n凭证：{}/{}\nAccess key ID：{access_key_id}\n\n它只用于签名发往 sts.{region}.amazonaws.com 的请求。", norm(&ty), norm(&a.name)),
                        &format!("Enter the AWS secret access key:\n\nCredential: {}/{}\nAccess key ID: {access_key_id}\n\nIt is only used to sign requests to sts.{region}.amazonaws.com.", norm(&ty), norm(&a.name)),
                    ))
                    .await
                }
            };
            let Some(secret) = secret else {
                return Ok(fail(kv_i18n::t("用户取消了输入，未保存。", "Input cancelled by the user; nothing was saved.")));
            };
            let mut p = Map::new();
            p.insert("kind".into(), json!("aws"));
            p.insert("type".into(), json!(ty));
            p.insert("name".into(), json!(a.name));
            p.insert(
                "config".into(),
                json!({
                    "access_key_id": a.access_key_id, "region": region, "role_arn": a.role_arn, "external_id": a.external_id,
                    "role_session_name": a.role_session_name, "duration_seconds": a.duration_seconds, "mfa_serial": a.mfa_serial, "mfa_totp": mfa_totp,
                }),
            );
            p.insert("secrets".into(), json!({"secret_access_key": secret}));
            p.insert("description".into(), json!(a.description));
            p.insert("typeDescription".into(), json!("AWS"));
            p.insert("overwrite".into(), json!(exists));
            let r: Value = s.request("setupProtocol", p).await?;
            let mut tp = Map::new();
            tp.insert("type".into(), json!(ty));
            tp.insert("name".into(), json!(a.name));
            tp.insert("force".into(), json!(true));
            #[derive(Deserialize)]
            struct C {
                expiration: String,
            }
            let verify = match s.request::<C>("aws", tp).await {
                Ok(c) => kv_i18n::t(&format!("已验证可以获取临时凭证（有效至 {}）", c.expiration), &format!("verified that temporary credentials can be obtained (valid until {})", c.expiration)),
                Err(e) => kv_i18n::t(&format!("⚠️ 已保存，但获取临时凭证失败：{}", e.0), &format!("⚠️ saved, but getting temporary credentials failed: {}", e.0)),
            };
            Ok(ok(kv_i18n::t(&format!("{}；{verify}。", setup_result(&r, "AWS 凭证", "AWS credential")), &format!("{}; {verify}.", setup_result(&r, "AWS 凭证", "AWS credential")))))
        })
        .await
    }

    #[tool(description = kv_i18n::t(
        "通过 STS 获取 AWS 临时凭证（AccessKeyId / SecretAccessKey / SessionToken），有缓存。使用时设置环境变量 AWS_ACCESS_KEY_ID、AWS_SECRET_ACCESS_KEY、AWS_SESSION_TOKEN、AWS_REGION。",
        "Get temporary AWS credentials (AccessKeyId / SecretAccessKey / SessionToken) via STS, with caching. To use them, set the environment variables AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_REGION.",
    ))]
    async fn credential_aws_credentials(
        &self,
        Parameters(a): Parameters<AwsCredentialsArgs>,
    ) -> CallToolResult {
        wrap(async {
            let target = CredentialTarget {
                r#type: a.r#type.clone(),
                name: Some(a.name.clone()),
            };
            let s = self.session.scoped(a.purpose, Some(target));
            let ty = resolve_type(&s, &a.name, a.r#type.as_deref(), &["aws"]).await?;
            let mut p = Map::new();
            p.insert("type".into(), json!(ty));
            p.insert("name".into(), json!(a.name));
            p.insert("duration_seconds".into(), json!(a.duration_seconds));
            p.insert("force".into(), json!(a.force_refresh == Some(true)));
            #[derive(Deserialize, serde::Serialize)]
            struct C {
                access_key_id: String,
                secret_access_key: String,
                session_token: String,
                #[serde(flatten)]
                rest: Map<String, Value>,
            }
            let c: C = s.request("aws", p).await?;
            Ok(ok_data(
                kv_i18n::t("AWS 临时凭证：", "AWS temporary credentials:"),
                &c,
            ))
        })
        .await
    }
}

#[derive(Deserialize, JsonSchema)]
pub struct AccessTokenArgs {
    #[schemars(description = purpose_desc())]
    pub purpose: String,
    pub name: String,
    #[schemars(description = kv_i18n::t("凭证类型；省略时按名字自动查找", "Credential type; looked up by name if omitted"))]
    pub r#type: Option<String>,
    #[schemars(description = kv_i18n::t("仅 google_service_account：本次请求的 scope（默认用设置时的）", "google_service_account only: scopes for this request (defaults to those set at setup)"))]
    pub scopes: Option<Vec<String>>,
    #[schemars(description = kv_i18n::t("仅 github_app：把 token 限制到这些仓库名", "github_app only: restrict the token to these repository names"))]
    pub repositories: Option<Vec<String>>,
    #[schemars(description = kv_i18n::t("仅 github_app：收窄权限，如 {\"contents\": \"read\"}", "github_app only: narrow the permissions, e.g. {\"contents\": \"read\"}"))]
    pub permissions: Option<std::collections::HashMap<String, String>>,
    #[schemars(description = kv_i18n::t("忽略缓存，强制获取新 token", "Ignore the cache and force a new token"))]
    pub force_refresh: Option<bool>,
    #[schemars(description = kv_i18n::t("xoauth2：额外返回 IMAP/SMTP/POP 的 SASL XOAUTH2 认证字符串（Gmail、Outlook 邮箱用）", "xoauth2: also return the SASL XOAUTH2 auth string for IMAP/SMTP/POP (for Gmail and Outlook mail)"))]
    pub format: Option<String>,
    #[schemars(description = kv_i18n::t("仅 format=xoauth2：邮箱地址；省略则使用授权时识别出的账号", "format=xoauth2 only: email address; defaults to the account identified during authorization"))]
    pub username: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct SetupGsaArgs {
    #[schemars(description = purpose_desc())]
    pub purpose: String,
    pub name: String,
    pub r#type: Option<String>,
    #[schemars(description = kv_i18n::t("服务账号 JSON 密钥文件路径", "Path to the service account JSON key file"))]
    pub key_file: String,
    #[schemars(description = kv_i18n::t("默认 scope，省略则为 cloud-platform", "Default scopes; cloud-platform if omitted"))]
    pub scopes: Option<Vec<String>>,
    #[schemars(description = kv_i18n::t("域范围授权时要模拟的 Workspace 用户邮箱", "Workspace user email to impersonate with domain-wide delegation"))]
    pub subject: Option<String>,
    pub description: Option<String>,
    pub overwrite: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct SetupGithubAppArgs {
    #[schemars(description = purpose_desc())]
    pub purpose: String,
    pub name: String,
    pub r#type: Option<String>,
    #[schemars(description = kv_i18n::t("App ID（数字）或 Client ID", "App ID (numeric) or Client ID"))]
    pub app_id: String,
    #[schemars(description = kv_i18n::t("App 私钥 .pem 文件路径", "Path to the App private key .pem file"))]
    pub private_key_file: String,
    #[schemars(description = kv_i18n::t("installation ID；App 只装在一个账号上时可省略", "Installation ID; may be omitted if the App is installed on only one account"))]
    pub installation_id: Option<String>,
    #[schemars(description = kv_i18n::t("GitHub Enterprise Server 的 API 地址，默认 https://api.github.com", "API base URL for GitHub Enterprise Server, default https://api.github.com"))]
    pub api_base_url: Option<String>,
    pub description: Option<String>,
    pub overwrite: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct SetupJwtArgs {
    #[schemars(description = purpose_desc())]
    pub purpose: String,
    pub name: String,
    pub r#type: Option<String>,
    pub algorithm: String,
    #[schemars(description = kv_i18n::t("私钥 PEM/.p8 文件路径（非 HS* 算法必填）", "Path to the private key PEM/.p8 file (required for non-HS* algorithms)"))]
    pub key_file: Option<String>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub audience: Option<Value>,
    #[schemars(description = kv_i18n::t("header 中的 kid", "kid in the header"))]
    pub key_id: Option<String>,
    #[schemars(description = kv_i18n::t("有效期，默认 1200（20 分钟）", "Lifetime in seconds, default 1200 (20 minutes)"))]
    pub lifetime_seconds: Option<i64>,
    #[schemars(description = kv_i18n::t("其他固定声明", "Additional fixed claims"))]
    pub claims: Option<Map<String, Value>>,
    #[schemars(description = kv_i18n::t("其他 header 字段", "Additional header fields"))]
    pub header: Option<Map<String, Value>>,
    pub description: Option<String>,
    pub overwrite: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct SetupTotpArgs {
    #[schemars(description = purpose_desc())]
    pub purpose: String,
    pub name: String,
    pub r#type: Option<String>,
    #[schemars(description = kv_i18n::t("服务名，如 GitHub", "Service name, e.g. GitHub"))]
    pub issuer: Option<String>,
    pub account: Option<String>,
    #[schemars(description = kv_i18n::t("位数，默认 6", "Number of digits, default 6"))]
    pub digits: Option<i64>,
    #[schemars(description = kv_i18n::t("周期秒数，默认 30", "Period in seconds, default 30"))]
    pub period: Option<i64>,
    pub algorithm: Option<String>,
    pub description: Option<String>,
    pub overwrite: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct TotpCodeArgs {
    #[schemars(description = purpose_desc())]
    pub purpose: String,
    pub name: String,
    pub r#type: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct SetupAwsArgs {
    #[schemars(description = purpose_desc())]
    pub purpose: String,
    pub name: String,
    pub r#type: Option<String>,
    #[schemars(description = kv_i18n::t("Access key ID（AKIA 开头）", "Access key ID (starts with AKIA)"))]
    pub access_key_id: String,
    #[schemars(description = kv_i18n::t("仅当用户已在对话中给出时传入；否则省略，由用户在弹窗输入", "Pass only if the user already gave it in the chat; otherwise omit and the user enters it in a dialog"))]
    pub secret_access_key: Option<String>,
    #[schemars(description = kv_i18n::t("STS 所用区域，默认 us-east-1", "Region used for STS, default us-east-1"))]
    pub region: Option<String>,
    #[schemars(description = kv_i18n::t("要扮演的 IAM 角色 ARN", "ARN of the IAM role to assume"))]
    pub role_arn: Option<String>,
    pub external_id: Option<String>,
    pub role_session_name: Option<String>,
    #[schemars(description = kv_i18n::t("临时凭证有效期，默认 3600", "Lifetime of temporary credentials in seconds, default 3600"))]
    pub duration_seconds: Option<i64>,
    #[schemars(description = kv_i18n::t("MFA 设备 ARN", "MFA device ARN"))]
    pub mfa_serial: Option<String>,
    #[schemars(description = kv_i18n::t("用于生成 MFA 验证码的 TOTP 凭证名", "Name of the TOTP credential used to generate MFA codes"))]
    pub mfa_totp_name: Option<String>,
    pub description: Option<String>,
    pub overwrite: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct AwsCredentialsArgs {
    #[schemars(description = purpose_desc())]
    pub purpose: String,
    pub name: String,
    pub r#type: Option<String>,
    #[schemars(description = kv_i18n::t("有效期（秒）；指定时不使用缓存", "Lifetime in seconds; bypasses the cache when specified"))]
    pub duration_seconds: Option<i64>,
    pub force_refresh: Option<bool>,
}

#[derive(Debug, Clone, serde::Serialize, Deserialize)]
struct OAuthConfigView {
    provider: String,
    flow: String,
    client_id: String,
    token_url: String,
    #[serde(default)]
    authorization_url: Option<String>,
    #[serde(default)]
    device_authorization_url: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    extra_auth_params: std::collections::HashMap<String, String>,
    token_auth_method: String,
    #[serde(default)]
    redirect_uri: Option<String>,
}

async fn oauth_login_impl(server: &Server, a: OauthLoginArgs) -> Result<CallToolResult, String> {
    let ty = a.r#type.clone().unwrap_or_else(|| "oauth2".to_string());
    let target = CredentialTarget {
        r#type: Some(ty.clone()),
        name: Some(a.name.clone()),
    };
    let s = server.session.scoped(a.purpose.clone(), Some(target));
    let existing = super::common::try_info(&s, &ty, &a.name)
        .await
        .map_err(String::from)?;
    if let Some(e) = &existing {
        if e.kind != "oauth2" {
            return Ok(fail(kv_i18n::t(
                &format!("\"{}/{}\" 已存在且不是 OAuth 凭证。", e.r#type, e.name),
                &format!(
                    "\"{}/{}\" already exists and is not an OAuth credential.",
                    e.r#type, e.name
                ),
            )));
        }
    }
    let base: OAuthConfigView = existing
        .as_ref()
        .and_then(|e| e.config.clone())
        .and_then(|c| serde_json::from_value(Value::Object(c)).ok())
        .unwrap_or(OAuthConfigView {
            provider: String::new(),
            flow: String::new(),
            client_id: String::new(),
            token_url: String::new(),
            authorization_url: None,
            device_authorization_url: None,
            scopes: vec![],
            extra_auth_params: Default::default(),
            token_auth_method: String::new(),
            redirect_uri: None,
        });
    let label = format!("{}/{}", norm(&ty), norm(&a.name));

    let wants_change = a.provider.is_some()
        || a.flow.is_some()
        || a.client_id.is_some()
        || a.public_client.is_some()
        || a.scopes.is_some()
        || a.tenant.is_some()
        || a.issuer.is_some()
        || a.authorization_url.is_some()
        || a.token_url.is_some()
        || a.device_authorization_url.is_some()
        || a.redirect_uri.is_some()
        || a.extra_auth_params.is_some()
        || a.token_auth_method.is_some();

    let mut setup_msg: Option<String> = None;
    if existing.is_none() || wants_change {
        let provider_changed =
            a.provider.is_some() && a.provider.as_deref() != Some(base.provider.as_str());
        let provider = a.provider.clone().unwrap_or_else(|| {
            if existing.is_none() && base.provider.is_empty() {
                if a.issuer.is_some() {
                    "oidc".to_string()
                } else {
                    "custom".to_string()
                }
            } else {
                base.provider.clone()
            }
        });
        let preset = if a.provider.is_some() || a.tenant.is_some() {
            resolve_oauth_provider(&provider, a.tenant.as_deref())?
        } else {
            None
        };
        if a.provider.is_some() && preset.is_none() {
            return Ok(fail(kv_i18n::t(
                &format!("未知的 provider \"{}\"。可用：{}；其他服务请用 issuer 或手动指定端点。", a.provider.clone().unwrap_or_default(), crate::templates::oauth_provider_names()),
                &format!("Unknown provider \"{}\". Available: {}; for other services use issuer or specify the endpoints manually.", a.provider.clone().unwrap_or_default(), crate::templates::oauth_provider_names()),
            )));
        }
        let from_base = if provider_changed { None } else { Some(&base) };
        let discovered = match &a.issuer {
            Some(iss) => Some(discover_oidc(iss).await?),
            None => None,
        };
        let flow = a.flow.clone().unwrap_or_else(|| {
            if base.flow.is_empty() {
                "authorization_code".to_string()
            } else {
                base.flow.clone()
            }
        });
        let mut scopes: Vec<String> = a.scopes.clone().unwrap_or_else(|| {
            if base.scopes.is_empty() {
                preset
                    .as_ref()
                    .map(|p| p.default_scopes.clone())
                    .unwrap_or_default()
            } else {
                base.scopes.clone()
            }
        });
        if flow != "client_credentials" {
            if let Some(p) = &preset {
                for req in &p.required_scopes {
                    if !scopes.contains(req) {
                        scopes.push(req.clone());
                    }
                }
            }
        }
        let public_client = a.public_client.unwrap_or_else(|| {
            a.token_auth_method.as_deref() == Some("none")
                || (a.token_auth_method.is_none() && base.token_auth_method == "none")
        });
        let client_id = a.client_id.clone().or_else(|| {
            if base.client_id.is_empty() {
                None
            } else {
                Some(base.client_id.clone())
            }
        });
        let authorization_url = a
            .authorization_url
            .clone()
            .or(discovered
                .as_ref()
                .and_then(|d| d.authorization_url.clone()))
            .or_else(|| preset.as_ref().map(|p| p.authorization_url.clone()))
            .or_else(|| from_base.and_then(|b| b.authorization_url.clone()));
        let token_url = a
            .token_url
            .clone()
            .or(discovered.as_ref().map(|d| d.token_url.clone()))
            .or_else(|| preset.as_ref().map(|p| p.token_url.clone()))
            .or_else(|| {
                from_base
                    .map(|b| b.token_url.clone())
                    .filter(|s| !s.is_empty())
            });
        let device_authorization_url = a
            .device_authorization_url
            .clone()
            .or(discovered
                .as_ref()
                .and_then(|d| d.device_authorization_url.clone()))
            .or_else(|| {
                preset
                    .as_ref()
                    .and_then(|p| p.device_authorization_url.clone())
            })
            .or_else(|| from_base.and_then(|b| b.device_authorization_url.clone()));
        let extra_auth_params = a
            .extra_auth_params
            .clone()
            .or_else(|| {
                if provider_changed {
                    None
                } else {
                    Some(base.extra_auth_params.clone()).filter(|m| !m.is_empty())
                }
            })
            .or_else(|| preset.as_ref().map(|p| p.extra_auth_params.clone()))
            .unwrap_or_default();
        let token_auth_method = if public_client {
            "none".to_string()
        } else {
            a.token_auth_method
                .clone()
                .or_else(|| {
                    if base.token_auth_method != "none" && !base.token_auth_method.is_empty() {
                        Some(base.token_auth_method.clone())
                    } else {
                        None
                    }
                })
                .or_else(|| {
                    preset
                        .as_ref()
                        .and_then(|p| p.token_auth_method.map(String::from))
                })
                .unwrap_or_else(|| "client_secret_post".to_string())
        };
        let redirect_uri = a.redirect_uri.clone().or_else(|| base.redirect_uri.clone());

        let Some(client_id) = client_id.filter(|s| !s.is_empty()) else {
            return Ok(fail(kv_i18n::t(
                "新建 OAuth 凭证需要 client_id。",
                "client_id is required to create an OAuth credential.",
            )));
        };
        let Some(token_url) = token_url.filter(|s| !s.is_empty()) else {
            return Ok(fail(kv_i18n::t(
                "缺少 token_url：请指定 provider、issuer 或 token_url。",
                "Missing token_url: specify provider, issuer, or token_url.",
            )));
        };
        if flow == "authorization_code" && authorization_url.is_none() {
            return Ok(fail(kv_i18n::t(
                "授权码流程缺少 authorization_url。",
                "The authorization code flow requires authorization_url.",
            )));
        }
        if flow == "device_code" && device_authorization_url.is_none() {
            return Ok(fail(kv_i18n::t("该服务商没有设备码端点，请改用 authorization_code 或指定 device_authorization_url。", "This provider has no device code endpoint; use authorization_code or specify device_authorization_url.")));
        }
        if flow == "client_credentials" && public_client {
            return Ok(fail(kv_i18n::t(
                "client_credentials 流程需要 client secret。",
                "The client_credentials flow requires a client secret.",
            )));
        }
        let client_id_display = safe_display(&client_id, &CLIENT_ID_RE, "client_id")?;
        let token_host = super::common::https_host(&token_url, "token_url")?;

        if existing.is_some() {
            guard_overwrite(&s, &ty, &a.name, Some(true))
                .await
                .map_err(String::from)?;
        }

        let config = json!({
            "provider": provider, "flow": flow, "client_id": client_id, "authorization_url": authorization_url,
            "token_url": token_url, "device_authorization_url": device_authorization_url, "scopes": scopes,
            "extra_auth_params": extra_auth_params, "token_auth_method": token_auth_method, "redirect_uri": redirect_uri,
        });
        let same_binding = existing.is_some()
            && SECRET_BINDING_KEYS.iter().all(|k| {
                let b = match *k {
                    "client_id" => json!(base.client_id),
                    "token_url" => json!(base.token_url),
                    "authorization_url" => json!(base.authorization_url),
                    "device_authorization_url" => json!(base.device_authorization_url),
                    _ => json!(base.token_auth_method),
                };
                b == *config.get(k).unwrap_or(&Value::Null)
            });
        let ask_secret = || async {
            let msg = kv_i18n::t(
                &format!("请输入 OAuth client secret\n\n凭证：{label}\nclient_id：{client_id_display}\n它只会被发送到：{token_host}"),
                &format!("Enter the OAuth client secret\n\nCredential: {label}\nclient_id: {client_id_display}\nIt will only be sent to: {token_host}"),
            );
            crate::dialog::prompt_secret(&msg).await.ok_or_else(|| {
                kv_i18n::t(
                    "用户取消了输入，未保存。",
                    "Input cancelled by the user; nothing was saved.",
                )
            })
        };
        let mut client_secret = if !public_client && !same_binding {
            Some(ask_secret().await?)
        } else {
            None
        };

        fn setup_params(
            ty: &str,
            name: &str,
            config: &Value,
            secret: Option<&str>,
            reuse: bool,
            description: &Option<String>,
            overwrite: bool,
        ) -> Map<String, Value> {
            let mut p = Map::new();
            p.insert("kind".into(), json!("oauth2"));
            p.insert("type".into(), json!(ty));
            p.insert("name".into(), json!(name));
            p.insert("config".into(), config.clone());
            p.insert(
                "secrets".into(),
                secret
                    .map(|cs| json!({"client_secret": cs}))
                    .unwrap_or_else(|| json!({})),
            );
            p.insert("reuseClientSecret".into(), json!(reuse));
            p.insert("description".into(), json!(description));
            p.insert(
                "typeDescription".into(),
                json!(kv_i18n::t("OAuth 2.0 授权", "OAuth 2.0 authorization")),
            );
            p.insert("overwrite".into(), json!(overwrite));
            p
        }
        let p = setup_params(
            &ty,
            &a.name,
            &config,
            client_secret.as_deref(),
            !public_client && same_binding,
            &a.description,
            existing.is_some(),
        );
        let setup = match s.request::<Value>("setupProtocol", p).await {
            Ok(r) => r,
            Err(e) if !public_client && same_binding && e.0.contains(SECRET_REBIND_MARK) => {
                let cs = ask_secret().await?;
                let p = setup_params(
                    &ty,
                    &a.name,
                    &config,
                    Some(&cs),
                    false,
                    &a.description,
                    existing.is_some(),
                );
                let r = s
                    .request::<Value>("setupProtocol", p)
                    .await
                    .map_err(String::from)?;
                client_secret = Some(cs);
                r
            }
            Err(e) => return Err(e.0),
        };
        let _ = client_secret;
        setup_msg = Some(setup_result(
            &setup,
            &kv_i18n::t("OAuth 配置", "OAuth configuration"),
            "OAuth configuration",
        ));
    }

    // ---- Perform the authorization ----
    let mut ip = Map::new();
    ip.insert("type".into(), json!(ty));
    ip.insert("name".into(), json!(a.name));
    #[derive(Deserialize)]
    struct InfoWrap {
        config: OAuthConfigView,
    }
    let info: InfoWrap = s.request("info", ip).await.map_err(String::from)?;
    let cfg = info.config;
    let result: Value;
    if cfg.flow == "authorization_code" {
        let preset = resolve_oauth_provider(&cfg.provider, None)?;
        let r = run_browser_flow(RunBrowserFlowOpts {
            authorization_url: cfg.authorization_url.as_deref().unwrap_or_default(),
            client_id: &cfg.client_id,
            scopes: &cfg.scopes,
            extra_params: &cfg.extra_auth_params,
            redirect_uri: cfg.redirect_uri.as_deref(),
            redirect_host: preset.and_then(|p| p.redirect_host),
        })
        .await?;
        let mut ep = Map::new();
        ep.insert("type".into(), json!(ty));
        ep.insert("name".into(), json!(a.name));
        ep.insert("code".into(), json!(r.code));
        ep.insert("code_verifier".into(), json!(r.code_verifier));
        ep.insert("redirect_uri".into(), json!(r.redirect_uri));
        result = s.request("oauthExchange", ep).await.map_err(String::from)?;
    } else if cfg.flow == "device_code" {
        let mut dp = Map::new();
        dp.insert("type".into(), json!(ty));
        dp.insert("name".into(), json!(a.name));
        #[derive(Deserialize)]
        struct DeviceStart {
            device_code: String,
            user_code: String,
            verification_uri: Option<String>,
            verification_uri_complete: Option<String>,
            interval: i64,
            expires_in: i64,
        }
        let d: DeviceStart = s
            .request("oauthDeviceStart", dp)
            .await
            .map_err(String::from)?;
        let user_code_re = regex::Regex::new(r"^[A-Za-z0-9-]{4,20}$").unwrap();
        let user_code = safe_display(
            &d.user_code,
            &user_code_re,
            &kv_i18n::t(
                "服务商返回的 user_code",
                "user_code returned by the provider",
            ),
        )?;
        let url = d
            .verification_uri_complete
            .clone()
            .or(d.verification_uri.clone());
        if let Some(u) = &url {
            if u.len() > 300 || u.chars().any(char::is_whitespace) {
                return Err(kv_i18n::t(
                    "服务商返回的验证网址格式异常",
                    "The verification URL returned by the provider is malformed",
                ));
            }
        }
        copy_to_clipboard(&user_code);
        let proceed = crate::dialog::ask(
            &kv_i18n::t(
                &format!("请在 {} 输入验证码：\n\n{user_code}\n\n（已复制到剪贴板）点击下方按钮打开验证页面。", url.clone().unwrap_or_else(|| kv_i18n::t("服务商的验证页面", "the provider's verification page"))),
                &format!("Enter this code at {}:\n\n{user_code}\n\n(Copied to the clipboard.) Click the button below to open the page.", url.clone().unwrap_or_else(|| kv_i18n::t("服务商的验证页面", "the provider's verification page"))),
            ),
            &kv_i18n::t("打开验证页面", "Open verification page"),
        )
        .await;
        if !proceed {
            return Ok(fail(kv_i18n::t(
                "用户取消了授权。",
                "Authorization was cancelled by the user.",
            )));
        }
        copy_to_clipboard(&user_code); // Copy again, in case the clipboard was overwritten in the meantime
        if let Some(u) = &url {
            let _ = open_in_browser(u).await;
        }
        let _notice = crate::dialog::show_notice(
            &kv_i18n::t(
                &format!("等待浏览器中完成授权…\n\n验证码：{user_code}"),
                &format!("Waiting for authorization in the browser…\n\nCode: {user_code}"),
            ),
            d.expires_in.max(0) as u64,
        );
        let mut interval = d.interval;
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(d.expires_in.max(0) as u64);
        loop {
            if std::time::Instant::now() > deadline {
                return Ok(fail(kv_i18n::t(
                    "设备码已过期，请重新调用 credential_oauth_login。",
                    "The device code has expired; call credential_oauth_login again.",
                )));
            }
            tokio::time::sleep(std::time::Duration::from_secs(interval.max(0) as u64)).await;
            let mut pp = Map::new();
            pp.insert("type".into(), json!(ty));
            pp.insert("name".into(), json!(a.name));
            pp.insert("device_code".into(), json!(d.device_code));
            let p: Value = s
                .request("oauthDevicePoll", pp)
                .await
                .map_err(String::from)?;
            match p.get("status").and_then(Value::as_str) {
                Some("done") => {
                    let mut rest = p.as_object().cloned().unwrap_or_default();
                    rest.remove("status");
                    result = Value::Object(rest);
                    break;
                }
                Some("slow_down") => interval += 5,
                Some("denied") => {
                    return Ok(fail(kv_i18n::t(
                        "用户拒绝了授权。",
                        "The user denied authorization.",
                    )))
                }
                Some("expired") => {
                    return Ok(fail(kv_i18n::t(
                        "设备码已过期，请重新调用 credential_oauth_login。",
                        "The device code has expired; call credential_oauth_login again.",
                    )))
                }
                _ => {}
            }
        }
    } else {
        let mut tp = Map::new();
        tp.insert("type".into(), json!(ty));
        tp.insert("name".into(), json!(a.name));
        tp.insert("force".into(), json!(true));
        let tok: Value = s.request("accessToken", tp).await.map_err(String::from)?;
        result = json!({"scope": tok.get("scope"), "expires_at": tok.get("expires_at")});
    }
    let head = setup_msg
        .map(|m| format!("{m}{}", kv_i18n::t("；", "; ")))
        .unwrap_or_default();
    Ok(ok_data(
        kv_i18n::t(
            &format!("{head}授权完成。之后用 credential_access_token（name: \"{}\"）获取 access token。", norm(&a.name)),
            &format!("{head}{}complete. Use credential_access_token (name: \"{}\") to get access tokens from now on.", if head.is_empty() { "Authorization " } else { "authorization " }, norm(&a.name)),
        ),
        result,
    ))
}

#[cfg(test)]
mod helper_tests {
    use super::*;

    #[test]
    fn setup_result_describes_a_fresh_save_without_a_new_type() {
        let r = json!({"type": "oauth2", "name": "github-bot", "typeCreated": false, "replaced": false});
        let msg = setup_result(&r, "OAuth2 凭证", "OAuth2 credential");
        assert_eq!(msg, "Saved OAuth2 credential \"oauth2/github-bot\"");
        assert!(!msg.contains("did not exist"));
    }

    #[test]
    fn setup_result_mentions_the_type_being_auto_created() {
        let r =
            json!({"type": "oauth2", "name": "github-bot", "typeCreated": true, "replaced": false});
        let msg = setup_result(&r, "OAuth2 credential", "OAuth2 credential");
        assert!(msg.contains("did not exist and was created"));
        assert!(msg.contains("Saved OAuth2 credential \"oauth2/github-bot\""));
    }

    #[test]
    fn setup_result_says_replaced_instead_of_saved_on_overwrite() {
        let r =
            json!({"type": "oauth2", "name": "github-bot", "typeCreated": false, "replaced": true});
        let msg = setup_result(&r, "OAuth2 credential", "OAuth2 credential");
        assert!(msg.contains("Replaced OAuth2 credential \"oauth2/github-bot\""));
    }
}
