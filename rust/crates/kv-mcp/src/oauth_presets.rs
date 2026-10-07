//! Common OAuth 2.0 provider presets. The resolved endpoints are written in full into the
//! credential config, so refreshing the token later no longer depends on this file (changes to a
//! preset don't affect already-saved credentials). Direct port of src/shared/oauth-presets.ts.

#[derive(Debug, Clone)]
pub struct OAuthPreset {
    // Mirrors the TS data shape; not read by any tool handler yet (kept for parity/future use).
    #[allow(dead_code)]
    pub label: String,
    pub authorization_url: String,
    pub token_url: String,
    pub device_authorization_url: Option<String>,
    /// Extra authorization request parameters (e.g. Google only returns a refresh token if
    /// access_type=offline is set).
    pub extra_auth_params: std::collections::HashMap<String, String>,
    pub default_scopes: Vec<String>,
    /// Scope(s) that are always appended (e.g. Microsoft only returns a refresh token if
    /// offline_access is requested).
    pub required_scopes: Vec<String>,
    /// Callback host used when redirect_uri isn't specified (Microsoft requires localhost).
    pub redirect_host: Option<&'static str>,
    #[allow(dead_code)]
    pub notes: String,
    pub token_auth_method: Option<&'static str>,
}

struct PresetData {
    label: (&'static str, &'static str),
    authorization_url: &'static str,
    token_url: &'static str,
    device_authorization_url: Option<&'static str>,
    extra_auth_params: &'static [(&'static str, &'static str)],
    default_scopes: &'static [&'static str],
    required_scopes: &'static [&'static str],
    redirect_host: Option<&'static str>,
    notes: (&'static str, &'static str),
}

macro_rules! same {
    ($s:expr) => {
        ($s, $s)
    };
}

fn presets() -> std::collections::HashMap<&'static str, PresetData> {
    use std::collections::HashMap;
    let mut m: HashMap<&'static str, PresetData> = HashMap::new();
    m.insert("google", PresetData {
        label: same!("Google"),
        authorization_url: "https://accounts.google.com/o/oauth2/v2/auth",
        token_url: "https://oauth2.googleapis.com/token",
        device_authorization_url: Some("https://oauth2.googleapis.com/device/code"),
        extra_auth_params: &[("access_type", "offline"), ("prompt", "consent")],
        default_scopes: &["openid", "email"],
        required_scopes: &[],
        redirect_host: None,
        notes: (
            "在 Google Cloud Console 创建 OAuth client（浏览器流程选 Desktop app；设备码流程选 TVs and Limited Input devices）。应用处于 Testing 状态时 refresh token 7 天后失效。",
            "Create an OAuth client in Google Cloud Console (Desktop app for the browser flow; TVs and Limited Input devices for the device-code flow). While the app is in Testing status, refresh tokens expire after 7 days.",
        ),
    });
    m.insert("github", PresetData {
        label: same!("GitHub"),
        authorization_url: "https://github.com/login/oauth/authorize",
        token_url: "https://github.com/login/oauth/access_token",
        device_authorization_url: Some("https://github.com/login/device/code"),
        extra_auth_params: &[],
        default_scopes: &["read:user"],
        required_scopes: &[],
        redirect_host: None,
        notes: (
            "OAuth App 的 callback URL 设为 http://127.0.0.1/callback（任意端口都可用）；设备码流程需在 App 设置里启用 Device Flow。",
            "Set the OAuth App callback URL to http://127.0.0.1/callback (any port works); the device-code flow requires enabling Device Flow in the App settings.",
        ),
    });
    m.insert("microsoft", PresetData {
        label: same!("Microsoft Entra ID"),
        authorization_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
        token_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        device_authorization_url: Some("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode"),
        extra_auth_params: &[],
        default_scopes: &["User.Read"],
        required_scopes: &["offline_access"],
        redirect_host: Some("localhost"),
        notes: (
            "App registration 添加「移动和桌面应用程序」平台，redirect URI 登记为 http://localhost/callback（Microsoft 对 localhost 忽略端口，但路径须一致）；tenant 默认 common。",
            "In the App registration, add the \"Mobile and desktop applications\" platform and register the redirect URI http://localhost/callback (Microsoft ignores the port for localhost, but the path must match); tenant defaults to common.",
        ),
    });
    m.insert("outlook", PresetData {
        label: (
            "Outlook / Microsoft 365 邮箱（IMAP）",
            "Outlook / Microsoft 365 mail (IMAP)",
        ),
        authorization_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
        token_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        device_authorization_url: Some("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode"),
        extra_auth_params: &[],
        default_scopes: &["openid", "email", "https://outlook.office.com/IMAP.AccessAsUser.All"],
        required_scopes: &["offline_access"],
        redirect_host: Some("localhost"),
        notes: (
            "App registration 添加「移动和桌面应用程序」平台，redirect URI 如 http://localhost:47902/callback（用 redirect_uri 参数指定）；个人账号（outlook.com/hotmail/live/msn）tenant 用 consumers 或 common，且应用的受支持账户类型须包含个人 Microsoft 账户；发信可追加 scope https://outlook.office.com/SMTP.Send。注意：个人账号的 IMAP OAuth 自 2024 年 12 月起受微软服务端 bug 影响（认证成功但报 User is authenticated but not connected），个人邮箱请改用 outlook_graph。",
            "In the App registration, add the \"Mobile and desktop applications\" platform with a redirect URI such as http://localhost:47902/callback (pass it via the redirect_uri parameter); for personal accounts (outlook.com/hotmail/live/msn) use tenant consumers or common, and the app's supported account types must include personal Microsoft accounts; to send mail, add the scope https://outlook.office.com/SMTP.Send. Note: since December 2024, IMAP OAuth for personal accounts is affected by a Microsoft server-side bug (authentication succeeds but fails with \"User is authenticated but not connected\"); use outlook_graph for personal mailboxes instead.",
        ),
    });
    m.insert("outlook_graph", PresetData {
        label: (
            "Outlook / Microsoft 365 邮箱（Microsoft Graph）",
            "Outlook / Microsoft 365 mail (Microsoft Graph)",
        ),
        authorization_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
        token_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        device_authorization_url: Some("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode"),
        extra_auth_params: &[],
        default_scopes: &["openid", "email", "Mail.Read"],
        required_scopes: &["offline_access"],
        redirect_host: Some("localhost"),
        notes: (
            "通过 Microsoft Graph 读取邮件（graph.microsoft.com/v1.0/me/messages），个人账号和企业账号都可用。默认只读（Mail.Read）；需要发信追加 Mail.Send。App registration 配置同 outlook 预设；个人账号 tenant 用 consumers。",
            "Reads mail via Microsoft Graph (graph.microsoft.com/v1.0/me/messages); works for both personal and work accounts. Read-only by default (Mail.Read); add Mail.Send to send mail. App registration setup is the same as the outlook preset; use tenant consumers for personal accounts.",
        ),
    });
    m.insert(
        "gitlab",
        PresetData {
            label: same!("GitLab.com"),
            authorization_url: "https://gitlab.com/oauth/authorize",
            token_url: "https://gitlab.com/oauth/token",
            device_authorization_url: Some("https://gitlab.com/oauth/authorize_device"),
            extra_auth_params: &[],
            default_scopes: &["read_user"],
            required_scopes: &[],
            redirect_host: None,
            notes: (
                "自建 GitLab 请改用 issuer（OIDC 自动发现）。",
                "For self-hosted GitLab, use issuer (OIDC discovery) instead.",
            ),
        },
    );
    m.insert("dropbox", PresetData {
        label: same!("Dropbox"),
        authorization_url: "https://www.dropbox.com/oauth2/authorize",
        token_url: "https://api.dropboxapi.com/oauth2/token",
        device_authorization_url: None,
        extra_auth_params: &[("token_access_type", "offline")],
        default_scopes: &[],
        required_scopes: &[],
        redirect_host: None,
        notes: (
            "App Console 中添加 redirect URI http://127.0.0.1:<端口>/callback（需固定端口，用 redirect_uri 参数指定）。",
            "Add the redirect URI http://127.0.0.1:<port>/callback in the App Console (requires a fixed port; pass it via the redirect_uri parameter).",
        ),
    });
    m
}

pub fn preset_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = presets().into_keys().collect();
    names.sort_unstable();
    names
}

pub fn resolve_preset(provider: &str, tenant: &str) -> Result<Option<OAuthPreset>, String> {
    let all = presets();
    let Some(p) = all.get(provider) else {
        return Ok(None);
    };
    let tenant_re_ok = !tenant.is_empty()
        && tenant.len() <= 100
        && tenant
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
    if !tenant_re_ok {
        return Err(kv_i18n::t(
            &format!("非法的 tenant：{tenant}"),
            &format!("Invalid tenant: {tenant}"),
        ));
    }
    let sub = |u: &str| u.replace("{tenant}", tenant);
    Ok(Some(OAuthPreset {
        label: kv_i18n::t(p.label.0, p.label.1),
        authorization_url: sub(p.authorization_url),
        token_url: sub(p.token_url),
        device_authorization_url: p.device_authorization_url.map(sub),
        extra_auth_params: p
            .extra_auth_params
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        default_scopes: p.default_scopes.iter().map(|s| s.to_string()).collect(),
        required_scopes: p.required_scopes.iter().map(|s| s.to_string()).collect(),
        redirect_host: p.redirect_host,
        notes: kv_i18n::t(p.notes.0, p.notes.1),
        token_auth_method: None,
    }))
}
