// 常见 OAuth 2.0 服务商预设。解析后的端点会完整写进凭证配置，
// 之后刷新 token 不再依赖这里（预设变化不会影响已保存的凭证）。

export interface OAuthPreset {
  label: string;
  authorization_url: string;
  token_url: string;
  device_authorization_url?: string;
  /** 授权请求附加参数（如 Google 需要 access_type=offline 才会给 refresh token） */
  extra_auth_params?: Record<string, string>;
  default_scopes: string[];
  /** 始终追加的 scope（如 Microsoft 需要 offline_access 才会给 refresh token） */
  required_scopes?: string[];
  /** 未指定 redirect_uri 时的回调主机（Microsoft 要求 localhost） */
  redirect_host?: "127.0.0.1" | "localhost";
  notes: string;
}

export const OAUTH_PRESETS: Record<string, OAuthPreset> = {
  google: {
    label: "Google",
    authorization_url: "https://accounts.google.com/o/oauth2/v2/auth",
    token_url: "https://oauth2.googleapis.com/token",
    device_authorization_url: "https://oauth2.googleapis.com/device/code",
    extra_auth_params: { access_type: "offline", prompt: "consent" },
    default_scopes: ["openid", "email"],
    notes:
      "在 Google Cloud Console 创建 OAuth client（浏览器流程选 Desktop app；设备码流程选 TVs and Limited Input devices）。" +
      "应用处于 Testing 状态时 refresh token 7 天后失效。",
  },
  github: {
    label: "GitHub",
    authorization_url: "https://github.com/login/oauth/authorize",
    token_url: "https://github.com/login/oauth/access_token",
    device_authorization_url: "https://github.com/login/device/code",
    default_scopes: ["read:user"],
    notes: "OAuth App 的 callback URL 设为 http://127.0.0.1/callback（任意端口都可用）；设备码流程需在 App 设置里启用 Device Flow。",
  },
  microsoft: {
    label: "Microsoft Entra ID",
    authorization_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
    token_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
    device_authorization_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode",
    default_scopes: ["User.Read"],
    required_scopes: ["offline_access"],
    redirect_host: "localhost",
    notes:
      "App registration 添加「移动和桌面应用程序」平台，redirect URI 登记为 http://localhost/callback（Microsoft 对 localhost 忽略端口，但路径须一致）；tenant 默认 common。",
  },
  outlook: {
    label: "Outlook / Microsoft 365 邮箱（IMAP）",
    authorization_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
    token_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
    device_authorization_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode",
    // openid email：从 id_token 拿到邮箱地址，用作 XOAUTH2 的用户名
    default_scopes: ["openid", "email", "https://outlook.office.com/IMAP.AccessAsUser.All"],
    required_scopes: ["offline_access"],
    redirect_host: "localhost",
    notes:
      "App registration 添加「移动和桌面应用程序」平台，redirect URI 如 http://localhost:47902/callback（用 redirect_uri 参数指定）；" +
      "个人账号（outlook.com/hotmail/live/msn）tenant 用 consumers 或 common，且应用的受支持账户类型须包含个人 Microsoft 账户；" +
      "发信可追加 scope https://outlook.office.com/SMTP.Send。" +
      "注意：个人账号的 IMAP OAuth 自 2024 年 12 月起受微软服务端 bug 影响（认证成功但报 User is authenticated but not connected），个人邮箱请改用 outlook_graph。",
  },
  outlook_graph: {
    label: "Outlook / Microsoft 365 邮箱（Microsoft Graph）",
    authorization_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
    token_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
    device_authorization_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode",
    default_scopes: ["openid", "email", "Mail.Read"],
    required_scopes: ["offline_access"],
    redirect_host: "localhost",
    notes:
      "通过 Microsoft Graph 读取邮件（graph.microsoft.com/v1.0/me/messages），个人账号和企业账号都可用。" +
      "默认只读（Mail.Read）；需要发信追加 Mail.Send。App registration 配置同 outlook 预设；个人账号 tenant 用 consumers。",
  },
  gitlab: {
    label: "GitLab.com",
    authorization_url: "https://gitlab.com/oauth/authorize",
    token_url: "https://gitlab.com/oauth/token",
    device_authorization_url: "https://gitlab.com/oauth/authorize_device",
    default_scopes: ["read_user"],
    notes: "自建 GitLab 请改用 issuer（OIDC 自动发现）。",
  },
  dropbox: {
    label: "Dropbox",
    authorization_url: "https://www.dropbox.com/oauth2/authorize",
    token_url: "https://api.dropboxapi.com/oauth2/token",
    extra_auth_params: { token_access_type: "offline" },
    default_scopes: [],
    notes: "App Console 中添加 redirect URI http://127.0.0.1:<端口>/callback（需固定端口，用 redirect_uri 参数指定）。",
  },
};

export function resolvePreset(provider: string, tenant = "common"): OAuthPreset | null {
  const p = Object.hasOwn(OAUTH_PRESETS, provider) ? OAUTH_PRESETS[provider] : undefined;
  if (!p) return null;
  if (!/^[A-Za-z0-9.-]{1,100}$/.test(tenant)) throw new Error(`非法的 tenant：${tenant}`);
  const sub = (u?: string) => u?.replaceAll("{tenant}", tenant);
  return {
    ...p,
    authorization_url: sub(p.authorization_url)!,
    token_url: sub(p.token_url)!,
    device_authorization_url: sub(p.device_authorization_url),
  };
}
