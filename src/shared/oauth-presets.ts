// Common OAuth 2.0 provider presets. The resolved endpoints are written in full into the credential
// config, so refreshing the token later no longer depends on this file (changes to a preset don't affect already-saved credentials).

import { t } from "./i18n.js";

export interface OAuthPreset {
  label: string;
  authorization_url: string;
  token_url: string;
  device_authorization_url?: string;
  /** Extra authorization request parameters (e.g. Google only returns a refresh token if access_type=offline is set) */
  extra_auth_params?: Record<string, string>;
  default_scopes: string[];
  /** Scope(s) that are always appended (e.g. Microsoft only returns a refresh token if offline_access is requested) */
  required_scopes?: string[];
  /** Callback host used when redirect_uri isn't specified (Microsoft requires localhost) */
  redirect_host?: "127.0.0.1" | "localhost";
  notes: string;
}

/** [zh, en] pair, resolved to the current language in resolvePreset() */
type Bilingual = readonly [zh: string, en: string];

type OAuthPresetData = Omit<OAuthPreset, "label" | "notes"> & { label: string | Bilingual; notes: Bilingual };

const text = (v: string | Bilingual): string => (typeof v === "string" ? v : t(v[0], v[1]));

export const OAUTH_PRESETS: Record<string, OAuthPresetData> = {
  google: {
    label: "Google",
    authorization_url: "https://accounts.google.com/o/oauth2/v2/auth",
    token_url: "https://oauth2.googleapis.com/token",
    device_authorization_url: "https://oauth2.googleapis.com/device/code",
    extra_auth_params: { access_type: "offline", prompt: "consent" },
    default_scopes: ["openid", "email"],
    notes: [
      "在 Google Cloud Console 创建 OAuth client（浏览器流程选 Desktop app；设备码流程选 TVs and Limited Input devices）。" +
        "应用处于 Testing 状态时 refresh token 7 天后失效。",
      "Create an OAuth client in Google Cloud Console (Desktop app for the browser flow; TVs and Limited Input devices for the device-code flow). " +
        "While the app is in Testing status, refresh tokens expire after 7 days.",
    ],
  },
  github: {
    label: "GitHub",
    authorization_url: "https://github.com/login/oauth/authorize",
    token_url: "https://github.com/login/oauth/access_token",
    device_authorization_url: "https://github.com/login/device/code",
    default_scopes: ["read:user"],
    notes: [
      "OAuth App 的 callback URL 设为 http://127.0.0.1/callback（任意端口都可用）；设备码流程需在 App 设置里启用 Device Flow。",
      "Set the OAuth App callback URL to http://127.0.0.1/callback (any port works); the device-code flow requires enabling Device Flow in the App settings.",
    ],
  },
  microsoft: {
    label: "Microsoft Entra ID",
    authorization_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
    token_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
    device_authorization_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode",
    default_scopes: ["User.Read"],
    required_scopes: ["offline_access"],
    redirect_host: "localhost",
    notes: [
      "App registration 添加「移动和桌面应用程序」平台，redirect URI 登记为 http://localhost/callback（Microsoft 对 localhost 忽略端口，但路径须一致）；tenant 默认 common。",
      "In the App registration, add the \"Mobile and desktop applications\" platform and register the redirect URI http://localhost/callback (Microsoft ignores the port for localhost, but the path must match); tenant defaults to common.",
    ],
  },
  outlook: {
    label: ["Outlook / Microsoft 365 邮箱（IMAP）", "Outlook / Microsoft 365 mail (IMAP)"],
    authorization_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
    token_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
    device_authorization_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode",
    // openid email: gets the email address from the id_token, used as the XOAUTH2 username
    default_scopes: ["openid", "email", "https://outlook.office.com/IMAP.AccessAsUser.All"],
    required_scopes: ["offline_access"],
    redirect_host: "localhost",
    notes: [
      "App registration 添加「移动和桌面应用程序」平台，redirect URI 如 http://localhost:47902/callback（用 redirect_uri 参数指定）；" +
        "个人账号（outlook.com/hotmail/live/msn）tenant 用 consumers 或 common，且应用的受支持账户类型须包含个人 Microsoft 账户；" +
        "发信可追加 scope https://outlook.office.com/SMTP.Send。" +
        "注意：个人账号的 IMAP OAuth 自 2024 年 12 月起受微软服务端 bug 影响（认证成功但报 User is authenticated but not connected），个人邮箱请改用 outlook_graph。",
      "In the App registration, add the \"Mobile and desktop applications\" platform with a redirect URI such as http://localhost:47902/callback (pass it via the redirect_uri parameter); " +
        "for personal accounts (outlook.com/hotmail/live/msn) use tenant consumers or common, and the app's supported account types must include personal Microsoft accounts; " +
        "to send mail, add the scope https://outlook.office.com/SMTP.Send. " +
        "Note: since December 2024, IMAP OAuth for personal accounts is affected by a Microsoft server-side bug (authentication succeeds but fails with \"User is authenticated but not connected\"); use outlook_graph for personal mailboxes instead.",
    ],
  },
  outlook_graph: {
    label: ["Outlook / Microsoft 365 邮箱（Microsoft Graph）", "Outlook / Microsoft 365 mail (Microsoft Graph)"],
    authorization_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
    token_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
    device_authorization_url: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode",
    default_scopes: ["openid", "email", "Mail.Read"],
    required_scopes: ["offline_access"],
    redirect_host: "localhost",
    notes: [
      "通过 Microsoft Graph 读取邮件（graph.microsoft.com/v1.0/me/messages），个人账号和企业账号都可用。" +
        "默认只读（Mail.Read）；需要发信追加 Mail.Send。App registration 配置同 outlook 预设；个人账号 tenant 用 consumers。",
      "Reads mail via Microsoft Graph (graph.microsoft.com/v1.0/me/messages); works for both personal and work accounts. " +
        "Read-only by default (Mail.Read); add Mail.Send to send mail. App registration setup is the same as the outlook preset; use tenant consumers for personal accounts.",
    ],
  },
  gitlab: {
    label: "GitLab.com",
    authorization_url: "https://gitlab.com/oauth/authorize",
    token_url: "https://gitlab.com/oauth/token",
    device_authorization_url: "https://gitlab.com/oauth/authorize_device",
    default_scopes: ["read_user"],
    notes: ["自建 GitLab 请改用 issuer（OIDC 自动发现）。", "For self-hosted GitLab, use issuer (OIDC discovery) instead."],
  },
  dropbox: {
    label: "Dropbox",
    authorization_url: "https://www.dropbox.com/oauth2/authorize",
    token_url: "https://api.dropboxapi.com/oauth2/token",
    extra_auth_params: { token_access_type: "offline" },
    default_scopes: [],
    notes: [
      "App Console 中添加 redirect URI http://127.0.0.1:<端口>/callback（需固定端口，用 redirect_uri 参数指定）。",
      "Add the redirect URI http://127.0.0.1:<port>/callback in the App Console (requires a fixed port; pass it via the redirect_uri parameter).",
    ],
  },
};

export function resolvePreset(provider: string, tenant = "common"): OAuthPreset | null {
  const p = Object.hasOwn(OAUTH_PRESETS, provider) ? OAUTH_PRESETS[provider] : undefined;
  if (!p) return null;
  if (!/^[A-Za-z0-9.-]{1,100}$/.test(tenant)) throw new Error(t(`非法的 tenant：${tenant}`, `Invalid tenant: ${tenant}`));
  const sub = (u?: string) => u?.replaceAll("{tenant}", tenant);
  return {
    ...p,
    label: text(p.label),
    notes: text(p.notes),
    authorization_url: sub(p.authorization_url)!,
    token_url: sub(p.token_url)!,
    device_authorization_url: sub(p.device_authorization_url),
  };
}
