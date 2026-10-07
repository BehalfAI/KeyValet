import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { t } from "../../shared/i18n.js";
import { SECRET_REBIND_MARK } from "../../shared/protocol.js";
import { oauthProviderNames, resolveOAuthProvider } from "../templates.js";
import { ask, promptSecret, showNotice } from "../dialog.js";
import { xoauth2 } from "../mail.js";
import { copyToClipboard, discoverOidc, openInBrowser, runBrowserFlow } from "../oauth-flow.js";
import { recordSecrets } from "../gateway-env.js";
import type { HelperSession } from "../session.js";
import { CLIENT_ID_RE, fail, guardOverwrite, httpsHost, importFile, norm, ok, purposeField, resolveType, safeDisplay, tryInfo, wrap } from "./common.js";

const nameField = z.string().describe(t("凭证名（小写），如 google-work、github-bot", "Credential name (lowercase), e.g. google-work, github-bot"));
const optType = (kind: string) => z.string().optional().describe(t(`凭证类型，默认 "${kind}"（不存在时自动创建）`, `Credential type, default "${kind}" (created automatically if missing)`));
const descField = z.string().optional().describe(t("凭证说明", "Credential description"));
const overwriteField = z.boolean().optional().describe(t("已存在时替换（会弹窗请用户确认）", "Replace if it already exists (asks the user to confirm in a dialog)"));

type SetupResult = { type: string; name: string; typeCreated: boolean; replaced: boolean };

function setupMessage(r: SetupResult, what: string): string {
  const steps = [];
  if (r.typeCreated) steps.push(t(`凭证类型 "${r.type}" 不存在，已先创建`, `Credential type "${r.type}" did not exist and was created`));
  steps.push(
    t(`${r.replaced ? "已替换" : "已保存"} ${what} "${r.type}/${r.name}"`, `${r.replaced ? "Replaced" : "Saved"} ${what} "${r.type}/${r.name}"`),
  );
  return steps.join(t("；", "; "));
}

interface OAuthConfigView {
  provider: string;
  flow: "authorization_code" | "device_code" | "client_credentials";
  client_id: string;
  token_url: string;
  authorization_url?: string;
  device_authorization_url?: string;
  scopes: string[];
  extra_auth_params: Record<string, string>;
  token_auth_method: string;
  redirect_uri?: string;
}

const SECRET_BINDING_KEYS = ["client_id", "token_url", "authorization_url", "device_authorization_url", "token_auth_method"] as const;

export function registerProtocolTools(server: McpServer, session: HelperSession): void {
  // ---------------- OAuth 2.0 ----------------
  server.registerTool(
    "credential_oauth_login",
    {
      description: t(
        "配置并完成 OAuth 2.0 授权，refresh token 加密保存，之后用 credential_access_token 获取 access token（agent 拿不到 refresh token 和 client secret）。\n" +
          "flow：authorization_code（默认，打开浏览器，本地回调 + PKCE）、device_code（显示验证码让用户在浏览器输入）、client_credentials（机器对机器，无需用户交互）。\n" +
          `provider：${oauthProviderNames()}；其他服务用 issuer（OIDC 自动发现，如 Okta/Auth0/Keycloak）或手动指定端点。\n` +
          "client secret 不要通过参数传入，省略即可，会弹窗让用户输入。\n" +
          "已存在的凭证：只传 name 即可重新授权（沿用已保存的配置）；传入新的 scopes 等参数会更新配置。",
        "Configure and complete OAuth 2.0 authorization. The refresh token is stored encrypted; afterwards use credential_access_token to get access tokens (the agent never sees the refresh token or client secret).\n" +
          "flow: authorization_code (default; opens the browser, local callback + PKCE), device_code (shows a code for the user to enter in the browser), client_credentials (machine-to-machine, no user interaction).\n" +
          `provider: ${oauthProviderNames()}; for other services use issuer (OIDC discovery, e.g. Okta/Auth0/Keycloak) or specify the endpoints manually.\n` +
          "Do not pass the client secret as a parameter; omit it and the user will be prompted for it in a dialog.\n" +
          "Existing credential: pass just name to re-authorize (reusing the saved configuration); passing new scopes or other parameters updates the configuration.",
      ),
      inputSchema: {
        purpose: purposeField,
        name: nameField,
        type: optType("oauth2"),
        provider: z.string().optional().describe(
            t(
              "服务商：内置预设（google、github、microsoft、outlook、outlook_graph、gitlab、dropbox）或模板库中的 OAuth2 模板 id；自定义服务省略",
              "Provider: a built-in preset (google, github, microsoft, outlook, outlook_graph, gitlab, dropbox) or an OAuth2 template id from the template library; omit for custom services",
            ),
          ),
        flow: z.enum(["authorization_code", "device_code", "client_credentials"]).optional(),
        client_id: z.string().optional().describe(t("OAuth client ID（新建时必填）", "OAuth client ID (required when creating)")),
        public_client: z.boolean().optional().describe(t("公共客户端（无 client secret，仅靠 PKCE）", "Public client (no client secret, PKCE only)")),
        scopes: z.array(z.string()).optional().describe(t("授权范围，如 [\"https://www.googleapis.com/auth/gmail.readonly\"]", "Scopes, e.g. [\"https://www.googleapis.com/auth/gmail.readonly\"]")),
        tenant: z.string().optional().describe(t("Microsoft 租户 ID 或域名，默认 common", "Microsoft tenant ID or domain, default common")),
        issuer: z.string().optional().describe(t("OIDC issuer URL，用于自动发现端点", "OIDC issuer URL, used to discover endpoints automatically")),
        authorization_url: z.string().optional(),
        token_url: z.string().optional(),
        device_authorization_url: z.string().optional(),
        redirect_uri: z.string().optional().describe(t("固定回调地址（必须是本机回环地址）；默认随机端口 http://127.0.0.1:<port>/callback", "Fixed redirect URI (must be a local loopback address); default is a random port http://127.0.0.1:<port>/callback")),
        extra_auth_params: z.record(z.string(), z.string()).optional().describe(t("授权请求附加参数", "Extra parameters for the authorization request")),
        token_auth_method: z.enum(["client_secret_post", "client_secret_basic", "none"]).optional(),
        description: descField,
      },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      const type = a.type ?? "oauth2";
      const existing = await tryInfo(s, type, a.name);
      if (existing && existing.kind !== "oauth2") return fail(t(`"${existing.type}/${existing.name}" 已存在且不是 OAuth 凭证。`, `"${existing.type}/${existing.name}" already exists and is not an OAuth credential.`));
      const base = (existing?.config ?? {}) as Partial<OAuthConfigView>;
      const label = `${norm(type)}/${norm(a.name)}`;
      let setup: SetupResult | undefined;

      const wantsChange =
        a.provider !== undefined || a.flow !== undefined || a.client_id !== undefined || a.public_client !== undefined ||
        a.scopes !== undefined || a.tenant !== undefined || a.issuer !== undefined || a.authorization_url !== undefined ||
        a.token_url !== undefined || a.device_authorization_url !== undefined || a.redirect_uri !== undefined ||
        a.extra_auth_params !== undefined || a.token_auth_method !== undefined;

      if (!existing || wantsChange) {
        // ---- 组装配置：已保存的配置 ← 预设 ← OIDC 发现 ← 显式参数 ----
        const providerChanged = a.provider !== undefined && a.provider !== base.provider;
        const provider = a.provider ?? base.provider ?? (a.issuer ? "oidc" : "custom");
        const preset = a.provider || a.tenant ? resolveOAuthProvider(provider, a.tenant) : null;
        if (a.provider && !preset) return fail(
            t(
              `未知的 provider "${a.provider}"。可用：${oauthProviderNames()}；其他服务请用 issuer 或手动指定端点。`,
              `Unknown provider "${a.provider}". Available: ${oauthProviderNames()}; for other services use issuer or specify the endpoints manually.`,
            ),
          );
        const fromBase = providerChanged ? {} : base;
        const discovered: Partial<Awaited<ReturnType<typeof discoverOidc>>> = a.issuer ? await discoverOidc(a.issuer) : {};
        const flow = a.flow ?? base.flow ?? "authorization_code";
        const scopes = [...new Set([...(a.scopes ?? base.scopes ?? preset?.default_scopes ?? []), ...(flow !== "client_credentials" ? (preset?.required_scopes ?? []) : [])])];
        const publicClient = a.public_client ?? (a.token_auth_method === "none" || (!a.token_auth_method && base.token_auth_method === "none"));
        const config: Partial<OAuthConfigView> = {
          provider,
          flow,
          client_id: a.client_id ?? base.client_id,
          authorization_url: a.authorization_url ?? discovered.authorization_url ?? preset?.authorization_url ?? fromBase.authorization_url,
          token_url: a.token_url ?? discovered.token_url ?? preset?.token_url ?? fromBase.token_url,
          device_authorization_url:
            a.device_authorization_url ?? discovered.device_authorization_url ?? preset?.device_authorization_url ?? fromBase.device_authorization_url,
          scopes,
          extra_auth_params: a.extra_auth_params ?? (providerChanged ? undefined : base.extra_auth_params) ?? preset?.extra_auth_params ?? {},
          token_auth_method: publicClient
            ? "none"
            : (a.token_auth_method ??
              (base.token_auth_method !== "none" ? base.token_auth_method : undefined) ??
              (preset?.token_auth_method as OAuthConfigView["token_auth_method"] | undefined) ??
              "client_secret_post"),
          redirect_uri: a.redirect_uri ?? base.redirect_uri,
        };
        if (!config.client_id) return fail(t("新建 OAuth 凭证需要 client_id。", "client_id is required to create an OAuth credential."));
        if (!config.token_url) return fail(t("缺少 token_url：请指定 provider、issuer 或 token_url。", "Missing token_url: specify provider, issuer, or token_url."));
        if (flow === "authorization_code" && !config.authorization_url) return fail(t("授权码流程缺少 authorization_url。", "The authorization code flow requires authorization_url."));
        if (flow === "device_code" && !config.device_authorization_url) return fail(t("该服务商没有设备码端点，请改用 authorization_code 或指定 device_authorization_url。", "This provider has no device code endpoint; use authorization_code or specify device_authorization_url."));
        if (flow === "client_credentials" && publicClient) return fail(t("client_credentials 流程需要 client secret。", "The client_credentials flow requires a client secret."));
        // 会显示在弹窗中的值必须先严格校验，防止 agent 写入诱导文字（如“请输入 Mac 密码”）
        const clientId = safeDisplay(config.client_id, CLIENT_ID_RE, "client_id");
        const tokenHost = httpsHost(config.token_url, "token_url");

        // 修改已有凭证的配置：一律需要用户确认（即使是公共客户端、即使只改 scope）
        if (existing) await guardOverwrite(s, type, a.name, true);

        // ---- client secret：端点和 client 不变时沿用；否则必须由用户重新输入 ----
        const sameBinding = !!existing && SECRET_BINDING_KEYS.every((k) => (base as Record<string, unknown>)[k] === (config as Record<string, unknown>)[k]);
        const askSecret = async () => {
          const s = await promptSecret(
            t(
              `请输入 OAuth client secret\n\n凭证：${label}\nclient_id：${clientId}\n它只会被发送到：${tokenHost}`,
              `Enter the OAuth client secret\n\nCredential: ${label}\nclient_id: ${clientId}\nIt will only be sent to: ${tokenHost}`,
            ),
          );
          if (!s) throw new Error(t("用户取消了输入，未保存。", "Input cancelled by the user; nothing was saved."));
          return s;
        };
        let clientSecret = !publicClient && !sameBinding ? await askSecret() : undefined;
        const doSetup = (reuse: boolean) =>
          s.request<SetupResult>("setupProtocol", {
            kind: "oauth2",
            type,
            name: a.name,
            config,
            secrets: clientSecret ? { client_secret: clientSecret } : {},
            reuseClientSecret: reuse,
            description: a.description,
            typeDescription: t("OAuth 2.0 授权", "OAuth 2.0 authorization"),
            overwrite: !!existing,
          });
        try {
          setup = await doSetup(!publicClient && sameBinding);
        } catch (e) {
          // helper 的绑定校验更严格（如切换 flow 后端点被规范化），以它为准：请用户重新输入
          if (!publicClient && sameBinding && (e as Error).message.includes(SECRET_REBIND_MARK)) {
            clientSecret = await askSecret();
            setup = await doSetup(false);
          } else {
            throw e;
          }
        }
      }

      // ---- 执行授权 ----
      const info = await s.request<{ type: string; name: string; config: OAuthConfigView }>("info", { type, name: a.name });
      const cfg = info.config;
      let result: Record<string, unknown>;
      if (cfg.flow === "authorization_code") {
        const preset = resolveOAuthProvider(cfg.provider);
        const r = await runBrowserFlow({
          authorizationUrl: cfg.authorization_url!,
          clientId: cfg.client_id,
          scopes: cfg.scopes,
          extraParams: cfg.extra_auth_params,
          redirectUri: cfg.redirect_uri,
          redirectHost: preset?.redirect_host,
        });
        result = await s.request("oauthExchange", { type, name: a.name, ...r });
      } else if (cfg.flow === "device_code") {
        const d = await s.request<{
          device_code: string;
          user_code: string;
          verification_uri: string | null;
          verification_uri_complete: string | null;
          interval: number;
          expires_in: number;
        }>("oauthDeviceStart", { type, name: a.name });
        // 设备码和网址来自服务商，显示前校验格式
        const userCode = safeDisplay(d.user_code, /^[A-Za-z0-9-]{4,20}$/, t("服务商返回的 user_code", "user_code returned by the provider"));
        const url = d.verification_uri_complete ?? d.verification_uri;
        if (url && (url.length > 300 || /\s/.test(url))) throw new Error(t("服务商返回的验证网址格式异常", "The verification URL returned by the provider is malformed"));
        // 先让用户看清验证码，点按钮后再打开浏览器（浏览器抢焦点时，弹窗容易被误按回车关掉）
        copyToClipboard(userCode);
        const proceed = await ask(
          t(
            `请在 ${url ?? "服务商的验证页面"} 输入验证码：\n\n${userCode}\n\n（已复制到剪贴板）点击下方按钮打开验证页面。`,
            `Enter this code at ${url ?? "the provider's verification page"}:\n\n${userCode}\n\n(Copied to the clipboard.) Click the button below to open the page.`,
          ),
          t("打开验证页面", "Open verification page"),
        );
        if (!proceed) return fail(t("用户取消了授权。", "Authorization was cancelled by the user."));
        copyToClipboard(userCode); // 再复制一次，防止期间剪贴板被覆盖
        if (url) await openInBrowser(url).catch(() => {});
        // 等待期间的提示没有默认按钮：回车不会误关
        const close = showNotice(
          t(`等待浏览器中完成授权…\n\n验证码：${userCode}`, `Waiting for authorization in the browser…\n\nCode: ${userCode}`),
          d.expires_in,
        );
        try {
          let interval = d.interval;
          const deadline = Date.now() + d.expires_in * 1000;
          for (;;) {
            if (Date.now() > deadline) return fail(t("设备码已过期，请重新调用 credential_oauth_login。", "The device code has expired; call credential_oauth_login again."));
            await new Promise((res) => setTimeout(res, interval * 1000));
            const p = await s.request<{ status: string } & Record<string, unknown>>("oauthDevicePoll", {
              type,
              name: a.name,
              device_code: d.device_code,
            });
            if (p.status === "done") {
              const { status: _s, ...rest } = p;
              result = rest;
              break;
            }
            if (p.status === "slow_down") interval += 5;
            if (p.status === "denied") return fail(t("用户拒绝了授权。", "The user denied authorization."));
            if (p.status === "expired") return fail(t("设备码已过期，请重新调用 credential_oauth_login。", "The device code has expired; call credential_oauth_login again."));
          }
        } finally {
          close();
        }
      } else {
        const tok = await s.request<Record<string, unknown>>("accessToken", { type, name: a.name, force: true });
        result = { scope: tok.scope, expires_at: tok.expires_at };
      }
      const head = setup ? setupMessage(setup, t("OAuth 配置", "OAuth configuration")) + t("；", "; ") : "";
      return ok(
        t(
          `${head}授权完成。之后用 credential_access_token（name: "${norm(a.name)}"）获取 access token。`,
          `${head}${head ? "authorization" : "Authorization"} complete. Use credential_access_token (name: "${norm(a.name)}") to get access tokens from now on.`,
        ),
        result,
      );
    }),
  );

  // ---------------- 统一取 token ----------------
  server.registerTool(
    "credential_access_token",
    {
      description: t(
        "获取短期 access token，适用于 oauth2（自动刷新）、google_service_account、github_app（installation token）、jwt（按模板签发）。" +
          "返回的 token 有效期通常为 1 小时以内；长期秘密不会返回。",
        "Get a short-lived access token for oauth2 (auto-refreshed), google_service_account, github_app (installation token), or jwt (signed from the template). " +
          "Returned tokens are usually valid for at most 1 hour; long-term secrets are never returned.",
      ),
      inputSchema: {
        purpose: purposeField,
        name: nameField,
        type: z.string().optional().describe(t("凭证类型；省略时按名字自动查找", "Credential type; looked up by name if omitted")),
        scopes: z.array(z.string()).optional().describe(t("仅 google_service_account：本次请求的 scope（默认用设置时的）", "google_service_account only: scopes for this request (defaults to those set at setup)")),
        repositories: z.array(z.string()).optional().describe(t("仅 github_app：把 token 限制到这些仓库名", "github_app only: restrict the token to these repository names")),
        permissions: z.record(z.string(), z.string()).optional().describe(t("仅 github_app：收窄权限，如 {\"contents\": \"read\"}", "github_app only: narrow the permissions, e.g. {\"contents\": \"read\"}")),
        force_refresh: z.boolean().optional().describe(t("忽略缓存，强制获取新 token", "Ignore the cache and force a new token")),
        format: z
          .enum(["default", "xoauth2"])
          .optional()
          .describe(t("xoauth2：额外返回 IMAP/SMTP/POP 的 SASL XOAUTH2 认证字符串（Gmail、Outlook 邮箱用）", "xoauth2: also return the SASL XOAUTH2 auth string for IMAP/SMTP/POP (for Gmail and Outlook mail)")),
        username: z.string().optional().describe(t("仅 format=xoauth2：邮箱地址；省略则使用授权时识别出的账号", "format=xoauth2 only: email address; defaults to the account identified during authorization")),
      },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      const type = await resolveType(s, a.name, a.type, ["oauth2", "google_service_account", "github_app", "jwt"]);
      const r = await s.request<{ access_token: string; account?: string | null }>("accessToken", {
        type,
        name: a.name,
        scopes: a.scopes,
        repositories: a.repositories,
        permissions: a.permissions,
        force: a.force_refresh === true,
      });
      if (a.format === "xoauth2") {
        const username = a.username ?? r.account;
        if (!username) return fail(t("无法确定邮箱地址：请传 username，或在授权 scope 中包含 openid email。", "Cannot determine the email address: pass username, or include openid email in the authorization scopes."));
        const x = xoauth2(username, r.access_token);
        recordSecrets(session.sessionId, [r.access_token, x]);
        return ok(t("access token（含 XOAUTH2）：", "access token (with XOAUTH2):"), { ...r, username, xoauth2: x });
      }
      recordSecrets(session.sessionId, [r.access_token]);
      return ok(t("access token：", "access token:"), r);
    }),
  );

  // ---------------- Google 服务账号 ----------------
  server.registerTool(
    "credential_setup_google_service_account",
    {
      description: t(
        "导入 Google 服务账号 JSON 密钥文件（内容不会进入 AI 上下文）。之后用 credential_access_token 获取 access token。",
        "Import a Google service account JSON key file (its contents never enter the AI context). Afterwards use credential_access_token to get access tokens.",
      ),
      inputSchema: {
        purpose: purposeField,
        name: nameField,
        type: optType("google_service_account"),
        key_file: z.string().describe(t("服务账号 JSON 密钥文件路径", "Path to the service account JSON key file")),
        scopes: z.array(z.string()).optional().describe(t("默认 scope，省略则为 cloud-platform", "Default scopes; cloud-platform if omitted")),
        subject: z.string().optional().describe(t("域范围授权时要模拟的 Workspace 用户邮箱", "Workspace user email to impersonate with domain-wide delegation")),
        description: descField,
        overwrite: overwriteField,
      },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      const type = a.type ?? "google_service_account";
      const exists = await guardOverwrite(s, type, a.name, a.overwrite);
      const f = await importFile(a.key_file, `${norm(type)}/${norm(a.name)}`);
      const r = await s.request<SetupResult>("setupProtocol", {
        kind: "google_service_account",
        type,
        name: a.name,
        config: { scopes: a.scopes, subject: a.subject },
        secrets: { key_json: f.content },
        description: a.description,
        typeDescription: t("Google 服务账号", "Google service account"),
        overwrite: exists,
      });
      const verify = await session
        .request<{ expires_at: string; account: string }>("accessToken", { type, name: a.name, force: true })
        .then((tok) => t(`已验证可以获取 token（${tok.account}）`, `verified that a token can be obtained (${tok.account})`))
        .catch((e: Error) => t(`⚠️ 已保存，但获取 token 失败：${e.message}`, `⚠️ saved, but getting a token failed: ${e.message}`));
      return ok(
        t(
          `${setupMessage(r, "Google 服务账号")}；${verify}。建议删除原密钥文件 ${f.path}。`,
          `${setupMessage(r, "Google service account")}; ${verify}. Consider deleting the original key file ${f.path}.`,
        ),
      );
    }),
  );

  // ---------------- GitHub App ----------------
  server.registerTool(
    "credential_setup_github_app",
    {
      description: t(
        "设置 GitHub App（私钥从 .pem 文件导入）。之后用 credential_access_token 获取 1 小时有效的 installation token。",
        "Set up a GitHub App (private key imported from a .pem file). Afterwards use credential_access_token to get installation tokens valid for 1 hour.",
      ),
      inputSchema: {
        purpose: purposeField,
        name: nameField,
        type: optType("github_app"),
        app_id: z.string().describe(t("App ID（数字）或 Client ID", "App ID (numeric) or Client ID")),
        private_key_file: z.string().describe(t("App 私钥 .pem 文件路径", "Path to the App private key .pem file")),
        installation_id: z.string().optional().describe(t("installation ID；App 只装在一个账号上时可省略", "Installation ID; may be omitted if the App is installed on only one account")),
        api_base_url: z.string().optional().describe(t("GitHub Enterprise Server 的 API 地址，默认 https://api.github.com", "API base URL for GitHub Enterprise Server, default https://api.github.com")),
        description: descField,
        overwrite: overwriteField,
      },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      const type = a.type ?? "github_app";
      const exists = await guardOverwrite(s, type, a.name, a.overwrite);
      const f = await importFile(a.private_key_file, `${norm(type)}/${norm(a.name)}`);
      const r = await s.request<SetupResult>("setupProtocol", {
        kind: "github_app",
        type,
        name: a.name,
        config: { app_id: a.app_id, installation_id: a.installation_id, api_base_url: a.api_base_url },
        secrets: { private_key: f.content },
        description: a.description,
        typeDescription: "GitHub App",
        overwrite: exists,
      });
      const verify = await session
        .request<{ expires_at: string }>("accessToken", { type, name: a.name, force: true })
        .then(() => t("已验证可以获取 installation token", "verified that an installation token can be obtained"))
        .catch((e: Error) => t(`⚠️ 已保存，但获取 token 失败：${e.message}`, `⚠️ saved, but getting a token failed: ${e.message}`));
      return ok(
        t(
          `${setupMessage(r, "GitHub App")}；${verify}。建议删除原私钥文件 ${f.path}。`,
          `${setupMessage(r, "GitHub App")}; ${verify}. Consider deleting the original private key file ${f.path}.`,
        ),
      );
    }),
  );

  // ---------------- 通用 JWT ----------------
  server.registerTool(
    "credential_setup_jwt",
    {
      description: t(
        "设置 JWT 签发模板（如 App Store Connect API：algorithm=ES256, issuer=Issuer ID, key_id=Key ID, audience=appstoreconnect-v1）。" +
          "私钥从文件导入；HS* 算法的密钥由用户在弹窗输入。之后用 credential_access_token 获取签好的短期 JWT。",
        "Set up a JWT signing template (e.g. App Store Connect API: algorithm=ES256, issuer=Issuer ID, key_id=Key ID, audience=appstoreconnect-v1). " +
          "Private keys are imported from a file; for HS* algorithms the user enters the key in a dialog. Afterwards use credential_access_token to get signed short-lived JWTs.",
      ),
      inputSchema: {
        purpose: purposeField,
        name: nameField,
        type: optType("jwt"),
        algorithm: z.enum(["RS256", "RS384", "RS512", "PS256", "ES256", "ES384", "EdDSA", "HS256", "HS384", "HS512"]),
        key_file: z.string().optional().describe(t("私钥 PEM/.p8 文件路径（非 HS* 算法必填）", "Path to the private key PEM/.p8 file (required for non-HS* algorithms)")),
        issuer: z.string().optional().describe("iss"),
        subject: z.string().optional().describe("sub"),
        audience: z.union([z.string(), z.array(z.string())]).optional().describe("aud"),
        key_id: z.string().optional().describe(t("header 中的 kid", "kid in the header")),
        lifetime_seconds: z.number().int().optional().describe(t("有效期，默认 1200（20 分钟）", "Lifetime in seconds, default 1200 (20 minutes)")),
        claims: z.record(z.string(), z.unknown()).optional().describe(t("其他固定声明", "Additional fixed claims")),
        header: z.record(z.string(), z.unknown()).optional().describe(t("其他 header 字段", "Additional header fields")),
        description: descField,
        overwrite: overwriteField,
      },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      const type = a.type ?? "jwt";
      const exists = await guardOverwrite(s, type, a.name, a.overwrite);
      let key: string | undefined;
      let source = "";
      if (a.algorithm.startsWith("HS")) {
        key = (await promptSecret(
            t(
              `请输入 JWT 签名密钥（${a.algorithm}）：\n\n凭证：${norm(type)}/${norm(a.name)}`,
              `Enter the JWT signing key (${a.algorithm}):\n\nCredential: ${norm(type)}/${norm(a.name)}`,
            ),
          )) ?? undefined;
        if (!key) return fail(t("用户取消了输入，未保存。", "Input cancelled by the user; nothing was saved."));
      } else {
        if (!a.key_file) return fail(t(`${a.algorithm} 需要 key_file（私钥文件）。`, `${a.algorithm} requires key_file (private key file).`));
        const f = await importFile(a.key_file, `${norm(type)}/${norm(a.name)}`);
        key = f.content;
        source = f.path;
      }
      const r = await s.request<SetupResult>("setupProtocol", {
        kind: "jwt",
        type,
        name: a.name,
        config: {
          algorithm: a.algorithm,
          issuer: a.issuer,
          subject: a.subject,
          audience: a.audience,
          key_id: a.key_id,
          lifetime_seconds: a.lifetime_seconds,
          claims: a.claims,
          header: a.header,
        },
        secrets: { key },
        description: a.description,
        typeDescription: t("JWT 签发", "JWT signing"),
        overwrite: exists,
      });
      return ok(
        t(
          `${setupMessage(r, "JWT 模板")}。${source ? `建议删除原私钥文件 ${source}。` : ""}`,
          `${setupMessage(r, "JWT template")}.${source ? ` Consider deleting the original private key file ${source}.` : ""}`,
        ),
      );
    }),
  );

  // ---------------- TOTP ----------------
  server.registerTool(
    "credential_setup_totp",
    {
      description: t(
        "保存两步验证（TOTP）种子：用户在弹窗中粘贴 Base32 密钥或 otpauth:// 链接。之后用 credential_totp_code 获取当前验证码。",
        "Save a two-factor (TOTP) seed: the user pastes the Base32 key or otpauth:// link into a dialog. Afterwards use credential_totp_code to get the current code.",
      ),
      inputSchema: {
        purpose: purposeField,
        name: nameField,
        type: optType("totp"),
        issuer: z.string().optional().describe(t("服务名，如 GitHub", "Service name, e.g. GitHub")),
        account: z.string().optional().describe(t("账号", "Account")),
        digits: z.number().int().optional().describe(t("位数，默认 6", "Number of digits, default 6")),
        period: z.number().int().optional().describe(t("周期秒数，默认 30", "Period in seconds, default 30")),
        algorithm: z.enum(["SHA1", "SHA256", "SHA512"]).optional(),
        description: descField,
        overwrite: overwriteField,
      },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      const type = a.type ?? "totp";
      const exists = await guardOverwrite(s, type, a.name, a.overwrite);
      const secret = await promptSecret(
        t(
          `请粘贴两步验证密钥（Base32）或 otpauth:// 链接：\n\n凭证：${norm(type)}/${norm(a.name)}`,
          `Paste the two-factor key (Base32) or otpauth:// link:\n\nCredential: ${norm(type)}/${norm(a.name)}`,
        ),
      );
      if (!secret) return fail(t("用户取消了输入，未保存。", "Input cancelled by the user; nothing was saved."));
      const r = await s.request<SetupResult>("setupProtocol", {
        kind: "totp",
        type,
        name: a.name,
        config: { issuer: a.issuer, account: a.account, digits: a.digits, period: a.period, algorithm: a.algorithm },
        secrets: { secret },
        description: a.description,
        typeDescription: t("两步验证（TOTP）", "Two-factor authentication (TOTP)"),
        overwrite: exists,
      });
      const code = await s.request<{ code: string; remaining_seconds: number }>("totp", { type, name: a.name });
      return ok(
        t(
          `${setupMessage(r, "TOTP")}。当前验证码 ${code.code}（${code.remaining_seconds} 秒后刷新），可与验证器 App 对照确认。`,
          `${setupMessage(r, "TOTP")}. Current code ${code.code} (refreshes in ${code.remaining_seconds} s); compare it with your authenticator app to confirm.`,
        ),
      );
    }),
  );

  server.registerTool(
    "credential_totp_code",
    {
      description: t(
        "获取 TOTP 当前验证码（以及剩余有效秒数；即将过期时附带下一个验证码）",
        "Get the current TOTP code (plus remaining seconds of validity; includes the next code when it is about to expire)",
      ),
      inputSchema: { purpose: purposeField, name: nameField, type: z.string().optional().describe(t("凭证类型；省略时按名字自动查找", "Credential type; looked up by name if omitted")) },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      const type = await resolveType(s, a.name, a.type, ["totp"]);
      const r = await s.request<{ code: string; next_code?: string }>("totp", { type, name: a.name });
      recordSecrets(session.sessionId, [r.code, r.next_code]);
      return ok(t("验证码：", "Code:"), r);
    }),
  );

  // ---------------- AWS ----------------
  server.registerTool(
    "credential_setup_aws",
    {
      description: t(
        "保存 AWS 长期 access key（secret key 由用户在弹窗输入），之后用 credential_aws_credentials 通过 STS 获取临时凭证。" +
          "可配置 role_arn 以 AssumeRole；可关联一个 TOTP 凭证自动完成 MFA。",
        "Save a long-term AWS access key (the user enters the secret key in a dialog); afterwards use credential_aws_credentials to get temporary credentials via STS. " +
          "Optionally set role_arn to AssumeRole, and link a TOTP credential to complete MFA automatically.",
      ),
      inputSchema: {
        purpose: purposeField,
        name: nameField,
        type: optType("aws"),
        access_key_id: z.string().describe(t("Access key ID（AKIA 开头）", "Access key ID (starts with AKIA)")),
        secret_access_key: z
          .string()
          .optional()
          .describe(t("仅当用户已在对话中给出时传入；否则省略，由用户在弹窗输入", "Pass only if the user already gave it in the chat; otherwise omit and the user enters it in a dialog")),
        region: z.string().optional().describe(t("STS 所用区域，默认 us-east-1", "Region used for STS, default us-east-1")),
        role_arn: z.string().optional().describe(t("要扮演的 IAM 角色 ARN", "ARN of the IAM role to assume")),
        external_id: z.string().optional(),
        role_session_name: z.string().optional(),
        duration_seconds: z.number().int().optional().describe(t("临时凭证有效期，默认 3600", "Lifetime of temporary credentials in seconds, default 3600")),
        mfa_serial: z.string().optional().describe(t("MFA 设备 ARN", "MFA device ARN")),
        mfa_totp_name: z.string().optional().describe(t("用于生成 MFA 验证码的 TOTP 凭证名", "Name of the TOTP credential used to generate MFA codes")),
        description: descField,
        overwrite: overwriteField,
      },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      const type = a.type ?? "aws";
      const exists = await guardOverwrite(s, type, a.name, a.overwrite);
      const mfaTotp = a.mfa_totp_name
        ? { type: await resolveType(s, a.mfa_totp_name, undefined, ["totp"]), name: a.mfa_totp_name }
        : undefined;
      const region = safeDisplay(a.region ?? "us-east-1", /^[a-z]{2}(-gov)?-[a-z]+-\d$/, "region");
      const accessKeyId = safeDisplay(a.access_key_id, /^AKIA[A-Z0-9]{12,124}$/, t("access_key_id（应为 AKIA 开头的长期密钥）", "access_key_id (must be a long-term key starting with AKIA)"));
      const secret = a.secret_access_key || await promptSecret(
        t(
          `请输入 AWS secret access key：\n\n凭证：${norm(type)}/${norm(a.name)}\nAccess key ID：${accessKeyId}\n\n它只用于签名发往 sts.${region}.amazonaws.com 的请求。`,
          `Enter the AWS secret access key:\n\nCredential: ${norm(type)}/${norm(a.name)}\nAccess key ID: ${accessKeyId}\n\nIt is only used to sign requests to sts.${region}.amazonaws.com.`,
        ),
      );
      if (!secret) return fail(t("用户取消了输入，未保存。", "Input cancelled by the user; nothing was saved."));
      const r = await s.request<SetupResult>("setupProtocol", {
        kind: "aws",
        type,
        name: a.name,
        config: {
          access_key_id: a.access_key_id,
          region,
          role_arn: a.role_arn,
          external_id: a.external_id,
          role_session_name: a.role_session_name,
          duration_seconds: a.duration_seconds,
          mfa_serial: a.mfa_serial,
          mfa_totp: mfaTotp,
        },
        secrets: { secret_access_key: secret },
        description: a.description,
        typeDescription: "AWS",
        overwrite: exists,
      });
      const verify = await session
        .request<{ expiration: string }>("aws", { type, name: a.name, force: true })
        .then((c) => t(`已验证可以获取临时凭证（有效至 ${c.expiration}）`, `verified that temporary credentials can be obtained (valid until ${c.expiration})`))
        .catch((e: Error) => t(`⚠️ 已保存，但获取临时凭证失败：${e.message}`, `⚠️ saved, but getting temporary credentials failed: ${e.message}`));
      return ok(t(`${setupMessage(r, "AWS 凭证")}；${verify}。`, `${setupMessage(r, "AWS credential")}; ${verify}.`));
    }),
  );

  server.registerTool(
    "credential_aws_credentials",
    {
      description: t(
        "通过 STS 获取 AWS 临时凭证（AccessKeyId / SecretAccessKey / SessionToken），有缓存。" +
          "使用时设置环境变量 AWS_ACCESS_KEY_ID、AWS_SECRET_ACCESS_KEY、AWS_SESSION_TOKEN、AWS_REGION。",
        "Get temporary AWS credentials (AccessKeyId / SecretAccessKey / SessionToken) via STS, with caching. " +
          "To use them, set the environment variables AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_REGION.",
      ),
      inputSchema: {
        purpose: purposeField,
        name: nameField,
        type: z.string().optional().describe(t("凭证类型；省略时按名字自动查找", "Credential type; looked up by name if omitted")),
        duration_seconds: z.number().int().optional().describe(t("有效期（秒）；指定时不使用缓存", "Lifetime in seconds; bypasses the cache when specified")),
        force_refresh: z.boolean().optional(),
      },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      const type = await resolveType(s, a.name, a.type, ["aws"]);
      const c = await s.request<{ access_key_id: string; secret_access_key: string; session_token: string }>("aws", {
        type,
        name: a.name,
        duration_seconds: a.duration_seconds,
        force: a.force_refresh === true,
      });
      recordSecrets(session.sessionId, [c.access_key_id, c.secret_access_key, c.session_token]);
      return ok(t("AWS 临时凭证：", "AWS temporary credentials:"), c);
    }),
  );
}
