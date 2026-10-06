import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { oauthProviderNames, resolveOAuthProvider } from "../templates.js";
import { promptSecret, showNotice } from "../dialog.js";
import { xoauth2 } from "../mail.js";
import { copyToClipboard, discoverOidc, openInBrowser, runBrowserFlow } from "../oauth-flow.js";
import type { HelperSession } from "../session.js";
import { CLIENT_ID_RE, fail, guardOverwrite, httpsHost, importFile, norm, ok, purposeField, resolveType, safeDisplay, tryInfo, wrap } from "./common.js";

const nameField = z.string().describe("凭证名（小写），如 google-work、github-bot");
const optType = (kind: string) => z.string().optional().describe(`凭证类型，默认 "${kind}"（不存在时自动创建）`);
const descField = z.string().optional().describe("凭证说明");
const overwriteField = z.boolean().optional().describe("已存在时替换（会弹窗请用户确认）");

type SetupResult = { type: string; name: string; typeCreated: boolean; replaced: boolean };

function setupMessage(r: SetupResult, what: string): string {
  const steps = [];
  if (r.typeCreated) steps.push(`凭证类型 "${r.type}" 不存在，已先创建`);
  steps.push(`${r.replaced ? "已替换" : "已保存"} ${what} "${r.type}/${r.name}"`);
  return steps.join("；");
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
      description:
        "配置并完成 OAuth 2.0 授权，refresh token 加密保存，之后用 credential_access_token 获取 access token（agent 拿不到 refresh token 和 client secret）。\n" +
        "flow：authorization_code（默认，打开浏览器，本地回调 + PKCE）、device_code（显示验证码让用户在浏览器输入）、client_credentials（机器对机器，无需用户交互）。\n" +
        `provider：${oauthProviderNames()}；其他服务用 issuer（OIDC 自动发现，如 Okta/Auth0/Keycloak）或手动指定端点。\n` +
        "client secret 不要通过参数传入，省略即可，会弹窗让用户输入。\n" +
        "已存在的凭证：只传 name 即可重新授权（沿用已保存的配置）；传入新的 scopes 等参数会更新配置。",
      inputSchema: {
        purpose: purposeField,
        name: nameField,
        type: optType("oauth2"),
        provider: z.string().optional().describe("服务商：内置预设（google、github、microsoft、outlook、outlook_graph、gitlab、dropbox）或模板库中的 OAuth2 模板 id；自定义服务省略"),
        flow: z.enum(["authorization_code", "device_code", "client_credentials"]).optional(),
        client_id: z.string().optional().describe("OAuth client ID（新建时必填）"),
        public_client: z.boolean().optional().describe("公共客户端（无 client secret，仅靠 PKCE）"),
        scopes: z.array(z.string()).optional().describe("授权范围，如 [\"https://www.googleapis.com/auth/gmail.readonly\"]"),
        tenant: z.string().optional().describe("Microsoft 租户 ID 或域名，默认 common"),
        issuer: z.string().optional().describe("OIDC issuer URL，用于自动发现端点"),
        authorization_url: z.string().optional(),
        token_url: z.string().optional(),
        device_authorization_url: z.string().optional(),
        redirect_uri: z.string().optional().describe("固定回调地址（必须是本机回环地址）；默认随机端口 http://127.0.0.1:<port>/callback"),
        extra_auth_params: z.record(z.string(), z.string()).optional().describe("授权请求附加参数"),
        token_auth_method: z.enum(["client_secret_post", "client_secret_basic", "none"]).optional(),
        description: descField,
      },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      const type = a.type ?? "oauth2";
      const existing = await tryInfo(s, type, a.name);
      if (existing && existing.kind !== "oauth2") return fail(`"${existing.type}/${existing.name}" 已存在且不是 OAuth 凭证。`);
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
        if (a.provider && !preset) return fail(`未知的 provider "${a.provider}"。可用：${oauthProviderNames()}；其他服务请用 issuer 或手动指定端点。`);
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
        if (!config.client_id) return fail("新建 OAuth 凭证需要 client_id。");
        if (!config.token_url) return fail("缺少 token_url：请指定 provider、issuer 或 token_url。");
        if (flow === "authorization_code" && !config.authorization_url) return fail("授权码流程缺少 authorization_url。");
        if (flow === "device_code" && !config.device_authorization_url) return fail("该服务商没有设备码端点，请改用 authorization_code 或指定 device_authorization_url。");
        if (flow === "client_credentials" && publicClient) return fail("client_credentials 流程需要 client secret。");
        // 会显示在弹窗中的值必须先严格校验，防止 agent 写入诱导文字（如“请输入 Mac 密码”）
        const clientId = safeDisplay(config.client_id, CLIENT_ID_RE, "client_id");
        const tokenHost = httpsHost(config.token_url, "token_url");

        // 修改已有凭证的配置：一律需要用户确认（即使是公共客户端、即使只改 scope）
        if (existing) await guardOverwrite(s, type, a.name, true);

        // ---- client secret：端点和 client 不变时沿用；否则必须由用户重新输入 ----
        const sameBinding = !!existing && SECRET_BINDING_KEYS.every((k) => (base as Record<string, unknown>)[k] === (config as Record<string, unknown>)[k]);
        const askSecret = async () => {
          const s = await promptSecret(`请输入 OAuth client secret\n\n凭证：${label}\nclient_id：${clientId}\n它只会被发送到：${tokenHost}`);
          if (!s) throw new Error("用户取消了输入，未保存。");
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
            typeDescription: "OAuth 2.0 授权",
            overwrite: !!existing,
          });
        try {
          setup = await doSetup(!publicClient && sameBinding);
        } catch (e) {
          // helper 的绑定校验更严格（如切换 flow 后端点被规范化），以它为准：请用户重新输入
          if (!publicClient && sameBinding && /已变化/.test((e as Error).message)) {
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
        const userCode = safeDisplay(d.user_code, /^[A-Za-z0-9-]{4,20}$/, "服务商返回的 user_code");
        const url = d.verification_uri_complete ?? d.verification_uri;
        if (url && (url.length > 300 || /\s/.test(url))) throw new Error("服务商返回的验证网址格式异常");
        copyToClipboard(userCode);
        if (url) await openInBrowser(url).catch(() => {});
        const close = showNotice(`请在浏览器中完成授权。\n\n验证码：${userCode}\n（已复制到剪贴板）\n\n网址：${url ?? "见服务商说明"}`, d.expires_in);
        try {
          let interval = d.interval;
          const deadline = Date.now() + d.expires_in * 1000;
          for (;;) {
            if (Date.now() > deadline) return fail("设备码已过期，请重新调用 credential_oauth_login。");
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
            if (p.status === "denied") return fail("用户拒绝了授权。");
            if (p.status === "expired") return fail("设备码已过期，请重新调用 credential_oauth_login。");
          }
        } finally {
          close();
        }
      } else {
        const t = await s.request<Record<string, unknown>>("accessToken", { type, name: a.name, force: true });
        result = { scope: t.scope, expires_at: t.expires_at };
      }
      const head = setup ? setupMessage(setup, "OAuth 配置") + "；" : "";
      return ok(`${head}授权完成。之后用 credential_access_token（name: "${norm(a.name)}"）获取 access token。`, result);
    }),
  );

  // ---------------- 统一取 token ----------------
  server.registerTool(
    "credential_access_token",
    {
      description:
        "获取短期 access token，适用于 oauth2（自动刷新）、google_service_account、github_app（installation token）、jwt（按模板签发）。" +
        "返回的 token 有效期通常为 1 小时以内；长期秘密不会返回。",
      inputSchema: {
        purpose: purposeField,
        name: nameField,
        type: z.string().optional().describe("凭证类型；省略时按名字自动查找"),
        scopes: z.array(z.string()).optional().describe("仅 google_service_account：本次请求的 scope（默认用设置时的）"),
        repositories: z.array(z.string()).optional().describe("仅 github_app：把 token 限制到这些仓库名"),
        permissions: z.record(z.string(), z.string()).optional().describe("仅 github_app：收窄权限，如 {\"contents\": \"read\"}"),
        force_refresh: z.boolean().optional().describe("忽略缓存，强制获取新 token"),
        format: z
          .enum(["default", "xoauth2"])
          .optional()
          .describe("xoauth2：额外返回 IMAP/SMTP/POP 的 SASL XOAUTH2 认证字符串（Gmail、Outlook 邮箱用）"),
        username: z.string().optional().describe("仅 format=xoauth2：邮箱地址；省略则使用授权时识别出的账号"),
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
        if (!username) return fail("无法确定邮箱地址：请传 username，或在授权 scope 中包含 openid email。");
        return ok("access token（含 XOAUTH2）：", { ...r, username, xoauth2: xoauth2(username, r.access_token) });
      }
      return ok("access token：", r);
    }),
  );

  // ---------------- Google 服务账号 ----------------
  server.registerTool(
    "credential_setup_google_service_account",
    {
      description: "导入 Google 服务账号 JSON 密钥文件（内容不会进入 AI 上下文）。之后用 credential_access_token 获取 access token。",
      inputSchema: {
        purpose: purposeField,
        name: nameField,
        type: optType("google_service_account"),
        key_file: z.string().describe("服务账号 JSON 密钥文件路径"),
        scopes: z.array(z.string()).optional().describe("默认 scope，省略则为 cloud-platform"),
        subject: z.string().optional().describe("域范围授权时要模拟的 Workspace 用户邮箱"),
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
        typeDescription: "Google 服务账号",
        overwrite: exists,
      });
      const verify = await session
        .request<{ expires_at: string; account: string }>("accessToken", { type, name: a.name, force: true })
        .then((t) => `已验证可以获取 token（${t.account}）`)
        .catch((e: Error) => `⚠️ 已保存，但获取 token 失败：${e.message}`);
      return ok(`${setupMessage(r, "Google 服务账号")}；${verify}。建议删除原密钥文件 ${f.path}。`);
    }),
  );

  // ---------------- GitHub App ----------------
  server.registerTool(
    "credential_setup_github_app",
    {
      description: "设置 GitHub App（私钥从 .pem 文件导入）。之后用 credential_access_token 获取 1 小时有效的 installation token。",
      inputSchema: {
        purpose: purposeField,
        name: nameField,
        type: optType("github_app"),
        app_id: z.string().describe("App ID（数字）或 Client ID"),
        private_key_file: z.string().describe("App 私钥 .pem 文件路径"),
        installation_id: z.string().optional().describe("installation ID；App 只装在一个账号上时可省略"),
        api_base_url: z.string().optional().describe("GitHub Enterprise Server 的 API 地址，默认 https://api.github.com"),
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
        .then(() => "已验证可以获取 installation token")
        .catch((e: Error) => `⚠️ 已保存，但获取 token 失败：${e.message}`);
      return ok(`${setupMessage(r, "GitHub App")}；${verify}。建议删除原私钥文件 ${f.path}。`);
    }),
  );

  // ---------------- 通用 JWT ----------------
  server.registerTool(
    "credential_setup_jwt",
    {
      description:
        "设置 JWT 签发模板（如 App Store Connect API：algorithm=ES256, issuer=Issuer ID, key_id=Key ID, audience=appstoreconnect-v1）。" +
        "私钥从文件导入；HS* 算法的密钥由用户在弹窗输入。之后用 credential_access_token 获取签好的短期 JWT。",
      inputSchema: {
        purpose: purposeField,
        name: nameField,
        type: optType("jwt"),
        algorithm: z.enum(["RS256", "RS384", "RS512", "PS256", "ES256", "ES384", "EdDSA", "HS256", "HS384", "HS512"]),
        key_file: z.string().optional().describe("私钥 PEM/.p8 文件路径（非 HS* 算法必填）"),
        issuer: z.string().optional().describe("iss"),
        subject: z.string().optional().describe("sub"),
        audience: z.union([z.string(), z.array(z.string())]).optional().describe("aud"),
        key_id: z.string().optional().describe("header 中的 kid"),
        lifetime_seconds: z.number().int().optional().describe("有效期，默认 1200（20 分钟）"),
        claims: z.record(z.string(), z.unknown()).optional().describe("其他固定声明"),
        header: z.record(z.string(), z.unknown()).optional().describe("其他 header 字段"),
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
        key = (await promptSecret(`请输入 JWT 签名密钥（${a.algorithm}）：\n\n凭证：${norm(type)}/${norm(a.name)}`)) ?? undefined;
        if (!key) return fail("用户取消了输入，未保存。");
      } else {
        if (!a.key_file) return fail(`${a.algorithm} 需要 key_file（私钥文件）。`);
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
        typeDescription: "JWT 签发",
        overwrite: exists,
      });
      return ok(`${setupMessage(r, "JWT 模板")}。${source ? `建议删除原私钥文件 ${source}。` : ""}`);
    }),
  );

  // ---------------- TOTP ----------------
  server.registerTool(
    "credential_setup_totp",
    {
      description: "保存两步验证（TOTP）种子：用户在弹窗中粘贴 Base32 密钥或 otpauth:// 链接。之后用 credential_totp_code 获取当前验证码。",
      inputSchema: {
        purpose: purposeField,
        name: nameField,
        type: optType("totp"),
        issuer: z.string().optional().describe("服务名，如 GitHub"),
        account: z.string().optional().describe("账号"),
        digits: z.number().int().optional().describe("位数，默认 6"),
        period: z.number().int().optional().describe("周期秒数，默认 30"),
        algorithm: z.enum(["SHA1", "SHA256", "SHA512"]).optional(),
        description: descField,
        overwrite: overwriteField,
      },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      const type = a.type ?? "totp";
      const exists = await guardOverwrite(s, type, a.name, a.overwrite);
      const secret = await promptSecret(`请粘贴两步验证密钥（Base32）或 otpauth:// 链接：\n\n凭证：${norm(type)}/${norm(a.name)}`);
      if (!secret) return fail("用户取消了输入，未保存。");
      const r = await s.request<SetupResult>("setupProtocol", {
        kind: "totp",
        type,
        name: a.name,
        config: { issuer: a.issuer, account: a.account, digits: a.digits, period: a.period, algorithm: a.algorithm },
        secrets: { secret },
        description: a.description,
        typeDescription: "两步验证（TOTP）",
        overwrite: exists,
      });
      const code = await s.request<{ code: string; remaining_seconds: number }>("totp", { type, name: a.name });
      return ok(`${setupMessage(r, "TOTP")}。当前验证码 ${code.code}（${code.remaining_seconds} 秒后刷新），可与验证器 App 对照确认。`);
    }),
  );

  server.registerTool(
    "credential_totp_code",
    {
      description: "获取 TOTP 当前验证码（以及剩余有效秒数；即将过期时附带下一个验证码）",
      inputSchema: { purpose: purposeField, name: nameField, type: z.string().optional().describe("凭证类型；省略时按名字自动查找") },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      const type = await resolveType(s, a.name, a.type, ["totp"]);
      return ok("验证码：", await s.request("totp", { type, name: a.name }));
    }),
  );

  // ---------------- AWS ----------------
  server.registerTool(
    "credential_setup_aws",
    {
      description:
        "保存 AWS 长期 access key（secret key 由用户在弹窗输入），之后用 credential_aws_credentials 通过 STS 获取临时凭证。" +
        "可配置 role_arn 以 AssumeRole；可关联一个 TOTP 凭证自动完成 MFA。",
      inputSchema: {
        purpose: purposeField,
        name: nameField,
        type: optType("aws"),
        access_key_id: z.string().describe("Access key ID（AKIA 开头）"),
        region: z.string().optional().describe("STS 所用区域，默认 us-east-1"),
        role_arn: z.string().optional().describe("要扮演的 IAM 角色 ARN"),
        external_id: z.string().optional(),
        role_session_name: z.string().optional(),
        duration_seconds: z.number().int().optional().describe("临时凭证有效期，默认 3600"),
        mfa_serial: z.string().optional().describe("MFA 设备 ARN"),
        mfa_totp_name: z.string().optional().describe("用于生成 MFA 验证码的 TOTP 凭证名"),
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
      const accessKeyId = safeDisplay(a.access_key_id, /^AKIA[A-Z0-9]{12,124}$/, "access_key_id（应为 AKIA 开头的长期密钥）");
      const secret = await promptSecret(
        `请输入 AWS secret access key：\n\n凭证：${norm(type)}/${norm(a.name)}\nAccess key ID：${accessKeyId}\n\n它只用于签名发往 sts.${region}.amazonaws.com 的请求。`,
      );
      if (!secret) return fail("用户取消了输入，未保存。");
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
        .then((c) => `已验证可以获取临时凭证（有效至 ${c.expiration}）`)
        .catch((e: Error) => `⚠️ 已保存，但获取临时凭证失败：${e.message}`);
      return ok(`${setupMessage(r, "AWS 凭证")}；${verify}。`);
    }),
  );

  server.registerTool(
    "credential_aws_credentials",
    {
      description:
        "通过 STS 获取 AWS 临时凭证（AccessKeyId / SecretAccessKey / SessionToken），有缓存。" +
        "使用时设置环境变量 AWS_ACCESS_KEY_ID、AWS_SECRET_ACCESS_KEY、AWS_SESSION_TOKEN、AWS_REGION。",
      inputSchema: {
        purpose: purposeField,
        name: nameField,
        type: z.string().optional().describe("凭证类型；省略时按名字自动查找"),
        duration_seconds: z.number().int().optional().describe("有效期（秒）；指定时不使用缓存"),
        force_refresh: z.boolean().optional(),
      },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      const type = await resolveType(s, a.name, a.type, ["aws"]);
      const c = await s.request("aws", { type, name: a.name, duration_seconds: a.duration_seconds, force: a.force_refresh === true });
      return ok("AWS 临时凭证：", c);
    }),
  );
}
