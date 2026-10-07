import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { PLACEHOLDER_RE, injectStrings, placeholders, type CredentialTemplate } from "../../shared/templates.js";
import { promptSecret } from "../dialog.js";
import type { HelperSession, Requester } from "../session.js";
import { writeGatewayEnv } from "../gateway-env.js";
import { getTemplate, searchTemplates, summarize } from "../templates.js";
import { fail, guardOverwrite, norm, ok, purposeField, resolveType, wrap } from "./common.js";
import { t } from "../../shared/i18n.js";

const PROXY_KINDS = ["static", "oauth2", "google_service_account", "github_app", "jwt"];
const HOST_RE = /^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/;

/** 模板 id → 默认凭证类型名：openAiApi → open_ai_api */
export function typeFromTemplate(id: string): string {
  return (
    id
      .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
      .toLowerCase()
      .replace(/[^a-z0-9_.-]+/g, "_")
      .replace(/^[^a-z0-9]+/, "")
      .slice(0, 64) || "api_key"
  );
}

/** 用非敏感字段值渲染 URL 模板，算出其域名（路径里的秘密占位符不影响域名） */
export function hostFromUrlTemplate(urlTpl: string, attrs: Record<string, string>): string | null {
  const MARK = "zzsecretzz";
  const rendered = urlTpl.replace(PLACEHOLDER_RE, (_m, n: string) => (Object.hasOwn(attrs, n) ? attrs[n]! : MARK));
  try {
    const u = new URL(rendered);
    const h = u.hostname.toLowerCase();
    return u.protocol === "https:" && !h.includes(MARK) && HOST_RE.test(h) ? h : null;
  } catch {
    return null;
  }
}

const cleanLabel = (s: string) => s.replace(/[\u0000-\u001f\u007f]+/g, " ").slice(0, 100);

export interface TemplateSetArgs {
  template: string;
  type?: string;
  name: string;
  fields?: Record<string, string | number | boolean>;
  secret_fields?: string[];
  allowed_hosts?: string[];
  proxy_only?: boolean;
  description?: string;
  overwrite?: boolean;
  verify?: boolean;
}

/** 按模板保存 static 凭证：非敏感字段来自参数/默认值，秘密字段逐个弹窗输入，同时写入代理配置 */
export async function setFromTemplate(s: Requester, a: TemplateSetArgs) {
  const tpl = getTemplate(a.template);
  if (!tpl) throw new Error(t(`找不到模板 "${a.template}"，可用 credential_templates 搜索`, `Template "${a.template}" not found; search with credential_templates`));
  if (tpl.kind === "oauth2")
    throw new Error(t(`"${tpl.id}" 是 OAuth2 模板，请用 credential_oauth_login（provider: "${tpl.id}"）`, `"${tpl.id}" is an OAuth2 template; use credential_oauth_login (provider: "${tpl.id}")`));
  const type = a.type ?? typeFromTemplate(tpl.id);
  const label = `${norm(type)}/${norm(a.name)}`;

  // ---- 非敏感字段 ----
  const byName = new Map(tpl.fields.map((f) => [f.name, f]));
  const attrs: Record<string, string> = {};
  for (const f of tpl.fields) if (!f.secret && f.default !== undefined) attrs[f.name] = String(f.default);
  for (const [k, v] of Object.entries(a.fields ?? {})) {
    const f = byName.get(k);
    if (!f)
      throw new Error(
        t(
          `模板 ${tpl.id} 没有字段 ${k}（可用：${tpl.fields.map((x) => x.name).join("、")}）`,
          `Template ${tpl.id} has no field ${k} (available: ${tpl.fields.map((x) => x.name).join(", ")})`,
        ),
      );
    if (f.secret) throw new Error(t(`${k} 是秘密字段，不能通过参数传入，会弹窗让用户输入`, `${k} is a secret field; it cannot be passed as a parameter - the user will be prompted in a dialog`));
    attrs[k] = String(v);
  }
  const missing = tpl.fields.filter((f) => !f.secret && f.required && !attrs[f.name]);
  if (missing.length)
    throw new Error(
      t(
        `缺少必填字段：${missing.map((f) => `${f.name}（${f.label}）`).join("、")}，请通过 fields 传入`,
        `Missing required fields: ${missing.map((f) => `${f.name} (${f.label})`).join(", ")}; pass them via fields`,
      ),
    );

  // ---- 要输入的秘密字段：指定的 / 必填的 / 注入规则引用的 ----
  const secretFields = tpl.fields.filter((f) => f.secret);
  const referenced = new Set(placeholders(injectStrings(tpl.inject)));
  let wanted = a.secret_fields?.length
    ? a.secret_fields
    : secretFields.filter((f) => f.required || referenced.has(f.name)).map((f) => f.name);
  if (!wanted.length) wanted = secretFields.map((f) => f.name);
  for (const n of [...referenced]) if (byName.get(n)?.secret && !wanted.includes(n)) wanted.push(n);
  for (const n of wanted) if (!byName.get(n)?.secret) throw new Error(t(`${n} 不是模板 ${tpl.id} 的秘密字段`, `${n} is not a secret field of template ${tpl.id}`));

  // ---- 允许的域名 ----
  let hosts = a.allowed_hosts?.map((h) => h.trim().toLowerCase());
  if (!hosts?.length) {
    const computed = new Set<string>();
    const fromTest = tpl.test ? hostFromUrlTemplate(tpl.test.url, attrs) : null;
    if (fromTest) computed.add(fromTest);
    else for (const h of tpl.hosts ?? []) computed.add(h);
    hosts = [...computed];
  }
  for (const h of hosts) if (!HOST_RE.test(h)) throw new Error(t(`非法的域名 ${h}`, `Invalid host ${h}`));
  if (tpl.inject && !hosts.length) throw new Error(
      t(
        "无法从模板确定 API 域名，请通过 allowed_hosts 指定（如 [\"api.example.com\"]）",
        "Cannot determine the API host from the template; specify it with allowed_hosts (e.g. [\"api.example.com\"])",
      ),
    );

  const exists = await guardOverwrite(s, type, a.name, a.overwrite);

  // ---- 弹窗输入秘密（文案只含模板名、字段名和校验过的域名） ----
  const secrets: Record<string, string> = {};
  for (const n of wanted) {
    const f = byName.get(n)!;
    const where = tpl.inject ? t(`\n该凭证只会被代理发送到：${hosts.join("、")}`, `\nThis credential will only be sent by the proxy to: ${hosts.join(", ")}`) : "";
    const v = await promptSecret(
      t(
        `请输入「${cleanLabel(tpl.name)}」的 ${cleanLabel(f.label)}\n\n凭证：${label}${where}`,
        `Enter the ${cleanLabel(f.label)} for "${cleanLabel(tpl.name)}"\n\nCredential: ${label}${where}`,
      ),
    );
    if (!v) {
      if (f.required || referenced.has(n)) throw new Error(t("用户取消了输入，未保存。", "The user cancelled input; nothing was saved."));
      continue;
    }
    secrets[n] = v;
  }

  // 验证请求只在其引用的字段都有值时保留
  const have = new Set([...Object.keys(attrs), ...Object.keys(secrets)]);
  const test =
    tpl.test && placeholders([tpl.test.url, ...Object.values(tpl.test.headers ?? {}), ...Object.values(tpl.test.query ?? {})]).every((n) => have.has(n))
      ? tpl.test
      : undefined;
  const http = tpl.inject ? { inject: tpl.inject, allowed_hosts: hosts, proxy_only: a.proxy_only === true, ...(test ? { test } : {}) } : undefined;

  const r = await s.request<{ type: string; name: string; typeCreated: boolean; replaced: boolean }>("set", {
    type,
    name: a.name,
    secrets,
    attributes: attrs,
    http,
    template: tpl.id,
    description: a.description ?? tpl.name,
    typeDescription: tpl.name,
    overwrite: exists,
  });

  let verify: unknown = t("模板没有验证请求", "Template has no verification request");
  if (http && test && a.verify !== false) {
    verify = await s.request("httpTest", { type: r.type, name: r.name }).catch((e: Error) => ({ ok: false, error: e.message }));
  }
  return { ...r, template: tpl.id, secret_fields: Object.keys(secrets), proxy: http ? { allowed_hosts: hosts, proxy_only: http.proxy_only } : t("不可代理（模板没有注入规则）", "Not proxyable (template has no injection rule)"),
    verify,
  };
}

function templateDetail(tpl: CredentialTemplate) {
  return {
    ...summarize(tpl),
    source: tpl.source,
    docs: tpl.docs,
    fields: tpl.fields,
    inject: tpl.inject,
    test: tpl.test,
    oauth2: tpl.oauth2,
    how_to_use:
      tpl.kind === "oauth2"
        ? `credential_oauth_login { provider: "${tpl.id}", client_id: ..., name: ... }`
        : t(
            `credential_set { template: "${tpl.id}", name: ..., fields: { 非敏感字段 } }（秘密字段会弹窗输入）`,
            `credential_set { template: "${tpl.id}", name: ..., fields: { non-sensitive fields } } (secret fields are entered in a dialog)`,
          ),
  };
}

export function registerHttpTools(server: McpServer, session: HelperSession): void {
  server.registerTool(
    "credential_templates",
    {
      description: t(
        "搜索凭证模板（内置通用模板 + 自带模板库中的常用服务，以及可选的本地 n8n 模板库）。模板定义了需要哪些字段、哪些是秘密、如何注入请求（代理调用）、如何验证。" +
          "传 id 查看完整模板。不需要解锁。",
        "Search credential templates (built-in generic templates + common services from the bundled catalog, plus the optional local n8n catalog). A template defines which fields are needed, which are secret, how they are injected into requests (proxied calls) and how to verify them. " +
          "Pass id to see the full template. Does not require unlocking.",
      ),
      inputSchema: {
        query: z.string().optional().describe(t("服务名关键词，如 openai、github、notion", "Service name keyword, e.g. openai, github, notion")),
        id: z.string().optional().describe(t("模板 id，返回完整模板", "Template id; returns the full template")),
        kind: z.enum(["static", "oauth2"]).optional(),
        limit: z.number().int().optional().describe(t("默认 20，最多 100", "Default 20, max 100")),
      },
    },
    wrap(async (a) => {
      if (a.id) {
        const tpl = getTemplate(a.id);
        return tpl ? ok(t("模板：", "Template:"), templateDetail(tpl)) : fail(t(`找不到模板 "${a.id}"`, `Template "${a.id}" not found`));
      }
      const list = searchTemplates(a.query, a.kind, Math.min(Math.max(a.limit ?? 20, 1), 100));
      return ok(t(`找到 ${list.length} 个模板：`, `Found ${list.length} template(s):`), list.map(summarize));
    }),
  );

  server.registerTool(
    "credential_http_request",
    {
      description: t(
        "代理调用：由凭证库把凭证注入 HTTP 请求并发出，只返回响应——agent 看不到 API key / token。" +
          "适用于配置了代理的 static 凭证（模板或手动规则）以及 oauth2 / google_service_account / github_app / jwt 凭证（自动注入 access token）。" +
          "流式（SSE）响应会被完整接收，并在 stream.text 中返回从大模型增量拼出的完整文本；程序需要边收边输出时请用 credential_gateway。" +
          "只允许 https、只能发往该凭证允许的域名；不跟随重定向；响应中出现的秘密会被替换为 [REDACTED]。",
        "Proxied call: the vault injects the credential into the HTTP request, sends it and returns only the response - the agent never sees the API key / token. " +
          "Works with static credentials that have a proxy configuration (from a template or manual rules) and with oauth2 / google_service_account / github_app / jwt credentials (access token injected automatically). " +
          "Streaming (SSE) responses are received in full, and the text assembled from LLM deltas is returned in stream.text; for programs that need to stream incrementally, use credential_gateway. " +
          "HTTPS only, and only to the credential's allowed hosts; redirects are not followed; secrets appearing in the response are replaced with [REDACTED].",
      ),
      inputSchema: {
        purpose: purposeField,
        name: z.string().describe(t("凭证名", "Credential name")),
        type: z.string().optional().describe(t("凭证类型；省略时按名字自动查找", "Credential type; looked up by name if omitted")),
        method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]).optional().describe(t("默认 GET", "Default GET")),
        url: z.string().describe(t("完整 https URL", "Full https URL")),
        headers: z.record(z.string(), z.string()).optional().describe(t("额外请求头（认证头由凭证库注入，不要自己传）", "Extra request headers (auth headers are injected by the vault; do not pass them yourself)")),
        query: z.record(z.string(), z.string()).optional(),
        body: z.union([z.string(), z.record(z.string(), z.unknown()), z.array(z.unknown())]).optional().describe(t("请求体：字符串原样发送；对象/数组按 JSON 发送", "Request body: strings are sent as-is; objects/arrays are sent as JSON")),
      },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      const type = await resolveType(s, a.name, a.type, PROXY_KINDS);
      const r = await s.request("httpRequest", { type, name: a.name, method: a.method, url: a.url, headers: a.headers, query: a.query, body: a.body });
      return ok(t("响应：", "Response:"), r);
    }),
  );

  server.registerTool(
    "credential_test",
    {
      description: t(
        "用凭证的验证请求（来自模板，或 credential_configure_http 设置的 test）检查凭证是否有效。只返回是否成功、状态码和响应摘要。",
        "Check whether a credential works using its verification request (from the template, or the test set via credential_configure_http). Returns only success, status code and a response summary.",
      ),
      inputSchema: {
        purpose: purposeField,
        name: z.string(),
        type: z.string().optional().describe(t("凭证类型；省略时按名字自动查找", "Credential type; looked up by name if omitted")),
      },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      const type = await resolveType(s, a.name, a.type, PROXY_KINDS);
      const r = await s.request<{ ok: boolean; status: number }>("httpTest", { type, name: a.name });
      return r.ok
        ? ok(t(`凭证有效（HTTP ${r.status}）。`, `Credential is valid (HTTP ${r.status}).`), r)
        : fail(t(`凭证验证未通过（HTTP ${r.status}）。`, `Credential verification failed (HTTP ${r.status}).`) + `\n${JSON.stringify(r, null, 2)}`);
    }),
  );

  server.registerTool(
    "credential_configure_http",
    {
      description: t(
        "设置或修改凭证的代理调用配置：允许的域名、注入规则（static 凭证）、验证请求、是否只能代理调用（禁止读出原值）。" +
          "新增域名、修改注入规则、关闭「只能代理调用」、删除配置都会由凭证库弹窗请用户确认。" +
          "注入规则用 {{字段名}} 引用凭证字段（单值凭证用 {{value}}），如 {\"headers\": {\"Authorization\": \"Bearer {{value}}\"}}。",
        "Set or change a credential's proxy configuration: allowed hosts, injection rule (static credentials), verification request, and whether it is proxy-only (raw value cannot be read). " +
          "Adding hosts, changing the injection rule, turning off proxy-only, or removing the configuration requires user confirmation in a vault dialog. " +
          "Injection rules reference credential fields as {{field_name}} ({{value}} for single-value credentials), e.g. {\"headers\": {\"Authorization\": \"Bearer {{value}}\"}}.",
      ),
      inputSchema: {
        purpose: purposeField,
        name: z.string(),
        type: z.string().optional().describe(t("凭证类型；省略时按名字自动查找", "Credential type; looked up by name if omitted")),
        allowed_hosts: z.array(z.string()).optional().describe(t("允许发往的域名，如 [\"api.example.com\"]；*.example.com 匹配子域名", "Hosts requests may be sent to, e.g. [\"api.example.com\"]; *.example.com matches subdomains")),
        inject: z
          .object({
            headers: z.record(z.string(), z.string()).optional(),
            query: z.record(z.string(), z.string()).optional(),
            basic: z.object({ username: z.string(), password: z.string() }).optional(),
          })
          .optional()
          .describe(
            t(
              "注入规则。static 凭证用 {{字段名}}；oauth2 等 token 类凭证默认注入 Bearer，也可用 {{access_token}} 自定义，如 GitHub git 推送：{\"basic\": {\"username\": \"x-access-token\", \"password\": \"{{access_token}}\"}}",
              "Injection rule. Static credentials use {{field}}; token credentials (oauth2 etc.) inject a Bearer token by default or can use {{access_token}}, e.g. for GitHub git pushes: {\"basic\": {\"username\": \"x-access-token\", \"password\": \"{{access_token}}\"}}",
            ),
          ),
        test: z
          .object({
            method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]).optional(),
            url: z.string(),
            headers: z.record(z.string(), z.string()).optional(),
            query: z.record(z.string(), z.string()).optional(),
          })
          .optional()
          .describe(t("验证请求，如 {\"url\": \"https://api.example.com/me\"}", "Verification request, e.g. {\"url\": \"https://api.example.com/me\"}")),
        proxy_only: z.boolean().optional().describe(t("true：只能代理调用，credential_get 不再返回原值", "true: proxy-only; credential_get no longer returns the raw value")),
        remove: z.boolean().optional().describe(t("删除代理配置", "Remove the proxy configuration")),
      },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      const type = await resolveType(s, a.name, a.type, PROXY_KINDS);
      const r = await s.request("httpConfigure", {
        type,
        name: a.name,
        allowed_hosts: a.allowed_hosts,
        inject: a.inject,
        test: a.test ? { method: a.test.method ?? "GET", ...a.test } : undefined,
        proxy_only: a.proxy_only,
        remove: a.remove,
      });
      return ok(t("代理配置已更新：", "Proxy configuration updated:"), r);
    }),
  );

  server.registerTool(
    "credential_gateway",
    {
      description: t(
        "为凭证开通本地网关，给不能走 MCP 的程序（SDK、CLI、脚本）使用，支持流式响应。" +
          "网关地址和本会话专属令牌写入一个仅你可读的环境变量文件（env_file）；用 `set -a; . <env_file>; set +a; <命令>` 运行程序，常见 SDK（OpenAI、Anthropic 等）的 BASE_URL 和 API_KEY 已设置好。" +
          "程序把令牌当作 API key 发送，网关替换为真实凭证、只转发到允许的域名并对响应脱敏——程序和 agent 都拿不到真实 key。" +
          "只接受你本人账户的进程连接；会话结束即失效。不要读取、打印该文件，也不要把其中的值写进命令行参数。凭证需先配置代理（credential_set 用模板，或 credential_configure_http）。",
        "Open a local gateway for a credential, for programs that cannot use MCP (SDKs, CLIs, scripts); streaming responses are supported. " +
          "The gateway URL and a per-session token are written to an environment file readable only by you (env_file); run programs with `set -a; . <env_file>; set +a; <command>` — BASE_URL and API_KEY for common SDKs (OpenAI, Anthropic, …) are already set. " +
          "The program sends the token as its API key; the gateway swaps in the real credential, forwards only to allowed hosts and redacts responses, so neither the program nor the agent ever holds the real key. " +
          "Only processes of your own user account may connect; the token stops working when the session ends. Never read or print the file, or put its values in command-line arguments. " +
          "The credential must have a proxy configuration (credential_set with a template, or credential_configure_http).",
      ),
      inputSchema: {
        purpose: purposeField,
        name: z.string().describe(t("凭证名", "Credential name")),
        type: z.string().optional().describe(t("凭证类型；省略时按名字自动查找", "Credential type; looked up by name when omitted")),
      },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      const type = await resolveType(s, a.name, a.type, PROXY_KINDS);
      const g = await s.request<{ type: string; name: string; base: string; token: string; template: string | null; base_urls: Record<string, string> }>(
        "gatewayOpen",
        { type, name: a.name },
      );
      const env: Record<string, string> = {
        KEYVALET_GATEWAY_URL: g.base,
        KEYVALET_GATEWAY_TOKEN: g.token,
        ...(sdkEnv(g.template ?? undefined, g.base_urls, g.token) ?? {}),
      };
      const file = writeGatewayEnv(session.sessionId, g.type, g.name, env);
      return ok(t("网关已开通：", "Gateway opened:"), {
        env_file: file,
        variables: Object.keys(env),
        usage: `set -a; . ${file}; set +a; <command>`,
        base_urls: g.base_urls,
        how_to_call: t(
          "请求 <base_urls 中的地址>/<API 路径>，并把 $KEYVALET_GATEWAY_TOKEN 作为 API key 发送（Authorization: Bearer、x-api-key 或 x-goog-api-key）。不要读取、打印或在命令行参数中写出该文件的内容。",
          "Call <a base_urls entry>/<API path> and send $KEYVALET_GATEWAY_TOKEN as the API key (Authorization: Bearer, x-api-key or x-goog-api-key). Never read, print or put the file's values in command-line arguments.",
        ),
      });
    }),
  );
}

/** 常见 SDK 的环境变量（API key 填占位值即可，网关会替换为真实凭证） */
function sdkEnv(template: string | undefined, urls: Record<string, string>, token: string): Record<string, string> | undefined {
  const u = (host: string, suffix = "") => (urls[host] ? `${urls[host]}${suffix}` : undefined);
  const env = (pairs: Array<[string, string | undefined]>) =>
    pairs.every(([, v]) => v) ? (Object.fromEntries(pairs) as Record<string, string>) : undefined;
  switch (template) {
    case "openai":
      return env([["OPENAI_BASE_URL", u("api.openai.com", "/v1")], ["OPENAI_API_KEY", token]]);
    case "anthropic":
      return env([["ANTHROPIC_BASE_URL", u("api.anthropic.com")], ["ANTHROPIC_API_KEY", token]]);
    case "groq":
      return env([["GROQ_BASE_URL", u("api.groq.com")], ["GROQ_API_KEY", token]]);
    case "deepseek":
      return env([["OPENAI_BASE_URL", u("api.deepseek.com")], ["OPENAI_API_KEY", token]]);
    case "xai":
      return env([["OPENAI_BASE_URL", u("api.x.ai", "/v1")], ["OPENAI_API_KEY", token]]);
    case "openrouter":
      return env([["OPENAI_BASE_URL", u("openrouter.ai", "/api/v1")], ["OPENAI_API_KEY", token]]);
    case "together":
      return env([["OPENAI_BASE_URL", u("api.together.xyz", "/v1")], ["OPENAI_API_KEY", token]]);
    case "mistral":
      return env([["MISTRAL_BASE_URL", u("api.mistral.ai")], ["MISTRAL_API_KEY", token]]);
    default:
      return undefined;
  }
}
