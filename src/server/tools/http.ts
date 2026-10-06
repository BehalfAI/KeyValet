import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { PLACEHOLDER_RE, injectStrings, placeholders, type CredentialTemplate } from "../../shared/templates.js";
import { promptSecret } from "../dialog.js";
import type { HelperSession, Requester } from "../session.js";
import { getTemplate, searchTemplates, summarize } from "../templates.js";
import { fail, guardOverwrite, norm, ok, purposeField, resolveType, wrap } from "./common.js";

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
  if (!tpl) throw new Error(`找不到模板 "${a.template}"，可用 credential_templates 搜索`);
  if (tpl.kind === "oauth2") throw new Error(`"${tpl.id}" 是 OAuth2 模板，请用 credential_oauth_login（provider: "${tpl.id}"）`);
  const type = a.type ?? typeFromTemplate(tpl.id);
  const label = `${norm(type)}/${norm(a.name)}`;

  // ---- 非敏感字段 ----
  const byName = new Map(tpl.fields.map((f) => [f.name, f]));
  const attrs: Record<string, string> = {};
  for (const f of tpl.fields) if (!f.secret && f.default !== undefined) attrs[f.name] = String(f.default);
  for (const [k, v] of Object.entries(a.fields ?? {})) {
    const f = byName.get(k);
    if (!f) throw new Error(`模板 ${tpl.id} 没有字段 ${k}（可用：${tpl.fields.map((x) => x.name).join("、")}）`);
    if (f.secret) throw new Error(`${k} 是秘密字段，不能通过参数传入，会弹窗让用户输入`);
    attrs[k] = String(v);
  }
  const missing = tpl.fields.filter((f) => !f.secret && f.required && !attrs[f.name]);
  if (missing.length) throw new Error(`缺少必填字段：${missing.map((f) => `${f.name}（${f.label}）`).join("、")}，请通过 fields 传入`);

  // ---- 要输入的秘密字段：指定的 / 必填的 / 注入规则引用的 ----
  const secretFields = tpl.fields.filter((f) => f.secret);
  const referenced = new Set(placeholders(injectStrings(tpl.inject)));
  let wanted = a.secret_fields?.length
    ? a.secret_fields
    : secretFields.filter((f) => f.required || referenced.has(f.name)).map((f) => f.name);
  if (!wanted.length) wanted = secretFields.map((f) => f.name);
  for (const n of [...referenced]) if (byName.get(n)?.secret && !wanted.includes(n)) wanted.push(n);
  for (const n of wanted) if (!byName.get(n)?.secret) throw new Error(`${n} 不是模板 ${tpl.id} 的秘密字段`);

  // ---- 允许的域名 ----
  let hosts = a.allowed_hosts?.map((h) => h.trim().toLowerCase());
  if (!hosts?.length) {
    const computed = new Set<string>();
    const fromTest = tpl.test ? hostFromUrlTemplate(tpl.test.url, attrs) : null;
    if (fromTest) computed.add(fromTest);
    else for (const h of tpl.hosts ?? []) computed.add(h);
    hosts = [...computed];
  }
  for (const h of hosts) if (!HOST_RE.test(h)) throw new Error(`非法的域名 ${h}`);
  if (tpl.inject && !hosts.length) throw new Error("无法从模板确定 API 域名，请通过 allowed_hosts 指定（如 [\"api.example.com\"]）");

  const exists = await guardOverwrite(s, type, a.name, a.overwrite);

  // ---- 弹窗输入秘密（文案只含模板名、字段名和校验过的域名） ----
  const secrets: Record<string, string> = {};
  for (const n of wanted) {
    const f = byName.get(n)!;
    const where = tpl.inject ? `\n该凭证只会被代理发送到：${hosts.join("、")}` : "";
    const v = await promptSecret(`请输入「${cleanLabel(tpl.name)}」的 ${cleanLabel(f.label)}\n\n凭证：${label}${where}`);
    if (!v) {
      if (f.required || referenced.has(n)) throw new Error("用户取消了输入，未保存。");
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

  let verify: unknown = "模板没有验证请求";
  if (http && test && a.verify !== false) {
    verify = await s.request("httpTest", { type: r.type, name: r.name }).catch((e: Error) => ({ ok: false, error: e.message }));
  }
  return { ...r, template: tpl.id, secret_fields: Object.keys(secrets), proxy: http ? { allowed_hosts: hosts, proxy_only: http.proxy_only } : "不可代理（模板没有注入规则）", verify };
}

function templateDetail(t: CredentialTemplate) {
  return {
    ...summarize(t),
    source: t.source,
    docs: t.docs,
    fields: t.fields,
    inject: t.inject,
    test: t.test,
    oauth2: t.oauth2,
    how_to_use:
      t.kind === "oauth2"
        ? `credential_oauth_login { provider: "${t.id}", client_id: ..., name: ... }`
        : `credential_set { template: "${t.id}", name: ..., fields: { 非敏感字段 } }（秘密字段会弹窗输入）`,
  };
}

export function registerHttpTools(server: McpServer, session: HelperSession): void {
  server.registerTool(
    "credential_templates",
    {
      description:
        "搜索凭证模板（内置通用模板 + 自带模板库中的常用服务，以及可选的本地 n8n 模板库）。模板定义了需要哪些字段、哪些是秘密、如何注入请求（代理调用）、如何验证。" +
        "传 id 查看完整模板。不需要解锁。",
      inputSchema: {
        query: z.string().optional().describe("服务名关键词，如 openai、github、notion"),
        id: z.string().optional().describe("模板 id，返回完整模板"),
        kind: z.enum(["static", "oauth2"]).optional(),
        limit: z.number().int().optional().describe("默认 20，最多 100"),
      },
    },
    wrap(async (a) => {
      if (a.id) {
        const t = getTemplate(a.id);
        return t ? ok("模板：", templateDetail(t)) : fail(`找不到模板 "${a.id}"`);
      }
      const list = searchTemplates(a.query, a.kind, Math.min(Math.max(a.limit ?? 20, 1), 100));
      return ok(`找到 ${list.length} 个模板：`, list.map(summarize));
    }),
  );

  server.registerTool(
    "credential_http_request",
    {
      description:
        "代理调用：由凭证库把凭证注入 HTTP 请求并发出，只返回响应——agent 看不到 API key / token。" +
        "适用于配置了代理的 static 凭证（模板或手动规则）以及 oauth2 / google_service_account / github_app / jwt 凭证（自动注入 access token）。" +
        "只允许 https、只能发往该凭证允许的域名；不跟随重定向；响应中出现的秘密会被替换为 [REDACTED]。",
      inputSchema: {
        purpose: purposeField,
        name: z.string().describe("凭证名"),
        type: z.string().optional().describe("凭证类型；省略时按名字自动查找"),
        method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]).optional().describe("默认 GET"),
        url: z.string().describe("完整 https URL"),
        headers: z.record(z.string(), z.string()).optional().describe("额外请求头（认证头由凭证库注入，不要自己传）"),
        query: z.record(z.string(), z.string()).optional(),
        body: z.union([z.string(), z.record(z.string(), z.unknown()), z.array(z.unknown())]).optional().describe("请求体：字符串原样发送；对象/数组按 JSON 发送"),
      },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      const type = await resolveType(s, a.name, a.type, PROXY_KINDS);
      const r = await s.request("httpRequest", { type, name: a.name, method: a.method, url: a.url, headers: a.headers, query: a.query, body: a.body });
      return ok("响应：", r);
    }),
  );

  server.registerTool(
    "credential_test",
    {
      description: "用凭证的验证请求（来自模板，或 credential_configure_http 设置的 test）检查凭证是否有效。只返回是否成功、状态码和响应摘要。",
      inputSchema: {
        purpose: purposeField,
        name: z.string(),
        type: z.string().optional().describe("凭证类型；省略时按名字自动查找"),
      },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      const type = await resolveType(s, a.name, a.type, PROXY_KINDS);
      const r = await s.request<{ ok: boolean; status: number }>("httpTest", { type, name: a.name });
      return r.ok ? ok(`凭证有效（HTTP ${r.status}）。`, r) : fail(`凭证验证未通过（HTTP ${r.status}）。\n${JSON.stringify(r, null, 2)}`);
    }),
  );

  server.registerTool(
    "credential_configure_http",
    {
      description:
        "设置或修改凭证的代理调用配置：允许的域名、注入规则（static 凭证）、验证请求、是否只能代理调用（禁止读出原值）。" +
        "新增域名、修改注入规则、关闭「只能代理调用」、删除配置都会由凭证库弹窗请用户确认。" +
        "注入规则用 {{字段名}} 引用凭证字段（单值凭证用 {{value}}），如 {\"headers\": {\"Authorization\": \"Bearer {{value}}\"}}。",
      inputSchema: {
        purpose: purposeField,
        name: z.string(),
        type: z.string().optional().describe("凭证类型；省略时按名字自动查找"),
        allowed_hosts: z.array(z.string()).optional().describe("允许发往的域名，如 [\"api.example.com\"]；*.example.com 匹配子域名"),
        inject: z
          .object({
            headers: z.record(z.string(), z.string()).optional(),
            query: z.record(z.string(), z.string()).optional(),
            basic: z.object({ username: z.string(), password: z.string() }).optional(),
          })
          .optional()
          .describe("注入规则（仅 static 凭证）"),
        test: z
          .object({
            method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]).optional(),
            url: z.string(),
            headers: z.record(z.string(), z.string()).optional(),
            query: z.record(z.string(), z.string()).optional(),
          })
          .optional()
          .describe("验证请求，如 {\"url\": \"https://api.example.com/me\"}"),
        proxy_only: z.boolean().optional().describe("true：只能代理调用，credential_get 不再返回原值"),
        remove: z.boolean().optional().describe("删除代理配置"),
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
      return ok("代理配置已更新：", r);
    }),
  );
}
