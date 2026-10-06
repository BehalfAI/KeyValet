// 代理调用配置的校验与渲染（root helper 内）。
// 配置随凭证加密保存；agent 只能通过 helper 修改，且扩大域名等敏感改动需用户确认。

import { PLACEHOLDER_RE, injectStrings, placeholders, type InjectRule, type TestRequest } from "../shared/templates.js";
import { insecureLoopbackAllowed } from "./protocols/http.js";
import { VaultError, type CredentialRecord, type HttpConfig } from "./vault.js";

const HOST_RE = /^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/;
const HEADER_NAME_RE = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$/;
const QUERY_NAME_RE = /^[A-Za-z0-9_.\-[\]]{1,100}$/;
const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] as const;

/** 允许的域名：只接受域名（不接受 IP、localhost），防止代理被用来访问本机/内网服务 */
export function normalizeHosts(v: unknown): string[] {
  if (!Array.isArray(v) || v.length === 0 || v.length > 20) throw new VaultError("allowed_hosts 必须是 1~20 个域名");
  const out = new Set<string>();
  for (const h of v) {
    const s = typeof h === "string" ? h.trim().toLowerCase().replace(/\.$/, "") : "";
    if (!(HOST_RE.test(s) || (insecureLoopbackAllowed() && s === "127.0.0.1"))) throw new VaultError(`非法的域名 "${String(h)}"（只接受域名，如 api.example.com 或 *.example.com）`);
    out.add(s);
  }
  return [...out].sort();
}

export function hostAllowed(host: string, allowed: string[]): boolean {
  const h = host.toLowerCase();
  return allowed.some((a) => (a.startsWith("*.") ? h.endsWith(a.slice(1)) && h.length > a.length - 1 : h === a));
}

function checkStrRecord(v: unknown, what: string, keyRe: RegExp): Record<string, string> | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v !== "object" || Array.isArray(v)) throw new VaultError(`${what} 必须是对象`);
  const out: Record<string, string> = {};
  const entries = Object.entries(v as Record<string, unknown>);
  if (entries.length > 20) throw new VaultError(`${what} 最多 20 项`);
  for (const [k, x] of entries) {
    if (!keyRe.test(k.replace(PLACEHOLDER_RE, "x"))) throw new VaultError(`${what} 的名称 "${k}" 非法`);
    if (typeof x !== "string" || x.length > 2000) throw new VaultError(`${what}.${k} 必须是字符串`);
    out[k] = x;
  }
  return Object.keys(out).length ? out : undefined;
}

/** 字段来源：秘密字段 + 非敏感属性 + value */
export interface FieldValues {
  secrets: Record<string, string>;
  attributes: Record<string, string>;
  value: string;
}

export function fieldValues(rec: CredentialRecord): FieldValues {
  // 协议凭证的长期秘密（client secret、refresh token、私钥……）绝不参与占位符渲染
  if ((rec.kind ?? "static") !== "static") return { secrets: {}, attributes: rec.attributes ?? {}, value: "" };
  return { secrets: rec.secrets ?? {}, attributes: rec.attributes ?? {}, value: rec.value ?? "" };
}

function isSecretField(f: FieldValues, name: string): boolean {
  return Object.hasOwn(f.secrets, name) || (name === "value" && !!f.value);
}

function lookup(f: FieldValues, name: string): string | undefined {
  if (Object.hasOwn(f.secrets, name)) return f.secrets[name];
  if (Object.hasOwn(f.attributes, name)) return f.attributes[name];
  if (name === "value" && f.value) return f.value;
  return undefined;
}

export function render(tpl: string, f: FieldValues): string {
  return tpl.replace(PLACEHOLDER_RE, (_m, n: string) => {
    const v = lookup(f, n);
    if (v === undefined) throw new VaultError(`缺少字段 ${n}`);
    return v;
  });
}

/** 名称（头名/参数名）里的占位符只能引用非敏感字段，在设置时展开为固定值 */
function expandKeys(rec: Record<string, string> | undefined, f: FieldValues, what: string): Record<string, string> | undefined {
  if (!rec) return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(rec)) {
    const key = k.replace(PLACEHOLDER_RE, (_m, n: string) => {
      if (!Object.hasOwn(f.attributes, n)) throw new VaultError(`${what} 的名称只能引用非敏感字段（${n}）`);
      return f.attributes[n]!;
    });
    out[key] = v;
  }
  return out;
}

export function validateInject(raw: unknown, f: FieldValues): InjectRule | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw !== "object" || Array.isArray(raw)) throw new VaultError("inject 必须是对象");
  const r = raw as Record<string, unknown>;
  const rule: InjectRule = {};
  const headers = expandKeys(checkStrRecord(r.headers, "inject.headers", HEADER_NAME_RE), f, "请求头");
  const query = expandKeys(checkStrRecord(r.query, "inject.query", QUERY_NAME_RE), f, "查询参数");
  if (headers) {
    for (const k of Object.keys(headers)) {
      if (!HEADER_NAME_RE.test(k)) throw new VaultError(`请求头名称 "${k}" 非法`);
      if (["host", "content-length", "transfer-encoding", "connection"].includes(k.toLowerCase())) throw new VaultError(`不能注入请求头 ${k}`);
    }
    rule.headers = headers;
  }
  if (query) rule.query = query;
  if (r.basic !== undefined && r.basic !== null) {
    const b = r.basic as Record<string, unknown>;
    if (typeof b.username !== "string" || typeof b.password !== "string") throw new VaultError("inject.basic 需要 username 和 password");
    rule.basic = { username: b.username, password: b.password };
  }
  if (!rule.headers && !rule.query && !rule.basic) throw new VaultError("inject 至少要有 headers、query 或 basic 之一");
  for (const n of placeholders(injectStrings(rule))) {
    if (lookup(f, n) === undefined) throw new VaultError(`注入规则引用了不存在的字段 ${n}`);
  }
  return rule;
}

/**
 * 验证请求。allowSecrets=false（credential_configure_http 修改时）禁止引用秘密字段：
 * 否则可以把秘密放进 URL，再借错误信息或上游回显把它带出来。
 * 只有随新秘密一起写入的模板验证请求（如 Trello 的 /tokens/{{apiToken}}）允许引用秘密。
 */
export function validateTest(raw: unknown, f: FieldValues, allowSecrets: boolean): TestRequest | undefined {
  if (raw === undefined || raw === null) return undefined;
  const t = raw as Record<string, unknown>;
  const method = String(t.method ?? "GET").toUpperCase() as TestRequest["method"];
  if (!METHODS.includes(method)) throw new VaultError("test.method 非法");
  if (typeof t.url !== "string" || t.url.length > 2000) throw new VaultError("test.url 必须是字符串");
  const out: TestRequest = { method, url: t.url };
  const headers = checkStrRecord(t.headers, "test.headers", HEADER_NAME_RE);
  const query = checkStrRecord(t.query, "test.query", QUERY_NAME_RE);
  if (headers) out.headers = headers;
  if (query) out.query = query;
  if (!allowSecrets && method !== "GET" && method !== "HEAD") throw new VaultError("自定义验证请求只能是 GET 或 HEAD");
  for (const n of placeholders([out.url, ...Object.keys(headers ?? {}), ...Object.values(headers ?? {}), ...Object.keys(query ?? {}), ...Object.values(query ?? {})])) {
    if (lookup(f, n) === undefined) throw new VaultError(`验证请求引用了不存在的字段 ${n}`);
    if (!allowSecrets && isSecretField(f, n)) throw new VaultError(`自定义验证请求不能引用秘密字段 ${n}（认证由注入规则完成）`);
  }
  return out;
}

/** 校验完整的代理配置。token 类凭证（oauth2 等）不需要 inject。 */
export function validateHttpConfig(
  raw: unknown,
  rec: Pick<CredentialRecord, "kind" | "secrets" | "attributes" | "value">,
  opts: { allowSecretsInTest: boolean; prevTest?: TestRequest },
): HttpConfig {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new VaultError("http 配置必须是对象");
  const r = raw as Record<string, unknown>;
  const f = fieldValues(rec as CredentialRecord);
  const kind = rec.kind ?? "static";
  const inject = validateInject(r.inject, f);
  if (kind === "static" && !inject) throw new VaultError("static 凭证的代理调用需要注入规则（inject）");
  if (kind !== "static" && inject) throw new VaultError(`${kind} 凭证自动注入 access token，不能自定义注入规则`);
  if (!["static", "oauth2", "google_service_account", "github_app", "jwt"].includes(kind)) {
    throw new VaultError(`${kind} 凭证不支持代理调用`);
  }
  return {
    ...(inject ? { inject } : {}),
    allowed_hosts: normalizeHosts(r.allowed_hosts),
    proxy_only: r.proxy_only === true,
    // 沿用已有的验证请求（写入时已校验）；新传入的按 allowSecretsInTest 校验
    ...(r.test === opts.prevTest && opts.prevTest ? { test: opts.prevTest } : r.test ? { test: validateTest(r.test, f, opts.allowSecretsInTest) } : {}),
  };
}
