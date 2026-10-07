// Validation and rendering for proxy call configuration (inside the root helper).
// The configuration is saved encrypted alongside the credential; the agent can only modify it through
// the helper, and sensitive changes such as expanding the domain list require user confirmation.

import { PLACEHOLDER_RE, injectStrings, placeholders, type InjectRule, type TestRequest } from "../shared/templates.js";
import { insecureLoopbackAllowed } from "./protocols/http.js";
import { VaultError, type CredentialRecord, type HttpConfig } from "./vault.js";
import { t } from "../shared/i18n.js";

const HOST_RE = /^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/;
const HEADER_NAME_RE = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$/;
const QUERY_NAME_RE = /^[A-Za-z0-9_.\-[\]]{1,100}$/;
const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] as const;

/** Allowed hosts: only domain names are accepted (not IPs or localhost), to prevent the proxy from being used to reach local/internal services */
export function normalizeHosts(v: unknown): string[] {
  if (!Array.isArray(v) || v.length === 0 || v.length > 20) throw new VaultError(t("allowed_hosts 必须是 1~20 个域名", "allowed_hosts must contain 1-20 domain names"));
  const out = new Set<string>();
  for (const h of v) {
    const s = typeof h === "string" ? h.trim().toLowerCase().replace(/\.$/, "") : "";
    if (!(HOST_RE.test(s) || (insecureLoopbackAllowed() && s === "127.0.0.1"))) throw new VaultError(t(`非法的域名 "${String(h)}"（只接受域名，如 api.example.com 或 *.example.com）`, `Invalid domain "${String(h)}" (only domain names are accepted, e.g. api.example.com or *.example.com)`));
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
  if (typeof v !== "object" || Array.isArray(v)) throw new VaultError(t(`${what} 必须是对象`, `${what} must be an object`));
  const out: Record<string, string> = {};
  const entries = Object.entries(v as Record<string, unknown>);
  if (entries.length > 20) throw new VaultError(t(`${what} 最多 20 项`, `${what} may have at most 20 entries`));
  for (const [k, x] of entries) {
    if (!keyRe.test(k.replace(PLACEHOLDER_RE, "x"))) throw new VaultError(t(`${what} 的名称 "${k}" 非法`, `Invalid ${what} name "${k}"`));
    if (typeof x !== "string" || x.length > 2000) throw new VaultError(t(`${what}.${k} 必须是字符串`, `${what}.${k} must be a string`));
    out[k] = x;
  }
  return Object.keys(out).length ? out : undefined;
}

/** Field sources: secret fields + non-sensitive attributes + value */
export interface FieldValues {
  secrets: Record<string, string>;
  attributes: Record<string, string>;
  value: string;
}

export function fieldValues(rec: CredentialRecord): FieldValues {
  // A protocol credential's long-lived secrets (client secret, refresh token, private key, ...) never participate in placeholder rendering
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
    if (v === undefined) throw new VaultError(t(`缺少字段 ${n}`, `Missing field ${n}`));
    return v;
  });
}

/** Placeholders in names (header names/parameter names) may only reference non-sensitive fields, and are expanded to fixed values at configuration time */
function expandKeys(rec: Record<string, string> | undefined, f: FieldValues, what: string): Record<string, string> | undefined {
  if (!rec) return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(rec)) {
    const key = k.replace(PLACEHOLDER_RE, (_m, n: string) => {
      if (!Object.hasOwn(f.attributes, n)) throw new VaultError(t(`${what} 的名称只能引用非敏感字段（${n}）`, `${what} names may only reference non-secret fields (${n})`));
      return f.attributes[n]!;
    });
    out[key] = v;
  }
  return out;
}

export function validateInject(raw: unknown, f: FieldValues): InjectRule | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (typeof raw !== "object" || Array.isArray(raw)) throw new VaultError(t("inject 必须是对象", "inject must be an object"));
  const r = raw as Record<string, unknown>;
  const rule: InjectRule = {};
  const headers = expandKeys(checkStrRecord(r.headers, "inject.headers", HEADER_NAME_RE), f, t("请求头", "Header"));
  const query = expandKeys(checkStrRecord(r.query, "inject.query", QUERY_NAME_RE), f, t("查询参数", "Query parameter"));
  if (headers) {
    for (const k of Object.keys(headers)) {
      if (!HEADER_NAME_RE.test(k)) throw new VaultError(t(`请求头名称 "${k}" 非法`, `Invalid header name "${k}"`));
      if (["host", "content-length", "transfer-encoding", "connection"].includes(k.toLowerCase())) throw new VaultError(t(`不能注入请求头 ${k}`, `Header ${k} cannot be injected`));
    }
    rule.headers = headers;
  }
  if (query) rule.query = query;
  if (r.basic !== undefined && r.basic !== null) {
    const b = r.basic as Record<string, unknown>;
    if (typeof b.username !== "string" || typeof b.password !== "string") throw new VaultError(t("inject.basic 需要 username 和 password", "inject.basic requires username and password"));
    rule.basic = { username: b.username, password: b.password };
  }
  if (!rule.headers && !rule.query && !rule.basic) throw new VaultError(t("inject 至少要有 headers、query 或 basic 之一", "inject must have at least one of headers, query, or basic"));
  for (const n of placeholders(injectStrings(rule))) {
    if (lookup(f, n) === undefined) throw new VaultError(t(`注入规则引用了不存在的字段 ${n}`, `Injection rule references nonexistent field ${n}`));
  }
  return rule;
}

/**
 * Validates the test request. allowSecrets=false (when modifying via credential_configure_http) forbids
 * referencing secret fields: otherwise a secret could be placed into the URL and then exfiltrated via an
 * error message or upstream echo.
 * Only a template test request written alongside a new secret (e.g. Trello's /tokens/{{apiToken}}) is
 * allowed to reference secrets.
 */
export function validateTest(raw: unknown, f: FieldValues, allowSecrets: boolean): TestRequest | undefined {
  if (raw === undefined || raw === null) return undefined;
  const tr = raw as Record<string, unknown>;
  const method = String(tr.method ?? "GET").toUpperCase() as TestRequest["method"];
  if (!METHODS.includes(method)) throw new VaultError(t("test.method 非法", "Invalid test.method"));
  if (typeof tr.url !== "string" || tr.url.length > 2000) throw new VaultError(t("test.url 必须是字符串", "test.url must be a string"));
  const out: TestRequest = { method, url: tr.url };
  const headers = checkStrRecord(tr.headers, "test.headers", HEADER_NAME_RE);
  const query = checkStrRecord(tr.query, "test.query", QUERY_NAME_RE);
  if (headers) out.headers = headers;
  if (query) out.query = query;
  if (!allowSecrets && method !== "GET" && method !== "HEAD") throw new VaultError(t("自定义验证请求只能是 GET 或 HEAD", "A custom test request must be GET or HEAD"));
  for (const n of placeholders([out.url, ...Object.keys(headers ?? {}), ...Object.values(headers ?? {}), ...Object.keys(query ?? {}), ...Object.values(query ?? {})])) {
    if (lookup(f, n) === undefined) throw new VaultError(t(`验证请求引用了不存在的字段 ${n}`, `Test request references nonexistent field ${n}`));
    if (!allowSecrets && isSecretField(f, n)) throw new VaultError(t(`自定义验证请求不能引用秘密字段 ${n}（认证由注入规则完成）`, `A custom test request cannot reference secret field ${n} (authentication is handled by the injection rule)`));
  }
  return out;
}

/**
 * Validates the full proxy configuration. Token-based credentials (oauth2, etc.) inject
 * Authorization: Bearer <token> by default; a custom injection rule can also be defined, using
 * {{access_token}} to reference the current short-lived token (e.g. GitHub's git push requires Basic
 * auth: {"basic": {"username": "x-access-token", "password": "{{access_token}}"}}).
 */
export function validateHttpConfig(
  raw: unknown,
  rec: Pick<CredentialRecord, "kind" | "secrets" | "attributes" | "value">,
  opts: { allowSecretsInTest: boolean; prevTest?: TestRequest },
): HttpConfig {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new VaultError(t("http 配置必须是对象", "http config must be an object"));
  const r = raw as Record<string, unknown>;
  const kind = rec.kind ?? "static";
  const base = fieldValues(rec as CredentialRecord);
  // Token-based credentials: may only reference the current short-lived token (long-lived secrets don't participate in rendering) and non-sensitive fields
  const f = kind === "static" ? base : { ...base, secrets: { access_token: "<access_token>" } };
  const inject = validateInject(r.inject, f);
  if (kind === "static" && !inject) throw new VaultError(t("static 凭证的代理调用需要注入规则（inject）", "Proxied calls with a static credential require an injection rule (inject)"));
  if (!["static", "oauth2", "google_service_account", "github_app", "jwt"].includes(kind)) {
    throw new VaultError(t(`${kind} 凭证不支持代理调用`, `${kind} credentials do not support proxied calls`));
  }
  return {
    ...(inject ? { inject } : {}),
    allowed_hosts: normalizeHosts(r.allowed_hosts),
    proxy_only: r.proxy_only === true,
    // Reuse the existing test request (already validated when it was written); a newly supplied one is validated per allowSecretsInTest
    ...(r.test === opts.prevTest && opts.prevTest ? { test: opts.prevTest } : r.test ? { test: validateTest(r.test, f, opts.allowSecretsInTest) } : {}),
  };
}
