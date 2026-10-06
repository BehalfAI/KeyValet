// 代理调用：在 root helper 内把凭证注入 HTTP 请求并发出，agent 只拿到响应，看不到秘密。
// - 只允许 https、默认端口、且目标域名在该凭证的 allowed_hosts 内
// - 不跟随重定向（3xx 原样返回，agent 需要时自行再请求，同样受域名限制）
// - 响应中出现的秘密（含 base64 / URL 编码形式）替换为 [REDACTED]

import { insecureLoopbackAllowed, readLimited } from "./protocols/http.js";
import { accessToken } from "./protocols/index.js";
import { fieldValues, hostAllowed, render } from "./http-config.js";
import { Vault, VaultError, type CredentialRecord } from "./vault.js";

const TIMEOUT_MS = 60_000;
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;
const MAX_RETURN_CHARS = 256 * 1024;
const MAX_BODY_BYTES = 1024 * 1024;
const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"];
const FORBIDDEN_HEADERS = new Set(["host", "content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer", "proxy-authorization"]);
const RETURN_HEADERS = /^(content-type|content-length|location|retry-after|etag|last-modified|link|x-ratelimit-.*|ratelimit-.*|x-request-id|request-id)$/i;
const TEXTUAL = /^(text\/|application\/(json|xml|javascript|x-www-form-urlencoded|[a-z.+-]*\+(json|xml)))/i;
const TOKEN_KINDS = ["oauth2", "google_service_account", "github_app", "jwt"];

export interface ProxyInput {
  method?: unknown;
  url: unknown;
  headers?: unknown;
  query?: unknown;
  body?: unknown;
}

export interface ProxyResult {
  status: number;
  headers: Record<string, string>;
  body: string;
  body_encoding: "text" | "base64";
  truncated: boolean;
}

/** 代理请求的目标（用于审计：只记 方法 + 域名 + 路径，不记查询参数） */
export function describeTarget(p: ProxyInput): string | undefined {
  try {
    const u = new URL(String(p.url));
    return `${String(p.method ?? "GET").toUpperCase()} ${u.host}${u.pathname}`.slice(0, 300);
  } catch {
    return undefined;
  }
}

function checkUrl(raw: unknown, allowed: string[]): URL {
  if (typeof raw !== "string" || raw.length > 8000) throw new VaultError("url 必须是字符串");
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new VaultError("url 不合法"); // 不回显 URL：它可能由秘密渲染而来
  }
  const testLoopback = insecureLoopbackAllowed() && u.protocol === "http:" && u.hostname === "127.0.0.1"; // 仅测试
  if (u.protocol !== "https:" && !testLoopback) throw new VaultError("代理调用只允许 https");
  if (u.username || u.password) throw new VaultError("url 不能包含用户名或密码");
  if (u.port && u.port !== "443" && !testLoopback) throw new VaultError("代理调用只允许默认端口 443");
  if (!hostAllowed(u.hostname, allowed)) {
    throw new VaultError(`域名 ${u.hostname} 不在该凭证允许的范围内（${allowed.join("、")}）；如需新增请用 credential_configure_http`);
  }
  return u;
}

function strRecord(v: unknown, what: string): Record<string, string> {
  if (v === undefined || v === null) return {};
  if (typeof v !== "object" || Array.isArray(v)) throw new VaultError(`${what} 必须是对象`);
  const out: Record<string, string> = {};
  const entries = Object.entries(v as Record<string, unknown>);
  if (entries.length > 50) throw new VaultError(`${what} 最多 50 项`);
  for (const [k, x] of entries) {
    if (typeof x !== "string" && typeof x !== "number" && typeof x !== "boolean") throw new VaultError(`${what}.${k} 必须是字符串`);
    out[k] = String(x);
  }
  return out;
}

/** 生成需要从响应中抹掉的字符串（各秘密及其常见编码形式），长的优先；匹配时不区分大小写 */
export function redactionList(values: string[]): string[] {
  const set = new Set<string>();
  for (const v of values) {
    if (!v || v.length < 4) continue;
    const forms = [
      v,
      encodeURIComponent(v),
      encodeURIComponent(v).replace(/%20/g, "+"), // 表单编码
      JSON.stringify(v).slice(1, -1), // JSON 字符串转义
      JSON.stringify(v).slice(1, -1).replace(/\//g, "\\/"), // 部分 JSON 编码器转义 /
      Buffer.from(v).toString("base64"),
      Buffer.from(v).toString("base64").replace(/=+$/, ""),
      Buffer.from(v).toString("base64url"),
      Buffer.from(v).toString("hex"),
    ];
    for (const f of forms) if (f.length >= 4) set.add(f);
  }
  return [...set].sort((a, b) => b.length - a.length);
}

/** 不区分大小写地替换（URL 编码的 %xx 大小写、域名小写化等都能覆盖） */
export function redact(s: string, list: string[]): string {
  let out = s;
  for (const x of list) {
    const lx = x.toLowerCase();
    let lower = out.toLowerCase();
    let i = lower.indexOf(lx);
    while (i >= 0) {
      out = out.slice(0, i) + "[REDACTED]" + out.slice(i + x.length);
      lower = out.toLowerCase();
      i = lower.indexOf(lx, i + "[REDACTED]".length);
    }
  }
  return out;
}

function containsSecret(buf: Buffer, list: string[]): boolean {
  const lower = buf.toString("latin1").toLowerCase();
  return list.some((x) => lower.includes(Buffer.from(x).toString("latin1").toLowerCase()));
}

/** 计算要注入的头和查询参数，以及需要抹掉的秘密 */
async function buildInjection(vault: Vault, type: string, name: string, rec: CredentialRecord) {
  const headers: Record<string, string> = {};
  const query: Record<string, string> = {};
  const secrets: string[] = [];
  const kind = rec.kind ?? "static";
  // 所有长期秘密都加入脱敏列表（上游万一回显也不会泄露）
  secrets.push(...Object.values(rec.secrets ?? {}), rec.value ?? "");
  if (TOKEN_KINDS.includes(kind)) {
    const t = (await accessToken(vault, { type, name, viaProxy: true })) as { access_token: string };
    headers.Authorization = `Bearer ${t.access_token}`;
    secrets.push(t.access_token);
  } else {
    const rule = rec.http!.inject;
    if (!rule) throw new VaultError("该凭证没有注入规则");
    const f = fieldValues(rec);
    secrets.push(...Object.values(f.secrets), f.value);
    for (const [k, v] of Object.entries(rule.headers ?? {})) headers[k] = render(v, f);
    for (const [k, v] of Object.entries(rule.query ?? {})) query[k] = render(v, f);
    if (rule.basic) {
      const basic = Buffer.from(`${render(rule.basic.username, f)}:${render(rule.basic.password, f)}`).toString("base64");
      headers.Authorization = `Basic ${basic}`;
      secrets.push(basic);
    }
    secrets.push(...Object.values(headers), ...Object.values(query));
  }
  return { headers, query, redactions: redactionList(secrets) };
}

export async function proxyRequest(vault: Vault, p: ProxyInput & { type: unknown; name: unknown }): Promise<ProxyResult> {
  const { record } = vault.getRecord(p.type, p.name);
  const baseline = redactionList([...Object.values(record.secrets ?? {}), record.value ?? ""]);
  try {
    return await proxyRequestInner(vault, p);
  } catch (e) {
    // 任何错误信息都先脱敏再返回（也会写入审计日志）
    const msg = e instanceof Error ? e.message : String(e);
    throw new VaultError(redact(msg, baseline));
  }
}

async function proxyRequestInner(vault: Vault, p: ProxyInput & { type: unknown; name: unknown }): Promise<ProxyResult> {
  const { type, name, record } = vault.getRecord(p.type, p.name);
  if (!record.http) throw new VaultError(`"${type}/${name}" 没有配置代理调用，请先用 credential_configure_http 设置允许的域名`);
  const method = String(p.method ?? "GET").toUpperCase();
  if (!METHODS.includes(method)) throw new VaultError(`不支持的方法 ${method}`);
  const url = checkUrl(p.url, record.http.allowed_hosts);

  const agentHeaders = strRecord(p.headers, "headers");
  for (const [k, v] of Object.entries(strRecord(p.query, "query"))) url.searchParams.set(k, v);
  let body: string | undefined;
  if (p.body !== undefined && p.body !== null && (method === "GET" || method === "HEAD")) {
    throw new VaultError(`${method} 请求不能带请求体`);
  }
  if (p.body !== undefined && p.body !== null) {
    body = typeof p.body === "string" ? p.body : JSON.stringify(p.body);
    if (Buffer.byteLength(body) > MAX_BODY_BYTES) throw new VaultError("请求体过大（上限 1MB）");
    if (typeof p.body !== "string" && !Object.keys(agentHeaders).some((k) => k.toLowerCase() === "content-type")) {
      agentHeaders["Content-Type"] = "application/json";
    }
  }

  const inj = await buildInjection(vault, type, name, record);
  const headers: Record<string, string> = { "User-Agent": "keyvalet/0.1", "Accept-Encoding": "identity" };
  const injected = new Set(Object.keys(inj.headers).map((k) => k.toLowerCase()));
  for (const [k, v] of Object.entries(agentHeaders)) {
    const lk = k.toLowerCase();
    if (FORBIDDEN_HEADERS.has(lk) || injected.has(lk)) continue;
    if (!/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$/.test(k)) throw new VaultError(`请求头名称 "${k}" 非法`);
    headers[k] = v;
  }
  Object.assign(headers, inj.headers);
  for (const [k, v] of Object.entries(inj.query)) url.searchParams.set(k, v);

  let res: Response;
  try {
    res = await fetch(url, { method, headers, body, redirect: "manual", signal: AbortSignal.timeout(TIMEOUT_MS) });
  } catch (e) {
    throw new VaultError(`请求 ${url.hostname} 失败：${redact((e as Error).message, inj.redactions)}`);
  }
  const buf = await readLimited(res, MAX_RESPONSE_BYTES, url.hostname);
  const outHeaders: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    if (RETURN_HEADERS.test(k)) outHeaders[k] = redact(v, inj.redactions);
  });
  const ctype = res.headers.get("content-type") ?? "";
  const textual = TEXTUAL.test(ctype) || (!ctype && buf.length > 0 && !buf.includes(0));
  let text: string;
  if (textual) {
    text = redact(buf.toString("utf8"), inj.redactions); // 先脱敏再截断，避免秘密跨越截断点
  } else {
    // 二进制无法可靠脱敏：只要原始字节中出现秘密（任一编码形式）就拒绝返回
    if (containsSecret(buf, inj.redactions)) throw new VaultError("响应中包含凭证秘密，已拒绝返回该二进制响应");
    text = buf.toString("base64");
  }
  const truncated = text.length > MAX_RETURN_CHARS;
  if (truncated) text = text.slice(0, MAX_RETURN_CHARS);
  return { status: res.status, headers: outHeaders, body: text, body_encoding: textual ? "text" : "base64", truncated };
}

/** 用凭证的验证请求检查其是否可用 */
export async function testCredential(vault: Vault, p: { type: unknown; name: unknown }) {
  const { type, name, record } = vault.getRecord(p.type, p.name);
  const test = record.http?.test;
  if (!test) throw new VaultError(`"${type}/${name}" 没有验证请求（模板未提供，可用 credential_configure_http 设置 test）`);
  const f = fieldValues(record);
  const r = await proxyRequest(vault, {
    type,
    name,
    method: test.method,
    url: render(test.url, f),
    headers: Object.fromEntries(Object.entries(test.headers ?? {}).map(([k, v]) => [k, render(v, f)])),
    query: Object.fromEntries(Object.entries(test.query ?? {}).map(([k, v]) => [k, render(v, f)])),
  });
  return {
    ok: r.status >= 200 && r.status < 300,
    status: r.status,
    excerpt: r.body_encoding === "text" ? r.body.slice(0, 500) : `<${r.body.length} 字节二进制>`,
  };
}
