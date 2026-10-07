// Proxied calls: inject the credential into the HTTP request and send it from inside the root helper;
// the agent only receives the response and never sees the secret.
// - Only https is allowed, on the default port, with the target host in that credential's allowed_hosts
// - Redirects are not followed (3xx is returned as-is; the agent can issue a further request itself if
//   needed, still subject to the same host restriction)
// - Secrets appearing in the response (including base64 / URL-encoded forms) are replaced with [REDACTED]

import { insecureLoopbackAllowed, readLimited } from "./protocols/http.js";
import { accessToken } from "./protocols/index.js";
import { fieldValues, hostAllowed, render } from "./http-config.js";
import { Vault, VaultError, type CredentialRecord } from "./vault.js";
import { t } from "../shared/i18n.js";

const TIMEOUT_MS = 180_000; // LLM streaming responses can last several minutes
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;
const MAX_RETURN_CHARS = 256 * 1024;
const MAX_BODY_BYTES = 1024 * 1024;
const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"];
export const FORBIDDEN_HEADERS = new Set(["host", "content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer", "proxy-authorization"]);
const RETURN_HEADERS = /^(content-type|content-length|location|retry-after|etag|last-modified|link|x-ratelimit-.*|ratelimit-.*|x-request-id|request-id)$/i;
const TEXTUAL = /^(text\/|application\/(json|xml|javascript|x-www-form-urlencoded|[a-z.+-]*\+(json|xml)))/i;
const TOKEN_KINDS = ["oauth2", "google_service_account", "github_app", "jwt"];

/**
 * Parses an SSE (text/event-stream) response and extracts incremental text from common LLM streaming
 * formats: OpenAI Chat Completions (choices[].delta.content), OpenAI Responses
 * (response.output_text.delta), Anthropic (content_block_delta.delta.text), Gemini
 * (candidates[].content.parts[].text).
 */
export function aggregateSse(raw: string): { events: number; text: string | null } {
  let events = 0;
  let text = "";
  let recognized = false;
  for (const block of raw.split(/\r?\n\r?\n/)) {
    const data = block
      .split(/\r?\n/)
      .filter((l) => l.startsWith("data:"))
      .map((l) => l.slice(5).replace(/^ /, ""))
      .join("\n");
    if (!data) continue;
    events++;
    if (data === "[DONE]") continue;
    let j: any; // eslint-disable-line @typescript-eslint/no-explicit-any
    try {
      j = JSON.parse(data);
    } catch {
      continue;
    }
    const pieces: unknown[] = [];
    for (const c of Array.isArray(j?.choices) ? j.choices : []) pieces.push(c?.delta?.content, c?.text);
    if (j?.type === "response.output_text.delta") pieces.push(j.delta);
    if (j?.type === "content_block_delta") pieces.push(j?.delta?.text);
    for (const c of Array.isArray(j?.candidates) ? j.candidates : []) {
      for (const part of Array.isArray(c?.content?.parts) ? c.content.parts : []) pieces.push(part?.text);
    }
    for (const x of pieces) {
      if (typeof x === "string") {
        text += x;
        recognized = true;
      }
    }
  }
  return { events, text: recognized ? text : null };
}

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
  /** SSE streaming response: the event count, and the full text assembled from LLM deltas (already redacted) */
  stream?: { events: number; text: string | null };
}

/** The target of a proxied request (for auditing: records only method + host + path, not query parameters) */
export function describeTarget(p: ProxyInput): string | undefined {
  try {
    const u = new URL(String(p.url));
    return `${String(p.method ?? "GET").toUpperCase()} ${u.host}${u.pathname}`.slice(0, 300);
  } catch {
    return undefined;
  }
}

function checkUrl(raw: unknown, allowed: string[]): URL {
  if (typeof raw !== "string" || raw.length > 8000) throw new VaultError(t("url 必须是字符串", "url must be a string"));
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new VaultError(t("url 不合法", "Invalid url")); // don't echo back the URL: it may have been rendered from a secret
  }
  const testLoopback = insecureLoopbackAllowed() && u.protocol === "http:" && u.hostname === "127.0.0.1"; // test only
  if (u.protocol !== "https:" && !testLoopback) throw new VaultError(t("代理调用只允许 https", "Proxied calls only allow https"));
  if (u.username || u.password) throw new VaultError(t("url 不能包含用户名或密码", "url must not contain a username or password"));
  if (u.port && u.port !== "443" && !testLoopback) throw new VaultError(t("代理调用只允许默认端口 443", "Proxied calls only allow the default port 443"));
  if (!hostAllowed(u.hostname, allowed)) {
    throw new VaultError(
      t(
        `域名 ${u.hostname} 不在该凭证允许的范围内（${allowed.join("、")}）；如需新增请用 credential_configure_http`,
        `Host ${u.hostname} is not allowed for this credential (${allowed.join(", ")}); use credential_configure_http to add it`,
      ),
    );
  }
  return u;
}

function strRecord(v: unknown, what: string): Record<string, string> {
  if (v === undefined || v === null) return {};
  if (typeof v !== "object" || Array.isArray(v)) throw new VaultError(t(`${what} 必须是对象`, `${what} must be an object`));
  const out: Record<string, string> = {};
  const entries = Object.entries(v as Record<string, unknown>);
  if (entries.length > 50) throw new VaultError(t(`${what} 最多 50 项`, `${what} may have at most 50 entries`));
  for (const [k, x] of entries) {
    if (typeof x !== "string" && typeof x !== "number" && typeof x !== "boolean") throw new VaultError(t(`${what}.${k} 必须是字符串`, `${what}.${k} must be a string`));
    out[k] = String(x);
  }
  return out;
}

/** Builds the list of strings to strip from the response (each secret plus its common encoded forms), longest first; matching is case-insensitive */
export function redactionList(values: string[]): string[] {
  const set = new Set<string>();
  for (const v of values) {
    if (!v || v.length < 4) continue;
    const forms = [
      v,
      encodeURIComponent(v),
      encodeURIComponent(v).replace(/%20/g, "+"), // form encoding
      JSON.stringify(v).slice(1, -1), // JSON string escaping
      JSON.stringify(v).slice(1, -1).replace(/\//g, "\\/"), // some JSON encoders escape /
      Buffer.from(v).toString("base64"),
      Buffer.from(v).toString("base64").replace(/=+$/, ""),
      Buffer.from(v).toString("base64url"),
      Buffer.from(v).toString("hex"),
    ];
    for (const f of forms) if (f.length >= 4) set.add(f);
  }
  return [...set].sort((a, b) => b.length - a.length);
}

/**
 * Replaces case-insensitively (covers URL-encoded %xx casing, lowercased hostnames, etc.).
 * Matches on the original string using the regex's i flag: we can't toLowerCase() first and then slice
 * by index -- some characters (e.g. "İ") change length when lowercased, which would shift indices and
 * let secrets leak through.
 */
export function redact(s: string, list: string[]): string {
  let out = s;
  for (const x of list) {
    if (!x) continue;
    out = out.replace(new RegExp(x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi"), "[REDACTED]");
  }
  return out;
}

function containsSecret(buf: Buffer, list: string[]): boolean {
  const lower = buf.toString("latin1").toLowerCase();
  return list.some((x) => lower.includes(Buffer.from(x).toString("latin1").toLowerCase()));
}

/** Computes the headers and query parameters to inject, along with the secrets that need to be stripped */
export async function buildInjection(vault: Vault, type: string, name: string, rec: CredentialRecord) {
  const headers: Record<string, string> = {};
  const query: Record<string, string> = {};
  const secrets: string[] = [];
  const kind = rec.kind ?? "static";
  // All long-lived secrets are added to the redaction list (so they won't leak even if upstream echoes them back)
  secrets.push(...Object.values(rec.secrets ?? {}), rec.value ?? "");
  if (TOKEN_KINDS.includes(kind)) {
    const tok = (await accessToken(vault, { type, name, viaProxy: true })) as { access_token: string };
    secrets.push(tok.access_token);
    const rule = rec.http?.inject;
    if (!rule) {
      headers.Authorization = `Bearer ${tok.access_token}`;
    } else {
      // Custom injection rule: {{access_token}} references the current token
      const f = { secrets: { access_token: tok.access_token }, attributes: rec.attributes ?? {}, value: "" };
      for (const [k, v] of Object.entries(rule.headers ?? {})) headers[k] = render(v, f);
      for (const [k, v] of Object.entries(rule.query ?? {})) query[k] = render(v, f);
      if (rule.basic) {
        const basic = Buffer.from(`${render(rule.basic.username, f)}:${render(rule.basic.password, f)}`).toString("base64");
        headers.Authorization = `Basic ${basic}`;
        secrets.push(basic);
      }
      secrets.push(...Object.values(headers), ...Object.values(query));
    }
  } else {
    const rule = rec.http!.inject;
    if (!rule) throw new VaultError(t("该凭证没有注入规则", "This credential has no injection rule"));
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
    // Any error message is redacted before being returned (and before being written to the audit log)
    const msg = e instanceof Error ? e.message : String(e);
    throw new VaultError(redact(msg, baseline));
  }
}

async function proxyRequestInner(vault: Vault, p: ProxyInput & { type: unknown; name: unknown }): Promise<ProxyResult> {
  const { type, name, record } = vault.getRecord(p.type, p.name);
  if (!record.http) throw new VaultError(t(`"${type}/${name}" 没有配置代理调用，请先用 credential_configure_http 设置允许的域名`, `"${type}/${name}" has no proxy configuration; set the allowed hosts with credential_configure_http first`));
  const method = String(p.method ?? "GET").toUpperCase();
  if (!METHODS.includes(method)) throw new VaultError(t(`不支持的方法 ${method}`, `Unsupported method ${method}`));
  const url = checkUrl(p.url, record.http.allowed_hosts);

  const agentHeaders = strRecord(p.headers, "headers");
  for (const [k, v] of Object.entries(strRecord(p.query, "query"))) url.searchParams.set(k, v);
  let body: string | undefined;
  if (p.body !== undefined && p.body !== null && (method === "GET" || method === "HEAD")) {
    throw new VaultError(t(`${method} 请求不能带请求体`, `${method} requests cannot have a body`));
  }
  if (p.body !== undefined && p.body !== null) {
    body = typeof p.body === "string" ? p.body : JSON.stringify(p.body);
    if (Buffer.byteLength(body) > MAX_BODY_BYTES) throw new VaultError(t("请求体过大（上限 1MB）", "Request body too large (limit 1MB)"));
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
    if (!/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$/.test(k)) throw new VaultError(t(`请求头名称 "${k}" 非法`, `Invalid header name "${k}"`));
    headers[k] = v;
  }
  Object.assign(headers, inj.headers);
  for (const [k, v] of Object.entries(inj.query)) url.searchParams.set(k, v);

  let res: Response;
  try {
    res = await fetch(url, { method, headers, body, redirect: "manual", signal: AbortSignal.timeout(TIMEOUT_MS) });
  } catch (e) {
    const detail = redact((e as Error).message, inj.redactions);
    throw new VaultError(t(`请求 ${url.hostname} 失败：${detail}`, `Request to ${url.hostname} failed: ${detail}`));
  }
  const buf = await readLimited(res, MAX_RESPONSE_BYTES, url.hostname);
  const outHeaders: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    if (RETURN_HEADERS.test(k)) outHeaders[k] = redact(v, inj.redactions);
  });
  const ctype = res.headers.get("content-type") ?? "";
  const textual = TEXTUAL.test(ctype) || (!ctype && buf.length > 0 && !buf.includes(0));
  let text: string;
  let stream: ProxyResult["stream"];
  if (textual) {
    text = redact(buf.toString("utf8"), inj.redactions); // redact before truncating, to avoid splitting a secret across the truncation point
    if (/^text\/event-stream/i.test(ctype)) {
      stream = aggregateSse(text);
      // Redact once more after assembling: a secret may have been split across multiple deltas, or appear as a JSON \uXXXX escape
      if (stream.text !== null) stream.text = redact(stream.text, inj.redactions);
    }
  } else {
    // Binary data can't be reliably redacted: refuse to return it if the raw bytes contain a secret in any encoded form
    if (containsSecret(buf, inj.redactions)) throw new VaultError(t("响应中包含凭证秘密，已拒绝返回该二进制响应", "The response contains a credential secret; refusing to return this binary response"));
    text = buf.toString("base64");
  }
  const truncated = text.length > MAX_RETURN_CHARS;
  if (truncated) text = text.slice(0, MAX_RETURN_CHARS);
  // When a streaming response has already been assembled into full text, keep only the leading portion of the raw event stream (the agent usually just needs the text)
  if (stream?.text !== null && stream && text.length > 4000) text = text.slice(0, 4000);
  return {
    status: res.status,
    headers: outHeaders,
    body: text,
    body_encoding: textual ? "text" : "base64",
    truncated: truncated || (!!stream && stream.text !== null && text.length >= 4000),
    ...(stream ? { stream } : {}),
  };
}

/** Checks whether a credential is usable via its test request */
export async function testCredential(vault: Vault, p: { type: unknown; name: unknown }) {
  const { type, name, record } = vault.getRecord(p.type, p.name);
  const test = record.http?.test;
  if (!test) throw new VaultError(t(`"${type}/${name}" 没有验证请求（模板未提供，可用 credential_configure_http 设置 test）`, `"${type}/${name}" has no test request (none provided by the template; set test with credential_configure_http)`));
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
    excerpt: r.body_encoding === "text" ? r.body.slice(0, 500) : t(`<${r.body.length} 字节二进制>`, `<${r.body.length} bytes of binary>`),
  };
}
