// HTTP requests made by the root helper: only https is allowed, redirects are forbidden (to prevent secrets
// from being forwarded elsewhere), and there is a timeout and a response size cap.

import { VaultError } from "../vault.js";
import { t } from "../../shared/i18n.js";

const TIMEOUT_MS = 15_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const USER_AGENT = "keyvalet/0.1";

let allowInsecureLoopback = false;
/** Test-only: allow http://127.0.0.1 endpoints (never called from production code) */
export function allowInsecureLoopbackForTests(v: boolean): void {
  allowInsecureLoopback = v;
}

export function insecureLoopbackAllowed(): boolean {
  return allowInsecureLoopback;
}

export function assertHttpsUrl(raw: unknown, what: string): string {
  if (typeof raw !== "string") throw new VaultError(t(`${what} 必须是字符串`, `${what} must be a string`));
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new VaultError(t(`${what} 不是合法 URL：${raw}`, `${what} is not a valid URL: ${raw}`));
  }
  const loopbackOk = allowInsecureLoopback && u.protocol === "http:" && u.hostname === "127.0.0.1";
  if (u.protocol !== "https:" && !loopbackOk) throw new VaultError(t(`${what} 必须使用 https：${raw}`, `${what} must use https: ${raw}`));
  if (u.username || u.password) throw new VaultError(t(`${what} 不能包含用户名或密码`, `${what} must not contain a username or password`));
  return u.toString();
}

export interface HttpResult {
  status: number;
  text: string;
  /** Parsed JSON (may be an object or array); null when the response isn't JSON */
  json: unknown;
}

/** Get the JSON object (returns an empty object when it isn't one), for convenient field access */
export function obj(r: HttpResult): Record<string, unknown> {
  return r.json && typeof r.json === "object" && !Array.isArray(r.json) ? (r.json as Record<string, unknown>) : {};
}

export async function httpRequest(
  url: string,
  init: { method: "GET" | "POST"; headers?: Record<string, string>; body?: string },
): Promise<HttpResult> {
  assertHttpsUrl(url, t("请求地址", "Request URL"));
  let res: Response;
  try {
    res = await fetch(url, {
      method: init.method,
      // identity: refuse compression so a small response can't decompress into an oversized payload
      headers: { "User-Agent": USER_AGENT, Accept: "application/json", "Accept-Encoding": "identity", ...init.headers },
      body: init.body,
      redirect: "error",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (e) {
    throw new VaultError(t(`请求 ${new URL(url).host} 失败：${(e as Error).message}`, `Request to ${new URL(url).host} failed: ${(e as Error).message}`));
  }
  const text = (await readLimited(res, MAX_RESPONSE_BYTES, new URL(url).host)).toString("utf8");
  let json: unknown = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* not a JSON response */
  }
  return { status: res.status, text, json };
}

/** Count bytes while reading and abort as soon as the limit is exceeded (instead of reading everything into memory first) */
export async function readLimited(res: Response, limit: number, host: string): Promise<Buffer> {
  if (!res.body) return Buffer.alloc(0);
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => {});
      throw new VaultError(t(`${host} 的响应过大`, `Response from ${host} is too large`));
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

export function postForm(url: string, form: Record<string, string>, headers: Record<string, string> = {}): Promise<HttpResult> {
  return httpRequest(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
    body: new URLSearchParams(form).toString(),
  });
}

/** The remote error message may echo back part of the request content, so truncate it before returning it to the agent */
export function remoteError(host: string, r: HttpResult): VaultError {
  const o = obj(r);
  const err = o.error;
  const desc = o.error_description ?? o.message;
  const detail = [typeof err === "string" ? err : err ? JSON.stringify(err) : null, typeof desc === "string" ? desc : null]
    .filter(Boolean)
    .join(": ");
  return new VaultError(t(`${host} 返回错误（HTTP ${r.status}）：${(detail || r.text).slice(0, 300)}`, `${host} returned an error (HTTP ${r.status}): ${(detail || r.text).slice(0, 300)}`));
}
