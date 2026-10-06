// root helper 发出的 HTTP 请求：只允许 https、禁止重定向（防止秘密被转发到别处）、
// 有超时和响应大小上限。

import { VaultError } from "../vault.js";

const TIMEOUT_MS = 15_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const USER_AGENT = "keyvalet/0.1";

let allowInsecureLoopback = false;
/** 仅供测试：允许 http://127.0.0.1 端点（生产代码中从不调用） */
export function allowInsecureLoopbackForTests(v: boolean): void {
  allowInsecureLoopback = v;
}

export function insecureLoopbackAllowed(): boolean {
  return allowInsecureLoopback;
}

export function assertHttpsUrl(raw: unknown, what: string): string {
  if (typeof raw !== "string") throw new VaultError(`${what} 必须是字符串`);
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new VaultError(`${what} 不是合法 URL：${raw}`);
  }
  const loopbackOk = allowInsecureLoopback && u.protocol === "http:" && u.hostname === "127.0.0.1";
  if (u.protocol !== "https:" && !loopbackOk) throw new VaultError(`${what} 必须使用 https：${raw}`);
  if (u.username || u.password) throw new VaultError(`${what} 不能包含用户名或密码`);
  return u.toString();
}

export interface HttpResult {
  status: number;
  text: string;
  /** 解析后的 JSON（可能是对象或数组）；非 JSON 时为 null */
  json: unknown;
}

/** 取 JSON 对象（不是对象时返回空对象），便于读取字段 */
export function obj(r: HttpResult): Record<string, unknown> {
  return r.json && typeof r.json === "object" && !Array.isArray(r.json) ? (r.json as Record<string, unknown>) : {};
}

export async function httpRequest(
  url: string,
  init: { method: "GET" | "POST"; headers?: Record<string, string>; body?: string },
): Promise<HttpResult> {
  assertHttpsUrl(url, "请求地址");
  let res: Response;
  try {
    res = await fetch(url, {
      method: init.method,
      // identity：不接受压缩，避免小响应解压成超大数据
      headers: { "User-Agent": USER_AGENT, Accept: "application/json", "Accept-Encoding": "identity", ...init.headers },
      body: init.body,
      redirect: "error",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (e) {
    throw new VaultError(`请求 ${new URL(url).host} 失败：${(e as Error).message}`);
  }
  const text = (await readLimited(res, MAX_RESPONSE_BYTES, new URL(url).host)).toString("utf8");
  let json: unknown = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* 非 JSON 响应 */
  }
  return { status: res.status, text, json };
}

/** 边读边计数，超过上限立即中止（而不是先整个读进内存） */
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
      throw new VaultError(`${host} 的响应过大`);
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

/** 远端错误信息里可能回显部分请求内容，截断后再返回给 agent */
export function remoteError(host: string, r: HttpResult): VaultError {
  const o = obj(r);
  const err = o.error;
  const desc = o.error_description ?? o.message;
  const detail = [typeof err === "string" ? err : err ? JSON.stringify(err) : null, typeof desc === "string" ? desc : null]
    .filter(Boolean)
    .join(": ");
  return new VaultError(`${host} 返回错误（HTTP ${r.status}）：${(detail || r.text).slice(0, 300)}`);
}
