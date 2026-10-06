// 浏览器端的 OAuth 交互（以普通用户运行）：
// 本地回环回调 + PKCE + state 拿到授权码；授权码换 token 由 root helper 完成，
// client secret 和 refresh token 从不经过这里。

import crypto from "node:crypto";
import { execFile } from "node:child_process";
import http from "node:http";
import { readLimited } from "../helper/protocols/http.js";

const LOGIN_TIMEOUT_MS = 5 * 60_000;

export function openInBrowser(url: string): Promise<void> {
  return new Promise((resolve, reject) => {
    execFile("/usr/bin/open", [url], { env: { PATH: "/usr/bin:/bin" } }, (err) => (err ? reject(err) : resolve()));
  });
}

export function copyToClipboard(text: string): void {
  const p = execFile("/usr/bin/pbcopy", [], { env: { PATH: "/usr/bin:/bin" } });
  p.stdin?.end(text);
}

const PAGE = (title: string, body: string) =>
  `<!doctype html><meta charset="utf-8"><title>${title}</title>` +
  `<body style="font-family:-apple-system,sans-serif;max-width:32em;margin:15vh auto;text-align:center">` +
  `<h2>${title}</h2><p>${body}</p></body>`;

const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

export interface BrowserFlowResult {
  code: string;
  code_verifier: string;
  redirect_uri: string;
}

/**
 * 授权码 + PKCE。redirectUri 未指定时监听 127.0.0.1 的随机端口。
 * redirectHost 为 localhost 时同时监听 IPv4/IPv6，因为浏览器可能把 localhost 解析成 ::1。
 */
export async function runBrowserFlow(opts: {
  authorizationUrl: string;
  clientId: string;
  scopes: string[];
  extraParams: Record<string, string>;
  redirectUri?: string;
  redirectHost?: "127.0.0.1" | "localhost";
  open?: (url: string) => Promise<void>;
  timeoutMs?: number;
}): Promise<BrowserFlowResult> {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const state = crypto.randomBytes(24).toString("base64url");

  const fixed = opts.redirectUri ? new URL(opts.redirectUri) : null;
  const host = fixed ? fixed.hostname : (opts.redirectHost ?? "127.0.0.1");
  const path = fixed ? fixed.pathname : "/callback";
  const listenAddrs = host === "localhost" ? ["127.0.0.1", "::1"] : [host === "[::1]" ? "::1" : host];

  let settle!: { resolve: (code: string) => void; reject: (e: Error) => void };
  const codePromise = new Promise<string>((resolve, reject) => (settle = { resolve, reject }));

  const handler: http.RequestListener = (req, res) => {
    const u = new URL(req.url ?? "/", "http://placeholder");
    if (u.pathname !== path) {
      res.writeHead(404).end();
      return;
    }
    if (u.searchParams.get("state") !== state) {
      res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" }).end(PAGE("授权失败", "state 不匹配，请回到 AI 会话重新发起授权。"));
      return; // 不结束流程：可能是伪造请求，继续等真正的回调
    }
    const err = u.searchParams.get("error");
    if (err) {
      const desc = u.searchParams.get("error_description") ?? "";
      res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" }).end(PAGE("授权未完成", escapeHtml(`${err} ${desc}`)));
      settle.reject(new Error(`授权被拒绝或失败：${err}${desc ? ` (${desc})` : ""}`));
      return;
    }
    const code = u.searchParams.get("code");
    if (!code) {
      res.writeHead(400).end();
      return;
    }
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }).end(PAGE("授权成功 ✅", "凭证已安全保存，可以关闭此页面并回到 AI 会话。"));
    settle.resolve(code);
  };

  const servers: http.Server[] = [];
  let port = fixed?.port ? Number(fixed.port) : 0;
  for (const addr of listenAddrs) {
    const srv = http.createServer(handler);
    try {
      await new Promise<void>((resolve, reject) => {
        srv.once("error", reject);
        srv.listen(port, addr, () => resolve());
      });
    } catch (e) {
      if (servers.length === 0) throw new Error(`无法监听 ${addr}:${port}：${(e as Error).message}`);
      continue; // IPv6 不可用时只用 IPv4
    }
    servers.push(srv);
    port = (srv.address() as { port: number }).port; // 第二个地址用同一端口
  }
  const redirectUri = fixed ? fixed.toString() : `http://${host}:${port}${path}`;

  const auth = new URL(opts.authorizationUrl);
  for (const [k, v] of Object.entries(opts.extraParams)) auth.searchParams.set(k, v);
  auth.searchParams.set("response_type", "code");
  auth.searchParams.set("client_id", opts.clientId);
  auth.searchParams.set("redirect_uri", redirectUri);
  if (opts.scopes.length) auth.searchParams.set("scope", opts.scopes.join(" "));
  auth.searchParams.set("state", state);
  auth.searchParams.set("code_challenge", challenge);
  auth.searchParams.set("code_challenge_method", "S256");

  const timer = setTimeout(() => settle.reject(new Error("等待浏览器授权超时（5 分钟）")), opts.timeoutMs ?? LOGIN_TIMEOUT_MS);
  try {
    await (opts.open ?? openInBrowser)(auth.toString());
    const code = await codePromise;
    return { code, code_verifier: verifier, redirect_uri: redirectUri };
  } finally {
    clearTimeout(timer);
    for (const s of servers) s.close();
  }
}

/** OIDC 自动发现：从 issuer 取授权/token/设备码端点 */
export async function discoverOidc(issuer: string): Promise<{
  authorization_url?: string;
  token_url: string;
  device_authorization_url?: string;
}> {
  const base = new URL(issuer);
  if (base.protocol !== "https:") throw new Error("issuer 必须使用 https");
  const url = `${base.toString().replace(/\/+$/, "")}/.well-known/openid-configuration`;
  const res = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(15_000), headers: { "Accept-Encoding": "identity" } });
  if (!res.ok) throw new Error(`OIDC 发现失败：${url} 返回 HTTP ${res.status}`);
  const doc = JSON.parse((await readLimited(res, 256 * 1024, base.host)).toString("utf8")) as Record<string, unknown>;
  const norm = (s: unknown) => String(s ?? "").replace(/\/+$/, "");
  if (norm(doc.issuer) !== norm(base.toString())) throw new Error(`OIDC 文档中的 issuer（${String(doc.issuer)}）与请求的不一致`);
  if (typeof doc.token_endpoint !== "string") throw new Error("OIDC 文档缺少 token_endpoint");
  return {
    authorization_url: typeof doc.authorization_endpoint === "string" ? doc.authorization_endpoint : undefined,
    token_url: doc.token_endpoint,
    device_authorization_url: typeof doc.device_authorization_endpoint === "string" ? doc.device_authorization_endpoint : undefined,
  };
}
