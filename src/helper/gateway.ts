// 本地网关：给不能走 MCP 的程序（SDK、CLI、脚本）用的代理入口，支持流式响应。
//
//   http://127.0.0.1:<port>/<上游域名>/<路径>  →  https://<上游域名>/<路径>
//   认证：程序把网关令牌（kv_…）当作 API key 发送——Authorization: Bearer、x-api-key、api-key 或 x-goog-api-key
//
// - 令牌不放在 URL 里：命令行参数对本机所有用户可见（ps），而 SDK 本来就会把 API key 放进请求头
// - 只监听 127.0.0.1；只接受发起会话的用户（SUDO_UID）的进程的连接——令牌即使泄露给其他用户也无效
// - 令牌 32 字节随机、每个凭证一个，只在本会话（helper 进程）内有效
// - 校验 Host 头（防 DNS 重绑定），拒绝浏览器发起的请求（Origin / Sec-Fetch-*）
// - 去掉客户端自带的认证头和可能泄露令牌的头，注入真实凭证；只能发往该凭证允许的域名；不跟随重定向
// - 响应边转发边脱敏（只扣留可能是秘密开头的尾部），按客户端读取速度转发（背压），防止耗尽 root 进程内存

import { execFile } from "node:child_process";
import crypto from "node:crypto";
import { once } from "node:events";
import http from "node:http";
import type net from "node:net";
import { Readable, Transform } from "node:stream";
import { t } from "../shared/i18n.js";
import { hostAllowed } from "./http-config.js";
import { FORBIDDEN_HEADERS, buildInjection, redact, redactionList } from "./http-proxy.js";
import { insecureLoopbackAllowed } from "./protocols/http.js";
import { Vault, VaultError } from "./vault.js";

const MAX_IN_FLIGHT = 16;
const MAX_CONNECTIONS = 64;
const MAX_REQUEST_BODY = 20 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 50 * 1024 * 1024;
const TIMEOUT_MS = 10 * 60_000;
const TOKEN_PREFIX = "kv_";
/** 客户端发来的、可能携带令牌或凭证的请求头：一律去掉，由网关注入真实凭证 */
const CLIENT_AUTH_HEADERS = new Set(["authorization", "x-api-key", "api-key", "x-goog-api-key", "cookie", "proxy-authorization"]);
/** 其他不转发的请求头：可能泄露令牌（referer）、来自浏览器（origin、sec-*）、或会导致上游请求失败（expect） */
const DROP_REQUEST_HEADERS = /^(referer|origin|expect|forwarded|via|keep-alive|accept-encoding|x-forwarded-.*|sec-.*|proxy-.*)$/i;
const DROP_RESPONSE_HEADERS = /^(content-length|content-encoding|transfer-encoding|connection|keep-alive|set-cookie|alt-svc|access-control-.*)$/i;

/** 流式脱敏：在 latin1 字节视图上匹配（保持字节不变），只扣留可能是秘密开头的尾部 */
export class StreamRedactor {
  private carry = "";
  private readonly list: string[];
  private readonly keep: number;
  private readonly lowerList: string[];

  constructor(redactions: string[]) {
    this.list = redactions.map((x) => Buffer.from(x, "utf8").toString("latin1"));
    this.keep = Math.max(0, ...this.list.map((x) => x.length)) - 1;
    this.lowerList = this.list.map((x) => x.toLowerCase());
  }

  push(chunk: Buffer): Buffer {
    const s = redact(this.carry + chunk.toString("latin1"), this.list);
    const hold = this.holdLength(s);
    this.carry = hold ? s.slice(s.length - hold) : "";
    return Buffer.from(hold ? s.slice(0, s.length - hold) : s, "latin1");
  }

  /**
   * 只扣留“可能是某个秘密开头”的最长尾部（不区分大小写）。
   * 大模型的流式事件通常很短，若固定扣留最长秘密长度，会把它们全部延迟到流结束。
   */
  private holdLength(s: string): number {
    const lower = s.toLowerCase();
    for (let k = Math.min(this.keep, s.length); k > 0; k--) {
      const tail = lower.slice(lower.length - k);
      if (this.lowerList.some((x) => x.startsWith(tail))) return k;
    }
    return 0;
  }

  flush(): Buffer {
    const out = redact(this.carry, this.list);
    this.carry = "";
    return Buffer.from(out, "latin1");
  }
}

/** 以 root 查询本机 TCP 连接对端进程的 uid（lsof），排除网关自身 */
export function peerUid(remotePort: number): Promise<number | null> {
  return new Promise((resolve) => {
    execFile(
      "/usr/sbin/lsof",
      ["-nP", `-iTCP@127.0.0.1:${remotePort}`, "-sTCP:ESTABLISHED", "-F", "pu"],
      { timeout: 5000, env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" } },
      (_err, stdout) => {
        let pid = 0;
        for (const line of String(stdout).split("\n")) {
          if (line.startsWith("p")) pid = Number(line.slice(1));
          else if (line.startsWith("u") && pid !== process.pid) return resolve(Number(line.slice(1)));
        }
        resolve(null);
      },
    );
  });
}

interface Route {
  type: string;
  name: string;
  /** 开通网关时说明的目的：写入之后每次网关请求的审计记录 */
  purpose?: string;
}

export type GatewayAudit = (entry: Record<string, unknown>) => void;

export interface GatewayOptions {
  /** 只接受该 uid 的进程的连接（生产中为发起 sudo 的用户）；省略则不检查（仅测试） */
  allowedUid?: number;
  /** 测试可替换对端 uid 的查询 */
  peerUid?: (remotePort: number) => Promise<number | null>;
}

export class Gateway {
  private server: http.Server | null = null;
  private starting: Promise<void> | null = null;
  private port = 0;
  private readonly routes = new Map<string, Route>();
  private readonly peerChecks = new WeakMap<net.Socket, Promise<boolean>>();
  private inFlight = 0;

  constructor(
    private readonly vault: Vault,
    private readonly audit: GatewayAudit,
    private readonly opts: GatewayOptions = {},
  ) {}

  /** 为凭证开通网关入口（同一凭证重复开通返回同一个令牌） */
  async open(type: string, name: string, purpose?: string): Promise<{ base: string; token: string; port: number }> {
    if (!this.starting) this.starting = this.start(); // 并发开通只启动一次
    await this.starting;
    let token = [...this.routes.entries()].find(([, r]) => r.type === type && r.name === name)?.[0];
    if (!token) {
      token = TOKEN_PREFIX + crypto.randomBytes(32).toString("base64url");
      this.routes.set(token, { type, name, purpose });
    }
    return { base: `http://127.0.0.1:${this.port}`, token, port: this.port };
  }

  close(): void {
    this.routes.clear();
    this.server?.close();
    this.server = null;
    this.starting = null;
  }

  private start(): Promise<void> {
    return new Promise((resolve, reject) => {
      const srv = http.createServer((req, res) => {
        this.handle(req, res).catch((e: unknown) => this.fail(res, 502, t("网关内部错误", "Gateway internal error"), e));
      });
      srv.maxConnections = MAX_CONNECTIONS;
      srv.headersTimeout = 10_000;
      srv.requestTimeout = TIMEOUT_MS;
      srv.on("connection", (socket: net.Socket) => {
        if (this.opts.allowedUid === undefined) return;
        const lookup = this.opts.peerUid ?? peerUid;
        const check = lookup(socket.remotePort ?? 0).then((uid) => uid === this.opts.allowedUid);
        this.peerChecks.set(socket, check);
        void check.then((ok) => {
          if (!ok) socket.destroy(); // 其他用户的进程：直接断开
        });
      });
      srv.once("error", reject);
      srv.listen(0, "127.0.0.1", () => {
        this.port = (srv.address() as { port: number }).port;
        this.server = srv;
        resolve();
      });
    });
  }

  private fail(res: http.ServerResponse, status: number, message: string, cause?: unknown): void {
    void cause;
    if (res.headersSent) {
      res.destroy();
      return;
    }
    res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
    res.end(JSON.stringify({ error: { type: "keyvalet_gateway_error", message } }));
  }

  private record(entry: Record<string, unknown>): void {
    try {
      this.audit({ op: "gateway", ...entry });
    } catch {
      /* 审计失败不影响响应 */
    }
  }

  private tokenFrom(req: http.IncomingMessage): string | undefined {
    const candidates = [req.headers.authorization, req.headers["x-api-key"], req.headers["api-key"], req.headers["x-goog-api-key"]];
    for (const raw of candidates) {
      const v = (Array.isArray(raw) ? raw[0] : raw)?.trim().replace(/^Bearer\s+/i, "");
      if (v?.startsWith(TOKEN_PREFIX)) return v;
    }
    return undefined;
  }

  private async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const method = (req.method ?? "GET").toUpperCase();
    const u = new URL(req.url ?? "/", `http://127.0.0.1:${this.port}`);
    const [, upstreamHost = "", ...rest] = u.pathname.split("/");
    const hostname = upstreamHost.toLowerCase();
    const target = `${method} ${hostname}/${rest.join("/")}`.slice(0, 300);
    const deny = (status: number, reason: string, message: string, route?: Route) => {
      this.record({ ok: false, status, reason, target, ...(route ? { type: route.type, name: route.name, purpose: route.purpose } : {}) });
      this.fail(res, status, message);
    };

    // 对端进程必须属于会话用户
    const peerOk = this.peerChecks.get(req.socket);
    if (peerOk && !(await peerOk)) return deny(403, "peer_uid", "Forbidden");
    // DNS 重绑定防护：只接受直接访问 127.0.0.1 / localhost 的请求
    const hostHeader = (req.headers.host ?? "").toLowerCase();
    if (hostHeader !== `127.0.0.1:${this.port}` && hostHeader !== `localhost:${this.port}`) return deny(421, "host_header", "Misdirected request");
    // 浏览器发起的请求（网页）一律拒绝：浏览器总会带 Sec-Fetch-Site，跨域请求还带 Origin。
    // 注意不能按 sec-fetch-mode 判断——Node 自带的 fetch（OpenAI 等 SDK）也会发送它。
    const site = req.headers["sec-fetch-site"];
    if (req.headers.origin !== undefined || (site !== undefined && site !== "none")) {
      return deny(403, "browser", t("网关不接受浏览器发起的请求", "The gateway does not accept requests from browsers"));
    }
    const token = this.tokenFrom(req);
    const route = token ? this.routes.get(token) : undefined;
    if (!route || !upstreamHost) {
      return deny(401, "token", t("缺少或无效的网关令牌（请把 KeyValet 网关令牌作为 API key 发送）", "Missing or invalid gateway token (send the KeyValet gateway token as the API key)"));
    }
    if (this.inFlight >= MAX_IN_FLIGHT) return deny(429, "busy", t("网关请求过多，请稍后再试", "Too many gateway requests; retry later"), route);
    this.inFlight++; // 先计数再 await：避免并发请求都通过上限检查

    let status = 0;
    let redactions: string[] = [];
    try {
      const { type, name, record } = this.vault.getRecord(route.type, route.name);
      redactions = redactionList([...Object.values(record.secrets ?? {}), record.value ?? ""]);
      if (!record.http) return deny(403, "no_proxy", t("该凭证没有配置代理调用", "This credential has no proxy configuration"), route);
      const testLoopback = insecureLoopbackAllowed() && /^127\.0\.0\.1:\d+$/.test(upstreamHost); // 仅测试
      if (!testLoopback && (!/^[a-z0-9.-]+$/.test(hostname) || !hostAllowed(hostname, record.http.allowed_hosts))) {
        return deny(403, "host", t(`域名 ${hostname} 不在该凭证允许的范围内`, `Host ${hostname} is not allowed for this credential`), route);
      }

      const url = new URL(`${testLoopback ? "http" : "https"}://${upstreamHost}/${rest.join("/")}${u.search}`);
      const inj = await buildInjection(this.vault, type, name, record);
      redactions = inj.redactions;
      for (const [k, v] of Object.entries(inj.query)) url.searchParams.set(k, v);

      const headers: Record<string, string> = {};
      const injected = new Set(Object.keys(inj.headers).map((k) => k.toLowerCase()));
      for (const [k, v] of Object.entries(req.headers)) {
        const lk = k.toLowerCase();
        if (v === undefined || FORBIDDEN_HEADERS.has(lk) || CLIENT_AUTH_HEADERS.has(lk) || injected.has(lk) || DROP_REQUEST_HEADERS.test(lk)) continue;
        headers[k] = Array.isArray(v) ? v.join(", ") : v;
      }
      Object.assign(headers, inj.headers, { "accept-encoding": "identity" });

      let received = 0;
      const limiter = new Transform({
        transform(chunk: Buffer, _enc, cb) {
          received += chunk.length;
          if (received > MAX_REQUEST_BODY) return cb(new Error(t("请求体过大", "Request body too large")));
          cb(null, chunk);
        },
      });
      const abort = new AbortController();
      res.on("close", () => abort.abort()); // 客户端断开 → 取消上游请求
      const signal = AbortSignal.any([abort.signal, AbortSignal.timeout(TIMEOUT_MS)]);
      const hasBody = !["GET", "HEAD"].includes(method);

      const upstream = await fetch(url, {
        method,
        headers,
        body: hasBody ? (Readable.toWeb(req.pipe(limiter)) as unknown as BodyInit) : undefined,
        redirect: "manual",
        signal,
        // @ts-expect-error Node 的 fetch 发送流式请求体需要 duplex: "half"
        duplex: "half",
      });
      status = upstream.status;
      const outHeaders: Record<string, string> = {};
      upstream.headers.forEach((v, k) => {
        if (!DROP_RESPONSE_HEADERS.test(k)) outHeaders[k] = redact(v, inj.redactions);
      });
      res.writeHead(upstream.status, outHeaders);
      res.flushHeaders();

      const redactor = new StreamRedactor(inj.redactions);
      let total = 0;
      if (upstream.body) {
        const reader = upstream.body.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.byteLength;
          if (total > MAX_RESPONSE_BYTES) {
            await reader.cancel().catch(() => {});
            res.destroy(); // 超限：断开连接，而不是让客户端以为响应已完整
            return;
          }
          const out = redactor.push(Buffer.from(value));
          // 背压：客户端读得慢时等待，不在 root 进程里堆积数据
          if (out.length && !res.write(out) && !res.destroyed) await Promise.race([once(res, "drain"), once(res, "close")]);
          if (res.destroyed) {
            await reader.cancel().catch(() => {});
            return;
          }
        }
      }
      const tail = redactor.flush();
      if (tail.length) res.write(tail);
      res.end();
    } catch (e) {
      status = status || 502;
      const msg = redact(e instanceof Error ? e.message : String(e), redactions);
      this.fail(res, 502, t(`网关请求失败：${msg}`, `Gateway request failed: ${msg}`));
    } finally {
      this.inFlight--;
      if (status) this.record({ type: route.type, name: route.name, purpose: route.purpose, target, status, ok: status < 400 });
    }
  }
}

export function requireGateway(g: Gateway | undefined): Gateway {
  if (!g) throw new VaultError(t("本会话未启用网关", "The gateway is not available in this session"));
  return g;
}
