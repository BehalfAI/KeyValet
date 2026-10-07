// Local gateway: a proxy entry point for programs that can't go through MCP (SDKs, CLIs, scripts),
// supporting streaming responses.
//
//   http://127.0.0.1:<port>/<upstream host>/<path>  ->  https://<upstream host>/<path>
//   Authentication: the program sends the gateway token (kv_...) as an API key -- Authorization: Bearer,
//   x-api-key, api-key, or x-goog-api-key
//
// - The token is never placed in the URL: command-line arguments are visible to all local users (ps),
//   whereas an SDK already puts the API key in a request header
// - Listens only on 127.0.0.1; only accepts connections from processes of the user who started the
//   session (SUDO_UID) -- the token is useless even if leaked to another user
// - The token is 32 random bytes, one per credential, valid only within this session (the helper process)
// - Validates the Host header (prevents DNS rebinding), and rejects browser-originated requests
//   (Origin / Sec-Fetch-*)
// - Strips the client's own auth headers and any headers that might leak the token, then injects the
//   real credential; can only reach hosts allowed for that credential; does not follow redirects
// - Redacts the response while streaming it through (holding back only a tail that might be the start of
//   a secret), forwarding at the client's read speed (backpressure), to avoid exhausting the root
//   process's memory

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
/** Request headers from the client that might carry a token or credential: always stripped, with the gateway injecting the real credential instead */
const CLIENT_AUTH_HEADERS = new Set(["authorization", "x-api-key", "api-key", "x-goog-api-key", "cookie", "proxy-authorization"]);
/** Other request headers that aren't forwarded: might leak the token (referer), come from a browser (origin, sec-*), or cause the upstream request to fail (expect) */
const DROP_REQUEST_HEADERS = /^(referer|origin|expect|forwarded|via|keep-alive|accept-encoding|x-forwarded-.*|sec-.*|proxy-.*)$/i;
const DROP_RESPONSE_HEADERS = /^(content-length|content-encoding|transfer-encoding|connection|keep-alive|set-cookie|alt-svc|access-control-.*)$/i;

/** Streaming redaction: matches on a latin1 byte view (keeping bytes unchanged), holding back only a tail that might be the start of a secret */
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
   * Holds back only the longest tail that "might be the start of some secret" (case-insensitive).
   * LLM streaming events are often short, so always holding back the longest-secret length would delay
   * all of them until the end of the stream.
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

/** Queries, as root, the uid of the process on the other end of a local TCP connection (lsof), excluding the gateway itself */
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
  /** The purpose stated when the gateway was opened: written into the audit record of every subsequent gateway request */
  purpose?: string;
}

export type GatewayAudit = (entry: Record<string, unknown>) => void;

export interface GatewayOptions {
  /** Only accepts connections from processes with this uid (in production, the user who invoked sudo); omit to skip the check (tests only) */
  allowedUid?: number;
  /** Lets tests replace the peer-uid lookup */
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

  /** Opens a gateway entry point for a credential (opening the same credential again returns the same token) */
  async open(type: string, name: string, purpose?: string): Promise<{ base: string; token: string; port: number }> {
    if (!this.starting) this.starting = this.start(); // concurrent opens only start the server once
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
          if (!ok) socket.destroy(); // process belongs to another user: disconnect immediately
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
      /* an audit failure must not affect the response */
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

    // The peer process must belong to the session user
    const peerOk = this.peerChecks.get(req.socket);
    if (peerOk && !(await peerOk)) return deny(403, "peer_uid", "Forbidden");
    // DNS rebinding protection: only accept requests that directly target 127.0.0.1 / localhost
    const hostHeader = (req.headers.host ?? "").toLowerCase();
    if (hostHeader !== `127.0.0.1:${this.port}` && hostHeader !== `localhost:${this.port}`) return deny(421, "host_header", "Misdirected request");
    // Always reject browser-originated requests (web pages): a browser always sends Sec-Fetch-Site, and
    // cross-origin requests also send Origin.
    // Note this can't be judged by sec-fetch-mode -- Node's built-in fetch (used by SDKs like OpenAI's) sends that too.
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
    this.inFlight++; // increment the count before awaiting: prevents concurrent requests from all passing the limit check

    let status = 0;
    let redactions: string[] = [];
    try {
      const { type, name, record } = this.vault.getRecord(route.type, route.name);
      redactions = redactionList([...Object.values(record.secrets ?? {}), record.value ?? ""]);
      if (!record.http) return deny(403, "no_proxy", t("该凭证没有配置代理调用", "This credential has no proxy configuration"), route);
      const testLoopback = insecureLoopbackAllowed() && /^127\.0\.0\.1:\d+$/.test(upstreamHost); // test only
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
      res.on("close", () => abort.abort()); // client disconnected -> cancel the upstream request
      const signal = AbortSignal.any([abort.signal, AbortSignal.timeout(TIMEOUT_MS)]);
      const hasBody = !["GET", "HEAD"].includes(method);

      const upstream = await fetch(url, {
        method,
        headers,
        body: hasBody ? (Readable.toWeb(req.pipe(limiter)) as unknown as BodyInit) : undefined,
        redirect: "manual",
        signal,
        // @ts-expect-error Node's fetch requires duplex: "half" to send a streaming request body
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
            res.destroy(); // over the limit: disconnect instead of letting the client think the response is complete
            return;
          }
          const out = redactor.push(Buffer.from(value));
          // Backpressure: wait when the client reads slowly, instead of letting data pile up in the root process
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
