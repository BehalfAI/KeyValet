// root helper 入口：由 MCP server 通过 `sudo -n` 启动（sudoers 只允许免密运行本程序）。
// 启动后先读握手消息（目的、来源、会话），通过 Touch ID 认证后才提供服务。
// 只通过 stdin/stdout（sudo 子进程管道）与父进程通信；stdin 关闭即退出，
// 因此它的生命周期与 MCP session 绑定。

import { HELPER_JS, VAULT_DIR } from "../shared/paths.js";
import { MAX_LINE_BYTES, PROTOCOL_VERSION, cleanPurpose, type AuthMessage, type ReadyMessage, type Request } from "../shared/protocol.js";
import { touchIdGate } from "./auth-gate.js";
import { dispatch, resolveHint, type ClientContext, type SessionAuth } from "./dispatch.js";
import { readSettings } from "./settings.js";
import { fatal as fatalWith, verifyRootEnvironment } from "./trust.js";
import { Vault } from "./vault.js";

const HANDSHAKE_TIMEOUT_MS = 30_000;
/** 同时处理的请求上限（每个代理请求最多缓冲 5MB 响应，防止耗尽 root 进程内存） */
const MAX_IN_FLIGHT = 8;

function fatal(msg: string): never {
  return fatalWith("keyvalet-helper", msg);
}

function send(obj: unknown): void {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

function clip(v: unknown, n: number): string {
  return typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f]+/g, " ").slice(0, n) : "";
}

async function authenticate(vault: Vault, line: string, ctx: ClientContext, auth: SessionAuth, onReady: () => void): Promise<void> {
  let msg: AuthMessage;
  try {
    msg = JSON.parse(line) as AuthMessage;
  } catch {
    fatal("协议错误：握手消息不是合法 JSON");
  }
  const purpose = cleanPurpose(msg.purpose);
  const reject = (error: string): never => {
    try {
      vault.audit({ op: "unlock", ok: false, error, purpose: purpose ?? undefined, session: ctx.session, client: ctx });
    } catch {
      /* ignore */
    }
    const r: ReadyMessage = { ready: false, protocol: PROTOCOL_VERSION, error };
    send(r);
    process.exit(0);
  };
  Object.assign(ctx, {
    session: clip(msg.session, 64) || "unknown",
    cwd: clip(msg.cwd, 500),
    ppid: typeof msg.ppid === "number" ? msg.ppid : undefined,
    client: clip(msg.client, 100),
  });
  if (msg.op !== "auth") fatal("协议错误：第一条消息必须是 auth");
  if (!purpose) reject("必须说明解锁目的（purpose）");

  // 授权范围：all 一次授权全部；per_credential 只授权触发解锁的那个凭证（如有）
  const mode = readSettings(VAULT_DIR).grant_mode;
  const hint = mode === "per_credential" ? resolveHint(vault, msg.credential) : null;
  const scope =
    mode === "all"
      ? "解锁 KeyValet 凭证库（本会话可使用全部凭证）"
      : hint
        ? `授权本次 AI 会话使用凭证：${hint}`
        : "打开 KeyValet 凭证库会话（仅可查看列表；使用具体凭证时需再次授权）";
  const reason = `${scope}\n目的：${purpose}\n来源目录（agent 提供）：${ctx.cwd || "未知"}`;
  const gate = await touchIdGate(VAULT_DIR, reason);
  if (!gate.ok) reject(gate.error);

  auth.grantAll = mode === "all";
  if (hint) auth.grants.add(hint);
  vault.audit({ op: "unlock", ok: true, purpose, grant_mode: mode, granted: hint ?? undefined, session: ctx.session, client: ctx });
  onReady(); // 先切换状态再通知，保证随后到达的请求一定会被处理
  const ready: ReadyMessage = { ready: true, protocol: PROTOCOL_VERSION };
  send(ready);
}

function main(): void {
  process.umask(0o077);
  verifyRootEnvironment("keyvalet-helper", import.meta.url, HELPER_JS);

  const vault = new Vault(VAULT_DIR);
  try {
    vault.init();
  } catch (e) {
    fatal(`凭证库初始化失败：${(e as Error).message}`);
  }

  const ctx: ClientContext = {};
  const auth: SessionAuth = { grantAll: false, grants: new Set(), authorize: (reason) => touchIdGate(VAULT_DIR, reason) };
  const queue: Request[] = [];
  let inFlight = 0;
  const pump = () => {
    while (inFlight < MAX_IN_FLIGHT && queue.length) {
      const req = queue.shift()!;
      inFlight++;
      void dispatch(vault, req, ctx, auth)
        .then(send)
        .catch((e: unknown) => send({ id: req.id, ok: false, error: `内部错误：${e instanceof Error ? e.message : String(e)}` }))
        .finally(() => {
          inFlight--;
          pump();
        });
    }
    if (queue.length > 1000) fatal("待处理请求过多");
  };
  let state: "handshake" | "authenticating" | "ready" = "handshake";
  const handshakeTimer = setTimeout(() => fatal("等待握手超时"), HANDSHAKE_TIMEOUT_MS);

  let buf = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk: string) => {
    buf += chunk;
    if (buf.length > MAX_LINE_BYTES) fatal("请求过大");
    let nl: number;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      if (!line.trim()) continue;
      if (state === "handshake") {
        clearTimeout(handshakeTimer);
        state = "authenticating";
        void authenticate(vault, line, ctx, auth, () => {
          state = "ready";
        });
        continue;
      }
      // 认证通过之前不处理任何请求
      if (state !== "ready") fatal("协议错误：认证完成前收到请求");
      let req: Request;
      try {
        req = JSON.parse(line) as Request;
      } catch {
        fatal("协议错误：非法 JSON");
      }
      if (typeof req.id !== "number" || typeof req.op !== "string") fatal("协议错误：缺少 id/op");
      // 并发处理（有上限）：协议请求可能要等网络，响应按 id 匹配
      queue.push(req);
      pump();
    }
  });
  // 父进程（MCP session）退出 → 管道关闭 → helper 退出，下次必须重新认证
  process.stdin.on("end", () => {
    try {
      if (state === "ready") vault.audit({ op: "session-end", session: ctx.session, client: ctx });
    } catch {
      /* ignore */
    }
    process.exit(0);
  });
  for (const sig of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
    process.on(sig, () => process.exit(0));
  }
}

main();
