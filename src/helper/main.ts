// root helper 入口：由 MCP server 通过 `sudo -n` 启动（sudoers 只允许免密运行本程序）。
// 启动后先读握手消息（目的、来源、会话），通过 Touch ID 认证后才提供服务。
// 只通过 stdin/stdout（sudo 子进程管道）与父进程通信；stdin 关闭即退出，
// 因此它的生命周期与 MCP session 绑定。

import { setLang, t } from "../shared/i18n.js";
import { HELPER_JS, VAULT_DIR } from "../shared/paths.js";
import { MAX_LINE_BYTES, PROTOCOL_VERSION, cleanPurpose, type AuthMessage, type ReadyMessage, type Request } from "../shared/protocol.js";
import { touchIdGate } from "./auth-gate.js";
import { applyMode, dispatch, resolveHint, type ClientContext, type SessionAuth } from "./dispatch.js";
import { Gateway } from "./gateway.js";
import { parseMode, readSettings, rememberActive, rememberUntil, stricter, writeSettings } from "./settings.js";
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
    fatal(t("协议错误：握手消息不是合法 JSON", "Protocol error: handshake message is not valid JSON"));
  }
  setLang(msg.lang); // 与 MCP server 使用同一种界面语言
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
  if (msg.op !== "auth") fatal(t("协议错误：第一条消息必须是 auth", "Protocol error: the first message must be auth"));
  if (!purpose) reject(t("必须说明解锁目的（purpose）", "A purpose is required to unlock"));

  // 授权模式：全局设置与客户端请求（KEYVALET_GRANT_MODE，只能收严）中更严格的那个
  const settings = readSettings(VAULT_DIR);
  auth.requested = parseMode(msg.requested_mode);
  const mode = stricter(settings.grant_mode, auth.requested);
  const remembered = mode === "remember" && rememberActive(settings);

  if (!remembered) {
    const hint = mode === "per_credential" || mode === "per_use" ? resolveHint(vault, msg.credential) : null;
    const hours = settings.remember_hours === 0 ? t("永久", "forever") : t(`${settings.remember_hours} 小时`, `${settings.remember_hours} hours`);
    const scope =
      mode === "remember"
        ? t(`解锁 KeyValet，并在${hours}内记住（期间所有 AI 会话无需再认证）`, `Unlock KeyValet and remember it for ${hours} (no authentication for any AI session meanwhile)`)
        : mode === "per_session"
          ? t("解锁 KeyValet 凭证库（本会话可使用全部凭证）", "Unlock the KeyValet vault (this session can use all credentials)")
          : hint
            ? mode === "per_use"
              ? t(`授权本次使用凭证（仅此一次）：${hint}`, `Authorize a single use of credential: ${hint}`)
              : t(`授权本次 AI 会话使用凭证：${hint}`, `Authorize this AI session to use credential: ${hint}`)
            : t("打开 KeyValet 凭证库会话（仅可查看列表；使用具体凭证时需再次授权）", "Open a KeyValet vault session (list only; using a specific credential requires further authorization)");
    const reason = t(
      `${scope}\n目的：${purpose}\n来源目录（agent 提供）：${ctx.cwd || "未知"}`,
      `${scope}\nPurpose: ${purpose}\nWorking directory (reported by agent): ${ctx.cwd || "unknown"}`,
    );
    const gate = await touchIdGate(VAULT_DIR, reason);
    if (!gate.ok) reject(gate.error);
    if (mode === "remember") writeSettings(VAULT_DIR, { ...settings, remember_until: rememberUntil(settings.remember_hours) });
    applyMode(auth, settings);
    if (hint && mode === "per_use") (auth.oneShot ??= new Set()).add(hint);
    else if (hint) auth.grants.add(hint);
    vault.audit({ op: "unlock", ok: true, purpose, grant_mode: mode, granted: hint ?? undefined, session: ctx.session, client: ctx });
  } else {
    // remember 模式且仍在有效期内：不弹 Touch ID（每次使用照常审计）
    applyMode(auth, settings);
    vault.audit({ op: "unlock", ok: true, purpose, grant_mode: mode, remembered: true, session: ctx.session, client: ctx });
  }
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
    fatal(t(`凭证库初始化失败：${(e as Error).message}`, `Vault initialization failed: ${(e as Error).message}`));
  }

  const ctx: ClientContext = {};
  const auth: SessionAuth = { grantAll: false, grants: new Set(), authorize: (reason) => touchIdGate(VAULT_DIR, reason) };
  // 网关只接受发起会话的用户的进程连接（其他 macOS 用户即使拿到令牌也无法使用）
  auth.gateway = new Gateway(vault, (e) => vault.audit({ ...e, session: ctx.session, client: ctx }), { allowedUid: Number(process.env.SUDO_UID) });
  const queue: Request[] = [];
  let inFlight = 0;
  const pump = () => {
    while (inFlight < MAX_IN_FLIGHT && queue.length) {
      const req = queue.shift()!;
      inFlight++;
      void dispatch(vault, req, ctx, auth)
        .then(send)
        .catch((e: unknown) => send({ id: req.id, ok: false, error: t(`内部错误：${e instanceof Error ? e.message : String(e)}`, `Internal error: ${e instanceof Error ? e.message : String(e)}`) }))
        .finally(() => {
          inFlight--;
          pump();
        });
    }
    if (queue.length > 1000) fatal(t("待处理请求过多", "Too many pending requests"));
  };
  let state: "handshake" | "authenticating" | "ready" = "handshake";
  const handshakeTimer = setTimeout(() => fatal(t("等待握手超时", "Timed out waiting for handshake")), HANDSHAKE_TIMEOUT_MS);

  let buf = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk: string) => {
    buf += chunk;
    if (buf.length > MAX_LINE_BYTES) fatal(t("请求过大", "Request too large"));
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
      if (state !== "ready") fatal(t("协议错误：认证完成前收到请求", "Protocol error: request received before authentication completed"));
      let req: Request;
      try {
        req = JSON.parse(line) as Request;
      } catch {
        fatal(t("协议错误：非法 JSON", "Protocol error: invalid JSON"));
      }
      if (typeof req.id !== "number" || typeof req.op !== "string") fatal(t("协议错误：缺少 id/op", "Protocol error: missing id/op"));
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
