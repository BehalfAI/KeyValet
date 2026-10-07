// root helper entry point: started by the MCP server via `sudo -n` (sudoers only allows running this
// program without a password). On startup it first reads the handshake message (purpose, origin,
// session), and only provides service after passing Touch ID authentication.
// It communicates with its parent only via stdin/stdout (the sudo child process pipe); it exits as soon
// as stdin closes, so its lifetime is tied to the MCP session.

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
/** Maximum number of requests handled concurrently (each proxy request buffers up to a 5MB response, to prevent exhausting the root process's memory) */
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
  setLang(msg.lang); // use the same interface language as the MCP server
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

  // Grant mode: the stricter of the global setting and the client's request (KEYVALET_GRANT_MODE, which can only tighten it)
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
    // remember mode and still within its validity period: don't prompt Touch ID (each use is still audited as usual)
    applyMode(auth, settings);
    vault.audit({ op: "unlock", ok: true, purpose, grant_mode: mode, remembered: true, session: ctx.session, client: ctx });
  }
  onReady(); // switch state before notifying, to guarantee that requests arriving afterward are always handled
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
  // The gateway only accepts connections from processes of the user who started the session (other macOS users can't use it even if they obtain the token)
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
      // No request is processed before authentication succeeds
      if (state !== "ready") fatal(t("协议错误：认证完成前收到请求", "Protocol error: request received before authentication completed"));
      let req: Request;
      try {
        req = JSON.parse(line) as Request;
      } catch {
        fatal(t("协议错误：非法 JSON", "Protocol error: invalid JSON"));
      }
      if (typeof req.id !== "number" || typeof req.op !== "string") fatal(t("协议错误：缺少 id/op", "Protocol error: missing id/op"));
      // Handled concurrently (with a cap): protocol requests may need to wait on the network, and responses are matched by id
      queue.push(req);
      pump();
    }
  });
  // Parent process (MCP session) exits -> pipe closes -> helper exits, and must re-authenticate next time
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
