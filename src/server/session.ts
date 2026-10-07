// 一个 MCP server 进程 = 一个 agent session。
// 首次需要访问凭证时通过 `sudo -n` 启动 root helper（sudoers 只允许免密运行 helper 本身），
// 先发送握手消息（目的、来源目录、会话 ID），helper 弹出 Touch ID（显示目的）认证通过后才提供服务。
// 认证后本 session 内后续请求无需再认证；本进程退出（session 结束）→ 管道关闭 → helper 退出。

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import { lang, t } from "../shared/i18n.js";
import { HELPER_JS, INSTALL_DIR, NODE_BIN, SUDO_BIN, SUDOERS_FILE, TOUCHID_BIN } from "../shared/paths.js";
import { GRANT_REQUIRED_PREFIX, PROTOCOL_VERSION, cleanPurpose, type AuthMessage, type Op, type Request, type Response } from "../shared/protocol.js";

const UNLOCK_TIMEOUT_MS = 3 * 60_000;
const REQUEST_TIMEOUT_MS = 60_000; // AWS MFA 可能需要等下一个 TOTP 周期
const FAILURE_COOLDOWN_MS = 30_000; // 认证失败/取消后的冷却，防止 agent 反复弹窗轰炸
const GRANT_TIMEOUT_MS = 150_000; // 按凭证授权需要等待用户按 Touch ID

/** 工具要使用的凭证（用于 per_credential 模式的授权） */
export interface CredentialTarget {
  type?: string;
  name?: string;
}

export class SessionError extends Error {}

/** 带目的的请求接口：工具处理函数通过 session.scoped(purpose) 获得 */
export interface Requester {
  request<T>(op: Op, params: Record<string, unknown>): Promise<T>;
}

type Pending = { resolve: (v: unknown) => void; reject: (e: Error) => void; timer: NodeJS.Timeout };

export class HelperSession {
  /** 本次会话的随机 ID，写入每条审计记录 */
  readonly sessionId = crypto.randomBytes(6).toString("hex");
  private child: ChildProcessWithoutNullStreams | null = null;
  private ready = false;
  private unlocking: Promise<void> | null = null;
  private pending = new Map<number, Pending>();
  private nextId = 1;
  private cooldownUntil = 0;
  private unlockedAt: number | null = null;
  private unlockPurpose: string | null = null;
  private ttlTimer: NodeJS.Timeout | null = null;
  private granting = new Map<string, Promise<unknown>>();

  constructor(private readonly ttlMs: number) {
    process.once("exit", () => this.lock());
  }

  status() {
    return {
      state: this.ready ? "unlocked" : this.unlocking ? "unlocking" : "locked",
      session: this.sessionId,
      auth: "touch_id",
      unlockedAt: this.unlockedAt ? new Date(this.unlockedAt).toISOString() : null,
      unlockPurpose: this.unlockPurpose,
      expiresAt: this.unlockedAt && this.ttlMs > 0 ? new Date(this.unlockedAt + this.ttlMs).toISOString() : null,
      installProblem: installProblem(),
    };
  }

  /**
   * 返回一个请求接口：每个请求都带上 purpose；如需解锁，Touch ID 弹窗中显示该目的。
   * target 为工具要使用的凭证：per_credential 模式下解锁时即授权它。
   */
  scoped(purpose: string, target?: CredentialTarget): Requester {
    return {
      request: <T>(op: Op, params: Record<string, unknown>) => this.request<T>(op, { ...params, purpose }, purpose, target),
    };
  }

  async unlock(purpose: string, target?: CredentialTarget): Promise<void> {
    if (this.ready) return;
    if (!this.unlocking) {
      this.unlocking = this.doUnlock(purpose, target).finally(() => {
        this.unlocking = null;
      });
    }
    return this.unlocking;
  }

  lock(): void {
    const child = this.child;
    this.child = null;
    this.ready = false;
    this.unlockedAt = null;
    this.unlockPurpose = null;
    if (this.ttlTimer) clearTimeout(this.ttlTimer);
    this.ttlTimer = null;
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(new SessionError(t("凭证库已锁定", "Credential vault is locked")));
    }
    this.pending.clear();
    if (child) {
      child.stdin.end(); // helper 读到 EOF 后自行退出
      child.kill("SIGTERM");
    }
  }

  async request<T>(op: Op, params: Record<string, unknown>, unlockPurpose = t("查看凭证库", "View the credential vault"), target?: CredentialTarget): Promise<T> {
    await this.unlock(unlockPurpose, target);
    // 代理调用可能是持续数分钟的流式响应（helper 端上限 180 秒）
    const timeout = op === "httpRequest" || op === "httpTest" ? 200_000 : undefined;
    try {
      return await this.send<T>(op, params, timeout);
    } catch (e) {
      // per_credential 模式：该凭证尚未授权 → 弹 Touch ID 授权后重试一次
      const msg = (e as Error).message;
      if (!msg.startsWith(GRANT_REQUIRED_PREFIX)) throw e;
      const key = msg.slice(GRANT_REQUIRED_PREFIX.length).trim();
      const slash = key.indexOf("/");
      await this.grant(key.slice(0, slash), key.slice(slash + 1), unlockPurpose);
      return this.send<T>(op, params, timeout);
    }
  }

  /** 授权本会话使用某个凭证（同一凭证的并发授权合并为一次弹窗） */
  grant(type: string, name: string, purpose: string): Promise<unknown> {
    const key = `${type}/${name}`;
    let p = this.granting.get(key);
    if (!p) {
      p = this.send("grant", { type, name, purpose }, GRANT_TIMEOUT_MS).finally(() => this.granting.delete(key));
      this.granting.set(key, p);
    }
    return p;
  }

  private send<T>(op: Op, params: Record<string, unknown>, timeoutMs = REQUEST_TIMEOUT_MS): Promise<T> {
    const child = this.child;
    if (!child || !this.ready) return Promise.reject(new SessionError(t("凭证库未解锁", "Credential vault is not unlocked")));
    const id = this.nextId++;
    const req: Request = { id, op, params };
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new SessionError(t("helper 响应超时", "Helper response timed out")));
      }, timeoutMs);
      this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject, timer });
      child.stdin.write(JSON.stringify(req) + "\n");
    });
  }

  private async doUnlock(purposeIn: string, target?: CredentialTarget): Promise<void> {
    const now = Date.now();
    if (now < this.cooldownUntil) {
      const s = Math.ceil((this.cooldownUntil - now) / 1000);
      throw new SessionError(t(`上次认证失败或被取消，请 ${s} 秒后再试`, `The last authentication failed or was cancelled. Try again in ${s} seconds.`));
    }
    const purpose = cleanPurpose(purposeIn);
    if (!purpose) throw new SessionError(t("必须说明解锁目的（purpose）", "An unlock purpose (purpose) is required"));
    const problem = installProblem();
    if (problem) throw new SessionError(problem);

    // -n：从不询问密码；sudoers 规则只允许免密运行 helper，认证由 helper 内的 Touch ID 完成
    const child = spawn(SUDO_BIN, ["-n", "--", NODE_BIN, HELPER_JS], {
      stdio: ["pipe", "pipe", "pipe"],
      detached: true,
      env: {
        PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
        HOME: process.env.HOME ?? "",
        USER: process.env.USER ?? "",
        LOGNAME: process.env.LOGNAME ?? "",
        LANG: "en_US.UTF-8",
      },
    });
    this.child = child;

    let stderr = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (d: string) => {
      stderr = (stderr + d).slice(-4096);
    });

    const auth: AuthMessage = {
      op: "auth",
      purpose,
      cwd: process.cwd(),
      ppid: process.ppid,
      session: this.sessionId,
      client: "keyvalet",
      lang: lang(),
      // 客户端级别的收严（如给 Codex 配置 KEYVALET_GRANT_MODE=per_use）；不能放宽全局设置
      ...(process.env.KEYVALET_GRANT_MODE ? { requested_mode: process.env.KEYVALET_GRANT_MODE } : {}),
      ...(target?.name ? { credential: { type: target.type, name: target.name } } : {}),
    };
    child.stdin.write(JSON.stringify(auth) + "\n");

    await new Promise<void>((resolve, reject) => {
      let settled = false;
      const fail = (msg: string) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.cooldownUntil = Date.now() + FAILURE_COOLDOWN_MS;
        if (this.child === child) this.lock();
        reject(new SessionError(msg));
      };
      const timer = setTimeout(() => fail(t("等待 Touch ID 认证超时", "Timed out waiting for Touch ID authentication")), UNLOCK_TIMEOUT_MS);

      let buf = "";
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (d: string) => {
        buf += d;
        let nl: number;
        while ((nl = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, nl);
          buf = buf.slice(nl + 1);
          let msg: unknown;
          try {
            msg = JSON.parse(line);
          } catch {
            return fail(t("helper 输出了非法数据", "Helper produced invalid output"));
          }
          if (!settled) {
            const m = msg as { ready?: boolean; protocol?: number; error?: string };
            if (m.protocol !== PROTOCOL_VERSION) return fail(t("helper 版本不匹配，请重新安装", "Helper version mismatch; please reinstall"));
            if (m.ready !== true) return fail(m.error ?? t("解锁失败", "Unlock failed"));
            settled = true;
            clearTimeout(timer);
            this.ready = true;
            this.unlockedAt = Date.now();
            this.unlockPurpose = purpose;
            if (this.ttlMs > 0) this.ttlTimer = setTimeout(() => this.lock(), this.ttlMs).unref();
            resolve();
          } else {
            this.onResponse(msg as Response);
          }
        }
      });

      child.on("error", (e) => fail(t(`无法启动 sudo：${e.message}`, `Cannot start sudo: ${e.message}`)));
      child.on("exit", () => {
        if (!settled) return fail(describeSudoFailure(stderr));
        if (this.child === child) this.lock();
      });
    });
  }

  private onResponse(res: Response): void {
    const p = this.pending.get(res.id);
    if (!p) return;
    this.pending.delete(res.id);
    clearTimeout(p.timer);
    if (res.ok) p.resolve(res.result);
    else p.reject(new SessionError(res.error));
  }
}

function describeSudoFailure(stderr: string): string {
  if (/password is required/i.test(stderr)) return t("免密规则未生效（/etc/sudoers.d/keyvalet），请重新运行 ./scripts/install.sh", "The passwordless sudo rule (/etc/sudoers.d/keyvalet) is not in effect; please re-run ./scripts/install.sh");
  if (/not in the sudoers|not allowed/i.test(stderr)) return t("当前用户没有运行 helper 的 sudo 权限，请重新运行 ./scripts/install.sh", "The current user is not allowed to run the helper via sudo; please re-run ./scripts/install.sh");
  const tail = stderr.trim().split("\n").slice(-3).join(" | ");
  return t(`解锁失败${tail ? `：${tail}` : ""}`, `Unlock failed${tail ? `: ${tail}` : ""}`);
}

/** 检查安装：要以 root 运行的文件必须存在、属于 root、不可被他人写 */
function installProblem(): string | null {
  for (const p of [INSTALL_DIR, NODE_BIN, HELPER_JS, TOUCHID_BIN, SUDOERS_FILE]) {
    let st: fs.Stats;
    try {
      st = fs.lstatSync(p);
    } catch {
      return t(`未安装或安装不完整：缺少 ${p}。请在项目目录运行 ./scripts/install.sh`, `Not installed or installation incomplete: missing ${p}. Run ./scripts/install.sh in the project directory.`);
    }
    if (st.uid !== 0 || (st.mode & 0o022) !== 0 || st.isSymbolicLink()) {
      return t(`安装不安全：${p} 必须属于 root 且不可被他人写。请重新运行 ./scripts/install.sh`, `Insecure installation: ${p} must be owned by root and not writable by others. Please re-run ./scripts/install.sh`);
    }
  }
  return null;
}
