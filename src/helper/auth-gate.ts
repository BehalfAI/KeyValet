// Touch ID 关卡：helper 以 root 启动（sudoers 只允许免密运行 helper 本身），
// 在提供任何服务之前必须通过设备所有者认证。
//
// root 身份下指纹无法送达认证框，所以降权为发起 sudo 的用户（SUDO_UID）运行 touchid 程序；
// 该程序 root 所有、强化运行时签名（同用户进程无法注入/调试），结果以退出码直接返回给本进程。

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { TOUCHID_BIN } from "../shared/paths.js";
import { untrustedReason } from "./trust.js";

const AUTH_TIMEOUT_MS = 120_000;
/** 认证失败后的冷却：记在 root-only 的凭证库目录里，绕过 MCP server 直接启动 helper 也无法反复弹窗 */
const FAILURE_COOLDOWN_MS = 30_000;

export type GateResult = { ok: true } | { ok: false; error: string };

function failureFile(vaultDir: string): string {
  return path.join(vaultDir, "auth-failure");
}

export function cooldownRemainingMs(vaultDir: string): number {
  try {
    const last = Number(fs.readFileSync(failureFile(vaultDir), "utf8"));
    return Math.max(0, last + FAILURE_COOLDOWN_MS - Date.now());
  } catch {
    return 0;
  }
}

function recordFailure(vaultDir: string): void {
  try {
    fs.writeFileSync(failureFile(vaultDir), String(Date.now()), { mode: 0o600 });
  } catch {
    /* ignore */
  }
}

function clearFailure(vaultDir: string): void {
  try {
    fs.rmSync(failureFile(vaultDir), { force: true });
  } catch {
    /* ignore */
  }
}

/** 发起 sudo 的用户（由 sudo 设置，调用方无法伪造） */
function invokingUser(): { uid: number; gid: number } | null {
  const uid = Number(process.env.SUDO_UID);
  const gid = Number(process.env.SUDO_GID);
  if (!Number.isInteger(uid) || !Number.isInteger(gid) || uid <= 0) return null;
  return { uid, gid };
}

/** 同一时间只允许一个认证弹窗（多个 helper 并发启动时，冷却检查之前就可能各弹一个） */
function acquireAuthLock(vaultDir: string): (() => void) | null {
  const lock = path.join(vaultDir, ".auth-lock");
  try {
    fs.mkdirSync(lock, { mode: 0o700 });
  } catch {
    try {
      if (Date.now() - fs.statSync(lock).mtimeMs < AUTH_TIMEOUT_MS + 10_000) return null;
      fs.rmSync(lock, { recursive: true, force: true }); // 持锁进程已退出
      fs.mkdirSync(lock, { mode: 0o700 });
    } catch {
      return null;
    }
  }
  return () => fs.rmSync(lock, { recursive: true, force: true });
}

export async function touchIdGate(vaultDir: string, reason: string): Promise<GateResult> {
  const release = acquireAuthLock(vaultDir);
  if (!release) return { ok: false, error: "已有另一个解锁请求正在等待认证，请稍后再试" };
  try {
    return await gate(vaultDir, reason);
  } finally {
    release();
  }
}

async function gate(vaultDir: string, reason: string): Promise<GateResult> {
  const wait = cooldownRemainingMs(vaultDir);
  if (wait > 0) return { ok: false, error: `上次认证未通过，请 ${Math.ceil(wait / 1000)} 秒后再试` };
  let bad: string | null;
  try {
    bad = untrustedReason(TOUCHID_BIN);
  } catch {
    bad = "文件不存在";
  }
  if (bad) return { ok: false, error: `Touch ID 程序不可信（${bad}），请重新安装` };
  const user = invokingUser();
  if (!user) return { ok: false, error: "无法确定发起请求的用户（SUDO_UID）" };

  const code = await new Promise<number | null>((resolve) => {
    const child = spawn(TOUCHID_BIN, [reason], {
      uid: user.uid,
      gid: user.gid,
      cwd: "/",
      env: { PATH: "/usr/bin:/bin" },
      stdio: "ignore",
    });
    const timer = setTimeout(() => child.kill("SIGKILL"), AUTH_TIMEOUT_MS);
    child.on("error", () => resolve(null));
    child.on("exit", (c) => {
      clearTimeout(timer);
      resolve(c);
    });
  });

  if (code === 0) {
    clearFailure(vaultDir);
    return { ok: true };
  }
  recordFailure(vaultDir);
  if (code === 2) return { ok: false, error: "本机不支持设备所有者认证（Touch ID / 登录密码）" };
  return { ok: false, error: "Touch ID 认证未通过（已拒绝、取消或超时）" };
}
