// Touch ID gate: the helper starts as root (sudoers only allows running the helper itself without a password),
// and must pass device-owner authentication before providing any service.
//
// Fingerprint prompts can't reach the auth UI while running as root, so we drop privileges to the user
// who invoked sudo (SUDO_UID) to run the touchid program; that program is owned by root with hardened
// runtime signing (same-user processes can't inject into or debug it), and the result is returned to
// this process directly via its exit code.

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { t } from "../shared/i18n.js";
import { TOUCHID_BIN } from "../shared/paths.js";
import { untrustedReason } from "./trust.js";

const AUTH_TIMEOUT_MS = 120_000;
/** Cooldown after a failed authentication: recorded in the root-only vault directory, so even launching the helper directly (bypassing the MCP server) can't trigger repeated prompts */
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

/** The user who invoked sudo (set by sudo itself; the caller cannot forge this) */
function invokingUser(): { uid: number; gid: number } | null {
  const uid = Number(process.env.SUDO_UID);
  const gid = Number(process.env.SUDO_GID);
  if (!Number.isInteger(uid) || !Number.isInteger(gid) || uid <= 0) return null;
  return { uid, gid };
}

/** Only one authentication prompt is allowed at a time (when multiple helpers start concurrently, each could otherwise trigger its own prompt before the cooldown check runs) */
function acquireAuthLock(vaultDir: string): (() => void) | null {
  const lock = path.join(vaultDir, ".auth-lock");
  try {
    fs.mkdirSync(lock, { mode: 0o700 });
  } catch {
    try {
      if (Date.now() - fs.statSync(lock).mtimeMs < AUTH_TIMEOUT_MS + 10_000) return null;
      fs.rmSync(lock, { recursive: true, force: true }); // the lock-holding process has exited
      fs.mkdirSync(lock, { mode: 0o700 });
    } catch {
      return null;
    }
  }
  return () => fs.rmSync(lock, { recursive: true, force: true });
}

export async function touchIdGate(vaultDir: string, reason: string): Promise<GateResult> {
  const release = acquireAuthLock(vaultDir);
  if (!release) return { ok: false, error: t("已有另一个解锁请求正在等待认证，请稍后再试", "Another unlock request is already waiting for authentication; please try again later") };
  try {
    return await gate(vaultDir, reason);
  } finally {
    release();
  }
}

async function gate(vaultDir: string, reason: string): Promise<GateResult> {
  const wait = cooldownRemainingMs(vaultDir);
  if (wait > 0) return { ok: false, error: t(`上次认证未通过，请 ${Math.ceil(wait / 1000)} 秒后再试`, `The last authentication failed; please try again in ${Math.ceil(wait / 1000)} seconds`) };
  let bad: string | null;
  try {
    bad = untrustedReason(TOUCHID_BIN);
  } catch {
    bad = t("文件不存在", "file does not exist");
  }
  if (bad) return { ok: false, error: t(`Touch ID 程序不可信（${bad}），请重新安装`, `The Touch ID program is untrusted (${bad}); please reinstall`) };
  const user = invokingUser();
  if (!user) return { ok: false, error: t("无法确定发起请求的用户（SUDO_UID）", "Cannot determine the requesting user (SUDO_UID)") };

  const code = await new Promise<number | null>((resolve) => {
    const child = spawn(TOUCHID_BIN, [reason, t("拒绝", "Deny")], {
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
  if (code === 2) return { ok: false, error: t("本机不支持设备所有者认证（Touch ID / 登录密码）", "This Mac does not support device owner authentication (Touch ID / login password)") };
  return { ok: false, error: t("Touch ID 认证未通过（已拒绝、取消或超时）", "Touch ID authentication failed (denied, canceled, or timed out)") };
}
