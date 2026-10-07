// 凭证库设置（root-only，存于凭证库目录）。agent 无法直接修改；放宽权限的改动需用户按 Touch ID。

import fs from "node:fs";
import path from "node:path";

/**
 * 授权模式（从严到松）：
 *   per_use        每次使用凭证都要 Touch ID
 *   per_credential 每个会话中每个凭证一次（默认）
 *   per_session    每个会话一次，之后可用全部凭证
 *   remember       一次 Touch ID 后，在 remember_hours 内跨会话免认证（0 = 永久）
 */
export const GRANT_MODES = ["per_use", "per_credential", "per_session", "remember"] as const;
export type GrantMode = (typeof GRANT_MODES)[number];

export interface Settings {
  grant_mode: GrantMode;
  /** remember 模式的有效时长（小时），0 表示永久 */
  remember_hours: number;
  /** remember 模式下本次记住到何时（毫秒时间戳）；未记住或已清除时为空 */
  remember_until?: number;
}

const DEFAULTS: Settings = { grant_mode: "per_credential", remember_hours: 8 };
const STRICTNESS: Record<GrantMode, number> = { per_use: 3, per_credential: 2, per_session: 1, remember: 0 };

/** 兼容旧值：all → per_session */
export function parseMode(v: unknown): GrantMode | null {
  if (v === "all") return "per_session";
  return typeof v === "string" && (GRANT_MODES as readonly string[]).includes(v) ? (v as GrantMode) : null;
}

/** 两个模式中更严格的一个（客户端只能把模式收严，不能放宽） */
export function stricter(a: GrantMode, b: GrantMode | null): GrantMode {
  if (!b) return a;
  return STRICTNESS[b] > STRICTNESS[a] ? b : a;
}

/** next 是否比 cur 更宽松（需要用户认证） */
export function isLoosening(cur: Settings, next: Settings): boolean {
  if (STRICTNESS[next.grant_mode] < STRICTNESS[cur.grant_mode]) return true;
  if (next.grant_mode === "remember" && cur.grant_mode === "remember") {
    if (cur.remember_hours === 0) return false;
    return next.remember_hours === 0 || next.remember_hours > cur.remember_hours;
  }
  return false;
}

export function rememberActive(s: Settings, now = Date.now()): boolean {
  return s.grant_mode === "remember" && typeof s.remember_until === "number" && now < s.remember_until;
}

export function rememberUntil(hours: number, now = Date.now()): number {
  return hours === 0 ? Number.MAX_SAFE_INTEGER : now + hours * 3_600_000;
}

function file(vaultDir: string): string {
  return path.join(vaultDir, "settings.json");
}

export function readSettings(vaultDir: string): Settings {
  try {
    const raw = JSON.parse(fs.readFileSync(file(vaultDir), "utf8")) as Record<string, unknown>;
    const hours = Number(raw.remember_hours);
    return {
      grant_mode: parseMode(raw.grant_mode) ?? DEFAULTS.grant_mode,
      remember_hours: Number.isFinite(hours) && hours >= 0 ? hours : DEFAULTS.remember_hours,
      ...(typeof raw.remember_until === "number" ? { remember_until: raw.remember_until } : {}),
    };
  } catch {
    return { ...DEFAULTS };
  }
}

export function writeSettings(vaultDir: string, s: Settings): void {
  const tmp = `${file(vaultDir)}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, JSON.stringify(s, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(tmp, file(vaultDir));
}
