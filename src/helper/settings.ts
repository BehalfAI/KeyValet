// Vault settings (root-only, stored in the vault directory). The agent cannot modify them directly; loosening permissions requires the user to confirm with Touch ID.

import fs from "node:fs";
import path from "node:path";

/**
 * Grant modes (strictest to loosest):
 *   per_use        Touch ID is required every time a credential is used
 *   per_credential Once per credential per session (default)
 *   per_session    Once per session, after which all credentials can be used
 *   remember       After one Touch ID, no authentication is required across sessions for remember_hours (0 = forever)
 */
export const GRANT_MODES = ["per_use", "per_credential", "per_session", "remember"] as const;
export type GrantMode = (typeof GRANT_MODES)[number];

export interface Settings {
  grant_mode: GrantMode;
  /** Duration of remember mode in hours; 0 means forever */
  remember_hours: number;
  /** Timestamp (ms) until which this remember period stays active; absent when not remembered or already cleared */
  remember_until?: number;
}

const DEFAULTS: Settings = { grant_mode: "per_credential", remember_hours: 8 };
const STRICTNESS: Record<GrantMode, number> = { per_use: 3, per_credential: 2, per_session: 1, remember: 0 };

/** Backward compatibility for an old value: all → per_session */
export function parseMode(v: unknown): GrantMode | null {
  if (v === "all") return "per_session";
  return typeof v === "string" && (GRANT_MODES as readonly string[]).includes(v) ? (v as GrantMode) : null;
}

/** The stricter of two modes (a client can only tighten the mode, never loosen it) */
export function stricter(a: GrantMode, b: GrantMode | null): GrantMode {
  if (!b) return a;
  return STRICTNESS[b] > STRICTNESS[a] ? b : a;
}

/** Whether next is looser than cur (requires user authentication) */
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
