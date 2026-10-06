// 凭证库设置（root-only，存于凭证库目录）。agent 无法直接修改；放宽权限的改动需用户确认。

import fs from "node:fs";
import path from "node:path";

export type GrantMode = "per_credential" | "all";

export interface Settings {
  /** per_credential：每个凭证单独 Touch ID 授权；all：一次授权本会话使用全部凭证 */
  grant_mode: GrantMode;
}

const DEFAULTS: Settings = { grant_mode: "per_credential" };

function file(vaultDir: string): string {
  return path.join(vaultDir, "settings.json");
}

export function readSettings(vaultDir: string): Settings {
  try {
    const raw = JSON.parse(fs.readFileSync(file(vaultDir), "utf8")) as Partial<Settings>;
    return { grant_mode: raw.grant_mode === "all" ? "all" : "per_credential" };
  } catch {
    return { ...DEFAULTS };
  }
}

export function writeSettings(vaultDir: string, s: Settings): void {
  const tmp = `${file(vaultDir)}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, JSON.stringify(s, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(tmp, file(vaultDir));
}
