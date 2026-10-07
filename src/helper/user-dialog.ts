// A confirmation dialog raised by the root helper itself (dropping privileges to the user who invoked
// sudo to run the system's own osascript). Used for the most sensitive changes (such as expanding the
// domains a proxy is allowed to call): even if someone bypasses the MCP server and drives the helper
// directly, user confirmation is still required.

import { spawn } from "node:child_process";
import { t } from "../shared/i18n.js";

type Confirmer = (message: string, okLabel: string) => Promise<boolean>;

let override: Confirmer | null = null;
/** Test-only: replace the confirmation dialog */
export function setUserConfirmForTests(fn: Confirmer | null): void {
  override = fn;
}

export function confirmAsUser(message: string, okLabel: string): Promise<boolean> {
  if (override) return override(message, okLabel);
  const uid = Number(process.env.SUDO_UID);
  const gid = Number(process.env.SUDO_GID);
  if (!Number.isInteger(uid) || uid <= 0 || !Number.isInteger(gid)) return Promise.resolve(false);
  const script = `on run argv
  set r to display dialog (item 1 of argv) with title (item 2 of argv) buttons {(item 4 of argv), (item 3 of argv)} default button (item 4 of argv) cancel button (item 4 of argv) with icon caution giving up after 120
  if gave up of r then error number -128
  return button returned of r
end run`;
  return new Promise((resolve) => {
    const child = spawn("/usr/bin/osascript", ["-e", script, "--", message, t("KeyValet · 安全确认", "KeyValet · Security Confirmation"), okLabel, t("拒绝", "Deny")], {
      uid,
      gid,
      cwd: "/",
      env: { PATH: "/usr/bin:/bin" },
      stdio: ["ignore", "pipe", "ignore"],
    });
    let out = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (d: string) => (out += d));
    const timer = setTimeout(() => child.kill("SIGKILL"), 130_000);
    child.on("error", () => resolve(false));
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve(code === 0 && out.trim() === okLabel);
    });
  });
}
