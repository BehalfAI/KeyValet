// root helper 自己弹出的确认框（降权为发起 sudo 的用户运行系统自带的 osascript）。
// 用于最敏感的改动（如扩大代理可发往的域名）：即使有人绕过 MCP server 直接驱动 helper，也必须经用户确认。

import { spawn } from "node:child_process";
import { t } from "../shared/i18n.js";

type Confirmer = (message: string, okLabel: string) => Promise<boolean>;

let override: Confirmer | null = null;
/** 仅供测试：替换确认框 */
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
