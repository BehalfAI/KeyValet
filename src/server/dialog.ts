// Native macOS dialogs. All text is passed to AppleScript via argv to avoid script injection;
// only validated type/name values and fixed strings ever appear in the dialog — no long text
// that an agent could freely control is ever shown, preventing an agent from using a forged
// prompt to trick the user into entering their sudo password or similar.

import { execFile } from "node:child_process";
import { OSASCRIPT_BIN } from "../shared/paths.js";
import { t } from "../shared/i18n.js";

const TITLE = "KeyValet";

function runAppleScript(script: string, args: string[], timeoutMs: number): Promise<{ ok: boolean; stdout: string }> {
  return new Promise((resolve) => {
    execFile(
      OSASCRIPT_BIN,
      ["-e", script, "--", ...args],
      { timeout: timeoutMs, maxBuffer: 1024 * 1024, env: { PATH: "/usr/bin:/bin" } },
      (err, stdout) => resolve({ ok: !err, stdout: stdout.toString() }),
    );
  });
}

/**
 * Shows a hidden-input dialog so the user can type a credential value directly (never passing
 * through the AI context). Returns null on cancel or timeout.
 * Deliberately distinguished from the sudo password prompt (different title, icon, fixed
 * warning) so users don't accidentally type their login password here.
 */
export async function promptSecret(message: string): Promise<string | null> {
  const script = `on run argv
  set r to display dialog (item 1 of argv) with title (item 2 of argv) default answer "" with hidden answer buttons {(item 3 of argv), (item 4 of argv)} default button (item 4 of argv) cancel button (item 3 of argv) with icon note giving up after 300
  if gave up of r then error number -128
  return text returned of r
end run`;
  const full = t(
    `【保存秘密】${message}\n\n⚠️ 这里不是 Mac 登录密码 / sudo 密码，请勿在此输入登录密码。`,
    `[Save secret] ${message}\n\n⚠️ This is NOT your Mac login / sudo password. Do not enter your login password here.`,
  );
  const { ok, stdout } = await runAppleScript(
    script,
    [full, `${TITLE} · ${t("保存秘密", "Save Secret")}`, t("取消", "Cancel"), t("保存", "Save")],
    310_000,
  );
  if (!ok) return null;
  const value = stdout.endsWith("\n") ? stdout.slice(0, -1) : stdout;
  return value.length > 0 ? value : null;
}

/** Confirmation dialog; the default button is “Cancel”. */
export async function confirm(message: string, okLabel: string): Promise<boolean> {
  const script = `on run argv
  set r to display dialog (item 1 of argv) with title (item 2 of argv) buttons {(item 4 of argv), (item 3 of argv)} default button (item 4 of argv) cancel button (item 4 of argv) with icon caution giving up after 120
  if gave up of r then error number -128
  return button returned of r
end run`;
  const { ok, stdout } = await runAppleScript(script, [message, TITLE, okLabel, t("取消", "Cancel")], 130_000);
  return ok && stdout.trim() === okLabel;
}

/** Prompt dialog: the default button performs the action (Enter triggers it), “Cancel” is the cancel button. Returns whether the action button was clicked. */
export async function ask(message: string, okLabel: string): Promise<boolean> {
  const script = `on run argv
  set r to display dialog (item 1 of argv) with title (item 2 of argv) buttons {(item 4 of argv), (item 3 of argv)} default button 2 cancel button 1 with icon note giving up after 600
  if gave up of r then error number -128
  return button returned of r
end run`;
  const { ok, stdout } = await runAppleScript(script, [message, TITLE, okLabel, t("取消", "Cancel")], 610_000);
  return ok && stdout.trim() === okLabel;
}

/** Non-blocking notice dialog (e.g., for showing a device code); has no default button (so Enter won't dismiss it accidentally); returns a close function */
export function showNotice(message: string, timeoutSec = 900): () => void {
  const script = `on run argv
  display dialog (item 1 of argv) with title (item 2 of argv) buttons {(item 3 of argv)} giving up after ${Math.floor(timeoutSec)}
end run`;
  const child = execFile(OSASCRIPT_BIN, ["-e", script, "--", message, TITLE, t("好", "OK")], { env: { PATH: "/usr/bin:/bin" } }, () => {});
  return () => {
    if (child.exitCode === null) child.kill();
  };
}
