// macOS 原生对话框。所有文案都通过 argv 传给 AppleScript，避免脚本注入；
// 对话框里只出现经过校验的 type/name 和固定文案，不展示 agent 可随意控制的长文本，
// 防止 agent 用伪造提示诱导用户输入 sudo 密码等内容。

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
 * 弹出隐藏输入框，让用户直接输入凭证值（不经过 AI 上下文）。取消或超时返回 null。
 * 刻意与 sudo 密码框区分（不同标题、图标、固定警示），避免用户误把登录密码输进来。
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

/** 确认框，默认按钮为“取消”。 */
export async function confirm(message: string, okLabel: string): Promise<boolean> {
  const script = `on run argv
  set r to display dialog (item 1 of argv) with title (item 2 of argv) buttons {(item 4 of argv), (item 3 of argv)} default button (item 4 of argv) cancel button (item 4 of argv) with icon caution giving up after 120
  if gave up of r then error number -128
  return button returned of r
end run`;
  const { ok, stdout } = await runAppleScript(script, [message, TITLE, okLabel, t("取消", "Cancel")], 130_000);
  return ok && stdout.trim() === okLabel;
}

/** 询问框：默认按钮为执行操作（回车即执行），“取消”为取消按钮。返回是否点了执行。 */
export async function ask(message: string, okLabel: string): Promise<boolean> {
  const script = `on run argv
  set r to display dialog (item 1 of argv) with title (item 2 of argv) buttons {(item 4 of argv), (item 3 of argv)} default button 2 cancel button 1 with icon note giving up after 600
  if gave up of r then error number -128
  return button returned of r
end run`;
  const { ok, stdout } = await runAppleScript(script, [message, TITLE, okLabel, t("取消", "Cancel")], 610_000);
  return ok && stdout.trim() === okLabel;
}

/** 非阻塞的提示框（如显示设备码），没有默认按钮（回车不会误关），返回关闭函数 */
export function showNotice(message: string, timeoutSec = 900): () => void {
  const script = `on run argv
  display dialog (item 1 of argv) with title (item 2 of argv) buttons {(item 3 of argv)} giving up after ${Math.floor(timeoutSec)}
end run`;
  const child = execFile(OSASCRIPT_BIN, ["-e", script, "--", message, TITLE, t("好", "OK")], { env: { PATH: "/usr/bin:/bin" } }, () => {});
  return () => {
    if (child.exitCode === null) child.kill();
  };
}
