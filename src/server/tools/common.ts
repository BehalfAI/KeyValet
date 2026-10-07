import fs from "node:fs";
import { confirm } from "../dialog.js";
import { readSecretFile, resolveSecretFile } from "../files.js";
import { z } from "zod";
import type { Requester } from "../session.js";
import { t } from "../../shared/i18n.js";

export type ToolResult = { content: Array<{ type: "text"; text: string }>; isError?: boolean };

export function ok(text: string, data?: unknown): ToolResult {
  return { content: [{ type: "text", text: data === undefined ? text : `${text}\n${JSON.stringify(data, null, 2)}` }] };
}

export function fail(text: string): ToolResult {
  return { content: [{ type: "text", text }], isError: true };
}

export function wrap<A>(fn: (args: A) => Promise<ToolResult>): (args: A) => Promise<ToolResult> {
  return async (args) => {
    try {
      return await fn(args);
    } catch (e) {
      return fail(t(`错误：${(e as Error).message}`, `Error: ${(e as Error).message}`));
    }
  };
}

export const norm = (s: string) => s.trim().toLowerCase();

/** 必填的目的说明：显示在 Touch ID 弹窗中（需要解锁时），并写入审计日志 */
export const purposeField = z
  .string()
  .min(2)
  .max(300)
  .describe(
    t(
      "本次操作的目的（必填）：需要解锁时会显示在 Touch ID 弹窗中，并记入审计日志。例如“读取订单 #6 的测试邮件”",
      "Purpose of this operation (required): shown in the Touch ID prompt when unlocking is needed, and recorded in the audit log. E.g. \"Read the test email for order #6\"",
    ),
  );

export const optionalPurposeField = purposeField.optional().describe(t("本次操作的目的（可选）：需要解锁时显示在 Touch ID 弹窗中", "Purpose of this operation (optional): shown in the Touch ID prompt when unlocking is needed"));

export const CLIENT_ID_RE = /^[A-Za-z0-9._@:/-]{1,200}$/;

/** 会出现在原生弹窗里的值：必须匹配严格格式，杜绝 agent 写入诱导性文字 */
export function safeDisplay(v: unknown, re: RegExp, what: string): string {
  if (typeof v !== "string" || !re.test(v)) throw new Error(t(`${what} 格式不对`, `${what} has an invalid format`));
  return v;
}

export function httpsHost(url: unknown, what: string): string {
  try {
    const u = new URL(String(url));
    if (u.protocol === "https:" && /^[a-z0-9.-]+(:\d+)?$/i.test(u.host)) return u.host;
  } catch {
    /* fallthrough */
  }
  throw new Error(t(`${what} 必须是 https URL`, `${what} must be an https URL`));
}

/**
 * 从文件导入秘密前请用户确认：防止 agent 借本工具读取用户的任意文件
 * （如 ~/.ssh/id_ed25519）并存成可读回的凭证，绕过客户端对 agent 的文件访问限制。
 */
export async function importFile(p: string, label: string): Promise<{ content: string; path: string }> {
  const abs = resolveSecretFile(p);
  if (/[\u0000-\u001f\u007f]/.test(abs) || abs.length > 500) throw new Error(t("文件路径包含非法字符", "File path contains invalid characters"));
  // 先确认，后读取
  if (
    !(await confirm(
      t(`AI agent 请求从以下文件导入秘密：\n\n${abs}\n\n保存为凭证：${label}`, `An AI agent wants to import a secret from this file:\n\n${abs}\n\nSave as credential: ${label}`),
      t("允许导入", "Allow import"),
    ))
  ) {
    throw new Error(t("用户拒绝了文件导入。", "The user declined the file import."));
  }
  return { content: readSecretFile(abs), path: abs };
}

/**
 * 导入后删除原文件前再次确认（独立于导入确认）：删除不可恢复，必须让用户看清具体路径再点头。
 */
export async function confirmDeleteSourceFile(abs: string): Promise<boolean> {
  if (
    !(await confirm(
      t(`AI agent 请求删除刚刚导入的原文件：\n\n${abs}\n\n此操作不可恢复。`, `An AI agent wants to delete the original file it just imported from:\n\n${abs}\n\nThis cannot be undone.`),
      t("确认删除", "Delete"),
    ))
  ) {
    return false;
  }
  try {
    fs.rmSync(abs);
    return true;
  } catch {
    return false;
  }
}

export interface CredentialInfo {
  type: string;
  name: string;
  kind: string;
  config?: Record<string, unknown>;
}

export async function tryInfo(session: Requester, type: string, name: string): Promise<CredentialInfo | null> {
  if (!(await session.request<boolean>("exists", { type, name }))) return null;
  return session.request<CredentialInfo>("info", { type, name });
}

/**
 * 只给了 name 时，在指定种类的凭证中按名字查找类型。
 * 找到唯一一个则返回，否则报错让调用方指定 type。
 */
export async function resolveType(session: Requester, name: string, type: string | undefined, kinds: string[]): Promise<string> {
  if (type) return type;
  const all = await session.request<Array<{ type: string; name: string; kind: string }>>("list", {});
  const hits = all.filter((c) => c.name === norm(name) && kinds.includes(c.kind));
  if (hits.length === 1) return hits[0]!.type;
  if (hits.length === 0) throw new Error(t(`找不到名为 "${norm(name)}" 的 ${kinds.join("/")} 凭证`, `No ${kinds.join("/")} credential named "${norm(name)}" found`));
  throw new Error(
    t(
      `有多个名为 "${norm(name)}" 的凭证（${hits.map((h) => h.type).join("、")}），请指定 type`,
      `Multiple credentials are named "${norm(name)}" (${hits.map((h) => h.type).join(", ")}); please specify type`,
    ),
  );
}

/**
 * 已存在时：没有 overwrite 则报错。返回是否已存在。
 * 覆盖确认由 root helper 在写入时弹出（server 端不再重复弹窗）。
 */
export async function guardOverwrite(session: Requester, type: string, name: string, overwrite: boolean | undefined): Promise<boolean> {
  const exists = await session.request<boolean>("exists", { type, name });
  if (!exists) return false;
  if (!overwrite)
    throw new Error(
      t(
        `凭证 "${norm(type)}/${norm(name)}" 已存在。如需替换，请设置 overwrite=true（会弹窗请用户确认）。`,
        `Credential "${norm(type)}/${norm(name)}" already exists. To replace it, set overwrite=true (the user will be asked to confirm).`,
      ),
    );
  return true;
}
