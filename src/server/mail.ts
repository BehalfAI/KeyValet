// 邮件协议的 OAuth 认证：XOAUTH2（Gmail、Outlook/Microsoft 365 的 IMAP/SMTP 都使用它）。
// IMAP 测试在 MCP 进程（普通用户）中进行，只用到短期 access token。

import tls from "node:tls";

import { readLimited } from "../helper/protocols/http.js";
import { t } from "../shared/i18n.js";

export const IMAP_HOSTS: Record<string, string> = {
  outlook: "outlook.office365.com",
  microsoft: "outlook.office365.com",
  google: "imap.gmail.com",
};

/** SASL XOAUTH2 初始响应：base64("user=<u>^Aauth=Bearer <token>^A^A") */
export function xoauth2(username: string, accessToken: string): string {
  return Buffer.from(`user=${username}\x01auth=Bearer ${accessToken}\x01\x01`).toString("base64");
}

export interface ImapTestResult {
  authenticated: boolean;
  host: string;
  username: string;
  /** 收件箱邮件数（只读 EXAMINE，不改变任何邮件状态） */
  inbox_messages?: number;
  server_error?: string;
}

/**
 * 用 XOAUTH2 登录 IMAP，只读打开收件箱后退出。
 * 认证失败时服务器会先发一个 "+ <base64 JSON>" 的错误详情，解码后返回。
 */
export function imapXoauth2Test(opts: {
  host: string;
  port?: number;
  username: string;
  accessToken: string;
  timeoutMs?: number;
  /** 仅测试用：信任自签名证书 */
  ca?: string;
}): Promise<ImapTestResult> {
  const { host, username } = opts;
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port: opts.port ?? 993, servername: host, ca: opts.ca });
    socket.setTimeout(opts.timeoutMs ?? 20_000, () => {
      socket.destroy();
      reject(new Error(t(`连接 ${host} 超时`, `Connection to ${host} timed out`)));
    });
    socket.on("error", (e) => reject(new Error(t(`连接 ${host} 失败：${e.message}`, `Connection to ${host} failed: ${e.message}`))));

    let buf = "";
    let stage: "greeting" | "auth" | "examine" | "logout" = "greeting";
    let serverError: string | undefined;
    let inbox: number | undefined;
    const done = (r: ImapTestResult) => {
      socket.end();
      resolve(r);
    };

    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => {
      buf += chunk;
      if (buf.length > 1_000_000) {
        socket.destroy();
        return reject(new Error(t("IMAP 响应过大", "IMAP response too large")));
      }
      let nl: number;
      while ((nl = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        if (stage === "greeting") {
          if (!line.startsWith("* OK")) return done({ authenticated: false, host, username, server_error: t(`意外的问候：${line.slice(0, 200)}`, `Unexpected greeting: ${line.slice(0, 200)}`) });
          stage = "auth";
          socket.write(`A1 AUTHENTICATE XOAUTH2 ${xoauth2(username, opts.accessToken)}\r\n`);
        } else if (stage === "auth") {
          if (line.startsWith("+")) {
            // 错误详情（base64 JSON），回一个空行让服务器给出最终的 NO
            const detail = line.slice(1).trim();
            try {
              serverError = Buffer.from(detail, "base64").toString("utf8") || detail;
            } catch {
              serverError = detail;
            }
            socket.write("\r\n");
          } else if (line.startsWith("A1 OK")) {
            stage = "examine";
            socket.write("A2 EXAMINE INBOX\r\n");
          } else if (line.startsWith("A1 ")) {
            return done({ authenticated: false, host, username, server_error: [line.slice(3), serverError].filter(Boolean).join(" | ").slice(0, 500) });
          }
        } else if (stage === "examine") {
          const m = /^\* (\d+) EXISTS/.exec(line);
          if (m) inbox = Number(m[1]);
          if (line.startsWith("A2 ")) {
            stage = "logout";
            socket.write("A3 LOGOUT\r\n");
            return done({ authenticated: true, host, username, inbox_messages: inbox });
          }
        }
      }
    });
  });
}

export interface GraphMailResult {
  ok: boolean;
  folder?: string;
  total?: number;
  unread?: number;
  recent?: Array<{ received: string; from: string; subject: string }>;
  http_status?: number;
  error?: string;
}

/** 通过 Microsoft Graph 只读查看一个邮件夹：邮件数 + 最近几封的发件人/标题（不改变任何邮件状态） */
export async function graphMailTest(opts: {
  accessToken: string;
  folder?: string;
  top?: number;
  /** 仅测试用 */
  baseUrl?: string;
}): Promise<GraphMailResult> {
  const base = opts.baseUrl ?? "https://graph.microsoft.com/v1.0";
  const folder = encodeURIComponent(opts.folder ?? "inbox");
  const top = Math.min(Math.max(opts.top ?? 5, 1), 20);
  const get = async (path: string) => {
    const res = await fetch(`${base}${path}`, {
      headers: { Authorization: `Bearer ${opts.accessToken}`, Accept: "application/json", "Accept-Encoding": "identity" },
      redirect: "error",
      signal: AbortSignal.timeout(20_000),
    });
    const text = (await readLimited(res, 2 * 1024 * 1024, new URL(base).host)).toString("utf8");
    let body: Record<string, unknown> = {};
    try {
      body = JSON.parse(text) as Record<string, unknown>;
    } catch {
      /* 非 JSON */
    }
    return { status: res.status, body };
  };
  const fail = (r: { status: number; body: Record<string, unknown> }): GraphMailResult => {
    const e = (r.body.error ?? {}) as { code?: string; message?: string };
    return { ok: false, http_status: r.status, error: `${e.code ?? "HTTP " + r.status}${e.message ? `: ${e.message}` : ""}`.slice(0, 300) };
  };

  const f = await get(`/me/mailFolders/${folder}?$select=displayName,totalItemCount,unreadItemCount`);
  if (f.status !== 200) return fail(f);
  const m = await get(`/me/mailFolders/${folder}/messages?$top=${top}&$select=subject,receivedDateTime,from&$orderby=receivedDateTime%20desc`);
  if (m.status !== 200) return fail(m);
  const value = (Array.isArray(m.body.value) ? m.body.value : []) as Array<{
    subject?: string;
    receivedDateTime?: string;
    from?: { emailAddress?: { address?: string } };
  }>;
  return {
    ok: true,
    folder: String(f.body.displayName ?? opts.folder ?? "inbox"),
    total: Number(f.body.totalItemCount),
    unread: Number(f.body.unreadItemCount),
    recent: value.map((x) => ({
      received: String(x.receivedDateTime ?? ""),
      from: String(x.from?.emailAddress?.address ?? ""),
      subject: String(x.subject ?? "").slice(0, 120),
    })),
  };
}
