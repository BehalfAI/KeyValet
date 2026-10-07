// OAuth authentication for mail protocols: XOAUTH2 (used by IMAP/SMTP for both Gmail and
// Outlook/Microsoft 365).
// The IMAP test runs in the MCP process (as a regular user) and only ever uses a short-lived
// access token.

import tls from "node:tls";

import { readLimited } from "../helper/protocols/http.js";
import { t } from "../shared/i18n.js";

export const IMAP_HOSTS: Record<string, string> = {
  outlook: "outlook.office365.com",
  microsoft: "outlook.office365.com",
  google: "imap.gmail.com",
};

/** SASL XOAUTH2 initial response: base64("user=<u>^Aauth=Bearer <token>^A^A") */
export function xoauth2(username: string, accessToken: string): string {
  return Buffer.from(`user=${username}\x01auth=Bearer ${accessToken}\x01\x01`).toString("base64");
}

export interface ImapTestResult {
  authenticated: boolean;
  host: string;
  username: string;
  /** Inbox message count (read-only EXAMINE, doesn't change any message state) */
  inbox_messages?: number;
  server_error?: string;
}

/**
 * Logs into IMAP using XOAUTH2, opens the inbox read-only, then logs out.
 * On auth failure, the server first sends a "+ <base64 JSON>" error detail, which is decoded
 * and returned.
 */
export function imapXoauth2Test(opts: {
  host: string;
  port?: number;
  username: string;
  accessToken: string;
  timeoutMs?: number;
  /** Test-only: trust self-signed certificates */
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
            // Error detail (base64 JSON); reply with an empty line to get the server's final NO
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

/** Reads a mail folder read-only via Microsoft Graph: message counts + sender/subject of the most recent messages (doesn't change any message state) */
export async function graphMailTest(opts: {
  accessToken: string;
  folder?: string;
  top?: number;
  /** Test-only */
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
      /* not JSON */
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
