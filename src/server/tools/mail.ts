import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { IMAP_HOSTS, graphMailTest, imapXoauth2Test } from "../mail.js";
import type { HelperSession } from "../session.js";
import { t } from "../../shared/i18n.js";
import { fail, ok, purposeField, resolveType, wrap } from "./common.js";

export function registerMailTools(server: McpServer, session: HelperSession): void {
  server.registerTool(
    "credential_imap_test",
    {
      description: t(
        "用 oauth2 凭证通过 XOAUTH2 登录 IMAP，只读打开收件箱（EXAMINE，不改变任何邮件状态）后退出，用于验证邮箱授权是否可用。" +
          "Outlook/Microsoft 默认 outlook.office365.com，Google 默认 imap.gmail.com。不会返回 token。",
        "Log in to IMAP via XOAUTH2 using an oauth2 credential, open the inbox read-only (EXAMINE; no message state is changed), then log out. " +
          "Use it to verify that mailbox authorization works. Defaults: outlook.office365.com for Outlook/Microsoft, imap.gmail.com for Google. Never returns the token.",
      ),
      inputSchema: {
        purpose: purposeField,
        name: z.string().describe(t("oauth2 凭证名", "Name of the oauth2 credential")),
        type: z.string().optional().describe(t("凭证类型；省略时按名字自动查找", "Credential type; looked up by name if omitted")),
        host: z.string().optional().describe(t("IMAP 服务器；省略则按 provider 选择", "IMAP server; chosen from the provider if omitted")),
        port: z.number().int().optional().describe(t("默认 993（TLS）", "Defaults to 993 (TLS)")),
        username: z.string().optional().describe(t("邮箱地址；省略则使用授权时识别出的账号", "Email address; defaults to the account identified during authorization")),
      },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      const type = await resolveType(s, a.name, a.type, ["oauth2"]);
      const info = await s.request<{ config: { provider: string } }>("info", { type, name: a.name });
      const host = a.host ?? IMAP_HOSTS[info.config.provider];
      if (!host) throw new Error(t(`provider "${info.config.provider}" 没有默认 IMAP 服务器，请指定 host。`, `Provider "${info.config.provider}" has no default IMAP server; please specify host.`));
      if (!/^[a-z0-9.-]+$/i.test(host)) throw new Error(t("host 格式不对", "Invalid host format"));
      const tok = await s.request<{ access_token: string; account?: string | null; scope?: string | null }>("accessToken", { type, name: a.name });
      const username = a.username ?? tok.account;
      if (!username) throw new Error(t("无法确定邮箱地址：请传 username，或在授权 scope 中包含 openid email。", "Cannot determine the email address: pass username, or include openid email in the authorization scopes."));
      const r = await imapXoauth2Test({ host, port: a.port, username, accessToken: tok.access_token });
      if (r.authenticated) return ok(t(`IMAP 登录成功（${username} @ ${host}）。`, `IMAP login succeeded (${username} @ ${host}).`), r);

      const hints: string[] = [];
      const scope = tok.scope ?? "";
      if (/authenticated but not connected/i.test(r.server_error ?? "")) {
        // The token is valid and authentication succeeded; the problem is on the mailbox side
        hints.push(t("token 有效且认证已通过，但服务器无法连接到该用户名对应的邮箱", "The token is valid and authentication succeeded, but the server could not connect to the mailbox for this username"));
        hints.push(
          t(
            "个人账号（outlook.com/hotmail/live/msn 等）：这是微软服务端自 2024 年 12 月起的已知 bug，尚无修复 " +
              "（https://learn.microsoft.com/en-us/answers/questions/5673167）。请改用 Microsoft Graph：" +
              "credential_oauth_login 使用 provider=outlook_graph（同一个 client_id / tenant / redirect_uri，另起一个凭证名），" +
              "再用 credential_graph_mail_test 验证",
            "Personal accounts (outlook.com/hotmail/live/msn, etc.): this is a known Microsoft server-side bug since December 2024 with no fix yet " +
              "(https://learn.microsoft.com/en-us/answers/questions/5673167). Use Microsoft Graph instead: " +
              "run credential_oauth_login with provider=outlook_graph (same client_id / tenant / redirect_uri, under a new credential name), " +
              "then verify with credential_graph_mail_test",
          ),
        );
        hints.push(t("企业账号：username 须为邮箱的主地址，且管理员需为该邮箱启用 IMAP", "Work/school accounts: username must be the mailbox's primary address, and an admin must enable IMAP for the mailbox"));
      } else if (["outlook", "microsoft"].includes(info.config.provider)) {
        if (!/IMAP\.AccessAsUser\.All/i.test(scope)) hints.push(t("token 的 scope 中没有 IMAP.AccessAsUser.All：用 scopes 包含 https://outlook.office.com/IMAP.AccessAsUser.All 重新授权", "The token scope lacks IMAP.AccessAsUser.All: re-authorize with scopes including https://outlook.office.com/IMAP.AccessAsUser.All"));
        hints.push(t("个人账号（outlook.com/hotmail/live/msn）：tenant 应为 consumers 或 common（不能用目录租户 ID），应用的受支持账户类型须包含个人 Microsoft 账户", "Personal accounts (outlook.com/hotmail/live/msn): tenant must be consumers or common (not a directory tenant ID), and the app's supported account types must include personal Microsoft accounts"));
        hints.push(t("确认 username 与登录授权的账号一致", "Make sure username matches the account that granted authorization"));
        hints.push(t("个人账号需在 Outlook.com 设置 → 邮件 → 转发和 IMAP 中启用 IMAP；企业账号需管理员为该邮箱启用 IMAP", "Personal accounts must enable IMAP in Outlook.com Settings → Mail → Forwarding and IMAP; for work/school accounts an admin must enable IMAP for the mailbox"));
      } else if (info.config.provider === "google") {
        if (!scope.includes("https://mail.google.com/")) hints.push(t("Gmail IMAP 需要 scope https://mail.google.com/", "Gmail IMAP requires the scope https://mail.google.com/"));
      }
      return { content: [{ type: "text", text: t(
            `IMAP 登录失败。\n${JSON.stringify(r, null, 2)}${hints.length ? `\n\n可能的原因：\n- ${hints.join("\n- ")}` : ""}`,
            `IMAP login failed.\n${JSON.stringify(r, null, 2)}${hints.length ? `\n\nPossible causes:\n- ${hints.join("\n- ")}` : ""}`,
          ) }], isError: true };
    }),
  );

  server.registerTool(
    "credential_graph_mail_test",
    {
      description: t(
        "用 oauth2 凭证（Microsoft Graph，scope 含 Mail.Read）只读查看邮件夹：邮件总数、未读数和最近几封的时间/发件人/标题，" +
          "用于验证 Outlook / Microsoft 365 邮箱授权是否可用。不改变任何邮件状态，不返回 token。",
        "Read a mail folder read-only using an oauth2 credential (Microsoft Graph, scope includes Mail.Read): total and unread counts plus the time/sender/subject of the most recent messages. " +
          "Use it to verify that Outlook / Microsoft 365 mailbox authorization works. Changes no message state and never returns the token.",
      ),
      inputSchema: {
        purpose: purposeField,
        name: z.string().describe(t("oauth2 凭证名（provider=outlook_graph 或 microsoft，scope 含 Mail.Read）", "Name of the oauth2 credential (provider=outlook_graph or microsoft, scope includes Mail.Read)")),
        type: z.string().optional().describe(t("凭证类型；省略时按名字自动查找", "Credential type; looked up by name if omitted")),
        folder: z.string().optional().describe(t("邮件夹，默认 inbox；也可用 junkemail、sentitems 等或文件夹 ID", "Mail folder, default inbox; also junkemail, sentitems, etc., or a folder ID")),
        top: z.number().int().optional().describe(t("列出最近几封，默认 5，最多 20", "Number of recent messages to list, default 5, max 20")),
      },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      if (a.folder !== undefined && !/^[A-Za-z0-9_=-]{1,300}$/.test(a.folder)) return fail(t("folder 格式不对", "Invalid folder format"));
      const type = await resolveType(s, a.name, a.type, ["oauth2"]);
      const tok = await s.request<{ access_token: string; scope?: string | null }>("accessToken", { type, name: a.name });
      const r = await graphMailTest({ accessToken: tok.access_token, folder: a.folder, top: a.top });
      if (r.ok) return ok(t(`Graph 读取成功（${r.folder}：共 ${r.total} 封，未读 ${r.unread} 封）。`, `Graph read succeeded (${r.folder}: ${r.total} messages, ${r.unread} unread).`), r);
      const hints: string[] = [];
      const scope = tok.scope ?? "";
      if (!/Mail\.Read/i.test(scope)) {
        hints.push(t("token 的 scope 中没有 Mail.Read：这个凭证可能是为其他服务（如 IMAP）授权的；请用 provider=outlook_graph 另建凭证授权", "The token scope lacks Mail.Read: this credential may have been authorized for another service (e.g. IMAP); create a new credential with provider=outlook_graph"));
      }
      if (r.http_status === 401) hints.push(t("token 被拒绝：可尝试 credential_access_token(force_refresh=true) 后重试，或重新授权", "Token rejected: try credential_access_token(force_refresh=true) and retry, or re-authorize"));
      if (r.http_status === 403) hints.push(t("权限不足：确认授权时同意了「读取你的邮件」，必要时在 Azure 应用的 API 权限中添加 Microsoft Graph → Mail.Read", "Insufficient permissions: make sure \"Read your mail\" was consented during authorization; if needed, add Microsoft Graph → Mail.Read to the Azure app's API permissions"));
      return fail(
        t(
          `Graph 读取失败。\n${JSON.stringify(r, null, 2)}${hints.length ? `\n\n可能的原因：\n- ${hints.join("\n- ")}` : ""}`,
          `Graph read failed.\n${JSON.stringify(r, null, 2)}${hints.length ? `\n\nPossible causes:\n- ${hints.join("\n- ")}` : ""}`,
        ),
      );
    }),
  );
}
