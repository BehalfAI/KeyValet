import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { IMAP_HOSTS, graphMailTest, imapXoauth2Test } from "../mail.js";
import type { HelperSession } from "../session.js";
import { fail, ok, purposeField, resolveType, wrap } from "./common.js";

export function registerMailTools(server: McpServer, session: HelperSession): void {
  server.registerTool(
    "credential_imap_test",
    {
      description:
        "用 oauth2 凭证通过 XOAUTH2 登录 IMAP，只读打开收件箱（EXAMINE，不改变任何邮件状态）后退出，用于验证邮箱授权是否可用。" +
        "Outlook/Microsoft 默认 outlook.office365.com，Google 默认 imap.gmail.com。不会返回 token。",
      inputSchema: {
        purpose: purposeField,
        name: z.string().describe("oauth2 凭证名"),
        type: z.string().optional().describe("凭证类型；省略时按名字自动查找"),
        host: z.string().optional().describe("IMAP 服务器；省略则按 provider 选择"),
        port: z.number().int().optional().describe("默认 993（TLS）"),
        username: z.string().optional().describe("邮箱地址；省略则使用授权时识别出的账号"),
      },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      const type = await resolveType(s, a.name, a.type, ["oauth2"]);
      const info = await s.request<{ config: { provider: string } }>("info", { type, name: a.name });
      const host = a.host ?? IMAP_HOSTS[info.config.provider];
      if (!host) throw new Error(`provider "${info.config.provider}" 没有默认 IMAP 服务器，请指定 host。`);
      if (!/^[a-z0-9.-]+$/i.test(host)) throw new Error("host 格式不对");
      const t = await s.request<{ access_token: string; account?: string | null; scope?: string | null }>("accessToken", { type, name: a.name });
      const username = a.username ?? t.account;
      if (!username) throw new Error("无法确定邮箱地址：请传 username，或在授权 scope 中包含 openid email。");
      const r = await imapXoauth2Test({ host, port: a.port, username, accessToken: t.access_token });
      if (r.authenticated) return ok(`IMAP 登录成功（${username} @ ${host}）。`, r);

      const hints: string[] = [];
      const scope = t.scope ?? "";
      if (/authenticated but not connected/i.test(r.server_error ?? "")) {
        // token 有效、认证已通过，问题在邮箱侧
        hints.push("token 有效且认证已通过，但服务器无法连接到该用户名对应的邮箱");
        hints.push(
          "个人账号（outlook.com/hotmail/live/msn 等）：这是微软服务端自 2024 年 12 月起的已知 bug，尚无修复 " +
            "（https://learn.microsoft.com/en-us/answers/questions/5673167）。请改用 Microsoft Graph：" +
            "credential_oauth_login 使用 provider=outlook_graph（同一个 client_id / tenant / redirect_uri，另起一个凭证名），" +
            "再用 credential_graph_mail_test 验证",
        );
        hints.push("企业账号：username 须为邮箱的主地址，且管理员需为该邮箱启用 IMAP");
      } else if (["outlook", "microsoft"].includes(info.config.provider)) {
        if (!/IMAP\.AccessAsUser\.All/i.test(scope)) hints.push("token 的 scope 中没有 IMAP.AccessAsUser.All：用 scopes 包含 https://outlook.office.com/IMAP.AccessAsUser.All 重新授权");
        hints.push("个人账号（outlook.com/hotmail/live/msn）：tenant 应为 consumers 或 common（不能用目录租户 ID），应用的受支持账户类型须包含个人 Microsoft 账户");
        hints.push("确认 username 与登录授权的账号一致");
        hints.push("个人账号需在 Outlook.com 设置 → 邮件 → 转发和 IMAP 中启用 IMAP；企业账号需管理员为该邮箱启用 IMAP");
      } else if (info.config.provider === "google") {
        if (!scope.includes("https://mail.google.com/")) hints.push("Gmail IMAP 需要 scope https://mail.google.com/");
      }
      return { content: [{ type: "text", text: `IMAP 登录失败。\n${JSON.stringify(r, null, 2)}${hints.length ? `\n\n可能的原因：\n- ${hints.join("\n- ")}` : ""}` }], isError: true };
    }),
  );

  server.registerTool(
    "credential_graph_mail_test",
    {
      description:
        "用 oauth2 凭证（Microsoft Graph，scope 含 Mail.Read）只读查看邮件夹：邮件总数、未读数和最近几封的时间/发件人/标题，" +
        "用于验证 Outlook / Microsoft 365 邮箱授权是否可用。不改变任何邮件状态，不返回 token。",
      inputSchema: {
        purpose: purposeField,
        name: z.string().describe("oauth2 凭证名（provider=outlook_graph 或 microsoft，scope 含 Mail.Read）"),
        type: z.string().optional().describe("凭证类型；省略时按名字自动查找"),
        folder: z.string().optional().describe("邮件夹，默认 inbox；也可用 junkemail、sentitems 等或文件夹 ID"),
        top: z.number().int().optional().describe("列出最近几封，默认 5，最多 20"),
      },
    },
    wrap(async (a) => {
      const s = session.scoped(a.purpose, { type: a.type, name: a.name });
      if (a.folder !== undefined && !/^[A-Za-z0-9_=-]{1,300}$/.test(a.folder)) return fail("folder 格式不对");
      const type = await resolveType(s, a.name, a.type, ["oauth2"]);
      const t = await s.request<{ access_token: string; scope?: string | null }>("accessToken", { type, name: a.name });
      const r = await graphMailTest({ accessToken: t.access_token, folder: a.folder, top: a.top });
      if (r.ok) return ok(`Graph 读取成功（${r.folder}：共 ${r.total} 封，未读 ${r.unread} 封）。`, r);
      const hints: string[] = [];
      const scope = t.scope ?? "";
      if (!/Mail\.Read/i.test(scope)) {
        hints.push("token 的 scope 中没有 Mail.Read：这个凭证可能是为其他服务（如 IMAP）授权的；请用 provider=outlook_graph 另建凭证授权");
      }
      if (r.http_status === 401) hints.push("token 被拒绝：可尝试 credential_access_token(force_refresh=true) 后重试，或重新授权");
      if (r.http_status === 403) hints.push("权限不足：确认授权时同意了「读取你的邮件」，必要时在 Azure 应用的 API 权限中添加 Microsoft Graph → Mail.Read");
      return fail(`Graph 读取失败。\n${JSON.stringify(r, null, 2)}${hints.length ? `\n\n可能的原因：\n- ${hints.join("\n- ")}` : ""}`);
    }),
  );
}
