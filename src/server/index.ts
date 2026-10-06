#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { HelperSession } from "./session.js";
import { registerBasicTools } from "./tools/basic.js";
import { registerHttpTools } from "./tools/http.js";
import { registerMailTools } from "./tools/mail.js";
import { registerProtocolTools } from "./tools/protocols.js";

const ttlMinutes = Number(process.env.KEYVALET_SESSION_TTL_MINUTES ?? "0");
const session = new HelperSession(Number.isFinite(ttlMinutes) && ttlMinutes > 0 ? ttlMinutes * 60_000 : 0);

const server = new McpServer(
  { name: "keyvalet", version: "0.1.0" },
  {
    instructions:
      "KeyValet：本地凭证代理。使用凭证时弹出 Touch ID 认证（显示本次目的）。\n" +
      "读取凭证、获取 token、修改凭证等工具都必须传 purpose 说明本次目的（具体、真实，如“调用 OpenAI 生成摘要”），" +
      "会写入审计日志；用 credential_audit_log 可查询操作记录。\n" +
      "先用 credential_list 查看有哪些凭证（kind 字段表示种类）：\n" +
      "- static：API key、密码等。能用代理调用（credential_http_request，凭证库注入认证、agent 看不到 key）时优先代理；" +
      "需要原值时用 credential_get（设为 proxy_only 的凭证不能读出）；\n" +
      "保存新凭证时先用 credential_templates 查找服务模板，用 credential_set 的 template 参数保存（自动配置代理和验证）。\n" +
      "- oauth2 / google_service_account / github_app / jwt：用 credential_access_token 获取短期 token；\n" +
      "- totp：用 credential_totp_code 获取验证码；aws：用 credential_aws_credentials 获取临时凭证。\n" +
      "邮箱（Outlook、Gmail）IMAP/SMTP：用 credential_oauth_login（provider=outlook 或 google）授权，" +
      "credential_access_token 传 format=xoauth2 取认证字符串，credential_imap_test 验证登录。\n" +
      "保存秘密时不要向用户索要明文：省略 value/client secret 等参数让用户在原生弹窗中输入，私钥类文件用文件路径参数导入。\n" +
      "不要把读取到的凭证值回显给用户或写入文件/日志，除非用户明确要求。",
  },
);

registerBasicTools(server, session);
registerProtocolTools(server, session);
registerMailTools(server, session);
registerHttpTools(server, session);

// session 结束（客户端关闭 stdin 或发信号）时立即锁定并退出。
// 否则 sudo 子进程的管道会让本进程一直存活，已解锁的 root helper 也随之残留。
const shutdown = () => {
  session.lock();
  process.exit(0);
};
process.stdin.on("end", shutdown);
process.stdin.on("close", shutdown);
for (const sig of ["SIGTERM", "SIGINT", "SIGHUP"] as const) process.on(sig, shutdown);

await server.connect(new StdioServerTransport());
