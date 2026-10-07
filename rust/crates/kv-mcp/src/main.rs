//! MCP server entry point. Direct port of src/server/index.ts.

mod dialog;
mod files;
mod gateway_env;
mod mail;
mod oauth_flow;
mod oauth_presets;
mod server;
mod session;
mod templates;
mod tools {
    pub mod basic;
    pub mod common;
    pub mod http;
    pub mod mail;
    pub mod protocols;
}

use rmcp::handler::server::ServerHandler;
use rmcp::model::{Implementation, ServerCapabilities, ServerConfig};
use rmcp::{tool_handler, ServiceExt};
use server::Server;
use std::sync::Arc;

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Server {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("keyvalet", env!("CARGO_PKG_VERSION")))
            .with_instructions(kv_i18n::t(
                "KeyValet：本地凭证代理。使用凭证时弹出 Touch ID 认证（显示本次目的）。\n\
                读取凭证、获取 token、修改凭证等工具都必须传 purpose 说明本次目的（具体、真实，如\u{201c}调用 OpenAI 生成摘要\u{201d}），\
                会写入审计日志；用 credential_audit_log 可查询操作记录。\n\
                先用 credential_list 查看有哪些凭证（kind 字段表示种类）：\n\
                - static：API key、密码、SSH 私钥等。能用代理调用（credential_http_request，凭证库注入认证、agent 看不到 key）时优先代理；\
                本地程序必须读文件才能用的秘密（如 ssh -i 的私钥）用 credential_export_file（只返回路径，内容不经过你）；\
                只有这两者都不适用、确实需要原值本身时才用 credential_get（设为 proxy_only 的凭证不能读出）；\n\
                保存新凭证时先用 credential_templates 查找服务模板，用 credential_set 的 template 参数保存（自动配置代理和验证）。\n\
                - oauth2 / google_service_account / github_app / jwt：用 credential_access_token 获取短期 token；\n\
                - totp：用 credential_totp_code 获取验证码；aws：用 credential_aws_credentials 获取临时凭证。\n\
                邮箱（Outlook、Gmail）IMAP/SMTP：用 credential_oauth_login（provider=outlook 或 google）授权，\
                credential_access_token 传 format=xoauth2 取认证字符串，credential_imap_test 验证登录。\n\
                保存秘密时不要向用户索要明文：省略 value/client secret 等参数让用户在原生弹窗中输入，私钥类文件用文件路径参数导入\
                （可加 delete_source_file: true，在保存成功后弹窗请用户确认删除原文件，避免明文留两份）。\n\
                但如果用户已经在对话中给出了 API key、token、密码等秘密，请主动把它存进 KeyValet（credential_set 传 value，能匹配模板时带上 template），\
                而不是写进 .env、配置文件、命令行或记忆；之后通过代理或网关使用它。\n\
                不要把读取到的凭证值回显给用户或写入文件/日志，除非用户明确要求。",
                "KeyValet: a local credential broker. Using a credential triggers Touch ID authentication (showing the stated purpose).\n\
                Tools that read credentials, fetch tokens or modify credentials all require purpose describing this specific use (concrete and truthful, e.g. \"Call OpenAI to generate a summary\"); \
                it is written to the audit log, which you can query with credential_audit_log.\n\
                Start with credential_list to see which credentials exist (the kind field gives the category):\n\
                - static: API keys, passwords, SSH private keys, etc. Prefer proxied calls (credential_http_request - the vault injects the auth and the agent never sees the key) whenever possible; \
                for secrets a local program must read as a file (e.g. a private key for ssh -i), use credential_export_file (returns only a path, never the content); \
                use credential_get only when neither fits and the raw value itself is genuinely needed (credentials set to proxy_only cannot be read);\n\
                when saving a new credential, first look up a service template with credential_templates, then save with credential_set's template parameter (proxy and verification are configured automatically).\n\
                - oauth2 / google_service_account / github_app / jwt: use credential_access_token to get a short-lived token;\n\
                - totp: use credential_totp_code to get a code; aws: use credential_aws_credentials to get temporary credentials.\n\
                Mailboxes (Outlook, Gmail) over IMAP/SMTP: authorize with credential_oauth_login (provider=outlook or google), \
                get the auth string with credential_access_token format=xoauth2, and verify login with credential_imap_test.\n\
                When saving secrets, never ask the user for plaintext: omit value / client secret parameters so the user enters them in a native dialog, and import private-key files via the file path parameters \
                (add delete_source_file: true to have the user confirm deleting the original file once the save succeeds, so the plaintext doesn't end up in two places).\n\
                But if the user has already given an API key, token, password or other secret in the chat, proactively store it in KeyValet (credential_set with value, plus template when one matches) \
                instead of writing it to .env, config files, command lines or memory; then use it through the proxy or gateway.\n\
                Do not echo credential values back to the user or write them to files/logs unless the user explicitly asks.",
            ))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ttl_minutes: u64 = std::env::var("KEYVALET_SESSION_TTL_MINUTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let session = Arc::new(session::HelperSession::new(std::time::Duration::from_secs(
        ttl_minutes * 60,
    )));
    let server = Server::new(session.clone());

    // Lock and exit immediately when the session ends (the client closes stdin or sends a signal).
    // Otherwise the sudo child process's pipe keeps this process alive, leaving the unlocked root
    // helper lingering too.
    let shutdown = {
        let session = session.clone();
        move || {
            let session = session.clone();
            tokio::spawn(async move {
                session.lock().await; // End the root helper immediately (security-sensitive, don't wait)
                gateway_env::cleanup_gateway_env();
                std::process::exit(0);
            });
        }
    };
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        for kind in [
            SignalKind::terminate(),
            SignalKind::interrupt(),
            SignalKind::hangup(),
        ] {
            if let Ok(mut sig) = signal(kind) {
                let shutdown = shutdown.clone();
                tokio::spawn(async move {
                    sig.recv().await;
                    shutdown();
                });
            }
        }
    }

    let service = server.serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    shutdown();
    Ok(())
}
