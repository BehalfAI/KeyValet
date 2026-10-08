//! Direct port of src/server/tools/mail.ts.

use super::common::{fail, ok_data, purpose_desc, resolve_type, wrap};
use crate::mail::{graph_mail_test, imap_xoauth2_test, GraphMailOpts, ImapTestOpts, IMAP_HOSTS};
use crate::server::Server;
use crate::session::CredentialTarget;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::tool;
use rmcp::tool_router;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Map};

#[derive(Deserialize, JsonSchema)]
pub struct ImapTestArgs {
    #[schemars(description = purpose_desc())]
    pub purpose: String,
    #[schemars(description = kv_i18n::t("oauth2 凭证名", "Name of the oauth2 credential"))]
    pub name: String,
    #[schemars(description = kv_i18n::t("凭证类型；省略时按名字自动查找", "Credential type; looked up by name if omitted"))]
    pub r#type: Option<String>,
    #[schemars(description = kv_i18n::t("IMAP 服务器；省略则按 provider 选择", "IMAP server; chosen from the provider if omitted"))]
    pub host: Option<String>,
    #[schemars(description = kv_i18n::t("默认 993（TLS）", "Defaults to 993 (TLS)"))]
    pub port: Option<u16>,
    #[schemars(description = kv_i18n::t("邮箱地址；省略则使用授权时识别出的账号", "Email address; defaults to the account identified during authorization"))]
    pub username: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct GraphMailArgs {
    #[schemars(description = purpose_desc())]
    pub purpose: String,
    #[schemars(description = kv_i18n::t("oauth2 凭证名（provider=outlook_graph 或 microsoft，scope 含 Mail.Read）", "Name of the oauth2 credential (provider=outlook_graph or microsoft, scope includes Mail.Read)"))]
    pub name: String,
    #[schemars(description = kv_i18n::t("凭证类型；省略时按名字自动查找", "Credential type; looked up by name if omitted"))]
    pub r#type: Option<String>,
    #[schemars(description = kv_i18n::t("邮件夹，默认 inbox；也可用 junkemail、sentitems 等或文件夹 ID", "Mail folder, default inbox; also junkemail, sentitems, etc., or a folder ID"))]
    pub folder: Option<String>,
    #[schemars(description = kv_i18n::t("列出最近几封，默认 5，最多 20", "Number of recent messages to list, default 5, max 20"))]
    pub top: Option<u32>,
}

#[tool_router(router = mail_tool_router, vis = "pub")]
impl Server {
    #[tool(description = kv_i18n::t(
        "用 oauth2 凭证通过 XOAUTH2 登录 IMAP，只读打开收件箱（EXAMINE，不改变任何邮件状态）后退出，用于验证邮箱授权是否可用。Outlook/Microsoft 默认 outlook.office365.com，Google 默认 imap.gmail.com。不会返回 token。",
        "Log in to IMAP via XOAUTH2 using an oauth2 credential, open the inbox read-only (EXAMINE; no message state is changed), then log out. Use it to verify that mailbox authorization works. Defaults: outlook.office365.com for Outlook/Microsoft, imap.gmail.com for Google. Never returns the token.",
    ), annotations(read_only_hint = true, open_world_hint = true))]
    async fn credential_imap_test(
        &self,
        Parameters(a): Parameters<ImapTestArgs>,
    ) -> CallToolResult {
        wrap(async {
            let target = CredentialTarget { r#type: a.r#type.clone(), name: Some(a.name.clone()) };
            let s = self.session.scoped(a.purpose, Some(target));
            let ty = resolve_type(&s, &a.name, a.r#type.as_deref(), &["oauth2"]).await?;
            let mut p = Map::new();
            p.insert("type".into(), json!(ty));
            p.insert("name".into(), json!(a.name));
            #[derive(Deserialize)]
            struct Info {
                config: InfoConfig,
            }
            #[derive(Deserialize)]
            struct InfoConfig {
                provider: String,
            }
            let info: Info = s.request("info", p.clone()).await?;
            let host = a.host.clone().or_else(|| IMAP_HOSTS.get(info.config.provider.as_str()).map(|h| h.to_string()));
            let Some(host) = host else {
                return Err(kv_i18n::t(&format!("provider \"{}\" 没有默认 IMAP 服务器，请指定 host。", info.config.provider), &format!("Provider \"{}\" has no default IMAP server; please specify host.", info.config.provider)));
            };
            if !host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-')) {
                return Err(kv_i18n::t("host 格式不对", "Invalid host format"));
            }
            #[derive(Deserialize)]
            struct Tok {
                access_token: String,
                account: Option<String>,
                scope: Option<String>,
            }
            let tok: Tok = s.request("accessToken", p).await?;
            let Some(username) = a.username.clone().or_else(|| tok.account.clone()) else {
                return Err(kv_i18n::t("无法确定邮箱地址：请传 username，或在授权 scope 中包含 openid email。", "Cannot determine the email address: pass username, or include openid email in the authorization scopes."));
            };
            let r = imap_xoauth2_test(ImapTestOpts { host: &host, port: a.port, username: &username, access_token: &tok.access_token, timeout: std::time::Duration::from_secs(20) }).await?;
            if r.authenticated {
                return Ok(ok_data(kv_i18n::t(&format!("IMAP 登录成功（{username} @ {host}）。"), &format!("IMAP login succeeded ({username} @ {host})."), ), r));
            }

            let mut hints: Vec<String> = Vec::new();
            let scope = tok.scope.unwrap_or_default();
            let server_error = r.server_error.clone().unwrap_or_default();
            if server_error.to_lowercase().contains("authenticated but not connected") {
                hints.push(kv_i18n::t("token 有效且认证已通过，但服务器无法连接到该用户名对应的邮箱", "The token is valid and authentication succeeded, but the server could not connect to the mailbox for this username"));
                hints.push(kv_i18n::t(
                    "个人账号（outlook.com/hotmail/live/msn 等）：这是微软服务端自 2024 年 12 月起的已知 bug，尚无修复（https://learn.microsoft.com/en-us/answers/questions/5673167）。请改用 Microsoft Graph：credential_oauth_login 使用 provider=outlook_graph（同一个 client_id / tenant / redirect_uri，另起一个凭证名），再用 credential_graph_mail_test 验证",
                    "Personal accounts (outlook.com/hotmail/live/msn, etc.): this is a known Microsoft server-side bug since December 2024 with no fix yet (https://learn.microsoft.com/en-us/answers/questions/5673167). Use Microsoft Graph instead: run credential_oauth_login with provider=outlook_graph (same client_id / tenant / redirect_uri, under a new credential name), then verify with credential_graph_mail_test",
                ));
                hints.push(kv_i18n::t("企业账号：username 须为邮箱的主地址，且管理员需为该邮箱启用 IMAP", "Work/school accounts: username must be the mailbox's primary address, and an admin must enable IMAP for the mailbox"));
            } else if matches!(info.config.provider.as_str(), "outlook" | "microsoft") {
                if !scope.to_lowercase().contains("imap.accessasuser.all") {
                    hints.push(kv_i18n::t("token 的 scope 中没有 IMAP.AccessAsUser.All：用 scopes 包含 https://outlook.office.com/IMAP.AccessAsUser.All 重新授权", "The token scope lacks IMAP.AccessAsUser.All: re-authorize with scopes including https://outlook.office.com/IMAP.AccessAsUser.All"));
                }
                hints.push(kv_i18n::t("个人账号（outlook.com/hotmail/live/msn）：tenant 应为 consumers 或 common（不能用目录租户 ID），应用的受支持账户类型须包含个人 Microsoft 账户", "Personal accounts (outlook.com/hotmail/live/msn): tenant must be consumers or common (not a directory tenant ID), and the app's supported account types must include personal Microsoft accounts"));
                hints.push(kv_i18n::t("确认 username 与登录授权的账号一致", "Make sure username matches the account that granted authorization"));
                hints.push(kv_i18n::t("个人账号需在 Outlook.com 设置 → 邮件 → 转发和 IMAP 中启用 IMAP；企业账号需管理员为该邮箱启用 IMAP", "Personal accounts must enable IMAP in Outlook.com Settings → Mail → Forwarding and IMAP; for work/school accounts an admin must enable IMAP for the mailbox"));
            } else if info.config.provider == "google" && !scope.contains("https://mail.google.com/") {
                hints.push(kv_i18n::t("Gmail IMAP 需要 scope https://mail.google.com/", "Gmail IMAP requires the scope https://mail.google.com/"));
            }
            let body = serde_json::to_string_pretty(&r).unwrap_or_default();
            let hint_block = if hints.is_empty() { String::new() } else { kv_i18n::t(&format!("\n\n可能的原因：\n- {}", hints.join("\n- ")), &format!("\n\nPossible causes:\n- {}", hints.join("\n- "))) };
            Ok(fail(kv_i18n::t(&format!("IMAP 登录失败。\n{body}{hint_block}"), &format!("IMAP login failed.\n{body}{hint_block}"))))
        })
        .await
    }

    #[tool(description = kv_i18n::t(
        "用 oauth2 凭证（Microsoft Graph，scope 含 Mail.Read）只读查看邮件夹：邮件总数、未读数和最近几封的时间/发件人/标题，用于验证 Outlook / Microsoft 365 邮箱授权是否可用。不改变任何邮件状态，不返回 token。",
        "Read a mail folder read-only using an oauth2 credential (Microsoft Graph, scope includes Mail.Read): total and unread counts plus the time/sender/subject of the most recent messages. Use it to verify that Outlook / Microsoft 365 mailbox authorization works. Changes no message state and never returns the token.",
    ), annotations(read_only_hint = true, open_world_hint = true))]
    async fn credential_graph_mail_test(
        &self,
        Parameters(a): Parameters<GraphMailArgs>,
    ) -> CallToolResult {
        wrap(async {
            if let Some(f) = &a.folder {
                if !f.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '=' | '-')) || f.is_empty() || f.len() > 300 {
                    return Ok(fail(kv_i18n::t("folder 格式不对", "Invalid folder format")));
                }
            }
            let target = CredentialTarget { r#type: a.r#type.clone(), name: Some(a.name.clone()) };
            let s = self.session.scoped(a.purpose, Some(target));
            let ty = resolve_type(&s, &a.name, a.r#type.as_deref(), &["oauth2"]).await?;
            let mut p = Map::new();
            p.insert("type".into(), json!(ty));
            p.insert("name".into(), json!(a.name));
            #[derive(Deserialize)]
            struct Tok {
                access_token: String,
                scope: Option<String>,
            }
            let tok: Tok = s.request("accessToken", p).await?;
            let r = graph_mail_test(GraphMailOpts { access_token: &tok.access_token, folder: a.folder.as_deref(), top: a.top, base_url: None }).await?;
            if r.ok {
                return Ok(ok_data(kv_i18n::t(&format!("Graph 读取成功（{}：共 {} 封，未读 {} 封）。", r.folder.clone().unwrap_or_default(), r.total.unwrap_or(0), r.unread.unwrap_or(0)), &format!("Graph read succeeded ({}: {} messages, {} unread).", r.folder.clone().unwrap_or_default(), r.total.unwrap_or(0), r.unread.unwrap_or(0))), r));
            }
            let mut hints = Vec::new();
            let scope = tok.scope.unwrap_or_default();
            if !scope.to_lowercase().contains("mail.read") {
                hints.push(kv_i18n::t("token 的 scope 中没有 Mail.Read：这个凭证可能是为其他服务（如 IMAP）授权的；请用 provider=outlook_graph 另建凭证授权", "The token scope lacks Mail.Read: this credential may have been authorized for another service (e.g. IMAP); create a new credential with provider=outlook_graph"));
            }
            if r.http_status == Some(401) {
                hints.push(kv_i18n::t("token 被拒绝：可尝试 credential_access_token(force_refresh=true) 后重试，或重新授权", "Token rejected: try credential_access_token(force_refresh=true) and retry, or re-authorize"));
            }
            if r.http_status == Some(403) {
                hints.push(kv_i18n::t("权限不足：确认授权时同意了「读取你的邮件」，必要时在 Azure 应用的 API 权限中添加 Microsoft Graph → Mail.Read", "Insufficient permissions: make sure \"Read your mail\" was consented during authorization; if needed, add Microsoft Graph → Mail.Read to the Azure app's API permissions"));
            }
            let body = serde_json::to_string_pretty(&r).unwrap_or_default();
            let hint_block = if hints.is_empty() { String::new() } else { kv_i18n::t(&format!("\n\n可能的原因：\n- {}", hints.join("\n- ")), &format!("\n\nPossible causes:\n- {}", hints.join("\n- "))) };
            Ok(fail(kv_i18n::t(&format!("Graph 读取失败。\n{body}{hint_block}"), &format!("Graph read failed.\n{body}{hint_block}"))))
        })
        .await
    }
}
