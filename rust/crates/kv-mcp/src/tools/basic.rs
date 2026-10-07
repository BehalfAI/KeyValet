//! Direct port of src/server/tools/basic.ts.

use super::common::{
    fail, name_field_desc, norm, ok, ok_data, optional_purpose_desc, purpose_desc, resolve_type,
    type_field_desc, wrap,
};
use crate::gateway_env::{record_secrets, write_secret_file};
use crate::server::Server;
use crate::session::CredentialTarget;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::tool;
use rmcp::tool_router;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Map, Value};

#[derive(Deserialize, JsonSchema)]
pub struct UnlockArgs {
    #[schemars(description = purpose_desc())]
    pub purpose: String,
    /// Name of the credential to grant use of.
    #[schemars(description = kv_i18n::t("要授权使用的凭证名", "Name of the credential to grant use of"))]
    pub name: Option<String>,
    #[schemars(description = kv_i18n::t("凭证类型；省略时按名字查找", "Credential type; looked up by name if omitted"))]
    pub r#type: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct LockArgs {
    #[schemars(description = kv_i18n::t("同时清除\u{201c}记住\u{201d}状态", "Also clear the remembered authorization"))]
    pub forget: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct ListTypesArgs {
    #[schemars(description = optional_purpose_desc())]
    pub purpose: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct CreateTypeArgs {
    #[schemars(description = type_field_desc())]
    pub name: String,
    #[schemars(description = kv_i18n::t("类型说明", "Type description"))]
    pub description: Option<String>,
    #[schemars(description = purpose_desc())]
    pub purpose: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct ListArgs {
    #[schemars(description = kv_i18n::t("只列出该类型；省略则列出全部", "Only list this type; lists all if omitted"))]
    pub r#type: Option<String>,
    #[schemars(description = optional_purpose_desc())]
    pub purpose: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct GetArgs {
    #[schemars(description = type_field_desc())]
    pub r#type: String,
    #[schemars(description = name_field_desc())]
    pub name: String,
    #[schemars(description = purpose_desc())]
    pub purpose: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct ExportFileArgs {
    #[schemars(description = kv_i18n::t("凭证类型；省略时按名字在 static 凭证中查找", "Credential type; looked up among static credentials by name if omitted"))]
    pub r#type: Option<String>,
    #[schemars(description = name_field_desc())]
    pub name: String,
    #[schemars(description = kv_i18n::t("多秘密字段的模板凭证：要导出的字段名；省略则导出主值（value）", "For template credentials with multiple secret fields: which field to export; omitted exports the main value"))]
    pub field: Option<String>,
    #[schemars(description = purpose_desc())]
    pub purpose: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct SetArgs {
    #[schemars(description = kv_i18n::t("凭证类型（不存在时自动创建）；使用模板时可省略，按模板命名", "Credential type (created if missing); optional with template, defaults to a name derived from the template"))]
    pub r#type: Option<String>,
    #[schemars(description = name_field_desc())]
    pub name: String,
    #[schemars(description = kv_i18n::t("模板 id，如 openai、anthropic、github、bearer、header、basic", "Template id, e.g. openai, anthropic, github, bearer, header, basic"))]
    pub template: Option<String>,
    #[schemars(description = kv_i18n::t("仅模板：非敏感字段的值（如 Base URL、子域名）；秘密字段不要放这里", "Template only: values for non-sensitive fields (e.g. base URL, subdomain); never put secret fields here"))]
    pub fields: Option<Map<String, Value>>,
    #[schemars(description = kv_i18n::t("仅模板：要输入的秘密字段（默认为必填的和注入需要的）", "Template only: secret fields to prompt for (default: required ones and those used by injection)"))]
    pub secret_fields: Option<Vec<String>>,
    #[schemars(description = kv_i18n::t("仅模板：代理允许的域名（默认按模板计算）", "Template only: hosts the proxy may send to (default: derived from the template)"))]
    pub allowed_hosts: Option<Vec<String>>,
    #[schemars(description = kv_i18n::t("仅模板：只能代理调用，禁止 credential_get 读出原值", "Template only: proxy-only - credential_get cannot read the raw value"))]
    pub proxy_only: Option<bool>,
    #[schemars(description = kv_i18n::t("仅模板：保存后立即验证（默认 true）", "Template only: verify right after saving (default true)"))]
    pub verify: Option<bool>,
    #[schemars(description = kv_i18n::t("凭证值；省略则由用户在弹窗中输入。用户已在对话中给出密钥时直接传入（配合模板时，模板须只有一个秘密字段）", "Credential value; if omitted, the user enters it in a dialog. Pass it when the user already gave the secret in the chat (with a template, the template must have a single secret field)"))]
    pub value: Option<String>,
    #[schemars(description = kv_i18n::t("从该文件读取凭证值（内容不会进入 AI 上下文），如 ~/.ssh/id_ed25519", "Read the credential value from this file (content never enters the AI context), e.g. ~/.ssh/id_ed25519"))]
    pub value_file: Option<String>,
    #[schemars(description = kv_i18n::t("配合 value_file：保存成功后删除原文件（会弹窗请用户单独确认，不可恢复）。默认 false，即原文件原样保留", "With value_file: delete the original file after a successful save (the user is asked to confirm separately; cannot be undone). Default false - the original file is left in place"))]
    pub delete_source_file: Option<bool>,
    #[schemars(description = kv_i18n::t("凭证说明，例如用途", "Credential description, e.g. what it is used for"))]
    pub description: Option<String>,
    #[schemars(description = kv_i18n::t("非敏感附加信息，如 {\"username\": \"...\", \"url\": \"...\"}；不要把秘密放在这里", "Non-sensitive extra info, e.g. {\"username\": \"...\", \"url\": \"...\"}; never put secrets here"))]
    pub attributes: Option<Map<String, Value>>,
    #[schemars(description = kv_i18n::t("类型不存在需要新建时，类型的说明", "Description for the type, if it has to be created"))]
    pub type_description: Option<String>,
    #[schemars(description = kv_i18n::t("已存在时是否覆盖，默认 false", "Overwrite if it already exists (default false)"))]
    pub overwrite: Option<bool>,
    #[schemars(description = purpose_desc())]
    pub purpose: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct DeleteArgs {
    #[schemars(description = type_field_desc())]
    pub r#type: String,
    #[schemars(description = name_field_desc())]
    pub name: String,
    #[schemars(description = purpose_desc())]
    pub purpose: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct DeleteTypeArgs {
    #[schemars(description = type_field_desc())]
    pub name: String,
    #[schemars(description = purpose_desc())]
    pub purpose: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct AuditLogArgs {
    #[schemars(description = kv_i18n::t("只看本会话的记录", "Only entries from this session"))]
    pub this_session_only: Option<bool>,
    #[schemars(description = kv_i18n::t("指定会话 ID", "Filter by session ID"))]
    pub session: Option<String>,
    #[schemars(description = kv_i18n::t("凭证类型", "Credential type"))]
    pub r#type: Option<String>,
    #[schemars(description = kv_i18n::t("凭证名", "Credential name"))]
    pub name: Option<String>,
    #[schemars(description = kv_i18n::t("操作，如 unlock、get、accessToken、set、delete", "Operation, e.g. unlock, get, accessToken, set, delete"))]
    pub op: Option<String>,
    #[schemars(description = kv_i18n::t("起始时间（ISO 8601），如 2026-10-06T00:00:00Z", "Start time (ISO 8601), e.g. 2026-10-06T00:00:00Z"))]
    pub since: Option<String>,
    #[schemars(description = kv_i18n::t("最多返回条数，默认 50，最多 500", "Maximum entries to return (default 50, max 500)"))]
    pub limit: Option<i64>,
    #[schemars(description = optional_purpose_desc())]
    pub purpose: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct SettingsArgs {
    #[schemars(description = kv_i18n::t("省略则只查看（all 等同 per_session）", "Omit to only view (all = per_session)"))]
    pub grant_mode: Option<String>,
    #[schemars(description = kv_i18n::t("remember 模式的时长（小时），0 表示永久", "Duration for remember mode in hours; 0 = forever"))]
    pub remember_hours: Option<f64>,
    #[schemars(description = kv_i18n::t("清除当前的\u{201c}记住\u{201d}状态", "Clear the current remembered authorization"))]
    pub forget: Option<bool>,
    #[schemars(description = optional_purpose_desc())]
    pub purpose: Option<String>,
}

#[tool_router(router = basic_tool_router, vis = "pub")]
impl Server {
    #[tool(description = kv_i18n::t(
        "查看凭证库在本 session 中是否已解锁、授权模式、本会话已授权的凭证（不会触发认证）",
        "Show whether the vault is unlocked for this session, the grant mode, and which credentials this session has been granted (does not trigger authentication)",
    ))]
    async fn credential_status(&self) -> CallToolResult {
        wrap(async {
            let st = self.session.status().await;
            let grants = if st.get("state").and_then(Value::as_str) == Some("unlocked") {
                self.session
                    .scoped("status", None)
                    .request::<Value>("sessionInfo", Map::new())
                    .await
                    .ok()
            } else {
                None
            };
            let mut merged = st.as_object().cloned().unwrap_or_default();
            if let Some(g) = grants.and_then(|g| g.as_object().cloned()) {
                merged.insert("grants".into(), Value::Object(g));
            }
            Ok(ok_data(
                kv_i18n::t("状态：", "Status:"),
                Value::Object(merged),
            ))
        })
        .await
    }

    #[tool(description = kv_i18n::t(
        "弹出 Touch ID 认证（显示目的），通过后解锁凭证库。授权模式为 per_credential（默认）时，传 name 可同时授权使用该凭证；使用其他凭证时会再次弹 Touch ID。模式为 all 时一次解锁全部。其他工具在需要时也会自动触发认证。",
        "Show a Touch ID prompt (displaying the purpose) and unlock the vault once approved. In per_credential grant mode (default), pass name to also grant use of that credential; using other credentials will prompt Touch ID again. In all mode, one unlock grants everything. Other tools also trigger authentication automatically when needed.",
    ))]
    async fn credential_unlock(&self, Parameters(a): Parameters<UnlockArgs>) -> CallToolResult {
        wrap(async {
            let target = a.name.as_ref().map(|n| CredentialTarget {
                r#type: a.r#type.clone(),
                name: Some(n.clone()),
            });
            self.session.unlock(&a.purpose, target.as_ref()).await?;
            if let Some(name) = &a.name {
                let s = self.session.scoped(a.purpose.clone(), target.clone());
                let resolved_type = resolve_type(
                    &s,
                    name,
                    a.r#type.as_deref(),
                    &[
                        "static",
                        "oauth2",
                        "google_service_account",
                        "github_app",
                        "jwt",
                        "totp",
                        "aws",
                    ],
                )
                .await?;
                self.session
                    .grant(&resolved_type, &norm(name), &a.purpose)
                    .await?;
            }
            let info: Value = self
                .session
                .scoped(a.purpose.clone(), None)
                .request("sessionInfo", Map::new())
                .await?;
            let mut data = Map::new();
            data.insert(
                "session".into(),
                Value::String(self.session.session_id.clone()),
            );
            if let Some(obj) = info.as_object() {
                data.extend(obj.clone());
            }
            Ok(ok_data(
                kv_i18n::t("凭证库已解锁。", "Vault unlocked."),
                Value::Object(data),
            ))
        })
        .await
    }

    #[tool(description = kv_i18n::t(
        "立即锁定凭证库，之后再访问需要重新通过 Touch ID 认证。remember 模式下传 forget=true 同时清除\u{201c}记住\u{201d}状态（否则下次访问会自动解锁）。",
        "Lock the vault now; further access requires Touch ID again. In remember mode pass forget=true to also clear the remembered authorization (otherwise the next access unlocks automatically).",
    ))]
    async fn credential_lock(&self, Parameters(a): Parameters<LockArgs>) -> CallToolResult {
        wrap(async {
            if a.forget == Some(true) {
                let purpose = kv_i18n::t("锁定并清除记住状态", "Lock and forget");
                let mut p = Map::new();
                p.insert("forget".into(), json!(true));
                p.insert("purpose".into(), json!(purpose));
                self.session
                    .scoped(purpose, None)
                    .request::<Value>("settings", p)
                    .await?;
            }
            self.session.lock().await;
            Ok(ok(if a.forget == Some(true) {
                kv_i18n::t(
                    "凭证库已锁定，\u{201c}记住\u{201d}状态已清除。",
                    "Vault locked and remembered authorization cleared.",
                )
            } else {
                kv_i18n::t("凭证库已锁定。", "Vault locked.")
            }))
        })
        .await
    }

    #[tool(description = kv_i18n::t("列出所有凭证类型及每种类型下的凭证数量", "List all credential types and the number of credentials of each type"))]
    async fn credential_list_types(
        &self,
        Parameters(a): Parameters<ListTypesArgs>,
    ) -> CallToolResult {
        wrap(async {
            let purpose = a
                .purpose
                .unwrap_or_else(|| kv_i18n::t("查看凭证类型", "List credential types"));
            let r: Value = self
                .session
                .scoped(purpose, None)
                .request("listTypes", Map::new())
                .await?;
            Ok(ok_data(kv_i18n::t("凭证类型：", "Credential types:"), r))
        })
        .await
    }

    #[tool(description = kv_i18n::t(
        "创建凭证类型（已存在则不做任何事）。一般不需要手动调用，写入凭证时会自动创建缺失的类型。",
        "Create a credential type (no-op if it already exists). Usually unnecessary: missing types are created automatically when a credential is saved.",
    ))]
    async fn credential_create_type(
        &self,
        Parameters(a): Parameters<CreateTypeArgs>,
    ) -> CallToolResult {
        wrap(async {
            let mut p = Map::new();
            p.insert("name".into(), json!(a.name));
            p.insert("description".into(), json!(a.description));
            #[derive(Deserialize)]
            struct R {
                name: String,
                created: bool,
            }
            let r: R = self
                .session
                .scoped(a.purpose, None)
                .request("createType", p)
                .await?;
            Ok(ok(if r.created {
                kv_i18n::t(
                    &format!("已创建凭证类型 \"{}\"。", r.name),
                    &format!("Created credential type \"{}\".", r.name),
                )
            } else {
                kv_i18n::t(
                    &format!("凭证类型 \"{}\" 已存在。", r.name),
                    &format!("Credential type \"{}\" already exists.", r.name),
                )
            }))
        })
        .await
    }

    #[tool(description = kv_i18n::t(
        "列出凭证（类型、名称、kind、说明和非敏感属性，不含凭证值）。kind 不是 static 的是协议凭证，需用对应工具取 token。",
        "List credentials (type, name, kind, description and non-sensitive attributes; no secret values). Credentials whose kind is not static are protocol credentials; use the matching tool to obtain tokens.",
    ))]
    async fn credential_list(&self, Parameters(a): Parameters<ListArgs>) -> CallToolResult {
        wrap(async {
            let purpose = a
                .purpose
                .unwrap_or_else(|| kv_i18n::t("查看凭证列表", "List credentials"));
            let mut p = Map::new();
            p.insert("type".into(), json!(a.r#type));
            let r: Value = self
                .session
                .scoped(purpose, None)
                .request("list", p)
                .await?;
            Ok(ok_data(kv_i18n::t("凭证列表：", "Credentials:"), r))
        })
        .await
    }

    #[tool(description = kv_i18n::t(
        "读取一个凭证。static 凭证返回值及说明、非敏感属性；协议凭证（oauth2、google_service_account、github_app、jwt、totp、aws）只返回配置和状态，长期秘密不会返回，请用 credential_access_token / credential_totp_code / credential_aws_credentials 获取短期凭证。",
        "Read a credential. For static credentials, returns the value, description and non-sensitive attributes; for protocol credentials (oauth2, google_service_account, github_app, jwt, totp, aws), returns only configuration and status (long-lived secrets are never returned) - use credential_access_token / credential_totp_code / credential_aws_credentials to obtain short-lived credentials.",
    ))]
    async fn credential_get(&self, Parameters(a): Parameters<GetArgs>) -> CallToolResult {
        wrap(async {
            let target = CredentialTarget {
                r#type: Some(a.r#type.clone()),
                name: Some(a.name.clone()),
            };
            let mut p = Map::new();
            p.insert("type".into(), json!(a.r#type));
            p.insert("name".into(), json!(a.name));
            #[derive(Deserialize)]
            struct R {
                value: Option<String>,
                fields: Option<std::collections::HashMap<String, String>>,
            }
            let r: R = self
                .session
                .scoped(a.purpose, Some(target))
                .request("get", p)
                .await?;
            let mut secrets: Vec<Option<String>> = vec![r.value.clone()];
            secrets.extend(r.fields.clone().unwrap_or_default().into_values().map(Some));
            record_secrets(&self.session.session_id, secrets);
            Ok(ok_data(
                kv_i18n::t("凭证：", "Credential:"),
                json!({"value": r.value, "fields": r.fields}),
            ))
        })
        .await
    }

    #[tool(description = kv_i18n::t(
        "把一个 static 凭证的原始值写入只有你本人账户可读的私有临时文件（~/.keyvalet/run，0600），只把文件路径返回给 AI，内容本身不经过 AI 上下文。用于必须读本地文件才能工作的场景，典型例子是 SSH 私钥（配合 ssh -i <路径> 使用）、证书等。能走代理时优先用 credential_http_request / credential_gateway；只有代理不适用、又必须落地成文件时才用这个——不要先 credential_get 拿到值再自己写文件，那样秘密会先经过 AI 上下文。文件在本会话结束时自动删除。",
        "Write a static credential's raw value to a private temp file readable only by your own account (~/.keyvalet/run, 0600); only the file path is returned, never the content. For cases where a program must read a local file to work - the typical examples are SSH private keys (used with ssh -i <path>) and certificates. Prefer the proxy (credential_http_request / credential_gateway) when it applies; use this only when the proxy doesn't fit and the secret must land on disk as a file - don't call credential_get and write the file yourself, since that routes the secret through the AI context first. The file is deleted automatically when this session ends.",
    ))]
    async fn credential_export_file(
        &self,
        Parameters(a): Parameters<ExportFileArgs>,
    ) -> CallToolResult {
        wrap(async {
            let target = CredentialTarget { r#type: a.r#type.clone(), name: Some(a.name.clone()) };
            let s = self.session.scoped(a.purpose.clone(), Some(target));
            let resolved_type = resolve_type(&s, &a.name, a.r#type.as_deref(), &["static"]).await?;
            let mut p = Map::new();
            p.insert("type".into(), json!(resolved_type));
            p.insert("name".into(), json!(a.name));
            #[derive(Deserialize)]
            struct R {
                r#type: String,
                name: String,
                value: Option<String>,
                fields: Option<std::collections::HashMap<String, String>>,
            }
            let r: R = s.request("get", p).await?;
            if r.value.is_none() {
                return Ok(fail(kv_i18n::t(&format!("凭证 \"{}/{}\" 不是 static 凭证，没有可导出的原始值。", r.r#type, r.name), &format!("Credential \"{}/{}\" is not a static credential; it has no raw value to export.", r.r#type, r.name))));
            }
            let secret = match &a.field {
                Some(f) => r.fields.as_ref().and_then(|m| m.get(f)).cloned(),
                None => r.value.clone().filter(|v| !v.is_empty()),
            };
            let Some(secret) = secret else {
                let available = r.fields.clone().unwrap_or_default().into_keys().collect::<Vec<_>>().join(&kv_i18n::t("、", ", "));
                let available = if available.is_empty() { kv_i18n::t("无", "none") } else { available };
                return Ok(fail(match &a.field {
                    Some(f) => kv_i18n::t(&format!("凭证 \"{}/{}\" 没有字段 \"{f}\"（可用：{available}）", r.r#type, r.name), &format!("Credential \"{}/{}\" has no field \"{f}\" (available: {available})", r.r#type, r.name)),
                    None => kv_i18n::t(&format!("凭证 \"{}/{}\" 没有主值，请传 field 指定具体字段（可用：{available}）", r.r#type, r.name), &format!("Credential \"{}/{}\" has no main value; pass field to select one (available: {available})", r.r#type, r.name)),
                }));
            };
            let path = write_secret_file(&self.session.session_id, &r.r#type, &r.name, a.field.as_deref(), &secret).map_err(|e| e.to_string())?;
            Ok(ok_data(
                kv_i18n::t("已写入私有文件（内容未返回给我）：", "Written to a private file (content not returned to me):"),
                json!({
                    "path": path.display().to_string(),
                    "note": kv_i18n::t(
                        "只有你本人账户可读；本会话结束时自动删除，提前用完也可以自己删掉。不要让我读取或打印它的内容，直接把这个路径传给需要文件的命令（如 ssh -i）。",
                        "Readable only by your own account; deleted automatically when this session ends, or delete it yourself once done. Don't have me read or print its contents - pass this path directly to the command that needs a file (e.g. ssh -i).",
                    ),
                }),
            ))
        })
        .await
    }

    #[tool(description = kv_i18n::t(
        "保存 static 凭证（API key、密码、token、SSH 私钥等）。会先检查凭证类型是否存在，不存在则先创建该类型，再写入值。推荐传 template（用 credential_templates 搜索，如 openai、anthropic、github，或通用的 bearer / header / query / basic）：按模板逐个弹窗输入秘密字段，并自动配置代理调用（credential_http_request）和验证。value 和 value_file 都省略时会弹出 macOS 隐藏输入框让用户直接输入（推荐，凭证不经过 AI 上下文）；用户已在对话中给出秘密时，直接用 value 传入并主动保存。多行内容（如私钥）用 value_file 从文件导入；可加 delete_source_file: true，在保存成功后弹窗请用户确认删除原文件，避免明文留两份。覆盖已有凭证需要 overwrite=true，并且会弹窗请用户确认。之后要把 SSH 私钥这类文件型秘密用到本地程序（如 ssh -i）时，用 credential_export_file，不要用 credential_get。",
        "Save a static credential (API key, password, token, SSH private key, etc.). The credential type is created first if it does not exist. Passing template is recommended (search with credential_templates, e.g. openai, anthropic, github, or the generic bearer / header / query / basic): the user is prompted for each secret field in a dialog, and proxied calls (credential_http_request) and verification are configured automatically. If both value and value_file are omitted, a hidden macOS input dialog lets the user type the value directly (recommended - the secret never passes through the AI context); if the user already gave the secret in the chat, pass it via value and store it proactively. Import multi-line content (e.g. private keys) from a file with value_file; add delete_source_file: true to have the user confirm deleting the original file once the save succeeds, so the plaintext doesn't end up in two places. Overwriting an existing credential requires overwrite=true and the user is asked to confirm. Later, to use a file-shaped secret like an SSH private key with a local program (e.g. ssh -i), use credential_export_file, not credential_get.",
    ))]
    async fn credential_set(&self, Parameters(a): Parameters<SetArgs>) -> CallToolResult {
        wrap(super::http::credential_set_impl(self, a)).await
    }

    #[tool(description = kv_i18n::t("删除一个凭证（会弹窗请用户确认）", "Delete a credential (the user is asked to confirm)"))]
    async fn credential_delete(&self, Parameters(a): Parameters<DeleteArgs>) -> CallToolResult {
        wrap(async {
            let s = self.session.scoped(a.purpose, None);
            let mut p = Map::new();
            p.insert("type".into(), json!(a.r#type));
            p.insert("name".into(), json!(a.name));
            let exists: bool = s.request("exists", p.clone()).await?;
            let label = format!("{}/{}", norm(&a.r#type), norm(&a.name));
            if !exists {
                return Ok(fail(kv_i18n::t(
                    &format!("凭证 \"{label}\" 不存在。"),
                    &format!("Credential \"{label}\" not found."),
                )));
            }
            s.request::<Value>("delete", p).await?; // Confirmation dialog is handled by the root helper
            Ok(ok(kv_i18n::t(
                &format!("已删除凭证 \"{label}\"。"),
                &format!("Deleted credential \"{label}\"."),
            )))
        })
        .await
    }

    #[tool(description = kv_i18n::t(
        "删除一个空的凭证类型（类型下还有凭证时会失败；会弹窗请用户确认）",
        "Delete an empty credential type (fails if it still contains credentials; the user is asked to confirm)",
    ))]
    async fn credential_delete_type(
        &self,
        Parameters(a): Parameters<DeleteTypeArgs>,
    ) -> CallToolResult {
        wrap(async {
            let s = self.session.scoped(a.purpose, None);
            let label = norm(&a.name);
            #[derive(Deserialize)]
            struct TypeEntry {
                name: String,
                count: i64,
            }
            let types: Vec<TypeEntry> = s.request("listTypes", Map::new()).await?;
            let Some(entry) = types.into_iter().find(|t| t.name == label) else {
                return Ok(fail(kv_i18n::t(&format!("凭证类型 \"{label}\" 不存在。"), &format!("Credential type \"{label}\" not found."))));
            };
            if entry.count > 0 {
                return Ok(fail(kv_i18n::t(
                    &format!("凭证类型 \"{label}\" 下还有 {} 个凭证，请先删除它们。", entry.count),
                    &format!("Credential type \"{label}\" still contains {} credential(s); delete them first.", entry.count),
                )));
            }
            let message = kv_i18n::t(&format!("AI agent 请求删除凭证类型：\n\n{label}"), &format!("An AI agent wants to delete the credential type:\n\n{label}"));
            if !crate::dialog::confirm(&message, &kv_i18n::t("确认删除", "Delete")).await {
                return Ok(fail(kv_i18n::t("用户拒绝了删除操作。", "The user declined the deletion.")));
            }
            let mut p = Map::new();
            p.insert("name".into(), json!(a.name));
            s.request::<Value>("deleteType", p).await?;
            Ok(ok(kv_i18n::t(&format!("已删除凭证类型 \"{label}\"。"), &format!("Deleted credential type \"{label}\"."))))
        })
        .await
    }

    #[tool(description = kv_i18n::t(
        "查询凭证库的操作记录（最新的在前）：解锁、读取凭证、获取 token、修改/删除等，每条含时间、会话、操作、凭证、目的和结果。不含任何凭证值。可按本会话、凭证、操作、时间过滤。",
        "Query the vault's audit log (newest first): unlocks, credential reads, token requests, changes/deletions, etc. Each entry has time, session, operation, credential, purpose and result. Contains no credential values. Filter by this session, credential, operation or time.",
    ))]
    async fn credential_audit_log(
        &self,
        Parameters(a): Parameters<AuditLogArgs>,
    ) -> CallToolResult {
        wrap(async {
            let purpose = a.purpose.clone().unwrap_or_else(|| {
                kv_i18n::t("查询凭证操作记录", "Query the credential audit log")
            });
            let mut p = Map::new();
            p.insert(
                "this_session".into(),
                json!(a.this_session_only == Some(true)),
            );
            p.insert("session".into(), json!(a.session));
            p.insert("type".into(), json!(a.r#type));
            p.insert("name".into(), json!(a.name));
            p.insert("op".into(), json!(a.op));
            p.insert("since".into(), json!(a.since));
            p.insert("limit".into(), json!(a.limit));
            let r: Value = self
                .session
                .scoped(purpose, None)
                .request("auditQuery", p)
                .await?;
            Ok(ok_data(kv_i18n::t("操作记录：", "Audit log:"), r))
        })
        .await
    }

    #[tool(description = kv_i18n::t(
        "查看或修改 KeyValet 的授权模式。grant_mode：per_use（每次使用凭证都按 Touch ID）、per_credential（默认，每个会话中每个凭证按一次）、per_session（每个会话按一次）、remember（按一次后，remember_hours 小时内所有会话都不用再按；0 表示永久）。放宽（更宽松的模式或更长的记住时长）需要用户按 Touch ID；收紧立即生效。修改对当前会话也立即生效。forget=true 清除\u{201c}记住\u{201d}状态。只在用户明确要求时修改设置。",
        "View or change KeyValet's authorization mode. grant_mode: per_use (Touch ID for every use), per_credential (default; Touch ID once per credential per session), per_session (Touch ID once per session), remember (Touch ID once, then no prompts for any session for remember_hours hours; 0 = forever). Loosening (a more permissive mode or a longer remember window) requires the user's Touch ID; tightening applies immediately. Changes take effect in the current session too. forget=true clears the remembered authorization. Only change settings when the user explicitly asks.",
    ))]
    async fn credential_settings(&self, Parameters(a): Parameters<SettingsArgs>) -> CallToolResult {
        wrap(async {
            let changing =
                a.grant_mode.is_some() || a.remember_hours.is_some() || a.forget == Some(true);
            if changing && a.purpose.is_none() {
                return Ok(fail(kv_i18n::t(
                    "修改设置需要说明目的（purpose）。",
                    "Changing settings requires a purpose.",
                )));
            }
            let purpose = a
                .purpose
                .clone()
                .unwrap_or_else(|| kv_i18n::t("查看凭证库设置", "View vault settings"));
            let mut p = Map::new();
            p.insert("grant_mode".into(), json!(a.grant_mode));
            p.insert("remember_hours".into(), json!(a.remember_hours));
            p.insert("forget".into(), json!(a.forget));
            p.insert("purpose".into(), json!(a.purpose));
            let r: Value = self
                .session
                .scoped(purpose, None)
                .request("settings", p)
                .await?;
            Ok(ok_data(
                if changing {
                    kv_i18n::t("设置已更新：", "Settings updated:")
                } else {
                    kv_i18n::t("当前设置：", "Current settings:")
                },
                r,
            ))
        })
        .await
    }
}
