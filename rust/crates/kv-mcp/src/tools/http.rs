//! Direct port of src/server/tools/http.ts.

use super::common::{fail, guard_overwrite, norm, ok, ok_data, purpose_desc, resolve_type, wrap};
use crate::gateway_env::write_gateway_env;
use crate::server::Server;
use crate::session::{CredentialTarget, SessionError};
use crate::templates::{
    get_template, injected_placeholders, search_templates, summarize, template_detail,
};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::tool;
use rmcp::tool_router;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::sync::LazyLock;

const PROXY_KINDS: [&str; 5] = [
    "static",
    "oauth2",
    "google_service_account",
    "github_app",
    "jwt",
];
static HOST_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")
        .unwrap()
});

/// Template id -> default credential type name: openAiApi -> open_ai_api.
pub fn type_from_template(id: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = id.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if i > 0 && c.is_ascii_uppercase() && chars[i - 1].is_ascii_alphanumeric() {
            out.push('_');
        }
        out.push(c.to_ascii_lowercase());
    }
    let out: String = out
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let out = out.trim_start_matches(|c: char| !c.is_ascii_lowercase() && !c.is_ascii_digit());
    let out: String = out.chars().take(64).collect();
    if out.is_empty() {
        "api_key".to_string()
    } else {
        out
    }
}

/// Render the URL template with non-sensitive field values to compute its host (secret
/// placeholders in the path don't affect the host).
pub fn host_from_url_template(
    url_tpl: &str,
    attrs: &std::collections::HashMap<String, String>,
) -> Option<String> {
    const MARK: &str = "zzsecretzz";
    let re = regex::Regex::new(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}").unwrap();
    let rendered = re.replace_all(url_tpl, |caps: &regex::Captures| {
        attrs
            .get(&caps[1])
            .cloned()
            .unwrap_or_else(|| MARK.to_string())
    });
    let u = url::Url::parse(&rendered).ok()?;
    let h = u.host_str()?.to_lowercase();
    if u.scheme() == "https" && !h.contains(MARK) && HOST_RE.is_match(&h) {
        Some(h)
    } else {
        None
    }
}

fn clean_label(s: &str) -> String {
    s.chars()
        .map(|c| {
            if matches!(c, '\u{0000}'..='\u{001f}' | '\u{007f}') {
                ' '
            } else {
                c
            }
        })
        .take(100)
        .collect()
}

pub struct SetupResult {
    pub r#type: String,
    pub name: String,
    pub type_created: bool,
    pub replaced: bool,
}
impl<'de> Deserialize<'de> for SetupResult {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            r#type: String,
            name: String,
            #[serde(default, rename = "typeCreated")]
            type_created: bool,
            #[serde(default)]
            replaced: bool,
        }
        let r = Raw::deserialize(d)?;
        Ok(SetupResult {
            r#type: r.r#type,
            name: r.name,
            type_created: r.type_created,
            replaced: r.replaced,
        })
    }
}

pub struct TemplateSetArgs {
    pub template: String,
    pub r#type: Option<String>,
    pub name: String,
    pub fields: std::collections::HashMap<String, Value>,
    pub secret_fields: Option<Vec<String>>,
    pub value: Option<String>,
    pub allowed_hosts: Option<Vec<String>>,
    pub proxy_only: Option<bool>,
    pub description: Option<String>,
    pub overwrite: Option<bool>,
    pub verify: Option<bool>,
}

/// Save a static credential from a template: non-sensitive fields come from params/defaults,
/// secret fields are entered one by one in dialogs, and the proxy configuration is written at the
/// same time.
pub async fn set_from_template(
    server: &Server,
    purpose: &str,
    a: TemplateSetArgs,
) -> Result<Value, String> {
    let tpl = get_template(&a.template).ok_or_else(|| {
        kv_i18n::t(
            &format!(
                "找不到模板 \"{}\"，可用 credential_templates 搜索",
                a.template
            ),
            &format!(
                "Template \"{}\" not found; search with credential_templates",
                a.template
            ),
        )
    })?;
    if tpl.kind == "oauth2" {
        return Err(kv_i18n::t(
            &format!(
                "\"{}\" 是 OAuth2 模板，请用 credential_oauth_login（provider: \"{}\"）",
                tpl.id, tpl.id
            ),
            &format!(
                "\"{}\" is an OAuth2 template; use credential_oauth_login (provider: \"{}\")",
                tpl.id, tpl.id
            ),
        ));
    }
    let ty = a
        .r#type
        .clone()
        .unwrap_or_else(|| type_from_template(&tpl.id));
    let label = format!("{}/{}", norm(&ty), norm(&a.name));
    let target = CredentialTarget {
        r#type: Some(ty.clone()),
        name: Some(a.name.clone()),
    };
    let s = server.session.scoped(purpose.to_string(), Some(target));

    // ---- Non-sensitive fields ----
    let by_name: std::collections::HashMap<&str, &crate::templates::TemplateField> =
        tpl.fields.iter().map(|f| (f.name.as_str(), f)).collect();
    let mut attrs: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for f in &tpl.fields {
        if !f.secret {
            if let Some(d) = &f.default {
                attrs.insert(f.name.clone(), value_to_string(d));
            }
        }
    }
    for (k, v) in &a.fields {
        let Some(f) = by_name.get(k.as_str()) else {
            let available: Vec<&str> = tpl.fields.iter().map(|x| x.name.as_str()).collect();
            return Err(kv_i18n::t(
                &format!(
                    "模板 {} 没有字段 {k}（可用：{}）",
                    tpl.id,
                    available.join("、")
                ),
                &format!(
                    "Template {} has no field {k} (available: {})",
                    tpl.id,
                    available.join(", ")
                ),
            ));
        };
        if f.secret {
            return Err(kv_i18n::t(&format!("{k} 是秘密字段，不能通过参数传入，会弹窗让用户输入"), &format!("{k} is a secret field; it cannot be passed as a parameter - the user will be prompted in a dialog")));
        }
        attrs.insert(k.clone(), value_to_string(v));
    }
    let missing: Vec<String> = tpl
        .fields
        .iter()
        .filter(|f| !f.secret && f.required && !attrs.contains_key(&f.name))
        .map(|f| format!("{}（{}）", f.name, f.label))
        .collect();
    if !missing.is_empty() {
        return Err(kv_i18n::t(
            &format!("缺少必填字段：{}，请通过 fields 传入", missing.join("、")),
            &format!(
                "Missing required fields: {}; pass them via fields",
                missing.join(", ")
            ),
        ));
    }

    // ---- Secret fields to prompt for: explicitly specified / required / referenced by the injection rule ----
    let secret_fields: Vec<&crate::templates::TemplateField> =
        tpl.fields.iter().filter(|f| f.secret).collect();
    let referenced = injected_placeholders(tpl.inject.as_ref());
    let mut wanted: Vec<String> = match &a.secret_fields {
        Some(w) if !w.is_empty() => w.clone(),
        _ => secret_fields
            .iter()
            .filter(|f| f.required || referenced.contains(&f.name))
            .map(|f| f.name.clone())
            .collect(),
    };
    if wanted.is_empty() {
        wanted = secret_fields.iter().map(|f| f.name.clone()).collect();
    }
    for n in &referenced {
        if by_name.get(n.as_str()).is_some_and(|f| f.secret) && !wanted.contains(n) {
            wanted.push(n.clone());
        }
    }
    for n in &wanted {
        if !by_name.get(n.as_str()).is_some_and(|f| f.secret) {
            return Err(kv_i18n::t(
                &format!("{n} 不是模板 {} 的秘密字段", tpl.id),
                &format!("{n} is not a secret field of template {}", tpl.id),
            ));
        }
    }

    // ---- Allowed hosts ----
    let mut hosts: Vec<String> = a
        .allowed_hosts
        .clone()
        .unwrap_or_default()
        .iter()
        .map(|h| h.trim().to_lowercase())
        .collect();
    if hosts.is_empty() {
        let mut computed = std::collections::BTreeSet::new();
        if let Some(test) = &tpl.test {
            if let Some(h) = host_from_url_template(&test.url, &attrs) {
                computed.insert(h);
            }
        } else {
            for h in &tpl.hosts {
                computed.insert(h.clone());
            }
        }
        hosts = computed.into_iter().collect();
    }
    for h in &hosts {
        if !HOST_RE.is_match(h) {
            return Err(kv_i18n::t(
                &format!("非法的域名 {h}"),
                &format!("Invalid host {h}"),
            ));
        }
    }
    if tpl.inject.is_some() && hosts.is_empty() {
        return Err(kv_i18n::t("无法从模板确定 API 域名，请通过 allowed_hosts 指定（如 [\"api.example.com\"]）", "Cannot determine the API host from the template; specify it with allowed_hosts (e.g. [\"api.example.com\"])"));
    }

    if let Some(v) = &a.value {
        if v.is_empty() {
            return Err(kv_i18n::t("value 为空", "value is empty"));
        }
        if wanted.len() != 1 {
            return Err(kv_i18n::t(
                &format!("模板 {} 需要 {} 个秘密字段（{}），不能只用 value；请省略 value 让用户在弹窗中逐个输入", tpl.id, wanted.len(), wanted.join("、")),
                &format!("Template {} needs {} secret fields ({}), so value alone is not enough; omit value and let the user enter them in dialogs", tpl.id, wanted.len(), wanted.join(", ")),
            ));
        }
    }

    let exists = guard_overwrite(&s, &ty, &a.name, a.overwrite)
        .await
        .map_err(String::from)?;

    // ---- Prompt for secrets in dialogs (text includes only the template name, field name and validated hosts) ----
    let mut secrets: Map<String, Value> = Map::new();
    for n in &wanted {
        let f = by_name[n.as_str()];
        if let Some(v) = &a.value {
            secrets.insert(n.clone(), json!(v));
            continue;
        }
        let where_ = if tpl.inject.is_some() {
            kv_i18n::t(
                &format!("\n该凭证只会被代理发送到：{}", hosts.join("、")),
                &format!(
                    "\nThis credential will only be sent by the proxy to: {}",
                    hosts.join(", ")
                ),
            )
        } else {
            String::new()
        };
        let v = crate::dialog::prompt_secret(&kv_i18n::t(
            &format!(
                "请输入「{}」的 {}\n\n凭证：{label}{where_}",
                clean_label(&tpl.name),
                clean_label(&f.label)
            ),
            &format!(
                "Enter the {} for \"{}\"\n\nCredential: {label}{where_}",
                clean_label(&f.label),
                clean_label(&tpl.name)
            ),
        ))
        .await;
        match v {
            Some(v) => {
                secrets.insert(n.clone(), json!(v));
            }
            None => {
                if f.required || referenced.contains(n) {
                    return Err(kv_i18n::t(
                        "用户取消了输入，未保存。",
                        "The user cancelled input; nothing was saved.",
                    ));
                }
            }
        }
    }

    // Keep the verification request only if all the fields it references have values.
    let have: std::collections::HashSet<&str> = attrs
        .keys()
        .map(String::as_str)
        .chain(secrets.keys().map(String::as_str))
        .collect();
    let test = tpl.test.as_ref().filter(|t| {
        let mut vals = vec![t.url.as_str()];
        vals.extend(
            t.headers
                .as_ref()
                .map(|m| m.values().map(String::as_str))
                .into_iter()
                .flatten(),
        );
        vals.extend(
            t.query
                .as_ref()
                .map(|m| m.values().map(String::as_str))
                .into_iter()
                .flatten(),
        );
        crate::templates::placeholders(&vals.iter().map(|s| Some(*s)).collect::<Vec<_>>())
            .iter()
            .all(|n| have.contains(n.as_str()))
    });
    let http = tpl.inject.as_ref().map(|inject| {
        json!({
            "inject": inject, "allowed_hosts": hosts, "proxy_only": a.proxy_only == Some(true),
            "test": test,
        })
    });

    let mut p = Map::new();
    p.insert("type".into(), json!(ty));
    p.insert("name".into(), json!(a.name));
    p.insert("secrets".into(), Value::Object(secrets.clone()));
    p.insert("attributes".into(), json!(attrs));
    p.insert("http".into(), http.clone().unwrap_or(Value::Null));
    p.insert("template".into(), json!(tpl.id));
    p.insert(
        "description".into(),
        json!(a.description.clone().unwrap_or_else(|| tpl.name.clone())),
    );
    p.insert("type_description".into(), json!(tpl.name));
    p.insert("overwrite".into(), json!(exists));
    let r: SetupResult = s.request("set", p).await.map_err(String::from)?;

    let verify = if http.is_some() && test.is_some() && a.verify != Some(false) {
        let mut tp = Map::new();
        tp.insert("type".into(), json!(r.r#type));
        tp.insert("name".into(), json!(r.name));
        match s.request::<Value>("httpTest", tp).await {
            Ok(v) => v,
            Err(e) => json!({"ok": false, "error": e.0}),
        }
    } else {
        json!(kv_i18n::t(
            "模板没有验证请求",
            "Template has no verification request"
        ))
    };
    let proxy = if let Some(h) = &http {
        json!({"allowed_hosts": hosts, "proxy_only": h.get("proxy_only")})
    } else {
        json!(kv_i18n::t(
            "不可代理（模板没有注入规则）",
            "Not proxyable (template has no injection rule)"
        ))
    };
    Ok(json!({
        "type": r.r#type, "name": r.name, "typeCreated": r.type_created, "replaced": r.replaced,
        "template": tpl.id, "secret_fields": secrets.keys().collect::<Vec<_>>(), "proxy": proxy, "verify": verify,
    }))
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

pub async fn credential_set_impl(
    server: &Server,
    a: super::basic::SetArgs,
) -> Result<CallToolResult, String> {
    if a.delete_source_file == Some(true) && a.value_file.is_none() {
        return Ok(fail(kv_i18n::t(
            "delete_source_file 只能配合 value_file 使用。",
            "delete_source_file can only be used together with value_file.",
        )));
    }
    if let Some(template) = &a.template {
        if a.value_file.is_some() || a.attributes.is_some() {
            return Ok(fail(kv_i18n::t(
                "使用模板时请用 fields 传非敏感字段；秘密字段会弹窗输入，或者用户已在对话中给出时通过 value 传入（不要传 value_file / attributes）。",
                "With a template, pass non-sensitive fields via fields; secret fields are entered in a dialog, or passed via value when the user already gave it in the chat (do not pass value_file / attributes).",
            )));
        }
        let r = set_from_template(
            server,
            &a.purpose,
            TemplateSetArgs {
                template: template.clone(),
                r#type: a.r#type.clone(),
                name: a.name.clone(),
                fields: a.fields.clone().unwrap_or_default().into_iter().collect(),
                secret_fields: a.secret_fields.clone(),
                value: a.value.clone(),
                allowed_hosts: a.allowed_hosts.clone(),
                proxy_only: a.proxy_only,
                description: a.description.clone(),
                overwrite: a.overwrite,
                verify: a.verify,
            },
        )
        .await?;
        let type_created = r
            .get("typeCreated")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let replaced = r.get("replaced").and_then(Value::as_bool).unwrap_or(false);
        let ty = r.get("type").and_then(Value::as_str).unwrap_or_default();
        let name = r.get("name").and_then(Value::as_str).unwrap_or_default();
        let template_id = r
            .get("template")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let head = kv_i18n::t(
            &format!(
                "{}{}凭证 \"{ty}/{name}\"（模板 {template_id}）。",
                if type_created {
                    format!("凭证类型 \"{ty}\" 不存在，已先创建；")
                } else {
                    String::new()
                },
                if replaced { "已覆盖" } else { "已保存" }
            ),
            &format!(
                "{}{} credential \"{ty}/{name}\" (template {template_id}).",
                if type_created {
                    format!("Credential type \"{ty}\" did not exist and was created; ")
                } else {
                    String::new()
                },
                if replaced { "Overwrote" } else { "Saved" }
            ),
        );
        return Ok(ok_data(head, r));
    }
    let Some(ty) = a.r#type.clone() else {
        return Ok(fail(kv_i18n::t(
            "缺少 type（或改用 template）。",
            "Missing type (or use template instead).",
        )));
    };
    if a.value.is_some() && a.value_file.is_some() {
        return Ok(fail(kv_i18n::t(
            "value 和 value_file 只能二选一。",
            "Pass either value or value_file, not both.",
        )));
    }
    let target = CredentialTarget {
        r#type: Some(ty.clone()),
        name: Some(a.name.clone()),
    };
    let s = server.session.scoped(a.purpose.clone(), Some(target));
    // Unlock and check existence first, so the user doesn't type the value only to find out it can't be saved.
    let exists = guard_overwrite(&s, &ty, &a.name, a.overwrite)
        .await
        .map_err(String::from)?;
    let label = format!("{}/{}", norm(&ty), norm(&a.name));
    let mut secret = a.value.clone();
    let mut source = String::new();
    if let Some(vf) = &a.value_file {
        let f = super::common::import_file(vf, &label).await?;
        secret = Some(f.content);
        source = f.path;
    } else if secret.is_none() {
        let prompted = crate::dialog::prompt_secret(&kv_i18n::t(
            &format!("请输入要保存的凭证值：\n\n{label}\n\n注意：保存后，解锁凭证库的 AI 会话可以读取它。"),
            &format!("Enter the credential value to save:\n\n{label}\n\nNote: once saved, AI sessions that unlock the vault can read it."),
        ))
        .await;
        match prompted {
            Some(v) => secret = Some(v),
            None => {
                return Ok(fail(kv_i18n::t(
                    "用户取消了输入，未保存。",
                    "The user cancelled input; nothing was saved.",
                )))
            }
        }
    }
    let mut p = Map::new();
    p.insert("type".into(), json!(ty));
    p.insert("name".into(), json!(a.name));
    p.insert("value".into(), json!(secret));
    p.insert("description".into(), json!(a.description));
    p.insert("attributes".into(), json!(a.attributes));
    p.insert("type_description".into(), json!(a.type_description));
    p.insert("overwrite".into(), json!(exists));
    let r: SetupResult = s.request("set", p).await.map_err(String::from)?;
    let mut steps = Vec::new();
    if r.type_created {
        steps.push(kv_i18n::t(
            &format!("凭证类型 \"{}\" 不存在，已先创建", r.r#type),
            &format!(
                "Credential type \"{}\" did not exist and was created",
                r.r#type
            ),
        ));
    }
    steps.push(if r.replaced {
        kv_i18n::t(
            &format!("已覆盖凭证 \"{}/{}\"", r.r#type, r.name),
            &format!("Overwrote credential \"{}/{}\"", r.r#type, r.name),
        )
    } else {
        kv_i18n::t(
            &format!("已保存凭证 \"{}/{}\"", r.r#type, r.name),
            &format!("Saved credential \"{}/{}\"", r.r#type, r.name),
        )
    });
    if !source.is_empty() && a.delete_source_file == Some(true) {
        let deleted = super::common::confirm_delete_source_file(&source).await;
        steps.push(if deleted {
            kv_i18n::t(&format!("内容来自 {source}，原文件已删除"), &format!("Content read from {source}; the original file was deleted"))
        } else {
            kv_i18n::t(&format!("内容来自 {source}（用户拒绝删除原文件，或删除失败，请自行处理）"), &format!("Content read from {source} (the user declined to delete the original file, or deletion failed; handle it yourself)"))
        });
    } else if !source.is_empty() {
        steps.push(kv_i18n::t(
            &format!("内容来自 {source}（如不再需要，建议删除原文件，可传 delete_source_file: true 让我代为确认删除）"),
            &format!("Content read from {source} (consider deleting the original file if no longer needed; pass delete_source_file: true to have me confirm and delete it)"),
        ));
    }
    Ok(ok(
        steps.join(&kv_i18n::t("；", "; ")) + &kv_i18n::t("。", ".")
    ))
}

fn template_detail_or_fail(id: &str) -> CallToolResult {
    match get_template(id) {
        Some(tpl) => ok_data(kv_i18n::t("模板：", "Template:"), template_detail(tpl)),
        None => fail(kv_i18n::t(
            &format!("找不到模板 \"{id}\""),
            &format!("Template \"{id}\" not found"),
        )),
    }
}

#[derive(Deserialize, JsonSchema)]
pub struct TemplatesArgs {
    #[schemars(description = kv_i18n::t("服务名关键词，如 openai、github、notion", "Service name keyword, e.g. openai, github, notion"))]
    pub query: Option<String>,
    #[schemars(description = kv_i18n::t("模板 id，返回完整模板", "Template id; returns the full template"))]
    pub id: Option<String>,
    pub kind: Option<String>,
    #[schemars(description = kv_i18n::t("默认 20，最多 100", "Default 20, max 100"))]
    pub limit: Option<i64>,
}

#[derive(Deserialize, JsonSchema)]
pub struct HttpRequestArgs {
    #[schemars(description = purpose_desc())]
    pub purpose: String,
    #[schemars(description = kv_i18n::t("凭证名", "Credential name"))]
    pub name: String,
    #[schemars(description = kv_i18n::t("凭证类型；省略时按名字自动查找", "Credential type; looked up by name if omitted"))]
    pub r#type: Option<String>,
    #[schemars(description = kv_i18n::t("默认 GET", "Default GET"))]
    pub method: Option<String>,
    #[schemars(description = kv_i18n::t("完整 https URL", "Full https URL"))]
    pub url: String,
    #[schemars(description = kv_i18n::t("额外请求头（认证头由凭证库注入，不要自己传）", "Extra request headers (auth headers are injected by the vault; do not pass them yourself)"))]
    pub headers: Option<std::collections::HashMap<String, String>>,
    pub query: Option<std::collections::HashMap<String, String>>,
    #[schemars(description = kv_i18n::t("请求体：字符串原样发送；对象/数组按 JSON 发送", "Request body: strings are sent as-is; objects/arrays are sent as JSON"))]
    pub body: Option<Value>,
}

#[derive(Deserialize, JsonSchema)]
pub struct TestArgs {
    #[schemars(description = purpose_desc())]
    pub purpose: String,
    pub name: String,
    #[schemars(description = kv_i18n::t("凭证类型；省略时按名字自动查找", "Credential type; looked up by name if omitted"))]
    pub r#type: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct ConfigureHttpArgs {
    #[schemars(description = purpose_desc())]
    pub purpose: String,
    pub name: String,
    #[schemars(description = kv_i18n::t("凭证类型；省略时按名字自动查找", "Credential type; looked up by name if omitted"))]
    pub r#type: Option<String>,
    #[schemars(description = kv_i18n::t("允许发往的域名，如 [\"api.example.com\"]；*.example.com 匹配子域名", "Hosts requests may be sent to, e.g. [\"api.example.com\"]; *.example.com matches subdomains"))]
    pub allowed_hosts: Option<Vec<String>>,
    #[schemars(description = kv_i18n::t(
        "注入规则。static 凭证用 {{字段名}}；oauth2 等 token 类凭证默认注入 Bearer，也可用 {{access_token}} 自定义，如 GitHub git 推送：{\"basic\": {\"username\": \"x-access-token\", \"password\": \"{{access_token}}\"}}",
        "Injection rule. Static credentials use {{field}}; token credentials (oauth2 etc.) inject a Bearer token by default or can use {{access_token}}, e.g. for GitHub git pushes: {\"basic\": {\"username\": \"x-access-token\", \"password\": \"{{access_token}}\"}}",
    ))]
    pub inject: Option<Value>,
    #[schemars(description = kv_i18n::t("验证请求，如 {\"url\": \"https://api.example.com/me\"}", "Verification request, e.g. {\"url\": \"https://api.example.com/me\"}"))]
    pub test: Option<Value>,
    #[schemars(description = kv_i18n::t("true：只能代理调用，credential_get 不再返回原值", "true: proxy-only; credential_get no longer returns the raw value"))]
    pub proxy_only: Option<bool>,
    #[schemars(description = kv_i18n::t("删除代理配置", "Remove the proxy configuration"))]
    pub remove: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct GatewayArgs {
    #[schemars(description = purpose_desc())]
    pub purpose: String,
    #[schemars(description = kv_i18n::t("凭证名", "Credential name"))]
    pub name: String,
    #[schemars(description = kv_i18n::t("凭证类型；省略时按名字自动查找", "Credential type; looked up by name when omitted"))]
    pub r#type: Option<String>,
}

/// Environment variables for common SDKs (the API key can be a placeholder; the gateway swaps in
/// the real credential).
fn sdk_env(
    template: Option<&str>,
    urls: &Map<String, Value>,
    token: &str,
) -> Vec<(String, String)> {
    let u = |host: &str, suffix: &str| {
        urls.get(host)
            .and_then(Value::as_str)
            .map(|s| format!("{s}{suffix}"))
    };
    let pairs: Option<Vec<(&str, Option<String>)>> = match template {
        Some("openai") => Some(vec![
            ("OPENAI_BASE_URL", u("api.openai.com", "/v1")),
            ("OPENAI_API_KEY", Some(token.to_string())),
        ]),
        Some("anthropic") => Some(vec![
            ("ANTHROPIC_BASE_URL", u("api.anthropic.com", "")),
            ("ANTHROPIC_API_KEY", Some(token.to_string())),
        ]),
        Some("groq") => Some(vec![
            ("GROQ_BASE_URL", u("api.groq.com", "")),
            ("GROQ_API_KEY", Some(token.to_string())),
        ]),
        Some("deepseek") => Some(vec![
            ("OPENAI_BASE_URL", u("api.deepseek.com", "")),
            ("OPENAI_API_KEY", Some(token.to_string())),
        ]),
        Some("xai") => Some(vec![
            ("OPENAI_BASE_URL", u("api.x.ai", "/v1")),
            ("OPENAI_API_KEY", Some(token.to_string())),
        ]),
        Some("openrouter") => Some(vec![
            ("OPENAI_BASE_URL", u("openrouter.ai", "/api/v1")),
            ("OPENAI_API_KEY", Some(token.to_string())),
        ]),
        Some("together") => Some(vec![
            ("OPENAI_BASE_URL", u("api.together.xyz", "/v1")),
            ("OPENAI_API_KEY", Some(token.to_string())),
        ]),
        Some("mistral") => Some(vec![
            ("MISTRAL_BASE_URL", u("api.mistral.ai", "")),
            ("MISTRAL_API_KEY", Some(token.to_string())),
        ]),
        _ => None,
    };
    match pairs {
        Some(pairs) if pairs.iter().all(|(_, v)| v.is_some()) => pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.unwrap()))
            .collect(),
        _ => Vec::new(),
    }
}

#[tool_router(router = http_tool_router, vis = "pub")]
impl Server {
    #[tool(description = kv_i18n::t(
        "搜索凭证模板（内置通用模板 + 自带模板库中的常用服务，以及可选的本地 n8n 模板库）。模板定义了需要哪些字段、哪些是秘密、如何注入请求（代理调用）、如何验证。传 id 查看完整模板。不需要解锁。",
        "Search credential templates (built-in generic templates + common services from the bundled catalog, plus the optional local n8n catalog). A template defines which fields are needed, which are secret, how they are injected into requests (proxied calls) and how to verify them. Pass id to see the full template. Does not require unlocking.",
    ), annotations(read_only_hint = true))]
    async fn credential_templates(
        &self,
        Parameters(a): Parameters<TemplatesArgs>,
    ) -> CallToolResult {
        if let Some(id) = &a.id {
            return template_detail_or_fail(id);
        }
        let limit = a.limit.unwrap_or(20).clamp(1, 100) as usize;
        let list = search_templates(a.query.as_deref(), a.kind.as_deref(), limit);
        ok_data(
            kv_i18n::t(
                &format!("找到 {} 个模板：", list.len()),
                &format!("Found {} template(s):", list.len()),
            ),
            list.iter().map(|t| summarize(t)).collect::<Vec<_>>(),
        )
    }

    #[tool(description = kv_i18n::t(
        "代理调用：由凭证库把凭证注入 HTTP 请求并发出，只返回响应——agent 看不到 API key / token。适用于配置了代理的 static 凭证（模板或手动规则）以及 oauth2 / google_service_account / github_app / jwt 凭证（自动注入 access token）。流式（SSE）响应会被完整接收，并在 stream.text 中返回从大模型增量拼出的完整文本；程序需要边收边输出时请用 credential_gateway。只允许 https、只能发往该凭证允许的域名；不跟随重定向；响应中出现的秘密会被替换为 [REDACTED]。",
        "Proxied call: the vault injects the credential into the HTTP request, sends it and returns only the response - the agent never sees the API key / token. Works with static credentials that have a proxy configuration (from a template or manual rules) and with oauth2 / google_service_account / github_app / jwt credentials (access token injected automatically). Streaming (SSE) responses are received in full, and the text assembled from LLM deltas is returned in stream.text; for programs that need to stream incrementally, use credential_gateway. HTTPS only, and only to the credential's allowed hosts; redirects are not followed; secrets appearing in the response are replaced with [REDACTED].",
    ), annotations(open_world_hint = true))]
    async fn credential_http_request(
        &self,
        Parameters(a): Parameters<HttpRequestArgs>,
    ) -> CallToolResult {
        wrap(async {
            let target = CredentialTarget {
                r#type: a.r#type.clone(),
                name: Some(a.name.clone()),
            };
            let s = self.session.scoped(a.purpose, Some(target));
            let ty = resolve_type(&s, &a.name, a.r#type.as_deref(), &PROXY_KINDS).await?;
            let mut p = Map::new();
            p.insert("type".into(), json!(ty));
            p.insert("name".into(), json!(a.name));
            p.insert("method".into(), json!(a.method));
            p.insert("url".into(), json!(a.url));
            p.insert("headers".into(), json!(a.headers));
            p.insert("query".into(), json!(a.query));
            p.insert("body".into(), json!(a.body));
            let r: Value = s.request("httpRequest", p).await?;
            Ok(ok_data(kv_i18n::t("响应：", "Response:"), r))
        })
        .await
    }

    #[tool(description = kv_i18n::t(
        "用凭证的验证请求（来自模板，或 credential_configure_http 设置的 test）检查凭证是否有效。只返回是否成功、状态码和响应摘要。",
        "Check whether a credential works using its verification request (from the template, or the test set via credential_configure_http). Returns only success, status code and a response summary.",
    ), annotations(read_only_hint = true, open_world_hint = true))]
    async fn credential_test(&self, Parameters(a): Parameters<TestArgs>) -> CallToolResult {
        wrap(async {
            let target = CredentialTarget {
                r#type: a.r#type.clone(),
                name: Some(a.name.clone()),
            };
            let s = self.session.scoped(a.purpose, Some(target));
            let ty = resolve_type(&s, &a.name, a.r#type.as_deref(), &PROXY_KINDS).await?;
            let mut p = Map::new();
            p.insert("type".into(), json!(ty));
            p.insert("name".into(), json!(a.name));
            #[derive(Deserialize, serde::Serialize)]
            struct R {
                ok: bool,
                status: i64,
                #[serde(flatten)]
                rest: Map<String, Value>,
            }
            let r: R = s.request("httpTest", p).await?;
            if r.ok {
                Ok(ok_data(
                    kv_i18n::t(
                        &format!("凭证有效（HTTP {}）。", r.status),
                        &format!("Credential is valid (HTTP {}).", r.status),
                    ),
                    &r,
                ))
            } else {
                let body = serde_json::to_string_pretty(&r).unwrap_or_default();
                Ok(fail(format!(
                    "{}\n{body}",
                    kv_i18n::t(
                        &format!("凭证验证未通过（HTTP {}）。", r.status),
                        &format!("Credential verification failed (HTTP {}).", r.status)
                    )
                )))
            }
        })
        .await
    }

    #[tool(description = kv_i18n::t(
        "设置或修改凭证的代理调用配置：允许的域名、注入规则（static 凭证）、验证请求、是否只能代理调用（禁止读出原值）。新增域名、修改注入规则、关闭「只能代理调用」、删除配置都会由凭证库弹窗请用户确认。",
        "Set or change a credential's proxy configuration: allowed hosts, injection rule (static credentials), verification request, and whether it is proxy-only (raw value cannot be read). Adding hosts, changing the injection rule, turning off proxy-only, or removing the configuration requires user confirmation in a vault dialog.",
    ))]
    async fn credential_configure_http(
        &self,
        Parameters(a): Parameters<ConfigureHttpArgs>,
    ) -> CallToolResult {
        wrap(async {
            let target = CredentialTarget {
                r#type: a.r#type.clone(),
                name: Some(a.name.clone()),
            };
            let s = self.session.scoped(a.purpose, Some(target));
            let ty = resolve_type(&s, &a.name, a.r#type.as_deref(), &PROXY_KINDS).await?;
            let mut p = Map::new();
            p.insert("type".into(), json!(ty));
            p.insert("name".into(), json!(a.name));
            p.insert("allowed_hosts".into(), json!(a.allowed_hosts));
            p.insert("inject".into(), json!(a.inject));
            p.insert(
                "test".into(),
                match a.test {
                    Some(mut t) => {
                        if let Some(obj) = t.as_object_mut() {
                            obj.entry("method").or_insert(json!("GET"));
                        }
                        t
                    }
                    None => Value::Null,
                },
            );
            p.insert("proxy_only".into(), json!(a.proxy_only));
            p.insert("remove".into(), json!(a.remove));
            let r: Value = s.request("httpConfigure", p).await?;
            Ok(ok_data(
                kv_i18n::t("代理配置已更新：", "Proxy configuration updated:"),
                r,
            ))
        })
        .await
    }

    #[tool(description = kv_i18n::t(
        "为凭证开通本地网关，给不能走 MCP 的程序（SDK、CLI、脚本）使用，支持流式响应。网关地址和本会话专属令牌写入一个仅你可读的环境变量文件（env_file）；用 `set -a; . <env_file>; set +a; <命令>` 运行程序，常见 SDK（OpenAI、Anthropic 等）的 BASE_URL 和 API_KEY 已设置好。程序把令牌当作 API key 发送，网关替换为真实凭证、只转发到允许的域名并对响应脱敏——程序和 agent 都拿不到真实 key。只接受你本人账户的进程连接；锁定、会话结束或授权模式变更即失效。per_use 模式不支持可复用网关，请使用 credential_http_request。不要读取、打印该文件，也不要把其中的值写进命令行参数。凭证需先配置代理（credential_set 用模板，或 credential_configure_http）。",
        "Open a local gateway for a credential, for programs that cannot use MCP (SDKs, CLIs, scripts); streaming responses are supported. The gateway URL and a per-session token are written to an environment file readable only by you (env_file); run programs with `set -a; . <env_file>; set +a; <command>` - BASE_URL and API_KEY for common SDKs (OpenAI, Anthropic, …) are already set. The program sends the token as its API key; the gateway swaps in the real credential, forwards only to allowed hosts and redacts responses, so neither the program nor the agent ever holds the real key. Only processes of your own user account may connect; locking, session exit, or a grant-mode change invalidates the token. Reusable gateways are unavailable in per_use mode; use credential_http_request. Never read or print the file, or put its values in command-line arguments. The credential must have a proxy configuration (credential_set with a template, or credential_configure_http).",
    ), annotations(open_world_hint = true))]
    async fn credential_gateway(&self, Parameters(a): Parameters<GatewayArgs>) -> CallToolResult {
        wrap(async {
            let target = CredentialTarget { r#type: a.r#type.clone(), name: Some(a.name.clone()) };
            let s = self.session.scoped(a.purpose, Some(target));
            let ty = resolve_type(&s, &a.name, a.r#type.as_deref(), &PROXY_KINDS).await?;
            let mut p = Map::new();
            p.insert("type".into(), json!(ty));
            p.insert("name".into(), json!(a.name));
            #[derive(Deserialize)]
            struct R {
                r#type: String,
                name: String,
                base: String,
                token: String,
                template: Option<String>,
                base_urls: Map<String, Value>,
            }
            let g: R = s.request("gatewayOpen", p).await?;
            let mut env = vec![("KEYVALET_GATEWAY_URL".to_string(), g.base.clone()), ("KEYVALET_GATEWAY_TOKEN".to_string(), g.token.clone())];
            env.extend(sdk_env(g.template.as_deref(), &g.base_urls, &g.token));
            let file = write_gateway_env(&self.session.session_id, &g.r#type, &g.name, &env).map_err(|e| SessionError(e.to_string()))?;
            let file_str = file.display().to_string();
            Ok(ok_data(
                kv_i18n::t("网关已开通：", "Gateway opened:"),
                json!({
                    "env_file": file_str,
                    "variables": env.iter().map(|(k,_)| k).collect::<Vec<_>>(),
                    "usage": format!("set -a; . {}; set +a; <command>", crate::gateway_env::quote(&file_str)),
                    "base_urls": g.base_urls,
                    "how_to_call": kv_i18n::t(
                        "请求 <base_urls 中的地址>/<API 路径>，并把 $KEYVALET_GATEWAY_TOKEN 作为 API key 发送（Authorization: Bearer、x-api-key 或 x-goog-api-key）。不要读取、打印或在命令行参数中写出该文件的内容。",
                        "Call <a base_urls entry>/<API path> and send $KEYVALET_GATEWAY_TOKEN as the API key (Authorization: Bearer, x-api-key or x-goog-api-key). Never read, print or put the file's values in command-line arguments.",
                    ),
                }),
            ))
        })
        .await
    }
}

#[cfg(test)]
mod helper_tests {
    use super::*;

    #[test]
    fn type_from_template_converts_camel_case_to_snake_case() {
        assert_eq!(type_from_template("openAiApi"), "open_ai_api");
    }

    #[test]
    fn type_from_template_leaves_plain_lowercase_ids_unchanged() {
        assert_eq!(type_from_template("openai"), "openai");
    }

    #[test]
    fn type_from_template_trims_a_leading_non_alnum_character() {
        assert_eq!(type_from_template("-openai"), "openai");
    }

    #[test]
    fn type_from_template_falls_back_to_api_key_when_empty() {
        assert_eq!(type_from_template(""), "api_key");
        assert_eq!(type_from_template("---"), "api_key");
    }

    #[test]
    fn type_from_template_is_capped_at_64_characters() {
        let long = "a".repeat(100);
        assert_eq!(type_from_template(&long).len(), 64);
    }

    #[test]
    fn host_from_url_template_renders_placeholders_and_extracts_the_host() {
        let attrs = [("region".to_string(), "us".to_string())].into();
        assert_eq!(
            host_from_url_template("https://api.{{region}}.example.com/path", &attrs),
            Some("api.us.example.com".to_string())
        );
    }

    #[test]
    fn host_from_url_template_rejects_non_https() {
        let attrs = Default::default();
        assert_eq!(
            host_from_url_template("http://api.example.com", &attrs),
            None
        );
    }

    #[test]
    fn host_from_url_template_rejects_an_unresolved_placeholder_in_the_host() {
        // Missing attrs entry: the host ends up containing the literal "zzsecretzz" marker
        // instead of a real value, and must not be reported as a usable host.
        let attrs = Default::default();
        assert_eq!(
            host_from_url_template("https://{{missing}}.example.com", &attrs),
            None
        );
    }

    #[test]
    fn host_from_url_template_rejects_an_unparseable_url() {
        let attrs = Default::default();
        assert_eq!(host_from_url_template("not a url", &attrs), None);
    }

    #[test]
    fn clean_label_strips_control_characters_and_caps_length() {
        assert_eq!(clean_label("hello\x00\x1fworld"), "hello  world");
        assert_eq!(clean_label(&"x".repeat(200)).len(), 100);
    }

    #[test]
    fn value_to_string_unwraps_a_json_string_without_quotes() {
        assert_eq!(value_to_string(&json!("hello")), "hello");
    }

    #[test]
    fn value_to_string_renders_other_json_types_as_their_text_form() {
        assert_eq!(value_to_string(&json!(42)), "42");
        assert_eq!(value_to_string(&json!(true)), "true");
    }

    #[test]
    fn sdk_env_fills_in_known_templates_when_the_url_is_present() {
        let urls = serde_json::json!({"api.openai.com": "https://api.openai.com"})
            .as_object()
            .unwrap()
            .clone();
        let env = sdk_env(Some("openai"), &urls, "sk-test");
        assert!(env.contains(&(
            "OPENAI_BASE_URL".to_string(),
            "https://api.openai.com/v1".to_string()
        )));
        assert!(env.contains(&("OPENAI_API_KEY".to_string(), "sk-test".to_string())));
    }

    #[test]
    fn sdk_env_is_empty_for_an_unknown_template() {
        let urls = Map::new();
        assert!(sdk_env(Some("not-a-real-template"), &urls, "sk-test").is_empty());
    }

    #[test]
    fn sdk_env_is_empty_when_the_template_s_url_entry_is_missing() {
        // "openai" is known, but with no matching host in `urls` the pair is incomplete and
        // nothing should be emitted (no half-configured SDK env).
        let urls = Map::new();
        assert!(sdk_env(Some("openai"), &urls, "sk-test").is_empty());
    }
}
