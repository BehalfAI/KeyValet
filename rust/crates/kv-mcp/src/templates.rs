//! Template catalog: built-in generic templates + the bundled catalog (templates/catalog.json) +
//! an optional local n8n catalog (templates/n8n-catalog.json). Direct port of
//! src/server/templates.ts and src/shared/templates.ts.

use crate::oauth_presets::{self, OAuthPreset};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateField {
    pub name: String,
    pub label: String,
    /// Whether this is a secret (requires dialog input, is encrypted at rest, and is never
    /// returned to the agent).
    #[serde(default)]
    pub secret: bool,
    #[serde(default)]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InjectRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<std::collections::HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<std::collections::HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basic: Option<BasicAuth>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestRequest {
    #[serde(default)]
    pub method: Option<String>,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<std::collections::HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTemplate {
    pub authorization_url: String,
    pub token_url: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub extra_auth_params: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub token_auth_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialTemplate {
    pub id: String,
    pub name: String,
    pub source: String, // "builtin" | "catalog" | "n8n"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs: Option<String>,
    /// static: stores a value and can be used for proxy calls; oauth2: authorized via
    /// credential_oauth_login.
    pub kind: String,
    pub fields: Vec<TemplateField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inject: Option<InjectRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test: Option<TestRequest>,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth2: Option<OAuthTemplate>,
}

static PLACEHOLDER_RE: OnceLock<regex::Regex> = OnceLock::new();
fn placeholder_re() -> &'static regex::Regex {
    PLACEHOLDER_RE.get_or_init(|| regex::Regex::new(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}").unwrap())
}

/// All field names referenced across the given strings.
pub fn placeholders(values: &[Option<&str>]) -> Vec<String> {
    let mut out = Vec::new();
    for v in values.iter().flatten() {
        for cap in placeholder_re().captures_iter(v) {
            let name = cap[1].to_string();
            if !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

pub fn inject_strings(rule: Option<&InjectRule>) -> Vec<String> {
    let Some(rule) = rule else { return Vec::new() };
    let mut out = Vec::new();
    if let Some(h) = &rule.headers {
        out.extend(h.values().cloned());
    }
    if let Some(q) = &rule.query {
        out.extend(q.values().cloned());
    }
    if let Some(b) = &rule.basic {
        out.push(b.username.clone());
        out.push(b.password.clone());
    }
    out
}

/// All field names referenced by an injection rule.
pub fn injected_placeholders(rule: Option<&InjectRule>) -> Vec<String> {
    let strings = inject_strings(rule);
    placeholders(&strings.iter().map(|s| Some(s.as_str())).collect::<Vec<_>>())
}

/// Built-in generic templates: used for HTTP APIs that don't have a dedicated template.
fn builtin_templates() -> Vec<CredentialTemplate> {
    vec![
        CredentialTemplate {
            id: "bearer".into(),
            name: "Generic Bearer token (Authorization: Bearer <token>)".into(),
            source: "builtin".into(),
            docs: None,
            kind: "static".into(),
            fields: vec![TemplateField {
                name: "token".into(),
                label: "Token".into(),
                secret: true,
                required: true,
                default: None,
                description: None,
                options: None,
            }],
            inject: Some(InjectRule {
                headers: Some(
                    [("Authorization".to_string(), "Bearer {{token}}".to_string())].into(),
                ),
                query: None,
                basic: None,
            }),
            test: None,
            hosts: vec![],
            oauth2: None,
        },
        CredentialTemplate {
            id: "header".into(),
            name: "Generic header auth (custom header name, e.g. X-Api-Key)".into(),
            source: "builtin".into(),
            docs: None,
            kind: "static".into(),
            fields: vec![
                TemplateField {
                    name: "headerName".into(),
                    label: "Header name".into(),
                    secret: false,
                    required: true,
                    default: Some(serde_json::json!("X-Api-Key")),
                    description: None,
                    options: None,
                },
                TemplateField {
                    name: "key".into(),
                    label: "Key".into(),
                    secret: true,
                    required: true,
                    default: None,
                    description: None,
                    options: None,
                },
            ],
            inject: Some(InjectRule {
                headers: Some([("{{headerName}}".to_string(), "{{key}}".to_string())].into()),
                query: None,
                basic: None,
            }),
            test: None,
            hosts: vec![],
            oauth2: None,
        },
        CredentialTemplate {
            id: "query".into(),
            name: "Generic query parameter auth (e.g. ?api_key=...)".into(),
            source: "builtin".into(),
            docs: None,
            kind: "static".into(),
            fields: vec![
                TemplateField {
                    name: "paramName".into(),
                    label: "Parameter name".into(),
                    secret: false,
                    required: true,
                    default: Some(serde_json::json!("api_key")),
                    description: None,
                    options: None,
                },
                TemplateField {
                    name: "key".into(),
                    label: "Key".into(),
                    secret: true,
                    required: true,
                    default: None,
                    description: None,
                    options: None,
                },
            ],
            inject: Some(InjectRule {
                headers: None,
                query: Some([("{{paramName}}".to_string(), "{{key}}".to_string())].into()),
                basic: None,
            }),
            test: None,
            hosts: vec![],
            oauth2: None,
        },
        CredentialTemplate {
            id: "basic".into(),
            name: "Generic HTTP Basic auth (username + password)".into(),
            source: "builtin".into(),
            docs: None,
            kind: "static".into(),
            fields: vec![
                TemplateField {
                    name: "user".into(),
                    label: "Username".into(),
                    secret: false,
                    required: true,
                    default: None,
                    description: None,
                    options: None,
                },
                TemplateField {
                    name: "password".into(),
                    label: "Password".into(),
                    secret: true,
                    required: true,
                    default: None,
                    description: None,
                    options: None,
                },
            ],
            inject: Some(InjectRule {
                headers: None,
                query: None,
                basic: Some(BasicAuth {
                    username: "{{user}}".into(),
                    password: "{{password}}".into(),
                }),
            }),
            test: None,
            hosts: vec![],
            oauth2: None,
        },
    ]
}

fn load_catalog_from(dir: &std::path::Path, file: &str) -> Vec<CredentialTemplate> {
    let Ok(text) = std::fs::read_to_string(dir.join(file)) else {
        return Vec::new();
    };
    #[derive(Deserialize)]
    struct Catalog {
        templates: Vec<CredentialTemplate>,
    }
    serde_json::from_str::<Catalog>(&text)
        .map(|c| c.templates)
        .unwrap_or_default()
}

fn load_catalog(file: &str) -> Vec<CredentialTemplate> {
    load_catalog_from(
        std::path::Path::new(kv_platform::paths::TEMPLATES_DIR),
        file,
    )
}

/// Merge by priority; when ids match (case-insensitive), keep the higher-priority one.
fn merge_templates(
    templates: impl IntoIterator<Item = CredentialTemplate>,
) -> Vec<CredentialTemplate> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for t in templates {
        let k = t.id.to_lowercase();
        if seen.insert(k) {
            out.push(t);
        }
    }
    out
}

static ALL_TEMPLATES: OnceLock<Vec<CredentialTemplate>> = OnceLock::new();

/// Merge by priority; when ids match (case-insensitive), keep the higher-priority one.
pub fn all_templates() -> &'static [CredentialTemplate] {
    ALL_TEMPLATES.get_or_init(|| {
        merge_templates(
            builtin_templates()
                .into_iter()
                .chain(load_catalog("catalog.json"))
                .chain(load_catalog("n8n-catalog.json")),
        )
    })
}

pub fn get_template(id: &str) -> Option<&'static CredentialTemplate> {
    let lower = id.trim().to_lowercase();
    all_templates()
        .iter()
        .find(|t| t.id.to_lowercase() == lower)
}

/// Fuzzy search by id / name: exact match > prefix > contains.
pub fn search_templates(
    query: Option<&str>,
    kind: Option<&str>,
    limit: usize,
) -> Vec<&'static CredentialTemplate> {
    search_in(all_templates(), query, kind, limit)
}

fn search_in<'a>(
    templates: &'a [CredentialTemplate],
    query: Option<&str>,
    kind: Option<&str>,
    limit: usize,
) -> Vec<&'a CredentialTemplate> {
    let q = query.unwrap_or("").trim().to_lowercase();
    let mut scored: Vec<(f64, &'a CredentialTemplate)> = Vec::new();
    for t in templates {
        if let Some(k) = kind {
            if t.kind != k {
                continue;
            }
        }
        let id = t.id.to_lowercase();
        let name = t.name.to_lowercase();
        let mut score = 0.0;
        if q.is_empty() {
            score = 1.0;
        } else if id == q || name == q {
            score = 100.0;
        } else if id.starts_with(&q) || name.starts_with(&q) {
            score = 50.0;
        } else if id.contains(&q) || name.contains(&q) {
            score = 10.0;
        }
        if score > 0.0 {
            let bonus = match t.source.as_str() {
                "builtin" => 0.6,
                "catalog" => 0.5,
                _ => 0.0,
            };
            scored.push((score + bonus, t));
        }
    }
    scored.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap()
            .then_with(|| a.1.name.cmp(&b.1.name))
    });
    scored.into_iter().take(limit).map(|(_, t)| t).collect()
}

pub fn summarize(tpl: &CredentialTemplate) -> serde_json::Value {
    let secret_fields: Vec<&str> = tpl
        .fields
        .iter()
        .filter(|f| f.secret)
        .map(|f| f.name.as_str())
        .collect();
    let proxy = if tpl.kind == "oauth2" {
        kv_i18n::t(
            "授权后可代理（需设置允许的域名）",
            "Proxyable after authorization (allowed hosts must be set)",
        )
    } else if tpl.inject.is_some() {
        kv_i18n::t("可代理调用", "Proxyable")
    } else {
        kv_i18n::t("不可代理（仅存储）", "Not proxyable (storage only)")
    };
    serde_json::json!({
        "id": tpl.id, "name": tpl.name, "kind": tpl.kind, "secret_fields": secret_fields,
        "proxy": proxy, "can_test": tpl.test.is_some(), "hosts": tpl.hosts,
    })
}

pub fn template_detail(tpl: &CredentialTemplate) -> serde_json::Value {
    let mut v = summarize(tpl);
    let obj = v.as_object_mut().unwrap();
    obj.insert("source".into(), serde_json::json!(tpl.source));
    obj.insert("docs".into(), serde_json::json!(tpl.docs));
    obj.insert("fields".into(), serde_json::to_value(&tpl.fields).unwrap());
    obj.insert("inject".into(), serde_json::to_value(&tpl.inject).unwrap());
    obj.insert("test".into(), serde_json::to_value(&tpl.test).unwrap());
    obj.insert("oauth2".into(), serde_json::to_value(&tpl.oauth2).unwrap());
    let how_to_use = if tpl.kind == "oauth2" {
        format!(
            "credential_oauth_login {{ provider: \"{}\", client_id: ..., name: ... }}",
            tpl.id
        )
    } else {
        kv_i18n::t(
            &format!("credential_set {{ template: \"{}\", name: ..., fields: {{ 非敏感字段 }} }}（秘密字段会弹窗输入）", tpl.id),
            &format!("credential_set {{ template: \"{}\", name: ..., fields: {{ non-sensitive fields }} }} (secret fields are entered in a dialog)", tpl.id),
        )
    };
    obj.insert("how_to_use".into(), serde_json::json!(how_to_use));
    v
}

/// OAuth providers: built-in presets take priority, then n8n's OAuth2 templates (by template id).
pub fn resolve_oauth_provider(
    provider: &str,
    tenant: Option<&str>,
) -> Result<Option<OAuthPreset>, String> {
    if let Some(p) = oauth_presets::resolve_preset(provider, tenant.unwrap_or("common"))? {
        return Ok(Some(p));
    }
    let Some(tpl) = get_template(provider) else {
        return Ok(None);
    };
    let Some(o) = &tpl.oauth2 else {
        return Ok(None);
    };
    Ok(Some(OAuthPreset {
        label: tpl.name.clone(),
        authorization_url: o.authorization_url.clone(),
        token_url: o.token_url.clone(),
        device_authorization_url: None,
        extra_auth_params: o.extra_auth_params.clone(),
        default_scopes: o.scopes.clone(),
        required_scopes: vec![],
        redirect_host: None,
        notes: tpl
            .docs
            .as_ref()
            .map(|d| kv_i18n::t(&format!("参考：{d}"), &format!("See: {d}")))
            .unwrap_or_default(),
        token_auth_method: match o.token_auth_method.as_deref() {
            Some("client_secret_basic") => Some("client_secret_basic"),
            Some("client_secret_post") => Some("client_secret_post"),
            _ => None,
        },
    }))
}

pub fn oauth_provider_names() -> String {
    let extra = all_templates()
        .iter()
        .filter(|t| t.oauth2.is_some())
        .count();
    let names = oauth_presets::preset_names().join(&kv_i18n::t("、", ", "));
    if extra == 0 {
        names
    } else {
        kv_i18n::t(
            &format!("{names}，以及模板库中的 {extra} 个 OAuth2 模板（用 credential_templates kind=oauth2 搜索，以模板 id 作为 provider）"),
            &format!("{names}, plus {extra} OAuth2 templates from the catalog (search with credential_templates kind=oauth2 and use the template id as provider)"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storage_only_template() -> CredentialTemplate {
        CredentialTemplate {
            id: "test-storage".into(),
            name: "Test storage-only".into(),
            source: "builtin".into(),
            docs: None,
            kind: "static".into(),
            fields: vec![TemplateField {
                name: "value".into(),
                label: "Value".into(),
                secret: true,
                required: true,
                default: None,
                description: None,
                options: None,
            }],
            inject: None,
            test: None,
            hosts: vec![],
            oauth2: None,
        }
    }

    #[test]
    fn placeholders_extracts_field_names_in_first_seen_order_without_duplicates() {
        let v1 = Some("Bearer {{token}}");
        let v2 = Some("{{token}} and {{apiKey}} and {{ token }}");
        let v3: Option<&str> = None;
        assert_eq!(
            placeholders(&[v1, v2, v3]),
            vec!["token".to_string(), "apiKey".to_string()]
        );
    }

    #[test]
    fn placeholders_on_text_with_no_braces_is_empty() {
        assert_eq!(
            placeholders(&[Some("no placeholders here")]),
            Vec::<String>::new()
        );
    }

    #[test]
    fn inject_strings_collects_header_query_and_basic_auth_values() {
        let rule = InjectRule {
            headers: Some([("Authorization".to_string(), "Bearer {{token}}".to_string())].into()),
            query: Some([("api_key".to_string(), "{{key}}".to_string())].into()),
            basic: Some(BasicAuth {
                username: "{{user}}".into(),
                password: "{{password}}".into(),
            }),
        };
        let mut strings = inject_strings(Some(&rule));
        strings.sort();
        let mut expected = vec![
            "Bearer {{token}}".to_string(),
            "{{key}}".to_string(),
            "{{user}}".to_string(),
            "{{password}}".to_string(),
        ];
        expected.sort();
        assert_eq!(strings, expected);
    }

    #[test]
    fn inject_strings_on_none_is_empty() {
        assert_eq!(inject_strings(None), Vec::<String>::new());
    }

    #[test]
    fn injected_placeholders_extracts_field_names_from_an_inject_rule() {
        let rule = InjectRule {
            headers: Some([("X-Api-Key".to_string(), "{{key}}".to_string())].into()),
            query: None,
            basic: None,
        };
        assert_eq!(injected_placeholders(Some(&rule)), vec!["key".to_string()]);
    }

    #[test]
    fn builtin_templates_cover_the_four_generic_http_auth_shapes() {
        for id in ["bearer", "header", "query", "basic"] {
            let tpl = get_template(id).unwrap_or_else(|| panic!("missing builtin template {id}"));
            assert_eq!(tpl.source, "builtin");
            assert_eq!(tpl.kind, "static");
        }
    }

    #[test]
    fn get_template_is_case_insensitive_and_trims_whitespace() {
        assert!(get_template("BEARER").is_some());
        assert!(get_template("  bearer  ").is_some());
        assert!(get_template("does-not-exist").is_none());
    }

    /// The templates shipped in the repository -- not the installed copy under
    /// `kv_platform::paths::TEMPLATES_DIR`, which doesn't exist on machines without KeyValet.
    fn merged_with_repo_catalog() -> Vec<CredentialTemplate> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../templates");
        merge_templates(
            builtin_templates()
                .into_iter()
                .chain(load_catalog_from(&dir, "catalog.json"))
                .chain(load_catalog_from(&dir, "n8n-catalog.json")),
        )
    }

    #[test]
    fn the_bundled_catalog_is_loaded_alongside_the_builtins() {
        // "openai" comes from templates/catalog.json, not builtin_templates() -- this is the
        // only way to tell the catalog actually got merged in, not just the 4 generic templates.
        let merged = merged_with_repo_catalog();
        let tpl = merged
            .iter()
            .find(|t| t.id == "openai")
            .expect("bundled catalog should include openai");
        assert_eq!(tpl.source, "catalog");
        assert_eq!(tpl.hosts, vec!["api.openai.com".to_string()]);
    }

    #[test]
    fn search_templates_ranks_exact_match_above_prefix_above_contains() {
        // "basic" is an exact id match; anything just starting with or containing "basic" (if
        // the catalog ever grows one) must rank below it. Bearer is unrelated and shouldn't
        // appear in a search for "basic".
        let results = search_templates(Some("basic"), None, 10);
        assert_eq!(results[0].id, "basic");
        assert!(!results.iter().any(|t| t.id == "bearer"));
    }

    #[test]
    fn search_templates_respects_the_kind_filter_and_limit() {
        let merged = merged_with_repo_catalog();
        let all_static = search_in(&merged, None, Some("static"), 1000);
        assert!(all_static.iter().all(|t| t.kind == "static"));
        assert!(
            all_static.len() > 4,
            "expects the catalog to be loaded too, not just builtins"
        );

        let limited = search_in(&merged, None, Some("static"), 2);
        assert_eq!(limited.len(), 2);
    }

    #[test]
    fn search_templates_with_an_unknown_kind_returns_nothing() {
        assert!(search_templates(Some("bearer"), Some("nonexistent-kind"), 10).is_empty());
    }

    #[test]
    fn summarize_labels_proxy_support_by_template_shape() {
        let storage_only = summarize(&storage_only_template());
        assert_eq!(
            storage_only["proxy"],
            kv_i18n::t("不可代理（仅存储）", "Not proxyable (storage only)")
        );
        assert_eq!(storage_only["can_test"], false);

        let bearer = get_template("bearer").unwrap();
        let injectable = summarize(bearer);
        assert_eq!(injectable["proxy"], kv_i18n::t("可代理调用", "Proxyable"));

        let mut oauth_tpl = storage_only_template();
        oauth_tpl.kind = "oauth2".into();
        let oauth = summarize(&oauth_tpl);
        assert_eq!(
            oauth["proxy"],
            kv_i18n::t(
                "授权后可代理（需设置允许的域名）",
                "Proxyable after authorization (allowed hosts must be set)"
            )
        );
    }

    #[test]
    fn summarize_only_lists_field_names_that_are_secret() {
        let tpl = get_template("header").unwrap(); // headerName (not secret), key (secret)
        let summary = summarize(tpl);
        assert_eq!(summary["secret_fields"], serde_json::json!(["key"]));
    }

    #[test]
    fn template_detail_includes_the_full_field_list_and_a_how_to_use_hint() {
        let tpl = get_template("bearer").unwrap();
        let detail = template_detail(tpl);
        assert_eq!(detail["source"], "builtin");
        assert!(detail["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["name"] == "token"));
        assert!(
            detail["how_to_use"]
                .as_str()
                .unwrap()
                .contains("credential_set"),
            "static templates should be told to use credential_set, not credential_oauth_login"
        );
    }

    #[test]
    fn template_detail_for_an_oauth2_template_points_at_oauth_login_instead() {
        let mut oauth_tpl = storage_only_template();
        oauth_tpl.id = "test-oauth".into();
        oauth_tpl.kind = "oauth2".into();
        let detail = template_detail(&oauth_tpl);
        assert!(detail["how_to_use"]
            .as_str()
            .unwrap()
            .contains("credential_oauth_login"));
        assert!(detail["how_to_use"]
            .as_str()
            .unwrap()
            .contains("test-oauth"));
    }

    #[test]
    fn resolve_oauth_provider_finds_a_builtin_preset_by_exact_name() {
        // resolve_preset's lookup is case-sensitive (a plain HashMap::get, unlike
        // get_template's lowercased lookup) -- this documents the real behavior rather than
        // assuming case-insensitivity.
        assert!(resolve_oauth_provider("github", None).unwrap().is_some());
    }

    #[test]
    fn resolve_oauth_provider_returns_none_for_an_unknown_provider() {
        assert!(resolve_oauth_provider("not-a-real-provider", None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn oauth_provider_names_lists_the_builtin_presets() {
        let names = oauth_provider_names();
        assert!(names.contains("google"));
        assert!(names.contains("github"));
    }
}
