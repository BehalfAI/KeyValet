//! Validation and rendering for proxy call configuration (inside the root helper). The
//! configuration is saved encrypted alongside the credential; the agent can only modify it through
//! the helper, and sensitive changes such as expanding the domain list require user confirmation.
//! Direct port of src/helper/http-config.ts.

use kv_vault::{
    BasicAuth, CredentialRecord, HttpConfig, InjectRule, Kind, TestRequest, VaultError,
};
use serde_json::Value;
use std::sync::LazyLock;

static HOST_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")
        .unwrap()
});
static HEADER_NAME_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$").unwrap());
static QUERY_NAME_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[A-Za-z0-9_.\-\[\]]{1,100}$").unwrap());
static PLACEHOLDER_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}").unwrap());
const METHODS: [&str; 6] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"];

/// Allowed hosts: only domain names are accepted (not IPs or localhost), to prevent the proxy from
/// being used to reach local/internal services.
pub fn normalize_hosts(v: &Value) -> kv_vault::Result<Vec<String>> {
    let arr = v.as_array().filter(|a| !a.is_empty() && a.len() <= 20);
    let Some(arr) = arr else {
        return Err(VaultError::new(
            "allowed_hosts 必须是 1~20 个域名",
            "allowed_hosts must contain 1-20 domain names",
        ));
    };
    let mut set = std::collections::BTreeSet::new();
    for h in arr {
        let s = h
            .as_str()
            .map(|s| s.trim().to_lowercase().trim_end_matches('.').to_string())
            .unwrap_or_default();
        let loopback_ok = kv_protocols::http::insecure_loopback_allowed() && s == "127.0.0.1";
        if !(HOST_RE.is_match(&s) || loopback_ok) {
            let shown = h.as_str().unwrap_or_default();
            return Err(VaultError::new(
                &format!("非法的域名 \"{shown}\"（只接受域名，如 api.example.com 或 *.example.com）"),
                &format!("Invalid domain \"{shown}\" (only domain names are accepted, e.g. api.example.com or *.example.com)"),
            ));
        }
        set.insert(s);
    }
    Ok(set.into_iter().collect())
}

pub fn host_allowed(host: &str, allowed: &[String]) -> bool {
    let h = host.to_lowercase();
    allowed.iter().any(|a| {
        if let Some(suffix) = a.strip_prefix("*.") {
            h.ends_with(suffix) && h.len() > suffix.len()
        } else {
            h == *a
        }
    })
}

fn check_str_record(
    v: Option<&Value>,
    what: &str,
    key_re: &regex::Regex,
) -> kv_vault::Result<Option<std::collections::HashMap<String, String>>> {
    let obj = match v {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Object(o)) => o,
        _ => {
            return Err(VaultError::new(
                &format!("{what} 必须是对象"),
                &format!("{what} must be an object"),
            ))
        }
    };
    if obj.len() > 20 {
        return Err(VaultError::new(
            &format!("{what} 最多 20 项"),
            &format!("{what} may have at most 20 entries"),
        ));
    }
    let mut out = std::collections::HashMap::new();
    for (k, x) in obj {
        let placeholder_stripped = PLACEHOLDER_RE.replace_all(k, "x");
        if !key_re.is_match(&placeholder_stripped) {
            return Err(VaultError::new(
                &format!("{what} 的名称 \"{k}\" 非法"),
                &format!("Invalid {what} name \"{k}\""),
            ));
        }
        let Some(s) = x.as_str().filter(|s| s.len() <= 2000) else {
            return Err(VaultError::new(
                &format!("{what}.{k} 必须是字符串"),
                &format!("{what}.{k} must be a string"),
            ));
        };
        out.insert(k.clone(), s.to_string());
    }
    Ok(if out.is_empty() { None } else { Some(out) })
}

/// Field sources: secret fields + non-sensitive attributes + value.
#[derive(Debug, Clone, Default)]
pub struct FieldValues {
    pub secrets: std::collections::HashMap<String, String>,
    pub attributes: std::collections::HashMap<String, String>,
    pub value: String,
}

pub fn field_values(rec: &CredentialRecord) -> FieldValues {
    // A protocol credential's long-lived secrets (client secret, refresh token, private key, ...)
    // never participate in placeholder rendering.
    if rec.kind_or_static() != Kind::Static {
        return FieldValues {
            secrets: Default::default(),
            attributes: rec.attributes.clone(),
            value: String::new(),
        };
    }
    FieldValues {
        secrets: rec.secrets.clone().unwrap_or_default(),
        attributes: rec.attributes.clone(),
        value: rec.value.clone(),
    }
}

fn is_secret_field(f: &FieldValues, name: &str) -> bool {
    f.secrets.contains_key(name) || (name == "value" && !f.value.is_empty())
}

fn lookup<'a>(f: &'a FieldValues, name: &str) -> Option<&'a str> {
    if let Some(v) = f.secrets.get(name) {
        return Some(v);
    }
    if let Some(v) = f.attributes.get(name) {
        return Some(v);
    }
    if name == "value" && !f.value.is_empty() {
        return Some(&f.value);
    }
    None
}

pub fn placeholders(values: &[&str]) -> Vec<String> {
    let mut out = std::collections::HashSet::new();
    let mut ordered = Vec::new();
    for v in values {
        for cap in PLACEHOLDER_RE.captures_iter(v) {
            let name = cap[1].to_string();
            if out.insert(name.clone()) {
                ordered.push(name);
            }
        }
    }
    ordered
}

pub fn render(tpl: &str, f: &FieldValues) -> kv_vault::Result<String> {
    let mut err = None;
    let result = PLACEHOLDER_RE.replace_all(tpl, |cap: &regex::Captures| {
        let n = &cap[1];
        match lookup(f, n) {
            Some(v) => v.to_string(),
            None => {
                err = Some(VaultError::new(
                    &format!("缺少字段 {n}"),
                    &format!("Missing field {n}"),
                ));
                String::new()
            }
        }
    });
    if let Some(e) = err {
        return Err(e);
    }
    Ok(result.to_string())
}

/// Placeholders in names (header names/parameter names) may only reference non-sensitive fields,
/// and are expanded to fixed values at configuration time.
fn expand_keys(
    rec: Option<&std::collections::HashMap<String, String>>,
    f: &FieldValues,
    what: &str,
) -> kv_vault::Result<Option<std::collections::HashMap<String, String>>> {
    let Some(rec) = rec else { return Ok(None) };
    let mut out = std::collections::HashMap::new();
    for (k, v) in rec {
        let mut err = None;
        let key = PLACEHOLDER_RE.replace_all(k, |cap: &regex::Captures| {
            let n = &cap[1];
            match f.attributes.get(n) {
                Some(v) => v.clone(),
                None => {
                    err = Some(VaultError::new(
                        &format!("{what} 的名称只能引用非敏感字段（{n}）"),
                        &format!("{what} names may only reference non-secret fields ({n})"),
                    ));
                    String::new()
                }
            }
        });
        if let Some(e) = err {
            return Err(e);
        }
        out.insert(key.to_string(), v.clone());
    }
    Ok(Some(out))
}

pub fn validate_inject(
    raw: Option<&Value>,
    f: &FieldValues,
) -> kv_vault::Result<Option<InjectRule>> {
    let Some(raw) = raw.filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let r = raw
        .as_object()
        .ok_or_else(|| VaultError::new("inject 必须是对象", "inject must be an object"))?;
    let headers = expand_keys(
        check_str_record(r.get("headers"), "inject.headers", &HEADER_NAME_RE)?.as_ref(),
        f,
        &kv_i18n::t("请求头", "Header"),
    )?;
    let query = expand_keys(
        check_str_record(r.get("query"), "inject.query", &QUERY_NAME_RE)?.as_ref(),
        f,
        &kv_i18n::t("查询参数", "Query parameter"),
    )?;
    let mut rule = InjectRule::default();
    if let Some(headers) = &headers {
        for k in headers.keys() {
            if !HEADER_NAME_RE.is_match(k) {
                return Err(VaultError::new(
                    &format!("请求头名称 \"{k}\" 非法"),
                    &format!("Invalid header name \"{k}\""),
                ));
            }
            if matches!(
                k.to_lowercase().as_str(),
                "host" | "content-length" | "transfer-encoding" | "connection"
            ) {
                return Err(VaultError::new(
                    &format!("不能注入请求头 {k}"),
                    &format!("Header {k} cannot be injected"),
                ));
            }
        }
        rule.headers = Some(headers.clone());
    }
    if query.is_some() {
        rule.query = query;
    }
    if let Some(b) = r.get("basic").filter(|v| !v.is_null()) {
        let (Some(username), Some(password)) = (
            b.get("username").and_then(Value::as_str),
            b.get("password").and_then(Value::as_str),
        ) else {
            return Err(VaultError::new(
                "inject.basic 需要 username 和 password",
                "inject.basic requires username and password",
            ));
        };
        rule.basic = Some(BasicAuth {
            username: username.to_string(),
            password: password.to_string(),
        });
    }
    if rule.headers.is_none() && rule.query.is_none() && rule.basic.is_none() {
        return Err(VaultError::new(
            "inject 至少要有 headers、query 或 basic 之一",
            "inject must have at least one of headers, query, or basic",
        ));
    }
    let inject_strings = inject_strings(&rule);
    let refs: Vec<&str> = inject_strings.iter().map(String::as_str).collect();
    for n in placeholders(&refs) {
        if lookup(f, &n).is_none() {
            return Err(VaultError::new(
                &format!("注入规则引用了不存在的字段 {n}"),
                &format!("Injection rule references nonexistent field {n}"),
            ));
        }
    }
    Ok(Some(rule))
}

pub fn inject_strings(rule: &InjectRule) -> Vec<String> {
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

/// Validates the test request. `allow_secrets=false` (when modifying via credential_configure_http)
/// forbids referencing secret fields: otherwise a secret could be placed into the URL and then
/// exfiltrated via an error message or upstream echo. Only a template test request written
/// alongside a new secret (e.g. Trello's /tokens/{{apiToken}}) is allowed to reference secrets.
pub fn validate_test(
    raw: Option<&Value>,
    f: &FieldValues,
    allow_secrets: bool,
) -> kv_vault::Result<Option<TestRequest>> {
    let Some(raw) = raw.filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let method = raw
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET")
        .to_uppercase();
    if !METHODS.contains(&method.as_str()) {
        return Err(VaultError::new("test.method 非法", "Invalid test.method"));
    }
    let Some(url) = raw
        .get("url")
        .and_then(Value::as_str)
        .filter(|s| s.len() <= 2000)
    else {
        return Err(VaultError::new(
            "test.url 必须是字符串",
            "test.url must be a string",
        ));
    };
    let headers = check_str_record(raw.get("headers"), "test.headers", &HEADER_NAME_RE)?;
    let query = check_str_record(raw.get("query"), "test.query", &QUERY_NAME_RE)?;
    if !allow_secrets && method != "GET" && method != "HEAD" {
        return Err(VaultError::new(
            "自定义验证请求只能是 GET 或 HEAD",
            "A custom test request must be GET or HEAD",
        ));
    }
    let mut refs = vec![url.to_string()];
    if let Some(h) = &headers {
        refs.extend(h.keys().cloned());
        refs.extend(h.values().cloned());
    }
    if let Some(q) = &query {
        refs.extend(q.keys().cloned());
        refs.extend(q.values().cloned());
    }
    let ref_strs: Vec<&str> = refs.iter().map(String::as_str).collect();
    for n in placeholders(&ref_strs) {
        if lookup(f, &n).is_none() {
            return Err(VaultError::new(
                &format!("验证请求引用了不存在的字段 {n}"),
                &format!("Test request references nonexistent field {n}"),
            ));
        }
        if !allow_secrets && is_secret_field(f, &n) {
            return Err(VaultError::new(
                &format!("自定义验证请求不能引用秘密字段 {n}（认证由注入规则完成）"),
                &format!("A custom test request cannot reference secret field {n} (authentication is handled by the injection rule)"),
            ));
        }
    }
    Ok(Some(TestRequest {
        method,
        url: url.to_string(),
        headers,
        query,
    }))
}

pub struct ValidateOpts<'a> {
    pub allow_secrets_in_test: bool,
    pub prev_test: Option<&'a TestRequest>,
}

/// Validates the full proxy configuration. Token-based credentials (oauth2, etc.) inject
/// `Authorization: Bearer <token>` by default; a custom injection rule can also be defined, using
/// `{{access_token}}` to reference the current short-lived token (e.g. GitHub's git push requires
/// Basic auth: `{"basic": {"username": "x-access-token", "password": "{{access_token}}"}}`).
pub fn validate_http_config(
    raw: &Value,
    rec: &CredentialRecord,
    opts: ValidateOpts,
) -> kv_vault::Result<HttpConfig> {
    let r = raw
        .as_object()
        .ok_or_else(|| VaultError::new("http 配置必须是对象", "http config must be an object"))?;
    let kind = rec.kind_or_static();
    let base = field_values(rec);
    // Token-based credentials: may only reference the current short-lived token (long-lived
    // secrets don't participate in rendering) and non-sensitive fields.
    let f = if kind == Kind::Static {
        base
    } else {
        let mut secrets = std::collections::HashMap::new();
        secrets.insert("access_token".to_string(), "<access_token>".to_string());
        FieldValues { secrets, ..base }
    };
    let inject = validate_inject(r.get("inject"), &f)?;
    if kind == Kind::Static && inject.is_none() {
        return Err(VaultError::new(
            "static 凭证的代理调用需要注入规则（inject）",
            "Proxied calls with a static credential require an injection rule (inject)",
        ));
    }
    if !matches!(
        kind,
        Kind::Static | Kind::Oauth2 | Kind::GoogleServiceAccount | Kind::GithubApp | Kind::Jwt
    ) {
        return Err(VaultError::new(
            &format!("{} 凭证不支持代理调用", kind.as_str()),
            &format!("{} credentials do not support proxied calls", kind.as_str()),
        ));
    }
    let allowed_hosts = normalize_hosts(r.get("allowed_hosts").unwrap_or(&Value::Null))?;
    let proxy_only = r
        .get("proxy_only")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // Reuse the existing test request (already validated when it was written); a newly supplied one
    // is validated per allow_secrets_in_test.
    let test_val = r.get("test");
    let test = if let (Some(prev), Some(tv)) = (opts.prev_test, test_val) {
        if serde_json::to_value(prev).ok().as_ref() == Some(tv) {
            Some(prev.clone())
        } else {
            validate_test(test_val, &f, opts.allow_secrets_in_test)?
        }
    } else if test_val.is_some_and(|v| !v.is_null()) {
        validate_test(test_val, &f, opts.allow_secrets_in_test)?
    } else {
        None
    };
    Ok(HttpConfig {
        inject,
        allowed_hosts,
        proxy_only,
        test,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn static_rec() -> CredentialRecord {
        // Not `..Default::default()`: CredentialRecord's Drop impl means the compiler can't move
        // fields out of a temporary Default::default() for struct-update syntax either, so every
        // field is listed explicitly instead.
        CredentialRecord {
            kind: None,
            value: "secret-value".into(),
            config: None,
            secrets: None,
            state: None,
            generation: None,
            http: None,
            template: None,
            description: String::new(),
            attributes: [("subdomain".to_string(), "api".to_string())].into(),
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    #[test]
    fn normalize_hosts_rejects_ips_and_too_many_entries() {
        assert!(normalize_hosts(&json!(["api.example.com", "*.example.com"])).is_ok());
        assert!(normalize_hosts(&json!(["127.0.0.1"])).is_err());
        assert!(normalize_hosts(&json!([])).is_err());
    }

    #[test]
    fn host_allowed_matches_wildcard_subdomains_only() {
        let allowed = vec!["*.example.com".to_string(), "api.other.com".to_string()];
        assert!(host_allowed("foo.example.com", &allowed));
        assert!(
            !host_allowed("example.com", &allowed),
            "the wildcard doesn't match the bare domain itself"
        );
        assert!(host_allowed("api.other.com", &allowed));
        assert!(!host_allowed("evilapi.other.com", &allowed));
    }

    #[test]
    fn render_substitutes_known_fields_and_rejects_unknown_ones() {
        let f = field_values(&static_rec());
        assert_eq!(
            render("https://{{subdomain}}.example.com/v1?key={{value}}", &f).unwrap(),
            "https://api.example.com/v1?key=secret-value"
        );
        assert!(render("{{missing}}", &f).is_err());
    }

    #[test]
    fn validate_inject_requires_at_least_one_rule_and_checks_header_names() {
        let f = field_values(&static_rec());
        assert!(validate_inject(Some(&json!({})), &f).is_err());
        assert!(validate_inject(
            Some(&json!({"headers": {"Authorization": "Bearer {{value}}"}})),
            &f
        )
        .unwrap()
        .is_some());
        assert!(
            validate_inject(Some(&json!({"headers": {"Host": "evil"}})), &f).is_err(),
            "Host cannot be injected"
        );
    }

    #[test]
    fn validate_test_forbids_secret_fields_and_non_get_unless_allowed() {
        let f = field_values(&static_rec());
        assert!(
            validate_test(
                Some(&json!({"method": "GET", "url": "https://example.com/{{value}}"})),
                &f,
                false
            )
            .is_err(),
            "value is a secret field (non-empty)"
        );
        assert!(validate_test(
            Some(&json!({"method": "POST", "url": "https://example.com"})),
            &f,
            false
        )
        .is_err());
        assert!(validate_test(
            Some(&json!({"method": "GET", "url": "https://example.com/{{subdomain}}"})),
            &f,
            false
        )
        .unwrap()
        .is_some());
    }

    #[test]
    fn validate_http_config_requires_inject_for_static_credentials() {
        let rec = static_rec();
        let err = validate_http_config(
            &json!({"allowed_hosts": ["example.com"]}),
            &rec,
            ValidateOpts {
                allow_secrets_in_test: false,
                prev_test: None,
            },
        );
        assert!(err.is_err());
        let ok = validate_http_config(
            &json!({"allowed_hosts": ["example.com"], "inject": {"headers": {"Authorization": "Bearer {{value}}"}}}),
            &rec,
            ValidateOpts {
                allow_secrets_in_test: false,
                prev_test: None,
            },
        );
        assert!(ok.is_ok());
    }
}
