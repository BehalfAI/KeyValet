//! Proxied calls: inject the credential into the HTTP request and send it from inside the root
//! helper; the agent only receives the response and never sees the secret. Direct port of
//! src/helper/http-proxy.ts.
//! - Only https is allowed, on the default port, with the target host in that credential's allowed_hosts
//! - Redirects are not followed (3xx is returned as-is; the agent can issue a further request itself
//!   if needed, still subject to the same host restriction)
//! - Secrets appearing in the response (including base64 / URL-encoded forms) are replaced with [REDACTED]

use crate::config::{field_values, host_allowed, render};
use crate::redact::{contains_secret, redact, redaction_list};
use futures_util::StreamExt;
use kv_protocols::index::{access_token, AccessTokenParams};
use kv_vault::{CredentialRecord, Vault, VaultError};
use serde_json::Value;
use std::sync::LazyLock;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_millis(180_000); // LLM streaming responses can last several minutes
const MAX_RESPONSE_BYTES: usize = 5 * 1024 * 1024;
const MAX_RETURN_CHARS: usize = 256 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const METHODS: [&str; 6] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"];

pub const FORBIDDEN_HEADERS: [&str; 8] = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "trailer",
    "proxy-authorization",
];
const TOKEN_KINDS: [kv_vault::Kind; 4] = [
    kv_vault::Kind::Oauth2,
    kv_vault::Kind::GoogleServiceAccount,
    kv_vault::Kind::GithubApp,
    kv_vault::Kind::Jwt,
];

static RETURN_HEADERS: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)^(content-type|content-length|location|retry-after|etag|last-modified|link|x-ratelimit-.*|ratelimit-.*|x-request-id|request-id)$").unwrap()
});
static TEXTUAL: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)^(text/|application/(json|xml|javascript|x-www-form-urlencoded|[a-z.+-]*\+(json|xml)))").unwrap()
});
static HEADER_NAME_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$").unwrap());

/// Parses an SSE (text/event-stream) response and extracts incremental text from common LLM
/// streaming formats: OpenAI Chat Completions (choices[].delta.content), OpenAI Responses
/// (response.output_text.delta), Anthropic (content_block_delta.delta.text), Gemini
/// (candidates[].content.parts[].text).
pub fn aggregate_sse(raw: &str) -> (usize, Option<String>) {
    let mut events = 0;
    let mut text = String::new();
    let mut recognized = false;
    for block in regex_split(raw, r"\r?\n\r?\n") {
        let data: String = regex_split(block, r"\r?\n")
            .into_iter()
            .filter(|l| l.starts_with("data:"))
            .map(|l| l[5..].strip_prefix(' ').unwrap_or(&l[5..]))
            .collect::<Vec<_>>()
            .join("\n");
        if data.is_empty() {
            continue;
        }
        events += 1;
        if data == "[DONE]" {
            continue;
        }
        let Ok(j) = serde_json::from_str::<Value>(&data) else {
            continue;
        };
        let mut pieces: Vec<Option<&str>> = Vec::new();
        if let Some(choices) = j.get("choices").and_then(Value::as_array) {
            for c in choices {
                pieces.push(
                    c.get("delta")
                        .and_then(|d| d.get("content"))
                        .and_then(Value::as_str),
                );
                pieces.push(c.get("text").and_then(Value::as_str));
            }
        }
        if j.get("type").and_then(Value::as_str) == Some("response.output_text.delta") {
            pieces.push(j.get("delta").and_then(Value::as_str));
        }
        if j.get("type").and_then(Value::as_str) == Some("content_block_delta") {
            pieces.push(
                j.get("delta")
                    .and_then(|d| d.get("text"))
                    .and_then(Value::as_str),
            );
        }
        if let Some(candidates) = j.get("candidates").and_then(Value::as_array) {
            for c in candidates {
                if let Some(parts) = c
                    .get("content")
                    .and_then(|c| c.get("parts"))
                    .and_then(Value::as_array)
                {
                    for part in parts {
                        pieces.push(part.get("text").and_then(Value::as_str));
                    }
                }
            }
        }
        for p in pieces.into_iter().flatten() {
            text.push_str(p);
            recognized = true;
        }
    }
    (events, if recognized { Some(text) } else { None })
}

fn regex_split<'a>(s: &'a str, pattern: &str) -> Vec<&'a str> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, regex::Regex>>,
    > = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut guard = cache.lock().unwrap();
    let re = guard
        .entry(pattern.to_string())
        .or_insert_with(|| regex::Regex::new(pattern).unwrap());
    re.split(s).collect()
}

#[derive(Debug, Clone, Default)]
pub struct ProxyInput {
    pub method: Option<String>,
    pub url: String,
    pub headers: std::collections::HashMap<String, String>,
    pub query: std::collections::HashMap<String, String>,
    pub body: Option<Value>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProxyResult {
    pub status: u16,
    pub headers: std::collections::HashMap<String, String>,
    pub body: String,
    pub body_encoding: &'static str,
    pub truncated: bool,
    /// SSE streaming response: the event count, and the full text assembled from LLM deltas
    /// (already redacted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<StreamInfo>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StreamInfo {
    pub events: usize,
    pub text: Option<String>,
}

/// The target of a proxied request (for auditing: records only method + host + path, not query parameters).
pub fn describe_target(method: Option<&str>, url: &str) -> Option<String> {
    let u = url::Url::parse(url).ok()?;
    let s = format!(
        "{} {}{}",
        method.unwrap_or("GET").to_uppercase(),
        u.host_str().unwrap_or_default(),
        u.path()
    );
    Some(s.chars().take(300).collect())
}

fn check_url(raw: &str, allowed: &[String]) -> kv_vault::Result<url::Url> {
    if raw.len() > 8000 {
        return Err(VaultError::new("url 必须是字符串", "url must be a string"));
    }
    let u = url::Url::parse(raw).map_err(|_| VaultError::new("url 不合法", "Invalid url"))?; // don't echo back the URL: it may have been rendered from a secret
    let test_loopback = kv_protocols::http::insecure_loopback_allowed()
        && u.scheme() == "http"
        && u.host_str() == Some("127.0.0.1"); // test only
    if u.scheme() != "https" && !test_loopback {
        return Err(VaultError::new(
            "代理调用只允许 https",
            "Proxied calls only allow https",
        ));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(VaultError::new(
            "url 不能包含用户名或密码",
            "url must not contain a username or password",
        ));
    }
    if let Some(port) = u.port() {
        if port != 443 && !test_loopback {
            return Err(VaultError::new(
                "代理调用只允许默认端口 443",
                "Proxied calls only allow the default port 443",
            ));
        }
    }
    let host = u.host_str().unwrap_or_default();
    if !host_allowed(host, allowed) {
        let joined = allowed.join(&kv_i18n::t("、", ", "));
        return Err(VaultError::new(
            &format!("域名 {host} 不在该凭证允许的范围内（{joined}）；如需新增请用 credential_configure_http"),
            &format!("Host {host} is not allowed for this credential ({joined}); use credential_configure_http to add it"),
        ));
    }
    Ok(u)
}

pub struct Injection {
    pub headers: std::collections::HashMap<String, String>,
    pub query: std::collections::HashMap<String, String>,
    pub redactions: Vec<Vec<u8>>,
}

/// Computes the headers and query parameters to inject, along with the secrets that need to be stripped.
pub async fn build_injection(
    vault: &Vault,
    ty: &str,
    name: &str,
    rec: &CredentialRecord,
) -> kv_vault::Result<Injection> {
    let mut headers = std::collections::HashMap::new();
    let mut query = std::collections::HashMap::new();
    let mut secrets: Vec<String> = Vec::new();
    let kind = rec.kind_or_static();
    // All long-lived secrets are added to the redaction list (so they won't leak even if upstream echoes them back).
    secrets.extend(rec.secrets.clone().unwrap_or_default().into_values());
    if !rec.value.is_empty() {
        secrets.push(rec.value.clone());
    }
    if TOKEN_KINDS.contains(&kind) {
        let tok = access_token(
            vault,
            ty,
            name,
            AccessTokenParams {
                scopes: vec![],
                repositories: vec![],
                permissions: None,
                force: false,
                via_proxy: true,
            },
        )
        .await?;
        let access_token_str = tok
            .get("access_token")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        secrets.push(access_token_str.clone());
        match rec.http.as_ref().and_then(|h| h.inject.as_ref()) {
            None => {
                headers.insert(
                    "Authorization".to_string(),
                    format!("Bearer {access_token_str}"),
                );
            }
            Some(rule) => {
                // Custom injection rule: {{access_token}} references the current token.
                let f = crate::config::FieldValues {
                    secrets: [("access_token".to_string(), access_token_str)].into(),
                    attributes: rec.attributes.clone(),
                    value: String::new(),
                };
                if let Some(h) = &rule.headers {
                    for (k, v) in h {
                        headers.insert(k.clone(), render(v, &f)?);
                    }
                }
                if let Some(q) = &rule.query {
                    for (k, v) in q {
                        query.insert(k.clone(), render(v, &f)?);
                    }
                }
                if let Some(basic) = &rule.basic {
                    use base64::engine::{general_purpose::STANDARD, Engine};
                    let b = STANDARD.encode(format!(
                        "{}:{}",
                        render(&basic.username, &f)?,
                        render(&basic.password, &f)?
                    ));
                    headers.insert("Authorization".to_string(), format!("Basic {b}"));
                    secrets.push(b);
                }
                secrets.extend(headers.values().cloned());
                secrets.extend(query.values().cloned());
            }
        }
    } else {
        let rule = rec
            .http
            .as_ref()
            .and_then(|h| h.inject.as_ref())
            .ok_or_else(|| {
                VaultError::new(
                    "该凭证没有注入规则",
                    "This credential has no injection rule",
                )
            })?;
        let f = field_values(rec);
        secrets.extend(f.secrets.values().cloned());
        if !f.value.is_empty() {
            secrets.push(f.value.clone());
        }
        if let Some(h) = &rule.headers {
            for (k, v) in h {
                headers.insert(k.clone(), render(v, &f)?);
            }
        }
        if let Some(q) = &rule.query {
            for (k, v) in q {
                query.insert(k.clone(), render(v, &f)?);
            }
        }
        if let Some(basic) = &rule.basic {
            use base64::engine::{general_purpose::STANDARD, Engine};
            let b = STANDARD.encode(format!(
                "{}:{}",
                render(&basic.username, &f)?,
                render(&basic.password, &f)?
            ));
            headers.insert("Authorization".to_string(), format!("Basic {b}"));
            secrets.push(b);
        }
        secrets.extend(headers.values().cloned());
        secrets.extend(query.values().cloned());
    }
    let refs: Vec<&str> = secrets.iter().map(String::as_str).collect();
    Ok(Injection {
        headers,
        query,
        redactions: redaction_list(&refs),
    })
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(TIMEOUT)
        .build()
        .expect("TLS backend must be available")
}

pub async fn proxy_request(
    vault: &Vault,
    ty: &str,
    name: &str,
    p: ProxyInput,
) -> kv_vault::Result<ProxyResult> {
    let (_, _, record) = vault.get_record(ty, name)?;
    let mut baseline_values: Vec<String> = record
        .secrets
        .clone()
        .unwrap_or_default()
        .into_values()
        .collect();
    if !record.value.is_empty() {
        baseline_values.push(record.value.clone());
    }
    let baseline_refs: Vec<&str> = baseline_values.iter().map(String::as_str).collect();
    let baseline = redaction_list(&baseline_refs);
    match proxy_request_inner(vault, ty, name, p).await {
        Ok(r) => Ok(r),
        // Any error message is redacted before being returned (and before being written to the audit log).
        Err(e) => Err(VaultError(
            String::from_utf8_lossy(&redact(e.0.as_bytes(), &baseline)).to_string(),
        )),
    }
}

async fn proxy_request_inner(
    vault: &Vault,
    ty: &str,
    name: &str,
    p: ProxyInput,
) -> kv_vault::Result<ProxyResult> {
    let (ty, name, record) = vault.get_record(ty, name)?;
    let Some(http) = &record.http else {
        return Err(VaultError::new(
            &format!("\"{ty}/{name}\" 没有配置代理调用，请先用 credential_configure_http 设置允许的域名"),
            &format!("\"{ty}/{name}\" has no proxy configuration; set the allowed hosts with credential_configure_http first"),
        ));
    };
    let method = p
        .method
        .clone()
        .unwrap_or_else(|| "GET".to_string())
        .to_uppercase();
    if !METHODS.contains(&method.as_str()) {
        return Err(VaultError::new(
            &format!("不支持的方法 {method}"),
            &format!("Unsupported method {method}"),
        ));
    }
    let mut url = check_url(&p.url, &http.allowed_hosts)?;

    let mut agent_headers = p.headers.clone();
    {
        let mut qp = url.query_pairs_mut();
        for (k, v) in &p.query {
            qp.append_pair(k, v);
        }
    }
    let mut body: Option<String> = None;
    if p.body.is_some() && matches!(method.as_str(), "GET" | "HEAD") {
        return Err(VaultError::new(
            &format!("{method} 请求不能带请求体"),
            &format!("{method} requests cannot have a body"),
        ));
    }
    if let Some(b) = &p.body {
        let body_str = if let Value::String(s) = b {
            s.clone()
        } else {
            serde_json::to_string(b).unwrap()
        };
        if body_str.len() > MAX_BODY_BYTES {
            return Err(VaultError::new(
                "请求体过大（上限 1MB）",
                "Request body too large (limit 1MB)",
            ));
        }
        if !matches!(b, Value::String(_))
            && !agent_headers
                .keys()
                .any(|k| k.eq_ignore_ascii_case("content-type"))
        {
            agent_headers.insert("Content-Type".to_string(), "application/json".to_string());
        }
        body = Some(body_str);
    }

    let inj = build_injection(vault, &ty, &name, &record).await?;
    let mut headers: Vec<(String, String)> = vec![
        ("User-Agent".to_string(), "keyvalet/0.1".to_string()),
        ("Accept-Encoding".to_string(), "identity".to_string()),
    ];
    let injected: std::collections::HashSet<String> =
        inj.headers.keys().map(|k| k.to_lowercase()).collect();
    for (k, v) in &agent_headers {
        let lk = k.to_lowercase();
        if FORBIDDEN_HEADERS.contains(&lk.as_str()) || injected.contains(&lk) {
            continue;
        }
        if !HEADER_NAME_RE.is_match(k) {
            return Err(VaultError::new(
                &format!("请求头名称 \"{k}\" 非法"),
                &format!("Invalid header name \"{k}\""),
            ));
        }
        headers.push((k.clone(), v.clone()));
    }
    headers.extend(inj.headers.iter().map(|(k, v)| (k.clone(), v.clone())));
    {
        let mut qp = url.query_pairs_mut();
        for (k, v) in &inj.query {
            qp.append_pair(k, v);
        }
    }

    let mut req = client().request(method.parse().unwrap(), url.as_str());
    for (k, v) in &headers {
        req = req.header(k, v);
    }
    if let Some(b) = body.clone() {
        req = req.body(b);
    }
    let res = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            let detail =
                String::from_utf8_lossy(&redact(e.to_string().as_bytes(), &inj.redactions))
                    .to_string();
            let host = url.host_str().unwrap_or_default();
            return Err(VaultError::new(
                &format!("请求 {host} 失败：{detail}"),
                &format!("Request to {host} failed: {detail}"),
            ));
        }
    };
    let status = res.status().as_u16();
    let mut out_headers = std::collections::HashMap::new();
    for (k, v) in res.headers() {
        if RETURN_HEADERS.is_match(k.as_str()) {
            out_headers.insert(
                k.as_str().to_string(),
                String::from_utf8_lossy(&redact(v.as_bytes(), &inj.redactions)).to_string(),
            );
        }
    }
    let ctype = res
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let buf = read_limited(res, MAX_RESPONSE_BYTES, url.host_str().unwrap_or_default()).await?;
    let textual =
        TEXTUAL.is_match(&ctype) || (ctype.is_empty() && !buf.is_empty() && !buf.contains(&0));

    let mut text: String;
    let mut stream: Option<StreamInfo> = None;
    let body_encoding;
    if textual {
        // Redact before truncating, to avoid splitting a secret across the truncation point.
        text = String::from_utf8_lossy(&redact(&buf, &inj.redactions)).to_string();
        body_encoding = "text";
        if ctype.to_lowercase().starts_with("text/event-stream") {
            let (events, stream_text) = aggregate_sse(&text);
            // Redact once more after assembling: a secret may have been split across multiple
            // deltas, or appear as a JSON \uXXXX escape.
            let redacted_text = stream_text.map(|t| {
                String::from_utf8_lossy(&redact(t.as_bytes(), &inj.redactions)).to_string()
            });
            stream = Some(StreamInfo {
                events,
                text: redacted_text,
            });
        }
    } else {
        // Binary data can't be reliably redacted: refuse to return it if the raw bytes contain a
        // secret in any encoded form.
        if contains_secret(&buf, &inj.redactions) {
            return Err(VaultError::new("响应中包含凭证秘密，已拒绝返回该二进制响应", "The response contains a credential secret; refusing to return this binary response"));
        }
        use base64::engine::{general_purpose::STANDARD, Engine};
        text = STANDARD.encode(&buf);
        body_encoding = "base64";
    }
    let mut truncated = text.chars().count() > MAX_RETURN_CHARS;
    if truncated {
        text = text.chars().take(MAX_RETURN_CHARS).collect();
    }
    // When a streaming response has already been assembled into full text, keep only the leading
    // portion of the raw event stream (the agent usually just needs the text).
    if let Some(s) = &stream {
        if s.text.is_some() && text.chars().count() > 4000 {
            text = text.chars().take(4000).collect();
            truncated = true;
        }
    }
    Ok(ProxyResult {
        status,
        headers: out_headers,
        body: text,
        body_encoding,
        truncated,
        stream,
    })
}

async fn read_limited(
    res: reqwest::Response,
    limit: usize,
    host: &str,
) -> kv_vault::Result<Vec<u8>> {
    let mut stream = res.bytes_stream();
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            VaultError::new(
                &format!("{host} 的响应读取失败：{e}"),
                &format!("Failed to read the response from {host}: {e}"),
            )
        })?;
        out.extend_from_slice(&chunk);
        if out.len() > limit {
            return Err(VaultError::new(
                &format!("{host} 的响应过大"),
                &format!("Response from {host} is too large"),
            ));
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TestResult {
    pub ok: bool,
    pub status: u16,
    pub excerpt: String,
}

/// Checks whether a credential is usable via its test request.
pub async fn test_credential(vault: &Vault, ty: &str, name: &str) -> kv_vault::Result<TestResult> {
    let (ty, name, record) = vault.get_record(ty, name)?;
    let Some(test) = record.http.as_ref().and_then(|h| h.test.clone()) else {
        return Err(VaultError::new(
            &format!("\"{ty}/{name}\" 没有验证请求（模板未提供，可用 credential_configure_http 设置 test）"),
            &format!("\"{ty}/{name}\" has no test request (none provided by the template; set test with credential_configure_http)"),
        ));
    };
    let f = field_values(&record);
    let mut headers = std::collections::HashMap::new();
    for (k, v) in test.headers.unwrap_or_default() {
        headers.insert(k, render(&v, &f)?);
    }
    let mut query = std::collections::HashMap::new();
    for (k, v) in test.query.unwrap_or_default() {
        query.insert(k, render(&v, &f)?);
    }
    let r = proxy_request(
        vault,
        &ty,
        &name,
        ProxyInput {
            method: Some(test.method),
            url: render(&test.url, &f)?,
            headers,
            query,
            body: None,
        },
    )
    .await?;
    let ok = (200..300).contains(&r.status);
    let excerpt = if r.body_encoding == "text" {
        r.body.chars().take(500).collect()
    } else {
        kv_i18n::t(
            &format!("<{} 字节二进制>", r.body.len()),
            &format!("<{} bytes of binary>", r.body.len()),
        )
    };
    Ok(TestResult {
        ok,
        status: r.status,
        excerpt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_sse_recognizes_openai_chat_completions_deltas() {
        let raw = "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\ndata: [DONE]\n\n";
        let (events, text) = aggregate_sse(raw);
        assert_eq!(events, 3);
        assert_eq!(text, Some("Hello".to_string()));
    }

    #[test]
    fn aggregate_sse_recognizes_anthropic_and_gemini_and_unrecognized_is_none() {
        let anthropic = "data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\n";
        assert_eq!(aggregate_sse(anthropic).1, Some("hi".to_string()));
        let gemini = "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"yo\"}]}}]}\n\n";
        assert_eq!(aggregate_sse(gemini).1, Some("yo".to_string()));
        assert_eq!(aggregate_sse("data: {\"unrelated\":true}\n\n").1, None);
    }

    #[test]
    fn describe_target_strips_query_and_caps_length() {
        assert_eq!(
            describe_target(Some("post"), "https://api.example.com/v1/x?secret=abc").unwrap(),
            "POST api.example.com/v1/x"
        );
    }

    #[test]
    fn check_url_enforces_https_default_port_and_allowed_hosts() {
        let allowed = vec!["api.example.com".to_string()];
        assert!(check_url("https://api.example.com/v1", &allowed).is_ok());
        assert!(check_url("http://api.example.com/v1", &allowed).is_err());
        assert!(check_url("https://api.example.com:8443/v1", &allowed).is_err());
        assert!(check_url("https://evil.com/v1", &allowed).is_err());
        assert!(check_url("https://user:pass@api.example.com/v1", &allowed).is_err());
    }
}
