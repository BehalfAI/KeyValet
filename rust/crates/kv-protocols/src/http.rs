//! HTTP requests made by the root helper: only https is allowed, redirects are forbidden (to
//! prevent secrets from being forwarded elsewhere), and there is a timeout and a response size cap.
//! Direct port of src/helper/protocols/http.ts.

use futures_util::StreamExt;
use kv_vault::{scrub_json, VaultError};
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

const TIMEOUT: Duration = Duration::from_millis(15_000);
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const USER_AGENT: &str = "keyvalet/0.1";

static ALLOW_INSECURE_LOOPBACK: AtomicBool = AtomicBool::new(false);

/// Test-only: allow http://127.0.0.1 endpoints (never called from production code).
pub fn allow_insecure_loopback_for_tests(v: bool) {
    ALLOW_INSECURE_LOOPBACK.store(v, Ordering::SeqCst);
}

pub fn insecure_loopback_allowed() -> bool {
    ALLOW_INSECURE_LOOPBACK.load(Ordering::SeqCst)
}

pub fn assert_https_url(raw: &str, what: &str) -> kv_vault::Result<String> {
    let u = url::Url::parse(raw).map_err(|_| {
        VaultError::new(
            &format!("{what} 不是合法 URL：{raw}"),
            &format!("{what} is not a valid URL: {raw}"),
        )
    })?;
    let loopback_ok =
        insecure_loopback_allowed() && u.scheme() == "http" && u.host_str() == Some("127.0.0.1");
    if u.scheme() != "https" && !loopback_ok {
        return Err(VaultError::new(
            &format!("{what} 必须使用 https：{raw}"),
            &format!("{what} must use https: {raw}"),
        ));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(VaultError::new(
            &format!("{what} 不能包含用户名或密码"),
            &format!("{what} must not contain a username or password"),
        ));
    }
    Ok(u.to_string())
}

#[derive(Debug, Clone)]
pub struct HttpResult {
    pub status: u16,
    pub text: String,
    /// Parsed JSON (may be an object or array); `Value::Null` when the response isn't JSON (matches
    /// the TS `json: unknown` field's `null`-for-non-JSON convention).
    pub json: Value,
}

impl Drop for HttpResult {
    fn drop(&mut self) {
        self.text.zeroize();
        scrub_json(&mut self.json);
    }
}

/// Get the JSON object (returns an empty map when it isn't one), for convenient field access.
pub fn obj(r: &HttpResult) -> &serde_json::Map<String, Value> {
    static EMPTY: std::sync::LazyLock<serde_json::Map<String, Value>> =
        std::sync::LazyLock::new(serde_json::Map::new);
    r.json.as_object().unwrap_or(&EMPTY)
}

struct SecretBody(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for SecretBody {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(TIMEOUT)
        .build()
        .expect("TLS backend must be available")
}

pub enum Method {
    Get,
    Post,
}

pub async fn http_request(
    url: &str,
    method: Method,
    headers: &[(&str, &str)],
    body: Option<String>,
) -> kv_vault::Result<HttpResult> {
    let body =
        body.map(|body| bytes::Bytes::from_owner(SecretBody(Zeroizing::new(body.into_bytes()))));
    let url = assert_https_url(url, &kv_i18n::t("请求地址", "Request URL"))?;
    let host = url::Url::parse(&url)
        .map(|u| u.host_str().unwrap_or_default().to_string())
        .unwrap_or_default();
    let mut req = client().request(
        if matches!(method, Method::Get) {
            reqwest::Method::GET
        } else {
            reqwest::Method::POST
        },
        &url,
    );
    req = req
        .header("User-Agent", USER_AGENT)
        .header("Accept", "application/json")
        .header("Accept-Encoding", "identity");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    if let Some(b) = body {
        // Bytes keeps the zeroizing owner alive across reqwest/hyper body clones.
        req = req.body(b);
    }
    let res = req.send().await.map_err(|_| {
        VaultError::new(
            &format!("请求 {host} 失败"),
            &format!("Request to {host} failed"),
        )
    })?;
    let status = res.status().as_u16();
    let mut bytes = read_limited(res, MAX_RESPONSE_BYTES, &host).await?;
    let text = match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(text) => text,
        Err(error) => {
            let bytes = Zeroizing::new(error.into_bytes());
            String::from_utf8_lossy(&bytes).into_owned()
        }
    };
    let json = serde_json::from_str(&text).unwrap_or(Value::Null);
    Ok(HttpResult { status, text, json })
}

/// Count bytes while reading and abort as soon as the limit is exceeded (instead of reading
/// everything into memory first).
pub async fn read_limited(
    res: reqwest::Response,
    limit: usize,
    host: &str,
) -> kv_vault::Result<Zeroizing<Vec<u8>>> {
    let mut stream = res.bytes_stream();
    // Avoid reallocations leaving earlier copies of credential bytes in the allocator.
    let mut out = Zeroizing::new(Vec::with_capacity(limit));
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| {
            VaultError::new(
                &format!("{host} 的响应读取失败"),
                &format!("Failed to read the response from {host}"),
            )
        })?;
        if chunk.len() > limit - out.len() {
            return Err(VaultError::new(
                &format!("{host} 的响应过大"),
                &format!("Response from {host} is too large"),
            ));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

pub async fn post_form(
    url: &str,
    form: &[(&str, &str)],
    extra_headers: &[(&str, &str)],
) -> kv_vault::Result<HttpResult> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form)
        .finish();
    let mut headers = vec![("Content-Type", "application/x-www-form-urlencoded")];
    headers.extend_from_slice(extra_headers);
    http_request(url, Method::Post, &headers, Some(body)).await
}

/// Provider diagnostics can contain client secrets, refresh tokens, assertions or their encodings.
/// Return only HTTP status and a fixed OAuth error code; never return untrusted diagnostic text.
pub fn remote_error(host: &str, r: &HttpResult) -> VaultError {
    const CODES: &[&str] = &[
        "invalid_request",
        "invalid_client",
        "invalid_grant",
        "unauthorized_client",
        "unsupported_grant_type",
        "invalid_scope",
        "access_denied",
        "server_error",
        "temporarily_unavailable",
        "authorization_pending",
        "slow_down",
        "expired_token",
    ];
    let code = r
        .json
        .get("error")
        .and_then(Value::as_str)
        .filter(|code| CODES.contains(code));
    let detail = code.map(|code| format!(": {code}")).unwrap_or_default();
    VaultError::new(
        &format!("{host} 返回错误（HTTP {}）{detail}；已隐藏上游诊断内容以保护凭证", r.status),
        &format!("{host} returned an error (HTTP {}){detail}; upstream diagnostics were omitted to protect credentials", r.status),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_required_unless_loopback_allowed_for_tests() {
        assert!(assert_https_url("https://example.com/a", "url").is_ok());
        assert!(assert_https_url("http://example.com/a", "url").is_err());
        assert!(assert_https_url("http://127.0.0.1:1234/a", "url").is_err());
        allow_insecure_loopback_for_tests(true);
        assert!(assert_https_url("http://127.0.0.1:1234/a", "url").is_ok());
        assert!(
            assert_https_url("http://example.com/a", "url").is_err(),
            "loopback allowance doesn't extend to other hosts"
        );
        allow_insecure_loopback_for_tests(false);
    }

    #[test]
    fn rejects_userinfo_in_the_url() {
        assert!(assert_https_url("https://user:pass@example.com/a", "url").is_err());
    }

    #[test]
    fn remote_errors_omit_plain_and_encoded_credentials() {
        let diagnostics = "synthetic-secret c3ludGhldGljLXNlY3JldA== synthetic%2Dsecret";
        for code in ["invalid_client", diagnostics] {
            let response = HttpResult {
                status: 400,
                text: diagnostics.into(),
                json: serde_json::json!({"error": code, "error_description": diagnostics, "message": diagnostics}),
            };
            let error = remote_error("example.com", &response).0;
            assert!(error.contains("400"));
            assert_eq!(error.contains("invalid_client"), code == "invalid_client");
            for sensitive in diagnostics.split_whitespace() {
                assert!(!error.contains(sensitive));
            }
        }
    }
}
