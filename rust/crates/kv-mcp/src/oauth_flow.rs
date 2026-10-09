//! Browser-side OAuth interaction (runs as a regular user):
//! Obtains the authorization code via a local loopback callback + PKCE + state; exchanging the
//! code for a token is done by the root helper -- the client secret and refresh token never pass
//! through here. Direct port of src/server/oauth-flow.ts.

use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use url::Url;

const LOGIN_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(5 * 60_000);
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

pub async fn open_in_browser(url: &str) -> std::io::Result<()> {
    tokio::process::Command::new("/usr/bin/open")
        .arg(url)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .status()
        .await
        .map(|_| ())
}

pub fn copy_to_clipboard(text: &str) {
    if let Ok(mut child) = tokio::process::Command::new("/usr/bin/pbcopy")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            let text = text.to_string();
            tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let _ = stdin.write_all(text.as_bytes()).await;
            });
        }
    }
}

fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><meta charset=\"utf-8\"><title>{title}</title><body style=\"font-family:-apple-system,sans-serif;max-width:32em;margin:15vh auto;text-align:center\"><h2>{title}</h2><p>{body}</p></body>"
    )
}

fn escape_html(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' | '<' | '>' | '"' | '\'' => format!("&#{};", c as u32),
            c => c.to_string(),
        })
        .collect()
}

pub struct BrowserFlowResult {
    pub code: String,
    pub code_verifier: String,
    pub redirect_uri: String,
}

pub struct RunBrowserFlowOpts<'a> {
    pub authorization_url: &'a str,
    pub client_id: &'a str,
    pub scopes: &'a [String],
    pub extra_params: &'a std::collections::HashMap<String, String>,
    pub redirect_uri: Option<&'a str>,
    /// Callback host used when redirect_uri isn't specified ("127.0.0.1" or "localhost").
    pub redirect_host: Option<&'static str>,
}

/// Authorization code + PKCE. When `redirect_uri` isn't specified, listens on a random port on
/// 127.0.0.1. When `redirect_host` is "localhost", listens on both IPv4 and IPv6, since the
/// browser may resolve localhost to ::1.
pub async fn run_browser_flow(opts: RunBrowserFlowOpts<'_>) -> Result<BrowserFlowResult, String> {
    let mut verifier_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut verifier_bytes);
    let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let mut state_bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut state_bytes);
    let state = URL_SAFE_NO_PAD.encode(state_bytes);

    let fixed = opts
        .redirect_uri
        .map(Url::parse)
        .transpose()
        .map_err(|e| e.to_string())?;
    let host = fixed
        .as_ref()
        .map(|u| u.host_str().unwrap_or_default().to_string())
        .unwrap_or_else(|| opts.redirect_host.unwrap_or("127.0.0.1").to_string());
    let path = fixed
        .as_ref()
        .map(|u| u.path().to_string())
        .unwrap_or_else(|| "/callback".to_string());
    let listen_addrs: Vec<&str> = if host == "localhost" {
        vec!["127.0.0.1", "::1"]
    } else if host == "[::1]" || host == "::1" {
        vec!["::1"]
    } else {
        vec![host.as_str()]
    };
    let fixed_port = fixed.as_ref().and_then(|u| u.port());

    let (tx, rx) = oneshot::channel::<Result<String, String>>();
    let tx = Arc::new(std::sync::Mutex::new(Some(tx)));
    let state_clone = state.clone();
    let path_clone = path.clone();

    let make_handler = move || {
        let state = state_clone.clone();
        let path = path_clone.clone();
        let tx = tx.clone();
        move |req: Request<hyper::body::Incoming>| {
            let state = state.clone();
            let path = path.clone();
            let tx = tx.clone();
            async move {
                let uri = req.uri();
                let url = Url::parse(&format!("http://placeholder{uri}")).unwrap();
                if url.path() != path {
                    return Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    );
                }
                let qs: std::collections::HashMap<String, String> = url
                    .query_pairs()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect();
                if qs.get("state").map(String::as_str) != Some(state.as_str()) {
                    let body = page(&kv_i18n::t("授权失败", "Authorization failed"), &kv_i18n::t("state 不匹配，请回到 AI 会话重新发起授权。", "State mismatch. Please return to the AI session and start the authorization again."));
                    return Ok(html_response(StatusCode::BAD_REQUEST, body));
                    // Don't end the flow: this may be a forged request; keep waiting for the real callback.
                }
                if let Some(err) = qs.get("error") {
                    let desc = qs.get("error_description").cloned().unwrap_or_default();
                    let body = page(
                        &kv_i18n::t("授权未完成", "Authorization not completed"),
                        &escape_html(&format!("{err} {desc}")),
                    );
                    if let Some(sender) = tx.lock().unwrap().take() {
                        let _ = sender.send(Err(kv_i18n::t(
                            &format!(
                                "授权被拒绝或失败：{err}{}",
                                if desc.is_empty() {
                                    String::new()
                                } else {
                                    format!(" ({desc})")
                                }
                            ),
                            &format!(
                                "Authorization denied or failed: {err}{}",
                                if desc.is_empty() {
                                    String::new()
                                } else {
                                    format!(" ({desc})")
                                }
                            ),
                        )));
                    }
                    return Ok(html_response(StatusCode::BAD_REQUEST, body));
                }
                let Some(code) = qs.get("code") else {
                    return Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    );
                };
                let body = page(&kv_i18n::t("授权成功 ✅", "Authorization successful ✅"), &kv_i18n::t("凭证已安全保存，可以关闭此页面并回到 AI 会话。", "The credential has been saved securely. You can close this page and return to the AI session."));
                if let Some(sender) = tx.lock().unwrap().take() {
                    let _ = sender.send(Ok(code.clone()));
                }
                Ok(html_response(StatusCode::OK, body))
            }
        }
    };

    let mut listeners = Vec::new();
    let mut port = fixed_port.unwrap_or(0);
    for addr in &listen_addrs {
        let bind_addr = format!(
            "{}:{port}",
            if addr.contains(':') {
                format!("[{addr}]")
            } else {
                addr.to_string()
            }
        );
        match TcpListener::bind(&bind_addr).await {
            Ok(l) => {
                port = l.local_addr().map(|a| a.port()).unwrap_or(port);
                listeners.push(l);
            }
            Err(e) => {
                if listeners.is_empty() {
                    return Err(kv_i18n::t(
                        &format!("无法监听 {addr}:{port}：{e}"),
                        &format!("Cannot listen on {addr}:{port}: {e}"),
                    ));
                }
                // If IPv6 isn't available, use IPv4 only.
            }
        }
    }
    let redirect_uri = fixed
        .map(|u| u.to_string())
        .unwrap_or_else(|| format!("http://{host}:{port}{path}"));

    let shutdown = Arc::new(tokio::sync::Notify::new());
    for listener in listeners {
        let handler = make_handler();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.notified() => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { continue };
                        let io = hyper_util::rt::TokioIo::new(stream);
                        let service = hyper::service::service_fn(handler.clone());
                        tokio::spawn(async move {
                            let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new()).serve_connection(io, service).await;
                        });
                    }
                }
            }
        });
    }

    let mut auth = Url::parse(opts.authorization_url).map_err(|e| e.to_string())?;
    {
        let mut qp = auth.query_pairs_mut();
        for (k, v) in opts.extra_params {
            qp.append_pair(k, v);
        }
        qp.append_pair("response_type", "code");
        qp.append_pair("client_id", opts.client_id);
        qp.append_pair("redirect_uri", &redirect_uri);
        if !opts.scopes.is_empty() {
            qp.append_pair("scope", &opts.scopes.join(" "));
        }
        qp.append_pair("state", &state);
        qp.append_pair("code_challenge", &challenge);
        qp.append_pair("code_challenge_method", "S256");
    }

    let result = async {
        open_in_browser(auth.as_str())
            .await
            .map_err(|e| e.to_string())?;
        match tokio::time::timeout(LOGIN_TIMEOUT, rx).await {
            Ok(Ok(Ok(code))) => Ok(BrowserFlowResult {
                code,
                code_verifier: verifier,
                redirect_uri: redirect_uri.clone(),
            }),
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(_)) => Err(kv_i18n::t(
                "等待浏览器授权时发生内部错误",
                "Internal error while waiting for browser authorization",
            )),
            Err(_) => Err(kv_i18n::t(
                "等待浏览器授权超时（5 分钟）",
                "Timed out waiting for browser authorization (5 minutes)",
            )),
        }
    }
    .await;
    shutdown.notify_waiters();
    result
}

fn html_response(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// OIDC auto-discovery: fetches the authorization/token/device-code endpoints from the issuer.
pub struct OidcEndpoints {
    pub authorization_url: Option<String>,
    pub token_url: String,
    pub device_authorization_url: Option<String>,
}

pub async fn discover_oidc(issuer: &str) -> Result<OidcEndpoints, String> {
    let base = Url::parse(issuer).map_err(|_| kv_i18n::t("非法的 issuer", "Invalid issuer"))?;
    if base.scheme() != "https" {
        return Err(kv_i18n::t("issuer 必须使用 https", "issuer must use https"));
    }
    let url = format!(
        "{}/.well-known/openid-configuration",
        base.as_str().trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    let res = client
        .get(&url)
        .header("Accept-Encoding", "identity")
        .send()
        .await
        .map_err(|e| {
            kv_i18n::t(
                &format!("OIDC 发现失败：{e}"),
                &format!("OIDC discovery failed: {e}"),
            )
        })?;
    if !res.status().is_success() {
        return Err(kv_i18n::t(
            &format!("OIDC 发现失败：{url} 返回 HTTP {}", res.status()),
            &format!(
                "OIDC discovery failed: {url} returned HTTP {}",
                res.status()
            ),
        ));
    }
    let bytes = read_limited(res, MAX_RESPONSE_BYTES, base.host_str().unwrap_or_default()).await?;
    let doc: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| kv_i18n::t("OIDC 文档不是合法 JSON", "OIDC document is not valid JSON"))?;
    let norm = |s: &str| s.trim_end_matches('/').to_string();
    let doc_issuer = doc
        .get("issuer")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if norm(doc_issuer) != norm(base.as_str()) {
        return Err(kv_i18n::t(
            &format!("OIDC 文档中的 issuer（{doc_issuer}）与请求的不一致"),
            &format!(
                "The issuer in the OIDC document ({doc_issuer}) does not match the requested one"
            ),
        ));
    }
    let token_url = doc
        .get("token_endpoint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            kv_i18n::t(
                "OIDC 文档缺少 token_endpoint",
                "OIDC document is missing token_endpoint",
            )
        })?
        .to_string();
    Ok(OidcEndpoints {
        authorization_url: doc
            .get("authorization_endpoint")
            .and_then(|v| v.as_str())
            .map(String::from),
        token_url,
        device_authorization_url: doc
            .get("device_authorization_endpoint")
            .and_then(|v| v.as_str())
            .map(String::from),
    })
}

async fn read_limited(res: reqwest::Response, limit: usize, host: &str) -> Result<Vec<u8>, String> {
    use futures_util::StreamExt;
    let mut stream = res.bytes_stream();
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            kv_i18n::t(
                &format!("{host} 的响应读取失败：{e}"),
                &format!("Failed to read the response from {host}: {e}"),
            )
        })?;
        out.extend_from_slice(&chunk);
        if out.len() > limit {
            return Err(kv_i18n::t(
                &format!("{host} 的响应过大"),
                &format!("Response from {host} is too large"),
            ));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_html_escapes_the_five_html_special_characters() {
        assert_eq!(
            escape_html(r#"<script>&"'</script>"#),
            "&#60;script&#62;&#38;&#34;&#39;&#60;/script&#62;"
        );
    }

    #[test]
    fn escape_html_leaves_plain_text_untouched() {
        assert_eq!(escape_html("plain text 123"), "plain text 123");
    }

    #[test]
    fn page_embeds_the_title_and_body_in_the_html_template() {
        let html = page("Authorization successful", "You can close this page.");
        assert!(html.contains("Authorization successful"));
        assert!(html.contains("You can close this page."));
        assert!(html.starts_with("<!doctype html>"));
    }

    // discover_oidc's success path needs a real HTTPS endpoint (it hardcodes scheme == "https"
    // and the system's real root certificates, with no injection seam for a local test server),
    // so only the failure paths that never reach the network are covered here.

    #[tokio::test]
    async fn discover_oidc_rejects_a_non_https_issuer() {
        let Err(err) = discover_oidc("http://issuer.example.com").await else {
            panic!("expected a non-https issuer to be rejected");
        };
        assert!(err.contains("https"));
    }

    #[tokio::test]
    async fn discover_oidc_rejects_an_unparseable_issuer() {
        let Err(err) = discover_oidc("not a url").await else {
            panic!("expected an unparseable issuer to be rejected");
        };
        assert!(err.contains("issuer") || err.contains("Invalid"));
    }
}
