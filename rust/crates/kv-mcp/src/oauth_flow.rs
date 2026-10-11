//! Browser-side OAuth interaction (runs as a regular user):
//! Obtains the authorization code via a local loopback callback + PKCE + state; exchanging the
//! code for a token is done by the root helper -- the client secret and refresh token never pass
//! through here. Direct port of src/server/oauth-flow.ts.

use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request, Response, StatusCode, Uri};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch, Semaphore};
use tokio::task::JoinSet;
use url::Url;

const LOGIN_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(5 * 60_000);
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_CALLBACK_CONNECTIONS: usize = 32;

struct CallbackHandler {
    state: String,
    path: String,
    result: std::sync::Mutex<Option<oneshot::Sender<Result<String, String>>>>,
}

impl CallbackHandler {
    fn handle(&self, method: &Method, uri: &Uri) -> Response<Full<Bytes>> {
        let empty = |status| {
            Response::builder()
                .status(status)
                .body(Full::new(Bytes::new()))
                .unwrap()
        };
        if method != Method::GET {
            return empty(StatusCode::METHOD_NOT_ALLOWED);
        }
        if uri.path() != self.path {
            return empty(StatusCode::NOT_FOUND);
        }
        // Parse the query directly. Reinterpreting an HTTP request target as a URL can fail
        // (absolute/authority/asterisk forms are also legal HTTP targets).
        let mut qs = std::collections::HashMap::new();
        for (key, value) in url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
        {
            if matches!(
                key.as_ref(),
                "state" | "code" | "error" | "error_description"
            ) && qs.contains_key(key.as_ref())
            {
                return empty(StatusCode::BAD_REQUEST);
            }
            qs.insert(key.into_owned(), value.into_owned());
        }
        if qs.get("state") != Some(&self.state) {
            let body = page(&kv_i18n::t("授权失败", "Authorization failed"), &kv_i18n::t("state 不匹配，请回到 AI 会话重新发起授权。", "State mismatch. Please return to the AI session and start the authorization again."));
            // A forged request must not end the flow; keep waiting for the real callback.
            return html_response(StatusCode::BAD_REQUEST, body);
        }
        if qs.contains_key("code") && qs.contains_key("error") {
            return empty(StatusCode::BAD_REQUEST);
        }
        if let Some(err) = qs.get("error") {
            let desc = qs
                .get("error_description")
                .map(String::as_str)
                .unwrap_or_default();
            let body = page(
                &kv_i18n::t("授权未完成", "Authorization not completed"),
                &escape_html(&format!("{err} {desc}")),
            );
            if let Some(sender) = self.result.lock().unwrap().take() {
                let detail = if desc.is_empty() {
                    String::new()
                } else {
                    format!(" ({desc})")
                };
                let _ = sender.send(Err(kv_i18n::t(
                    &format!("授权被拒绝或失败：{err}{detail}"),
                    &format!("Authorization denied or failed: {err}{detail}"),
                )));
            }
            return html_response(StatusCode::BAD_REQUEST, body);
        }
        let Some(code) = qs.get("code").filter(|code| !code.is_empty()) else {
            return empty(StatusCode::BAD_REQUEST);
        };
        let body = page(&kv_i18n::t("授权成功 ✅", "Authorization successful ✅"), &kv_i18n::t("可以关闭此页面并回到 AI 会话完成凭证保存。", "You can close this page and return to the AI session to finish saving the credential."));
        if let Some(sender) = self.result.lock().unwrap().take() {
            let _ = sender.send(Ok(code.clone()));
        }
        html_response(StatusCode::OK, body)
    }
}

/// Own every listener and connection. Dropping a cancelled flow aborts the task tree; normal
/// shutdown lets the callback response finish before closing idle sockets.
struct CallbackServer {
    shutdown: watch::Sender<bool>,
    listeners: JoinSet<()>,
}

impl CallbackServer {
    fn start(listeners: Vec<TcpListener>, handler: Arc<CallbackHandler>) -> Self {
        let (shutdown, stop) = watch::channel(false);
        let slots = Arc::new(Semaphore::new(MAX_CALLBACK_CONNECTIONS));
        let mut tasks = JoinSet::new();
        for listener in listeners {
            let handler = handler.clone();
            let mut stop = stop.clone();
            let slots = slots.clone();
            tasks.spawn(async move {
                let mut connections = JoinSet::new();
                loop {
                    tokio::select! {
                        biased;
                        _ = stop.changed() => break,
                        accepted = listener.accept() => {
                            let Ok((stream, _)) = accepted else { break };
                            let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
                            let handler = handler.clone();
                            let mut stop = stop.clone();
                            connections.spawn(async move {
                                let _permit = permit;
                                if *stop.borrow() { return; }
                                let service = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                                    std::future::ready(Ok::<_, Infallible>(handler.handle(req.method(), req.uri())))
                                });
                                let mut builder = hyper::server::conn::http1::Builder::new();
                                builder
                                    .keep_alive(false)
                                    .max_buf_size(16 * 1024)
                                    .timer(hyper_util::rt::TokioTimer::new())
                                    .header_read_timeout(std::time::Duration::from_secs(10));
                                let conn = builder.serve_connection(hyper_util::rt::TokioIo::new(stream), service);
                                tokio::pin!(conn);
                                tokio::select! {
                                    biased;
                                    _ = stop.changed() => {
                                        conn.as_mut().graceful_shutdown();
                                        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), conn).await;
                                    }
                                    _ = &mut conn => {}
                                }
                            });
                        }
                        _ = connections.join_next(), if !connections.is_empty() => {}
                    }
                    while connections.try_join_next().is_some() {}
                }
                drop(listener);
                while connections.join_next().await.is_some() {}
            });
        }
        Self {
            shutdown,
            listeners: tasks,
        }
    }

    async fn shutdown(&mut self) {
        let _ = self.shutdown.send(true);
        while self.listeners.join_next().await.is_some() {}
    }
}

impl Drop for CallbackServer {
    fn drop(&mut self) {
        self.listeners.abort_all();
    }
}

pub async fn open_in_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = tokio::process::Command::new("/usr/bin/open");
        c.arg(url).env_clear().env("PATH", "/usr/bin:/bin");
        c
    };
    #[cfg(target_os = "linux")]
    let mut cmd = {
        if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
            eprintln!("KeyValet: open this URL in your browser (SSH requires forwarding the callback port):\n{url}");
            return Ok(());
        }
        let mut c = tokio::process::Command::new("/usr/bin/xdg-open");
        c.arg(url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null());
        c
    };
    #[cfg(windows)]
    let mut cmd = {
        // rundll32 resolves via the process's own System32; no PATH involved.
        let mut c = tokio::process::Command::new(r"C:\Windows\System32\rundll32.exe");
        c.args(["url.dll,FileProtocolHandler", url]).env_clear();
        c
    };
    let status = cmd.kill_on_drop(true).status().await?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other("browser launcher failed"))
    }
}

pub fn copy_to_clipboard(text: &str) {
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = tokio::process::Command::new("/usr/bin/pbcopy");
        c.env_clear().env("PATH", "/usr/bin:/bin");
        c
    };
    #[cfg(target_os = "linux")]
    let mut cmd = {
        if std::env::var_os("WAYLAND_DISPLAY").is_some()
            && std::path::Path::new("/usr/bin/wl-copy").exists()
        {
            tokio::process::Command::new("/usr/bin/wl-copy")
        } else if std::env::var_os("DISPLAY").is_some()
            && std::path::Path::new("/usr/bin/xclip").exists()
        {
            let mut command = tokio::process::Command::new("/usr/bin/xclip");
            command.args(["-selection", "clipboard"]);
            command
        } else {
            return;
        }
    };
    #[cfg(windows)]
    let mut cmd = {
        let mut c = tokio::process::Command::new(r"C:\Windows\System32\clip.exe");
        c.env_clear();
        c
    };
    if let Ok(mut child) = cmd.stdin(std::process::Stdio::piped()).spawn() {
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
    run_browser_flow_with(opts, LOGIN_TIMEOUT, |url| async move {
        open_in_browser(&url).await
    })
    .await
}

async fn run_browser_flow_with<F, Fut>(
    opts: RunBrowserFlowOpts<'_>,
    timeout: std::time::Duration,
    open: F,
) -> Result<BrowserFlowResult, String>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<()>>,
{
    // Validate before spawning any server task, so invalid configuration cannot leave a port
    // behind. The server guard below also covers browser errors, timeout and cancellation.
    let mut auth = Url::parse(opts.authorization_url).map_err(|e| e.to_string())?;
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
    if fixed.as_ref().is_some_and(|url| {
        url.scheme() != "http"
            || !matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.port() == Some(0)
    }) {
        return Err(kv_i18n::t(
            "redirect_uri 必须是有效的 HTTP 回环回调地址",
            "redirect_uri must be a valid HTTP loopback callback address",
        ));
    }
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
    let fixed_port = fixed.as_ref().and_then(|u| u.port_or_known_default());

    let (tx, rx) = oneshot::channel::<Result<String, String>>();

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

    let handler = Arc::new(CallbackHandler {
        state: state.clone(),
        path,
        result: std::sync::Mutex::new(Some(tx)),
    });
    let mut server = CallbackServer::start(listeners, handler);
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

    let result = tokio::time::timeout(timeout, async {
        open(auth.into()).await.map_err(|e| e.to_string())?;
        match rx.await {
            Ok(Ok(code)) => Ok(BrowserFlowResult {
                code,
                code_verifier: verifier,
                redirect_uri: redirect_uri.clone(),
            }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(kv_i18n::t(
                "等待浏览器授权时发生内部错误",
                "Internal error while waiting for browser authorization",
            )),
        }
    })
    .await
    .unwrap_or_else(|_| {
        Err(kv_i18n::t(
            "等待浏览器授权超时（5 分钟）",
            "Timed out waiting for browser authorization (5 minutes)",
        ))
    });
    server.shutdown().await;
    result
}

fn html_response(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .header("referrer-policy", "no-referrer")
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

    fn test_opts(extra: &std::collections::HashMap<String, String>) -> RunBrowserFlowOpts<'_> {
        RunBrowserFlowOpts {
            authorization_url: "https://issuer.example/authorize",
            client_id: "synthetic-client",
            scopes: &[],
            extra_params: extra,
            redirect_uri: None,
            redirect_host: None,
        }
    }

    fn test_flow(
        fail_to_open: bool,
    ) -> (
        tokio::task::JoinHandle<Result<BrowserFlowResult, String>>,
        oneshot::Receiver<String>,
    ) {
        let (tx, rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let extra = std::collections::HashMap::new();
            run_browser_flow_with(test_opts(&extra), LOGIN_TIMEOUT, move |url| async move {
                tx.send(url).unwrap();
                if fail_to_open {
                    Err(std::io::Error::other("simulated browser error"))
                } else {
                    Ok(())
                }
            })
            .await
        });
        (task, rx)
    }

    fn callback_url(auth: &str) -> Url {
        let auth = Url::parse(auth).unwrap();
        let redirect = auth
            .query_pairs()
            .find(|(k, _)| k == "redirect_uri")
            .unwrap()
            .1;
        Url::parse(&redirect).unwrap()
    }

    #[tokio::test]
    async fn cancelling_a_browser_flow_closes_the_listener_and_idle_connections() {
        use tokio::io::AsyncReadExt;
        let (flow, auth) = test_flow(false);
        let callback = callback_url(&auth.await.unwrap());
        let address = ("127.0.0.1", callback.port().unwrap());
        let mut idle = tokio::net::TcpStream::connect(address).await.unwrap();
        flow.abort();
        let Err(error) = flow.await else {
            panic!("the flow should be cancelled")
        };
        assert!(error.is_cancelled());
        let read =
            tokio::time::timeout(std::time::Duration::from_secs(2), idle.read(&mut [0u8; 1]))
                .await
                .expect("the cancelled flow must close accepted sockets");
        assert!(matches!(read, Ok(0) | Err(_)));
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
        TcpListener::bind(address)
            .await
            .expect("callback port must be reusable");
    }

    #[tokio::test]
    async fn browser_open_errors_release_the_callback_port() {
        let (flow, auth) = test_flow(true);
        let callback = callback_url(&auth.await.unwrap());
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), flow)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.err().unwrap(), "simulated browser error");
        TcpListener::bind(("127.0.0.1", callback.port().unwrap()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn the_login_timeout_also_covers_a_browser_launcher_that_never_finishes() {
        let (tx, rx) = oneshot::channel();
        let flow = tokio::spawn(async move {
            let extra = std::collections::HashMap::new();
            run_browser_flow_with(
                test_opts(&extra),
                std::time::Duration::from_millis(30),
                move |url| async move {
                    tx.send(url).unwrap();
                    std::future::pending().await
                },
            )
            .await
        });
        let callback = callback_url(&rx.await.unwrap());
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), flow)
            .await
            .expect("a stalled launcher must respect the login deadline")
            .unwrap();
        assert!(result.is_err());
        TcpListener::bind(("127.0.0.1", callback.port().unwrap()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn malformed_callbacks_do_not_consume_the_flow_and_success_finishes_its_response() {
        let (flow, auth) = test_flow(false);
        let auth = Url::parse(&auth.await.unwrap()).unwrap();
        let params: std::collections::HashMap<_, _> = auth.query_pairs().into_owned().collect();
        let mut callback = callback_url(auth.as_str());
        let state = &params["state"];
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        for query in [
            "state=wrong&code=forged".to_string(),
            format!("state={state}&state={state}&code=duplicate-state"),
            format!("state={state}&code=a&code=b"),
            format!("state={state}&code=a&error=denied"),
            format!("state={state}&code="),
        ] {
            callback.set_query(Some(&query));
            assert_eq!(
                client.get(callback.clone()).send().await.unwrap().status(),
                StatusCode::BAD_REQUEST
            );
            assert!(!flow.is_finished());
        }
        callback.set_query(Some(&format!("state={state}&code=synthetic-code")));
        assert_eq!(
            client.post(callback.clone()).send().await.unwrap().status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        let response = client.get(callback.clone()).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let body = response.text().await.unwrap();
        assert!(body.contains("<!doctype html>"));
        let result = flow.await.unwrap().unwrap();
        assert_eq!(result.code, "synthetic-code");
        assert_eq!(result.redirect_uri, params["redirect_uri"]);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(Sha256::digest(result.code_verifier.as_bytes())),
            params["code_challenge"]
        );
        TcpListener::bind(("127.0.0.1", callback.port().unwrap()))
            .await
            .unwrap();
    }

    #[test]
    fn unusual_http_request_targets_do_not_panic_or_accept_a_callback() {
        let (tx, mut rx) = oneshot::channel();
        let handler = CallbackHandler {
            state: "synthetic-state".into(),
            path: "/callback".into(),
            result: std::sync::Mutex::new(Some(tx)),
        };
        for target in [
            "*",
            "[::1]:443",
            "example.com:443",
            "http://[::1]/different",
        ] {
            let uri: Uri = target.parse().unwrap();
            assert_eq!(
                handler.handle(&Method::GET, &uri).status(),
                StatusCode::NOT_FOUND
            );
        }
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
    }

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

    #[tokio::test]
    async fn invalid_redirects_are_rejected_before_starting_the_browser() {
        let extra = std::collections::HashMap::new();
        for redirect in [
            "http://127.0.0.1:0/callback",
            "http://localhost:8765/callback#fragment",
            "http://user:password@127.0.0.1:8765/callback",
            "https://127.0.0.1:8765/callback",
            "http://example.com/callback",
        ] {
            let mut opts = test_opts(&extra);
            opts.redirect_uri = Some(redirect);
            let result = run_browser_flow_with(opts, LOGIN_TIMEOUT, |_| async {
                panic!("an invalid redirect must not start the browser");
            })
            .await;
            assert!(result.err().unwrap().contains("redirect_uri"));
        }
    }
}
