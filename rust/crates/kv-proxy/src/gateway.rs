//! Local gateway: a proxy entry point on 127.0.0.1 for programs that can't speak MCP (SDKs, CLIs,
//! scripts), with streaming support. Direct port of src/helper/gateway.ts.
//!
//!   http://127.0.0.1:<port>/<upstream-host>/<path>  ->  https://<upstream-host>/<path>
//!   Auth: the program sends the gateway token (kv_...) as its API key -- Authorization: Bearer,
//!   x-api-key, api-key, or x-goog-api-key.
//!
//! - The token never goes in the URL: command-line arguments are visible to every local user (ps),
//!   and SDKs already put API keys in a header anyway.
//! - Only listens on 127.0.0.1; only accepts connections from the session user's own processes
//!   (checked via the peer's uid) -- even a leaked token is useless to another user.
//! - The token is 32 random bytes, one per credential, valid only for this session (the helper process).
//! - Checks the Host header (anti DNS-rebinding); rejects browser-originated requests.
//! - Strips the client's own auth headers and anything that could leak the token; injects the real
//!   credential; only allowed hosts for that credential; doesn't follow redirects.
//! - Streams the response while redacting it, respecting the client's read speed (backpressure), so
//!   the root process never buffers unbounded data in memory.

use crate::proxy::{build_injection, inject_query, FORBIDDEN_HEADERS};
use crate::redact::StreamRedactor;
use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::Body;
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response, StatusCode};
use kv_vault::Vault;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};

const MAX_IN_FLIGHT: usize = 16;
const MAX_CONNECTIONS: usize = 64;
const MAX_REQUEST_BODY: usize = 20 * 1024 * 1024;
const MAX_RESPONSE_BYTES: u64 = 50 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(600);
const TOKEN_PREFIX: &str = "kv_";
/// Request headers the client sends that might carry the token or a credential: always stripped;
/// the gateway injects the real credential instead.
const CLIENT_AUTH_HEADERS: [&str; 6] = [
    "authorization",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "cookie",
    "proxy-authorization",
];

#[derive(Debug, Clone)]
struct Route {
    r#type: String,
    name: String,
    purpose: Option<String>,
}

pub type GatewayAudit = Arc<dyn Fn(serde_json::Map<String, serde_json::Value>) + Send + Sync>;

struct Inner {
    routes: Mutex<HashMap<String, Route>>,
    closed: std::sync::atomic::AtomicBool,
    port: Mutex<u16>,
    in_flight: Arc<Semaphore>,
    connections: Arc<Semaphore>,
    /// Bumped (under the `routes` lock) whenever tokens are revoked. A request records the epoch
    /// it was authorized under. The watch channel also wakes requests stalled on uploads,
    /// upstream responses or downstream backpressure, so revocation cancels them promptly.
    epoch: watch::Sender<u64>,
}

impl Inner {
    fn revoke(&self) {
        let mut routes = self.routes.lock().unwrap();
        routes.clear();
        self.epoch
            .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
    }

    fn revoked_since(&self, epoch: u64) -> bool {
        *self.epoch.borrow() != epoch
    }

    async fn revoked(&self, epoch: u64) {
        let mut changes = self.epoch.subscribe();
        while *changes.borrow_and_update() == epoch {
            if changes.changed().await.is_err() {
                break;
            }
        }
    }
}

pub struct Gateway {
    inner: Arc<Inner>,
    vault: Arc<Vault>,
    audit: GatewayAudit,
    allowed_uid: Option<kv_platform::peer::GatewayPeer>,
    started: tokio::sync::OnceCell<Mutex<Option<JoinHandle<()>>>>,
    shutdown: watch::Sender<bool>,
}

pub struct OpenResult {
    pub base: String,
    pub token: String,
    pub port: u16,
}

impl Gateway {
    pub fn new(
        vault: Arc<Vault>,
        audit: GatewayAudit,
        allowed_uid: Option<kv_platform::peer::GatewayPeer>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                routes: Mutex::new(HashMap::new()),
                closed: std::sync::atomic::AtomicBool::new(false),
                port: Mutex::new(0),
                in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
                connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
                epoch: watch::channel(0).0,
            }),
            vault,
            audit,
            allowed_uid,
            started: tokio::sync::OnceCell::new(),
            shutdown: watch::channel(false).0,
        }
    }

    /// Revoke existing tokens (and stop requests in flight) when the session's policy changes.
    pub fn revoke_all(&self) {
        self.inner.revoke();
    }

    /// Opens a gateway entry point for a credential (re-opening the same credential returns the same token).
    pub async fn open(
        &self,
        r#type: &str,
        name: &str,
        purpose: Option<&str>,
    ) -> std::io::Result<OpenResult> {
        self.ensure_started().await?;
        let mut routes = self.inner.routes.lock().unwrap();
        if self.inner.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(std::io::Error::other("gateway is closed"));
        }
        let existing = routes
            .iter()
            .find(|(_, r)| r.r#type == r#type && r.name == name)
            .map(|(t, _)| t.clone());
        let token = match existing {
            Some(t) => t,
            None => {
                let mut bytes = [0u8; 32];
                getrandom(&mut bytes);
                let t = format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
                routes.insert(
                    t.clone(),
                    Route {
                        r#type: r#type.to_string(),
                        name: name.to_string(),
                        purpose: purpose.map(str::to_string),
                    },
                );
                t
            }
        };
        let port = *self.inner.port.lock().unwrap();
        Ok(OpenResult {
            base: format!("http://127.0.0.1:{port}"),
            token,
            port,
        })
    }

    pub fn close(&self) {
        self.inner
            .closed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.inner.revoke();
        self.shutdown.send_replace(true);
    }

    /// Wait for the listener and every connection to release their session vault references.
    pub async fn shutdown(&self) {
        self.close();
        let task = self
            .started
            .get()
            .and_then(|task| task.lock().unwrap().take());
        if let Some(task) = task {
            let _ = task.await;
        }
    }

    async fn ensure_started(&self) -> std::io::Result<()> {
        if self.inner.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(std::io::Error::other("gateway is closed"));
        }
        let inner = self.inner.clone();
        let vault = self.vault.clone();
        let audit = self.audit.clone();
        #[allow(clippy::clone_on_copy)] // GatewayPeer is Vec<u8> on Windows
        let allowed_uid = self.allowed_uid.clone();
        let shutdown = self.shutdown.subscribe();
        self.started
            .get_or_try_init(|| async move {
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let port = listener.local_addr()?.port();
                *inner.port.lock().unwrap() = port;
                let task =
                    tokio::spawn(serve(listener, inner, vault, audit, allowed_uid, shutdown));
                Ok::<_, std::io::Error>(Mutex::new(Some(task)))
            })
            .await
            .map(|_| ())
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.close();
        if let Some(task) = self
            .started
            .get()
            .and_then(|task| task.lock().unwrap().take())
        {
            // Backup for an aborted helper session: dropping serve's JoinSet aborts its children.
            task.abort();
        }
    }
}

fn getrandom(buf: &mut [u8]) {
    ::getrandom::getrandom(buf).expect("OS RNG must be available to mint a gateway token");
}

/// Who may talk to this gateway: the unix uid or the Windows user SID of the session owner.
/// The actual peer lookup lives in `kv_platform::peer::loopback_client`.
#[cfg(unix)]
fn peer_is_allowed(want: &u32, port: u16) -> bool {
    kv_platform::peer::loopback_client(port) == Some(*want)
}
/// Windows twin: the client's token user SID must equal the vault owner's SID.
#[cfg(windows)]
fn peer_is_allowed(want: &[u8], port: u16) -> bool {
    kv_platform::peer::loopback_client(port)
        .is_some_and(|peer| kv_platform::peer::sid_equal(&peer.sid, want))
}

async fn serve(
    listener: TcpListener,
    inner: Arc<Inner>,
    vault: Arc<Vault>,
    audit: GatewayAudit,
    allowed_uid: Option<kv_platform::peer::GatewayPeer>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut connections = JoinSet::new();
    while !*shutdown.borrow() {
        let accepted = tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            _ = connections.join_next(), if !connections.is_empty() => continue,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, peer_addr)) = accepted else {
            break;
        };
        // Idle or unauthenticated sockets must also be bounded; they do not consume a request
        // permit, but each holds a descriptor, a connection task and a session vault reference.
        let Ok(permit) = inner.connections.clone().try_acquire_owned() else {
            continue;
        };
        let inner = inner.clone();
        let vault = vault.clone();
        let audit = audit.clone();
        #[allow(clippy::clone_on_copy)] // GatewayPeer is Vec<u8> on Windows
        let allowed_uid = allowed_uid.clone();
        connections.spawn(async move {
            let _permit = permit;
            if let Some(want_uid) = &allowed_uid {
                if !peer_is_allowed(want_uid, peer_addr.port()) {
                    return; // a different user's process: disconnect immediately
                }
            }
            let io = hyper_util::rt::TokioIo::new(stream);
            let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                let inner = inner.clone();
                let vault = vault.clone();
                let audit = audit.clone();
                let port = *inner.port.lock().unwrap();
                async move {
                    Ok::<_, std::convert::Infallible>(
                        handle(req, inner, vault, audit, port, peer_addr).await,
                    )
                }
            });
            let _ =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
        });
    }
    drop(listener);
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

/// A body error makes hyper abort the connection instead of ending the response normally, so a
/// client never mistakes a cut-off stream for a complete one.
type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;

/// Keep the streaming producer owned by the response, so disconnect/lock also cancels an
/// upstream stalled between chunks and releases the redactor's credential copies.
struct ResponseStream {
    receiver: tokio_stream::wrappers::ReceiverStream<Result<Frame<Bytes>, std::io::Error>>,
    task: JoinHandle<()>,
    revocations: tokio_stream::wrappers::WatchStream<u64>,
    epoch: u64,
    finished: bool,
}

impl futures_util::Stream for ResponseStream {
    type Item = Result<Frame<Bytes>, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        if self.finished {
            return std::task::Poll::Ready(None);
        }
        while let std::task::Poll::Ready(Some(epoch)) =
            std::pin::Pin::new(&mut self.revocations).poll_next(cx)
        {
            if epoch != self.epoch {
                self.finished = true;
                self.task.abort();
                return std::task::Poll::Ready(Some(Err(std::io::Error::other(
                    "gateway token revoked",
                ))));
            }
        }
        std::pin::Pin::new(&mut self.receiver).poll_next(cx)
    }
}

impl Drop for ResponseStream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn full_body(b: impl Into<Bytes>) -> BoxBody {
    Full::new(b.into()).map_err(|never| match never {}).boxed()
}

fn fail(status: StatusCode, message: &str) -> Response<BoxBody> {
    let body = serde_json::json!({"error": {"type": "keyvalet_gateway_error", "message": message}});
    Response::builder()
        .status(status)
        .header("content-type", "application/json; charset=utf-8")
        .body(full_body(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn token_from(req: &Request<Incoming>) -> Option<String> {
    for name in ["authorization", "x-api-key", "api-key", "x-goog-api-key"] {
        if let Some(v) = req.headers().get(name).and_then(|v| v.to_str().ok()) {
            let v = v
                .trim()
                .strip_prefix("Bearer ")
                .or(v.trim().strip_prefix("bearer "))
                .unwrap_or(v.trim());
            if v.starts_with(TOKEN_PREFIX) {
                return Some(v.to_string());
            }
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
async fn handle(
    req: Request<Incoming>,
    inner: Arc<Inner>,
    vault: Arc<Vault>,
    audit: GatewayAudit,
    port: u16,
    _peer: SocketAddr,
) -> Response<BoxBody> {
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(str::to_string);
    let mut segments = path.trim_start_matches('/').splitn(2, '/');
    let upstream_host = segments.next().unwrap_or_default().to_lowercase();
    let rest = segments.next().unwrap_or_default();
    let method = req.method().clone();
    let target = format!("{} {}/{}", method, upstream_host, rest)
        .chars()
        .take(300)
        .collect::<String>();

    let record_audit = |ok: bool, status: u16, reason: Option<&str>, route: Option<&Route>| {
        let mut e = serde_json::Map::new();
        e.insert("ok".into(), ok.into());
        e.insert("status".into(), status.into());
        if let Some(r) = reason {
            e.insert("reason".into(), r.into());
        }
        e.insert("target".into(), target.clone().into());
        if let Some(route) = route {
            e.insert("type".into(), route.r#type.clone().into());
            e.insert("name".into(), route.name.clone().into());
            if let Some(p) = &route.purpose {
                e.insert("purpose".into(), p.clone().into());
            }
        }
        audit(e);
    };

    // DNS-rebinding protection: only accept requests that directly address 127.0.0.1/localhost.
    let host_header = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    if host_header != format!("127.0.0.1:{port}") && host_header != format!("localhost:{port}") {
        record_audit(false, 421, Some("host_header"), None);
        return fail(StatusCode::MISDIRECTED_REQUEST, "Misdirected request");
    }
    // Browser-originated requests (web pages) are always rejected: a browser always sends
    // Sec-Fetch-Site, and cross-origin requests also carry Origin. Can't key off sec-fetch-mode --
    // Node's own built-in fetch (used by the OpenAI SDK etc.) sends it too.
    let site = req
        .headers()
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok());
    if req.headers().contains_key("origin") || site.is_some_and(|s| s != "none") {
        record_audit(false, 403, Some("browser"), None);
        return fail(
            StatusCode::FORBIDDEN,
            &kv_i18n::t(
                "网关不接受浏览器发起的请求",
                "The gateway does not accept requests from browsers",
            ),
        );
    }
    let token = token_from(&req);
    // Read the epoch under the same lock as the route, so a concurrent revocation is never missed.
    let authorized = token.as_ref().and_then(|t| {
        let routes = inner.routes.lock().unwrap();
        routes
            .get(t)
            .cloned()
            .map(|route| (route, *inner.epoch.borrow()))
    });
    let Some((route, epoch)) = authorized else {
        record_audit(false, 401, Some("token"), None);
        return fail(
            StatusCode::UNAUTHORIZED,
            &kv_i18n::t(
                "缺少或无效的网关令牌（请把 KeyValet 网关令牌作为 API key 发送）",
                "Missing or invalid gateway token (send the KeyValet gateway token as the API key)",
            ),
        );
    };
    if upstream_host.is_empty() {
        record_audit(false, 401, Some("token"), Some(&route));
        return fail(StatusCode::UNAUTHORIZED, "Missing upstream host");
    }
    let permit = match inner.in_flight.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            record_audit(false, 429, Some("busy"), Some(&route));
            return fail(
                StatusCode::TOO_MANY_REQUESTS,
                &kv_i18n::t(
                    "网关请求过多，请稍后再试",
                    "Too many gateway requests; retry later",
                ),
            );
        }
    };
    let result = tokio::select! {
        biased;
        _ = inner.revoked(epoch) => Err(revoked_error()),
        result = tokio::time::timeout(TIMEOUT, handle_authorized(
            req,
            &vault,
            &route,
            (&inner, epoch, permit),
            &upstream_host,
            rest,
            query.as_deref(),
        )) => result.unwrap_or_else(|_| Err((
            StatusCode::GATEWAY_TIMEOUT,
            "timeout".to_string(),
            kv_i18n::t("网关请求超时", "Gateway request timed out"),
        ))),
    };

    match result {
        Ok(resp) => {
            record_audit(
                resp.status().as_u16() < 400,
                resp.status().as_u16(),
                None,
                Some(&route),
            );
            resp
        }
        Err((status, reason, message)) => {
            record_audit(false, status.as_u16(), Some(&reason), Some(&route));
            fail(status, &message)
        }
    }
}

fn revoked_error() -> (StatusCode, String, String) {
    (
        StatusCode::UNAUTHORIZED,
        "revoked".to_string(),
        kv_i18n::t("网关令牌已撤销", "The gateway token has been revoked"),
    )
}

async fn handle_authorized(
    req: Request<Incoming>,
    vault: &Vault,
    route: &Route,
    (inner, epoch, permit): (&Arc<Inner>, u64, OwnedSemaphorePermit),
    upstream_host: &str,
    rest: &str,
    query: Option<&str>,
) -> Result<Response<BoxBody>, (StatusCode, String, String)> {
    let (ty, name, record) = vault
        .get_record(&route.r#type, &route.name)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, "vault".to_string(), e.0))?;
    let Some(http) = &record.http else {
        return Err((
            StatusCode::FORBIDDEN,
            "no_proxy".to_string(),
            kv_i18n::t(
                "该凭证没有配置代理调用",
                "This credential has no proxy configuration",
            ),
        ));
    };
    // The URL path only ever carries a bare host (production only ever talks to the default port
    // 443 over https, same restriction as proxy_request's check_url); a "host:port" form is only
    // accepted, and only for the literal loopback address, so tests can route to a local mock
    // server -- mirroring check_url's own test_loopback carve-out. allowed_hosts is always matched
    // against the bare host either way.
    let (bare_host, host_port) = match upstream_host.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (upstream_host, None),
    };
    let test_loopback = kv_protocols::http::insecure_loopback_allowed()
        && bare_host == "127.0.0.1"
        && host_port.is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    let host_format_ok = regex_hostname_ok(bare_host) && (host_port.is_none() || test_loopback);
    if !host_format_ok || !crate::config::host_allowed(bare_host, &http.allowed_hosts) {
        let joined = http.allowed_hosts.join(&kv_i18n::t("、", ", "));
        return Err((
            StatusCode::FORBIDDEN,
            "host".to_string(),
            kv_i18n::t(
                &format!("域名 {bare_host} 不在该凭证允许的范围内（{joined}）"),
                &format!("Host {bare_host} is not allowed for this credential ({joined})"),
            ),
        ));
    }

    let scheme = if test_loopback { "http" } else { "https" };
    let qs = query.map(|q| format!("?{q}")).unwrap_or_default();
    let mut url =
        url::Url::parse(&format!("{scheme}://{upstream_host}/{rest}{qs}")).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "url".to_string(),
                "Invalid URL".to_string(),
            )
        })?;

    let method = req.method().clone();
    let request_headers = req.headers().clone();
    let body_bytes = if matches!(method.as_str(), "GET" | "HEAD") {
        Bytes::new()
    } else {
        let too_large = || {
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                "body".to_string(),
                kv_i18n::t("请求体过大", "Request body too large"),
            )
        };
        if req.body().size_hint().lower() > MAX_REQUEST_BODY as u64 {
            return Err(too_large());
        }
        Limited::new(req.into_body(), MAX_REQUEST_BODY)
            .collect()
            .await
            .map_err(|e| {
                if e.is::<http_body_util::LengthLimitError>() {
                    too_large()
                } else {
                    (
                        StatusCode::BAD_REQUEST,
                        "body".to_string(),
                        kv_i18n::t("请求体读取失败", "Failed to read the request body"),
                    )
                }
            })?
            .to_bytes()
    };

    let inj = build_injection(vault, &ty, &name, &record)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, "inject".to_string(), e.0))?;
    inject_query(&mut url, &inj.query);
    let injected: std::collections::HashSet<String> =
        inj.headers.keys().map(|k| k.to_lowercase()).collect();
    let mut out_headers = zeroize::Zeroizing::new(Vec::new());
    for (k, v) in &request_headers {
        let lk = k.as_str().to_lowercase();
        if CLIENT_AUTH_HEADERS.contains(&lk.as_str())
            || FORBIDDEN_HEADERS.contains(&lk.as_str())
            || injected.contains(&lk)
            || drop_request_header(&lk)
        {
            continue;
        }
        if let Ok(vs) = v.to_str() {
            out_headers.push((k.as_str().to_string(), vs.to_string()));
        }
    }
    out_headers.extend(inj.headers.iter().map(|(k, v)| (k.clone(), v.clone())));
    out_headers.push(("accept-encoding".to_string(), "identity".to_string()));

    if inner.revoked_since(epoch) {
        return Err(revoked_error());
    }

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(TIMEOUT)
        .build()
        .unwrap();
    let mut rb = client.request(method.as_str().parse().unwrap(), url.as_str());
    for (k, v) in out_headers.iter() {
        rb = rb.header(k, v);
    }
    if !body_bytes.is_empty() {
        rb = rb.body(body_bytes);
    }
    let signal_abort = tokio::time::timeout(TIMEOUT, rb.send()).await;
    let upstream = match signal_abort {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            let detail = String::from_utf8_lossy(&crate::redact::redact(
                e.without_url().to_string().as_bytes(),
                &inj.redactions,
            ))
            .into_owned();
            return Err((
                StatusCode::BAD_GATEWAY,
                "fetch".to_string(),
                kv_i18n::t(
                    &format!("网关请求失败：{detail}"),
                    &format!("Gateway request failed: {detail}"),
                ),
            ));
        }
        Err(_) => {
            return Err((
                StatusCode::GATEWAY_TIMEOUT,
                "timeout".to_string(),
                kv_i18n::t("网关请求超时", "Gateway request timed out"),
            ))
        }
    };

    if inner.revoked_since(epoch) {
        return Err(revoked_error());
    }
    let status = upstream.status().as_u16();
    let mut resp_headers = Vec::new();
    for (k, v) in upstream.headers() {
        let lk = k.as_str().to_lowercase();
        if drop_response_header(&lk) {
            continue;
        }
        if let Ok(vs) = v.to_str() {
            resp_headers.push((
                k.as_str().to_string(),
                String::from_utf8_lossy(&crate::redact::redact(vs.as_bytes(), &inj.redactions))
                    .to_string(),
            ));
        }
    }

    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(4);
    let redactions = inj.redactions.clone();
    let revocations = tokio_stream::wrappers::WatchStream::new(inner.epoch.subscribe());
    let inner = inner.clone();
    let task = tokio::spawn(async move {
        // The permit lives until the upstream stream finishes, fails or is cancelled.
        let _permit = permit;
        let forward = async {
            let mut redactor = StreamRedactor::new(redactions);
            let mut stream = upstream.bytes_stream();
            let mut total: u64 = 0;
            use futures_util::StreamExt;
            let abort = |reason: &str| Err(std::io::Error::other(reason.to_string()));
            while let Some(chunk) = stream.next().await {
                if inner.revoked_since(epoch) {
                    let _ = tx.send(abort("gateway token revoked")).await;
                    return;
                }
                let Ok(chunk) = chunk else {
                    let _ = tx.send(abort("upstream stream failed")).await;
                    return;
                };
                total += chunk.len() as u64;
                if total > MAX_RESPONSE_BYTES {
                    // Over the limit: abort rather than let the client think the response completed.
                    let _ = tx.send(abort("response too large")).await;
                    return;
                }
                let out = redactor.push(&chunk);
                if !out.is_empty() && tx.send(Ok(Frame::data(Bytes::from(out)))).await.is_err() {
                    return; // client disconnected
                }
            }
            let tail = redactor.flush();
            if !tail.is_empty() {
                let _ = tx.send(Ok(Frame::data(Bytes::from(tail)))).await;
            }
        };
        tokio::select! {
            biased;
            _ = inner.revoked(epoch) => {},
            _ = forward => {},
        }
    });
    let stream_body = StreamBody::new(ResponseStream {
        receiver: tokio_stream::wrappers::ReceiverStream::new(rx),
        task,
        revocations,
        epoch,
        finished: false,
    })
    .boxed();

    let mut builder =
        Response::builder().status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY));
    for (k, v) in resp_headers {
        builder = builder.header(k, v);
    }
    Ok(builder.body(stream_body).unwrap())
}

fn drop_request_header(lk: &str) -> bool {
    matches!(
        lk,
        "referer" | "origin" | "expect" | "forwarded" | "via" | "keep-alive" | "accept-encoding"
    ) || lk.starts_with("x-forwarded-")
        || lk.starts_with("sec-")
        || lk.starts_with("proxy-")
}
fn drop_response_header(lk: &str) -> bool {
    matches!(
        lk,
        "content-length"
            | "content-encoding"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "set-cookie"
            | "alt-svc"
    ) || lk.starts_with("access-control-")
}
fn regex_hostname_ok(h: &str) -> bool {
    !h.is_empty()
        && h.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn idle_connections_are_bounded_and_release_their_slots_on_disconnect() {
        let tmp = tempfile::tempdir().unwrap();
        let gateway = Gateway::new(
            Arc::new(Vault::new(tmp.path().join("vault"))),
            Arc::new(|_| {}),
            None,
        );
        let entry = gateway.open("api_key", "svc", None).await.unwrap();
        let mut idle = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            idle.push(
                tokio::net::TcpStream::connect(("127.0.0.1", entry.port))
                    .await
                    .unwrap(),
            );
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while gateway.inner.connections.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(reqwest::Client::new()
            .get(&entry.base)
            .timeout(Duration::from_secs(2))
            .send()
            .await
            .is_err());
        drop(idle);
        tokio::time::timeout(Duration::from_secs(2), async {
            while gateway.inner.connections.available_permits() != MAX_CONNECTIONS {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            reqwest::Client::new()
                .get(&entry.base)
                .send()
                .await
                .unwrap()
                .status(),
            401
        );
        gateway.shutdown().await;
    }

    #[tokio::test]
    async fn open_reuses_the_same_token_for_the_same_credential() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = Arc::new(kv_vault::Vault::new(tmp.path().join("vault")));
        vault.prepare().unwrap();
        if !vault.dir.join("master.key").exists() {
            // Explicit legacy fixture: production code never creates this file.
            std::fs::write(vault.dir.join("master.key"), [7u8; 32]).unwrap();
            #[cfg(unix)]
            std::fs::set_permissions(
                vault.dir.join("master.key"),
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
            )
            .unwrap();
        }
        vault.init_legacy().unwrap();
        let gw = Gateway::new(vault, Arc::new(|_| {}), None);
        let a = gw.open("api_key", "svc", Some("test")).await.unwrap();
        let b = gw.open("api_key", "svc", Some("test again")).await.unwrap();
        assert_eq!(a.token, b.token);
        let c = gw.open("api_key", "other", Some("test")).await.unwrap();
        assert_ne!(a.token, c.token);
        assert!(a.token.starts_with(TOKEN_PREFIX));
    }

    #[test]
    fn hostname_validation_rejects_anything_but_lowercase_dns_chars() {
        assert!(regex_hostname_ok("api.example.com"));
        assert!(!regex_hostname_ok("API.EXAMPLE.COM"));
        assert!(!regex_hostname_ok("evil.com/../etc"));
        assert!(!regex_hostname_ok(""));
    }
}
