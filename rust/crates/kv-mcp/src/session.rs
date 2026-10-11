//! One MCP server process = one agent session.
//! The first time a credential needs to be accessed, a root helper is launched via `sudo -n`
//! (sudoers only allows the helper itself to run passwordlessly); a handshake message (purpose,
//! source directory, session ID) is sent first, and the helper only starts serving requests
//! after Touch ID (showing the purpose) succeeds.
//! Hardware authentication unlocks this session; subsequent credential approvals follow the
//! configured grant mode. Lock, expiry or helper disconnect revokes pending calls and private
//! temporary files. Process exit closes the pipe and the helper exits.
//! Direct port of src/server/session.ts.

use kv_ipc::{
    AuthMessage, CredentialHint, ProtectionProbe, ReadyMessage, Request as WireRequest, Response,
    GRANT_REQUIRED_PREFIX, PROTOCOL_VERSION,
};
#[cfg(windows)]
use kv_platform::paths::{HELPER_BIN, HELPER_PIPE};
#[cfg(target_os = "linux")]
use kv_platform::paths::{HELPER_BIN, HELPER_SOCKET};
#[cfg(target_os = "macos")]
use kv_platform::paths::{HELPER_BIN, HELPER_SOCKET, SUDOERS_FILE, SUDO_BIN, TOUCHID_BIN};
use kv_platform::trust::untrusted_reason;
use serde_json::{Map, Value};
use std::collections::HashMap;
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
#[cfg(target_os = "macos")]
use tokio::process::{Child, ChildStdin};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex, Semaphore};

const UNLOCK_TIMEOUT: Duration = Duration::from_millis(180_000);
const REQUEST_TIMEOUT: Duration = Duration::from_millis(60_000);
const PROTECTION_TIMEOUT: Duration = Duration::from_secs(5);
/// Proxied calls may be streaming responses lasting several minutes (helper-side cap is 180s).
const PROXY_REQUEST_TIMEOUT: Duration = Duration::from_millis(200_000);
/// Cooldown after auth failure/cancellation, to stop an agent from spamming prompts.
const FAILURE_COOLDOWN: Duration = Duration::from_millis(30_000);
/// Per-credential grants need to wait for the user to press Touch ID.
const GRANT_TIMEOUT: Duration = Duration::from_millis(150_000);

#[derive(Debug)]
pub struct SessionError(pub String);
impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for SessionError {}
impl From<String> for SessionError {
    fn from(s: String) -> Self {
        SessionError(s)
    }
}

/// The credential a tool intends to use (for authorization in per_credential mode).
#[derive(Debug, Clone, Default)]
pub struct CredentialTarget {
    pub r#type: Option<String>,
    pub name: Option<String>,
}

type Pending = oneshot::Sender<Result<Value, String>>;

fn response_result(
    result: Result<Result<Value, String>, oneshot::error::RecvError>,
) -> Result<Value, SessionError> {
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(SessionError(error)),
        Err(_) => Err(SessionError(kv_i18n::t(
            "helper 已断开连接",
            "The helper disconnected",
        ))),
    }
}

/// The session's byte stream to the helper: a sudo-spawned child's pipes (fallback mode), or a
/// Unix-socket connection to the launchd daemon when HELPER_SOCKET exists.
enum Transport {
    #[cfg(target_os = "macos")]
    Stdio { stdin: ChildStdin, child: Child },
    Socket {
        writer: Box<dyn AsyncWrite + Unpin + Send>,
    },
}

impl Transport {
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            #[cfg(target_os = "macos")]
            Transport::Stdio { stdin, .. } => stdin.write_all(buf).await,
            Transport::Socket { writer } => writer.write_all(buf).await,
        }
    }

    fn close(&mut self) {
        match self {
            #[cfg(target_os = "macos")]
            Transport::Stdio { child, .. } => {
                let _ = child.start_kill();
            }
            Transport::Socket { .. } => {}
        }
    }
}

struct WriteRequest {
    line: zeroize::Zeroizing<Vec<u8>>,
    sent: oneshot::Sender<std::io::Result<()>>,
}

/// A dedicated writer owns the transport. Revocation can abort it without waiting for a
/// blocked write or the shared state mutex; a cancelled partial frame closes the connection.
struct Connection {
    sender: mpsc::Sender<WriteRequest>,
    requests: Arc<Semaphore>,
    task: tokio::task::JoinHandle<()>,
    reader: Option<tokio::task::AbortHandle>,
    expiry: Option<tokio::task::AbortHandle>,
}

impl Connection {
    fn new(mut transport: Transport, inner: &Arc<AsyncMutex<Inner>>, generation: u64) -> Self {
        let (sender, mut receiver) = mpsc::channel::<WriteRequest>(16);
        let inner = Arc::downgrade(inner);
        let task = tokio::spawn(async move {
            while let Some(mut request) = receiver.recv().await {
                if request.sent.is_closed() {
                    continue;
                }
                let result = tokio::select! {
                    biased;
                    _ = request.sent.closed() => break,
                    result = transport.write_all(&request.line) => result,
                };
                let failed = result.is_err();
                let _ = request.sent.send(result);
                if failed {
                    break;
                }
            }
            transport.close();
            drop(transport);
            if let Some(inner) = inner.upgrade() {
                let mut inner = inner.lock().await;
                if inner.generation == generation {
                    inner.revoke();
                    inner.child = None;
                }
            }
        });
        Self {
            sender,
            requests: Arc::new(Semaphore::new(kv_ipc::MAX_IN_FLIGHT_REQUESTS)),
            task,
            reader: None,
            expiry: None,
        }
    }

    fn attach_reader<R: AsyncRead + Unpin + Send + 'static>(
        &mut self,
        reader: BufReader<R>,
        inner: &Arc<AsyncMutex<Inner>>,
        generation: u64,
    ) {
        let inner = Arc::downgrade(inner);
        let task = tokio::spawn(async move {
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let line = zeroize::Zeroizing::new(line);
                if line.trim().is_empty() {
                    continue;
                }
                let Ok(resp) = serde_json::from_str::<Response>(&line) else {
                    break;
                };
                let (id, result) = match resp {
                    Response::Ok { id, result, .. } => (id, Ok(result)),
                    Response::Err { id, error, .. } => (id, Err(error)),
                };
                let Some(inner) = inner.upgrade() else { return };
                let mut state = inner.lock().await;
                if state.generation != generation {
                    return;
                }
                if let Some(tx) = state.pending.remove(&id) {
                    let _ = tx.send(result);
                }
            }
            if let Some(inner) = inner.upgrade() {
                let mut state = inner.lock().await;
                if state.generation == generation && state.child.is_some() {
                    state.revoke();
                    state.child = None;
                }
            }
        });
        self.reader = Some(task.abort_handle());
    }

    fn attach_expiry(
        &mut self,
        deadline: tokio::time::Instant,
        inner: &Arc<AsyncMutex<Inner>>,
        generation: u64,
    ) {
        let inner = Arc::downgrade(inner);
        let task = tokio::spawn(async move {
            tokio::time::sleep_until(deadline).await;
            if let Some(inner) = inner.upgrade() {
                let mut state = inner.lock().await;
                if state.generation == generation {
                    state.revoke();
                    state.child = None;
                }
            }
        });
        self.expiry = Some(task.abort_handle());
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // Wake requests waiting for a slot as well as those already waiting for a reply.
        self.requests.close();
        self.task.abort();
        if let Some(reader) = &self.reader {
            // Generic split streams (notably Windows pipes) stay open until both halves drop.
            reader.abort();
        }
        if let Some(expiry) = &self.expiry {
            expiry.abort();
        }
    }
}

/// Remove a pending response even when the caller cancels the future rather than timing out.
struct PendingRequest {
    inner: Arc<AsyncMutex<Inner>>,
    id: u64,
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.inner.try_lock() {
            inner.pending.remove(&self.id);
        } else {
            let inner = self.inner.clone();
            let id = self.id;
            tokio::spawn(async move {
                inner.lock().await.pending.remove(&id);
            });
        }
    }
}

/// True when the launchd daemon is installed and should serve this session (the stdio fallback
/// stays for hosts that predate it or could not be code-signed).
#[cfg(unix)]
fn daemon_socket_available() -> bool {
    std::fs::symlink_metadata(HELPER_SOCKET)
        .map(|m| m.file_type().is_socket())
        .unwrap_or(false)
}

/// On Windows the pipe has no filesystem entry to stat; a successful open means the service is
/// up. PermissionDenied means it exists but we may not talk to it -- still "available" (the
/// real refusal must come from the service, not a client-side guess).
#[cfg(windows)]
fn daemon_socket_available() -> bool {
    // Connect exactly once in unlock(), with server verification and PIPE_BUSY retry. Probing
    // by opening here would consume a service instance and race the actual connection.
    true
}

type HelperConnection = (
    Transport,
    Box<dyn AsyncRead + Unpin + Send>,
    Option<tokio::process::ChildStderr>,
    bool,
);

/// Only the public startup exchange. The caller supplies an already verified connection;
/// owning both halves here also closes them when the enclosing timeout cancels the probe.
async fn probe_protection(
    mut transport: Transport,
    reader: Box<dyn AsyncRead + Unpin + Send>,
) -> Result<Value, SessionError> {
    let message = ProtectionProbe::Status {
        protocol: PROTOCOL_VERSION,
        lang: Some(kv_i18n::lang().as_str().to_string()),
    };
    let mut line = serde_json::to_vec(&message).unwrap();
    line.push(b'\n');
    transport
        .write_all(&line)
        .await
        .map_err(|e| SessionError(format!("Cannot request protection status: {e}")))?;
    let report = kv_platform::protection::read_probe_response(reader)
        .await
        .map_err(|e| SessionError(e.to_string()));
    transport.close();
    report
}

/// Both status probes and unlocks use the same installed-binary and transport peer checks.
async fn connect_helper() -> Result<HelperConnection, SessionError> {
    if let Some(problem) = install_problem() {
        return Err(SessionError(problem));
    }
    let use_daemon = daemon_socket_available();
    #[cfg(windows)]
    let (stdin, read_half, stderr) = {
        // The helper service must answer the pipe itself; there is no stdio fallback on
        // Windows (that path only exists for unsigned sudo-mode installs).
        if !use_daemon {
            return Err(SessionError(kv_i18n::t(
                "KeyValetHelper 服务没有运行，请先启动它",
                "The KeyValetHelper service is not running; start it first",
            )));
        }
        match kv_platform::pipe::connect_service(HELPER_PIPE).await {
            Ok(stream) => {
                // connect_service verifies the kernel-reported server PID, SYSTEM token
                // and installed executable before any credential request is sent.
                let (read, writer) = tokio::io::split(stream);
                (
                    Transport::Socket {
                        writer: Box::new(writer),
                    },
                    Box::new(read) as Box<dyn AsyncRead + Unpin + Send>,
                    None::<tokio::process::ChildStderr>,
                )
            }
            Err(_) => {
                return Err(SessionError(kv_i18n::t(
                    "无法连接 KeyValetHelper 服务",
                    "Cannot connect to the KeyValetHelper service",
                )))
            }
        }
    };
    #[cfg(target_os = "linux")]
    let (stdin, read_half, stderr) = {
        if !use_daemon {
            return Err(SessionError(
                "KeyValet systemd service is not running; run sudo systemctl start keyvalet".into(),
            ));
        }
        let stream = tokio::net::UnixStream::connect(HELPER_SOCKET)
            .await
            .map_err(|e| SessionError(format!("Cannot connect to KeyValet service: {e}")))?;
        let uid = kv_platform::linux::LinuxHost::system()
            .service_identity()
            .map_err(|e| SessionError(e.to_string()))?
            .0;
        use std::os::fd::AsRawFd;
        if kv_platform::peer::peer_uid(stream.as_raw_fd()).ok() != Some(uid) {
            return Err(SessionError(
                "vault socket peer is not the keyvalet service account".into(),
            ));
        }
        let (read, writer) = stream.into_split();
        (
            Transport::Socket {
                writer: Box::new(writer),
            },
            Box::new(read) as Box<dyn AsyncRead + Unpin + Send>,
            None::<tokio::process::ChildStderr>,
        )
    };
    #[cfg(target_os = "macos")]
    let (stdin, read_half, stderr) = if use_daemon {
        // A stale socket or a stopped daemon falls back to the sudo path (kept this
        // version); a socket that answers but isn't root-owned is refused, not fallen back
        // to -- it cannot be our daemon.
        match tokio::net::UnixStream::connect(HELPER_SOCKET).await {
            Ok(stream) => {
                #[cfg(target_os = "macos")]
                let trusted =
                    kv_platform::peer::peer_uid(std::os::unix::io::AsRawFd::as_raw_fd(&stream))
                        .map(|u| u == 0)
                        .unwrap_or(false);
                if !trusted {
                    return Err(SessionError(kv_i18n::t(
                        "凭证库服务套接字不属于 root，拒绝连接",
                        "The vault daemon socket is not root-owned; refusing to connect",
                    )));
                }
                let (read, writer) = stream.into_split();
                (
                    Transport::Socket {
                        writer: Box::new(writer),
                    },
                    Box::new(read) as Box<dyn AsyncRead + Unpin + Send>,
                    None,
                )
            }
            Err(_) => match spawn_sudo_helper() {
                Ok((t, r, e)) => (t, r, Some(e)),
                Err(e) => return Err(e),
            },
        }
    } else {
        match spawn_sudo_helper() {
            Ok((t, r, e)) => (t, r, Some(e)),
            Err(e) => return Err(e),
        }
    };

    Ok((stdin, read_half, stderr, use_daemon))
}

struct Inner {
    child: Option<Connection>,
    ready: bool,
    generation: u64,
    pending: HashMap<u64, Pending>,
    next_id: u64,
    cooldown_until: Option<SystemTime>,
    unlocked_at: Option<SystemTime>,
    unlock_purpose: Option<String>,
}

impl Inner {
    fn revoke(&mut self) {
        crate::gateway_env::cleanup_gateway_env();
        self.generation += 1;
        self.ready = false;
        self.unlocked_at = None;
        self.unlock_purpose = None;
        for (_, pending) in self.pending.drain() {
            let _ = pending.send(Err(kv_i18n::t(
                "凭证库已锁定",
                "Credential vault is locked",
            )));
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Reader/expiry tasks only hold weak references. Dropping the last session owner must
        // also remove private exports, even if no explicit lock or EOF callback can run.
        crate::gateway_env::cleanup_gateway_env();
    }
}

pub struct HelperSession {
    pub session_id: String,
    ttl: Duration,
    inner: Arc<AsyncMutex<Inner>>,
    /// Serializes concurrent `unlock()` calls into a single in-flight attempt: the first caller to
    /// acquire this performs the real unlock; everyone else blocks here and then sees `ready` already
    /// true once it's their turn (equivalent to TS's single shared in-flight promise).
    unlock_lock: Arc<AsyncMutex<()>>,
    /// Serialize approval prompts; the helper decides whether a broad grant already exists.
    grant_lock: Arc<AsyncMutex<()>>,
}

/// A request interface carrying a purpose: tool handlers obtain it via `session.scoped(purpose)`.
pub struct Requester<'a> {
    session: &'a HelperSession,
    purpose: String,
    target: Option<CredentialTarget>,
}
/// Matches TS's `scoped()`: `request: (op, params) => this.request(op, { ...params, purpose
/// }, ...)` -- every call through a `Requester` carries its purpose automatically, so individual
/// tool handlers don't each have to remember to insert it (and real ones didn't:
/// credential_imap_test's accessToken request, and others, omitted it and failed outright with
/// "A purpose is required for this operation" until this was added).
fn with_purpose(mut params: Map<String, Value>, purpose: &str) -> Map<String, Value> {
    params.insert("purpose".into(), Value::String(purpose.to_string()));
    params
}

impl Requester<'_> {
    pub async fn request<T: serde::de::DeserializeOwned>(
        &self,
        op: &str,
        params: Map<String, Value>,
    ) -> Result<T, SessionError> {
        let params = with_purpose(params, &self.purpose);
        let v = self
            .session
            .request_value(op, params, &self.purpose, self.target.as_ref())
            .await?;
        serde_json::from_value(v).map_err(|e| SessionError(format!("malformed response: {e}")))
    }
}

/// Random identifier for this MCP process.
fn gen_session_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 6];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn iso(t: SystemTime) -> Option<String> {
    let since_epoch = t.duration_since(SystemTime::UNIX_EPOCH).ok()?;
    chrono::DateTime::<chrono::Utc>::from_timestamp(
        i64::try_from(since_epoch.as_secs()).ok()?,
        since_epoch.subsec_nanos(),
    )
    .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

fn valid_ttl(ttl: Duration) -> bool {
    use chrono::Datelike;
    chrono::TimeDelta::from_std(ttl)
        .ok()
        .and_then(|ttl| chrono::Utc::now().checked_add_signed(ttl))
        .is_some_and(|end| end.year() <= 9999)
        && tokio::time::Instant::now().checked_add(ttl).is_some()
        && SystemTime::now().checked_add(ttl).is_some()
}

pub fn parse_ttl_minutes(raw: Option<&str>) -> Result<Duration, SessionError> {
    let invalid = || {
        SessionError(
        "KEYVALET_SESSION_TTL_MINUTES must be a nonnegative integer with a representable expiry".into(),
    )
    };
    let Some(raw) = raw else {
        return Ok(Duration::ZERO);
    };
    let seconds = raw
        .parse::<u64>()
        .ok()
        .and_then(|minutes| minutes.checked_mul(60))
        .ok_or_else(invalid)?;
    let ttl = Duration::from_secs(seconds);
    if !valid_ttl(ttl) {
        return Err(invalid());
    }
    Ok(ttl)
}

impl HelperSession {
    pub fn new(ttl: Duration) -> Self {
        Self {
            session_id: gen_session_id(),
            ttl,
            inner: Arc::new(AsyncMutex::new(Inner {
                child: None,
                ready: false,
                generation: 0,
                pending: HashMap::new(),
                next_id: 1,
                cooldown_until: None,
                unlocked_at: None,
                unlock_purpose: None,
            })),
            unlock_lock: Arc::new(AsyncMutex::new(())),
            grant_lock: Arc::new(AsyncMutex::new(())),
        }
    }

    /// Read the connection generation and its public state under the same lock.
    pub(crate) async fn status_snapshot(&self) -> (u64, Value) {
        let inner = self.inner.lock().await;
        let state = if inner.ready {
            "unlocked"
        } else if self.unlock_lock.try_lock().is_err() {
            "unlocking"
        } else {
            "locked"
        };
        let unlocked_at = inner.unlocked_at.and_then(iso);
        let expires_at = if self.ttl > Duration::ZERO {
            inner
                .unlocked_at
                .and_then(|t| t.checked_add(self.ttl))
                .and_then(iso)
        } else {
            None
        };
        let auth = if cfg!(windows) {
            "windows_hello"
        } else if cfg!(target_os = "linux") {
            "polkit"
        } else {
            "touch_id"
        };
        let status = serde_json::json!({
            "state": state, "session": self.session_id, "auth": auth,
            "unlockedAt": unlocked_at, "unlockPurpose": inner.unlock_purpose,
            "expiresAt": expires_at, "installProblem": install_problem(),
        });
        (inner.generation, status)
    }

    /// Public metadata on a separate trusted connection: no unlock, grant or cooldown changes.
    pub async fn protection(&self) -> Result<Value, SessionError> {
        let probe = async {
            let (transport, reader, stderr, _) = connect_helper().await?;
            drop(stderr);
            probe_protection(transport, reader).await
        };
        tokio::time::timeout(PROTECTION_TIMEOUT, probe)
            .await
            .unwrap_or_else(|_| Err(SessionError("Protection status probe timed out".into())))
    }

    /// Read grants only on an existing session; a concurrent lock must never trigger an unlock.
    pub async fn session_info(&self) -> Result<Value, SessionError> {
        self.send("sessionInfo", Map::new(), REQUEST_TIMEOUT).await
    }

    /// Returns a request interface: every request carries the purpose; if unlocking is needed, the
    /// Touch ID prompt shows that purpose. `target` is the credential the tool intends to use: in
    /// per_credential mode, unlocking also authorizes it.
    pub fn scoped(
        &self,
        purpose: impl Into<String>,
        target: Option<CredentialTarget>,
    ) -> Requester<'_> {
        Requester {
            session: self,
            purpose: purpose.into(),
            target,
        }
    }

    pub async fn unlock(
        &self,
        purpose: &str,
        target: Option<&CredentialTarget>,
    ) -> Result<(), SessionError> {
        if self.inner.lock().await.ready {
            return Ok(());
        }
        let _guard = self.unlock_lock.lock().await;
        if self.inner.lock().await.ready {
            return Ok(());
        }
        self.do_unlock(purpose, target).await
    }

    pub async fn lock(&self) {
        let mut inner = self.inner.lock().await;
        inner.revoke();
        inner.child = None;
    }

    async fn request_value(
        &self,
        op: &str,
        params: Map<String, Value>,
        unlock_purpose: &str,
        target: Option<&CredentialTarget>,
    ) -> Result<Value, SessionError> {
        self.unlock(unlock_purpose, target).await?;
        let timeout = if matches!(op, "httpRequest" | "httpTest") {
            PROXY_REQUEST_TIMEOUT
        } else {
            REQUEST_TIMEOUT
        };
        match self.send(op, params.clone(), timeout).await {
            Ok(v) => Ok(v),
            Err(e) => {
                // per_credential mode: this credential isn't authorized yet -> show Touch ID to
                // authorize, then retry once.
                let Some(key) = e.0.strip_prefix(GRANT_REQUIRED_PREFIX) else {
                    return Err(e);
                };
                let Some((ty, name)) = key.trim().split_once('/') else {
                    return Err(e);
                };
                self.grant(ty, name, unlock_purpose, Some(op), Some(&params))
                    .await?;
                self.send(op, params, timeout).await
            }
        }
    }

    /// Send the complete requested operation; trusted prompt text and binding come from root.
    pub async fn grant(
        &self,
        ty: &str,
        name: &str,
        purpose: &str,
        operation: Option<&str>,
        request: Option<&Map<String, Value>>,
    ) -> Result<Value, SessionError> {
        let _guard = self.grant_lock.lock().await;
        let mut params = Map::new();
        params.insert("type".into(), Value::String(ty.to_string()));
        params.insert("name".into(), Value::String(name.to_string()));
        params.insert("purpose".into(), Value::String(purpose.to_string()));
        if let Some(op) = operation {
            params.insert("operation".into(), Value::String(op.into()));
        }
        if let Some(request) = request {
            params.insert("request".into(), Value::Object(request.clone()));
        }
        self.send("grant", params, GRANT_TIMEOUT).await
    }

    async fn send(
        &self,
        op: &str,
        params: Map<String, Value>,
        timeout: Duration,
    ) -> Result<Value, SessionError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let operation = async {
            let (requests, generation) = {
                let inner = self.inner.lock().await;
                let connection = inner
                    .child
                    .as_ref()
                    .filter(|_| inner.ready)
                    .ok_or_else(|| {
                        SessionError(kv_i18n::t(
                            "凭证库未解锁",
                            "Credential vault is not unlocked",
                        ))
                    })?;
                (connection.requests.clone(), inner.generation)
            };
            // Queue outside shared state, within the caller's total deadline. A connection owns
            // the semaphore so lock/expiry/disconnect closes it and wakes queued calls promptly.
            let _permit = requests.acquire_owned().await.map_err(|_| {
                SessionError(kv_i18n::t("helper 已断开连接", "The helper disconnected"))
            })?;
            let (tx, rx) = oneshot::channel();
            let mut inner = self.inner.lock().await;
            if !inner.ready || inner.child.is_none() || inner.generation != generation {
                return Err(SessionError(kv_i18n::t(
                    "凭证库未解锁",
                    "Credential vault is not unlocked",
                )));
            }
            let id = inner.next_id;
            inner.next_id += 1;
            let req = WireRequest {
                id,
                op: op.to_string(),
                params,
            };
            let mut line = zeroize::Zeroizing::new(serde_json::to_vec(&req).unwrap());
            line.push(b'\n');
            let sender = inner.child.as_ref().unwrap().sender.clone();
            inner.pending.insert(id, tx);
            drop(inner);
            let _pending = PendingRequest {
                inner: self.inner.clone(),
                id,
            };
            let (sent, written) = oneshot::channel();
            // Keep lock/disconnect responsive even while waiting for writer backpressure.
            let write = async {
                sender
                    .send(WriteRequest { line, sent })
                    .await
                    .map_err(|_| ())?;
                written.await.map_err(|_| ())?.map_err(|_| ())
            };
            tokio::pin!(rx);
            tokio::select! {
                biased;
                result = &mut rx => return response_result(result),
                result = write => {
                    if result.is_err() {
                        return Err(SessionError(kv_i18n::t("无法写入 helper", "Cannot write to the helper")));
                    }
                }
            }
            response_result(rx.await)
        };
        tokio::time::timeout_at(deadline, operation)
            .await
            .unwrap_or_else(|_| {
                Err(SessionError(kv_i18n::t(
                    "helper 响应超时",
                    "Helper response timed out",
                )))
            })
    }

    /// Records the failure cooldown and tears down the (now-untrusted) child, returning the error
    /// to propagate to the caller.
    async fn fail_unlock(&self, msg: String) -> SessionError {
        {
            let mut inner = self.inner.lock().await;
            inner.cooldown_until = Some(SystemTime::now() + FAILURE_COOLDOWN);
        }
        self.lock().await;
        SessionError(msg)
    }

    async fn do_unlock(
        &self,
        purpose_in: &str,
        target: Option<&CredentialTarget>,
    ) -> Result<(), SessionError> {
        if !valid_ttl(self.ttl) {
            return Err(SessionError(
                "Session TTL is outside the supported clock range".into(),
            ));
        }
        let expected_generation = self.inner.lock().await.generation;
        {
            let inner = self.inner.lock().await;
            if let Some(until) = inner.cooldown_until {
                if let Ok(remaining) = until.duration_since(SystemTime::now()) {
                    let s = remaining.as_secs() + 1;
                    return Err(SessionError(kv_i18n::t(&format!("上次认证失败或被取消，请 {s} 秒后再试"), &format!("The last authentication failed or was cancelled. Try again in {s} seconds."))));
                }
            }
        }
        let purpose = kv_ipc::clean_purpose(Some(purpose_in)).ok_or_else(|| {
            SessionError(kv_i18n::t(
                "必须说明解锁目的（purpose）",
                "An unlock purpose (purpose) is required",
            ))
        })?;
        let (mut stdin, read_half, stderr, use_daemon) = connect_helper().await?;

        let stderr_tail = Arc::new(std::sync::Mutex::new(String::new()));
        if let Some(mut stderr) = stderr {
            let tail = stderr_tail.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let _ = stderr.read_to_end(&mut buf).await;
                let text = String::from_utf8_lossy(&buf).to_string();
                let clipped: String = text
                    .chars()
                    .rev()
                    .take(4096)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                *tail.lock().unwrap() = clipped;
            });
        }

        let auth = AuthMessage {
            op: "auth".to_string(),
            purpose: purpose.clone(),
            requested_mode: std::env::var("KEYVALET_GRANT_MODE").ok(),
            lang: Some(kv_i18n::lang().as_str().to_string()),
            credential: target.and_then(|t| {
                t.name.clone().map(|name| CredentialHint {
                    r#type: t.r#type.clone(),
                    name,
                })
            }),
            cwd: std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            ppid: {
                #[cfg(unix)]
                {
                    std::os::unix::process::parent_id()
                }
                #[cfg(windows)]
                {
                    0
                }
            },
            session: self.session_id.clone(),
            client: "keyvalet".to_string(),
        };
        let mut line = serde_json::to_vec(&auth).unwrap();
        line.push(b'\n');
        if !matches!(
            tokio::time::timeout(UNLOCK_TIMEOUT, stdin.write_all(&line)).await,
            Ok(Ok(()))
        ) {
            stdin.close();
            return Err(SessionError(kv_i18n::t(
                "无法写入 helper",
                "Cannot write to the helper",
            )));
        }

        let mut reader = BufReader::new(read_half);
        let mut first_line = String::new();
        let read_result =
            tokio::time::timeout(UNLOCK_TIMEOUT, reader.read_line(&mut first_line)).await;
        match read_result {
            Err(_) => {
                stdin.close();
                return Err(self
                    .fail_unlock(kv_i18n::t(
                        "等待系统认证超时",
                        "Timed out waiting for system authentication",
                    ))
                    .await);
            }
            Ok(Err(_)) | Ok(Ok(0)) => {
                stdin.close();
                let tail = stderr_tail.lock().unwrap().clone();
                let msg = if use_daemon {
                    kv_i18n::t(
                        "凭证库服务在认证前断开了连接",
                        "The vault daemon disconnected before authenticating",
                    )
                } else {
                    describe_sudo_failure(&tail)
                };
                return Err(self.fail_unlock(msg).await);
            }
            Ok(Ok(_)) => {}
        }
        let msg: ReadyMessage = match serde_json::from_str(first_line.trim()) {
            Ok(m) => m,
            Err(_) => {
                stdin.close();
                return Err(self
                    .fail_unlock(kv_i18n::t(
                        "helper 输出了非法数据",
                        "Helper produced invalid output",
                    ))
                    .await);
            }
        };
        match msg {
            ReadyMessage::Ready { protocol, .. } if protocol == PROTOCOL_VERSION => {}
            ReadyMessage::Ready { .. } => {
                stdin.close();
                return Err(self
                    .fail_unlock(kv_i18n::t(
                        "helper 版本不匹配，请重新安装",
                        "Helper version mismatch; please reinstall",
                    ))
                    .await);
            }
            ReadyMessage::NotReady { error, .. } => {
                stdin.close();
                return Err(self.fail_unlock(error).await);
            }
        }

        let mut inner = self.inner.lock().await;
        if inner.generation != expected_generation {
            stdin.close();
            return Err(SessionError(kv_i18n::t(
                "会话在认证期间已锁定",
                "The session was locked during authentication",
            )));
        }
        let expiry = if self.ttl > Duration::ZERO {
            Some(
                tokio::time::Instant::now()
                    .checked_add(self.ttl)
                    .ok_or_else(|| {
                        SessionError("Session TTL is outside the supported clock range".into())
                    })?,
            )
        } else {
            None
        };
        inner.generation += 1;
        crate::gateway_env::activate_session_files();
        inner.ready = true;
        inner.unlocked_at = Some(SystemTime::now());
        inner.unlock_purpose = Some(purpose);
        inner.cooldown_until = None;
        let mut connection = Connection::new(stdin, &self.inner, inner.generation);
        connection.attach_reader(reader, &self.inner, inner.generation);
        if let Some(deadline) = expiry {
            connection.attach_expiry(deadline, &self.inner, inner.generation);
        }
        // No await after publishing ready: cancellation cannot leave an unlocked session
        // without its reader handle or expiry task. Neither task owns the session state.
        inner.child = Some(connection);
        Ok(())
    }
}

/// Spawns the stdio-mode helper via passwordless sudo; returns the transport, its stdout (boxed
/// for sharing with the socket path), and its stderr for failure diagnosis.
#[cfg(target_os = "macos")]
fn spawn_sudo_helper() -> Result<
    (
        Transport,
        Box<dyn AsyncRead + Unpin + Send>,
        tokio::process::ChildStderr,
    ),
    SessionError,
> {
    let mut cmd = std::process::Command::new(SUDO_BIN);
    cmd.args(["-n", "--", HELPER_BIN])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env("USER", std::env::var("USER").unwrap_or_default())
        .env("LOGNAME", std::env::var("LOGNAME").unwrap_or_default())
        .env("LANG", "en_US.UTF-8");
    let mut child = tokio::process::Command::from(cmd)
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            SessionError(kv_i18n::t(
                &format!("无法启动 sudo：{e}"),
                &format!("Cannot start sudo: {e}"),
            ))
        })?;
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    Ok((Transport::Stdio { stdin, child }, Box::new(stdout), stderr))
}

fn describe_sudo_failure(stderr: &str) -> String {
    let lower = stderr.to_lowercase();
    if lower.contains("password is required") {
        return kv_i18n::t("免密规则未生效（/etc/sudoers.d/keyvalet），请重新运行 ./scripts/install.sh", "The passwordless sudo rule (/etc/sudoers.d/keyvalet) is not in effect; please re-run ./scripts/install.sh");
    }
    if lower.contains("not in the sudoers") || lower.contains("not allowed") {
        return kv_i18n::t("当前用户没有运行 helper 的 sudo 权限，请重新运行 ./scripts/install.sh", "The current user is not allowed to run the helper via sudo; please re-run ./scripts/install.sh");
    }
    let tail: Vec<&str> = stderr.trim().lines().rev().take(3).collect();
    let tail: String = tail.into_iter().rev().collect::<Vec<_>>().join(" | ");
    if tail.is_empty() {
        kv_i18n::t("解锁失败", "Unlock failed")
    } else {
        kv_i18n::t(
            &format!("解锁失败：{tail}"),
            &format!("Unlock failed: {tail}"),
        )
    }
}

/// Verifies the installation: files meant to run as root must exist, be owned by root, and not be
/// writable by others.
#[cfg(target_os = "macos")]
fn install_problem() -> Option<String> {
    let mut paths = vec![kv_platform::paths::INSTALL_DIR, HELPER_BIN, TOUCHID_BIN];
    // The daemon socket is an alternative to the sudoers rule this version (kept as fallback);
    // a correctly daemon-mode install doesn't need the rule.
    if !daemon_socket_available() {
        paths.push(SUDOERS_FILE);
    }
    for p in paths {
        if let Some(reason) = untrusted_reason(Path::new(p)) {
            return Some(kv_i18n::t(
                &format!("安装不安全：{reason}。请重新运行 ./scripts/install.sh"),
                &format!("Insecure installation: {reason}. Please re-run ./scripts/install.sh"),
            ));
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn install_problem() -> Option<String> {
    for path in [
        kv_platform::paths::INSTALL_DIR,
        HELPER_BIN,
        kv_platform::paths::OWNER_UID_FILE,
        kv_platform::paths::POLKIT_POLICY,
    ] {
        if let Some(reason) = untrusted_reason(Path::new(path)) {
            return Some(format!(
                "Insecure installation: {reason}; re-run scripts/install.sh"
            ));
        }
    }
    if let Err(reason) = kv_platform::linux::LinuxHost::system().owner_uid() {
        return Some(reason);
    }
    None
}

/// Both sides of the service/interactive-agent boundary must be installed and DACL-trusted.
#[cfg(windows)]
fn install_problem() -> Option<String> {
    for p in [
        kv_platform::paths::INSTALL_DIR,
        HELPER_BIN,
        kv_platform::paths::AGENT_BIN,
    ] {
        if let Some(reason) = untrusted_reason(Path::new(p)) {
            return Some(kv_i18n::t(
                &format!("安装不安全：{reason}"),
                &format!("Insecure installation: {reason}"),
            ));
        }
    }
    None
}

#[cfg(test)]
mod misc_tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn protection_probe_only_sends_public_fields_and_closes_after_success_or_error() {
        let report: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../kv-ipc/tests/fixtures/hello-protection.json"
        )))
        .unwrap();
        for (response, succeeds) in [
            (
                json!({"id": 0, "ok": true, "result": {"protocol": PROTOCOL_VERSION, "vault_protection": report}}),
                true,
            ),
            (
                json!({"id": 0, "ok": false, "error": "metadata unavailable"}),
                false,
            ),
            (json!({"ready": true, "protocol": PROTOCOL_VERSION}), false),
            (
                json!({"id": 0, "ok": true, "result": {"protocol": PROTOCOL_VERSION, "vault_protection": {}}}),
                false,
            ),
        ] {
            let (stream, peer) = tokio::io::duplex(4096);
            let (reader, writer) = tokio::io::split(stream);
            let request = tokio::spawn(probe_protection(
                Transport::Socket {
                    writer: Box::new(writer),
                },
                Box::new(reader),
            ));
            let mut peer = BufReader::new(peer);
            let mut frame = String::new();
            tokio::time::timeout(Duration::from_secs(1), peer.read_line(&mut frame))
                .await
                .unwrap()
                .unwrap();
            let sent: Value = serde_json::from_str(&frame).unwrap();
            assert_eq!(sent["op"], "protection");
            assert_eq!(sent["protocol"], PROTOCOL_VERSION);
            assert_eq!(sent.as_object().unwrap().len(), 3);
            assert!(sent["lang"].is_string());
            peer.get_mut()
                .write_all(format!("{response}\n").as_bytes())
                .await
                .unwrap();
            peer.get_mut().shutdown().await.unwrap();
            let result = tokio::time::timeout(Duration::from_secs(1), request)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(result.is_ok(), succeeds);
            if succeeds {
                assert_eq!(result.unwrap(), report);
            }
            let mut extra = Vec::new();
            tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut extra))
                .await
                .unwrap()
                .unwrap();
            assert!(
                extra.is_empty(),
                "no auth or credential request may follow a protection probe"
            );
        }
    }

    #[tokio::test]
    async fn timing_out_a_protection_probe_closes_the_connection_without_authentication() {
        let (stream, peer) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(stream);
        let request = tokio::spawn(tokio::time::timeout(
            Duration::from_millis(50),
            probe_protection(
                Transport::Socket {
                    writer: Box::new(writer),
                },
                Box::new(reader),
            ),
        ));
        let mut peer = BufReader::new(peer);
        let mut frame = String::new();
        tokio::time::timeout(Duration::from_secs(1), peer.read_line(&mut frame))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&frame).unwrap()["op"],
            "protection"
        );
        assert!(request.await.unwrap().is_err());
        let mut extra = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut extra))
            .await
            .unwrap()
            .unwrap();
        assert!(extra.is_empty());
    }

    #[tokio::test]
    async fn disconnected_protection_transport_returns_error_without_retry_or_authentication() {
        let (stream, peer) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(stream);
        drop(peer);
        let error = probe_protection(
            Transport::Socket {
                writer: Box::new(writer),
            },
            Box::new(reader),
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("Cannot request protection status"));
    }

    async fn session_with_writer(capacity: usize) -> (Arc<HelperSession>, tokio::io::DuplexStream) {
        let session = Arc::new(HelperSession::new(Duration::ZERO));
        let (stream, peer) = tokio::io::duplex(capacity);
        let (reader, writer) = tokio::io::split(stream);
        let mut inner = session.inner.lock().await;
        inner.ready = true;
        inner.generation = 1;
        inner.child = Some(Connection::new(
            Transport::Socket {
                writer: Box::new(writer),
            },
            &session.inner,
            1,
        ));
        inner
            .child
            .as_mut()
            .unwrap()
            .attach_reader(BufReader::new(reader), &session.inner, 1);
        drop(inner);
        (session, peer)
    }

    #[tokio::test]
    async fn concurrent_calls_queue_before_exceeding_the_helper_request_limit() {
        let (session, peer) = session_with_writer(64 * 1024).await;
        let mut peer = BufReader::new(peer);
        let total = 3 * kv_ipc::MAX_IN_FLIGHT_REQUESTS;
        let mut calls = Vec::new();
        for slot in 0..total {
            let session = session.clone();
            calls.push(tokio::spawn(async move {
                let result = session
                    .send(
                        "list",
                        json!({"slot": slot}).as_object().unwrap().clone(),
                        Duration::from_secs(5),
                    )
                    .await
                    .unwrap();
                assert_eq!(result, slot);
            }));
        }
        let mut initial = Vec::new();
        for _ in 0..kv_ipc::MAX_IN_FLIGHT_REQUESTS {
            let mut line = String::new();
            tokio::time::timeout(Duration::from_secs(1), peer.read_line(&mut line))
                .await
                .unwrap()
                .unwrap();
            initial.push(serde_json::from_str::<WireRequest>(&line).unwrap());
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(30), peer.fill_buf())
                .await
                .is_err(),
            "extra calls must wait for a response before sending another frame"
        );
        assert_eq!(
            session.inner.lock().await.pending.len(),
            kv_ipc::MAX_IN_FLIGHT_REQUESTS
        );
        for request in initial {
            let response = Response::ok(request.id, request.params["slot"].clone());
            peer.get_mut()
                .write_all(format!("{}\n", serde_json::to_string(&response).unwrap()).as_bytes())
                .await
                .unwrap();
        }
        for _ in kv_ipc::MAX_IN_FLIGHT_REQUESTS..total {
            let mut line = String::new();
            tokio::time::timeout(Duration::from_secs(1), peer.read_line(&mut line))
                .await
                .unwrap()
                .unwrap();
            let request: WireRequest = serde_json::from_str(&line).unwrap();
            let response = Response::ok(request.id, request.params["slot"].clone());
            peer.get_mut()
                .write_all(format!("{}\n", serde_json::to_string(&response).unwrap()).as_bytes())
                .await
                .unwrap();
        }
        for call in calls {
            call.await.unwrap();
        }
        assert!(session.inner.lock().await.pending.is_empty());
        session.lock().await;
    }

    #[tokio::test]
    async fn queued_calls_obey_the_total_deadline_and_are_revoked_on_lock() {
        let (session, peer) = session_with_writer(64 * 1024).await;
        let mut peer = BufReader::new(peer);
        let mut calls = Vec::new();
        for _ in 0..kv_ipc::MAX_IN_FLIGHT_REQUESTS {
            let session = session.clone();
            calls.push(tokio::spawn(async move {
                session
                    .send("list", Map::new(), Duration::from_secs(60))
                    .await
            }));
        }
        for _ in 0..kv_ipc::MAX_IN_FLIGHT_REQUESTS {
            tokio::time::timeout(Duration::from_secs(1), peer.read_line(&mut String::new()))
                .await
                .unwrap()
                .unwrap();
        }
        assert!(session
            .send("list", Map::new(), Duration::from_millis(30))
            .await
            .is_err());
        assert_eq!(
            session.inner.lock().await.pending.len(),
            kv_ipc::MAX_IN_FLIGHT_REQUESTS
        );
        let queued = session.clone();
        calls.push(tokio::spawn(async move {
            queued
                .send("list", Map::new(), Duration::from_secs(60))
                .await
        }));
        tokio::task::yield_now().await;
        session.lock().await;
        for call in calls {
            assert!(tokio::time::timeout(Duration::from_secs(1), call)
                .await
                .expect("lock must also wake calls waiting for a request slot")
                .unwrap()
                .is_err());
        }
        assert!(session.inner.lock().await.pending.is_empty());
    }

    #[tokio::test]
    async fn request_timeout_includes_a_blocked_write() {
        let (session, mut peer) = session_with_writer(1).await;
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            session.send("list", Map::new(), Duration::from_millis(20)),
        )
        .await
        .unwrap();
        assert!(result.is_err());
        let mut partial = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut partial))
            .await
            .unwrap()
            .unwrap();
        assert!(!partial.is_empty());
        assert!(
            !partial.contains(&b'\n'),
            "a timed-out partial frame must close the stream"
        );
        assert!(session.inner.lock().await.pending.is_empty());
        session.lock().await;
    }

    #[tokio::test]
    async fn dropping_the_session_closes_the_pipe_and_aborts_its_expiry_task() {
        let (session, mut peer) = session_with_writer(4096).await;
        let weak = Arc::downgrade(&session.inner);
        let expiry = {
            let mut inner = session.inner.lock().await;
            let connection = inner.child.as_mut().unwrap();
            connection.attach_expiry(
                tokio::time::Instant::now() + Duration::from_secs(3600),
                &session.inner,
                1,
            );
            connection.expiry.as_ref().unwrap().clone()
        };
        drop(session);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), peer.read(&mut [0u8; 1]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(weak.upgrade().is_none());
        tokio::time::timeout(Duration::from_secs(1), async {
            while !expiry.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn expiry_closes_the_transport_and_revokes_pending_requests() {
        let (session, peer) = session_with_writer(4096).await;
        {
            let mut inner = session.inner.lock().await;
            inner.child.as_mut().unwrap().attach_expiry(
                tokio::time::Instant::now() + Duration::from_millis(50),
                &session.inner,
                1,
            );
        }
        let caller = session.clone();
        let request = tokio::spawn(async move {
            caller
                .send("list", Map::new(), Duration::from_secs(60))
                .await
        });
        let mut peer = BufReader::new(peer);
        peer.read_line(&mut String::new()).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(1), request)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        let inner = session.inner.lock().await;
        assert!(!inner.ready);
        assert!(inner.child.is_none());
        assert!(inner.pending.is_empty());
    }

    #[tokio::test]
    async fn a_malformed_helper_reply_revokes_the_session_instead_of_waiting_for_timeout() {
        let (session, peer) = session_with_writer(4096).await;
        let caller = session.clone();
        let request = tokio::spawn(async move {
            caller
                .send("list", Map::new(), Duration::from_secs(60))
                .await
        });
        let mut peer = BufReader::new(peer);
        peer.read_line(&mut String::new()).await.unwrap();
        peer.get_mut()
            .write_all(b"{malformed JSON}\n")
            .await
            .unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(1), request)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        assert!(!session.inner.lock().await.ready);
    }

    #[tokio::test]
    async fn lock_revokes_a_request_even_when_the_writer_is_blocked() {
        let (session, mut peer) = session_with_writer(1).await;
        let caller = session.clone();
        let request = tokio::spawn(async move {
            caller
                .send("list", Map::new(), Duration::from_secs(60))
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), peer.read_exact(&mut [0u8; 1]))
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), session.lock())
            .await
            .unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(1), request)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        let inner = session.inner.lock().await;
        assert!(!inner.ready);
        assert!(inner.pending.is_empty());
        assert!(inner.child.is_none());
    }

    #[tokio::test]
    async fn cancelling_a_partial_write_closes_the_transport_and_removes_pending_calls() {
        let (session, mut peer) = session_with_writer(1).await;
        let caller = session.clone();
        let request = tokio::spawn(async move {
            caller
                .send("list", Map::new(), Duration::from_secs(60))
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), peer.read_exact(&mut [0u8; 1]))
            .await
            .unwrap()
            .unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        let mut remaining = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut remaining))
            .await
            .unwrap()
            .unwrap();
        let inner = session.inner.lock().await;
        assert!(!inner.ready);
        assert!(inner.pending.is_empty());
    }

    #[tokio::test]
    async fn concurrent_requests_keep_complete_frames_and_match_out_of_order_replies() {
        let (session, peer) = session_with_writer(4096).await;
        let mut peer = BufReader::new(peer);
        let a = session.clone();
        let b = session.clone();
        let first =
            tokio::spawn(async move { a.send("list", Map::new(), Duration::from_secs(2)).await });
        let second =
            tokio::spawn(async move { b.send("info", Map::new(), Duration::from_secs(2)).await });
        let mut requests = Vec::new();
        for _ in 0..2 {
            let mut line = String::new();
            tokio::time::timeout(Duration::from_secs(1), peer.read_line(&mut line))
                .await
                .unwrap()
                .unwrap();
            requests.push(serde_json::from_str::<WireRequest>(&line).unwrap());
        }
        for request in requests.into_iter().rev() {
            session
                .inner
                .lock()
                .await
                .pending
                .remove(&request.id)
                .unwrap()
                .send(Ok(Value::String(request.op)))
                .unwrap();
        }
        assert_eq!(first.await.unwrap().unwrap(), json!("list"));
        assert_eq!(second.await.unwrap().unwrap(), json!("info"));
        session.lock().await;
    }

    #[tokio::test]
    async fn reply_timeout_removes_the_pending_call_without_corrupting_a_complete_frame() {
        let (session, peer) = session_with_writer(4096).await;
        assert!(session
            .send("list", Map::new(), Duration::from_millis(20))
            .await
            .is_err());
        let mut peer = BufReader::new(peer);
        let mut line = String::new();
        peer.read_line(&mut line).await.unwrap();
        assert_eq!(
            serde_json::from_str::<WireRequest>(&line).unwrap().op,
            "list"
        );
        let inner = session.inner.lock().await;
        assert!(inner.ready);
        assert!(inner.pending.is_empty());
        drop(inner);
        session.lock().await;
    }

    #[tokio::test]
    async fn locking_during_a_status_grant_query_revokes_it_without_unlock_or_cooldown() {
        let (session, peer) = session_with_writer(4096).await;
        let caller = session.clone();
        let query = tokio::spawn(async move { caller.session_info().await });
        let mut peer = BufReader::new(peer);
        let mut frame = String::new();
        tokio::time::timeout(Duration::from_secs(1), peer.read_line(&mut frame))
            .await
            .unwrap()
            .unwrap();
        let request: WireRequest = serde_json::from_str(&frame).unwrap();
        assert_eq!(request.op, "sessionInfo");
        assert!(
            request.params.is_empty(),
            "status must not carry an unlock purpose"
        );
        session.lock().await;
        assert!(tokio::time::timeout(Duration::from_secs(1), query)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        let inner = session.inner.lock().await;
        assert!(!inner.ready);
        assert!(inner.child.is_none());
        assert!(inner.pending.is_empty());
        assert!(inner.cooldown_until.is_none());
        assert!(inner.unlocked_at.is_none());
    }

    #[tokio::test]
    async fn status_grant_query_on_a_locked_session_never_starts_an_unlock() {
        let session = HelperSession::new(Duration::ZERO);
        assert!(session.session_info().await.is_err());
        let inner = session.inner.lock().await;
        assert!(!inner.ready);
        assert!(inner.child.is_none());
        assert!(inner.cooldown_until.is_none());
        assert!(inner.unlocked_at.is_none());
        assert!(inner.pending.is_empty());
    }

    #[test]
    fn with_purpose_inserts_the_purpose_into_the_params() {
        let params = with_purpose(Map::new(), "test the thing");
        assert_eq!(params["purpose"], "test the thing");
    }

    #[test]
    fn with_purpose_overrides_any_purpose_the_caller_already_set() {
        // A caller passing its own (possibly stale, possibly absent) "purpose" must not win over
        // the Requester's real one -- this is what actually fixed credential_imap_test et al.,
        // not just adding the key when it was missing.
        let mut params = Map::new();
        params.insert("purpose".into(), serde_json::json!("stale or wrong"));
        let params = with_purpose(params, "the real purpose");
        assert_eq!(params["purpose"], "the real purpose");
    }

    #[test]
    fn gen_session_id_is_twelve_lowercase_hex_characters() {
        let id = gen_session_id();
        assert_eq!(id.len(), 12);
        assert!(id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn gen_session_id_is_not_the_same_every_call() {
        // Astronomically unlikely to collide (2^48 space) unless the RNG itself is broken.
        assert_ne!(gen_session_id(), gen_session_id());
    }

    #[test]
    fn iso_formats_as_rfc3339_with_millis_and_a_z_suffix() {
        let t = std::time::UNIX_EPOCH + Duration::from_millis(1_234);
        assert_eq!(iso(t).as_deref(), Some("1970-01-01T00:00:01.234Z"));
        if let Some(far_future) =
            SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(20_000_000_000_000))
        {
            assert!(iso(far_future).is_none());
        }
    }

    #[test]
    fn ttl_configuration_rejects_overflow_and_unrepresentable_dates() {
        assert_eq!(parse_ttl_minutes(None).unwrap(), Duration::ZERO);
        assert_eq!(parse_ttl_minutes(Some("0")).unwrap(), Duration::ZERO);
        assert_eq!(
            parse_ttl_minutes(Some("30")).unwrap(),
            Duration::from_secs(1800)
        );
        for raw in [
            "",
            "-1",
            "invalid",
            "18446744073709551615",
            "307445734561825860",
        ] {
            assert!(parse_ttl_minutes(Some(raw)).is_err(), "{raw}");
        }
    }

    #[test]
    fn describe_sudo_failure_recognizes_the_missing_passwordless_rule() {
        let msg = describe_sudo_failure("sudo: a password is required");
        assert!(msg.contains("sudoers.d/keyvalet") || msg.contains("install.sh"));
    }

    #[test]
    fn describe_sudo_failure_recognizes_a_user_not_in_sudoers() {
        let msg = describe_sudo_failure("guang is not in the sudoers file");
        assert!(msg.to_lowercase().contains("sudo") || msg.contains("install.sh"));
        let msg2 = describe_sudo_failure("sorry, user guang is not allowed to execute");
        assert!(msg2.contains("install.sh"));
    }

    #[test]
    fn describe_sudo_failure_falls_back_to_the_last_lines_of_stderr() {
        let msg = describe_sudo_failure("line one\nline two\nline three\nline four");
        // Only the last 3 lines, oldest first.
        assert!(!msg.contains("line one"));
        assert!(msg.contains("line two"));
        assert!(msg.contains("line three"));
        assert!(msg.contains("line four"));
    }

    #[test]
    fn describe_sudo_failure_on_empty_stderr_is_a_generic_message() {
        let msg = describe_sudo_failure("");
        assert!(msg.contains("Unlock failed") || msg.contains("解锁失败"));
    }

    #[test]
    #[ignore = "Requires an installed KeyValet; cargo test -p kv-mcp install_problem_is_none -- --ignored"]
    fn install_problem_is_none_on_a_correctly_installed_machine() {
        // Unlike generic OS-owned path fixtures, this explicitly needs a real installation.
        assert_eq!(install_problem(), None);
    }
}
