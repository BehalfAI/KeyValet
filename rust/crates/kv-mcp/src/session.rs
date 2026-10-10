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
    AuthMessage, CredentialHint, ReadyMessage, Request as WireRequest, Response,
    GRANT_REQUIRED_PREFIX, PROTOCOL_VERSION,
};
use kv_platform::paths::{HELPER_BIN, HELPER_SOCKET, SUDOERS_FILE, SUDO_BIN, TOUCHID_BIN};
use kv_platform::trust::untrusted_reason;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin};
use tokio::sync::{oneshot, Mutex as AsyncMutex};

const UNLOCK_TIMEOUT: Duration = Duration::from_millis(180_000);
const REQUEST_TIMEOUT: Duration = Duration::from_millis(60_000);
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

/// The session's byte stream to the helper: a sudo-spawned child's pipes (fallback mode), or a
/// Unix-socket connection to the launchd daemon when HELPER_SOCKET exists.
enum Transport {
    Stdio {
        stdin: ChildStdin,
        child: Child,
    },
    Socket {
        writer: tokio::net::unix::OwnedWriteHalf,
    },
}

impl Transport {
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Transport::Stdio { stdin, .. } => stdin.write_all(buf).await,
            Transport::Socket { writer } => writer.write_all(buf).await,
        }
    }

    async fn close(&mut self) {
        match self {
            Transport::Stdio { stdin, child } => {
                let _ = stdin.shutdown().await;
                let _ = child.start_kill();
            }
            Transport::Socket { writer } => {
                let _ = writer.shutdown().await;
            }
        }
    }
}

/// True when the launchd daemon is installed and should serve this session (the stdio fallback
/// stays for hosts that predate it or could not be code-signed).
fn daemon_socket_available() -> bool {
    std::fs::symlink_metadata(HELPER_SOCKET)
        .map(|m| m.file_type().is_socket())
        .unwrap_or(false)
}

struct Inner {
    child: Option<Transport>,
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

fn iso(t: SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
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

    pub async fn status(&self) -> Value {
        let inner = self.inner.lock().await;
        let state = if inner.ready {
            "unlocked"
        } else if self.unlock_lock.try_lock().is_err() {
            "unlocking"
        } else {
            "locked"
        };
        let unlocked_at = inner.unlocked_at.map(iso);
        let expires_at = if self.ttl > Duration::ZERO {
            inner.unlocked_at.map(|t| iso(t + self.ttl))
        } else {
            None
        };
        serde_json::json!({
            "state": state, "session": self.session_id, "auth": "touch_id",
            "unlockedAt": unlocked_at, "unlockPurpose": inner.unlock_purpose,
            "expiresAt": expires_at, "installProblem": install_problem(),
        })
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
        if let Some(mut c) = inner.child.take() {
            c.close().await;
        }
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
        let (tx, rx) = oneshot::channel();
        let id;
        {
            let mut inner = self.inner.lock().await;
            if !inner.ready || inner.child.is_none() {
                return Err(SessionError(kv_i18n::t(
                    "凭证库未解锁",
                    "Credential vault is not unlocked",
                )));
            }
            id = inner.next_id;
            inner.next_id += 1;
            let req = WireRequest {
                id,
                op: op.to_string(),
                params,
            };
            let mut line = serde_json::to_vec(&req).unwrap();
            line.push(b'\n');
            let ch = inner.child.as_mut().unwrap();
            if ch.write_all(&line).await.is_err() {
                return Err(SessionError(kv_i18n::t(
                    "无法写入 helper",
                    "Cannot write to the helper",
                )));
            }
            inner.pending.insert(id, tx);
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(Ok(v))) => Ok(v),
            Ok(Ok(Err(e))) => Err(SessionError(e)),
            Ok(Err(_)) => Err(SessionError(kv_i18n::t(
                "helper 已断开连接",
                "The helper disconnected",
            ))),
            Err(_) => {
                self.inner.lock().await.pending.remove(&id);
                Err(SessionError(kv_i18n::t(
                    "helper 响应超时",
                    "Helper response timed out",
                )))
            }
        }
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
        if let Some(problem) = install_problem() {
            return Err(SessionError(problem));
        }

        let use_daemon = daemon_socket_available();
        let (mut stdin, read_half, stderr) = if use_daemon {
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
                    #[cfg(not(target_os = "macos"))]
                    let trusted = false;
                    if !trusted {
                        return Err(SessionError(kv_i18n::t(
                            "凭证库服务套接字不属于 root，拒绝连接",
                            "The vault daemon socket is not root-owned; refusing to connect",
                        )));
                    }
                    let (read, writer) = stream.into_split();
                    (
                        Transport::Socket { writer },
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
            ppid: std::os::unix::process::parent_id(),
            session: self.session_id.clone(),
            client: "keyvalet".to_string(),
        };
        let mut line = serde_json::to_vec(&auth).unwrap();
        line.push(b'\n');
        if stdin.write_all(&line).await.is_err() {
            stdin.close().await;
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
                stdin.close().await;
                return Err(self
                    .fail_unlock(kv_i18n::t(
                        "等待 Touch ID 认证超时",
                        "Timed out waiting for Touch ID authentication",
                    ))
                    .await);
            }
            Ok(Err(_)) | Ok(Ok(0)) => {
                stdin.close().await;
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
                stdin.close().await;
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
                stdin.close().await;
                return Err(self
                    .fail_unlock(kv_i18n::t(
                        "helper 版本不匹配，请重新安装",
                        "Helper version mismatch; please reinstall",
                    ))
                    .await);
            }
            ReadyMessage::NotReady { error, .. } => {
                stdin.close().await;
                return Err(self.fail_unlock(error).await);
            }
        }

        let generation = {
            let mut inner = self.inner.lock().await;
            if inner.generation != expected_generation {
                stdin.close().await;
                return Err(SessionError(kv_i18n::t(
                    "会话在认证期间已锁定",
                    "The session was locked during authentication",
                )));
            }
            inner.generation += 1;
            crate::gateway_env::activate_session_files();
            inner.ready = true;
            inner.unlocked_at = Some(SystemTime::now());
            inner.unlock_purpose = Some(purpose);
            inner.cooldown_until = None;
            inner.child = Some(stdin);
            inner.generation
        };

        // Pump the helper's remaining stdout lines (Responses) to whichever request is waiting.
        let inner = self.inner.clone();
        tokio::spawn(async move {
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.trim().is_empty() {
                    continue;
                }
                let Ok(resp) = serde_json::from_str::<Response>(&line) else {
                    continue;
                };
                let (id, result) = match resp {
                    Response::Ok { id, result, .. } => (id, Ok(result)),
                    Response::Err { id, error, .. } => (id, Err(error)),
                };
                let mut state = inner.lock().await;
                if state.generation != generation {
                    return;
                }
                if let Some(tx) = state.pending.remove(&id) {
                    let _ = tx.send(result);
                }
            }
            // EOF or read error: the helper exited.
            // The helper exited (or the pipe closed) on its own: clear state so the next request
            // re-authenticates rather than hanging forever waiting for a dead child.
            let mut g = inner.lock().await;
            if g.generation == generation && g.child.is_some() {
                g.revoke();
                g.child = None;
            }
        });

        if self.ttl > Duration::ZERO {
            let inner2 = self.inner.clone();
            let ttl = self.ttl;
            tokio::spawn(async move {
                tokio::time::sleep(ttl).await;
                let mut g = inner2.lock().await;
                if g.generation != generation {
                    return;
                }
                g.revoke();
                if let Some(mut c) = g.child.take() {
                    c.close().await;
                }
            });
        }
        Ok(())
    }
}

/// Spawns the stdio-mode helper via passwordless sudo; returns the transport, its stdout (boxed
/// for sharing with the socket path), and its stderr for failure diagnosis.
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
    let mut child = tokio::process::Command::from(cmd).spawn().map_err(|e| {
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

#[cfg(test)]
mod misc_tests {
    use super::*;

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
        assert_eq!(iso(t), "1970-01-01T00:00:01.234Z");
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
    fn install_problem_is_none_on_a_correctly_installed_machine() {
        // Environment-dependent, like kv_platform::trust's own
        // root_owned_read_only_system_paths_are_trusted test: only assert on a machine where
        // KeyValet is actually installed (this is the exact regression check for the /etc
        // symlink bug fixed in kv_platform::trust::untrusted_reason -- that bug made this
        // return Some(...) on every stock Mac, permanently blocking MCP unlock).
        if std::path::Path::new(kv_platform::paths::INSTALL_DIR).is_dir() {
            assert_eq!(install_problem(), None);
        }
    }
}
