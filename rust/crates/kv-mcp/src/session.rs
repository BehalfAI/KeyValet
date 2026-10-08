//! One MCP server process = one agent session.
//! The first time a credential needs to be accessed, a root helper is launched via `sudo -n`
//! (sudoers only allows the helper itself to run passwordlessly); a handshake message (purpose,
//! source directory, session ID) is sent first, and the helper only starts serving requests
//! after Touch ID (showing the purpose) succeeds.
//! Once authenticated, no further authentication is needed for the rest of this session; when
//! this process exits (session ends) -> the pipe closes -> the helper exits.
//! Direct port of src/server/session.ts.

use kv_ipc::{
    AuthMessage, CredentialHint, ReadyMessage, Request as WireRequest, Response,
    GRANT_REQUIRED_PREFIX, PROTOCOL_VERSION,
};
use kv_platform::paths::{HELPER_BIN, SUDOERS_FILE, SUDO_BIN, TOUCHID_BIN};
use kv_platform::trust::untrusted_reason;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
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

struct ChildHandle {
    stdin: ChildStdin,
    child: Child,
}

struct Inner {
    child: Option<ChildHandle>,
    ready: bool,
    pending: HashMap<u64, Pending>,
    next_id: u64,
    cooldown_until: Option<SystemTime>,
    unlocked_at: Option<SystemTime>,
    unlock_purpose: Option<String>,
}

pub struct HelperSession {
    pub session_id: String,
    ttl: Duration,
    inner: Arc<AsyncMutex<Inner>>,
    /// Serializes concurrent `unlock()` calls into a single in-flight attempt: the first caller to
    /// acquire this performs the real unlock; everyone else blocks here and then sees `ready` already
    /// true once it's their turn (equivalent to TS's single shared in-flight promise).
    unlock_lock: Arc<AsyncMutex<()>>,
    /// Same coalescing trick for `grant()` -- simplified to one global lock rather than per-credential
    /// (concurrent grants for different credentials still end up serialized by the helper's own
    /// cross-process auth lock, so this costs nothing in practice), remembering only the single most
    /// recently granted key (matches this session's actual usage pattern: one credential at a time).
    grant_lock: Arc<AsyncMutex<()>>,
    last_granted: Arc<std::sync::Mutex<Option<String>>>,
}

/// A request interface carrying a purpose: tool handlers obtain it via `session.scoped(purpose)`.
pub struct Requester<'a> {
    session: &'a HelperSession,
    purpose: String,
    target: Option<CredentialTarget>,
}
impl Requester<'_> {
    pub async fn request<T: serde::de::DeserializeOwned>(
        &self,
        op: &str,
        params: Map<String, Value>,
    ) -> Result<T, SessionError> {
        let v = self
            .session
            .request_value(op, params, &self.purpose, self.target.as_ref())
            .await?;
        serde_json::from_value(v).map_err(|e| SessionError(format!("malformed response: {e}")))
    }
}

/// `"METHOD host/path"` for an httpRequest/httpTest op's params, e.g. `"POST api.openai.com/v1/
/// chat/completions"` -- mirrors `kv_proxy::proxy::describe_target`'s format (not reused directly:
/// this crate doesn't otherwise depend on kv-proxy, which is the privileged helper's concern, not
/// the unprivileged MCP server's). Deliberately drops the query string, same as the audit log.
fn http_request_hint(params: &Map<String, Value>) -> Option<String> {
    let url = params.get("url")?.as_str()?;
    let method = params
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET");
    let u = url::Url::parse(url).ok()?;
    let s = format!("{} {}{}", method.to_uppercase(), u.host_str()?, u.path());
    Some(s.chars().take(300).collect())
}

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
                pending: HashMap::new(),
                next_id: 1,
                cooldown_until: None,
                unlocked_at: None,
                unlock_purpose: None,
            })),
            unlock_lock: Arc::new(AsyncMutex::new(())),
            grant_lock: Arc::new(AsyncMutex::new(())),
            last_granted: Arc::new(std::sync::Mutex::new(None)),
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
        inner.ready = false;
        inner.unlocked_at = None;
        inner.unlock_purpose = None;
        for (_, p) in inner.pending.drain() {
            let _ = p.send(Err(kv_i18n::t(
                "凭证库已锁定",
                "Credential vault is locked",
            )));
        }
        if let Some(mut c) = inner.child.take() {
            let _ = c.stdin.shutdown().await;
            let _ = c.child.start_kill();
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
        // For an HTTP-shaped op, show the Touch ID prompt what it's actually about to send
        // (method + host + path -- not the query string, matching how this same call is later
        // audited). Built from the very params this call is sending, not re-derived later, so it
        // can't drift from the real request; it's still just a display hint, never a cryptographic
        // binding -- see the comment beside `request_hint` in kv-core's `grant_credential`.
        let request_hint = matches!(op, "httpRequest" | "httpTest")
            .then(|| http_request_hint(&params))
            .flatten();
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
                self.grant(ty, name, unlock_purpose, request_hint.as_deref())
                    .await?;
                self.send(op, params, timeout).await
            }
        }
    }

    /// Authorizes this session to use a credential (concurrent grants are coalesced into a single
    /// prompt -- see the `grant_lock` doc comment). `request_hint`: see `request_value`.
    pub async fn grant(
        &self,
        ty: &str,
        name: &str,
        purpose: &str,
        request_hint: Option<&str>,
    ) -> Result<Value, SessionError> {
        let key = format!("{ty}/{name}");
        let _guard = self.grant_lock.lock().await;
        if self.last_granted.lock().unwrap().as_deref() == Some(key.as_str()) {
            return Ok(serde_json::json!({"granted": key, "already": true}));
        }
        let mut params = Map::new();
        params.insert("type".into(), Value::String(ty.to_string()));
        params.insert("name".into(), Value::String(name.to_string()));
        params.insert("purpose".into(), Value::String(purpose.to_string()));
        if let Some(h) = request_hint {
            params.insert("request_hint".into(), Value::String(h.to_string()));
        }
        let r = self.send("grant", params, GRANT_TIMEOUT).await?;
        *self.last_granted.lock().unwrap() = Some(key);
        Ok(r)
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
            if ch.stdin.write_all(&line).await.is_err() {
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

        // -n: never prompt for a password; the sudoers rule only allows the helper to run
        // passwordlessly, and authentication is done via Touch ID inside the helper.
        let mut cmd = tokio::process::Command::new(SUDO_BIN);
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
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return Err(SessionError(kv_i18n::t(
                    &format!("无法启动 sudo：{e}"),
                    &format!("Cannot start sudo: {e}"),
                )))
            }
        };
        let mut stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();

        let stderr_tail = Arc::new(std::sync::Mutex::new(String::new()));
        {
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
            let _ = child.start_kill();
            return Err(SessionError(kv_i18n::t(
                "无法写入 helper",
                "Cannot write to the helper",
            )));
        }

        let mut reader = BufReader::new(stdout);
        let mut first_line = String::new();
        let read_result =
            tokio::time::timeout(UNLOCK_TIMEOUT, reader.read_line(&mut first_line)).await;
        match read_result {
            Err(_) => {
                let _ = child.start_kill();
                return Err(self
                    .fail_unlock(kv_i18n::t(
                        "等待 Touch ID 认证超时",
                        "Timed out waiting for Touch ID authentication",
                    ))
                    .await);
            }
            Ok(Err(_)) | Ok(Ok(0)) => {
                let tail = stderr_tail.lock().unwrap().clone();
                return Err(self.fail_unlock(describe_sudo_failure(&tail)).await);
            }
            Ok(Ok(_)) => {}
        }
        let msg: ReadyMessage = match serde_json::from_str(first_line.trim()) {
            Ok(m) => m,
            Err(_) => {
                let _ = child.start_kill();
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
                let _ = child.start_kill();
                return Err(self
                    .fail_unlock(kv_i18n::t(
                        "helper 版本不匹配，请重新安装",
                        "Helper version mismatch; please reinstall",
                    ))
                    .await);
            }
            ReadyMessage::NotReady { error, .. } => {
                let _ = child.start_kill();
                return Err(self.fail_unlock(error).await);
            }
        }

        {
            let mut inner = self.inner.lock().await;
            inner.ready = true;
            inner.unlocked_at = Some(SystemTime::now());
            inner.unlock_purpose = Some(purpose);
            inner.cooldown_until = None;
            inner.child = Some(ChildHandle { stdin, child });
        }
        *self.last_granted.lock().unwrap() = None;

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
                if let Some(tx) = inner.lock().await.pending.remove(&id) {
                    let _ = tx.send(result);
                }
            }
            // EOF or read error: the helper exited.
            // The helper exited (or the pipe closed) on its own: clear state so the next request
            // re-authenticates rather than hanging forever waiting for a dead child.
            let mut g = inner.lock().await;
            if g.child.is_some() {
                g.ready = false;
                g.child = None;
                for (_, p) in g.pending.drain() {
                    let _ = p.send(Err(kv_i18n::t("helper 已退出", "The helper exited")));
                }
            }
        });

        if self.ttl > Duration::ZERO {
            let inner2 = self.inner.clone();
            let ttl = self.ttl;
            tokio::spawn(async move {
                tokio::time::sleep(ttl).await;
                let mut g = inner2.lock().await;
                g.ready = false;
                g.unlocked_at = None;
                g.unlock_purpose = None;
                if let Some(mut c) = g.child.take() {
                    let _ = c.stdin.shutdown().await;
                    let _ = c.child.start_kill();
                }
            });
        }
        Ok(())
    }
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
    for p in [
        kv_platform::paths::INSTALL_DIR,
        HELPER_BIN,
        TOUCHID_BIN,
        SUDOERS_FILE,
    ] {
        if let Some(reason) = untrusted_reason(Path::new(p)) {
            return Some(kv_i18n::t(
                &format!("安装不安全：{reason}。请重新运行 ./scripts/install.sh"),
                &format!("Insecure installation: {reason}. Please re-run ./scripts/install.sh"),
            ));
        }
    }
    None
}
