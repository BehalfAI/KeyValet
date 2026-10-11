//! The daemon-side registry of per-user agents (`kv-touchid --agent` connected to AGENT_SOCKET)
//! and the `Authenticator` / `Confirmer` / `MasterKeyProvider` implementations that route every
//! UI and Secure Enclave operation through them. The LaunchAgent runs in the user's Aqua session;
//! Apple does not support these operations inside a launchd daemon. Before registering, a
//! connection is checked by peer uid and code signature (`peer::verify_peer_code`), so a same-user
//! process cannot impersonate the agent and approve prompts on the user's behalf.

#[cfg(unix)]
use crate::paths::AGENT_LABEL;
#[cfg(unix)]
use crate::paths::TOUCHID_BIN;
use crate::{AuthOutcome, Authenticator, Confirmer};
use kv_ipc::agent as wire;
use kv_vault::{EnclaveKey, EnclaveMetadata, MasterKey, MasterKeyProvider, Result, VaultError};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::{oneshot, Mutex as AsyncMutex};

/// The agent registry key: the unix uid on macOS, the owner's text SID on Windows.
#[cfg(unix)]
pub type AgentKey = u32;
/// The agent registry key: the unix uid on macOS, the owner's text SID on Windows.
#[cfg(windows)]
pub type AgentKey = String;

pub const REQUEST_TIMEOUT: Duration = Duration::from_millis(130_000);
const KICKSTART_WAIT: Duration = Duration::from_secs(5);

type Payload = (wire::EnclavePayload, usize);
type PendingReply = std::result::Result<(Value, Option<Payload>), String>;

/// One verified agent connection: serialized outgoing requests, a reader pump that pairs
/// replies (and enclave payload frames) with pending oneshots.
struct AgentConn {
    writer: AsyncMutex<Option<Box<dyn AsyncWrite + Unpin + Send>>>,
    reader_task: Mutex<Option<tokio::task::AbortHandle>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<PendingReply>>>,
    next_id: AtomicU64,
    dead: AtomicBool,
}

struct AgentPending<'a> {
    conn: &'a AgentConn,
    id: u64,
}

impl Drop for AgentPending<'_> {
    fn drop(&mut self) {
        self.conn.pending.lock().unwrap().remove(&self.id);
    }
}

struct AgentWrite<'a> {
    conn: &'a AgentConn,
    writer: tokio::sync::MutexGuard<'a, Option<Box<dyn AsyncWrite + Unpin + Send>>>,
    complete: bool,
}

impl Drop for AgentWrite<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.writer.take();
            self.conn.fail_all("agent write cancelled or failed");
        }
    }
}

impl AgentConn {
    fn start<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(stream: S) -> Arc<Self> {
        let (reader, writer) = tokio::io::split(stream);
        let conn = Arc::new(Self {
            writer: AsyncMutex::new(Some(Box::new(writer))),
            reader_task: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            dead: AtomicBool::new(false),
        });
        let pump = conn.clone();
        let task = tokio::spawn(async move { pump.read_loop(Box::new(reader)).await });
        *conn.reader_task.lock().unwrap() = Some(task.abort_handle());
        conn
    }

    fn fail_all(&self, reason: &str) {
        self.dead.store(true, Ordering::SeqCst);
        if let Some(task) = self.reader_task.lock().unwrap().as_ref() {
            task.abort();
        }
        if let Ok(mut writer) = self.writer.try_lock() {
            writer.take();
        }
        for (_, tx) in self.pending.lock().unwrap().drain() {
            let _ = tx.send(Err(reason.to_string()));
        }
    }

    /// Header lines are read byte-by-byte (they are tiny; a few messages per session) so no
    /// read ever pulls enclave payload bytes into a growable/non-zeroizing buffer -- the key
    /// material goes straight into a fixed `Zeroizing` buffer and nowhere else.
    async fn read_loop(&self, mut reader: Box<dyn AsyncRead + Unpin + Send>) {
        loop {
            let mut line: Vec<u8> = Vec::new();
            let mut byte = [0u8; 1];
            let line_result: std::result::Result<(), String> = loop {
                match reader.read(&mut byte).await {
                    Ok(0) => break Err("agent disconnected".to_string()),
                    Ok(_) if byte[0] == b'\n' => break Ok(()),
                    Ok(_) => {
                        line.push(byte[0]);
                        if line.len() > wire::MAX_LINE_BYTES {
                            break Err("agent reply line too large".to_string());
                        }
                    }
                    Err(e) => break Err(format!("agent read failed: {e}")),
                }
            };
            if let Err(e) = line_result {
                self.fail_all(&e);
                return;
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let Ok(header) = serde_json::from_slice::<Value>(&line) else {
                self.fail_all("invalid agent reply JSON");
                return;
            };
            // The binary frame of an enclave reply follows its header immediately.
            if header.get("len").is_some() {
                match wire::enclave_len(&header) {
                    Ok(len) => {
                        let mut payload: wire::EnclavePayload =
                            zeroize::Zeroizing::new([0u8; wire::MAX_ENCLAVE_PAYLOAD + 1]);
                        let mut filled = 0;
                        let mut ok = true;
                        while filled < len {
                            match reader.read(&mut payload[filled..len]).await {
                                Ok(0) | Err(_) => {
                                    ok = false;
                                    break;
                                }
                                Ok(n) => filled += n,
                            }
                        }
                        if !ok {
                            self.fail_all("truncated enclave payload");
                            return;
                        }
                        self.deliver(&header, Ok((header.clone(), Some((payload, len)))));
                    }
                    Err(e) => {
                        // The frame cannot be skipped safely: its bytes might contain newlines
                        // or valid JSON. Never interpret them as replies to other requests.
                        self.fail_all(&e);
                        return;
                    }
                }
                continue;
            }
            self.deliver(&header, Ok((header.clone(), None)));
        }
    }

    fn deliver(&self, header: &Value, reply: PendingReply) {
        if let Some(id) = header.get("id").and_then(Value::as_u64) {
            if let Some(tx) = self.pending.lock().unwrap().remove(&id) {
                let _ = tx.send(reply);
            }
        }
    }

    async fn request(self: &Arc<Self>, msg: Value, timeout: Duration) -> PendingReply {
        if self.dead.load(Ordering::SeqCst) {
            return Err("agent disconnected".to_string());
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let mut msg = msg;
        msg["id"] = json!(id);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        let _pending = AgentPending { conn: self, id };
        let operation = async {
            let line = wire::encode_line(&msg);
            let writer = self.writer.lock().await;
            if self.dead.load(Ordering::SeqCst) || writer.is_none() {
                return Err("agent disconnected".to_string());
            }
            let mut writer = AgentWrite {
                conn: self,
                writer,
                complete: false,
            };
            tokio::pin!(rx);
            tokio::select! {
                biased;
                result = &mut rx => return result.unwrap_or_else(|_| Err("agent disconnected".to_string())),
                result = writer.writer.as_mut().unwrap().write_all(&line) => {
                    result.map_err(|e| format!("cannot write to the agent: {e}"))?;
                }
            }
            writer.complete = true;
            drop(writer);
            rx.await
                .unwrap_or_else(|_| Err("agent disconnected".to_string()))
        };
        match tokio::time::timeout(timeout, operation).await {
            Ok(result) => result,
            Err(_) => Err("agent request timed out".to_string()),
        }
    }
}

/// AgentKey -> verified agent connection, shared daemon-wide.
#[derive(Default)]
pub struct AgentHub {
    conns: Mutex<HashMap<AgentKey, Arc<AgentConn>>>,
    prompt_locks: Mutex<HashMap<AgentKey, Arc<AsyncMutex<()>>>>,
    /// How the currently registered agent was accepted ("signed" / "unsigned"); exposed to the
    /// session status so `agent_trust` says what it means.
    trust: Mutex<&'static str>,
}

impl AgentHub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Registers a freshly verified agent stream for `key`, replacing any older connection.
    pub fn register<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        &self,
        key: AgentKey,
        stream: S,
        trust: &'static str,
    ) {
        *self.trust.lock().unwrap() = trust;
        let conn = AgentConn::start(stream);
        if let Some(old) = self.conns.lock().unwrap().insert(key, conn) {
            old.fail_all("replaced by a new agent connection");
        }
    }

    /// How the current agent connection was accepted; "none" when no agent has registered.
    pub fn agent_trust(&self) -> &'static str {
        if self
            .conns
            .lock()
            .unwrap()
            .values()
            .all(|c| c.dead.load(Ordering::SeqCst))
        {
            return "none";
        }
        *self.trust.lock().unwrap()
    }

    pub fn has_live_agent(&self, key: &AgentKey) -> bool {
        self.conn(key).is_some()
    }

    /// One prompt at a time per user: dialogs/flows queue rather than stacking.
    fn prompt_lock(&self, key: &AgentKey) -> Arc<AsyncMutex<()>> {
        self.prompt_locks
            .lock()
            .unwrap()
            .entry({
                #[allow(clippy::clone_on_copy)] // AgentKey is String on Windows, u32 elsewhere
                key.clone()
            })
            .or_default()
            .clone()
    }

    fn conn(&self, key: &AgentKey) -> Option<Arc<AgentConn>> {
        let conn = self.conns.lock().unwrap().get(key).cloned();
        conn.filter(|c| !c.dead.load(Ordering::SeqCst))
    }

    /// Returns the agent connection. On macOS the LaunchAgent is kickstarted once if it isn't
    /// up yet (launchctl runs it lazily). On Windows the service creates its protected agent
    /// at startup or on an interactive launch notification. Wait a short window for either.
    async fn ensure(&self, key: &AgentKey) -> std::result::Result<Arc<AgentConn>, String> {
        if let Some(conn) = self.conn(key) {
            return Ok(conn);
        }
        #[cfg(unix)]
        {
            let _ = tokio::process::Command::new("/bin/launchctl")
                .arg("kickstart")
                .arg("-k")
                .arg(format!("gui/{key}/{AGENT_LABEL}"))
                .env_clear()
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .await;
        }
        let deadline = std::time::Instant::now() + KICKSTART_WAIT;
        loop {
            if let Some(conn) = self.conn(key) {
                return Ok(conn);
            }
            if std::time::Instant::now() > deadline {
                return Err(kv_i18n::t(
                    "用户会话代理未运行，无法进行界面或硬件认证",
                    "The per-user agent is not running; UI and hardware authentication are unavailable",
                )
                .to_string());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub async fn request(&self, key: &AgentKey, msg: Value, timeout: Duration) -> PendingReply {
        let conn = self.ensure(key).await?;
        conn.request(msg, timeout).await
    }
}

#[derive(Clone)]
pub struct AgentAuthenticator {
    pub hub: Arc<AgentHub>,
    pub key: AgentKey,
}

impl Authenticator for AgentAuthenticator {
    async fn authenticate(&self, reason: &str, deny_label: &str) -> AuthOutcome {
        let prompt = self.hub.prompt_lock(&self.key);
        let _prompt = prompt.lock().await;
        let msg = wire::request(
            0,
            "authenticate",
            &[("reason", json!(reason)), ("cancel", json!(deny_label))],
        );
        match self.hub.request(&self.key, msg, REQUEST_TIMEOUT).await {
            Ok((reply, None)) => match reply.get("outcome").and_then(Value::as_str) {
                Some("approved") => AuthOutcome::Approved,
                Some("unsupported") => AuthOutcome::Unsupported,
                Some("denied") => AuthOutcome::Denied,
                _ => AuthOutcome::Error("malformed agent reply".to_string()),
            },
            Ok((_, Some(_))) => AuthOutcome::Error("unexpected agent reply payload".to_string()),
            Err(e) => AuthOutcome::Error(e),
        }
    }
}

#[derive(Clone)]
pub struct AgentConfirmer {
    pub hub: Arc<AgentHub>,
    pub key: AgentKey,
}

impl Confirmer for AgentConfirmer {
    async fn confirm(&self, message: &str, ok_label: &str) -> bool {
        let prompt = self.hub.prompt_lock(&self.key);
        let _prompt = prompt.lock().await;
        let msg = wire::request(
            0,
            "confirm",
            &[("message", json!(message)), ("ok_label", json!(ok_label))],
        );
        match self.hub.request(&self.key, msg, REQUEST_TIMEOUT).await {
            Ok((reply, None)) => reply.get("confirmed").and_then(Value::as_bool) == Some(true),
            _ => false,
        }
    }
}

/// Synchronous `MasterKeyProvider` over the async agent channel. Called from inside the
/// multi-threaded runtime (via `Vault::init_with_provider` in dispatch), so `block_in_place`
/// is the supported bridge here.
pub struct AgentMasterKeyProvider {
    pub hub: Arc<AgentHub>,
    pub key: AgentKey,
}

impl AgentMasterKeyProvider {
    fn run(
        &self,
        operation: &str,
        metadata: Option<&EnclaveMetadata>,
        reason: &str,
    ) -> Result<EnclaveKey> {
        let hub = self.hub.clone();
        #[allow(clippy::clone_on_copy)] // AgentKey is String on Windows, u32 elsewhere
        let key = self.key.clone();
        let msg = wire::request(
            0,
            "enclave",
            &[
                ("operation", json!(operation)),
                ("reason", json!(reason)),
                ("cancel", json!(kv_i18n::t("取消", "Cancel"))),
                (
                    "metadata",
                    metadata
                        .map(serde_json::to_value)
                        .transpose()?
                        .unwrap_or(Value::Null),
                ),
            ],
        );
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async move {
                // The agent serves prompts serially; take the daemon's per-user prompt lock too,
                // so a derive doesn't silently queue behind another prompt on the 130 s clock.
                let prompt = hub.prompt_lock(&key);
                let _prompt = prompt.lock().await;
                let (header, payload) = hub
                    .request(&key, msg, REQUEST_TIMEOUT)
                    .await
                    .map_err(VaultError)?;
                let (buf, len) = payload.ok_or_else(|| {
                    VaultError(
                        header
                            .get("error")
                            .and_then(Value::as_str)
                            .unwrap_or("enclave reply carried no payload")
                            .to_string(),
                    )
                })?;
                decode_enclave_output(&buf[..len], metadata)
            })
        })
    }
}

impl MasterKeyProvider for AgentMasterKeyProvider {
    fn create(&self, reason: &str) -> Result<EnclaveKey> {
        self.run("create", None, reason)
    }
    fn unlock(&self, metadata: &EnclaveMetadata, reason: &str) -> Result<MasterKey> {
        metadata.decode()?;
        Ok(self.run("derive", Some(metadata), reason)?.key)
    }
}

/// Verifies one agent connection on macOS: peer uid, code signature against `AGENT_REQUIREMENT`,
/// then the shared hello negotiation (`negotiate`).
#[cfg(unix)]
pub async fn accept_agent(
    stream: UnixStream,
    uid: u32,
    mut audit: impl FnMut(&str),
) -> Option<UnixStream> {
    use std::os::unix::io::AsRawFd;
    let reason = match crate::peer::peer_uid(stream.as_raw_fd()) {
        Ok(u) if u == uid => match crate::peer::peer_audit_token(stream.as_raw_fd()) {
            Ok(token) => {
                crate::peer::verify_peer_code(&token, crate::paths::AGENT_REQUIREMENT, TOUCHID_BIN)
                    .err()
                    .map(|e| format!("untrusted-agent:{e}"))
            }
            Err(e) => Some(format!("peer-token-failed:{e}")),
        },
        Ok(_) => Some("not-allowed-user".to_string()),
        Err(e) => Some(format!("peer-uid-failed:{e}")),
    };
    if let Some(reason) = reason {
        audit(&reason);
        let (reader, mut writer) = tokio::io::split(stream);
        let _ = reader;
        let line = wire::encode_line(&wire::hello_reply(false, Some(&reason)));
        let _ = writer.write_all(&line).await;
        let _ = writer.shutdown().await;
        return None;
    }
    negotiate(stream, audit).await
}

/// Shared hello handshake after the peer has been verified by the OS-specific checks: a valid
/// hello must arrive within 5 s, `{"ok":false,"reason":...}` answers and closes on any failure,
/// `{"ok":true}` and the live stream on success (`audit` gets the reason for the daemon's
/// `agent-rejected` log entry).
pub async fn negotiate<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    mut audit: impl FnMut(&str),
) -> Option<S> {
    let mut stream = stream;
    let valid = read_hello(&mut stream)
        .await
        .map(|v| wire::is_valid_hello(&v))
        .unwrap_or(false);
    if !valid {
        audit("bad-hello");
        let line = wire::encode_line(&wire::hello_reply(false, Some("bad-hello")));
        let _ = stream.write_all(&line).await;
        let _ = stream.shutdown().await;
        return None;
    }
    let line = wire::encode_line(&wire::hello_reply(true, None));
    if stream.write_all(&line).await.is_err() {
        return None;
    }
    Some(stream)
}

/// Read without prefetching the next frame, with both a size and time bound.
pub async fn read_hello<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Value> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut bytes = Vec::new();
        loop {
            let byte = stream.read_u8().await?;
            if byte == b'\n' {
                break;
            }
            if bytes.len() >= wire::MAX_LINE_BYTES {
                return Err(std::io::Error::other("agent hello too large"));
            }
            bytes.push(byte);
        }
        serde_json::from_slice(&bytes).map_err(std::io::Error::from)
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "agent hello timed out"))?
}

/// Parses the framed enclave/agent reply payload into an `EnclaveKey` (shared with
/// `enclave::EnclaveMasterKeyProvider`'s decoder -- duplicated here deliberately so the agent
/// broker does not depend on the macOS-only enclave module).
pub(crate) fn decode_enclave_output(
    output: &[u8],
    metadata: Option<&EnclaveMetadata>,
) -> Result<EnclaveKey> {
    if output.len() <= 32 || output.len() > 8192 {
        return Err(VaultError::new(
            "硬件密钥响应长度不对",
            "Invalid hardware key response length",
        ));
    }
    let restored: EnclaveMetadata = serde_json::from_slice(&output[32..])?;
    restored.decode()?;
    if metadata.is_some_and(|expected| expected != &restored) {
        return Err(VaultError::new(
            "硬件密钥响应不匹配",
            "Hardware key response does not match",
        ));
    }
    let mut key: MasterKey = Default::default();
    key.copy_from_slice(&output[..32]);
    Ok(EnclaveKey {
        key,
        metadata: restored,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use kv_vault::HelloMetadata;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[tokio::test]
    async fn blocked_agent_writes_time_out_and_close_partial_frames() {
        let (server, mut peer) = tokio::io::duplex(1);
        let conn = AgentConn::start(server);
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            conn.request(json!({"op":"authenticate"}), Duration::from_millis(20)),
        )
        .await
        .unwrap();
        assert!(result.unwrap_err().contains("timed out"));
        assert!(conn.dead.load(Ordering::SeqCst));
        assert!(conn.pending.lock().unwrap().is_empty());
        let mut partial = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut partial))
            .await
            .unwrap()
            .unwrap();
        assert!(!partial.contains(&b'\n'));
    }

    #[tokio::test]
    async fn agent_revocation_interrupts_a_blocked_writer() {
        let (server, mut peer) = tokio::io::duplex(1);
        let conn = AgentConn::start(server);
        let caller = conn.clone();
        let request = tokio::spawn(async move {
            caller
                .request(json!({"op":"authenticate"}), Duration::from_secs(60))
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), peer.read_exact(&mut [0u8; 1]))
            .await
            .unwrap()
            .unwrap();
        conn.fail_all("test revocation");
        assert!(tokio::time::timeout(Duration::from_secs(1), request)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        assert!(conn.pending.lock().unwrap().is_empty());
        assert!(conn.writer.lock().await.is_none());
    }

    /// Drives `AgentConn`'s read loop: one request in flight, and the client writes the reply.
    async fn conn_with_reply(writes: Vec<Vec<u8>>, pause_between: bool) -> PendingReply {
        let (server, mut client) = tokio::io::duplex(wire::MAX_LINE_BYTES);
        let conn = AgentConn::start(server);
        let c = conn.clone();
        let task = tokio::spawn(async move { c.request(json!({}), Duration::from_secs(5)).await });
        // Sync point: the request line must arrive before the client writes (current-thread
        // runtimes only poll spawned tasks while awaiting).
        let mut request_line = String::new();
        BufReader::new(&mut client)
            .read_line(&mut request_line)
            .await
            .unwrap();
        assert!(request_line.contains("\"id\":1"), "{request_line}");
        for part in writes {
            client.write_all(&part).await.unwrap();
            if pause_between {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        drop(client);
        task.await.unwrap()
    }

    fn enclave_reply(id: u64, payload: &[u8]) -> Vec<u8> {
        let mut bytes = wire::encode_line(&json!({"id": id, "ok": true, "len": payload.len()}));
        bytes.extend_from_slice(payload);
        bytes
    }

    #[tokio::test]
    async fn a_payload_is_delivered_whole_or_split_across_writes() {
        let key = [42u8; 40]; // 32-byte key + 8 bytes of metadata
        for split in [false, true] {
            let writes = if split {
                let frame = enclave_reply(1, &key);
                let cut = frame.len() - key.len() + 5; // header + first 5 payload bytes
                vec![frame[..cut].to_vec(), frame[cut..].to_vec()]
            } else {
                vec![enclave_reply(1, &key)]
            };
            let reply = conn_with_reply(writes, split).await.unwrap();
            let (header, payload) = reply;
            assert_eq!(header["id"], json!(1));
            let (buf, len) = payload.expect("payload frame expected");
            assert_eq!(&buf[..len], &key[..]);
        }
    }

    #[tokio::test]
    async fn a_truncated_payload_fails_the_request() {
        // Header promises 64 bytes, the connection closes after 10.
        let mut frame = wire::encode_line(&json!({"id": 1, "ok": true, "len": 64}));
        frame.extend_from_slice(&[1u8; 10]);
        let reply = conn_with_reply(vec![frame], false).await;
        assert!(reply.is_err());
    }

    #[tokio::test]
    async fn invalid_frames_close_the_channel_without_accepting_following_replies() {
        let mut invalid = vec![b"{broken JSON\n".to_vec(), b"\"\xff\"\n".to_vec()];
        for len in [json!(0), json!(8193), json!(-1), json!("64"), Value::Null] {
            invalid.push(wire::encode_line(&json!({"id":1,"ok":true,"len":len})));
        }
        for mut frame in invalid {
            let (server, client) = tokio::io::duplex(4096);
            let conn = AgentConn::start(server);
            let mut requests = Vec::new();
            for _ in 0..2 {
                let conn = conn.clone();
                requests.push(tokio::spawn(async move {
                    conn.request(json!({"op":"confirm"}), Duration::from_secs(5))
                        .await
                }));
            }
            let mut client = BufReader::new(client);
            for _ in 0..2 {
                client.read_line(&mut String::new()).await.unwrap();
            }
            // With invalid framing, these bytes could be payload rather than a real approval.
            frame.extend(wire::encode_line(&json!({"id":2,"confirmed":true})));
            client.get_mut().write_all(&frame).await.unwrap();
            drop(client);
            for request in requests {
                assert!(tokio::time::timeout(Duration::from_secs(1), request)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err());
            }
            assert!(conn.dead.load(Ordering::SeqCst));
            assert!(conn.pending.lock().unwrap().is_empty());
            assert!(conn
                .request(json!({}), Duration::from_secs(1))
                .await
                .is_err());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_unsigned_peer_is_rejected_before_the_hello() {
        let (stream, mut client) = UnixStream::pair().unwrap();
        let uid = unsafe { libc::getuid() };
        let mut reasons = Vec::new();
        let accepted = accept_agent(stream, uid, |r| reasons.push(r.to_string())).await;
        assert!(accepted.is_none());
        // The reply tells the connector exactly why (and the test binary, being
        // linker-signed, cannot satisfy the Apple-anchored requirement).
        let mut line = String::new();
        BufReader::new(&mut client)
            .read_line(&mut line)
            .await
            .unwrap();
        let reply: Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(reply["ok"], json!(false));
        assert!(reply["reason"]
            .as_str()
            .unwrap()
            .starts_with("untrusted-agent"));
        assert_eq!(reasons.len(), 1);
        let _ = client.write_all(b"x").await;
    }

    #[tokio::test]
    async fn hello_is_bounded_and_leaves_the_next_frame_unread() {
        let mut bytes = wire::encode_line(&wire::hello());
        bytes.extend_from_slice(b"next-frame");
        let mut input = bytes.as_slice();
        assert!(wire::is_valid_hello(&read_hello(&mut input).await.unwrap()));
        assert_eq!(input, b"next-frame");
        let oversized = vec![b'x'; wire::MAX_LINE_BYTES + 1];
        assert!(read_hello(&mut oversized.as_slice()).await.is_err());
        assert!(read_hello(&mut b"".as_slice()).await.is_err());
    }

    async fn read_request(peer: &mut BufReader<tokio::io::DuplexStream>) -> Value {
        let mut line = String::new();
        peer.read_line(&mut line).await.unwrap();
        serde_json::from_str(&line).unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn completed_requests_discard_late_approvals_after_timeout_or_cancellation() {
        for cancelled in [false, true] {
            let (server, peer) = tokio::io::duplex(4096);
            let conn = AgentConn::start(server);
            let mut peer = BufReader::new(peer);
            let caller = conn.clone();
            let old = tokio::spawn(async move {
                caller
                    .request(json!({"op":"authenticate"}), Duration::from_secs(5))
                    .await
            });
            let old_id = read_request(&mut peer).await["id"].as_u64().unwrap();
            if cancelled {
                old.abort();
                assert!(old.await.unwrap_err().is_cancelled());
            } else {
                assert!(old.await.unwrap().is_err());
            }
            assert!(conn.pending.lock().unwrap().is_empty());
            assert!(!conn.dead.load(Ordering::SeqCst));

            let caller = conn.clone();
            let current = tokio::spawn(async move {
                caller
                    .request(json!({"op":"authenticate"}), Duration::from_secs(5))
                    .await
            });
            let current_id = read_request(&mut peer).await["id"].as_u64().unwrap();
            assert_ne!(old_id, current_id);
            let mut replies = wire::encode_line(&json!({"id":old_id,"outcome":"approved"}));
            replies.extend(wire::encode_line(
                &json!({"id":current_id,"outcome":"denied"}),
            ));
            peer.get_mut().write_all(&replies).await.unwrap();
            let (reply, payload) = current.await.unwrap().unwrap();
            assert_eq!(reply, json!({"id":current_id,"outcome":"denied"}));
            assert!(payload.is_none());
            assert!(conn.pending.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn concurrent_requests_receive_their_own_replies_even_in_reverse_order() {
        let (server, peer) = tokio::io::duplex(4096);
        let conn = AgentConn::start(server);
        let mut peer = BufReader::new(peer);
        let mut requests = Vec::new();
        for marker in ["first", "second"] {
            let caller = conn.clone();
            requests.push(tokio::spawn(async move {
                caller
                    .request(
                        json!({"op":"confirm","marker":marker,"id":u64::MAX}),
                        Duration::from_secs(5),
                    )
                    .await
            }));
        }
        let received = [read_request(&mut peer).await, read_request(&mut peer).await];
        let first_id = received[0]["id"].as_u64().unwrap();
        let second_id = received[1]["id"].as_u64().unwrap();
        assert_ne!(first_id, second_id);
        assert_ne!(first_id, u64::MAX);
        assert_ne!(second_id, u64::MAX);
        for request in received.iter().rev() {
            peer.get_mut()
                .write_all(&wire::encode_line(
                    &json!({"id":request["id"],"marker":request["marker"],"confirmed":true}),
                ))
                .await
                .unwrap();
        }
        for (task, marker) in requests.into_iter().zip(["first", "second"]) {
            let (reply, payload) = tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(reply["marker"], marker);
            assert_eq!(reply["confirmed"], true);
            assert!(payload.is_none());
        }
        assert!(conn.pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unknown_request_payload_is_consumed_without_parsing_embedded_approval_json() {
        let (server, peer) = tokio::io::duplex(4096);
        let conn = AgentConn::start(server);
        let mut peer = BufReader::new(peer);
        let caller = conn.clone();
        let request = tokio::spawn(async move {
            caller
                .request(json!({"op":"confirm"}), Duration::from_secs(5))
                .await
        });
        let id = read_request(&mut peer).await["id"].as_u64().unwrap();
        let fake_approval = wire::encode_line(&json!({"id":id,"confirmed":true}));
        let mut frame = enclave_reply(u64::MAX, &fake_approval);
        frame.extend(wire::encode_line(&json!({"id":id,"confirmed":false})));
        peer.get_mut().write_all(&frame).await.unwrap();
        let (reply, payload) = tokio::time::timeout(Duration::from_secs(1), request)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(reply, json!({"id":id,"confirmed":false}));
        assert!(payload.is_none());
        assert!(!conn.dead.load(Ordering::SeqCst));
        assert!(conn.pending.lock().unwrap().is_empty());
    }

    #[tokio::test]
    #[allow(clippy::clone_on_copy)] // AgentKey is String on Windows, u32 on macOS.
    async fn replacing_an_agent_revokes_pending_requests_and_preserves_the_new_connection() {
        let key = AgentKey::default();
        let hub = AgentHub::new();
        let (server, peer) = tokio::io::duplex(4096);
        hub.register(key.clone(), server, "unsigned");
        let old_conn = hub.conn(&key).unwrap();
        let mut peer = BufReader::new(peer);
        let caller = old_conn.clone();
        let pending = tokio::spawn(async move {
            caller
                .request(json!({"op":"confirm"}), Duration::from_secs(60))
                .await
        });
        read_request(&mut peer).await;
        let (new_server, new_peer) = tokio::io::duplex(4096);
        hub.register(key.clone(), new_server, "signed");
        assert!(tokio::time::timeout(Duration::from_secs(1), pending)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        assert!(old_conn.dead.load(Ordering::SeqCst));
        assert!(old_conn.pending.lock().unwrap().is_empty());
        assert_eq!(hub.agent_trust(), "signed");
        let mut new_peer = BufReader::new(new_peer);
        let caller = hub.conn(&key).unwrap();
        let current = tokio::spawn(async move {
            caller
                .request(json!({"op":"confirm"}), Duration::from_secs(5))
                .await
        });
        let id = read_request(&mut new_peer).await["id"].as_u64().unwrap();
        new_peer
            .get_mut()
            .write_all(&wire::encode_line(&json!({"id":id,"confirmed":true})))
            .await
            .unwrap();
        let (reply, payload) = tokio::time::timeout(Duration::from_secs(1), current)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(reply["confirmed"], true);
        assert!(payload.is_none());
    }

    fn hello_metadata() -> EnclaveMetadata {
        EnclaveMetadata::windows_hello(
            &HelloMetadata {
                key_name: "keyvalet.vault.0123456789abcdef0123456789abcdef".into(),
                public_key: STANDARD.encode([42; 294]),
                tpm_backed: Some(true),
            },
            &[7; 32],
        )
        .unwrap()
    }

    fn key_response(metadata: &EnclaveMetadata) -> zeroize::Zeroizing<Vec<u8>> {
        let mut output = zeroize::Zeroizing::new((0u8..32).collect::<Vec<_>>());
        output.extend(serde_json::to_vec(metadata).unwrap());
        output
    }

    #[test]
    fn hardware_reply_decoding_preserves_binary_key_and_pins_hello_metadata() {
        let metadata = hello_metadata();
        let output = key_response(&metadata);
        for expected in [None, Some(&metadata)] {
            let decoded = decode_enclave_output(&output, expected).unwrap();
            assert_eq!(&decoded.key[..], &output[..32]);
            assert_eq!(decoded.metadata, metadata);
        }
    }

    #[test]
    fn hardware_reply_length_bound_includes_metadata_and_all_trailing_bytes() {
        for len in [0, 1, 31, 32, wire::MAX_ENCLAVE_PAYLOAD + 1] {
            assert!(decode_enclave_output(&zeroize::Zeroizing::new(vec![0; len]), None).is_err());
        }
        let metadata = hello_metadata();
        let mut output = key_response(&metadata);
        output.resize(wire::MAX_ENCLAVE_PAYLOAD, b' ');
        assert_eq!(
            decode_enclave_output(&output, Some(&metadata))
                .unwrap()
                .metadata,
            metadata
        );
        output.push(b' ');
        assert!(decode_enclave_output(&output, Some(&metadata)).is_err());
    }

    #[test]
    fn hardware_reply_metadata_rejects_duplicate_fields_unknown_fields_and_trailing_data() {
        let metadata = hello_metadata();
        let json = serde_json::to_string(&metadata).unwrap();
        let duplicate = json.replacen("{", "{\"version\":1,", 1);
        let unknown = json.replacen("{", "{\"unexpected\":true,", 1);
        for invalid in [
            duplicate.into_bytes(),
            unknown.into_bytes(),
            format!("{json}{{}}").into_bytes(),
            format!("{json}\0").into_bytes(),
            b"null".to_vec(),
            b"{}".to_vec(),
            vec![0xff],
        ] {
            let mut output = zeroize::Zeroizing::new(vec![42; 32]);
            output.extend(invalid);
            assert!(decode_enclave_output(&output, None).is_err());
        }
    }

    #[test]
    fn hardware_reply_rejects_valid_but_substituted_key_challenge_attestation_and_provider() {
        let expected = hello_metadata();
        let (info, challenge) = expected.hello().unwrap();
        let mut changed_name = info.clone();
        changed_name.key_name = "keyvalet.vault.ffffffffffffffffffffffffffffffff".into();
        let mut changed_public = info.clone();
        changed_public.public_key = STANDARD.encode([43; 294]);
        let mut changed_attestation = info.clone();
        changed_attestation.tpm_backed = Some(false);
        for substituted in [
            EnclaveMetadata::windows_hello(&changed_name, &challenge).unwrap(),
            EnclaveMetadata::windows_hello(&changed_public, &challenge).unwrap(),
            EnclaveMetadata::windows_hello(&changed_attestation, &challenge).unwrap(),
            EnclaveMetadata::windows_hello(&info, &[8; 32]).unwrap(),
            EnclaveMetadata::software(&[0; 32]),
        ] {
            substituted.decode().unwrap();
            assert!(decode_enclave_output(&key_response(&substituted), Some(&expected)).is_err());
        }
    }

    #[test]
    fn hardware_reply_rejects_corrupt_metadata_before_exposing_a_key() {
        let valid = hello_metadata();
        let mut invalid = Vec::new();
        for version in [0, 5, u32::MAX] {
            invalid.push(EnclaveMetadata {
                version,
                ..valid.clone()
            });
        }
        for blob in ["", "not base64!"] {
            invalid.push(EnclaveMetadata {
                key_blob: blob.into(),
                ..valid.clone()
            });
        }
        for len in [0, 31, 33] {
            invalid.push(EnclaveMetadata {
                peer_public_key: STANDARD.encode(vec![0; len]),
                ..valid.clone()
            });
        }
        for metadata in invalid {
            assert!(decode_enclave_output(&key_response(&metadata), None).is_err());
        }
    }

    #[tokio::test]
    async fn hello_exact_size_limit_is_accepted_without_reading_a_following_frame() {
        let mut frame = serde_json::to_vec(&wire::hello()).unwrap();
        frame.resize(wire::MAX_LINE_BYTES, b' ');
        frame.extend_from_slice(b"\nnext-frame\n");
        let mut input = frame.as_slice();
        assert!(wire::is_valid_hello(&read_hello(&mut input).await.unwrap()));
        assert_eq!(input, b"next-frame\n");
    }

    #[tokio::test(start_paused = true)]
    async fn a_partial_hello_still_uses_the_absolute_five_second_deadline() {
        let (mut server, mut peer) = tokio::io::duplex(4096);
        peer.write_all(b"{\"op\":\"agent-hello\"").await.unwrap();
        let start = tokio::time::Instant::now();
        let error = read_hello(&mut server).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(tokio::time::Instant::now() - start, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn bad_hello_is_audited_rejected_and_closed_before_registration() {
        for frame in [
            b"{\"op\":\"agent-hello\",\"protocol\":2}\n".as_slice(),
            b"{\"op\":\"agent-hello\",\"protocol\":\"1\"}\n",
            b"{broken\n",
            b"null\n",
        ] {
            let (server, mut peer) = tokio::io::duplex(4096);
            peer.write_all(frame).await.unwrap();
            let mut audit = Vec::new();
            assert!(negotiate(server, |reason| audit.push(reason.to_owned()))
                .await
                .is_none());
            assert_eq!(audit, ["bad-hello"]);
            let mut response = Vec::new();
            peer.read_to_end(&mut response).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&response).unwrap(),
                json!({"ok":false,"reason":"bad-hello"})
            );
        }
    }

    fn registered_hub() -> (Arc<AgentHub>, AgentKey, BufReader<tokio::io::DuplexStream>) {
        let hub = AgentHub::new();
        let key = AgentKey::default();
        let (server, peer) = tokio::io::duplex(4096);
        #[allow(clippy::clone_on_copy)] // AgentKey is String on Windows, u32 on macOS.
        hub.register(key.clone(), server, "signed");
        (hub, key, BufReader::new(peer))
    }

    #[tokio::test]
    async fn disconnect_revokes_every_waiting_request_and_reports_no_live_agent() {
        let (hub, key, mut peer) = registered_hub();
        let conn = hub.conn(&key).unwrap();
        let mut waiting = Vec::new();
        for _ in 0..3 {
            let caller = conn.clone();
            waiting.push(tokio::spawn(async move {
                caller
                    .request(json!({"op":"confirm"}), Duration::from_secs(60))
                    .await
            }));
        }
        for _ in 0..waiting.len() {
            read_request(&mut peer).await;
        }
        drop(peer);
        for request in waiting {
            assert!(tokio::time::timeout(Duration::from_secs(1), request)
                .await
                .unwrap()
                .unwrap()
                .is_err());
        }
        assert!(conn.dead.load(Ordering::SeqCst));
        assert!(conn.pending.lock().unwrap().is_empty());
        assert!(conn.writer.lock().await.is_none());
        assert!(!hub.has_live_agent(&key));
        assert_eq!(hub.agent_trust(), "none");
        assert!(conn
            .request(json!({}), Duration::from_secs(1))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn cancelling_a_partial_request_closes_the_channel_and_clears_pending_state() {
        let (server, mut peer) = tokio::io::duplex(1);
        let conn = AgentConn::start(server);
        let caller = conn.clone();
        let task = tokio::spawn(async move {
            caller
                .request(json!({"op":"confirm"}), Duration::from_secs(60))
                .await
        });
        peer.read_exact(&mut [0u8; 1]).await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let mut partial = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), peer.read_to_end(&mut partial))
            .await
            .unwrap()
            .unwrap();
        assert!(!partial.contains(&b'\n'));
        assert!(conn.dead.load(Ordering::SeqCst));
        assert!(conn.pending.lock().unwrap().is_empty());
        assert!(conn.writer.lock().await.is_none());
    }

    #[tokio::test]
    async fn authentication_only_accepts_exact_outcomes_from_json_replies() {
        for (value, expected) in [
            (json!("approved"), Some(AuthOutcome::Approved)),
            (json!("denied"), Some(AuthOutcome::Denied)),
            (json!("unsupported"), Some(AuthOutcome::Unsupported)),
            (json!("Approved"), None),
            (json!(true), None),
            (Value::Null, None),
        ] {
            let (hub, key, mut peer) = registered_hub();
            let authenticator = AgentAuthenticator { hub, key };
            let call =
                tokio::spawn(async move { authenticator.authenticate("test", "cancel").await });
            let request = read_request(&mut peer).await;
            assert_eq!(request["op"], "authenticate");
            peer.get_mut()
                .write_all(&wire::encode_line(
                    &json!({"id":request["id"],"outcome":value}),
                ))
                .await
                .unwrap();
            let actual = call.await.unwrap();
            if let Some(expected) = expected {
                assert_eq!(actual, expected);
            } else {
                assert!(matches!(actual, AuthOutcome::Error(_)));
            }
        }
    }

    #[tokio::test]
    async fn confirmation_requires_an_explicit_boolean_true() {
        for value in [
            json!(true),
            json!(false),
            json!("true"),
            json!(1),
            Value::Null,
        ] {
            let (hub, key, mut peer) = registered_hub();
            let confirmer = AgentConfirmer { hub, key };
            let call = tokio::spawn(async move { confirmer.confirm("test", "OK").await });
            let request = read_request(&mut peer).await;
            assert_eq!(request["op"], "confirm");
            peer.get_mut()
                .write_all(&wire::encode_line(
                    &json!({"id":request["id"],"confirmed":value}),
                ))
                .await
                .unwrap();
            assert_eq!(call.await.unwrap(), value == json!(true));
        }
    }

    #[tokio::test]
    async fn a_binary_key_reply_cannot_be_used_as_authentication_approval() {
        let (hub, key, mut peer) = registered_hub();
        let authenticator = AgentAuthenticator { hub, key };
        let call = tokio::spawn(async move { authenticator.authenticate("test", "cancel").await });
        let request = read_request(&mut peer).await;
        let mut frame =
            wire::encode_line(&json!({"id":request["id"],"ok":true,"len":32,"outcome":"approved"}));
        frame.extend_from_slice(&[42; 32]);
        peer.get_mut().write_all(&frame).await.unwrap();
        assert!(matches!(call.await.unwrap(), AuthOutcome::Error(_)));
    }

    #[tokio::test]
    async fn a_binary_key_reply_cannot_be_used_as_confirmation_approval() {
        let (hub, key, mut peer) = registered_hub();
        let confirmer = AgentConfirmer { hub, key };
        let call = tokio::spawn(async move { confirmer.confirm("test", "OK").await });
        let request = read_request(&mut peer).await;
        let mut frame =
            wire::encode_line(&json!({"id":request["id"],"ok":true,"len":32,"confirmed":true}));
        frame.extend_from_slice(&[42; 32]);
        peer.get_mut().write_all(&frame).await.unwrap();
        assert!(!call.await.unwrap());
    }
}
