//! The daemon-side registry of per-user agents (`kv-touchid --agent` connected to AGENT_SOCKET)
//! and the `Authenticator` / `Confirmer` / `MasterKeyProvider` implementations that route every
//! UI and Secure Enclave operation through them. The LaunchAgent runs in the user's Aqua session;
//! Apple does not support these operations inside a launchd daemon. Before registering, a
//! connection is checked by peer uid and code signature (`peer::verify_peer_code`), so a same-user
//! process cannot impersonate the agent and approve prompts on the user's behalf.

use crate::paths::{AGENT_LABEL, TOUCHID_BIN};
use crate::{AuthOutcome, Authenticator, Confirmer};
use kv_ipc::agent as wire;
use kv_vault::{EnclaveKey, EnclaveMetadata, MasterKey, MasterKeyProvider, Result, VaultError};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{oneshot, Mutex as AsyncMutex};

pub const REQUEST_TIMEOUT: Duration = Duration::from_millis(130_000);
const KICKSTART_WAIT: Duration = Duration::from_secs(5);

type Payload = (wire::EnclavePayload, usize);
type PendingReply = std::result::Result<(Value, Option<Payload>), String>;

/// One verified agent connection: serialized outgoing requests, a reader pump that pairs
/// replies (and enclave payload frames) with pending oneshots.
struct AgentConn {
    writer: AsyncMutex<tokio::io::WriteHalf<UnixStream>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<PendingReply>>>,
    next_id: AtomicU64,
    dead: AtomicBool,
}

impl AgentConn {
    fn start(stream: UnixStream) -> Arc<Self> {
        let (reader, writer) = tokio::io::split(stream);
        let conn = Arc::new(Self {
            writer: AsyncMutex::new(writer),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            dead: AtomicBool::new(false),
        });
        let pump = conn.clone();
        tokio::spawn(async move { pump.read_loop(reader).await });
        conn
    }

    fn fail_all(&self, reason: &str) {
        self.dead.store(true, Ordering::SeqCst);
        for (_, tx) in self.pending.lock().unwrap().drain() {
            let _ = tx.send(Err(reason.to_string()));
        }
    }

    /// Header lines are read byte-by-byte (they are tiny; a few messages per session) so no
    /// read ever pulls enclave payload bytes into a growable/non-zeroizing buffer -- the key
    /// material goes straight into a fixed `Zeroizing` buffer and nowhere else.
    async fn read_loop(&self, mut reader: tokio::io::ReadHalf<UnixStream>) {
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
            let line_text = String::from_utf8_lossy(&line);
            let line_text = line_text.trim();
            if line_text.is_empty() {
                continue;
            }
            let Ok(header) = serde_json::from_str::<Value>(line_text) else {
                continue;
            };
            // The binary frame of an enclave reply follows its header immediately.
            if header.get("ok").and_then(Value::as_bool) == Some(true)
                && header.get("len").and_then(Value::as_u64).is_some()
            {
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
                        self.deliver(
                            &header,
                            if ok {
                                Ok((header.clone(), Some((payload, len))))
                            } else {
                                Err("truncated enclave payload".to_string())
                            },
                        );
                    }
                    Err(e) => self.deliver(&header, Err(e)),
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
        let mut line = wire::encode_line(&msg);
        let send = self.writer.lock().await.write_all(&line).await;
        line.clear();
        if let Err(e) = send {
            self.pending.lock().unwrap().remove(&id);
            self.dead.store(true, Ordering::SeqCst);
            return Err(format!("cannot write to the agent: {e}"));
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(_)) => Err("agent disconnected".to_string()),
            Err(_) => {
                self.pending.lock().unwrap().remove(&id);
                Err("agent request timed out".to_string())
            }
        }
    }
}

/// uid -> verified agent connection, shared daemon-wide.
#[derive(Default)]
pub struct AgentHub {
    conns: Mutex<HashMap<u32, Arc<AgentConn>>>,
    prompt_locks: Mutex<HashMap<u32, Arc<AsyncMutex<()>>>>,
}

impl AgentHub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Registers a freshly verified agent stream for `uid`, replacing any older connection.
    pub fn register(&self, uid: u32, stream: UnixStream) {
        let conn = AgentConn::start(stream);
        if let Some(old) = self.conns.lock().unwrap().insert(uid, conn) {
            old.fail_all("replaced by a new agent connection");
        }
    }

    /// One prompt at a time per user: dialogs/flows queue rather than stacking.
    fn prompt_lock(&self, uid: u32) -> Arc<AsyncMutex<()>> {
        self.prompt_locks
            .lock()
            .unwrap()
            .entry(uid)
            .or_default()
            .clone()
    }

    fn conn(&self, uid: u32) -> Option<Arc<AgentConn>> {
        let conn = self.conns.lock().unwrap().get(&uid).cloned();
        conn.filter(|c| !c.dead.load(Ordering::SeqCst))
    }

    /// Returns the agent connection, kickstarting the LaunchAgent once if it isn't up yet
    /// (launchctl runs it lazily; KeepAlive should already have started it at login).
    async fn ensure(&self, uid: u32) -> std::result::Result<Arc<AgentConn>, String> {
        if let Some(conn) = self.conn(uid) {
            return Ok(conn);
        }
        let _ = tokio::process::Command::new("/bin/launchctl")
            .arg("kickstart")
            .arg(format!("gui/{uid}/{AGENT_LABEL}"))
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;
        let deadline = std::time::Instant::now() + KICKSTART_WAIT;
        loop {
            if let Some(conn) = self.conn(uid) {
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

    async fn request(&self, uid: u32, msg: Value, timeout: Duration) -> PendingReply {
        let conn = self.ensure(uid).await?;
        conn.request(msg, timeout).await
    }
}

#[derive(Clone)]
pub struct AgentAuthenticator {
    pub hub: Arc<AgentHub>,
    pub uid: u32,
}

impl Authenticator for AgentAuthenticator {
    async fn authenticate(&self, reason: &str, deny_label: &str) -> AuthOutcome {
        let prompt = self.hub.prompt_lock(self.uid);
        let _prompt = prompt.lock().await;
        let msg = wire::request(
            0,
            "authenticate",
            &[("reason", json!(reason)), ("cancel", json!(deny_label))],
        );
        match self.hub.request(self.uid, msg, REQUEST_TIMEOUT).await {
            Ok((reply, _)) => match reply.get("outcome").and_then(Value::as_str) {
                Some("approved") => AuthOutcome::Approved,
                Some("unsupported") => AuthOutcome::Unsupported,
                Some("denied") => AuthOutcome::Denied,
                _ => AuthOutcome::Error("malformed agent reply".to_string()),
            },
            Err(e) => AuthOutcome::Error(e),
        }
    }
}

#[derive(Clone)]
pub struct AgentConfirmer {
    pub hub: Arc<AgentHub>,
    pub uid: u32,
}

impl Confirmer for AgentConfirmer {
    async fn confirm(&self, message: &str, ok_label: &str) -> bool {
        let prompt = self.hub.prompt_lock(self.uid);
        let _prompt = prompt.lock().await;
        let msg = wire::request(
            0,
            "confirm",
            &[("message", json!(message)), ("ok_label", json!(ok_label))],
        );
        match self.hub.request(self.uid, msg, REQUEST_TIMEOUT).await {
            Ok((reply, _)) => reply.get("confirmed").and_then(Value::as_bool) == Some(true),
            Err(_) => false,
        }
    }
}

/// Synchronous `MasterKeyProvider` over the async agent channel. Called from inside the
/// multi-threaded runtime (via `Vault::init_with_provider` in dispatch), so `block_in_place`
/// is the supported bridge here.
pub struct AgentMasterKeyProvider {
    pub hub: Arc<AgentHub>,
    pub uid: u32,
}

impl AgentMasterKeyProvider {
    fn run(
        &self,
        operation: &str,
        metadata: Option<&EnclaveMetadata>,
        reason: &str,
    ) -> Result<EnclaveKey> {
        let hub = self.hub.clone();
        let uid = self.uid;
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
                let (header, payload) = hub
                    .request(uid, msg, REQUEST_TIMEOUT)
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
                crate::enclave::EnclaveMasterKeyProvider::decode_output(&buf[..len], metadata)
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

/// Verifies one agent connection: peer uid, code signature against `AGENT_REQUIREMENT`, and a
/// valid hello -- in that order, answering `{"ok":false,"reason":...}` before closing on any
/// failure (`audit` receives the reason for the daemon's `agent-rejected` log entry).
pub async fn accept_agent(
    stream: UnixStream,
    uid: u32,
    mut audit: impl FnMut(&str),
) -> Option<UnixStream> {
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
    let (reader, mut writer) = tokio::io::split(stream);
    if let Some(reason) = reason {
        audit(&reason);
        let line = wire::encode_line(&wire::hello_reply(false, Some(&reason)));
        let _ = writer.write_all(&line).await;
        let _ = writer.shutdown().await;
        return None;
    }
    // Verified peer: a valid hello must arrive within 5 s before registering.
    let mut reader = tokio::io::BufReader::new(reader);
    let mut raw = String::new();
    let hello = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut raw).await
    })
    .await;
    let valid = matches!(hello, Ok(Ok(n)) if n > 0)
        && serde_json::from_str::<Value>(raw.trim())
            .map(|v| wire::is_valid_hello(&v))
            .unwrap_or(false);
    let mut stream = reader.into_inner().unsplit(writer);
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    /// Drives `AgentConn`'s read loop: one request in flight, and the client writes the reply.
    async fn conn_with_reply(writes: Vec<Vec<u8>>, pause_between: bool) -> PendingReply {
        let (server, mut client) = UnixStream::pair().unwrap();
        let conn = AgentConn::start(server);
        let c = conn.clone();
        let task = tokio::spawn(async move { c.request(json!({}), Duration::from_secs(5)).await });
        // Sync point: the request line must arrive before the client writes (current-thread
        // runtimes only poll spawned tasks while awaiting).
        let mut request_line = String::new();
        tokio::io::AsyncBufReadExt::read_line(&mut BufReader::new(&mut client), &mut request_line)
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
}
