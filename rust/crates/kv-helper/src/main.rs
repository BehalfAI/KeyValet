//! Root helper entry point, in two modes:
//! - **stdio mode** (no args): started by the MCP server via `sudo -n`; one session over
//!   stdin/stdout, lifetime tied to the MCP session. Kept as the fallback for one version.
//! - **daemon mode** (`--daemon --uid <uid>`): a launchd daemon in the system domain, serving one
//!   session per client connection on HELPER_SOCKET (peer uid must equal `--uid`; uid 0 gets only
//!   a `control` query), plus AGENT_SOCKET for the per-user LaunchAgent whose code signature is
//!   verified before it may answer prompts. Apple does not support Secure Enclave or
//!   LocalAuthentication inside a launchd daemon, so every UI/hardware operation goes through the
//!   agent (`AgentAuthenticator` / `AgentConfirmer` / `AgentMasterKeyProvider`).
//!
//! Each connection is one session: it unlocks with a fresh Touch ID / Secure Enclave derivation
//! at handshake and drops its vault key when the connection closes; the daemon holds no vault
//! key while idle.
//!
//! Concurrency note: request handling stays serialized behind the session's auth-state lock (see
//! the TS port note); MAX_IN_FLIGHT only bounds read-ahead. `kv_i18n::set_lang` remains
//! process-global in daemon mode -- last handshake wins (known limitation).

use kv_core::dispatch::{ClientContext, SessionAuth, TouchIdSessionGate};
use kv_core::settings::{parse_mode, read_settings, remember_active, remember_until, stricter};
use kv_ipc::{clean_purpose, AuthMessage, ReadyMessage, Request, MAX_LINE_BYTES, PROTOCOL_VERSION};
use kv_platform::macos::{RootUserDialogConfirmer, TouchIdAuthenticator};
use kv_platform::paths::{HELPER_BIN, VAULT_DIR};
use kv_platform::trust::verify_root_environment;
use kv_vault::Vault;
use serde_json::{json, Map, Value};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex as AsyncMutex;

const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const MAX_IN_FLIGHT: usize = 8;
const MAX_CLIENTS: usize = 32;

fn fatal(msg: &str) -> ! {
    eprintln!("keyvalet-helper: {msg}");
    std::process::exit(1);
}

struct HardwareUnlock<'a> {
    vault: &'a Vault,
    provider: &'a (dyn kv_vault::MasterKeyProvider + Send + Sync),
}

impl kv_platform::Authenticator for HardwareUnlock<'_> {
    async fn authenticate(&self, reason: &str, _deny_label: &str) -> kv_platform::AuthOutcome {
        match self.vault.init_with_provider(self.provider, reason) {
            Ok(()) => kv_platform::AuthOutcome::Approved,
            Err(e) => kv_platform::AuthOutcome::Error(e.0),
        }
    }
}

fn clip(s: &str, n: usize) -> String {
    s.chars()
        .filter(|c| !matches!(c, '\u{0000}'..='\u{001f}' | '\u{007f}'))
        .take(n)
        .collect()
}

async fn send<W: AsyncWrite + Unpin>(out: &AsyncMutex<W>, value: &Value) {
    let mut line = serde_json::to_vec(value).unwrap();
    line.push(b'\n');
    let _ = out.lock().await.write_all(&line).await;
}

/// Why a connection ended before it was ready. In stdio mode these map to the legacy exit codes
/// (protocol errors exit 1, a rejected handshake exits 0); in daemon mode every one just closes
/// that connection.
enum Reject {
    ProtocolError(String),
    Refused,
}

async fn reject_with<W: AsyncWrite + Unpin>(
    out: &AsyncMutex<W>,
    vault: &Vault,
    ctx: &ClientContext,
    purpose: Option<&str>,
    error: String,
) -> Reject {
    let mut entry = Map::new();
    entry.insert("op".into(), json!("unlock"));
    entry.insert("ok".into(), json!(false));
    entry.insert("error".into(), json!(error));
    if let Some(p) = purpose {
        entry.insert("purpose".into(), json!(p));
    }
    entry.insert("session".into(), json!(ctx.session));
    entry.insert("client".into(), serde_json::to_value(ctx).unwrap());
    let _ = vault.audit(entry);
    let msg = ReadyMessage::NotReady {
        ready: kv_ipc::False,
        protocol: PROTOCOL_VERSION,
        error: error.clone(),
    };
    send(out, &serde_json::to_value(&msg).unwrap()).await;
    Reject::Refused
}

/// Handles the handshake: every session authenticates the hardware key before reading the vault,
/// then reports readiness. Errors are answered with `NotReady` and end only this connection.
async fn authenticate<G, W>(
    vault: &Vault,
    line: &str,
    ctx: &mut ClientContext,
    auth: &mut SessionAuth<G>,
    out: &AsyncMutex<W>,
    provider: &(dyn kv_vault::MasterKeyProvider + Send + Sync),
) -> Result<(), Reject>
where
    G: kv_core::AuthorizeGate,
    W: AsyncWrite + Unpin,
{
    let msg: AuthMessage = match serde_json::from_str(line) {
        Ok(m) => m,
        Err(_) => {
            return Err(Reject::ProtocolError(kv_i18n::t(
                "协议错误：握手消息不是合法 JSON",
                "Protocol error: handshake message is not valid JSON",
            )))
        }
    };
    kv_i18n::set_lang(msg.lang.as_deref().unwrap_or(""));
    let purpose = clean_purpose(Some(&msg.purpose));

    ctx.session = Some(if msg.session.is_empty() {
        "unknown".to_string()
    } else {
        clip(&msg.session, 64)
    });
    ctx.cwd = Some(clip(&msg.cwd, 500));
    ctx.ppid = Some(msg.ppid);
    ctx.client = Some(clip(&msg.client, 100));

    if msg.op != "auth" {
        return Err(Reject::ProtocolError(kv_i18n::t(
            "协议错误：第一条消息必须是 auth",
            "Protocol error: the first message must be auth",
        )));
    }
    let Some(purpose) = purpose.clone() else {
        return Err(reject_with(
            out,
            vault,
            ctx,
            None,
            kv_i18n::t(
                "必须说明解锁目的（purpose）",
                "A purpose is required to unlock",
            ),
        )
        .await);
    };

    let protection = match vault.protection() {
        Ok(p) => p,
        Err(e) => return Err(reject_with(out, vault, ctx, Some(&purpose), e.0).await),
    };
    if protection.provider != "secure_enclave" {
        return Err(reject_with(out, vault, ctx, Some(&purpose), kv_i18n::t("macOS 已停用文件密钥模式；请运行 keyvalet setup-enclave 初始化或迁移", "File-key mode has been removed on macOS; run keyvalet setup-enclave to initialize or migrate")).await);
    }

    let settings = read_settings(std::path::Path::new(VAULT_DIR));
    auth.requested = msg.requested_mode.as_deref().and_then(parse_mode);
    let mode = stricter(settings.grant_mode, auth.requested);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as f64;
    let remembered =
        mode == kv_core::settings::GrantMode::Remember && remember_active(&settings, now);

    // Hardware unlock cannot inspect credentials before authentication, so this prompt only
    // grants the vault session. Credential-specific authorization follows the existing policy.
    {
        let reason = kv_core::prompt::session_unlock(mode);
        let unlock = HardwareUnlock { vault, provider };
        let authorization = kv_core::auth_gate::touch_id_gate(
            &vault.dir,
            &reason,
            &kv_i18n::t("取消", "Cancel"),
            &unlock,
        )
        .await;
        if let Err(error) = authorization {
            return Err(reject_with(out, vault, ctx, Some(&purpose), error).await);
        }
        if mode == kv_core::settings::GrantMode::Remember && !remembered {
            let mut next = settings.clone();
            next.remember_until = Some(remember_until(settings.remember_hours, now));
            let _ = kv_core::write_settings(std::path::Path::new(VAULT_DIR), &next);
        }
        auth.apply_mode(&settings);
        let mut entry = Map::new();
        entry.insert("op".into(), json!("unlock"));
        entry.insert("ok".into(), json!(true));
        entry.insert("purpose".into(), json!(purpose));
        entry.insert("grant_mode".into(), json!(mode.as_str()));
        entry.insert("vault_protection".into(), json!(protection.provider));
        entry.insert("session".into(), json!(ctx.session));
        entry.insert("client".into(), serde_json::to_value(&*ctx).unwrap());
        let _ = vault.audit(entry);
    }
    send(
        out,
        &serde_json::to_value(ReadyMessage::Ready {
            ready: kv_ipc::True,
            protocol: PROTOCOL_VERSION,
        })
        .unwrap(),
    )
    .await;
    Ok(())
}

/// One session over any byte stream: handshake (30 s deadline), then the request loop, then the
/// session-end audit entry. All session state is per-call, so the daemon can run many of these
/// concurrently with nothing shared but the AgentHub and the socket limit.
async fn serve<R, W, A, C, M>(
    mut reader: R,
    writer: W,
    vault: Arc<Vault>,
    gateway_uid: Option<u32>,
    authenticator: A,
    confirmer: C,
    provider: Arc<M>,
) -> Reject
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
    A: kv_platform::Authenticator + Send + Sync + 'static,
    C: kv_platform::Confirmer + Clone + Send + Sync + 'static,
    M: kv_vault::MasterKeyProvider + Send + Sync + 'static,
{
    let ctx = Arc::new(AsyncMutex::new(ClientContext::default()));
    let deny_label = kv_i18n::t("拒绝", "Deny");
    let gate = TouchIdSessionGate {
        vault_dir: vault.dir.clone(),
        authenticator,
        deny_label,
    };
    let auth = Arc::new(AsyncMutex::new(SessionAuth::new(gate)));
    // The session's gateway. We keep our own clone so teardown doesn't have to wait on the
    // auth lock (a dispatch may be holding it, e.g. inside a Touch ID prompt).
    let gateway = {
        let vault_for_audit = vault.clone();
        let ctx_for_audit = ctx.clone();
        let gateway_audit: kv_proxy::gateway::GatewayAudit =
            Arc::new(move |mut e: Map<String, Value>| {
                if let Ok(c) = ctx_for_audit.try_lock() {
                    e.insert("session".into(), json!(c.session));
                    e.insert("client".into(), serde_json::to_value(&*c).unwrap());
                }
                let _ = vault_for_audit.audit(e);
            });
        let gateway = Arc::new(kv_proxy::gateway::Gateway::new(
            vault.clone(),
            gateway_audit,
            gateway_uid,
        ));
        auth.lock().await.gateway = Some(gateway.clone());
        gateway
    };

    let stdout = Arc::new(AsyncMutex::new(writer));

    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Handshake,
        Authenticating,
        Ready,
    }
    let state = Arc::new(AsyncMutex::new(State::Handshake));

    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    let in_flight = Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT));
    // Dispatch tasks spawned for this session: aborted + drained when the session ends so no
    // request keeps running (or keeps the vault) after the client is gone.
    let mut tasks: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    let handshake_deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;

    let end = 'outer: loop {
        let read = tokio::time::timeout_at(handshake_deadline, reader.read(&mut chunk));
        let n = if *state.lock().await == State::Handshake {
            match read.await {
                Ok(Ok(n)) => n,
                Ok(Err(_)) => break Reject::Refused,
                Err(_) => {
                    break Reject::ProtocolError(kv_i18n::t(
                        "等待握手超时",
                        "Timed out waiting for handshake",
                    ))
                }
            }
        } else {
            match reader.read(&mut chunk).await {
                Ok(n) => n,
                Err(_) => break Reject::Refused,
            }
        };
        if n == 0 {
            break Reject::Refused; // EOF: client closed the connection
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_LINE_BYTES {
            break Reject::ProtocolError(kv_i18n::t("请求过大", "Request too large"));
        }
        while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            let line_bytes: Vec<u8> = buf.drain(..=pos).collect();
            let line = String::from_utf8_lossy(&line_bytes[..line_bytes.len() - 1])
                .trim()
                .to_string();
            if line.is_empty() {
                continue;
            }

            let mut st = state.lock().await;
            if *st == State::Handshake {
                *st = State::Authenticating;
                drop(st);
                let mut ctx_guard = ctx.lock().await;
                let mut auth_guard = auth.lock().await;
                let handshake = authenticate(
                    &vault,
                    &line,
                    &mut ctx_guard,
                    &mut auth_guard,
                    &stdout,
                    provider.as_ref(),
                )
                .await;
                drop(ctx_guard);
                drop(auth_guard);
                match handshake {
                    Ok(()) => *state.lock().await = State::Ready,
                    Err(reject) => break 'outer reject,
                }
                continue;
            }
            if *st != State::Ready {
                break 'outer Reject::ProtocolError(kv_i18n::t(
                    "协议错误：认证完成前收到请求",
                    "Protocol error: request received before authentication completed",
                ));
            }
            drop(st);

            let req: Request = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(_) => {
                    break 'outer Reject::ProtocolError(kv_i18n::t(
                        "协议错误：非法 JSON",
                        "Protocol error: invalid JSON",
                    ))
                }
            };

            // Bounds how many dispatches may be spawned (and so how much input-reading outpaces
            // processing): acquiring blocks the main loop itself once MAX_IN_FLIGHT are
            // outstanding, backpressure through the socket rather than an in-memory queue.
            let permit = in_flight.clone().acquire_owned().await.unwrap();
            let vault = vault.clone();
            let ctx = ctx.clone();
            let auth = auth.clone();
            let stdout = stdout.clone();
            let confirmer = confirmer.clone();
            while tasks.try_join_next().is_some() {}
            tasks.spawn(async move {
                let _permit = permit;
                let id = req.id;
                let client_ctx = ctx.lock().await.clone();
                let mut auth_guard = auth.lock().await;
                let resp = kv_core::dispatch(
                    &vault,
                    id,
                    &req.op,
                    req.params,
                    &client_ctx,
                    Some(&mut auth_guard),
                    &confirmer,
                )
                .await;
                drop(auth_guard);
                send(&stdout, &serde_json::to_value(&resp).unwrap()).await;
            });
        }
    };

    // Teardown order: stop the gateway first (listener + connection tasks -- no auth lock, so
    // a dispatch stuck inside a prompt can't keep it alive), then cancel leftover dispatches,
    // then the session-end audit. The SessionAuth's own clone of the gateway is dropped with it;
    // Drop -> shutdown is idempotent.
    gateway.shutdown();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}

    if *state.lock().await == State::Ready {
        let c = ctx.lock().await;
        let mut entry = Map::new();
        entry.insert("op".into(), json!("session-end"));
        entry.insert("session".into(), json!(c.session));
        entry.insert("client".into(), serde_json::to_value(&*c).unwrap());
        let _ = vault.audit(entry);
    }
    end
}

fn main() {
    unsafe { libc::umask(0o077) };
    // A core dump on crash would write this process's whole memory -- including the master key
    // and every decrypted secret currently in play -- to a file on disk in one shot. Zeroing
    // secrets on drop (CredentialRecord's Drop impl) doesn't help against that: a crash dumps
    // whatever was live at that instant, zeroed-and-already-freed memory or not. Disabling the
    // dump entirely removes that path rather than trying to guess which crash is "safe."
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--daemon") {
        let uid: u32 = args
            .get(3)
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| fatal("usage: kv-helper --daemon --uid <uid>"));
        if args.get(2).map(String::as_str) != Some("--uid") {
            fatal("usage: kv-helper --daemon --uid <uid>");
        }
        daemon::run(uid);
        return;
    }
    stdio_main();
}

#[tokio::main]
async fn stdio_main() {
    let self_path = std::env::current_exe().unwrap_or_default();
    if let Err(e) = verify_root_environment(&self_path, std::path::Path::new(HELPER_BIN), &[]) {
        fatal(&e);
    }

    let vault = Arc::new(Vault::new(VAULT_DIR));
    if let Err(e) = vault.prepare() {
        fatal(&kv_i18n::t(
            &format!("凭证库初始化失败：{}", e.0),
            &format!("Vault initialization failed: {}", e.0),
        ));
    }

    // SIGTERM/SIGINT/SIGHUP: exit immediately, matching the TS version.
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        for kind in [
            SignalKind::terminate(),
            SignalKind::interrupt(),
            SignalKind::hangup(),
        ] {
            if let Ok(mut sig) = signal(kind) {
                tokio::spawn(async move {
                    sig.recv().await;
                    std::process::exit(0);
                });
            }
        }
    }

    let sudo_uid: Option<u32> = std::env::var("SUDO_UID").ok().and_then(|v| v.parse().ok());
    let provider = Arc::new(kv_platform::enclave::EnclaveMasterKeyProvider);
    match serve(
        tokio::io::stdin(),
        tokio::io::stdout(),
        vault,
        sudo_uid,
        TouchIdAuthenticator,
        RootUserDialogConfirmer,
        provider,
    )
    .await
    {
        Reject::ProtocolError(e) => fatal(&e),
        Reject::Refused => std::process::exit(0),
    }
}

#[cfg(target_os = "macos")]
mod daemon;

#[cfg(test)]
mod session_tests {
    use super::*;
    use kv_platform::{AuthOutcome, Authenticator, Confirmer};
    use kv_vault::{EnclaveKey, EnclaveMetadata, MasterKey, MasterKeyProvider};
    use serde_json::json;
    use tokio::io::AsyncBufReadExt;

    const PASSWORD: &str = "a separate offline recovery passphrase";

    fn enclave_metadata() -> EnclaveMetadata {
        // Pre-encoded fixture (base64 of single-byte values), mirroring kv-vault's own tests.
        EnclaveMetadata {
            version: 1,
            key_blob: "BQ==".to_string(),
            peer_public_key: "BAUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=".to_string(),
        }
    }

    struct Fixed;
    impl MasterKeyProvider for Fixed {
        fn create(&self, _reason: &str) -> kv_vault::Result<EnclaveKey> {
            Ok(EnclaveKey {
                key: MasterKey::new([5u8; 32]),
                metadata: enclave_metadata(),
            })
        }
        fn unlock(&self, metadata: &EnclaveMetadata, _reason: &str) -> kv_vault::Result<MasterKey> {
            assert_eq!(metadata, &enclave_metadata());
            Ok(MasterKey::new([5u8; 32]))
        }
    }

    #[derive(Clone, Copy)]
    struct AlwaysApprove;
    impl Authenticator for AlwaysApprove {
        async fn authenticate(&self, _r: &str, _d: &str) -> AuthOutcome {
            AuthOutcome::Approved
        }
    }
    #[derive(Clone, Copy)]
    struct AlwaysConfirm;
    impl Confirmer for AlwaysConfirm {
        async fn confirm(&self, _m: &str, _o: &str) -> bool {
            true
        }
    }

    fn enclave_vault(tmp: &tempfile::TempDir) -> Arc<Vault> {
        let vault = Arc::new(Vault::new(tmp.path().join("vault")));
        vault.prepare().unwrap();
        vault.initialize_enclave(&Fixed, PASSWORD, "test").unwrap();
        vault
    }

    fn auth_line() -> String {
        let msg = AuthMessage {
            op: "auth".into(),
            purpose: "run the test".into(),
            requested_mode: None,
            lang: Some("en".into()),
            credential: None,
            cwd: "/tmp".into(),
            ppid: 1,
            session: "test-session".into(),
            client: "test".into(),
        };
        let mut line = serde_json::to_vec(&msg).unwrap();
        line.push(b'\n');
        String::from_utf8(line).unwrap()
    }

    /// handshake -> ready -> one request -> EOF -> session-end audit, all over an in-memory
    /// duplex stream with fake UI/hardware providers.
    #[tokio::test]
    async fn a_session_runs_the_full_lifecycle_over_a_duplex_stream() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = enclave_vault(&tmp);
        let audit_vault = vault.clone();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (sr, sw) = tokio::io::split(server);
        let session = tokio::spawn(serve(
            sr,
            sw,
            vault,
            Some(501),
            AlwaysApprove,
            AlwaysConfirm,
            Arc::new(Fixed),
        ));

        let (mut cr, mut cw) = tokio::io::split(client);
        cw.write_all(auth_line().as_bytes()).await.unwrap();
        let mut first = String::new();
        tokio::io::BufReader::new(&mut cr)
            .read_line(&mut first)
            .await
            .unwrap();
        assert!(first.contains("\"ready\":true"), "{first}");

        let req = json!({"id": 1, "op": "list", "params": {"purpose": "run the test"}});
        cw.write_all(serde_json::to_string(&req).unwrap().as_bytes())
            .await
            .unwrap();
        cw.write_all(b"\n").await.unwrap();
        let mut resp = String::new();
        tokio::io::BufReader::new(&mut cr)
            .read_line(&mut resp)
            .await
            .unwrap();
        assert!(resp.contains("\"id\":1"), "{resp}");

        drop(cr);
        drop(cw); // EOF ends the session
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), session)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(outcome, Reject::Refused));

        // The session-end entry is the last thing the audit log recorded.
        let log = std::fs::read_to_string(audit_vault.dir.join("audit.log")).unwrap();
        let last = log.lines().last().unwrap();
        assert!(last.contains("\"op\":\"session-end\""), "{last}");
        assert!(last.contains("test-session"), "{last}");
    }

    /// A rejected handshake (no purpose) writes NotReady and ends only that connection.
    #[tokio::test]
    async fn a_rejected_handshake_closes_only_that_session() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = enclave_vault(&tmp);
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (sr, sw) = tokio::io::split(server);
        let session = tokio::spawn(serve(
            sr,
            sw,
            vault,
            Some(501),
            AlwaysApprove,
            AlwaysConfirm,
            Arc::new(Fixed),
        ));

        let (mut cr, mut cw) = tokio::io::split(client);
        let mut bad = serde_json::from_str::<serde_json::Map<String, Value>>(&auth_line()).unwrap();
        bad.insert("purpose".into(), json!("a")); // too short after cleaning -> reject
        cw.write_all(serde_json::to_string(&bad).unwrap().as_bytes())
            .await
            .unwrap();
        cw.write_all(b"\n").await.unwrap();
        let mut reply = String::new();
        tokio::io::BufReader::new(&mut cr)
            .read_line(&mut reply)
            .await
            .unwrap();
        assert!(reply.contains("\"ready\":false"), "{reply}");
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), session)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(outcome, Reject::Refused));
    }

    /// Regression for the daemon-mode leak: a gateway must not outlive its session. Open one
    /// inside a session, close the client, and assert the port refuses connections and the
    /// vault has no strong references left beyond the caller's.
    #[tokio::test]
    async fn session_end_shuts_down_the_gateway_and_drops_the_vault() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = enclave_vault(&tmp);
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (sr, sw) = tokio::io::split(server);
        let my_uid = unsafe { libc::getuid() };
        let session = tokio::spawn(serve(
            sr,
            sw,
            vault.clone(),
            Some(my_uid),
            AlwaysApprove,
            AlwaysConfirm,
            Arc::new(Fixed),
        ));

        let (mut cr, mut cw) = tokio::io::split(client);
        cw.write_all(auth_line().as_bytes()).await.unwrap();
        let mut buf = tokio::io::BufReader::new(&mut cr);
        let mut first = String::new();
        buf.read_line(&mut first).await.unwrap();
        assert!(first.contains("\"ready\":true"), "{first}");

        // Give the credential an inline http config, then open the gateway.
        let set = json!({"id": 1, "op": "set", "params": {
            "purpose": "run the test", "type": "api_key", "name": "svc", "value": "sk-abc",
            "http": {"inject": {"headers": {"Authorization": "Bearer {{value}}"}}, "allowed_hosts": ["api.example.com"]}
        }});
        cw.write_all(serde_json::to_string(&set).unwrap().as_bytes())
            .await
            .unwrap();
        cw.write_all(b"\n").await.unwrap();
        let mut line = String::new();
        buf.read_line(&mut line).await.unwrap();
        assert!(line.contains("\"ok\":true"), "{line}");

        let open = json!({"id": 2, "op": "gatewayOpen", "params": {
            "purpose": "run the test", "type": "api_key", "name": "svc"
        }});
        cw.write_all(serde_json::to_string(&open).unwrap().as_bytes())
            .await
            .unwrap();
        cw.write_all(b"\n").await.unwrap();
        let mut line = String::new();
        buf.read_line(&mut line).await.unwrap();
        assert!(line.contains("\"ok\":true"), "{line}");
        let result = serde_json::from_str::<Value>(&line).unwrap()["result"].clone();
        let port = result["port"]
            .as_u64()
            .or_else(|| {
                result["base"]
                    .as_str()
                    .and_then(|b| b.rsplit(':').next()?.parse::<u64>().ok())
            })
            .unwrap() as u16;

        // The gateway accepts connections while the session is live.
        assert!(std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_ok());

        drop(cw);
        drop(buf);
        drop(cr);
        tokio::time::timeout(std::time::Duration::from_secs(5), session)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            Arc::strong_count(&vault),
            1,
            "nothing from the session may retain the vault key"
        );
        assert!(
            std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_err(),
            "the gateway listener must be gone with the session"
        );
    }

    /// Approves the first two authentications (handshake unlock, gateway grant), then blocks on
    /// the third -- the per-credential grant prompt for `get` -- while holding the auth lock.
    struct ApproveThenBlock {
        calls: std::sync::atomic::AtomicUsize,
    }
    impl Authenticator for ApproveThenBlock {
        async fn authenticate(&self, _r: &str, _d: &str) -> AuthOutcome {
            if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
                AuthOutcome::Approved
            } else {
                tokio::time::sleep(std::time::Duration::from_secs(600)).await;
                AuthOutcome::Approved
            }
        }
    }
    impl Clone for ApproveThenBlock {
        fn clone(&self) -> Self {
            Self {
                calls: std::sync::atomic::AtomicUsize::new(
                    self.calls.load(std::sync::atomic::Ordering::SeqCst),
                ),
            }
        }
    }

    /// Teardown must not wait on the auth lock: with a dispatch task parked inside a Touch ID
    /// prompt (holding it), EOF must still shut the gateway and return promptly.
    #[tokio::test]
    async fn session_end_is_not_delayed_by_a_prompt_blocked_dispatch() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = enclave_vault(&tmp);
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (sr, sw) = tokio::io::split(server);
        let my_uid = unsafe { libc::getuid() };
        let session = tokio::spawn(serve(
            sr,
            sw,
            vault.clone(),
            Some(my_uid),
            ApproveThenBlock {
                calls: std::sync::atomic::AtomicUsize::new(0),
            },
            AlwaysConfirm,
            Arc::new(Fixed),
        ));

        let (mut cr, mut cw) = tokio::io::split(client);
        cw.write_all(auth_line().as_bytes()).await.unwrap();
        let mut buf = tokio::io::BufReader::new(&mut cr);
        let mut first = String::new();
        buf.read_line(&mut first).await.unwrap();
        assert!(first.contains("\"ready\":true"), "{first}");

        let set = json!({"id": 1, "op": "set", "params": {
            "purpose": "run the test", "type": "api_key", "name": "svc", "value": "sk-abc",
            "http": {"inject": {"headers": {"Authorization": "Bearer {{value}}"}}, "allowed_hosts": ["api.example.com"]}
        }});
        cw.write_all(serde_json::to_string(&set).unwrap().as_bytes())
            .await
            .unwrap();
        cw.write_all(b"\n").await.unwrap();
        let mut line = String::new();
        buf.read_line(&mut line).await.unwrap();
        assert!(line.contains("\"ok\":true"), "{line}");

        let open = json!({"id": 2, "op": "gatewayOpen", "params": {
            "purpose": "run the test", "type": "api_key", "name": "svc"
        }});
        cw.write_all(serde_json::to_string(&open).unwrap().as_bytes())
            .await
            .unwrap();
        cw.write_all(b"\n").await.unwrap();
        let mut line = String::new();
        buf.read_line(&mut line).await.unwrap();
        assert!(line.contains("\"ok\":true"), "{line}");
        let result = serde_json::from_str::<Value>(&line).unwrap()["result"].clone();
        let port = result["port"]
            .as_u64()
            .or_else(|| {
                result["base"]
                    .as_str()
                    .and_then(|b| b.rsplit(':').next()?.parse::<u64>().ok())
            })
            .unwrap() as u16;
        assert!(std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_ok());

        // This dispatch parks inside the grant prompt, holding the session auth lock.
        let get = json!({"id": 3, "op": "get", "params": {
            "purpose": "run the test", "type": "api_key", "name": "svc"
        }});
        cw.write_all(serde_json::to_string(&get).unwrap().as_bytes())
            .await
            .unwrap();
        cw.write_all(b"\n").await.unwrap();
        // Give the dispatch a moment to reach the blocked authenticate.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let started = std::time::Instant::now();
        drop(cw);
        drop(buf);
        drop(cr);
        tokio::time::timeout(std::time::Duration::from_secs(5), session)
            .await
            .unwrap()
            .unwrap();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "teardown must not wait on a prompt-blocked dispatch"
        );
        assert!(
            std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_err(),
            "the gateway listener must be gone with the session"
        );
        assert_eq!(Arc::strong_count(&vault), 1);
    }
}
