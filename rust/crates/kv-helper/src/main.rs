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
use kv_ipc::{
    clean_purpose, AuthMessage, ProtectionProbe, ReadyMessage, Request, Response, MAX_LINE_BYTES,
    PROTOCOL_VERSION,
};
#[cfg(target_os = "macos")]
use kv_platform::macos::{RootUserDialogConfirmer, TouchIdAuthenticator};
#[cfg(target_os = "macos")]
use kv_platform::paths::HELPER_BIN;
#[cfg(target_os = "macos")]
use kv_platform::paths::VAULT_DIR;
#[cfg(target_os = "macos")]
use kv_platform::trust::verify_root_environment;
use kv_vault::Vault;
use serde_json::{json, Map, Value};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex as AsyncMutex;

#[cfg(any(unix, windows))] // session serving is shared; Windows uses the named-pipe daemon
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
#[cfg(any(unix, windows))] // session serving is shared; Windows uses the named-pipe daemon
const MAX_IN_FLIGHT: usize = kv_ipc::MAX_IN_FLIGHT_REQUESTS;
#[cfg(any(unix, windows))] // session serving is shared; Windows uses the named-pipe daemon
const MAX_CLIENTS: usize = 32;

fn fatal(msg: &str) -> ! {
    eprintln!("keyvalet-helper: {msg}");
    std::process::exit(1);
}

#[cfg(any(unix, windows))] // session serving is shared; Windows uses the named-pipe daemon
struct HardwareUnlock<'a> {
    vault: &'a Arc<Vault>,
    provider: Arc<dyn kv_vault::MasterKeyProvider + Send + Sync>,
}

#[cfg(any(unix, windows))]
impl kv_platform::Authenticator for HardwareUnlock<'_> {
    async fn authenticate(&self, reason: &str, _deny_label: &str) -> kv_platform::AuthOutcome {
        #[cfg(target_os = "linux")]
        let result = {
            let vault = self.vault.clone();
            let provider = self.provider.clone();
            let reason = reason.to_owned();
            tokio::task::spawn_blocking(move || {
                vault.init_with_provider(provider.as_ref(), &reason)
            })
            .await
            .unwrap_or_else(|e| Err(kv_vault::VaultError(e.to_string())))
        };
        #[cfg(not(target_os = "linux"))]
        let result = self
            .vault
            .init_with_provider(self.provider.as_ref(), reason);
        match result {
            Ok(()) => kv_platform::AuthOutcome::Approved,
            Err(e) => kv_platform::AuthOutcome::Error(e.0),
        }
    }
}

#[cfg(any(unix, windows))] // session serving is shared; Windows uses the named-pipe daemon
fn clip(s: &str, n: usize) -> String {
    s.chars()
        .filter(|c| !matches!(c, '\u{0000}'..='\u{001f}' | '\u{007f}'))
        .take(n)
        .collect()
}

#[cfg(any(unix, windows))] // session serving is shared; Windows uses the named-pipe daemon
async fn send<W: AsyncWrite + Unpin>(out: &AsyncMutex<W>, value: &Value) {
    let mut line = serde_json::to_vec(value).unwrap();
    line.push(b'\n');
    let _ = out.lock().await.write_all(&line).await;
}

/// Why a connection ended before it was ready. In stdio mode these map to the legacy exit codes
/// (protocol errors exit 1, a rejected handshake exits 0); in daemon mode every one just closes
/// that connection.
#[cfg(any(unix, windows))] // session serving is shared; Windows uses the named-pipe daemon
enum Reject {
    ProtocolError(String),
    Refused,
}

#[cfg(any(unix, windows))] // session serving is shared; Windows uses the named-pipe daemon
async fn reject_with<W: AsyncWrite + Unpin>(
    out: &AsyncMutex<W>,
    vault: &Arc<Vault>,
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
#[cfg(any(unix, windows))] // session serving is shared; Windows uses the named-pipe daemon
async fn authenticate<G, W>(
    vault: &Arc<Vault>,
    line: &str,
    ctx: &mut ClientContext,
    auth: &mut SessionAuth<G>,
    out: &AsyncMutex<W>,
    provider: Arc<dyn kv_vault::MasterKeyProvider + Send + Sync>,
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
    if !matches!(
        protection.provider,
        "secure_enclave" | "windows_hello" | "tpm2" | "software_key"
    ) {
        return Err(reject_with(out, vault, ctx, Some(&purpose), kv_i18n::t("请先运行 keyvalet setup-enclave（macOS）、setup-hello（Windows）或 setup-tpm（Linux）初始化或迁移", "Run keyvalet setup-enclave (macOS), setup-hello (Windows) or setup-tpm (Linux) to initialize or migrate")).await);
    }

    let settings = read_settings(&vault.dir);
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
        #[cfg(target_os = "linux")]
        let reason = format!(
            "{reason}\n{}",
            kv_i18n::t(&format!("用途：{purpose}"), &format!("Purpose: {purpose}"))
        );
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
            // Another session may have tightened the policy while hardware authentication
            // was pending. Never restore that session's old mode or remembered window.
            if let Err(error) = kv_core::compare_and_write_settings(&vault.dir, &settings, &next) {
                return Err(reject_with(out, vault, ctx, Some(&purpose), error.to_string()).await);
            }
        }
        let mut current = read_settings(&vault.dir);
        current.grant_mode = stricter(mode, Some(current.grant_mode));
        auth.apply_mode(&current);
        let mut entry = Map::new();
        entry.insert("op".into(), json!("unlock"));
        entry.insert("ok".into(), json!(true));
        entry.insert("purpose".into(), json!(purpose));
        entry.insert("grant_mode".into(), json!(current.grant_mode.as_str()));
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
#[cfg(any(unix, windows))] // session serving is shared; Windows uses the named-pipe daemon
#[allow(clippy::too_many_arguments)] // the session context is a fixed contract; grouping it adds indirection
async fn serve<R, W, A, C, M>(
    mut reader: R,
    writer: W,
    vault: Arc<Vault>,
    gateway_uid: Option<kv_platform::peer::GatewayPeer>,
    agent_trust: &'static str,
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
    let peer = authenticator.peer_identity();
    let ctx = Arc::new(AsyncMutex::new(ClientContext {
        agent_trust: Some(agent_trust.to_string()),
        peer_uid: peer.map(|(uid, _)| uid),
        peer_pid: peer.map(|(_, pid)| pid),
        ..Default::default()
    }));
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
    let handshake_deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    let mut requests = tokio::task::JoinSet::new();

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
        while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            // A read can contain the end of one frame and the beginning of another. The
            // limit includes the newline and applies to the frame, not the whole buffer.
            if pos + 1 > MAX_LINE_BYTES {
                break 'outer Reject::ProtocolError(kv_i18n::t("请求过大", "Request too large"));
            }
            let line_bytes: Vec<u8> = buf.drain(..=pos).collect();
            let line = match std::str::from_utf8(&line_bytes[..line_bytes.len() - 1]) {
                Ok(line) => line.trim().to_string(),
                Err(_) => {
                    break 'outer Reject::ProtocolError(kv_i18n::t(
                        "协议错误：非法 UTF-8",
                        "Protocol error: invalid UTF-8",
                    ))
                }
            };
            if line.is_empty() {
                continue;
            }

            let mut st = state.lock().await;
            if *st == State::Handshake {
                if let Ok(ProtectionProbe::Status { protocol, lang }) = serde_json::from_str(&line)
                {
                    drop(st);
                    kv_i18n::set_lang(lang.as_deref().unwrap_or(""));
                    let response = if protocol != PROTOCOL_VERSION {
                        Response::err(0, "Helper version mismatch; please reinstall")
                    } else {
                        match kv_platform::protection::status(&vault) {
                            Ok(report) => Response::ok(
                                0,
                                json!({"protocol": PROTOCOL_VERSION, "vault_protection": report}),
                            ),
                            Err(error) => Response::err(0, error.0),
                        }
                    };
                    send(&stdout, &serde_json::to_value(response).unwrap()).await;
                    // In particular, ignore any credential commands already buffered after the
                    // probe. This connection can never transition to an authenticated session.
                    break 'outer Reject::Refused;
                }
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
                    provider.clone(),
                );
                #[cfg(target_os = "linux")]
                let handshake = {
                    let mut extra = [0u8; 1];
                    tokio::select! {
                        result = handshake => result,
                        input = reader.read(&mut extra) => match input {
                            Ok(0) | Err(_) => Err(Reject::Refused),
                            Ok(_) => Err(Reject::ProtocolError("request received while authentication is pending".into())),
                        }
                    }
                };
                #[cfg(not(target_os = "linux"))]
                let handshake = handshake.await;
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

            // Keep reading even when dispatch is saturated: awaiting a permit here would hide
            // EOF behind a pending approval and keep the unlocked vault alive after disconnect.
            while requests.try_join_next().is_some() {}
            let permit = match in_flight.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    // Busy replies share the bounded task set. A client that also stops reading
                    // replies must not turn overload errors into an unbounded output queue.
                    if requests.len() >= 2 * MAX_IN_FLIGHT {
                        break 'outer Reject::ProtocolError(kv_i18n::t(
                            "待处理请求过多",
                            "Too many pending requests",
                        ));
                    }
                    let stdout = stdout.clone();
                    requests.spawn(async move {
                        let response = Response::err(
                            req.id,
                            kv_i18n::t("请求繁忙，请稍后重试", "Session busy; retry later"),
                        );
                        send(&stdout, &serde_json::to_value(response).unwrap()).await;
                    });
                    continue;
                }
            };
            let vault = vault.clone();
            let ctx = ctx.clone();
            let auth = auth.clone();
            let stdout = stdout.clone();
            let confirmer = confirmer.clone();
            requests.spawn(async move {
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
        // An unfinished frame also needs room for its terminating newline. The read size
        // caps the temporary excess at one chunk; an oversized partial frame cannot linger.
        if buf.len() >= MAX_LINE_BYTES {
            break Reject::ProtocolError(kv_i18n::t("请求过大", "Request too large"));
        }
    };

    // Revoke the gateway before waiting for an auth lock held by an unfinished prompt.
    // Then cancel and drain every session request before releasing listener/vault references.
    gateway.close();
    requests.abort_all();
    while requests.join_next().await.is_some() {}
    gateway.shutdown().await;

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
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077)
    };
    // A core dump on crash would write this process's whole memory -- including the master key
    // and every decrypted secret currently in play -- to a file on disk in one shot. Zeroing
    // secrets on drop (CredentialRecord's Drop impl) doesn't help against that: a crash dumps
    // whatever was live at that instant, zeroed-and-already-freed memory or not. Disabling the
    // dump entirely removes that path rather than trying to guess which crash is "safe."
    #[cfg(unix)]
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
    let args: Vec<String> = std::env::args().collect();
    #[cfg(target_os = "linux")]
    {
        if args.len() != 2 || args[1] != "--daemon" {
            fatal("usage: kv-helper --daemon (systemd, User=keyvalet)");
        }
        daemon_linux::run(daemon_linux::Environment::system()).unwrap_or_else(|e| fatal(&e));
    }
    #[cfg(target_os = "macos")]
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
    #[cfg(windows)]
    match args.get(1).map(String::as_str) {
        Some("--service") => daemon_win::run_service(),
        Some("--console") => daemon_win::run_console(),
        _ => {
            // Plain kv-helper.exe is never user-invoked on Windows: the LocalSystem service owns
            // the pipes and the stdio/sudo fallback does not exist there.
            fatal(&kv_i18n::t(
                "kv-helper 由 KeyValetHelper 服务运行（--service），调试可用 --console",
                "kv-helper runs as the KeyValetHelper service (--service); use --console for debugging",
            ));
        }
    }
    #[cfg(target_os = "macos")]
    stdio_main();
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    fatal(&kv_i18n::t(
        "此平台暂不支持",
        "this platform is not supported yet",
    ));
}

#[cfg(target_os = "macos")]
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
        // No agent broker in stdio mode; Touch ID and dialogs run in-process.
        "none",
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

/// Answers a privileged control connection: `{"op":"control","command":"sessions"}` ->
/// `{"sessions":N}`; anything else closes the connection (matches the macOS daemon exactly).
#[cfg(unix)]
pub(crate) async fn control<S>(stream: S, sessions: Arc<std::sync::atomic::AtomicUsize>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut line = String::new();
    let n = tokio::io::AsyncBufReadExt::read_line(
        &mut tokio::io::BufReader::new(&mut reader),
        &mut line,
    )
    .await;
    let ok = matches!(n, Ok(1..)) && {
        let v: Value = serde_json::from_str(line.trim()).unwrap_or(Value::Null);
        v.get("op").and_then(Value::as_str) == Some("control")
            && v.get("command").and_then(Value::as_str) == Some("sessions")
    };
    if ok {
        let reply = json!({"sessions": sessions.load(std::sync::atomic::Ordering::SeqCst)});
        let mut bytes = serde_json::to_vec(&reply).unwrap();
        bytes.push(b'\n');
        let _ = writer.write_all(&bytes).await;
    }
    let _ = writer.shutdown().await;
}

#[cfg(target_os = "macos")]
mod daemon;
#[cfg(target_os = "linux")]
mod daemon_linux;
#[cfg(windows)]
mod daemon_win;
#[cfg(windows)]
mod mcp_win;

#[cfg(all(test, any(unix, windows)))]
mod session_tests {
    use super::*;
    use kv_platform::{AuthOutcome, Authenticator, Confirmer};
    use kv_vault::{EnclaveKey, EnclaveMetadata, MasterKey, MasterKeyProvider};
    use serde_json::json;
    use tokio::io::AsyncBufReadExt;

    #[tokio::test]
    async fn session_disconnect_closes_the_gateway_and_releases_the_unlocked_vault() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = enclave_vault(&tmp);
        vault
            .set(kv_vault::SetParams {
                r#type: "api_key".into(),
                name: "svc".into(),
                value: Some("synthetic-secret".into()),
                http: Some(kv_vault::HttpConfig {
                    inject: Some(kv_vault::InjectRule {
                        headers: Some(std::collections::HashMap::from([(
                            "Authorization".into(),
                            "Bearer {{value}}".into(),
                        )])),
                        ..Default::default()
                    }),
                    allowed_hosts: vec!["example.com".into()],
                    proxy_only: true,
                    test: None,
                }),
                ..Default::default()
            })
            .unwrap();
        kv_core::write_settings(
            &vault.dir,
            &kv_core::settings::Settings {
                grant_mode: kv_core::settings::GrantMode::PerSession,
                remember_hours: 8.0,
                remember_until: None,
            },
        )
        .unwrap();
        let weak = Arc::downgrade(&vault);
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (sr, sw) = tokio::io::split(server);
        let session = tokio::spawn(serve(
            sr,
            sw,
            vault,
            None,
            "signed",
            AlwaysApprove,
            AlwaysConfirm,
            Arc::new(Fixed),
        ));
        let (cr, mut cw) = tokio::io::split(client);
        let mut cr = tokio::io::BufReader::new(cr);
        cw.write_all(auth_line().as_bytes()).await.unwrap();
        let mut line = String::new();
        cr.read_line(&mut line).await.unwrap();
        assert!(line.contains("\"ready\":true"), "{line}");
        let request = json!({"id":1,"op":"gatewayOpen","params":{"type":"api_key","name":"svc","purpose":"test gateway lifecycle"}});
        cw.write_all(format!("{request}\n").as_bytes())
            .await
            .unwrap();
        line.clear();
        cr.read_line(&mut line).await.unwrap();
        let opened: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(opened["ok"], true, "{line}");
        let authority = opened["result"]["base"]
            .as_str()
            .unwrap()
            .strip_prefix("http://")
            .unwrap()
            .to_string();
        let mut idle = tokio::net::TcpStream::connect(&authority).await.unwrap();
        drop(cr);
        drop(cw);
        tokio::time::timeout(std::time::Duration::from_secs(5), session)
            .await
            .unwrap()
            .unwrap();
        assert!(
            weak.upgrade().is_none(),
            "ended session must release its unlocked vault"
        );
        assert!(tokio::net::TcpStream::connect(&authority).await.is_err());
        use tokio::io::AsyncReadExt;
        let read =
            tokio::time::timeout(std::time::Duration::from_secs(1), idle.read(&mut [0u8; 1]))
                .await
                .unwrap();
        assert!(matches!(read, Ok(0) | Err(_)));
    }

    #[tokio::test]
    async fn a_full_request_queue_still_rejects_overload_and_observes_disconnect() {
        use std::sync::atomic::{AtomicBool, Ordering};

        #[derive(Clone)]
        struct PendingApproval {
            started: Arc<tokio::sync::Notify>,
            cancelled: Arc<AtomicBool>,
        }
        struct OnCancel(Arc<AtomicBool>);
        impl Drop for OnCancel {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        impl Authenticator for PendingApproval {
            async fn authenticate(&self, _reason: &str, _deny: &str) -> AuthOutcome {
                let _guard = OnCancel(self.cancelled.clone());
                self.started.notify_one();
                std::future::pending().await
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let vault = enclave_vault(&tmp);
        vault
            .set(kv_vault::SetParams {
                r#type: "api_key".into(),
                name: "pending".into(),
                value: Some("synthetic-secret".into()),
                ..Default::default()
            })
            .unwrap();
        let weak = Arc::downgrade(&vault);
        let approval = PendingApproval {
            started: Arc::new(tokio::sync::Notify::new()),
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (sr, sw) = tokio::io::split(server);
        let session = tokio::spawn(serve(
            sr,
            sw,
            vault,
            None,
            "signed",
            approval.clone(),
            AlwaysConfirm,
            Arc::new(Fixed),
        ));
        let (cr, mut cw) = tokio::io::split(client);
        let mut cr = tokio::io::BufReader::new(cr);
        cw.write_all(auth_line().as_bytes()).await.unwrap();
        let mut line = String::new();
        cr.read_line(&mut line).await.unwrap();
        assert!(line.contains("\"ready\":true"), "{line}");
        for id in 1..=MAX_IN_FLIGHT + 1 {
            let request = json!({"id":id,"op":"grant","params":{"type":"api_key","name":"pending","purpose":"test pending approval"}});
            cw.write_all(format!("{request}\n").as_bytes())
                .await
                .unwrap();
        }
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            approval.started.notified(),
        )
        .await
        .unwrap();
        line.clear();
        tokio::time::timeout(std::time::Duration::from_secs(2), cr.read_line(&mut line))
            .await
            .expect("overload must receive a reply while approval is pending")
            .unwrap();
        let busy: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(busy["id"], MAX_IN_FLIGHT + 1);
        assert_eq!(busy["ok"], false);

        drop(cr);
        drop(cw);
        tokio::time::timeout(std::time::Duration::from_secs(2), session)
            .await
            .expect("a saturated session must still observe EOF")
            .unwrap();
        assert!(approval.cancelled.load(Ordering::SeqCst));
        assert!(
            weak.upgrade().is_none(),
            "disconnect must release the vault"
        );
    }

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

    #[tokio::test]
    async fn hardware_unlock_cannot_restore_settings_changed_during_authentication() {
        use kv_core::{GrantMode, Settings};

        struct ChangingProvider {
            dir: std::path::PathBuf,
            next: Settings,
        }
        impl MasterKeyProvider for ChangingProvider {
            fn create(&self, _reason: &str) -> kv_vault::Result<EnclaveKey> {
                panic!("authentication must not create a key");
            }
            fn unlock(
                &self,
                metadata: &EnclaveMetadata,
                reason: &str,
            ) -> kv_vault::Result<MasterKey> {
                kv_core::write_settings(&self.dir, &self.next)?;
                Fixed.unlock(metadata, reason)
            }
        }

        for (initial, changed, effective) in [
            (GrantMode::Remember, GrantMode::PerUse, GrantMode::PerUse),
            (
                GrantMode::Remember,
                GrantMode::Remember,
                GrantMode::Remember,
            ),
            (
                GrantMode::PerCredential,
                GrantMode::Remember,
                GrantMode::PerCredential,
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let vault = enclave_vault(&tmp);
            let initial = Settings {
                grant_mode: initial,
                remember_hours: 8.0,
                remember_until: None,
            };
            let next = Settings {
                grant_mode: changed,
                remember_hours: 1.0,
                remember_until: None,
            };
            kv_core::write_settings(&vault.dir, &initial).unwrap();
            let provider = Arc::new(ChangingProvider {
                dir: vault.dir.clone(),
                next: next.clone(),
            });
            let gate = TouchIdSessionGate {
                vault_dir: vault.dir.clone(),
                authenticator: AlwaysApprove,
                deny_label: "Deny".into(),
            };
            let mut auth = SessionAuth::new(gate);
            let (reader, writer) = tokio::io::duplex(4096);
            let out = AsyncMutex::new(writer);
            assert!(authenticate(
                &vault,
                &auth_line(),
                &mut ClientContext::default(),
                &mut auth,
                &out,
                provider,
            )
            .await
            .is_ok());
            let mut ready = String::new();
            tokio::io::BufReader::new(reader)
                .read_line(&mut ready)
                .await
                .unwrap();
            assert!(ready.contains("\"ready\":true"), "{ready}");
            assert_eq!(kv_core::read_settings(&vault.dir), next);
            assert_eq!(auth.mode, Some(effective));
            assert_eq!(auth.grant_all, effective == GrantMode::Remember);
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

    /// The gateway peer value used in tests: a uid on unix, owner SID bytes on Windows.
    fn test_peer() -> Option<kv_platform::peer::GatewayPeer> {
        #[cfg(unix)]
        {
            Some(501)
        }
        #[cfg(windows)]
        {
            Some(vec![1, 5, 0, 0, 0, 0, 0, 5])
        }
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

    #[derive(Clone, Copy)]
    struct NoSecretAccess;
    impl Authenticator for NoSecretAccess {
        async fn authenticate(&self, _r: &str, _d: &str) -> AuthOutcome {
            panic!("a protection probe must not authenticate");
        }
    }
    impl Confirmer for NoSecretAccess {
        async fn confirm(&self, _m: &str, _o: &str) -> bool {
            panic!("a protection probe must not request approval");
        }
    }
    impl MasterKeyProvider for NoSecretAccess {
        fn create(&self, _r: &str) -> kv_vault::Result<EnclaveKey> {
            panic!("a protection probe must not create keys");
        }
        fn unlock(&self, _m: &EnclaveMetadata, _r: &str) -> kv_vault::Result<MasterKey> {
            panic!("a protection probe must not unlock keys");
        }
    }

    async fn public_probe(
        vault: Arc<Vault>,
        commands: &[u8],
        chunk_size: usize,
    ) -> (Reject, String) {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (reader, writer) = tokio::io::split(server);
        let session = tokio::spawn(serve(
            reader,
            writer,
            vault,
            test_peer(),
            "signed",
            NoSecretAccess,
            NoSecretAccess,
            Arc::new(NoSecretAccess),
        ));
        for chunk in commands.chunks(chunk_size) {
            if client.write_all(chunk).await.is_err() {
                break; // Oversized input may be refused before the sender finishes.
            }
            tokio::task::yield_now().await;
        }
        let _ = client.shutdown().await;
        let mut output = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_to_string(&mut output),
        )
        .await
        .unwrap()
        .unwrap();
        (session.await.unwrap(), output)
    }

    #[tokio::test]
    async fn malformed_or_truncated_protection_probes_never_authenticate_or_change_vault_files() {
        let tmp = tempfile::tempdir().unwrap();
        let initialized = enclave_vault(&tmp);
        let path = initialized.dir.clone();
        drop(initialized);
        let vault = Arc::new(Vault::new(path));
        let data_before = std::fs::read(vault.dir.join("vault.enc")).unwrap();
        let audit_before = std::fs::read(vault.dir.join("audit.log")).ok();
        let mut disguised_auth: Value = serde_json::from_str(&auth_line()).unwrap();
        disguised_auth["op"] = json!("protection");
        disguised_auth["protocol"] = json!(PROTOCOL_VERSION);
        let mut invalid = vec![
            b"{invalid}\n".to_vec(),
            b"\xff\n".to_vec(),
            b"{\"op\":\"protection\"}\n".to_vec(),
            format!("{{\"op\":\"protection\",\"protocol\":\"{PROTOCOL_VERSION}\"}}\n").into_bytes(),
            format!("{{\"op\":\"protection\",\"protocol\":{PROTOCOL_VERSION},\"lang\":false}}\n").into_bytes(),
            format!("{{\"op\":\"protection\",\"protocol\":{PROTOCOL_VERSION},\"id\":1,\"params\":{{\"op\":\"get\"}}}}\n").into_bytes(),
            format!("{{\"op\":\"protection\",\"op\":\"auth\",\"protocol\":{PROTOCOL_VERSION}}}\n").into_bytes(),
            format!("{disguised_auth}\n").into_bytes(),
            format!("{{\"op\":\"protection\",\"protocol\":{PROTOCOL_VERSION}}}").into_bytes(),
        ];
        invalid.push(vec![b'x'; MAX_LINE_BYTES + 1]);
        for input in invalid {
            let (rejected, output) = public_probe(vault.clone(), &input, 64 * 1024).await;
            assert!(matches!(
                rejected,
                Reject::ProtocolError(_) | Reject::Refused
            ));
            assert!(!output.contains("\"ready\":true"), "{output}");
            assert!(!output.contains("vault_protection"), "{output}");
            assert_eq!(
                std::fs::read(vault.dir.join("vault.enc")).unwrap(),
                data_before
            );
            assert_eq!(
                std::fs::read(vault.dir.join("audit.log")).ok(),
                audit_before
            );
        }
    }

    #[tokio::test]
    async fn invalid_utf8_inside_a_probe_string_is_rejected_without_replacement() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::new(tmp.path().join("vault")));
        vault.prepare().unwrap();
        let prefix =
            format!("{{\"op\":\"protection\",\"protocol\":{PROTOCOL_VERSION},\"lang\":\"en-");
        let mut invalid = prefix.as_bytes().to_vec();
        invalid.extend_from_slice(b"\xff\"}\n");
        let (rejected, output) = public_probe(vault.clone(), &invalid, 3).await;
        assert!(matches!(rejected, Reject::ProtocolError(_)));
        assert!(
            output.is_empty(),
            "invalid UTF-8 became a successful probe: {output}"
        );

        // An explicitly encoded replacement character is valid UTF-8, including when its
        // bytes cross reads. It must not be confused with malformed input.
        let valid = format!("{prefix}\u{fffd}\"}}\n");
        let (rejected, output) = public_probe(vault.clone(), valid.as_bytes(), 3).await;
        assert!(matches!(rejected, Reject::Refused));
        assert_eq!(
            kv_platform::protection::read_probe_response(output.as_bytes())
                .await
                .unwrap()["provider"],
            "uninitialized"
        );
        assert!(!vault.dir.join("audit.log").exists());
        assert!(!vault.dir.join("vault.enc").exists());
    }

    #[tokio::test]
    async fn invalid_utf8_credential_requests_never_change_values() {
        let tmp = tempfile::tempdir().unwrap();
        let initialized = enclave_vault(&tmp);
        initialized
            .set(kv_vault::SetParams {
                r#type: "api_key".into(),
                name: "target".into(),
                value: Some("synthetic-original-secret".into()),
                ..Default::default()
            })
            .unwrap();
        kv_core::write_settings(
            &initialized.dir,
            &kv_core::settings::Settings {
                grant_mode: kv_core::settings::GrantMode::PerSession,
                remember_hours: 8.0,
                remember_until: None,
            },
        )
        .unwrap();
        let path = initialized.dir.clone();
        drop(initialized);
        for value in [
            b"synthetic-\xff-secret".as_slice(),
            "synthetic-\u{fffd}-secret".as_bytes(),
        ] {
            let before = std::fs::read(path.join("vault.enc")).unwrap();
            let (client, server) = tokio::io::duplex(64 * 1024);
            let (reader, writer) = tokio::io::split(server);
            let session = tokio::spawn(serve(
                reader,
                writer,
                Arc::new(Vault::new(&path)),
                None,
                "signed",
                AlwaysApprove,
                AlwaysConfirm,
                Arc::new(Fixed),
            ));
            let (reader, mut writer) = tokio::io::split(client);
            let mut reader = tokio::io::BufReader::new(reader);
            writer.write_all(auth_line().as_bytes()).await.unwrap();
            let mut ready = String::new();
            reader.read_line(&mut ready).await.unwrap();
            assert!(ready.contains("\"ready\":true"), "{ready}");

            let mut request = b"{\"id\":1,\"op\":\"set\",\"params\":{\"type\":\"api_key\",\"name\":\"target\",\"value\":\"".to_vec();
            request.extend_from_slice(value);
            request.extend_from_slice(
                b"\",\"overwrite\":true,\"purpose\":\"test exact UTF-8 credential storage\"}}\n",
            );
            writer.write_all(&request).await.unwrap();
            let mut response = String::new();
            // Keep the connection alive for the valid request until its response arrives.
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                reader.read_line(&mut response),
            )
            .await
            .unwrap()
            .unwrap();
            drop(writer);
            drop(reader);
            let rejected = session.await.unwrap();
            if std::str::from_utf8(value).is_err() {
                assert!(matches!(rejected, Reject::ProtocolError(_)));
                assert!(
                    response.is_empty(),
                    "invalid UTF-8 became a credential write: {response}"
                );
                assert_eq!(std::fs::read(path.join("vault.enc")).unwrap(), before);
            } else {
                assert!(matches!(rejected, Reject::Refused));
                let response: Value = serde_json::from_str(&response).unwrap();
                assert_eq!(response["ok"], true);
                let saved = Vault::new(&path);
                saved.init_with_provider(&Fixed, "test").unwrap();
                assert_eq!(
                    saved.get("api_key", "target").unwrap().value,
                    "synthetic-\u{fffd}-secret"
                );
            }
        }
    }

    #[tokio::test]
    async fn probe_size_limits_apply_to_each_frame_instead_of_a_coalesced_read() {
        struct ChunkedInput {
            bytes: Vec<u8>,
            position: usize,
        }
        impl AsyncRead for ChunkedInput {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                output: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                let size = output
                    .remaining()
                    .min(8193)
                    .min(self.bytes.len() - self.position);
                output.put_slice(&self.bytes[self.position..self.position + size]);
                self.position += size;
                std::task::Poll::Ready(Ok(()))
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::new(tmp.path().join("vault")));
        vault.prepare().unwrap();
        for frame_size in [MAX_LINE_BYTES - 1, MAX_LINE_BYTES, MAX_LINE_BYTES + 1] {
            let mut commands = serde_json::to_vec(&ProtectionProbe::Status {
                protocol: PROTOCOL_VERSION,
                lang: Some("en".into()),
            })
            .unwrap();
            commands.resize(frame_size - 1, b' ');
            commands.push(b'\n');
            commands.extend_from_slice(
                b"{\"id\":1,\"op\":\"get\",\"params\":{\"name\":\"buffered-secret\"}}\n",
            );
            let (mut client, writer) = tokio::io::duplex(64 * 1024);
            let rejected = serve(
                ChunkedInput {
                    bytes: commands,
                    position: 0,
                },
                writer,
                vault.clone(),
                test_peer(),
                "signed",
                NoSecretAccess,
                NoSecretAccess,
                Arc::new(NoSecretAccess),
            )
            .await;
            let mut output = String::new();
            client.read_to_string(&mut output).await.unwrap();
            if frame_size <= MAX_LINE_BYTES {
                assert!(
                    matches!(rejected, Reject::Refused),
                    "legal {frame_size}-byte frame was refused"
                );
                kv_platform::protection::read_probe_response(output.as_bytes())
                    .await
                    .unwrap();
                assert_eq!(output.lines().count(), 1);
            } else {
                assert!(matches!(rejected, Reject::ProtocolError(_)));
                assert!(output.is_empty());
            }
            assert!(!output.contains("buffered-secret"));
            assert!(!vault.dir.join("audit.log").exists());
            assert!(!vault.dir.join("vault.enc").exists());
        }
    }

    #[tokio::test]
    async fn fragmented_protection_probes_report_uninitialized_legacy_and_corrupted_vaults_without_keys(
    ) {
        let request = format!(
            "{}\n",
            serde_json::to_string(&ProtectionProbe::Status {
                protocol: PROTOCOL_VERSION,
                lang: Some("en".into()),
            })
            .unwrap()
        );
        for state in ["uninitialized", "legacy", "corrupted"] {
            let tmp = tempfile::tempdir().unwrap();
            let vault = Arc::new(Vault::new(tmp.path().join("vault")));
            vault.prepare().unwrap();
            let fixture = match state {
                "legacy" => Some(("master.key", vec![5u8; 32])),
                "corrupted" => Some(("vault.enc", b"corrupted-test-fixture".to_vec())),
                _ => None,
            };
            if let Some((file, contents)) = &fixture {
                let path = vault.dir.join(file);
                std::fs::write(&path, contents).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
                }
            }
            let (rejected, output) = public_probe(vault.clone(), request.as_bytes(), 3).await;
            assert!(matches!(rejected, Reject::Refused));
            assert_eq!(output.lines().count(), 1, "{output}");
            if state == "corrupted" {
                assert!(matches!(
                    serde_json::from_str::<Response>(&output).unwrap(),
                    Response::Err { id: 0, .. }
                ));
            } else {
                let response = kv_platform::protection::read_probe_response(output.as_bytes())
                    .await
                    .unwrap();
                assert_eq!(
                    response["provider"],
                    if state == "legacy" {
                        "migration_required"
                    } else {
                        "uninitialized"
                    }
                );
                assert_eq!(
                    response["key_protection"]["hardware"],
                    if state == "legacy" {
                        "software"
                    } else {
                        "not_configured"
                    }
                );
            }
            assert!(!output.contains("key_blob") && !output.contains("peer_public_key"));
            assert!(!output.contains("corrupted-test-fixture"));
            assert!(!vault.dir.join("audit.log").exists());
            if let Some((file, contents)) = fixture {
                assert_eq!(std::fs::read(vault.dir.join(file)).unwrap(), contents);
            }
            if state != "legacy" {
                assert!(!vault.dir.join("master.key").exists());
            }
        }
    }

    #[tokio::test]
    async fn protection_probes_report_malformed_vault_metadata_without_keys_or_writes() {
        let tmp = tempfile::tempdir().unwrap();
        let initialized = enclave_vault(&tmp);
        let path = initialized.dir.clone();
        drop(initialized);
        let vault = Arc::new(Vault::new(&path));
        let original: Value =
            serde_json::from_slice(&std::fs::read(path.join("vault.enc")).unwrap()).unwrap();
        let audit = std::fs::read(path.join("audit.log")).ok();
        let request = format!(
            "{}\n",
            serde_json::to_string(&ProtectionProbe::Status {
                protocol: PROTOCOL_VERSION,
                lang: Some("en".into()),
            })
            .unwrap()
        );
        for (pointer, invalid) in [
            ("/v", json!(2)),
            ("/iv", json!("not base64!")),
            ("/master_key/recovery/version", json!(2)),
            ("/master_key/recovery/ciphertext", json!("not base64!")),
            ("/master_key/device_binding/version", json!(2)),
            ("/master_key/device_binding/digest", json!("not base64!")),
        ] {
            let mut file = original.clone();
            *file.pointer_mut(pointer).unwrap() = invalid;
            let damaged = serde_json::to_vec(&file).unwrap();
            std::fs::write(path.join("vault.enc"), &damaged).unwrap();
            let (rejected, output) = public_probe(vault.clone(), request.as_bytes(), 3).await;
            assert!(matches!(rejected, Reject::Refused));
            assert_eq!(output.lines().count(), 1, "{pointer}: {output}");
            assert!(matches!(
                serde_json::from_str::<Response>(&output).unwrap(),
                Response::Err { id: 0, .. }
            ));
            assert!(!output.contains("vault_protection"), "{pointer}: {output}");
            assert!(!output.contains("key_blob"), "{pointer}: {output}");
            assert_eq!(std::fs::read(path.join("vault.enc")).unwrap(), damaged);
            assert_eq!(std::fs::read(path.join("audit.log")).ok(), audit);
            assert!(!path.join("master.key").exists());
        }
    }

    #[tokio::test]
    async fn protection_probes_cannot_unlock_or_run_buffered_credential_commands() {
        for protocol in [PROTOCOL_VERSION, PROTOCOL_VERSION + 1] {
            let tmp = tempfile::tempdir().unwrap();
            let initialized = enclave_vault(&tmp);
            initialized
                .set(kv_vault::SetParams {
                    r#type: "api_key".into(),
                    name: "private-name".into(),
                    value: Some("test-only-secret".into()),
                    ..Default::default()
                })
                .unwrap();
            let path = initialized.dir.clone();
            drop(initialized);
            let vault = Arc::new(Vault::new(&path));
            let file_before = std::fs::read(path.join("vault.enc")).unwrap();
            let audit_before = std::fs::read(path.join("audit.log")).ok();
            let (mut client, server) = tokio::io::duplex(64 * 1024);
            let (sr, sw) = tokio::io::split(server);
            let session = tokio::spawn(serve(
                sr,
                sw,
                vault.clone(),
                test_peer(),
                "signed",
                NoSecretAccess,
                NoSecretAccess,
                Arc::new(NoSecretAccess),
            ));
            let probe = ProtectionProbe::Status {
                protocol,
                lang: Some("en".into()),
            };
            // The second frame is already buffered when the helper handles the probe.
            let commands = format!(
                "{}\n{}\n",
                serde_json::to_string(&probe).unwrap(),
                json!({"id": 1, "op": "get", "params": {
                    "type": "api_key", "name": "private-name", "purpose": "test bypass"
                }}),
            );
            client.write_all(commands.as_bytes()).await.unwrap();
            let mut output = String::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                client.read_to_string(&mut output),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(matches!(session.await.unwrap(), Reject::Refused));
            assert_eq!(output.lines().count(), 1);
            let reply: Response = serde_json::from_str(&output).unwrap();
            if protocol == PROTOCOL_VERSION {
                let Response::Ok { id, result, .. } = reply else {
                    panic!("{output}");
                };
                assert_eq!(id, 0);
                assert_eq!(result["protocol"], PROTOCOL_VERSION);
                assert_eq!(result["vault_protection"]["provider"], "secure_enclave");
                assert_eq!(
                    result["vault_protection"]["key_protection"]["hardware"],
                    "hardware_backed"
                );
            } else {
                assert!(matches!(reply, Response::Err { id: 0, .. }));
            }
            for forbidden in [
                "ready",
                "key_blob",
                "peer_public_key",
                "private-name",
                "test-only-secret",
            ] {
                assert!(!output.contains(forbidden), "{output}");
            }
            assert!(vault.get("api_key", "private-name").is_err());
            assert_eq!(std::fs::read(path.join("vault.enc")).unwrap(), file_before);
            assert_eq!(std::fs::read(path.join("audit.log")).ok(), audit_before);
        }
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
            test_peer(),
            "signed",
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
            test_peer(),
            "signed",
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
        let session = tokio::spawn(serve(
            sr,
            sw,
            vault.clone(),
            test_peer(),
            "signed",
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
        let session = tokio::spawn(serve(
            sr,
            sw,
            vault.clone(),
            test_peer(),
            "signed",
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
