//! Root helper entry point: started by the MCP server via `sudo -n` (sudoers only allows running
//! this program without a password). On startup it first reads the handshake message (purpose,
//! origin, session), and only provides service after passing Touch ID authentication.
//! It communicates with its parent only via stdin/stdout (the sudo child process pipe); it exits as
//! soon as stdin closes, so its lifetime is tied to the MCP session.
//! Direct port of src/helper/main.ts.
//!
//! Concurrency note: unlike the TS version's single-threaded interleaving of up to 8 in-flight
//! requests, this port fully serializes request handling behind the session's auth-state lock (see
//! `AUTH` below) for simplicity and correctness -- a single agent turn issues tool calls one at a
//! time in practice, so this is a deliberate simplification, not a perf regression users will hit.

use kv_core::dispatch::{ClientContext, SessionAuth, TouchIdSessionGate};
use kv_core::settings::{parse_mode, read_settings, remember_active, remember_until, stricter};
use kv_ipc::{clean_purpose, AuthMessage, ReadyMessage, Request, MAX_LINE_BYTES, PROTOCOL_VERSION};
use kv_platform::macos::{RootUserDialogConfirmer, TouchIdAuthenticator};
use kv_platform::paths::{HELPER_BIN, VAULT_DIR};
use kv_platform::trust::verify_root_environment;
use kv_vault::Vault;
use serde_json::{json, Map, Value};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex as AsyncMutex;

const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const MAX_IN_FLIGHT: usize = 8;

fn fatal(msg: &str) -> ! {
    eprintln!("keyvalet-helper: {msg}");
    std::process::exit(1);
}

type Gate = TouchIdSessionGate<TouchIdAuthenticator>;

fn clip(s: &str, n: usize) -> String {
    s.chars()
        .filter(|c| !matches!(c, '\u{0000}'..='\u{001f}' | '\u{007f}'))
        .take(n)
        .collect()
}

async fn send(out: &AsyncMutex<tokio::io::Stdout>, value: &Value) {
    let mut line = serde_json::to_vec(value).unwrap();
    line.push(b'\n');
    let _ = out.lock().await.write_all(&line).await;
}

/// Handles the handshake line: authenticates (Touch ID, unless a `remember` window is active), then
/// reports readiness. Exits the process directly on protocol errors or a rejected handshake, mirroring
/// the TS version's `fatal`/`reject`.
async fn authenticate(
    vault: &Vault,
    line: &str,
    ctx: &mut ClientContext,
    auth: &mut SessionAuth<Gate>,
    out: &AsyncMutex<tokio::io::Stdout>,
) {
    let msg: AuthMessage = match serde_json::from_str(line) {
        Ok(m) => m,
        Err(_) => fatal(&kv_i18n::t(
            "协议错误：握手消息不是合法 JSON",
            "Protocol error: handshake message is not valid JSON",
        )),
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

    let reject = |error: String, vault: &Vault, ctx: &ClientContext| -> ! {
        let mut entry = Map::new();
        entry.insert("op".into(), json!("unlock"));
        entry.insert("ok".into(), json!(false));
        entry.insert("error".into(), json!(error));
        if let Some(p) = &purpose {
            entry.insert("purpose".into(), json!(p));
        }
        entry.insert("session".into(), json!(ctx.session));
        entry.insert("client".into(), serde_json::to_value(ctx).unwrap());
        let _ = vault.audit(entry);
        // Blocking write here is fine: we're about to exit regardless, and `send` requires an
        // async context we'd rather not set up again just for this final message.
        let msg = ReadyMessage::NotReady {
            ready: kv_ipc::False,
            protocol: PROTOCOL_VERSION,
            error,
        };
        println!("{}", serde_json::to_string(&msg).unwrap());
        std::process::exit(0);
    };

    if msg.op != "auth" {
        fatal(&kv_i18n::t(
            "协议错误：第一条消息必须是 auth",
            "Protocol error: the first message must be auth",
        ));
    }
    let Some(purpose) = purpose.clone() else {
        reject(
            kv_i18n::t(
                "必须说明解锁目的（purpose）",
                "A purpose is required to unlock",
            ),
            vault,
            ctx,
        );
    };

    let settings = read_settings(std::path::Path::new(VAULT_DIR));
    auth.requested = msg.requested_mode.as_deref().and_then(parse_mode);
    let mode = stricter(settings.grant_mode, auth.requested);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as f64;
    let remembered =
        mode == kv_core::settings::GrantMode::Remember && remember_active(&settings, now);

    let hint = if !remembered
        && matches!(
            mode,
            kv_core::settings::GrantMode::PerCredential | kv_core::settings::GrantMode::PerUse
        ) {
        kv_core::resolve_hint(vault, msg.credential.as_ref())
    } else {
        None
    };

    if !remembered {
        let hours = if settings.remember_hours == 0.0 {
            kv_i18n::t("永久", "forever")
        } else {
            kv_i18n::t(
                &format!("{} 小时", settings.remember_hours),
                &format!("{} hours", settings.remember_hours),
            )
        };
        let scope = match mode {
            kv_core::settings::GrantMode::Remember => kv_i18n::t(
                &format!("解锁 KeyValet，并在{hours}内记住（期间所有 AI 会话无需再认证）"),
                &format!("Unlock KeyValet and remember it for {hours} (no authentication for any AI session meanwhile)"),
            ),
            kv_core::settings::GrantMode::PerSession => kv_i18n::t("解锁 KeyValet 凭证库（本会话可使用全部凭证）", "Unlock the KeyValet vault (this session can use all credentials)"),
            kv_core::settings::GrantMode::PerUse if hint.is_some() => kv_i18n::t(&format!("授权本次使用凭证（仅此一次）：{}", hint.as_deref().unwrap()), &format!("Authorize a single use of credential: {}", hint.as_deref().unwrap())),
            kv_core::settings::GrantMode::PerCredential if hint.is_some() => kv_i18n::t(&format!("授权本次 AI 会话使用凭证：{}", hint.as_deref().unwrap()), &format!("Authorize this AI session to use credential: {}", hint.as_deref().unwrap())),
            _ => kv_i18n::t(
                "打开 KeyValet 凭证库会话（仅可查看列表；使用具体凭证时需再次授权）",
                "Open a KeyValet vault session (list only; using a specific credential requires further authorization)",
            ),
        };
        let reason = kv_i18n::t(
            &format!(
                "{scope}\n目的：{purpose}\n来源目录（agent 提供）：{}",
                ctx.cwd
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .unwrap_or("未知")
            ),
            &format!(
                "{scope}\nPurpose: {purpose}\nWorking directory (reported by agent): {}",
                ctx.cwd
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .unwrap_or("unknown")
            ),
        );
        if let Err(error) = auth.authorize(&reason).await {
            reject(error, vault, ctx);
        }
        if mode == kv_core::settings::GrantMode::Remember {
            let mut next = settings.clone();
            next.remember_until = Some(remember_until(settings.remember_hours, now));
            let _ = kv_core::write_settings(std::path::Path::new(VAULT_DIR), &next);
        }
        auth.apply_mode(&settings);
        if let Some(h) = &hint {
            if mode == kv_core::settings::GrantMode::PerUse {
                // This handshake prompt only ever shows the credential name (`scope` above), never
                // a request_hint -- so it has no request content to bind a digest to. An HTTP-shaped
                // op that piggybacks on this grant still goes through its own `consume_grant` check
                // (kv-core/dispatch.rs) with a real digest, which a `None` here can never match: it
                // falls through to a fresh, properly request-bound Touch ID prompt instead of
                // silently trusting a "single use" approval that never named what the use was.
                auth.one_shot
                    .get_or_insert_with(Default::default)
                    .insert(h.clone(), None);
            } else {
                auth.grants.insert(h.clone());
            }
        }
        let mut entry = Map::new();
        entry.insert("op".into(), json!("unlock"));
        entry.insert("ok".into(), json!(true));
        entry.insert("purpose".into(), json!(purpose));
        entry.insert("grant_mode".into(), json!(mode.as_str()));
        if let Some(h) = &hint {
            entry.insert("granted".into(), json!(h));
        }
        entry.insert("session".into(), json!(ctx.session));
        entry.insert("client".into(), serde_json::to_value(&*ctx).unwrap());
        let _ = vault.audit(entry);
    } else {
        auth.apply_mode(&settings);
        let mut entry = Map::new();
        entry.insert("op".into(), json!("unlock"));
        entry.insert("ok".into(), json!(true));
        entry.insert("purpose".into(), json!(purpose));
        entry.insert("grant_mode".into(), json!(mode.as_str()));
        entry.insert("remembered".into(), json!(true));
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
}

#[tokio::main]
async fn main() {
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
    let self_path = std::env::current_exe().unwrap_or_default();
    if let Err(e) = verify_root_environment(&self_path, std::path::Path::new(HELPER_BIN), &[]) {
        fatal(&e);
    }

    let vault = Arc::new(Vault::new(VAULT_DIR));
    if let Err(e) = vault.init() {
        fatal(&kv_i18n::t(
            &format!("凭证库初始化失败：{}", e.0),
            &format!("Vault initialization failed: {}", e.0),
        ));
    }

    let ctx = Arc::new(AsyncMutex::new(ClientContext::default()));
    let deny_label = kv_i18n::t("拒绝", "Deny");
    let gate = Gate {
        vault_dir: vault.dir.clone(),
        authenticator: TouchIdAuthenticator,
        deny_label,
    };
    let auth = Arc::new(AsyncMutex::new(SessionAuth::new(gate)));
    let sudo_uid: Option<u32> = std::env::var("SUDO_UID").ok().and_then(|v| v.parse().ok());
    {
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
        let gateway = kv_proxy::gateway::Gateway::new(vault.clone(), gateway_audit, sudo_uid);
        auth.lock().await.gateway = Some(Arc::new(gateway));
    }

    let stdout = Arc::new(AsyncMutex::new(tokio::io::stdout()));

    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Handshake,
        Authenticating,
        Ready,
    }
    let state = Arc::new(AsyncMutex::new(State::Handshake));

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

    let mut stdin = tokio::io::stdin();
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    let in_flight = Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT));
    let handshake_deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;

    loop {
        let read = tokio::time::timeout_at(handshake_deadline, stdin.read(&mut chunk));
        let n = if *state.lock().await == State::Handshake {
            match read.await {
                Ok(Ok(n)) => n,
                Ok(Err(_)) => break,
                Err(_) => fatal(&kv_i18n::t(
                    "等待握手超时",
                    "Timed out waiting for handshake",
                )),
            }
        } else {
            match stdin.read(&mut chunk).await {
                Ok(n) => n,
                Err(_) => break,
            }
        };
        if n == 0 {
            break; // EOF: parent (MCP session) exited
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_LINE_BYTES {
            fatal(&kv_i18n::t("请求过大", "Request too large"));
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
                let vault = vault.clone();
                let ctx = ctx.clone();
                let auth = auth.clone();
                let stdout = stdout.clone();
                let state2 = state.clone();
                let mut ctx_guard = ctx.lock().await;
                let mut auth_guard = auth.lock().await;
                authenticate(&vault, &line, &mut ctx_guard, &mut auth_guard, &stdout).await;
                drop(ctx_guard);
                drop(auth_guard);
                *state2.lock().await = State::Ready;
                continue;
            }
            if *st != State::Ready {
                fatal(&kv_i18n::t(
                    "协议错误：认证完成前收到请求",
                    "Protocol error: request received before authentication completed",
                ));
            }
            drop(st);

            let req: Request = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(_) => fatal(&kv_i18n::t(
                    "协议错误：非法 JSON",
                    "Protocol error: invalid JSON",
                )),
            };

            // Bounds how many dispatches may be spawned (and so how much stdin-reading outpaces
            // processing): acquiring blocks the main loop itself once MAX_IN_FLIGHT are outstanding,
            // which in turn stops draining stdin -- backpressure through the pipe, not an in-memory
            // queue (the TS version's explicit 1000-item queue cap has no equivalent need here).
            let permit = in_flight.clone().acquire_owned().await.unwrap();
            let vault = vault.clone();
            let ctx = ctx.clone();
            let auth = auth.clone();
            let stdout = stdout.clone();
            tokio::spawn(async move {
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
                    &RootUserDialogConfirmer,
                )
                .await;
                drop(auth_guard);
                send(&stdout, &serde_json::to_value(&resp).unwrap()).await;
            });
        }
    }

    if *state.lock().await == State::Ready {
        let c = ctx.lock().await;
        let mut entry = Map::new();
        entry.insert("op".into(), json!("session-end"));
        entry.insert("session".into(), json!(c.session));
        entry.insert("client".into(), serde_json::to_value(&*c).unwrap());
        let _ = vault.audit(entry);
    }
}
