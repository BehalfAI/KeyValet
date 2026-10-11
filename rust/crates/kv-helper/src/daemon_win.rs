//! Windows helper service: `kv-helper --service` runs through the SCM dispatcher as the
//! `KeyValetHelper` service (LocalSystem); `kv-helper --console` runs the same accept loops in
//! the foreground for debugging. Sessions arrive on HELPER_PIPE (one connection = one session,
//! exactly like the macOS daemon's Unix socket); the per-user agent connects to AGENT_PIPE and
//! is accepted only after its process SID matches the owner, its executable path is the
//! installed `kv-agent.exe`, and its Authenticode signature verifies — or the ACL-trusted
//! `allow-unsigned-agent` marker exists.
//!
//! Acceptance table (mirrors the macOS daemon's uid checks):
//!   HELPER_PIPE: peer.sid == owner      -> credential session (serve)
//!                peer.elevated          -> control query handler ({"sessions": N})
//!                anything else          -> drop + audit `peer-rejected`
//!   AGENT_PIPE:  sid==owner && exe==AGENT_BIN && signature ok         -> register ("signed")
//!                sid==owner && exe==AGENT_BIN && allow-unsigned marker -> register ("unsigned")
//!                anything else          -> drop + audit `agent-rejected`

use crate::{fatal, serve, MAX_CLIENTS};
use kv_platform::agent::{
    read_hello, AgentAuthenticator, AgentConfirmer, AgentHub, AgentKey, AgentMasterKeyProvider,
};
use kv_platform::paths::{
    AGENT_BIN, AGENT_PIPE, AGENT_PUBLISHER, ALLOW_UNSIGNED_AGENT, HELPER_PIPE, MCP_PIPE,
    OWNER_SID_FILE, SERVICE_NAME, VAULT_DIR,
};
use kv_platform::peer::{accept_client, sid_equal, sid_to_string};
use kv_platform::trust::{
    allow_unsigned_agent, load_owner_sid, same_file_path, trusted_path, untrusted_reason,
    verify_publisher, verify_root_environment,
};
use kv_vault::Vault;
use serde_json::{json, Map};
use std::os::windows::io::{AsRawHandle, BorrowedHandle, OwnedHandle};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinSet;

/// The hub key for this install's single interactive user.
fn owner_key(owner_sid: &[u8]) -> AgentKey {
    sid_to_string(owner_sid).unwrap_or_default()
}

/// `DisconnectNamedPipe` on the server handle ends the client connection cleanly, letting the
/// session write its session-end audit entry while it unwinds — the named-pipe analogue of the
/// macOS daemon's fd-shutdown registry.
fn disconnect(raw: usize) {
    use windows::Win32::System::Pipes::DisconnectNamedPipe;
    unsafe {
        let _ = DisconnectNamedPipe(windows::Win32::Foundation::HANDLE(raw as _));
    }
}

/// Accept-and-dispatch for one pipe. `is_agent` selects the AGENT_PIPE table; clients use the
/// session table. Peer checks happen before any byte is served.
async fn accept_loop(
    pipe_name: &'static str,
    owner_sid: Arc<Vec<u8>>,
    hub: Arc<AgentHub>,
    sessions: Arc<AtomicUsize>,
    permits: Arc<tokio::sync::Semaphore>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    if *stop.borrow() {
        return;
    }
    let factory = match kv_platform::pipe::server_options(pipe_name, &owner_sid) {
        Ok(f) => f,
        Err(e) => fatal(&format!("cannot create {pipe_name}: {e}")),
    };
    let session_handles: Arc<AsyncMutex<std::collections::HashMap<u64, OwnedHandle>>> =
        Arc::new(AsyncMutex::new(std::collections::HashMap::new()));
    let session_counter = Arc::new(AtomicUsize::new(0));
    let audit_reject = |op: &str, reason: String| {
        let vault = Vault::new(VAULT_DIR);
        let mut entry = Map::new();
        entry.insert("op".into(), json!(op));
        entry.insert("reason".into(), json!(reason));
        let _ = vault.audit(entry);
    };

    let mut join_set: JoinSet<()> = JoinSet::new();
    let mut agent_process: Option<kv_platform::agent_process::ProtectedProcess> = None;
    let mut agent_session = None;
    let mut agent_registered = false;
    let mut restart_tick = tokio::time::interval(std::time::Duration::from_secs(10));
    restart_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    if pipe_name == AGENT_PIPE
        && trusted_path(Path::new(AGENT_BIN))
        && (verify_publisher(Path::new(AGENT_BIN), AGENT_PUBLISHER).is_ok()
            || allow_unsigned_agent(Path::new(ALLOW_UNSIGNED_AGENT)))
    {
        let session =
            unsafe { windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId() };
        agent_process =
            kv_platform::agent_process::ProtectedProcess::launch(session, &owner_sid).ok();
        if agent_process.is_some() {
            agent_session = Some(session);
        }
    }
    // Always keep a listening instance alive, including while dispatching or reaping a client.
    // Otherwise the name becomes available for squatting after the last session disconnects.
    let mut pipe = factory
        .create(true)
        .unwrap_or_else(|e| fatal(&format!("cannot bind {pipe_name}: {e}")));
    loop {
        tokio::select! {
            conn = pipe.connect() => {
                if conn.is_err() {
                    let _ = pipe.disconnect();
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
                let next = factory.create(false).unwrap_or_else(|e| fatal(&format!("cannot rebind {pipe_name}: {e}")));
                let mut pipe = std::mem::replace(&mut pipe, next);
                let identity = accept_client(&pipe).await.ok();
                if pipe_name == MCP_PIPE {
                    if let Some(p) = identity.filter(|p| sid_equal(&p.sid, &owner_sid)) {
                        let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                        let owner_sid = owner_sid.clone();
                        let stop = stop.clone();
                        join_set.spawn(async move {
                            let _permit = permit;
                            if let Err(e) = crate::mcp_win::serve_launcher(pipe, owner_sid, p.session_id, stop).await {
                                eprintln!("keyvalet-helper: MCP worker: {e}");
                            }
                        });
                    } else {
                        audit_reject("peer-rejected", "MCP launcher is not the owner".into());
                    }
                } else if pipe_name == HELPER_PIPE {
                    match identity {
                        // Elevated processes (an admin's kv-cli) may ask the same control
                        // questions root asks over the macOS socket.
                        Some(p) if p.elevated => {
                            let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                            let sessions = sessions.clone();
                            let hub = hub.clone();
                            let key = owner_key(&owner_sid);
                            // UAC may use a different administrator account for a standard
                            // install owner. The trusted elevated CLI can manage the vault, but
                            // Hello always goes to the recorded owner's interactive agent.
                            let trusted_cli = same_file_path(&p.exe_path, Path::new(kv_platform::paths::CLI_BIN))
                                && trusted_path(&p.exe_path);
                            join_set.spawn(async move {
                                let _permit = permit;
                                control_windows(pipe, sessions, hub, key, trusted_cli).await;
                            });
                        }
                        Some(p) if sid_equal(&p.sid, &owner_sid) => {
                            let Ok(permit) = permits.clone().try_acquire_owned() else {
                                continue; // drop the pipe: too many sessions
                            };
                            let vault = Arc::new(Vault::new(VAULT_DIR));
                            if vault.prepare().is_err() {
                                continue;
                            }
                            let hub = hub.clone();
                            let sessions = sessions.clone();
                            let handles = session_handles.clone();
                            let counter = session_counter.clone();
                            let owner_key = owner_key(&owner_sid);
                            let key = owner_key.clone();
                            let Ok(handle) = (unsafe { BorrowedHandle::borrow_raw(pipe.as_raw_handle()) }).try_clone_to_owned() else { continue; };
                            join_set.spawn(async move {
                                let _permit = permit;
                                sessions.fetch_add(1, Ordering::SeqCst);
                                let sid_n = counter.fetch_add(1, Ordering::SeqCst) as u64;
                                handles.lock().await.insert(sid_n, handle);
                                let (reader, writer) = tokio::io::split(pipe);
                                let provider = Arc::new(AgentMasterKeyProvider {
                                    hub: hub.clone(),
                                    key: key.clone(),
                                });
                                match serve(
                                    reader,
                                    writer,
                                    vault,
                                    Some(p.sid.clone()),
                                    hub.agent_trust(),
                                    AgentAuthenticator { hub: hub.clone(), key: key.clone() },
                                    AgentConfirmer { hub, key },
                                    provider,
                                )
                                .await
                                {
                                    crate::Reject::ProtocolError(e) => {
                                        eprintln!("keyvalet-helper: session protocol error: {e}")
                                    }
                                    crate::Reject::Refused => {}
                                }
                                handles.lock().await.remove(&sid_n);
                                sessions.fetch_sub(1, Ordering::SeqCst);
                            });
                        }
                        Some(_) => {
                            audit_reject("peer-rejected", "not-the-owner".to_string());
                        }
                        None => {
                            audit_reject("peer-rejected", "peer-identify-failed".to_string());
                        }
                    }
                } else {
                    // AGENT_PIPE
                    let mut unsigned = false;
                    let reason = match &identity {
                        None => Some("peer-identify-failed".to_string()),
                        Some(p) if !sid_equal(&p.sid, &owner_sid) => {
                            Some("not-allowed-user".to_string())
                        }
                        Some(p) if !same_file_path(&p.exe_path, Path::new(AGENT_BIN))
                            || !trusted_path(&p.exe_path) => {
                            Some(format!("bad-exe:{}", p.exe_path.display()))
                        }
                        Some(p) => {
                            match verify_publisher(&p.exe_path, AGENT_PUBLISHER) {
                                Ok(()) => None,
                                Err(e) => {
                                    if allow_unsigned_agent(Path::new(ALLOW_UNSIGNED_AGENT)) {
                                        unsigned = true;
                                        audit_reject(
                                            "agent-accepted-unsigned",
                                            format!("unsigned accepted: {e}"),
                                        );
                                        None
                                    } else {
                                        Some(format!("untrusted-agent:{e}"))
                                    }
                                }
                            }
                        }
                    };
                    if let Some(reason) = reason {
                        audit_reject("agent-rejected", reason.clone());
                        let (_, mut writer) = tokio::io::split(pipe);
                        let line = kv_ipc::agent::encode_line(&kv_ipc::agent::hello_reply(
                            false,
                            Some(&reason),
                        ));
                        let _ = writer.write_all(&line).await;
                        let _ = writer.shutdown().await;
                        continue;
                    }
                    let hello = read_hello(&mut pipe).await.unwrap_or(serde_json::Value::Null);
                    if hello["op"] == "agent-launch" && hello["protocol"] == kv_ipc::agent::AGENT_PROTOCOL {
                        if !agent_process.as_ref().is_some_and(|p| p.running())
                            || (agent_registered && !hub.has_live_agent(&owner_key(&owner_sid)))
                        {
                            let session = identity.as_ref().unwrap().session_id;
                            // A broker timeout retires the connection even if its process is
                            // still alive. Stop that worker before creating a replacement.
                            drop(agent_process.take());
                            agent_registered = false;
                            match kv_platform::agent_process::ProtectedProcess::launch(session, &owner_sid) {
                                Ok(process) => {
                                    agent_process = Some(process);
                                    agent_session = Some(session);
                                }
                                Err(e) => {
                                    audit_reject("agent-launch-failed", e.to_string());
                                    let _ = pipe.write_all(&kv_ipc::agent::encode_line(&kv_ipc::agent::hello_reply(false, Some("agent-launch-failed")))).await;
                                    continue;
                                }
                            }
                        }
                        let _ = pipe.write_all(&kv_ipc::agent::encode_line(&kv_ipc::agent::hello_reply(true, None))).await;
                        continue;
                    }
                    let owned = identity.as_ref().is_some_and(|p| agent_process.as_ref().is_some_and(|owned| owned.matches(p.pid)));
                    if !owned || !kv_ipc::agent::is_valid_hello(&hello) {
                        let reason = if owned { "bad-hello" } else { "agent-not-service-child" };
                        audit_reject("agent-rejected", reason.into());
                        let _ = pipe.write_all(&kv_ipc::agent::encode_line(&kv_ipc::agent::hello_reply(false, Some(reason)))).await;
                        continue;
                    }
                    if pipe.write_all(&kv_ipc::agent::encode_line(&kv_ipc::agent::hello_reply(true, None))).await.is_ok() {
                        hub.register(owner_key(&owner_sid), pipe, if unsigned { "unsigned" } else { "signed" });
                        agent_registered = true;
                    }
                }
            }
            done = join_set.join_next(), if !join_set.is_empty() => {
                let _ = done;
            }
            _ = restart_tick.tick(), if pipe_name == AGENT_PIPE => {
                if let Some(session) = agent_session {
                    let restart = !agent_process.as_ref().is_some_and(|p| p.running())
                        || (agent_registered && !hub.has_live_agent(&owner_key(&owner_sid)));
                    if restart
                        && trusted_path(Path::new(AGENT_BIN))
                        && (verify_publisher(Path::new(AGENT_BIN), AGENT_PUBLISHER).is_ok()
                            || allow_unsigned_agent(Path::new(ALLOW_UNSIGNED_AGENT)))
                    {
                        drop(agent_process.take());
                        agent_registered = false;
                        agent_process = kv_platform::agent_process::ProtectedProcess::launch(session, &owner_sid).ok();
                    }
                }
            }
            _ = stop.changed() => {
                if *stop.borrow() {
                    for (_, handle) in session_handles.lock().await.drain() {
                        disconnect(handle.as_raw_handle() as usize);
                    }
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        async { while join_set.join_next().await.is_some() {} },
                    )
                    .await;
                    join_set.abort_all();
                    return;
                }
            }
        }
    }
}

/// Management is privileged; key work additionally requires the trusted installed CLI.
/// It goes through the same interactive agent as ordinary sessions, never through session 0.
async fn control_windows(
    mut pipe: tokio::net::windows::named_pipe::NamedPipeServer,
    sessions: Arc<AtomicUsize>,
    hub: Arc<AgentHub>,
    key: AgentKey,
    trusted_cli: bool,
) {
    use tokio::io::AsyncReadExt;
    let request = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut line = Vec::new();
        loop {
            let byte = pipe.read_u8().await?;
            if byte == b'\n' {
                break;
            }
            if line.len() >= kv_ipc::agent::MAX_LINE_BYTES {
                return Err(std::io::Error::other("control request too large"));
            }
            line.push(byte);
        }
        serde_json::from_slice::<serde_json::Value>(&line).map_err(std::io::Error::from)
    })
    .await;
    let Ok(Ok(request)) = request else {
        return;
    };
    if request["op"] != "control" {
        return;
    }
    let (reply, payload) = match request["command"].as_str() {
        Some("sessions") => (json!({"sessions": sessions.load(Ordering::SeqCst)}), None),
        Some("agent") if trusted_cli => {
            let work = request["request"].clone();
            if work["op"] != "enclave" {
                return;
            }
            match hub
                .request(&key, work, kv_platform::agent::REQUEST_TIMEOUT)
                .await
            {
                Ok(reply) => reply,
                Err(error) => (json!({"ok":false,"error":error}), None),
            }
        }
        _ => (json!({"ok":false,"error":"control operation denied"}), None),
    };
    if pipe
        .write_all(&kv_ipc::agent::encode_line(&reply))
        .await
        .is_ok()
    {
        if let Some((buffer, len)) = payload {
            let _ = pipe.write_all(&buffer[..len]).await;
        }
    }
    let _ = pipe.shutdown().await;
}

/// The shared runtime: both service and console mode end up here.
async fn run_daemon(stop_tx: tokio::sync::watch::Sender<bool>) {
    let self_path = std::env::current_exe().unwrap_or_default();
    if let Err(e) = verify_root_environment(
        &self_path,
        std::path::Path::new(kv_platform::paths::HELPER_BIN),
        &[],
    ) {
        fatal(&e);
    }
    if let Err(e) = kv_platform::fs::ensure_private_dir(std::path::Path::new(VAULT_DIR)) {
        fatal(&format!("vault directory {VAULT_DIR}: {e}"));
    }
    let owner_sid = match load_owner_sid(Path::new(OWNER_SID_FILE)) {
        Ok(s) => Arc::new(s),
        Err(e) => fatal(&format!("cannot load the owner identity: {e}")),
    };
    if let Some(reason) = untrusted_reason(Path::new(OWNER_SID_FILE)) {
        fatal(&format!("owner.sid is not trusted: {reason}"));
    }
    if let Err(e) = kv_platform::agent_process::expose_service_identity(&owner_sid) {
        fatal(&format!(
            "cannot expose authenticated service identity: {e}"
        ));
    }

    let hub = AgentHub::new();
    let sessions = Arc::new(AtomicUsize::new(0));
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CLIENTS));
    // Re-broadcast the single sender so both accept loops can watch it.
    let stop_rx = stop_tx.subscribe();

    let clients = accept_loop(
        HELPER_PIPE,
        owner_sid.clone(),
        hub.clone(),
        sessions,
        permits,
        stop_rx.clone(),
    );
    let agents = accept_loop(
        AGENT_PIPE,
        owner_sid.clone(),
        hub.clone(),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(tokio::sync::Semaphore::new(4)),
        stop_rx.clone(),
    );
    let mcp = accept_loop(
        MCP_PIPE,
        owner_sid,
        hub,
        Arc::new(AtomicUsize::new(0)),
        Arc::new(tokio::sync::Semaphore::new(MAX_CLIENTS)),
        stop_rx,
    );
    tokio::join!(clients, agents, mcp);
}

/// `kv-helper --console`: same loops, foreground, Ctrl-C to stop.
#[tokio::main]
pub async fn run_console() {
    let (stop_tx, _) = tokio::sync::watch::channel(false);
    let ctrl = stop_tx.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = ctrl.send(true);
    });
    run_daemon(stop_tx).await;
}

#[allow(non_snake_case)]
mod service {
    use super::*;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    define_windows_service!(ffi_service_main, service_main);

    /// `kv-helper --service`: hand control to the SCM dispatcher.
    pub fn run() {
        if let Err(e) = service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
            fatal(&format!("cannot start the service dispatcher: {e}"));
        }
    }

    fn service_main(_args: Vec<std::ffi::OsString>) {
        let (ctrl_tx, mut ctrl_rx) = tokio::sync::mpsc::unbounded_channel::<ServiceControl>();
        let status_handle = match service_control_handler::register(SERVICE_NAME, move |ctrl| {
            let _ = ctrl_tx.send(ctrl);
            match ctrl {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        }) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("keyvalet-helper: cannot register the service control handler: {e}");
                return;
            }
        };
        let status_handle = std::sync::Arc::new(status_handle);
        let set_state = {
            let status_handle = status_handle.clone();
            move |state: ServiceState, accepted| {
                let _ = status_handle.set_service_status(ServiceStatus {
                    service_type: ServiceType::OWN_PROCESS,
                    current_state: state,
                    controls_accepted: accepted,
                    exit_code: ServiceExitCode::Win32(0),
                    checkpoint: 0,
                    wait_hint: std::time::Duration::from_secs(10),
                    process_id: None,
                });
            }
        };
        set_state(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        );

        let (stop_tx, _stop_rx) = tokio::sync::watch::channel(false);
        // run_daemon is async; drive it on a runtime built for the service thread.
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("keyvalet-helper: cannot start the tokio runtime: {e}");
                set_state(ServiceState::Stopped, ServiceControlAccept::empty());
                return;
            }
        };
        let set_state_after = set_state.clone();
        rt.block_on(async move {
            let ctrl_stop = stop_tx.clone();
            let stop_pending = set_state.clone();
            tokio::spawn(async move {
                while let Some(ctrl) = ctrl_rx.recv().await {
                    if matches!(ctrl, ServiceControl::Stop | ServiceControl::Shutdown) {
                        stop_pending(ServiceState::StopPending, ServiceControlAccept::empty());
                        let _ = ctrl_stop.send(true);
                        return;
                    }
                }
            });
            run_daemon(stop_tx).await;
        });
        // Dropped/expired WinTrust or process-creation jobs may still be finishing OS calls.
        // Keep SCM shutdown bounded; they cannot register a worker after the stop broadcast.
        rt.shutdown_timeout(std::time::Duration::from_secs(5));
        set_state_after(ServiceState::Stopped, ServiceControlAccept::empty());
    }
}

pub use service::run as run_service;
