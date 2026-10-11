//! `kv-helper --daemon --uid <uid>`: the launchd daemon. Serves credential sessions to the one
//! local user it was installed for, and accepts the per-user agent's connection after code
//! verification. Holds no vault key while idle.

use crate::{control, fatal, serve, MAX_CLIENTS};
use kv_platform::agent::{
    accept_agent, AgentAuthenticator, AgentConfirmer, AgentHub, AgentMasterKeyProvider,
};
use kv_platform::paths::{AGENT_SOCKET, HELPER_BIN, HELPER_SOCKET, RUN_DIR, VAULT_DIR};
use kv_platform::trust::verify_root_environment;
use kv_vault::Vault;
use serde_json::{json, Map};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinSet;

fn prepare_run_dir() {
    let dir = std::path::Path::new(RUN_DIR);
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                fatal(&format!("{RUN_DIR} exists and is not a real directory"));
            }
            if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                fatal(&format!(
                    "{RUN_DIR} must be root-owned and not group/other-writable"
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Err(e) = std::fs::create_dir(dir) {
                fatal(&format!("cannot create {RUN_DIR}: {e}"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
            }
        }
        Err(e) => fatal(&format!("cannot stat {RUN_DIR}: {e}")),
    }
}

/// Removes a stale socket file only if it really is a socket; anything else is left alone
/// (and the subsequent bind fails, which is the right outcome).
fn remove_stale_socket(path: &str) {
    let p = std::path::Path::new(path);
    if let Ok(meta) = std::fs::symlink_metadata(p) {
        if meta.file_type().is_socket() {
            let _ = std::fs::remove_file(p);
        } else {
            fatal(&format!(
                "{path} exists and is not a socket; refusing to remove it"
            ));
        }
    }
}

/// Duplicates a connected stream (for the writer half and the shutdown registry): `dup` shares
/// the file status flags, so the new fd inherits the listener's O_NONBLOCK as required by
/// `UnixStream::from_std`.
fn dup_stream(stream: &UnixStream) -> std::io::Result<UnixStream> {
    use std::os::unix::io::FromRawFd;
    let fd = unsafe { libc::dup(stream.as_raw_fd()) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    UnixStream::from_std(std_stream)
}

fn bind(path: &str) -> UnixListener {
    remove_stale_socket(path);
    let listener = match UnixListener::bind(path) {
        Ok(l) => l,
        Err(e) => fatal(&format!("cannot bind {path}: {e}")),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Authorization is enforced by peer uid/code checks, not the mode bits.
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666));
    }
    listener
}

#[tokio::main]
pub async fn run(uid: u32) {
    if unsafe { libc::getuid() } != 0 {
        fatal("--daemon must run as root (launchd system domain)");
    }
    let self_path = std::env::current_exe().unwrap_or_default();
    if let Err(e) = verify_root_environment(&self_path, std::path::Path::new(HELPER_BIN), &[]) {
        fatal(&e);
    }
    prepare_run_dir();
    let client_listener = bind(HELPER_SOCKET);
    let agent_listener = bind(AGENT_SOCKET);
    let hub = AgentHub::new();
    let sessions = Arc::new(AtomicUsize::new(0));
    // Session streams keyed by a counter so each finished session removes its own dup'd fd.
    let session_streams: Arc<AsyncMutex<std::collections::HashMap<u64, UnixStream>>> =
        Arc::new(AsyncMutex::new(std::collections::HashMap::new()));
    let session_counter = Arc::new(AtomicUsize::new(0));
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CLIENTS));

    // One `agent-rejected` entry per reason per 60 s (with the suppressed count folded into the
    // next entry) so a same-user process can't flood the audit log by re-connecting.
    let reject_times = Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
        String,
        (std::time::Instant, u32),
    >::new()));
    let audit_reject = {
        let reject_times = reject_times.clone();
        move |reason: String| {
            let mut times = reject_times.lock().unwrap();
            use std::collections::hash_map::Entry;
            let suppressed = match times.entry(reason.clone()) {
                Entry::Occupied(mut e) => {
                    let (since, suppressed) = e.get_mut();
                    if since.elapsed() < std::time::Duration::from_secs(60) {
                        *suppressed += 1;
                        return;
                    }
                    let n = *suppressed;
                    *since = std::time::Instant::now();
                    *suppressed = 0;
                    n
                }
                Entry::Vacant(e) => {
                    e.insert((std::time::Instant::now(), 0));
                    0
                }
            };
            drop(times);
            let vault = Vault::new(VAULT_DIR);
            let mut entry = Map::new();
            entry.insert("op".into(), json!("agent-rejected"));
            entry.insert("reason".into(), json!(reason));
            if suppressed > 0 {
                entry.insert("suppressed".into(), json!(suppressed));
            }
            let _ = vault.audit(entry);
        }
    };

    // Agent accept loop.
    {
        let hub = hub.clone();
        tokio::spawn(async move {
            loop {
                match agent_listener.accept().await {
                    Ok((stream, _)) => {
                        if let Some(stream) =
                            accept_agent(stream, uid, |r| audit_reject(r.to_string())).await
                        {
                            hub.register(uid, stream, "signed");
                        }
                    }
                    Err(_) => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
                }
            }
        });
    }

    // SIGTERM: stop accepting, close session streams (each session writes its session-end audit
    // as it unwinds), then exit.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    {
        use tokio::signal::unix::{signal, SignalKind};
        let shutdown_tx = shutdown_tx.clone();
        let session_streams = session_streams.clone();
        tokio::spawn(async move {
            if let Ok(mut sig) = signal(SignalKind::terminate()) {
                sig.recv().await;
                let _ = shutdown_tx.send(true);
                for (_, mut s) in session_streams.lock().await.drain() {
                    let _ = s.shutdown().await;
                }
                // Don't leave sockets that look live behind.
                let _ = std::fs::remove_file(HELPER_SOCKET);
                let _ = std::fs::remove_file(AGENT_SOCKET);
            }
        });
    }

    let mut join_set: JoinSet<()> = JoinSet::new();
    let mut shutdown_rx = shutdown_rx.clone();
    loop {
        tokio::select! {
            accept = client_listener.accept() => {
                let Ok((stream, _)) = accept else { continue };
                let peer = kv_platform::peer::peer_uid(stream.as_raw_fd());
                match peer {
                    Ok(0) => {
                        let sessions = sessions.clone();
                        join_set.spawn(control(stream, sessions));
                    }
                    Ok(u) if u == uid => {
                        let Ok(permit) = permits.clone().try_acquire_owned() else {
                            // Tell the client why instead of a silent close.
                            let msg = kv_ipc::ReadyMessage::NotReady {
                                ready: kv_ipc::False,
                                protocol: kv_ipc::PROTOCOL_VERSION,
                                error: kv_i18n::t(
                                    "已打开的 KeyValet 会话过多（32 个），请关闭一些 AI 会话",
                                    "Too many KeyValet sessions are open (32); close some AI sessions",
                                ),
                            };
                            let mut line = serde_json::to_vec(&msg).unwrap();
                            line.push(b'\n');
                            let mut stream = stream;
                            let _ = stream.write_all(&line).await;
                            let _ = stream.shutdown().await;
                            continue;
                        };
                        let vault = Arc::new(Vault::new(VAULT_DIR));
                        if let Err(e) = vault.prepare() {
                            eprintln!("keyvalet-helper: vault init failed: {}", e.0);
                            let mut stream = stream;
                            let _ = stream.shutdown().await;
                            continue;
                        }
                        let hub = hub.clone();
                        let sessions = sessions.clone();
                        let session_streams = session_streams.clone();
                        let session_counter = session_counter.clone();
                        join_set.spawn(async move {
                            let _permit = permit;
                            sessions.fetch_add(1, Ordering::SeqCst);
                            let sid = session_counter
                                .fetch_add(1, Ordering::SeqCst)
                                as u64;
                            let registered = {
                                let mut list = session_streams.lock().await;
                                match dup_stream(&stream) {
                                    Ok(handle) => {
                                        list.insert(sid, handle);
                                        true
                                    }
                                    Err(_) => false,
                                }
                            };
                            if registered {
                                if let Ok(writer) = dup_stream(&stream) {
                                    let provider = Arc::new(AgentMasterKeyProvider {
                                        hub: hub.clone(),
                                        key: uid,
                                    });
                                    let _ = serve(
                                        stream,
                                        writer,
                                        vault,
                                        Some(uid),
                                        // macOS only ever registers a signature-verified agent.
                                        "signed",
                                        AgentAuthenticator { hub: hub.clone(), key: uid },
                                        AgentConfirmer { hub, key: uid },
                                        provider,
                                    )
                                    .await;
                                }
                                session_streams.lock().await.remove(&sid);
                            }
                            sessions.fetch_sub(1, Ordering::SeqCst);
                        });
                    }
                    _ => {
                        let mut stream = stream;
                        let _ = stream.shutdown().await;
                    }
                }
            }
            done = join_set.join_next(), if !join_set.is_empty() => {
                let _ = done;
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    // Give in-flight sessions a moment to write their session-end audit entry,
                    // then leave regardless.
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        async { while join_set.join_next().await.is_some() {} },
                    )
                    .await;
                    std::process::exit(0);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[tokio::test]
    async fn control_answers_the_sessions_count_and_closes() {
        let (daemon_side, mut client) = UnixStream::pair().unwrap();
        let sessions = Arc::new(AtomicUsize::new(3));
        let task = tokio::spawn(control(daemon_side, sessions));

        client
            .write_all(b"{\"op\":\"control\",\"command\":\"sessions\"}\n")
            .await
            .unwrap();
        let mut line = String::new();
        BufReader::new(&mut client)
            .read_line(&mut line)
            .await
            .unwrap();
        let reply: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(reply, json!({"sessions": 3}));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn control_rejects_anything_but_the_sessions_query() {
        let (daemon_side, mut client) = UnixStream::pair().unwrap();
        let task = tokio::spawn(control(daemon_side, Arc::new(AtomicUsize::new(0))));
        client
            .write_all(b"{\"op\":\"get\",\"type\":\"x\",\"name\":\"y\"}\n")
            .await
            .unwrap();
        // No reply; the connection just closes.
        let mut line = String::new();
        let n = BufReader::new(&mut client)
            .read_line(&mut line)
            .await
            .unwrap();
        assert_eq!(n, 0);
        task.await.unwrap();
    }
}
