//! Linux resident helper. Never launched through per-session passwordless sudo.
use crate::{control, serve, MAX_CLIENTS};
use kv_platform::linux::{LinuxHost, LinuxMasterKeyProvider, Polkit};
use kv_platform::paths::{HELPER_BIN, HELPER_SOCKET, POLKIT_POLICY, RUN_DIR, VAULT_DIR};
use kv_platform::trust::untrusted_reason;
use kv_vault::Vault;
use std::future::Future;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct Count {
    sessions: Arc<AtomicUsize>,
    approval: Polkit,
}
impl Drop for Count {
    fn drop(&mut self) {
        self.approval.cancel();
        self.sessions.fetch_sub(1, Ordering::SeqCst);
    }
}

fn verify_run_dir(path: &Path, uid: u32) -> io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != uid
        || meta.mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "systemd must create /run/keyvalet with owner keyvalet and mode 0755",
        ));
    }
    Ok(())
}

fn lock_runtime(directory: &Path) -> io::Result<std::fs::File> {
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("daemon.lock"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(lock)
}

fn bind_socket(path: &Path, uid: u32) -> io::Result<tokio::net::UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() || meta.uid() != uid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "refusing to replace a foreign socket or a non-socket path",
                ));
            }
            std::fs::remove_file(path)?;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    Ok(listener)
}

type Accepted<'a> = Pin<
    Box<
        dyn Future<Output = io::Result<(tokio::net::UnixStream, tokio::net::unix::SocketAddr)>>
            + Send
            + 'a,
    >,
>;

pub struct Environment {
    host: LinuxHost,
    helper: std::path::PathBuf,
    policy: std::path::PathBuf,
    run_dir: std::path::PathBuf,
    socket: std::path::PathBuf,
    vault: std::path::PathBuf,
    uid: unsafe extern "C" fn() -> libc::uid_t,
    euid: unsafe extern "C" fn() -> libc::uid_t,
    identity: fn(&LinuxHost) -> io::Result<(u32, u32)>,
    vault_owner: fn(&LinuxHost) -> Result<u32, String>,
    owner: fn(&LinuxHost) -> Result<u32, String>,
    current_exe: fn() -> io::Result<std::path::PathBuf>,
    trust: fn(&Path) -> Option<String>,
    peer: Box<
        dyn Fn(std::os::fd::RawFd) -> io::Result<kv_platform::peer::PeerCredentials> + Send + Sync,
    >,
    accept: for<'a> fn(&'a tokio::net::UnixListener) -> Accepted<'a>,
    signal: fn(tokio::signal::unix::SignalKind) -> io::Result<tokio::signal::unix::Signal>,
    shutdown: Pin<Box<dyn Future<Output = ()> + Send>>,
    max_clients: usize,
    control_timeout: std::time::Duration,
}
impl Environment {
    pub fn system() -> Self {
        Self {
            host: LinuxHost::system(),
            helper: HELPER_BIN.into(),
            policy: POLKIT_POLICY.into(),
            run_dir: RUN_DIR.into(),
            socket: HELPER_SOCKET.into(),
            vault: VAULT_DIR.into(),
            uid: libc::getuid,
            euid: libc::geteuid,
            identity: LinuxHost::service_identity,
            vault_owner: LinuxHost::verify_vault_owner,
            owner: LinuxHost::owner_uid,
            current_exe: std::env::current_exe,
            trust: untrusted_reason,
            peer: Box::new(kv_platform::peer::peer_credentials),
            accept: accept_socket,
            signal: tokio::signal::unix::signal,
            shutdown: Box::pin(std::future::pending()),
            max_clients: MAX_CLIENTS,
            control_timeout: std::time::Duration::from_secs(5),
        }
    }
}
fn accept_socket(listener: &tokio::net::UnixListener) -> Accepted<'_> {
    Box::pin(listener.accept())
}

#[tokio::main]
pub async fn run(environment: Environment) -> Result<(), String> {
    run_async(environment).await
}

async fn run_async(mut env: Environment) -> Result<(), String> {
    let (uid, _) = (env.identity)(&env.host).map_err(|e| e.to_string())?;
    if unsafe { (env.uid)() } != uid || unsafe { (env.euid)() } != uid {
        return Err("Linux helper must run as the keyvalet service account".into());
    }
    let exe = (env.current_exe)().unwrap_or_default();
    if exe != env.helper {
        return Err("helper must run from its installed path".into());
    }
    for path in [&env.helper, &env.policy] {
        if let Some(reason) = (env.trust)(path) {
            return Err(reason);
        }
    }
    (env.vault_owner)(&env.host)?;
    let owner = (env.owner)(&env.host)?;
    verify_run_dir(&env.run_dir, uid).map_err(|e| e.to_string())?;
    let parent = env.run_dir.parent().ok_or("missing runtime parent")?;
    if let Some(reason) = (env.trust)(parent) {
        return Err(reason);
    }
    let _lock = lock_runtime(&env.run_dir).map_err(|e| e.to_string())?;
    let listener = bind_socket(&env.socket, uid).map_err(|e| e.to_string())?;
    let sessions = Arc::new(AtomicUsize::new(0));
    let permits = Arc::new(tokio::sync::Semaphore::new(env.max_clients));
    let mut clients = tokio::task::JoinSet::new();
    let mut terminate =
        (env.signal)(tokio::signal::unix::SignalKind::terminate()).map_err(|e| e.to_string())?;
    let mut interrupt =
        (env.signal)(tokio::signal::unix::SignalKind::interrupt()).map_err(|e| e.to_string())?;
    loop {
        tokio::select! {
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
            _ = &mut env.shutdown => break,
            _ = clients.join_next(), if !clients.is_empty() => {},
            accept = (env.accept)(&listener) => {
                let Ok((stream, _)) = accept else {
                    // Back off on persistent errors and let shutdown and signal tasks run.
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    continue;
                };
                let Ok(peer) = (env.peer)(stream.as_raw_fd()) else { continue };
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue };
                if peer.uid == 0 {
                    let count = sessions.clone();
                    let timeout = env.control_timeout;
                    clients.spawn(async move {
                        let _permit = permit;
                        let _ = tokio::time::timeout(timeout, control(stream, count)).await;
                    });
                    continue;
                }
                if peer.uid != owner { continue; }
                let Ok(approval) = Polkit::for_peer(peer) else { continue };
                let vault = Arc::new(Vault::new(&env.vault));
                if let Err(e) = vault.prepare() { eprintln!("keyvalet-helper: {}", e.0); continue; }
                let provider = Arc::new(LinuxMasterKeyProvider::for_service(approval.clone()));
                sessions.fetch_add(1, Ordering::SeqCst);
                let count = Count { sessions: sessions.clone(), approval: approval.clone() };
                clients.spawn(async move {
                    let _permit = permit;
                    let _count = count;
                    let (read, write) = stream.into_split();
                    if let crate::Reject::ProtocolError(error) = serve(read, write, vault, Some(peer.uid), "polkit", approval.clone(), approval, provider).await {
                        eprintln!("keyvalet-helper: {error}");
                    }
                });
            }
        }
    }
    drop(listener);
    clients.abort_all();
    while clients.join_next().await.is_some() {}
    let _ = std::fs::remove_file(&env.socket);
    Ok(())
}

#[cfg(test)]
mod tests;
