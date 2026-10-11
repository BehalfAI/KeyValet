use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn identity(_: &LinuxHost) -> io::Result<(u32, u32)> {
    Ok((unsafe { libc::getuid() }, 1000))
}
fn owner(_: &LinuxHost) -> Result<u32, String> {
    Ok(1000)
}
fn verified(_: &LinuxHost) -> Result<u32, String> {
    Ok(unsafe { libc::getuid() })
}
fn trusted(_: &Path) -> Option<String> {
    None
}
fn untrusted(_: &Path) -> Option<String> {
    Some("fixture trust failure".into())
}
fn failed_identity(_: &LinuxHost) -> io::Result<(u32, u32)> {
    Err(io::Error::other("fixture identity failure"))
}
fn failed_owner(_: &LinuxHost) -> Result<u32, String> {
    Err("fixture owner failure".into())
}
unsafe extern "C" fn wrong_uid() -> libc::uid_t {
    unsafe { libc::getuid() }.wrapping_add(1)
}
fn wrong_exe() -> io::Result<std::path::PathBuf> {
    Err(io::Error::other("fixture missing executable"))
}
fn failed_signal(_: tokio::signal::unix::SignalKind) -> io::Result<tokio::signal::unix::Signal> {
    Err(io::Error::other("fixture signal error"))
}
fn failed_accept(_: &tokio::net::UnixListener) -> Accepted<'_> {
    Box::pin(async { Err(io::Error::other("fixture accept error")) })
}

fn peer(uid: u32, pid: u32) -> kv_platform::peer::PeerCredentials {
    kv_platform::peer::PeerCredentials {
        uid,
        gid: 1000,
        pid,
    }
}

fn environment(directory: &Path) -> (Environment, tokio::sync::oneshot::Sender<()>) {
    let mut env = Environment::system();
    env.helper = std::env::current_exe().unwrap();
    env.policy = directory.join("policy");
    env.run_dir = directory.join("run");
    env.socket = env.run_dir.join("helper.sock");
    env.vault = directory.join("vault");
    env.identity = identity;
    env.vault_owner = verified;
    env.owner = owner;
    env.trust = trusted;
    env.peer = Box::new(|_| Ok(peer(1000, std::process::id())));
    env.control_timeout = std::time::Duration::from_millis(50);
    std::fs::create_dir_all(&env.run_dir).unwrap();
    std::fs::set_permissions(&env.run_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    env.shutdown = Box::pin(async {
        let _ = stopped.await;
    });
    (env, stop)
}

async fn connect(path: &Path) -> tokio::net::UnixStream {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Ok(stream) = tokio::net::UnixStream::connect(path).await {
                return stream;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap()
}

async fn closed(stream: &mut tokio::net::UnixStream) {
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

async fn control_count(path: &Path) -> usize {
    let mut stream = connect(path).await;
    stream
        .write_all(b"{\"op\":\"control\",\"command\":\"sessions\"}\n")
        .await
        .unwrap();
    let mut reply = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut reply),
    )
    .await
    .unwrap()
    .unwrap();
    serde_json::from_slice::<serde_json::Value>(&reply).unwrap()["sessions"]
        .as_u64()
        .unwrap() as usize
}

#[tokio::test]
async fn startup_rejects_identity_privilege_executable_trust_owner_and_runtime_errors() {
    for failure in 0..9 {
        let temp = tempfile::tempdir().unwrap();
        let (mut env, _stop) = environment(temp.path());
        match failure {
            0 => env.identity = failed_identity,
            1 => env.uid = wrong_uid,
            2 => env.euid = wrong_uid,
            3 => env.current_exe = wrong_exe,
            4 => env.trust = untrusted,
            5 => env.vault_owner = failed_owner,
            6 => env.owner = failed_owner,
            7 => std::fs::set_permissions(&env.run_dir, std::fs::Permissions::from_mode(0o777))
                .unwrap(),
            8 => {
                env.trust = |path| {
                    (path.file_name().is_none_or(|name| name != "policy")
                        && path != std::env::current_exe().unwrap())
                    .then(|| "fixture parent trust failure".into())
                }
            }
            _ => unreachable!(),
        }
        assert!(run_async(env).await.is_err(), "case {failure}");
        assert!(!temp.path().join("run/helper.sock").exists());
    }
}

#[test]
fn daemon_entry_returns_startup_errors_without_exiting_its_caller() {
    let temp = tempfile::tempdir().unwrap();
    let (mut env, _stop) = environment(temp.path());
    env.identity = failed_identity;
    assert!(run(env).unwrap_err().contains("identity failure"));
}

#[tokio::test]
async fn lock_socket_metadata_and_signal_failures_are_reported() {
    let temp = tempfile::tempdir().unwrap();
    let (env, _stop) = environment(temp.path());
    let lock = lock_runtime(&env.run_dir).unwrap();
    assert!(run_async(env).await.is_err());
    drop(lock);
    let (env, _stop) = environment(temp.path());
    std::os::unix::fs::symlink(&env.socket, &env.socket).unwrap();
    assert!(run_async(env).await.is_err());
    std::fs::remove_file(temp.path().join("run/helper.sock")).unwrap();
    let (mut env, _stop) = environment(temp.path());
    env.signal = failed_signal;
    assert!(run_async(env).await.unwrap_err().contains("signal error"));
}

#[tokio::test]
async fn shutdown_handles_accept_errors_and_removes_its_socket() {
    let temp = tempfile::tempdir().unwrap();
    let (mut env, stop) = environment(temp.path());
    let path = env.socket.clone();
    env.accept = failed_accept;
    let task = tokio::spawn(run_async(env));
    let _client = connect(&path).await;
    stop.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!path.exists());
}

#[tokio::test]
async fn foreign_invalid_or_exited_peers_and_broken_vaults_cannot_start_sessions() {
    for failure in 0..4 {
        let temp = tempfile::tempdir().unwrap();
        let (mut env, stop) = environment(temp.path());
        match failure {
            0 => env.peer = Box::new(|_| Err(io::Error::other("fixture credentials error"))),
            1 => env.peer = Box::new(|_| Ok(peer(1001, std::process::id()))),
            2 => env.peer = Box::new(|_| Ok(peer(1000, u32::MAX))),
            3 => std::fs::write(&env.vault, b"invalid vault directory").unwrap(),
            _ => unreachable!(),
        }
        let path = env.socket.clone();
        let task = tokio::spawn(run_async(env));
        let mut client = connect(&path).await;
        closed(&mut client).await;
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn a_full_client_budget_closes_new_connections_and_shutdown_aborts_sessions() {
    let temp = tempfile::tempdir().unwrap();
    let (mut env, stop) = environment(temp.path());
    env.max_clients = 1;
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    env.peer = Box::new(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok(peer(1000, std::process::id()))
    });
    let path = env.socket.clone();
    let task = tokio::spawn(run_async(env));
    let mut first = connect(&path).await;
    while accepted.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    let mut second = connect(&path).await;
    closed(&mut second).await;
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
    closed(&mut first).await;
    assert!(!path.exists());
}

#[tokio::test]
async fn root_control_observes_sessions_and_protocol_errors_release_the_session() {
    let temp = tempfile::tempdir().unwrap();
    let (mut env, stop) = environment(temp.path());
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    env.peer = Box::new(move |_| {
        Ok(peer(
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                1000
            } else {
                0
            },
            std::process::id(),
        ))
    });
    let path = env.socket.clone();
    let task = tokio::spawn(run_async(env));
    let mut session = connect(&path).await;
    while accepted.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    assert_eq!(control_count(&path).await, 1);
    session.write_all(b"invalid hello\n").await.unwrap();
    closed(&mut session).await;
    assert_eq!(control_count(&path).await, 0);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn stalled_root_control_connections_time_out_and_release_their_permit() {
    let temp = tempfile::tempdir().unwrap();
    let (mut env, stop) = environment(temp.path());
    env.max_clients = 1;
    env.peer = Box::new(|_| Ok(peer(0, std::process::id())));
    let path = env.socket.clone();
    let task = tokio::spawn(run_async(env));
    let mut stalled = connect(&path).await;
    closed(&mut stalled).await;
    assert_eq!(control_count(&path).await, 0);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
}

#[test]
#[ignore = "Subprocess fixture, invoked by unix_signals_stop_the_isolated_daemon"]
fn unix_signal_fixture() {
    let directory = std::path::PathBuf::from(std::env::var_os("KV_TEST_RUNTIME").unwrap());
    let (mut env, _stop) = environment(&directory);
    env.peer = Box::new(|_| Ok(peer(0, std::process::id())));
    env.shutdown = Box::pin(std::future::pending());
    run(env).unwrap();
}

#[tokio::test]
async fn unix_signals_stop_the_isolated_daemon() {
    for signal in [libc::SIGTERM, libc::SIGINT] {
        let temp = tempfile::tempdir().unwrap();
        let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "daemon_linux::tests::unix_signal_fixture",
                "--ignored",
            ])
            .env("KV_TEST_RUNTIME", temp.path())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let path = temp.path().join("run/helper.sock");
        assert_eq!(control_count(&path).await, 0);
        assert_eq!(
            unsafe { libc::kill(child.id().unwrap() as libc::pid_t, signal) },
            0
        );
        let status = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(status.success(), "signal {signal}: {status}");
        assert!(!path.exists());
    }
}

#[test]
fn runtime_directory_requires_its_owner_and_disallows_group_or_other_writes() {
    let temp = tempfile::tempdir().unwrap();
    let uid = unsafe { libc::getuid() };
    for mode in [0o700, 0o750, 0o755] {
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        verify_run_dir(temp.path(), uid).unwrap();
    }
    for mode in [0o770, 0o757, 0o777] {
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(verify_run_dir(temp.path(), uid).is_err());
    }
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(verify_run_dir(temp.path(), uid.wrapping_add(1)).is_err());
}

#[test]
fn runtime_directory_rejects_symlinks_files_and_missing_paths() {
    let temp = tempfile::tempdir().unwrap();
    let uid = unsafe { libc::getuid() };
    let file = temp.path().join("file");
    std::fs::write(&file, b"preserve").unwrap();
    let link = temp.path().join("link");
    std::os::unix::fs::symlink(temp.path(), &link).unwrap();
    for path in [file, link, temp.path().join("missing")] {
        assert!(verify_run_dir(&path, uid).is_err());
    }
}

#[test]
fn daemon_lock_is_exclusive_and_released_when_its_owner_exits() {
    let temp = tempfile::tempdir().unwrap();
    let first = lock_runtime(temp.path()).unwrap();
    assert!(lock_runtime(temp.path()).is_err());
    assert_eq!(
        std::fs::metadata(temp.path().join("daemon.lock"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
    drop(first);
    assert!(lock_runtime(temp.path()).is_ok());
}

#[test]
fn daemon_lock_never_follows_a_symlink() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    std::fs::write(&target, b"preserve").unwrap();
    std::os::unix::fs::symlink(&target, temp.path().join("daemon.lock")).unwrap();
    assert!(lock_runtime(temp.path()).is_err());
    assert_eq!(std::fs::read(target).unwrap(), b"preserve");
}

#[tokio::test]
async fn helper_socket_replaces_an_owned_stale_socket_and_accepts_kernel_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("helper.sock");
    let uid = unsafe { libc::getuid() };
    let stale = std::os::unix::net::UnixListener::bind(&path).unwrap();
    drop(stale);
    let listener = bind_socket(&path, uid).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o666);
    let _client = tokio::net::UnixStream::connect(&path).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let peer = kv_platform::peer::peer_credentials(server.as_raw_fd()).unwrap();
    assert_eq!(peer.uid, uid);
    assert_eq!(peer.pid, std::process::id());
}

#[tokio::test]
async fn helper_socket_creates_a_new_endpoint_but_preserves_foreign_or_non_socket_paths() {
    let temp = tempfile::tempdir().unwrap();
    let uid = unsafe { libc::getuid() };
    let socket = temp.path().join("socket");
    let listener = bind_socket(&socket, uid).unwrap();
    assert!(bind_socket(&socket, uid.wrapping_add(1)).is_err());
    assert!(std::fs::symlink_metadata(&socket)
        .unwrap()
        .file_type()
        .is_socket());
    drop(listener);
    let file = temp.path().join("file");
    std::fs::write(&file, b"preserve").unwrap();
    let link = temp.path().join("link");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    for path in [&file, &link, temp.path()] {
        assert!(bind_socket(path, uid).is_err());
    }
    let loop_dir = temp.path().join("loop");
    std::os::unix::fs::symlink(&loop_dir, &loop_dir).unwrap();
    assert_eq!(
        bind_socket(&loop_dir.join("helper.sock"), uid)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ELOOP)
    );
    assert_eq!(std::fs::read(file).unwrap(), b"preserve");
    assert!(std::fs::symlink_metadata(link)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[tokio::test]
async fn dropping_a_session_decrements_the_count_and_revokes_approval() {
    let approval = Polkit::for_peer(kv_platform::peer::PeerCredentials {
        uid: 1000,
        gid: 1000,
        pid: std::process::id(),
    })
    .unwrap();
    let sessions = Arc::new(AtomicUsize::new(2));
    let count = Count {
        sessions: sessions.clone(),
        approval: approval.clone(),
    };
    drop(count);
    assert_eq!(sessions.load(Ordering::SeqCst), 1);
    use kv_platform::Authenticator;
    assert!(matches!(
        approval.authenticate("test", "cancel").await,
        kv_platform::AuthOutcome::Error(_)
    ));
}
