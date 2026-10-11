//! Stdio clients relay to a protected user worker created by SYSTEM. Native secret input
//! never resides in the ordinary launcher, whose memory is readable by its parent account.
use kv_platform::agent_process::{new_mcp_channel, ProtectedProcess};
use kv_platform::paths::{AGENT_PUBLISHER, ALLOW_UNSIGNED_AGENT, MCP_BIN};
use kv_platform::peer::{accept_client, sid_equal};
use kv_platform::trust::{allow_unsigned_agent, same_file_path, trusted_path, verify_publisher};
use kv_platform::worker::{CONNECT_TIMEOUT, CREATE_TIMEOUT, VERIFY_TIMEOUT};
use serde_json::json;
use std::{io, path::Path, sync::Arc, time::Duration};
use tokio::net::windows::named_pipe::NamedPipeServer;

pub async fn serve_launcher(
    mut launcher: NamedPipeServer,
    owner: Arc<Vec<u8>>,
    session: u32,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> io::Result<()> {
    if *stop.borrow() {
        return Ok(());
    }
    let mut started = false;
    let result = async {
        let request = tokio::select! {
            result = kv_platform::worker::read_launch(&mut launcher) => result?,
            _ = stop.changed() => return Ok(()),
        };
        run(
            &mut launcher,
            &owner,
            session,
            request,
            &mut stop,
            &mut started,
        )
        .await
    }
    .await;
    if result.is_err() && !started && !*stop.borrow() {
        let _ = kv_platform::worker::write_json(
            &mut launcher,
            &json!({"ok":false,"reason":"worker-launch-failed"}),
        )
        .await;
    }
    result
}

async fn run(
    launcher: &mut NamedPipeServer,
    owner: &[u8],
    session: u32,
    request: kv_ipc::mcp_worker::Launch,
    stop: &mut tokio::sync::watch::Receiver<bool>,
    started: &mut bool,
) -> io::Result<()> {
    if !request.valid() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid MCP launch context",
        ));
    }
    let path = Path::new(MCP_BIN);
    // Certificate chain verification may block on network retrieval. Keep it off the async
    // executor and never start a worker if verification is stopped or exceeds its deadline.
    let verify = tokio::task::spawn_blocking(move || {
        trusted_path(path)
            && (verify_publisher(path, AGENT_PUBLISHER).is_ok()
                || allow_unsigned_agent(Path::new(ALLOW_UNSIGNED_AGENT)))
    });
    let trusted = tokio::select! {
        biased;
        _ = stop.changed() => return Ok(()),
        result = tokio::time::timeout(VERIFY_TIMEOUT, verify) => result.ok().and_then(Result::ok).unwrap_or(false),
    };
    if !trusted {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "MCP worker is not trusted",
        ));
    }
    if *stop.borrow() {
        return Ok(());
    }
    let name = new_mcp_channel()?;
    let factory = kv_platform::pipe::server_options(&name, owner)?;
    let mut channel = factory.create(true)?;
    let launch_owner = owner.to_vec();
    let launch_name = name.clone();
    let launch = tokio::task::spawn_blocking(move || {
        ProtectedProcess::launch_mcp(session, &launch_owner, &launch_name)
    });
    let child = tokio::select! {
        biased;
        _ = stop.changed() => return Ok(()),
        result = tokio::time::timeout(CREATE_TIMEOUT, launch) => result
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "MCP worker creation timed out"))?
            .map_err(io::Error::other)??,
    };
    let handshake = async {
        loop {
            channel.connect().await?;
            let peer = accept_client(&channel).await?;
            if child.matches(peer.pid)
                && sid_equal(&peer.sid, owner)
                && same_file_path(&peer.exe_path, path)
            {
                break;
            }
            // Keep the original instance while creating its replacement, preserving the name.
            let next = factory.create(false)?;
            channel.disconnect()?;
            channel = next;
        }
        kv_platform::worker::accept_worker(&mut channel, request.context).await?;
        kv_platform::worker::write_json(launcher, &json!({"ok":true})).await?;
        *started = true;
        Ok::<(), io::Error>(())
    };
    let started = tokio::select! {
        biased;
        _ = stop.changed() => Err(io::Error::new(io::ErrorKind::Interrupted, "service stopped")),
        _ = async {
            while child.running() { tokio::time::sleep(Duration::from_millis(100)).await; }
        } => Err(io::Error::new(io::ErrorKind::BrokenPipe, "MCP worker exited before connecting")),
        result = tokio::time::timeout(CONNECT_TIMEOUT, handshake) => {
            result.unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "MCP worker did not connect")))
        },
    };
    let result = match started {
        Ok(()) => tokio::select! {
            result = kv_platform::worker::relay(launcher, &mut channel) => result,
            _ = stop.changed() => Ok(()),
        },
        Err(e) => Err(e),
    };
    // Named pipes have no half-close. Explicitly close both directions on client EOF; the
    // worker then locks its helper session and deletes its exported files before exiting.
    let _ = channel.disconnect();
    drop(channel);
    for _ in 0..20 {
        if !child.running() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if child.running() {
        let _ = child.terminate();
        // TerminateProcess is asynchronous. Keep the retained handle and wait for exit so
        // the cleaner does not mistake a terminating creator for a live file owner.
        for _ in 0..20 {
            if !child.running() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    drop(child); // Close the retained process/job handles before stale-file cleanup.
    if let Ok(cleaner) = ProtectedProcess::launch_cleanup(session, owner) {
        for _ in 0..10 {
            if !cleaner.running() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    result
}
