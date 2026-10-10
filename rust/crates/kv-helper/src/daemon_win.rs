//! Windows service mode (`kv-helper --service`): serves client sessions on HELPER_PIPE and the
//! per-user agent channel on AGENT_PIPE, mirroring the macOS daemon's one-connection-one-session
//! split. W1 sets up the transport only: peer identification lands in W2, and until it does
//! `peer::accept_client` refuses every client (fail closed -- a helper that can't tell who called
//! must not start a session).

use crate::fatal;
use kv_platform::paths::{AGENT_PIPE, HELPER_PIPE};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

/// A fresh listening instance for `name`: each accepted client consumes the instance, so the
/// accept loop binds a new one per iteration. `first_pipe_instance` applies only to the first.
fn next_pipe(name: &str, first: bool) -> NamedPipeServer {
    let mut opts = ServerOptions::new();
    opts.first_pipe_instance(first);
    match opts.create(name) {
        Ok(s) => s,
        Err(e) => fatal(&format!("cannot bind {name}: {e}")),
    }
}

/// Serve one pipe forever; `handle` gets each connected instance. Identifying (or for W1,
/// refusing) the peer is the handler's job.
async fn serve_pipe<Fut>(name: &'static str, handle: impl Fn(NamedPipeServer) -> Fut)
where
    Fut: std::future::Future<Output = ()>,
{
    let mut first = true;
    loop {
        let pipe = next_pipe(name, first);
        first = false;
        if pipe.connect().await.is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            continue;
        }
        handle(pipe).await;
    }
}

#[tokio::main]
pub async fn run() {
    let self_path = std::env::current_exe().unwrap_or_default();
    if let Err(e) = kv_platform::trust::verify_root_environment(
        &self_path,
        std::path::Path::new(kv_platform::paths::HELPER_BIN),
        &[],
    ) {
        fatal(&e);
    }
    // Client sessions: every connection is refused until `peer::accept_client` can identify the
    // caller (W2). Failing closed here is the whole point of the seam.
    let clients = serve_pipe(HELPER_PIPE, |pipe| async move {
        let _ = kv_platform::peer::accept_client(&pipe).await;
        // Unidentified connections get nothing: drop the pipe (no reply, no session).
        drop(pipe);
    });

    // The agent channel is likewise closed to every peer until the W2 SID check exists.
    let agent = serve_pipe(AGENT_PIPE, |pipe| async move {
        drop(pipe);
    });

    tokio::join!(clients, agent);
}
