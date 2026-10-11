//! Ordinary client invocation is a stdio relay; only the service-created worker handles tools.
use kv_ipc::mcp_worker::{valid_channel, Context};
use kv_platform::{paths::MCP_PIPE, pipe::connect_service, worker};
use std::io;
use tokio::net::windows::named_pipe::NamedPipeClient;

pub async fn start() -> anyhow::Result<Option<NamedPipeClient>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => {
            launch().await?;
            Ok(None)
        }
        [arg] if arg == "--cleanup-stale" => {
            crate::gateway_env::purge_legacy_records();
            Ok(None)
        }
        [mode, flag, name] if mode == "--worker" && flag == "--channel" && valid_channel(name) => {
            let mut pipe = connect_service(name).await?;
            let context = worker::request_worker(&mut pipe).await?;
            std::env::set_current_dir(&context.cwd)?;
            std::env::set_var(
                "KEYVALET_SESSION_TTL_MINUTES",
                context.ttl_minutes.to_string(),
            );
            std::env::set_var("KEYVALET_LANG", context.lang);
            match context.grant_mode {
                Some(mode) => std::env::set_var("KEYVALET_GRANT_MODE", mode),
                None => std::env::remove_var("KEYVALET_GRANT_MODE"),
            }
            Ok(Some(pipe))
        }
        _ => anyhow::bail!("usage: kv-mcp (the Windows service must be installed and running)"),
    }
}

async fn launch() -> io::Result<()> {
    let context = Context {
        cwd: std::env::current_dir()?.to_string_lossy().into_owned(),
        ttl_minutes: std::env::var("KEYVALET_SESSION_TTL_MINUTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        grant_mode: std::env::var("KEYVALET_GRANT_MODE").ok(),
        lang: kv_i18n::lang().as_str().to_owned(),
    };
    if !context.valid() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid MCP launch context",
        ));
    }
    let mut pipe = connect_service(MCP_PIPE).await?;
    worker::request_launch(&mut pipe, context).await?;
    worker::relay_io(tokio::io::stdin(), tokio::io::stdout(), &mut pipe).await?;
    // Drop the entire pipe on either EOF; flushing a named pipe cannot signal a half-close.
    Ok(())
}
