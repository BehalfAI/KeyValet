//! The Windows agent runs as the installing user in an interactive session. It accepts work
//! only from the authenticated LocalSystem helper; no local listener or command-line key output.
#[cfg(windows)]
mod hello;
#[cfg(any(windows, test))]
mod hello_crypto;
#[cfg(any(windows, test))]
mod hello_logic;

#[cfg(windows)]
#[tokio::main]
async fn main() {
    use kv_ipc::agent as wire;
    use kv_platform::{paths, pipe};
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let serving = match arguments.as_slice() {
        [] => false,
        [arg] if arg == "--launch" => false,
        [arg] if arg == "--serve" => true,
        [arg] if arg == "--help" || arg == "-h" => {
            println!("kv-agent [--launch]\nNotify the KeyValet service to start the Windows Hello agent.");
            return;
        }
        _ => {
            eprintln!("usage: kv-agent [--launch]");
            std::process::exit(2);
        }
    };

    let me = kv_platform::peer::self_identity().expect("cannot identify agent user");
    if me.elevated || kv_platform::peer::sid_to_string(&me.sid).as_deref() == Some("S-1-5-18") {
        eprintln!("kv-agent must run as the unelevated interactive user");
        std::process::exit(1);
    }
    let mut backoff = std::time::Duration::from_secs(1);
    loop {
        let connected = pipe::connect_service(paths::AGENT_PIPE).await;
        if let Ok(mut channel) = connected {
            let handshake = async {
                let hello = if serving {
                    wire::hello()
                } else {
                    json!({"op":"agent-launch", "protocol":wire::AGENT_PROTOCOL})
                };
                channel.write_all(&wire::encode_line(&hello)).await?;
                read_line(&mut channel).await
            };
            if let Ok(Ok(reply)) =
                tokio::time::timeout(std::time::Duration::from_secs(10), handshake).await
            {
                if reply["reason"].as_str() == Some("not-allowed-user") {
                    return;
                }
                if reply["ok"] == true {
                    if !serving {
                        return;
                    }
                    backoff = std::time::Duration::from_secs(1);
                    let mut active: Option<kv_vault::EnclaveMetadata> = None;
                    while let Ok(request) = read_line(&mut channel).await {
                        let id = request["id"].as_u64().unwrap_or(0);
                        let op = request["op"].as_str().unwrap_or("").to_owned();
                        let metadata = active.clone();
                        // Initialize WinRT on the thread actually invoking it; the pool does
                        // not inherit the runtime thread's apartment.
                        let result = tokio::task::spawn_blocking(move || {
                            hello::handle(&request, metadata.as_ref())
                        })
                        .await;
                        let (reply, payload, new_active) = result.unwrap_or_else(|_| {
                            (
                                wire::reply(
                                    id,
                                    &[
                                        ("ok", json!(false)),
                                        ("error", json!("agent worker failed")),
                                    ],
                                ),
                                None,
                                None,
                            )
                        });
                        if let Some(metadata) = new_active {
                            active = Some(metadata);
                        }
                        if op == "enclave" && reply["ok"] != true {
                            active = None;
                        }
                        if channel.write_all(&wire::encode_line(&reply)).await.is_err() {
                            break;
                        }
                        if let Some((bytes, len)) = payload {
                            if channel.write_all(&bytes[..len]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(std::time::Duration::from_secs(30));
    }

    async fn read_line(
        pipe: &mut tokio::net::windows::named_pipe::NamedPipeClient,
    ) -> std::io::Result<Value> {
        let mut bytes = Vec::new();
        loop {
            let byte = pipe.read_u8().await?;
            if byte == b'\n' {
                break;
            }
            if bytes.len() >= wire::MAX_LINE_BYTES {
                return Err(std::io::Error::other("agent request too large"));
            }
            bytes.push(byte);
        }
        serde_json::from_slice(&bytes).map_err(std::io::Error::from)
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("kv-agent requires Windows 11 and Windows Hello");
    std::process::exit(2);
}
