//! Bounded Windows worker negotiation, testable without SYSTEM, installed binaries or Hello.
//! OS peer/code-identity checks belong to the real service/client before calling these functions.
use kv_ipc::mcp_worker::{Context, Launch, Ready, Started, WorkerHello, PROTOCOL};
use serde_json::{json, Value};
use std::{io, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
pub const VERIFY_TIMEOUT: Duration = Duration::from_secs(10);
pub const CREATE_TIMEOUT: Duration = Duration::from_secs(5);
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
// The service bounds certificate verification, process creation and child negotiation.
// Leave time for its bounded failure reply as well as scheduling and pipe writes.
pub const LAUNCH_TIMEOUT: Duration = Duration::from_secs(40);

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// No buffered reader: the first MCP frame after a hello must remain unread.
pub async fn read_json<S: AsyncRead + Unpin>(
    stream: &mut S,
    timeout: Duration,
) -> io::Result<Value> {
    serde_json::from_slice(&read_frame(stream, timeout).await?)
        .map_err(|_| invalid("invalid worker hello JSON"))
}

async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    tokio::time::timeout(timeout, async {
        let mut bytes = Vec::new();
        loop {
            let byte = stream.read_u8().await?;
            if byte == b'\n' {
                break;
            }
            if bytes.len() == kv_ipc::agent::MAX_LINE_BYTES {
                return Err(invalid("worker hello too large"));
            }
            bytes.push(byte);
        }
        Ok(bytes)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "worker hello timed out"))?
}

pub async fn write_json<S: AsyncWrite + Unpin>(stream: &mut S, value: &Value) -> io::Result<()> {
    let mut line = serde_json::to_vec(value)?;
    if line.len() > kv_ipc::agent::MAX_LINE_BYTES {
        return Err(invalid("worker hello too large"));
    }
    line.push(b'\n');
    tokio::time::timeout(HELLO_TIMEOUT, async {
        stream.write_all(&line).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "worker hello write timed out"))?
}

pub async fn read_launch<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Launch> {
    // Deserialize the original frame into its schema. Passing through Value would discard
    // duplicate fields before serde can reject conflicting operation/protocol/context values.
    let request: Launch = serde_json::from_slice(&read_frame(stream, HELLO_TIMEOUT).await?)
        .map_err(|_| invalid("invalid MCP launch request"))?;
    if !request.valid() {
        return Err(invalid("invalid MCP launch context"));
    }
    Ok(request)
}

pub async fn request_launch<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    context: Context,
) -> io::Result<()> {
    if !context.valid() {
        return Err(invalid("invalid MCP launch context"));
    }
    write_json(
        stream,
        &serde_json::to_value(Launch {
            op: "mcp-launch".into(),
            protocol: PROTOCOL,
            context,
        })?,
    )
    .await?;
    let reply: Started = serde_json::from_slice(&read_frame(stream, LAUNCH_TIMEOUT).await?)
        .map_err(|_| invalid("invalid MCP launch reply"))?;
    if !reply.ok {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "MCP launch rejected: {}",
                reply.reason.as_deref().unwrap_or("unspecified")
            ),
        ));
    }
    if reply.reason.is_some() {
        return Err(invalid("inconsistent MCP launch reply"));
    }
    Ok(())
}

/// Only call after verifying the retained child PID, SID and executable of this pipe peer.
pub async fn accept_worker<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    context: Context,
) -> io::Result<()> {
    let hello: WorkerHello = serde_json::from_slice(&read_frame(stream, HELLO_TIMEOUT).await?)
        .map_err(|_| invalid("invalid MCP worker hello"))?;
    if !hello.valid() || !context.valid() {
        return Err(invalid("invalid MCP worker hello/context"));
    }
    write_json(stream, &serde_json::to_value(Ready { ok: true, context })?).await
}

pub async fn request_worker<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> io::Result<Context> {
    write_json(stream, &json!({"op":"mcp-worker", "protocol":PROTOCOL})).await?;
    let reply: Ready = serde_json::from_slice(&read_frame(stream, HELLO_TIMEOUT).await?)
        .map_err(|_| invalid("invalid MCP worker reply"))?;
    if !reply.ok || !reply.context.valid() {
        return Err(invalid("MCP worker was rejected"));
    }
    Ok(reply.context)
}

/// A named pipe has no half-close. Return on either EOF/error; the owner then closes the
/// entire channel and revokes the worker. copy_bidirectional would wait forever on stdin EOF.
pub async fn relay<A, B>(a: &mut A, b: &mut B) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (ar, aw) = tokio::io::split(a);
    relay_io(ar, aw, b).await
}

pub async fn relay_io<R, W, B>(mut ar: R, mut aw: W, b: &mut B) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut br, mut bw) = tokio::io::split(b);
    tokio::select! {
        result = async { tokio::io::copy(&mut ar, &mut bw).await?; bw.flush().await } => result,
        result = async { tokio::io::copy(&mut br, &mut aw).await?; aw.flush().await } => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        pin::Pin,
        task::{Context as TaskContext, Poll},
    };

    #[derive(Default)]
    struct ProbeWriter {
        bytes: Vec<u8>,
        short_writes: bool,
        write_error: Option<io::ErrorKind>,
        pending_flush: bool,
        flush_error: Option<io::ErrorKind>,
        flushes: usize,
    }
    impl AsyncWrite for ProbeWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if let Some(kind) = self.write_error {
                return Poll::Ready(Err(io::Error::from(kind)));
            }
            let len = if self.short_writes {
                bytes.len().min(1)
            } else {
                bytes.len()
            };
            self.bytes.extend_from_slice(&bytes[..len]);
            Poll::Ready(Ok(len))
        }
        fn poll_flush(mut self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            self.flushes += 1;
            if self.pending_flush {
                Poll::Pending
            } else {
                Poll::Ready(
                    self.flush_error
                        .map_or(Ok(()), |kind| Err(io::Error::from(kind))),
                )
            }
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct ErrorReader(io::ErrorKind);
    impl AsyncRead for ErrorReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut TaskContext<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::from(self.0)))
        }
    }
    fn context() -> Context {
        Context {
            cwd: r"C:\项目".into(),
            ttl_minutes: 30,
            grant_mode: Some("per_use".into()),
            lang: "zh".into(),
        }
    }

    #[tokio::test]
    async fn worker_handshake_preserves_the_following_mcp_frame() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let peer = tokio::spawn(async move {
            accept_worker(&mut server, context()).await.unwrap();
            server.write_all(b"{\"jsonrpc\":\"2.0\"}\n").await.unwrap();
        });
        let received = request_worker(&mut client).await.unwrap();
        assert_eq!(received.cwd, context().cwd);
        assert_eq!(received.grant_mode.as_deref(), Some("per_use"));
        assert_eq!(
            read_json(&mut client, HELLO_TIMEOUT).await.unwrap()["jsonrpc"],
            "2.0"
        );
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn fragmented_hello_is_read_without_prefetch() {
        let (mut client, mut server) = tokio::io::duplex(32);
        let sender = tokio::spawn(async move {
            for byte in b"{\"ok\":true}\nnext" {
                client.write_all(&[*byte]).await.unwrap();
            }
        });
        assert_eq!(
            read_json(&mut server, HELLO_TIMEOUT).await.unwrap(),
            json!({"ok":true})
        );
        let mut next = [0; 4];
        server.read_exact(&mut next).await.unwrap();
        assert_eq!(&next, b"next");
        sender.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn silent_or_partial_peers_cannot_occupy_a_worker_forever() {
        let (mut client, mut server) = tokio::io::duplex(32);
        client.write_all(b"{\"op\":").await.unwrap();
        assert_eq!(
            read_json(&mut server, HELLO_TIMEOUT)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[tokio::test]
    async fn malformed_oversized_and_truncated_hello_fail_closed() {
        for mut bytes in [
            b"not-json\n".to_vec(),
            b"{\"ok\":\n".to_vec(),
            vec![b'x'; kv_ipc::agent::MAX_LINE_BYTES + 1],
            b"{\"ok\":true}".to_vec(),
        ] {
            if bytes.len() > kv_ipc::agent::MAX_LINE_BYTES {
                bytes.push(b'\n');
            }
            assert!(read_json(&mut bytes.as_slice(), HELLO_TIMEOUT)
                .await
                .is_err());
        }
    }

    #[tokio::test]
    async fn wrong_protocol_and_cross_role_hello_never_get_ready_context() {
        for hello in [
            json!({"op":"agent-hello","protocol":PROTOCOL}),
            json!({"op":"mcp-worker","protocol":PROTOCOL+1}),
            json!({"op":"mcp-worker","protocol":PROTOCOL,"session_id":99}),
            json!({"op":"mcp-worker","protocol":"1"}),
        ] {
            let (mut client, mut server) = tokio::io::duplex(1024);
            write_json(&mut client, &hello).await.unwrap();
            assert!(accept_worker(&mut server, context()).await.is_err());
            drop(server);
            assert_eq!(
                client.read_u8().await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }

    #[tokio::test]
    async fn denied_and_inconsistent_launcher_replies_are_not_success() {
        for reply in [
            json!({"ok":false,"reason":"untrusted-binary"}),
            json!({"ok":true,"reason":"untrusted-binary"}),
            json!({"ok":"true"}),
            json!({"ok":true,"environment":{"PATH":"evil"}}),
        ] {
            let (mut client, mut server) = tokio::io::duplex(2048);
            let peer = tokio::spawn(async move {
                read_launch(&mut server).await.unwrap();
                write_json(&mut server, &reply).await.unwrap();
            });
            assert!(request_launch(&mut client, context()).await.is_err());
            peer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn invalid_local_context_does_not_send_any_bytes() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let mut ctx = context();
        ctx.ttl_minutes = u64::MAX;
        assert!(request_launch(&mut client, ctx).await.is_err());
        drop(client);
        assert_eq!(
            server.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test(start_paused = true)]
    async fn blocked_handshake_writer_has_a_deadline() {
        let (mut client, _server) = tokio::io::duplex(1);
        assert_eq!(
            write_json(&mut client, &json!({"ok":true}))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[tokio::test]
    async fn relay_exits_on_either_eof_and_forwards_both_directions() {
        for close_launcher in [true, false] {
            let (mut launcher, mut service_in) = tokio::io::duplex(64);
            let (mut service_out, mut worker) = tokio::io::duplex(64);
            let task = tokio::spawn(async move { relay(&mut service_in, &mut service_out).await });
            launcher.write_all(b"request").await.unwrap();
            let mut bytes = [0; 7];
            worker.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"request");
            worker.write_all(b"reply").await.unwrap();
            let mut bytes = [0; 5];
            launcher.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"reply");
            if close_launcher {
                drop(launcher);
            } else {
                drop(worker);
            }
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
    }

    #[test]
    fn launcher_deadline_includes_all_service_stages_and_a_failure_reply() {
        assert!(LAUNCH_TIMEOUT > VERIFY_TIMEOUT + CREATE_TIMEOUT + CONNECT_TIMEOUT + HELLO_TIMEOUT);
    }

    #[tokio::test]
    async fn launcher_negotiation_preserves_the_pipelined_mcp_message() {
        let (mut client, mut server) = tokio::io::duplex(2048);
        let peer = tokio::spawn(async move {
            let request = read_launch(&mut server).await.unwrap();
            assert_eq!(request.context.cwd, context().cwd);
            write_json(&mut server, &json!({"ok":true})).await.unwrap();
            server
                .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":99}\n")
                .await
                .unwrap();
        });
        request_launch(&mut client, context()).await.unwrap();
        assert_eq!(
            read_json(&mut client, HELLO_TIMEOUT).await.unwrap()["id"],
            99
        );
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn invalid_launch_requests_cannot_select_extra_environment_or_identity() {
        for request in [
            json!({"op":"mcp-launch","protocol":PROTOCOL,"context":context(),"session":1}),
            json!({"op":"mcp-launch","protocol":PROTOCOL,"context":{"cwd":"C:\\project","ttl_minutes":30,"grant_mode":null,"lang":"en","executable":"evil.exe"}}),
            json!({"op":"mcp-launch","protocol":PROTOCOL+1,"context":context()}),
            json!({"op":"mcp-worker","protocol":PROTOCOL,"context":context()}),
        ] {
            let bytes = kv_ipc::agent::encode_line(&request);
            assert!(read_launch(&mut bytes.as_slice()).await.is_err());
        }
    }

    #[tokio::test]
    async fn rejected_invalid_and_cross_role_ready_replies_are_not_worker_context() {
        for reply in [
            json!({"ok":false,"context":context()}),
            json!({"ok":true}),
            json!({"ok":true,"context":{"cwd":"C:\\project","ttl_minutes":u64::MAX,"grant_mode":null,"lang":"en"}}),
            json!({"ok":true,"context":context(),"environment":{"PATH":"evil"}}),
            json!({"op":"agent-hello","protocol":1}),
        ] {
            let (mut client, mut server) = tokio::io::duplex(2048);
            let peer = tokio::spawn(async move {
                read_json(&mut server, HELLO_TIMEOUT).await.unwrap();
                write_json(&mut server, &reply).await.unwrap();
            });
            assert!(request_worker(&mut client).await.is_err());
            peer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn oversized_outgoing_frame_sends_no_partial_data() {
        let (mut client, mut server) = tokio::io::duplex(64);
        assert!(write_json(
            &mut client,
            &json!({"oversize":"x".repeat(kv_ipc::agent::MAX_LINE_BYTES)})
        )
        .await
        .is_err());
        drop(client);
        assert_eq!(
            server.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn exact_limit_frame_is_accepted_but_invalid_utf8_is_rejected() {
        let mut valid = format!("\"{}\"\n", "x".repeat(kv_ipc::agent::MAX_LINE_BYTES - 2));
        assert!(read_json(&mut valid.as_bytes(), HELLO_TIMEOUT)
            .await
            .is_ok());
        valid.insert(1, 'x');
        assert!(read_json(&mut valid.as_bytes(), HELLO_TIMEOUT)
            .await
            .is_err());
        assert!(read_json(&mut b"\"\xff\"\n".as_slice(), HELLO_TIMEOUT)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn duplicate_launch_fields_are_rejected_instead_of_taking_the_last_value() {
        for frame in [
            r#"{"op":"mcp-worker","op":"mcp-launch","protocol":1,"context":{"cwd":"C:\\project","ttl_minutes":0,"lang":"en"}}"#,
            r#"{"op":"mcp-launch","protocol":2,"protocol":1,"context":{"cwd":"C:\\project","ttl_minutes":0,"lang":"en"}}"#,
            r#"{"op":"mcp-launch","protocol":1,"context":{"cwd":"C:\\other","cwd":"C:\\project","ttl_minutes":0,"lang":"en"}}"#,
        ] {
            let frame = format!("{frame}\n");
            assert_eq!(
                read_launch(&mut frame.as_bytes()).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[tokio::test]
    async fn duplicate_worker_hello_never_receives_ready_context() {
        let (mut client, mut server) = tokio::io::duplex(512);
        client
            .write_all(b"{\"op\":\"mcp-worker\",\"protocol\":2,\"protocol\":1}\n")
            .await
            .unwrap();
        assert_eq!(
            accept_worker(&mut server, context())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        drop(server);
        assert_eq!(
            client.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn duplicate_success_or_context_in_replies_is_not_accepted() {
        let (mut client, mut server) = tokio::io::duplex(2048);
        let peer = tokio::spawn(async move {
            read_launch(&mut server).await.unwrap();
            server
                .write_all(b"{\"ok\":false,\"ok\":true}\n")
                .await
                .unwrap();
        });
        assert_eq!(
            request_launch(&mut client, context())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        peer.await.unwrap();

        for frame in [
            r#"{"ok":false,"ok":true,"context":{"cwd":"C:\\project","ttl_minutes":0,"lang":"en"}}"#,
            r#"{"ok":true,"context":{"cwd":"C:\\other","cwd":"C:\\project","ttl_minutes":0,"lang":"en"}}"#,
        ] {
            let (mut client, mut server) = tokio::io::duplex(2048);
            let peer = tokio::spawn(async move {
                read_json(&mut server, HELLO_TIMEOUT).await.unwrap();
                server
                    .write_all(format!("{frame}\n").as_bytes())
                    .await
                    .unwrap();
            });
            assert_eq!(
                request_worker(&mut client).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            peer.await.unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn continuing_partial_progress_does_not_reset_the_read_deadline() {
        let (mut client, mut server) = tokio::io::duplex(32);
        let start = tokio::time::Instant::now();
        let sender = tokio::spawn(async move {
            loop {
                client.write_all(b" ").await.unwrap();
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        assert_eq!(
            read_json(&mut server, HELLO_TIMEOUT)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(tokio::time::Instant::now() - start, HELLO_TIMEOUT);
        sender.abort();
        assert!(sender.await.unwrap_err().is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn silent_launch_and_worker_replies_have_their_own_deadlines() {
        for launching in [true, false] {
            let (mut client, mut server) = tokio::io::duplex(2048);
            let peer = tokio::spawn(async move {
                read_json(&mut server, HELLO_TIMEOUT).await.unwrap();
                std::future::pending::<()>().await;
                drop(server);
            });
            let start = tokio::time::Instant::now();
            let result = if launching {
                request_launch(&mut client, context()).await
            } else {
                request_worker(&mut client).await.map(|_| ())
            };
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
            assert_eq!(
                tokio::time::Instant::now() - start,
                if launching {
                    LAUNCH_TIMEOUT
                } else {
                    HELLO_TIMEOUT
                }
            );
            peer.abort();
            assert!(peer.await.unwrap_err().is_cancelled());
        }
    }

    #[tokio::test]
    async fn handshake_writer_handles_short_writes_and_flushes_the_complete_frame() {
        let mut writer = ProbeWriter {
            short_writes: true,
            ..Default::default()
        };
        write_json(&mut writer, &json!({"text":"项目\nline"}))
            .await
            .unwrap();
        assert_eq!(
            writer.bytes.iter().filter(|byte| **byte == b'\n').count(),
            1
        );
        assert_eq!(writer.bytes.last(), Some(&b'\n'));
        assert_eq!(
            serde_json::from_slice::<Value>(&writer.bytes).unwrap(),
            json!({"text":"项目\nline"})
        );
        assert_eq!(writer.flushes, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn handshake_deadline_includes_flush_after_a_successful_write() {
        let mut writer = ProbeWriter {
            pending_flush: true,
            ..Default::default()
        };
        assert_eq!(
            write_json(&mut writer, &json!({"ok":true}))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(writer.bytes, b"{\"ok\":true}\n");
        assert!(writer.flushes > 0);
    }

    #[tokio::test]
    async fn handshake_propagates_write_and_flush_errors() {
        for during_write in [true, false] {
            let mut writer = ProbeWriter {
                write_error: during_write.then_some(io::ErrorKind::BrokenPipe),
                flush_error: (!during_write).then_some(io::ErrorKind::ConnectionReset),
                ..Default::default()
            };
            assert_eq!(
                write_json(&mut writer, &json!({"ok":true}))
                    .await
                    .unwrap_err()
                    .kind(),
                if during_write {
                    io::ErrorKind::BrokenPipe
                } else {
                    io::ErrorKind::ConnectionReset
                }
            );
            assert_eq!(writer.bytes.is_empty(), during_write);
        }
    }

    #[tokio::test]
    async fn relay_returns_read_and_write_errors_without_waiting_for_the_other_direction() {
        let (mut service, _open_worker) = tokio::io::duplex(64);
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            relay_io(
                ErrorReader(io::ErrorKind::ConnectionReset),
                tokio::io::sink(),
                &mut service,
            ),
        )
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionReset);

        let (input, _open_input) = tokio::io::duplex(64);
        let (mut service, mut worker) = tokio::io::duplex(64);
        worker.write_all(b"reply").await.unwrap();
        let output = ProbeWriter {
            write_error: Some(io::ErrorKind::BrokenPipe),
            ..Default::default()
        };
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            relay_io(input, output, &mut service),
        )
        .await
        .unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn relay_flushes_all_buffered_output_before_returning_on_worker_eof() {
        let (input, _open_input) = tokio::io::duplex(64);
        let (mut service, mut worker) = tokio::io::duplex(64);
        let sender = tokio::spawn(async move {
            worker.write_all(&vec![0x7f; 20_000]).await.unwrap();
        });
        let mut output = Vec::new();
        {
            let buffered = tokio::io::BufWriter::with_capacity(4096, &mut output);
            tokio::time::timeout(
                Duration::from_secs(1),
                relay_io(input, buffered, &mut service),
            )
            .await
            .unwrap()
            .unwrap();
        }
        sender.await.unwrap();
        assert_eq!(output, vec![0x7f; 20_000]);
    }

    #[tokio::test]
    async fn denied_launch_without_a_reason_is_permission_denied() {
        let (mut client, mut server) = tokio::io::duplex(2048);
        let peer = tokio::spawn(async move {
            read_launch(&mut server).await.unwrap();
            write_json(&mut server, &json!({"ok":false})).await.unwrap();
        });
        assert_eq!(
            request_launch(&mut client, context())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        peer.await.unwrap();
    }
}
