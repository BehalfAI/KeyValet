//! Per-user LaunchAgent mode (`kv-touchid --agent`). The launchd daemon cannot use
//! LocalAuthentication or the Secure Enclave, so this process connects out to
//! `AGENT_SOCKET`, identifies itself by code signature (the daemon verifies it), and serves
//! authenticate/confirm/enclave requests by spawning the same children the root helper used to
//! spawn -- now already running as the user, so no privilege dropping. It never listens on any
//! socket.

use kv_ipc::agent as wire;
use kv_platform::macos::USER_CONFIRM_SCRIPT;
use kv_platform::paths::{AGENT_SOCKET, OSASCRIPT_BIN, TOUCHID_BIN};
use kv_platform::trust::untrusted_reason;
use serde_json::{json, Value};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const AUTH_TIMEOUT: Duration = Duration::from_millis(120_000);
const CONFIRM_TIMEOUT: Duration = Duration::from_millis(130_000);

pub struct RunOut {
    pub code: Option<i32>,
    /// Child stdout, bounded -- only the enclave child produces output.
    pub stdout: Vec<u8>,
    /// Only read by the test fake's `run_capture`; the real runner reports timeout separately.
    #[allow(dead_code)]
    pub timed_out: bool,
}

/// Injectable so the request-handling logic is testable without spawning real children.
pub trait Runner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        input: Option<&[u8]>,
        timeout: Duration,
    ) -> io::Result<RunOut>;
    /// `run` for outputs that are secrets: the child's stdout goes into a fixed caller-provided
    /// buffer (which the caller zeroizes), never a growable Vec. Returns (exit code, bytes
    /// captured, timed out). A reader thread drains the pipe so a large output can't deadlock it.
    fn run_capture(
        &self,
        program: &str,
        args: &[&str],
        input: Option<&[u8]>,
        timeout: Duration,
        buf: &mut [u8],
    ) -> io::Result<(Option<i32>, usize, bool)>;
}

pub struct ProcessRunner;

impl Runner for ProcessRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        input: Option<&[u8]>,
        timeout: Duration,
    ) -> io::Result<RunOut> {
        let mut child = Command::new(program)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .current_dir("/")
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        if let (Some(bytes), Some(mut stdin)) = (input, child.stdin.take()) {
            let _ = stdin.write_all(bytes);
            // Closing stdin is required for kv-touchid's enclave mode to start outputting.
            drop(stdin);
        }
        run_with_timeout(&mut child, timeout)
    }
    fn run_capture(
        &self,
        program: &str,
        args: &[&str],
        input: Option<&[u8]>,
        timeout: Duration,
        buf: &mut [u8],
    ) -> io::Result<(Option<i32>, usize, bool)> {
        let mut child = Command::new(program)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .current_dir("/")
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        if let (Some(bytes), Some(mut stdin)) = (input, child.stdin.take()) {
            let _ = stdin.write_all(bytes);
            drop(stdin);
        }
        std::thread::scope(|scope| {
            let mut out = child.stdout.take().unwrap();
            let drain = scope.spawn(move || -> io::Result<usize> {
                let mut filled = 0;
                while filled < buf.len() {
                    match out.read(&mut buf[filled..]) {
                        Ok(0) => break,
                        Ok(n) => filled += n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(e),
                    }
                }
                Ok(filled)
            });
            let deadline = Instant::now() + timeout;
            let mut timed_out = false;
            let code = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break status.code(),
                    Ok(None) if Instant::now() >= deadline => {
                        timed_out = true;
                        let _ = child.kill();
                        let _ = child.wait();
                        break None;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                    Err(_) => break None,
                }
            };
            let filled = drain.join().unwrap_or(Ok(0))?;
            Ok((code, filled, timed_out))
        })
    }
}

fn run_with_timeout(child: &mut Child, timeout: Duration) -> io::Result<RunOut> {
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let code = loop {
        match child.try_wait()? {
            Some(status) => break status.code(),
            None if Instant::now() >= deadline => {
                timed_out = true;
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    let mut stdout = Vec::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_end(&mut stdout);
    }
    Ok(RunOut {
        code,
        stdout,
        timed_out,
    })
}

fn checked(program: &str) -> io::Result<()> {
    if let Some(reason) = untrusted_reason(Path::new(program)) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{program} is untrusted: {reason}"),
        ));
    }
    Ok(())
}

/// Handles one daemon request line; returns the reply line to send, optionally followed by a
/// binary payload (enclave output).
pub fn handle_request(
    v: &Value,
    runner: &dyn Runner,
) -> (Value, Option<(wire::EnclavePayload, usize)>) {
    let id = v.get("id").and_then(Value::as_u64).unwrap_or(0);
    match v.get("op").and_then(Value::as_str) {
        Some("authenticate") => {
            let reason = s(v, "reason");
            let cancel = s(v, "cancel");
            if checked(TOUCHID_BIN).is_err() {
                return (wire::reply(id, &[("outcome", json!("denied"))]), None);
            }
            let outcome = match runner.run(TOUCHID_BIN, &[&reason, &cancel], None, AUTH_TIMEOUT) {
                Ok(out) => match out.code {
                    Some(0) => "approved",
                    Some(2) => "unsupported",
                    _ => "denied",
                },
                Err(_) => "denied",
            };
            (wire::reply(id, &[("outcome", json!(outcome))]), None)
        }
        Some("confirm") => {
            let message = s(v, "message");
            let ok_label = s(v, "ok_label");
            let title = kv_i18n::t("KeyValet · 安全确认", "KeyValet · Security Confirmation");
            let deny = kv_i18n::t("拒绝", "Deny");
            if checked(OSASCRIPT_BIN).is_err() {
                return (wire::reply(id, &[("confirmed", json!(false))]), None);
            }
            let args = [
                "-e",
                USER_CONFIRM_SCRIPT,
                "--",
                &message,
                &title,
                &ok_label,
                &deny,
            ];
            let confirmed = runner
                .run(OSASCRIPT_BIN, &args, None, CONFIRM_TIMEOUT)
                .map(|out| {
                    out.code == Some(0) && String::from_utf8_lossy(&out.stdout).trim() == ok_label
                })
                .unwrap_or(false);
            (wire::reply(id, &[("confirmed", json!(confirmed))]), None)
        }
        Some("enclave") => {
            let operation = s(v, "operation");
            if operation != "create" && operation != "derive" {
                return (
                    wire::reply(
                        id,
                        &[("ok", json!(false)), ("error", json!("invalid operation"))],
                    ),
                    None,
                );
            }
            let reason = s(v, "reason");
            let cancel = s(v, "cancel");
            if checked(TOUCHID_BIN).is_err() {
                return (
                    wire::reply(
                        id,
                        &[
                            ("ok", json!(false)),
                            ("error", json!("kv-touchid is untrusted")),
                        ],
                    ),
                    None,
                );
            }
            let metadata = v.get("metadata").cloned().unwrap_or(Value::Null);
            let input = if metadata.is_null() {
                None
            } else {
                Some(serde_json::to_vec(&metadata).unwrap_or_default())
            };
            // Key bytes land in a fixed zeroizing buffer, never a growable Vec.
            let mut payload: wire::EnclavePayload =
                Zeroizing::new([0u8; wire::MAX_ENCLAVE_PAYLOAD + 1]);
            match runner.run_capture(
                TOUCHID_BIN,
                &["--enclave", &operation, &reason, &cancel],
                input.as_deref(),
                AUTH_TIMEOUT,
                &mut payload[..],
            ) {
                // The buffer is one byte larger than the limit: 8193 captured bytes mean the
                // child overflowed, not that it happened to emit exactly the maximum.
                Ok((Some(0), n, _)) if (1..=wire::MAX_ENCLAVE_PAYLOAD).contains(&n) => (
                    wire::reply(id, &[("ok", json!(true)), ("len", json!(n))]),
                    Some((payload, n)),
                ),
                Ok((_, _, timed_out)) => (
                    wire::reply(
                        id,
                        &[
                            ("ok", json!(false)),
                            (
                                "error",
                                json!(if timed_out {
                                    "timed out"
                                } else {
                                    "enclave failed"
                                }),
                            ),
                        ],
                    ),
                    None,
                ),
                Err(e) => (
                    wire::reply(id, &[("ok", json!(false)), ("error", json!(e.to_string()))]),
                    None,
                ),
            }
        }
        _ => (
            wire::reply(id, &[("ok", json!(false)), ("error", json!("unknown op"))]),
            None,
        ),
    }
}

fn s(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn read_line_capped(reader: &mut impl BufRead) -> io::Result<Option<String>> {
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => Ok(None),
        Ok(_) => {
            if line.len() > wire::MAX_LINE_BYTES {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "line too large"));
            }
            Ok(Some(line.trim().to_string()))
        }
        Err(e) => Err(e),
    }
}

fn serve(reader: &mut impl BufRead, writer: &mut UnixStream) -> io::Result<()> {
    let runner = ProcessRunner;
    while let Some(line) = read_line_capped(reader)? {
        let Ok(v) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let (reply, payload) = handle_request(&v, &runner);
        writer.write_all(&wire::encode_line(&reply))?;
        if let Some((buf, len)) = payload {
            writer.write_all(&buf[..len])?;
        }
        writer.flush()?;
    }
    Ok(())
}

/// Entry point for `--agent`. Exits 0 only when the daemon says this user isn't served
/// (`not-allowed-user`) -- the plist's `KeepAlive {SuccessfulExit: false}` keeps it stopped then.
/// Any other end (socket missing, daemon restart) reconnects with backoff.
pub fn run() -> i32 {
    let mut backoff = Duration::from_secs(1);
    loop {
        match UnixStream::connect(AGENT_SOCKET) {
            Ok(stream) => {
                match kv_platform::peer::peer_uid(std::os::unix::io::AsRawFd::as_raw_fd(&stream)) {
                    Ok(0) => {}
                    _ => {
                        // The daemon socket must be root-owned; anything else is wrong.
                        std::thread::sleep(backoff);
                        continue;
                    }
                }
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut writer = stream;
                if writer
                    .write_all(&wire::encode_line(&wire::hello()))
                    .is_err()
                {
                    std::thread::sleep(backoff);
                    continue;
                }
                let first = match read_line_capped(&mut reader) {
                    Ok(Some(line)) => line,
                    _ => {
                        std::thread::sleep(backoff);
                        continue;
                    }
                };
                let ok = serde_json::from_str::<Value>(&first)
                    .ok()
                    .and_then(|v| v.get("ok").and_then(Value::as_bool))
                    .unwrap_or(false);
                if !ok {
                    let reason = serde_json::from_str::<Value>(&first)
                        .ok()
                        .and_then(|v| v.get("reason").and_then(Value::as_str).map(String::from))
                        .unwrap_or_default();
                    if reason == "not-allowed-user" {
                        return 0;
                    }
                    std::thread::sleep(backoff);
                    continue;
                }
                backoff = Duration::from_secs(1);
                let _ = serve(&mut reader, &mut writer);
            }
            Err(_) => std::thread::sleep(backoff),
        }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    struct Fake {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        code: Option<i32>,
        stdout: Vec<u8>,
    }
    impl Runner for Fake {
        fn run(
            &self,
            program: &str,
            args: &[&str],
            _input: Option<&[u8]>,
            _timeout: Duration,
        ) -> io::Result<RunOut> {
            self.calls.lock().unwrap().push((
                program.to_string(),
                args.iter().map(|s| s.to_string()).collect(),
            ));
            Ok(RunOut {
                code: self.code,
                stdout: self.stdout.clone(),
                timed_out: false,
            })
        }
        fn run_capture(
            &self,
            program: &str,
            args: &[&str],
            input: Option<&[u8]>,
            timeout: Duration,
            buf: &mut [u8],
        ) -> io::Result<(Option<i32>, usize, bool)> {
            let out = self.run(program, args, input, timeout)?;
            let n = out.stdout.len();
            if n <= buf.len() {
                buf[..n].copy_from_slice(&out.stdout[..n]);
            }
            Ok((out.code, n, out.timed_out))
        }
    }

    #[test]
    fn authenticate_maps_exit_codes_to_outcomes() {
        for (code, want) in [
            (Some(0), "approved"),
            (Some(1), "denied"),
            (Some(2), "unsupported"),
            (None, "denied"),
        ] {
            let fake = Fake {
                calls: Mutex::new(vec![]),
                code,
                stdout: vec![],
            };
            let (reply, payload) = handle_request(
                &json!({"id": 7, "op": "authenticate", "reason": "r", "cancel": "c"}),
                &fake,
            );
            assert_eq!(reply["outcome"], json!(want), "code {code:?}");
            assert_eq!(reply["id"], json!(7));
            assert!(payload.is_none());
        }
    }

    #[test]
    fn enclave_reply_is_a_header_plus_the_raw_payload() {
        let fake = Fake {
            calls: Mutex::new(vec![]),
            code: Some(0),
            stdout: vec![9u8; 64],
        };
        let (reply, payload) = handle_request(
            &json!({"id": 3, "op": "enclave", "operation": "derive", "reason": "r", "cancel": "c", "metadata": {"version":1}}),
            &fake,
        );
        assert_eq!(reply, json!({"id": 3, "ok": true, "len": 64}));
        let (buf, len) = payload.unwrap();
        assert_eq!(&buf[..len], &[9u8; 64]);
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls[0].0, TOUCHID_BIN);
        assert_eq!(calls[0].1[..2], ["--enclave", "derive"]);
    }

    #[test]
    fn enclave_failures_and_oversized_payloads_are_errors() {
        let fake = Fake {
            calls: Mutex::new(vec![]),
            code: Some(1),
            stdout: vec![],
        };
        let (reply, payload) = handle_request(
            &json!({"id": 1, "op": "enclave", "operation": "create", "reason": "r", "cancel": "c", "metadata": null}),
            &fake,
        );
        assert_eq!(reply["ok"], json!(false));
        assert!(payload.is_none());

        let huge = Fake {
            calls: Mutex::new(vec![]),
            code: Some(0),
            stdout: vec![0u8; wire::MAX_ENCLAVE_PAYLOAD + 1],
        };
        let (reply, _) = handle_request(
            &json!({"id": 1, "op": "enclave", "operation": "create", "reason": "r", "cancel": "c", "metadata": null}),
            &huge,
        );
        assert_eq!(reply["ok"], json!(false));
    }
}
