//! Wire protocol between the root helper daemon and the per-user agent (`kv-touchid --agent`,
//! running in the user's Aqua session). Apple does not support Secure Enclave or
//! LocalAuthentication inside a launchd daemon, so every prompt and hardware derivation goes
//! through this channel. Line-delimited JSON, max 64 KiB per line.
//!
//! agent -> daemon (first line after connect): `{"op":"agent-hello","protocol":1}`; the daemon
//! answers `{"ok":true}` only after the peer's code identity checks out, else
//! `{"ok":false,"reason":"..."}` and closes.
//!
//! daemon -> agent requests:
//!   `{"id":n,"op":"authenticate","reason":s,"cancel":s}`
//!       -> `{"id":n,"outcome":"approved"|"denied"|"unsupported"}`
//!   `{"id":n,"op":"confirm","message":s,"ok_label":s}`
//!       -> `{"id":n,"confirmed":bool}`
//!   `{"id":n,"op":"enclave","operation":"create"|"derive","reason":s,"cancel":s,
//!     "metadata":<EnclaveMetadata>|null}`
//!       -> header line `{"id":n,"ok":true,"len":N}` followed by exactly N raw bytes (kv-touchid's
//!          enclave stdout: 32-byte key + metadata JSON), or `{"id":n,"ok":false,"error":s}`.
//! N must be in 1..=8192. Both ends hold those raw bytes only in fixed `Zeroizing<[u8; 8193]>`
//! buffers -- never a growable Vec/String (same rule as kv-platform/src/enclave.rs).

use serde_json::{Map, Value};
use zeroize::Zeroizing;

pub const AGENT_PROTOCOL: u32 = 1;
/// Per-line cap for this channel (the credential protocol's 1 MiB line cap does not apply here).
pub const MAX_LINE_BYTES: usize = 64 * 1024;
/// Largest accepted enclave payload: 32-byte key + up to 8160 bytes of metadata JSON, matching
/// `EnclaveMasterKeyProvider`'s own bound.
pub const MAX_ENCLAVE_PAYLOAD: usize = 8192;
pub type EnclavePayload = Zeroizing<[u8; MAX_ENCLAVE_PAYLOAD + 1]>;

pub fn hello() -> Value {
    Value::Object(Map::from_iter([
        ("op".to_string(), Value::String("agent-hello".to_string())),
        ("protocol".to_string(), Value::from(AGENT_PROTOCOL)),
    ]))
}

/// What the daemon sends back to a hello. `reason` identifies the rejection class for the agent
/// (`not-allowed-user` means: leave stopped, this user is not the one the daemon serves).
pub fn hello_reply(ok: bool, reason: Option<&str>) -> Value {
    let mut m = Map::new();
    m.insert("ok".to_string(), Value::Bool(ok));
    if let Some(r) = reason {
        m.insert("reason".to_string(), Value::String(r.to_string()));
    }
    Value::Object(m)
}

pub fn is_valid_hello(v: &Value) -> bool {
    v.get("op").and_then(Value::as_str) == Some("agent-hello")
        && v.get("protocol").and_then(Value::as_u64) == Some(AGENT_PROTOCOL as u64)
}

pub fn request(id: u64, op: &str, fields: &[(&str, Value)]) -> Value {
    let mut m = Map::new();
    m.insert("id".to_string(), Value::from(id));
    m.insert("op".to_string(), Value::String(op.to_string()));
    for (k, v) in fields {
        m.insert((*k).to_string(), v.clone());
    }
    Value::Object(m)
}

pub fn reply(id: u64, fields: &[(&str, Value)]) -> Value {
    let mut m = Map::new();
    m.insert("id".to_string(), Value::from(id));
    for (k, v) in fields {
        m.insert((*k).to_string(), v.clone());
    }
    Value::Object(m)
}

/// The `len` field of an enclave header, validated: nonzero, capped, integer.
pub fn enclave_len(header: &Value) -> Result<usize, String> {
    if header.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(header
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("enclave request failed")
            .to_string());
    }
    match header.get("len").and_then(Value::as_u64) {
        Some(n) if n >= 1 && n <= MAX_ENCLAVE_PAYLOAD as u64 => Ok(n as usize),
        _ => Err("invalid enclave payload length".to_string()),
    }
}

/// Reads exactly `len` bytes of enclave payload into the fixed zeroizing buffer. Rejects a short
/// read (EOF / truncated) so a partial key is never returned.
pub fn read_enclave_payload(
    mut r: impl std::io::Read,
    len: usize,
) -> std::io::Result<(EnclavePayload, usize)> {
    if len == 0 || len > MAX_ENCLAVE_PAYLOAD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid enclave payload length",
        ));
    }
    let mut buf: EnclavePayload = Zeroizing::new([0u8; MAX_ENCLAVE_PAYLOAD + 1]);
    let mut filled = 0;
    while filled < len {
        match r.read(&mut buf[filled..len]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated enclave payload",
                ))
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok((buf, filled))
}

pub fn encode_line(v: &Value) -> Vec<u8> {
    let mut line = serde_json::to_vec(v).unwrap_or_default();
    line.push(b'\n');
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{self, Cursor, Read};

    #[test]
    fn hello_round_trip() {
        let h = hello();
        assert!(is_valid_hello(&h));
        assert!(!is_valid_hello(
            &json!({"op": "agent-hello", "protocol": 2})
        ));
        assert!(!is_valid_hello(&json!({"op": "x"})));
    }

    #[test]
    fn enclave_len_rejects_bad_headers() {
        assert_eq!(
            enclave_len(&json!({"id":1,"ok":true,"len":32})).unwrap(),
            32
        );
        assert!(enclave_len(&json!({"id":1,"ok":true,"len":0})).is_err());
        assert!(enclave_len(&json!({"id":1,"ok":true,"len":8193})).is_err());
        assert!(enclave_len(&json!({"id":1,"ok":true})).is_err());
        assert!(enclave_len(&json!({"id":1,"ok":false,"error":"denied"})).is_err());
    }

    #[test]
    fn payload_reads_exactly_the_declared_length() {
        let data = [7u8; 100];
        let (buf, n) = read_enclave_payload(&data[..], 100).unwrap();
        assert_eq!(n, 100);
        assert_eq!(&buf[..100], &data[..]);
    }

    #[test]
    fn payload_bounds_and_short_reads_are_rejected() {
        assert!(read_enclave_payload(&b"x"[..], 0).is_err());
        assert!(read_enclave_payload(&[0u8; 8193][..], 8193).is_err());
        // Short read: declared 64 bytes but the stream ends after 10.
        assert!(read_enclave_payload(&[1u8; 10][..], 64).is_err());
    }

    #[test]
    fn hello_rejects_type_confusion_and_protocol_overflow() {
        for protocol in [
            json!(null),
            json!(true),
            json!("1"),
            json!(1.0),
            json!(-1),
            json!(0),
            json!(u64::MAX),
        ] {
            assert!(!is_valid_hello(
                &json!({"op":"agent-hello","protocol":protocol})
            ));
        }
        for op in [
            json!(null),
            json!(1),
            json!(["agent-hello"]),
            json!("AGENT-HELLO"),
            json!("agent-hello\0"),
        ] {
            assert!(!is_valid_hello(&json!({"op":op,"protocol":1})));
        }
    }

    #[test]
    fn payload_length_requires_explicit_success_and_an_unsigned_integer() {
        for ok in [json!(null), json!("true"), json!(1), json!(false)] {
            assert!(enclave_len(&json!({"ok":ok,"len":32})).is_err());
        }
        for len in [
            json!(null),
            json!(true),
            json!("32"),
            json!(32.0),
            json!(-1),
            json!(u64::MAX),
        ] {
            assert!(enclave_len(&json!({"ok":true,"len":len})).is_err());
        }
        for len in [1, MAX_ENCLAVE_PAYLOAD] {
            assert_eq!(enclave_len(&json!({"ok":true,"len":len})).unwrap(), len);
        }
    }

    #[test]
    fn failed_payload_headers_keep_the_error_and_never_accept_the_length() {
        assert_eq!(
            enclave_len(&json!({"ok":false,"len":32,"error":"Hello cancelled"})),
            Err("Hello cancelled".into())
        );
        for error in [json!(null), json!(42), json!({"error":"denied"})] {
            assert_eq!(
                enclave_len(&json!({"ok":false,"len":32,"error":error})),
                Err("enclave request failed".into())
            );
        }
    }

    struct InterruptedFragments {
        input: Cursor<Vec<u8>>,
        calls: usize,
    }
    impl Read for InterruptedFragments {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls % 2 == 1 {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let take = buf.len().min(3);
            self.input.read(&mut buf[..take])
        }
    }

    #[test]
    fn interrupted_and_fragmented_payload_reads_retry_without_losing_bytes() {
        let data = b"\0\xff\n{\"id\":1,\"confirmed\":true}\n";
        let mut reader = InterruptedFragments {
            input: Cursor::new(data.to_vec()),
            calls: 0,
        };
        let (buf, len) = read_enclave_payload(&mut reader, data.len()).unwrap();
        assert_eq!(&buf[..len], data);
        assert!(reader.calls > data.len() / 3);
        assert!(buf[len..].iter().all(|byte| *byte == 0));
    }

    struct ErrorAfterPrefix(Cursor<Vec<u8>>);
    impl Read for ErrorAfterPrefix {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.0.read(buf)? {
                0 => Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "synthetic payload read failure",
                )),
                n => Ok(n),
            }
        }
    }

    #[test]
    fn payload_read_errors_propagate_without_returning_a_partial_key() {
        let error =
            read_enclave_payload(ErrorAfterPrefix(Cursor::new(vec![42; 10])), 32).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(error.to_string(), "synthetic payload read failure");
    }

    struct NeverRead;
    impl Read for NeverRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("an invalid declared length must not touch the reader");
        }
    }

    #[test]
    fn invalid_payload_lengths_are_rejected_before_reading() {
        for len in [0, MAX_ENCLAVE_PAYLOAD + 1, usize::MAX] {
            assert_eq!(
                read_enclave_payload(NeverRead, len).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn maximum_binary_payload_keeps_the_next_header_unread_and_sentinel_zero() {
        let data: Vec<u8> = (0..MAX_ENCLAVE_PAYLOAD).map(|i| (i % 256) as u8).collect();
        let next = encode_line(&json!({"id":2,"confirmed":false}));
        let mut input = data.clone();
        input.extend_from_slice(&next);
        let mut reader = Cursor::new(input);
        let (buf, len) = read_enclave_payload(&mut reader, MAX_ENCLAVE_PAYLOAD).unwrap();
        assert_eq!(len, MAX_ENCLAVE_PAYLOAD);
        assert_eq!(&buf[..len], data);
        assert_eq!(buf[len], 0);
        let mut remaining = Vec::new();
        reader.read_to_end(&mut remaining).unwrap();
        assert_eq!(remaining, next);
    }

    #[test]
    fn encoded_lines_cannot_split_frames_with_prompt_control_characters() {
        let request = request(
            u64::MAX,
            "confirm",
            &[
                ("message", json!("测试\r\n\0\t\"\\")),
                ("ok_label", json!("Use 🗝")),
            ],
        );
        let line = encode_line(&request);
        assert_eq!(line.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert_eq!(line.last(), Some(&b'\n'));
        assert_eq!(serde_json::from_slice::<Value>(&line).unwrap(), request);
    }
}
