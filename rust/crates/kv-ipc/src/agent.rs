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
}
