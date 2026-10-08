//! Canonical digest of the HTTP-shaped fields of a request. Used to cryptographically bind a
//! Touch ID approval to the exact request it was shown for, not just to the credential's name.
//!
//! Lives in `kv-ipc` (not `kv-core`) because both sides of the privilege boundary need the same
//! function: `kv-mcp` computes it client-side from the request it's about to retry, attaches it
//! to the `grant` call; `kv-core::dispatch` recomputes it server-side from the request that's
//! actually about to execute and rejects a mismatch. Identical logic on both sides, not just
//! identical output, is the point -- a second implementation that merely agrees today is a second
//! place for the two to quietly drift apart later.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// The fields of a request params map that are part of what gets sent over the wire to the
/// credential's host, in the order they're folded into the digest. `type`/`name`/`purpose` and
/// the display-only `request_hint` are deliberately excluded: they identify or explain the
/// request, they aren't part of it.
const DIGESTED_FIELDS: [&str; 5] = ["method", "url", "query", "headers", "body"];

/// Recursively sorts object keys (RFC 8785 JSON Canonicalization Scheme, restricted to what
/// `serde_json::Value` can represent -- `serde_json`'s own number/string formatting already
/// matches JCS, so key order is the one rule that doesn't already hold).
fn canonicalize(v: &Value) -> Value {
    match v {
        Value::Object(obj) => {
            let mut sorted: Vec<_> = obj.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            Value::Object(
                sorted
                    .into_iter()
                    .map(|(k, v)| (k.clone(), canonicalize(v)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `None` if `p` has no `url` field -- i.e. this isn't an HTTP-shaped request (`get`/`totp`/`aws`/
/// etc. have nothing here to bind to; grant checks for those fall back to the credential name
/// alone, as before this existed).
pub fn request_digest(p: &Map<String, Value>) -> Option<String> {
    p.get("url")?;
    let subset: Map<String, Value> = DIGESTED_FIELDS
        .iter()
        .filter_map(|&field| p.get(field).map(|v| (field.to_string(), v.clone())))
        .collect();
    let canon = canonicalize(&Value::Object(subset));
    let bytes = serde_json::to_vec(&canon).expect("serializing a Value never fails");
    Some(hex(&Sha256::digest(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn params(method: &str, url: &str, body: Value) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("type".into(), json!("openai"));
        m.insert("name".into(), json!("default"));
        m.insert("purpose".into(), json!("summarize a doc"));
        m.insert("method".into(), json!(method));
        m.insert("url".into(), json!(url));
        m.insert("body".into(), body);
        m
    }

    #[test]
    fn the_same_request_digests_the_same_twice() {
        let p = params(
            "POST",
            "https://api.openai.com/v1/chat/completions",
            json!({"model": "gpt-5"}),
        );
        assert_eq!(request_digest(&p), request_digest(&p));
    }

    #[test]
    fn key_order_in_the_body_does_not_change_the_digest() {
        let a = params("POST", "https://x/y", json!({"a": 1, "b": 2}));
        let b = params("POST", "https://x/y", json!({"b": 2, "a": 1}));
        assert_eq!(request_digest(&a), request_digest(&b));
    }

    #[test]
    fn fields_outside_the_digested_set_do_not_change_it() {
        let mut a = params("POST", "https://x/y", json!({"a": 1}));
        let mut b = a.clone();
        a.insert("purpose".into(), json!("summarize a doc"));
        b.insert("purpose".into(), json!("something else entirely"));
        assert_eq!(request_digest(&a), request_digest(&b));
    }

    #[test]
    fn a_different_body_digests_differently() {
        let a = params("POST", "https://x/y", json!({"amount": 100}));
        let b = params("POST", "https://x/y", json!({"amount": 100_000}));
        assert_ne!(request_digest(&a), request_digest(&b));
    }

    #[test]
    fn a_different_method_digests_differently() {
        let a = params("GET", "https://x/y", Value::Null);
        let b = params("DELETE", "https://x/y", Value::Null);
        assert_ne!(request_digest(&a), request_digest(&b));
    }

    #[test]
    fn a_different_url_digests_differently() {
        let a = params("GET", "https://x/y", Value::Null);
        let b = params("GET", "https://x/z", Value::Null);
        assert_ne!(request_digest(&a), request_digest(&b));
    }

    #[test]
    fn non_http_shaped_params_have_no_digest() {
        let mut p = Map::new();
        p.insert("type".into(), json!("totp"));
        p.insert("name".into(), json!("default"));
        assert_eq!(request_digest(&p), None);
    }
}
