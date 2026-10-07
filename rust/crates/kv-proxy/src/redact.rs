//! Secret redaction, shared by the proxy (`proxy.rs`) and the local gateway (`gateway.rs`).
//! Operates on raw bytes throughout (never re-decoding as UTF-8) because HTTP response bytes may
//! not be valid UTF-8 at all, let alone mid-way through a streamed chunk -- direct port of the
//! `redact`/`redactionList`/`StreamRedactor` pieces of src/helper/http-proxy.ts and src/helper/gateway.ts.

/// Builds the list of byte strings to strip from a response (each secret plus its common encoded
/// forms), longest first; matching is case-insensitive.
pub fn redaction_list(values: &[&str]) -> Vec<Vec<u8>> {
    use base64::engine::{general_purpose::STANDARD, Engine};
    let mut set: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    for v in values {
        if v.len() < 4 {
            continue;
        }
        let json_escaped = serde_json::to_string(v).unwrap();
        let json_escaped = &json_escaped[1..json_escaped.len() - 1]; // strip the surrounding quotes
        let percent = percent_encode(v);
        let forms: Vec<String> = vec![
            v.to_string(),
            percent.clone(),
            percent.replace("%20", "+"), // form encoding
            json_escaped.to_string(),
            json_escaped.replace('/', "\\/"), // some JSON encoders escape /
            STANDARD.encode(v),
            STANDARD.encode(v).trim_end_matches('=').to_string(),
            base64_url_no_pad(v),
            hex_encode(v.as_bytes()),
        ];
        for f in forms {
            if f.len() >= 4 {
                set.insert(f.into_bytes());
            }
        }
    }
    let mut out: Vec<Vec<u8>> = set.into_iter().collect();
    out.sort_by_key(|b| std::cmp::Reverse(b.len()));
    out
}

fn percent_encode(s: &str) -> String {
    // Matches JS encodeURIComponent: percent-encode everything except A-Za-z0-9 and -_.!~*'()
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            )
        {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn base64_url_no_pad(s: &str) -> String {
    use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(s)
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn to_lower_ascii(b: &[u8]) -> Vec<u8> {
    b.iter().map(u8::to_ascii_lowercase).collect()
}

/// Case-insensitive byte-level find of `needle` in `haystack` (ASCII-only case folding, matching
/// the original's latin1-byte-oriented approach -- the secrets being searched for are themselves
/// ASCII/UTF-8 text, not binary blobs, so ASCII case-insensitivity is the right semantics here,
/// same as the TS implementation's `i` regex flag on a latin1 byte view).
fn find_ci(haystack: &[u8], needle_lower: &[u8]) -> Option<usize> {
    if needle_lower.is_empty() || needle_lower.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle_lower.len())
        .position(|w| w.eq_ignore_ascii_case(needle_lower))
}

/// Replaces every occurrence of any entry in `list` with `[REDACTED]`, case-insensitively.
pub fn redact(s: &[u8], list: &[Vec<u8>]) -> Vec<u8> {
    let mut out = s.to_vec();
    for needle in list {
        if needle.is_empty() {
            continue;
        }
        let mut result = Vec::with_capacity(out.len());
        let mut i = 0;
        while i < out.len() {
            match find_ci(&out[i..], needle) {
                Some(off) => {
                    result.extend_from_slice(&out[i..i + off]);
                    result.extend_from_slice(b"[REDACTED]");
                    i += off + needle.len();
                }
                None => {
                    result.extend_from_slice(&out[i..]);
                    i = out.len();
                }
            }
        }
        out = result;
    }
    out
}

pub fn contains_secret(buf: &[u8], list: &[Vec<u8>]) -> bool {
    let lower = to_lower_ascii(buf);
    list.iter()
        .any(|x| find_ci(&lower, &to_lower_ascii(x)).is_some())
}

/// Streaming redaction for a forwarded response body: redacts as bytes arrive, holding back only
/// the longest possible "start of a secret" tail across chunk boundaries (not the whole chunk),
/// so output isn't needlessly delayed for the short deltas typical of LLM streaming responses.
pub struct StreamRedactor {
    carry: Vec<u8>,
    list: Vec<Vec<u8>>,
    lower_list: Vec<Vec<u8>>,
    keep: usize,
}

impl StreamRedactor {
    pub fn new(redactions: Vec<Vec<u8>>) -> Self {
        let keep = redactions
            .iter()
            .map(Vec::len)
            .max()
            .unwrap_or(0)
            .saturating_sub(1);
        let lower_list = redactions.iter().map(|x| to_lower_ascii(x)).collect();
        Self {
            carry: Vec::new(),
            list: redactions,
            lower_list,
            keep,
        }
    }

    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        let mut combined = std::mem::take(&mut self.carry);
        combined.extend_from_slice(chunk);
        let s = redact(&combined, &self.list);
        let hold = self.hold_length(&s);
        if hold > 0 {
            self.carry = s[s.len() - hold..].to_vec();
            s[..s.len() - hold].to_vec()
        } else {
            s
        }
    }

    /// The length of the longest suffix of `s` that could be the start of an entry in `list`
    /// (case-insensitive), so it isn't emitted before we see whether it completes into a secret.
    fn hold_length(&self, s: &[u8]) -> usize {
        let lower = to_lower_ascii(s);
        let max_k = self.keep.min(s.len());
        for k in (1..=max_k).rev() {
            let tail = &lower[lower.len() - k..];
            if self.lower_list.iter().any(|x| x.starts_with(tail)) {
                return k;
            }
        }
        0
    }

    pub fn flush(&mut self) -> Vec<u8> {
        let out = redact(&self.carry, &self.list);
        self.carry.clear();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_the_secret_and_its_common_encodings() {
        let list = redaction_list(&["sk-SECRET1234"]);
        let hit = |s: &str| redact(s.as_bytes(), &list) == b"[REDACTED]".to_vec();
        assert!(hit("sk-SECRET1234"));
        assert!(hit("SK-secret1234"), "case-insensitive");
        assert!(hit("sk-SECRET1234".to_uppercase().as_str()));
        let encoded = redaction_list(&["sk-SECRET1234"]);
        let b64 = base64_url_no_pad("sk-SECRET1234");
        assert_eq!(redact(b64.as_bytes(), &encoded), b"[REDACTED]".to_vec());
    }

    #[test]
    fn values_under_four_chars_are_not_redacted_to_avoid_mass_false_positives() {
        assert!(redaction_list(&["abc"]).is_empty());
    }

    #[test]
    fn contains_secret_detects_case_insensitively() {
        let list = redaction_list(&["sk-SECRET1234"]);
        assert!(contains_secret(b"prefix SK-secret1234 suffix", &list));
        assert!(!contains_secret(b"nothing here", &list));
    }

    #[test]
    fn stream_redactor_holds_back_a_secret_split_across_chunks() {
        let list = redaction_list(&["sk-abcdefgh"]);
        let mut r = StreamRedactor::new(list);
        let mut out = Vec::new();
        out.extend(r.push(b"hello sk-abcd"));
        out.extend(r.push(b"efgh world"));
        out.extend(r.flush());
        assert_eq!(out, b"hello [REDACTED] world");
    }

    #[test]
    fn stream_redactor_flush_emits_a_held_back_non_secret_tail() {
        let list = redaction_list(&["sk-abcdefgh"]);
        let mut r = StreamRedactor::new(list);
        let mut out = Vec::new();
        out.extend(r.push(b"ends with sk-ab")); // looks like it could start a secret
        out.extend(r.flush()); // ...but never completes
        assert_eq!(out, b"ends with sk-ab");
    }
}
