//! Secret redaction, shared by the proxy (`proxy.rs`) and the local gateway (`gateway.rs`).
//! Operates on raw bytes throughout (never re-decoding as UTF-8) because HTTP response bytes may
//! not be valid UTF-8 at all, let alone mid-way through a streamed chunk -- direct port of the
//! `redact`/`redactionList`/`StreamRedactor` pieces of src/helper/http-proxy.ts and src/helper/gateway.ts.

use zeroize::{Zeroize, Zeroizing};

/// Redaction patterns contain the original credentials, not just public replacements.
pub type Redactions = Zeroizing<Vec<Vec<u8>>>;
const REPLACEMENT: &[u8] = b"[REDACTED]";

/// Builds the list of byte strings to strip from a response (each secret plus its common encoded
/// forms), longest first; matching is case-insensitive.
pub fn redaction_list(values: &[&str]) -> Redactions {
    use base64::engine::{general_purpose::STANDARD, Engine};
    let mut out = Zeroizing::new(Vec::<Vec<u8>>::new());
    for v in values {
        if v.len() < 4 {
            continue;
        }
        let json_escaped = Zeroizing::new(serde_json::to_string(v).unwrap());
        let json_escaped = &json_escaped[1..json_escaped.len() - 1]; // strip the surrounding quotes
        let percent = Zeroizing::new(percent_encode(v));
        let base64 = Zeroizing::new(STANDARD.encode(v));
        let mut forms = Zeroizing::new(vec![
            v.to_string(),
            percent.to_string(),
            percent.replace("%20", "+"), // form encoding
            json_escaped.to_string(),
            json_escaped.replace('/', "\\/"), // some JSON encoders escape /
            base64.to_string(),
            base64.trim_end_matches('=').to_string(),
            base64_url_no_pad(v),
            hex_encode(v.as_bytes()),
        ]);
        for f in forms.iter_mut() {
            if f.len() >= 4 {
                out.push(std::mem::take(f).into_bytes());
            }
        }
    }
    out.sort_unstable();
    out.dedup_by(|duplicate, previous| {
        if duplicate == previous {
            duplicate.zeroize();
            true
        } else {
            false
        }
    });
    out.sort_by_key(|b| std::cmp::Reverse(b.len()));
    out
}

fn percent_encode(s: &str) -> String {
    // Matches JS encodeURIComponent: percent-encode everything except A-Za-z0-9 and -_.!~*'()
    let mut out = String::with_capacity(s.len() * 3);
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
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(b.len() * 2);
    for byte in b {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
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
    let mut out = Zeroizing::new(s.to_vec());
    for needle in list {
        if needle.is_empty() {
            continue;
        }
        let mut positions = Vec::new();
        let mut i = 0;
        while let Some(off) = find_ci(&out[i..], needle) {
            positions.push(i + off);
            i += off + needle.len();
        }
        if positions.is_empty() {
            continue;
        }
        // Reserve the final size so reallocations never abandon a partially redacted copy.
        let capacity =
            out.len() - positions.len() * needle.len() + positions.len() * REPLACEMENT.len();
        let mut result = Zeroizing::new(Vec::with_capacity(capacity));
        let mut previous = 0;
        for pos in positions {
            result.extend_from_slice(&out[previous..pos]);
            result.extend_from_slice(REPLACEMENT);
            previous = pos + needle.len();
        }
        result.extend_from_slice(&out[previous..]);
        out = result;
    }
    std::mem::take(&mut *out)
}

pub fn contains_secret(buf: &[u8], list: &[Vec<u8>]) -> bool {
    list.iter().any(|x| find_ci(buf, x).is_some())
}

/// Streaming redaction for a forwarded response body: redacts as bytes arrive, holding back only
/// the longest possible "start of a secret" tail across chunk boundaries (not the whole chunk),
/// so output isn't needlessly delayed for the short deltas typical of LLM streaming responses.
pub struct StreamRedactor {
    carry: Zeroizing<Vec<u8>>,
    list: Redactions,
    keep: usize,
}

impl StreamRedactor {
    pub fn new(redactions: Redactions) -> Self {
        let keep = redactions
            .iter()
            .map(Vec::len)
            .max()
            .unwrap_or(0)
            .saturating_sub(1);
        Self {
            carry: Zeroizing::new(Vec::new()),
            list: redactions,
            keep,
        }
    }

    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        let mut combined = Zeroizing::new(Vec::with_capacity(self.carry.len() + chunk.len()));
        combined.extend_from_slice(&self.carry);
        self.carry.zeroize();
        combined.extend_from_slice(chunk);
        let mut s = Zeroizing::new(redact(&combined, &self.list));
        let hold = self.hold_length(&s);
        if hold > 0 {
            self.carry = Zeroizing::new(s[s.len() - hold..].to_vec());
            s[..s.len() - hold].to_vec()
        } else {
            std::mem::take(&mut *s)
        }
    }

    /// The length of the longest suffix of `s` that could be the start of an entry in `list`
    /// (case-insensitive), so it isn't emitted before we see whether it completes into a secret.
    fn hold_length(&self, s: &[u8]) -> usize {
        let max_k = self.keep.min(s.len());
        for k in (1..=max_k).rev() {
            let tail = &s[s.len() - k..];
            if self
                .list
                .iter()
                .any(|x| x.len() >= k && x[..k].eq_ignore_ascii_case(tail))
            {
                return k;
            }
        }
        0
    }

    pub fn flush(&mut self) -> Vec<u8> {
        let out = redact(&self.carry, &self.list);
        self.carry.zeroize();
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

    #[test]
    fn every_encoded_form_is_redacted_at_every_chunk_boundary() {
        fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        wipes_on_drop::<Redactions>();
        let list = redaction_list(&["sk-a/\"b?☃"]);
        for pattern in list.iter() {
            for split in 0..=pattern.len() {
                let mut redactor = StreamRedactor::new(list.clone());
                let mut out = redactor.push(&pattern[..split]);
                out.extend(redactor.push(&pattern[split..]));
                out.extend(redactor.flush());
                assert!(
                    !contains_secret(&out, &list),
                    "split at {split} of {pattern:?}"
                );
                assert!(String::from_utf8_lossy(&out).contains("[REDACTED]"));
            }
        }
    }
}
