//! What the per-use prompt says about a proxied request body. For hosts in `RULES` the prompt
//! shows business-meaningful fields from a root-side whitelist (model, amount, channel, ...)
//! instead of an arbitrary body preview, so secrets embedded in the body never reach the Touch
//! ID sheet. The table lives here in kv-core -- not in `templates/catalog.json`, which the
//! unprivileged MCP server also reads and which is not in root's trust chain (see the comment
//! on `TEMPLATES_DIR` in `kv-platform/src/paths.rs`).

use crate::prompt::{shorten, single_line};

/// What one request body contributes to the prompt.
#[derive(Debug, PartialEq, Eq)]
pub enum BodyLine {
    /// No body line at all.
    None,
    /// Whitelisted `key=value` pairs joined for display.
    Summary(String),
    /// A known host whose body carried nothing whitelisted: show only the size.
    SizeOnly(usize),
    /// Unknown host: the raw preview, rendered by `prompt::http_request` as before.
    Preview(String),
}

struct Rule {
    /// Matches `host` itself and any subdomain of it.
    host_suffix: &'static str,
    /// Top-level body keys shown as `field=value`, in this order.
    fields: &'static [&'static str],
    /// Request headers shown as `label=<header value>` before the body fields.
    header_fields: &'static [(&'static str, &'static str)],
}

const RULES: &[Rule] = &[
    Rule {
        host_suffix: "api.openai.com",
        fields: &["model", "stream", "n", "size", "voice", "purpose"],
        header_fields: &[],
    },
    Rule {
        host_suffix: "api.anthropic.com",
        fields: &["model", "max_tokens", "stream"],
        header_fields: &[],
    },
    Rule {
        host_suffix: "api.github.com",
        fields: &[
            "name",
            "ref",
            "sha",
            "base",
            "head",
            "state",
            "private",
            "visibility",
            "permission",
            "title",
        ],
        header_fields: &[],
    },
    Rule {
        host_suffix: "api.stripe.com",
        fields: &[
            "amount", "currency", "customer", "price", "quantity", "status", "limit",
        ],
        header_fields: &[],
    },
    Rule {
        host_suffix: "slack.com",
        fields: &["channel", "user", "name", "limit", "text"],
        header_fields: &[],
    },
    Rule {
        host_suffix: "amazonaws.com",
        fields: &["Action"],
        header_fields: &[("x-amz-target", "target")],
    },
];

/// Names a whitelist entry must never coincide with (checked case-insensitively in tests) --
/// anything resembling a credential must stay out of the prompt even if a service names a
/// business field after it.
#[cfg(test)]
const NEVER: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "key",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "session",
    "private_key",
    "client_secret",
    "refresh_token",
    "access_token",
    "card",
    "cvc",
    "number",
    "ssn",
    "email",
];

/// Whether `host` has a summarization rule (exact match or subdomain, case-insensitive).
pub fn has_rule(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    RULES
        .iter()
        .any(|r| host == r.host_suffix || host.ends_with(&format!(".{}", r.host_suffix)))
}

/// A minimal `application/x-www-form-urlencoded` percent-decoder: `+` is a space, `%XX` is the
/// byte; invalid escapes are left as-is.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 3 <= bytes.len() => {
                let hex = |b: u8| -> Option<u8> {
                    match b {
                        b'0'..=b'9' => Some(b - b'0'),
                        b'a'..=b'f' => Some(b - b'a' + 10),
                        b'A'..=b'F' => Some(b - b'A' + 10),
                        _ => None,
                    }
                };
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push(hi << 4 | lo);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The part of a form key a whitelist field is compared against: the full key, or -- for
/// bracketed keys like `line_items[0][price]` -- the last bracket segment.
fn key_match(key: &str, field: &str) -> bool {
    if key == field {
        return true;
    }
    key.rsplit('[')
        .next()
        .and_then(|seg| seg.strip_suffix(']'))
        .is_some_and(|seg| seg == field)
}

/// One display pair, cleaned to a single line and shortened for the sheet.
fn pair(label: &str, value: &str) -> String {
    format!("{}={}", label, shorten(&single_line(value), 40))
}

/// Decides what the per-use prompt says about a request body for `host`.
pub fn body_line(host: &str, headers: &[(String, String)], body: Option<&str>) -> BodyLine {
    let host = host.to_ascii_lowercase();
    let Some(rule) = RULES
        .iter()
        .find(|r| host == r.host_suffix || host.ends_with(&format!(".{}", r.host_suffix)))
    else {
        return match body.filter(|b| !b.is_empty()) {
            Some(b) => BodyLine::Preview(b.to_string()),
            None => BodyLine::None,
        };
    };

    let mut pairs: Vec<String> = Vec::new();
    for (header_name, label) in rule.header_fields {
        if let Some((_, v)) = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(header_name))
        {
            pairs.push(pair(label, v));
        }
    }

    let body = body.unwrap_or_default();
    let trimmed = body.trim_start();
    if let Some(obj) = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.as_object().cloned())
    {
        for field in rule.fields {
            if let Some(v) = obj.get(*field) {
                let s = match v {
                    serde_json::Value::String(s) => Some(s.clone()),
                    serde_json::Value::Number(n) => Some(n.to_string()),
                    serde_json::Value::Bool(b) => Some(b.to_string()),
                    _ => None,
                };
                if let Some(s) = s {
                    pairs.push(pair(field, &s));
                }
            }
        }
    } else if !trimmed.is_empty() && !trimmed.starts_with('{') && !trimmed.starts_with('[') {
        let entries: Vec<(String, String)> = body
            .split('&')
            .filter_map(|kv| {
                let (k, v) = kv.split_once('=')?;
                Some((percent_decode(k), percent_decode(v)))
            })
            .collect();
        for field in rule.fields {
            if let Some((_, v)) = entries.iter().find(|(k, _)| key_match(k, field)) {
                pairs.push(pair(field, v));
            }
        }
    }

    if !pairs.is_empty() {
        BodyLine::Summary(pairs.join(" · "))
    } else if !body.is_empty() {
        BodyLine::SizeOnly(body.len())
    } else {
        BodyLine::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary_of(line: BodyLine) -> String {
        match line {
            BodyLine::Summary(s) => s,
            other => panic!("expected Summary, got {other:?}"),
        }
    }

    #[test]
    fn openai_body_shows_model_and_stream_but_never_message_content() {
        let body = r#"{"model":"gpt-5","messages":[{"role":"user","content":"my password is hunter2"}],"stream":true}"#;
        let s = summary_of(body_line("api.openai.com", &[], Some(body)));
        assert_eq!(s, "model=gpt-5 · stream=true");
        assert!(!s.contains("hunter2"));
        assert!(!s.contains("messages"));
    }

    #[test]
    fn anthropic_body_shows_model_and_max_tokens_but_not_the_system_prompt() {
        let body =
            r#"{"model":"claude-4","max_tokens":1024,"system":"the api key is sk-ant-secret"}"#;
        let s = summary_of(body_line("api.anthropic.com", &[], Some(body)));
        assert_eq!(s, "model=claude-4 · max_tokens=1024");
        assert!(!s.contains("sk-ant-secret"));
    }

    #[test]
    fn stripe_form_shows_business_fields_but_never_card_or_token_values() {
        let body = "amount=2000&currency=usd&source=tok_visa&card[number]=4242424242424242&metadata[password]=p4ss&line_items[0][price]=price_123";
        let s = summary_of(body_line("api.stripe.com", &[], Some(body)));
        assert_eq!(s, "amount=2000 · currency=usd · price=price_123");
        assert!(!s.contains("4242"));
        assert!(!s.contains("tok_visa"));
        assert!(!s.contains("p4ss"));
    }

    #[test]
    fn slack_json_never_shows_the_token() {
        let body = r#"{"channel":"C123","text":"deploy done","token":"xoxb-1-2-3"}"#;
        let s = summary_of(body_line("slack.com", &[], Some(body)));
        assert_eq!(s, "channel=C123 · text=deploy done");
        assert!(!s.contains("xoxb"));
    }

    #[test]
    fn github_json_shows_repo_fields() {
        let body = r#"{"name":"repo","private":true,"description":"d"}"#;
        let s = summary_of(body_line("api.github.com", &[], Some(body)));
        assert_eq!(s, "name=repo · private=true");
        assert!(!s.contains("description"));
    }

    #[test]
    fn aws_form_and_target_header_are_summarized() {
        let s = summary_of(body_line(
            "iam.amazonaws.com",
            &[],
            Some("Action=CreateAccessKey&UserName=bob"),
        ));
        assert_eq!(s, "Action=CreateAccessKey");
        assert!(!s.contains("bob"));

        let s = summary_of(body_line(
            "dynamodb.us-east-1.amazonaws.com",
            &[("X-Amz-Target".into(), "DynamoDB_20120810.Query".into())],
            Some(r#"{"TableName":"t"}"#),
        ));
        assert_eq!(s, "target=DynamoDB_20120810.Query");
        assert!(!s.contains("TableName"));
    }

    #[test]
    fn unknown_hosts_keep_the_raw_preview() {
        let body = r#"{"model":"gpt-5","anything":"secret-ish"}"#;
        assert_eq!(
            body_line("example.com", &[], Some(body)),
            BodyLine::Preview(body.to_string())
        );
        assert_eq!(body_line("example.com", &[], None), BodyLine::None);
        assert_eq!(body_line("example.com", &[], Some("")), BodyLine::None);
    }

    #[test]
    fn known_hosts_with_nothing_whitelisted_show_only_the_size() {
        assert_eq!(
            body_line("api.openai.com", &[], Some(r#"{"foo":"bar"}"#)),
            BodyLine::SizeOnly(13)
        );
        // A whitelisted name nested inside an object is not a top-level key.
        assert_eq!(
            body_line("api.openai.com", &[], Some(r#"{"metadata":{"model":"x"}}"#)),
            BodyLine::SizeOnly(26)
        );
        // Non-scalar values are skipped even for whitelisted keys.
        assert_eq!(
            body_line("api.openai.com", &[], Some(r#"{"model":["a"]}"#)),
            BodyLine::SizeOnly(15)
        );
        // Nothing whitelisted and no body at all.
        assert_eq!(body_line("api.openai.com", &[], None), BodyLine::None);
    }

    #[test]
    fn values_are_shortened_to_forty_chars() {
        let body = format!(r#"{{"channel":"C1","text":"{}"}}"#, "x".repeat(100));
        let s = summary_of(body_line("slack.com", &[], Some(&body)));
        let value = s.split("text=").nth(1).unwrap();
        assert_eq!(value.chars().count(), 40);
        assert!(value.ends_with('…'));
    }

    #[test]
    fn host_suffix_matching_covers_subdomains_and_case_only() {
        assert!(has_rule("bedrock-runtime.us-east-1.amazonaws.com"));
        assert!(has_rule("API.OPENAI.COM"));
        assert!(has_rule("api.slack.com"));
        assert!(!has_rule("api.openai.com.evil.example"));
        assert!(!has_rule("example.com"));
    }

    #[test]
    fn form_values_are_percent_decoded() {
        let s = summary_of(body_line(
            "slack.com",
            &[],
            Some("text=hello+world%21&channel=C%31"),
        ));
        assert_eq!(s, "channel=C1 · text=hello world!");
    }

    #[test]
    fn the_whitelist_never_names_a_secret_and_hosts_are_lowercase() {
        for rule in RULES {
            assert_eq!(
                rule.host_suffix,
                rule.host_suffix.to_ascii_lowercase(),
                "{} must be lowercase",
                rule.host_suffix
            );
            for entry in rule
                .fields
                .iter()
                .copied()
                .chain(rule.header_fields.iter().map(|(n, _)| *n))
                .chain(rule.header_fields.iter().map(|(_, l)| *l))
            {
                assert!(
                    !NEVER.contains(&entry.to_ascii_lowercase().as_str()),
                    "{entry} must not be a secret-ish name"
                );
            }
        }
    }
}
