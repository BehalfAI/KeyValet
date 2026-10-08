//! KeyValet hook for agent coding runtimes (Claude Code, Codex, …): notices secrets so they end
//! up in KeyValet instead of the chat, files or shell.
//!
//! Direct port of `claude-plugin/hooks/secrets.mjs`, which this binary replaces as the thing the
//! Claude Code plugin (and, best-effort, Codex) actually invokes. Two modes, same contract as the
//! JS version:
//!
//!   kv-hook prompt   UserPromptSubmit: the user pasted a key -> tell the agent to store it in
//!                    KeyValet.
//!   kv-hook tool     PreToolUse (Write/Edit/MultiEdit/NotebookEdit/Bash): a literal key is about
//!                    to be written to a file or a command -> ask the user first and point the
//!                    agent to KeyValet.
//!
//! "tool" mode also catches secrets KeyValet already handed the agent this session
//! (`credential_get` / `credential_totp_code` / `credential_access_token` /
//! `credential_aws_credentials` record what they returned in `~/.keyvalet/run/*.redact`) by exact
//! match -- this does not rely on the value looking like a known key format, unlike `PATTERNS`.
//!
//! Never prints the secret itself (only a masked preview). `KEYVALET_HOOKS=off` disables it.

use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// A known key format -> KeyValet template. Order matters: more specific prefixes are listed
/// before broader, more ambiguous ones, and a pattern that matches first "claims" that text so a
/// later, broader pattern doesn't also report it (see `detect`).
struct Pattern {
    id: &'static str,
    label: &'static str,
    re: &'static str,
    /// The match alone doesn't confirm it's this exact service (e.g. any `sk-...` could be a
    /// dozen different providers) -- still worth flagging, just say so.
    ambiguous: bool,
    /// Store it with a different tool than the default `credential_set` (e.g. AWS needs a key
    /// pair, not a single value).
    tool: Option<&'static str>,
    /// Skip the `looks_random` entropy/placeholder check -- e.g. a PEM header is unambiguously a
    /// real secret marker regardless of what follows it.
    no_entropy: bool,
}

const fn pat(id: &'static str, label: &'static str, re: &'static str) -> Pattern {
    Pattern {
        id,
        label,
        re,
        ambiguous: false,
        tool: None,
        no_entropy: false,
    }
}

/// Known key formats, in the same order and with the same intent as `secrets.mjs`'s `PATTERNS`.
fn patterns() -> Vec<Pattern> {
    vec![
        pat(
            "anthropic",
            "Anthropic API key",
            r"sk-ant-[A-Za-z0-9_-]{32,}",
        ),
        pat(
            "openrouter",
            "OpenRouter API key",
            r"sk-or-v1-[A-Za-z0-9]{40,}",
        ),
        pat(
            "openai",
            "OpenAI API key",
            r"sk-(?:proj-|svcacct-|admin-)[A-Za-z0-9_-]{20,}",
        ),
        Pattern {
            ambiguous: true,
            ..pat(
                "openai",
                "OpenAI-style API key (OpenAI, DeepSeek, …)",
                r"\bsk-[A-Za-z0-9]{32,}",
            )
        },
        pat(
            "github",
            "GitHub token",
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})",
        ),
        pat("gitlab", "GitLab token", r"\bglpat-[A-Za-z0-9_-]{20,}"),
        pat("slack", "Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{20,}"),
        pat(
            "stripe",
            "Stripe secret key",
            r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}",
        ),
        Pattern {
            ambiguous: true,
            ..pat(
                "google_gemini",
                "Google API key (Gemini or another Google API)",
                r"\bAIza[0-9A-Za-z_-]{35}",
            )
        },
        pat("groq", "Groq API key", r"\bgsk_[A-Za-z0-9]{40,}"),
        pat("xai", "xAI API key", r"\bxai-[A-Za-z0-9]{40,}"),
        pat(
            "huggingface",
            "Hugging Face token",
            r"\bhf_[A-Za-z0-9]{30,}",
        ),
        pat("replicate", "Replicate token", r"\br8_[A-Za-z0-9]{30,}"),
        pat(
            "perplexity",
            "Perplexity API key",
            r"\bpplx-[A-Za-z0-9]{40,}",
        ),
        pat("tavily", "Tavily API key", r"\btvly-[A-Za-z0-9-]{20,}"),
        pat("firecrawl", "Firecrawl API key", r"\bfc-[a-f0-9]{32}\b"),
        pat("pinecone", "Pinecone API key", r"\bpcsk_[A-Za-z0-9_]{40,}"),
        pat("npm", "npm token", r"\bnpm_[A-Za-z0-9]{36}\b"),
        pat(
            "sendgrid",
            "SendGrid API key",
            r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        ),
        pat(
            "resend",
            "Resend API key",
            r"\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}",
        ),
        pat(
            "notion",
            "Notion token",
            r"\b(?:ntn_|secret_)[A-Za-z0-9]{40,}",
        ),
        pat("linear", "Linear API key", r"\blin_api_[A-Za-z0-9]{40,}"),
        pat(
            "digitalocean",
            "DigitalOcean token",
            r"\bdo[opr]_v1_[a-f0-9]{64}",
        ),
        pat(
            "sentry",
            "Sentry token",
            r"\bsntr[yu]s?_[A-Za-z0-9+/=_]{40,}",
        ),
        Pattern {
            tool: Some("credential_setup_aws"),
            ..pat("aws", "AWS access key ID", r"\bAKIA[0-9A-Z]{16}\b")
        },
        Pattern {
            tool: Some("credential_set (value_file if it is in a file)"),
            no_entropy: true,
            ..pat(
                "private_key",
                "private key (PEM)",
                r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----",
            )
        },
        pat(
            "bearer",
            "JWT / bearer token",
            r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        ),
    ]
}

/// `"api_key = …"`, `"password: …"` in prose, including Chinese equivalents (prompts only -- too
/// noisy for code).
fn generic_re() -> Regex {
    Regex::new(
        r#"(?i)(?:api[_ -]?key|secret|token|password|passwd|pwd|密钥|密码|口令|令牌)["'\s]*(?:[:=：]|is|是|为)\s*["'`]?([^\s"'`,，;；]{12,})"#,
    )
    .unwrap()
}

/// Fake / placeholder values (`sk-xxxxxxxx`, `your-api-key-here`, `${OPENAI_API_KEY}`) don't
/// count.
fn looks_random(s: &str) -> bool {
    let placeholder = Regex::new(
        r"(?i)(x{6,}|\*{3,}|\.{3}|…|your|example|placeholder|dummy|redacted|\$\{|<.*>|process\.env|os\.environ)",
    )
    .unwrap();
    if placeholder.is_match(s) {
        return false;
    }
    if !s.bytes().any(|b| b.is_ascii_digit()) || !s.bytes().any(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    s.chars().collect::<HashSet<_>>().len() >= 10
}

pub fn mask(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 12 {
        let head: String = chars.iter().take(3).collect();
        format!("{head}…")
    } else {
        let head: String = chars.iter().take(6).collect();
        let tail: String = chars.iter().rev().take(4).rev().collect();
        format!("{head}…{tail}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub id: Option<String>,
    pub label: String,
    pub preview: String,
    pub tool: Option<String>,
    pub ambiguous: bool,
}

/// Find secrets in text. A match claimed by one pattern is blanked out before testing the next,
/// broader one, so e.g. an Anthropic key isn't *also* reported as a generic bearer token.
pub fn detect(text: &str, generic: bool) -> Vec<Hit> {
    if text.len() < 16 {
        return Vec::new();
    }
    let mut hits = Vec::new();
    let mut seen = HashSet::new();
    let mut rest = text.to_string();
    for p in patterns() {
        let re = Regex::new(p.re).unwrap();
        for m in re.find_iter(&rest.clone()) {
            let v = m.as_str();
            if !p.no_entropy && !looks_random(v) {
                continue;
            }
            if !seen.insert(v.to_string()) {
                continue;
            }
            hits.push(Hit {
                id: Some(p.id.to_string()),
                label: p.label.to_string(),
                preview: if p.no_entropy { v.to_string() } else { mask(v) },
                tool: p.tool.map(str::to_string),
                ambiguous: p.ambiguous,
            });
        }
        rest = re.replace_all(&rest, " ").to_string();
    }
    if generic {
        let re = generic_re();
        for m in re.captures_iter(&rest) {
            let Some(v) = m.get(1).map(|g| g.as_str()) else {
                continue;
            };
            if !looks_random(v) || seen.contains(v) {
                continue;
            }
            seen.insert(v.to_string());
            hits.push(Hit {
                id: None,
                label: "secret (password / token)".to_string(),
                preview: mask(v),
                tool: None,
                ambiguous: false,
            });
        }
    }
    hits
}

fn describe(hits: &[Hit]) -> String {
    hits.iter()
        .map(|h| {
            let how = if let Some(tool) = &h.tool {
                format!("store with {tool}")
            } else if let Some(id) = &h.id {
                let note = if h.ambiguous { " (confirm the service with the user if unclear)" } else { "" };
                format!("template `{id}`{note}")
            } else {
                "no known template — ask the user which service it is for, then search credential_templates".to_string()
            };
            format!("- {} ({}) → {how}", h.label, h.preview)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn prompt_context(hits: &[Hit]) -> String {
    [
        "KeyValet: the user's message contains what looks like a secret:".to_string(),
        describe(hits),
        String::new(),
        "Unless the user said not to store it, proactively save it in KeyValet now, before doing anything else with it:".to_string(),
        "1. credential_list — if a credential for the same service already exists, ask the user whether to replace it (overwrite: true) or save under a new name.".to_string(),
        "2. credential_set with the template, a short name (e.g. \"default\", or the project/account it belongs to), value = the exact secret from the message, and a purpose. \
For an AWS key pair use credential_setup_aws (access_key_id + secret_access_key). If the template needs several secret fields, omit value and let the user fill them in the dialog.".to_string(),
        "3. From then on use it through credential_http_request or credential_gateway. Do not write it to .env or other files, shell commands, code, memory or notes, and do not repeat it in your reply.".to_string(),
        "Tell the user in one line that it is stored in KeyValet. Mention once that /keyvalet:add lets them enter keys in a private dialog so they never pass through the chat.".to_string(),
    ]
    .join("\n")
}

/// Pulls the text a tool call is about to write, per tool shape. Unknown tools (and malformed
/// input) yield "" rather than erroring -- a hook must never break the session.
pub fn tool_text(tool_name: &str, input: &Value) -> String {
    let Some(obj) = input.as_object() else {
        return String::new();
    };
    let s = |v: Option<&Value>| v.and_then(Value::as_str).unwrap_or_default().to_string();
    match tool_name {
        "Write" => s(obj.get("content")),
        "Edit" => s(obj.get("new_string")),
        "MultiEdit" => obj
            .get("edits")
            .and_then(Value::as_array)
            .map(|edits| {
                edits
                    .iter()
                    .map(|e| {
                        e.get("new_string")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default(),
        "NotebookEdit" => s(obj.get("new_source")),
        "Bash" => s(obj.get("command")),
        _ => String::new(),
    }
}

/// `~/.keyvalet/run/*.redact`, one file per still-live session (written by `recordSecrets` in the
/// MCP server, deleted when that session ends). Ignores files older than a day so a crashed
/// session that skipped cleanup doesn't keep flagging long-dead values forever.
fn returned_secrets_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".keyvalet").join("run"))
}

fn load_returned_secrets() -> HashSet<String> {
    match returned_secrets_dir() {
        Some(dir) => load_returned_secrets_from(&dir),
        None => HashSet::new(),
    }
}

/// Pulled out of `load_returned_secrets` so a test can point it at a tempdir instead of mutating
/// the process-wide `HOME` env var (which `cargo test`'s parallel threads would race on).
fn load_returned_secrets_from(dir: &std::path::Path) -> HashSet<String> {
    let mut out = HashSet::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    let cutoff = SystemTime::now().checked_sub(Duration::from_secs(24 * 60 * 60));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("redact") {
            continue;
        }
        if let (Ok(meta), Some(cutoff)) = (entry.metadata(), cutoff) {
            if meta.modified().map(|m| m < cutoff).unwrap_or(false) {
                continue;
            }
        }
        if let Ok(content) = std::fs::read_to_string(&path) {
            for line in content.lines() {
                let v = line.trim();
                if !v.is_empty() {
                    out.insert(v.to_string());
                }
            }
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnedHit {
    pub preview: String,
}

/// Exact-match hits (unlike `detect`, not a format guess -- these are values KeyValet itself
/// handed out this session).
pub fn detect_returned_secrets(text: &str) -> Vec<ReturnedHit> {
    if text.is_empty() {
        return Vec::new();
    }
    load_returned_secrets()
        .into_iter()
        .filter(|v| text.contains(v.as_str()))
        .map(|v| ReturnedHit { preview: mask(&v) })
        .collect()
}

pub fn tool_reason(tool_name: &str, hits: &[Hit], returned_hits: &[ReturnedHit]) -> String {
    let where_ = if tool_name == "Bash" {
        "this shell command"
    } else {
        "this file"
    };
    let mut parts = Vec::new();
    if !hits.is_empty() {
        let list = hits
            .iter()
            .map(|h| format!("{} ({})", h.label, h.preview))
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!(
            "{where_} contains a literal secret — {list}. Keep secrets in KeyValet: call APIs with credential_http_request, run SDKs/scripts with credential_gateway (env file with a local base URL and a gateway token), and read env vars in code instead of hard-coding keys."
        ));
    }
    if !returned_hits.is_empty() {
        let list = returned_hits
            .iter()
            .map(|h| h.preview.clone())
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!(
            "{where_} contains a value KeyValet already returned this session ({list}). A secret KeyValet handed you should not go into a shell command or env-var prefix (ps shows it to every local user) or into a plain file — use credential_export_file instead and have the program read it from the private file it returns."
        ));
    }
    parts.push("Approve only if you really want this.".to_string());
    parts.join(" ")
}

/// Hook entry: returns the JSON to print, or `None` for no output. `mode` is `"prompt"` or
/// `"tool"`; `input` is the hook event JSON as received on stdin.
pub fn handle(mode: &str, input: &Value) -> Option<Value> {
    match mode {
        "prompt" => {
            let prompt = input
                .get("prompt")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let hits = detect(prompt, true);
            if hits.is_empty() {
                return None;
            }
            Some(serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "UserPromptSubmit",
                    "additionalContext": prompt_context(&hits),
                }
            }))
        }
        "tool" => {
            let name = input
                .get("tool_name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let empty = Value::Null;
            let tool_input = input.get("tool_input").unwrap_or(&empty);
            let text = tool_text(name, tool_input);
            let hits = detect(&text, false);
            let returned_hits = detect_returned_secrets(&text);
            if hits.is_empty() && returned_hits.is_empty() {
                return None;
            }
            let mut additional_context =
                String::from("KeyValet flagged a secret in this tool call. ");
            if !hits.is_empty() {
                additional_context.push_str("If the user hasn't stored it yet, store it with credential_set (template + value), then use credential_http_request / credential_gateway or read it from env vars instead of hard-coding it. ");
            }
            if !returned_hits.is_empty() {
                additional_context.push_str("A value returned by a KeyValet tool this session is present verbatim — use credential_export_file so the program reads it from a private file instead.");
            }
            Some(serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": tool_reason(name, &hits, &returned_hits),
                    "additionalContext": additional_context,
                }
            }))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_a_known_openai_key_and_masks_it() {
        let text = "here is my key: sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";
        let hits = detect(text, false);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, Some("openai".to_string()));
        assert!(!hits[0].preview.contains("abcdefghijklmnopqrstuvwxyz"));
        assert!(hits[0].preview.contains('…'));
    }

    #[test]
    fn a_specific_pattern_blanks_its_match_so_a_broader_one_does_not_also_fire() {
        // Anthropic's sk-ant- prefix would also satisfy the broader ambiguous sk-... pattern if
        // it weren't blanked out first.
        let text = "sk-ant-abcdefghijklmnopqrstuvwxyz0123456789";
        let hits = detect(text, false);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, Some("anthropic".to_string()));
    }

    #[test]
    fn placeholder_values_are_not_flagged() {
        assert!(detect("sk-proj-your-api-key-here-xxxxxxxxxxxxxxxxxxxx", false).is_empty());
        assert!(detect("sk-proj-${OPENAI_API_KEY}aaaaaaaaaaaaaaaaaaaa", false).is_empty());
    }

    #[test]
    fn short_text_is_never_scanned() {
        assert!(detect("sk-ant-x", false).is_empty());
    }

    #[test]
    fn generic_prose_pattern_only_fires_when_asked_for() {
        let text = "the api_key: 9f8e7d6c5b4a3210 is what you need";
        assert!(
            detect(text, false).is_empty(),
            "code mode is too noisy for generic prose"
        );
        let hits = detect(text, true);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].id.is_none());
    }

    #[test]
    fn pem_private_key_is_flagged_without_an_entropy_check() {
        let text = "-----BEGIN PRIVATE KEY-----\nMIIBIjANBg\n-----END PRIVATE KEY-----";
        let hits = detect(text, false);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, Some("private_key".to_string()));
        // no_entropy: the raw marker is shown, not masked -- it isn't the secret itself.
        assert_eq!(hits[0].preview, "-----BEGIN PRIVATE KEY-----");
    }

    #[test]
    fn mask_short_and_long_values() {
        assert_eq!(mask("short-ish"), "sho…");
        assert_eq!(mask("sk-proj-abcdefghijklmnop"), "sk-pro…mnop");
    }

    #[test]
    fn tool_text_extracts_by_tool_shape() {
        assert_eq!(
            tool_text("Write", &serde_json::json!({"content": "hello"})),
            "hello"
        );
        assert_eq!(
            tool_text("Edit", &serde_json::json!({"new_string": "hi"})),
            "hi"
        );
        assert_eq!(
            tool_text("Bash", &serde_json::json!({"command": "echo hi"})),
            "echo hi"
        );
        assert_eq!(
            tool_text(
                "MultiEdit",
                &serde_json::json!({"edits": [{"new_string": "a"}, {"new_string": "b"}]})
            ),
            "a\nb"
        );
        assert_eq!(
            tool_text("SomethingElse", &serde_json::json!({"content": "x"})),
            ""
        );
    }

    #[test]
    fn handle_prompt_mode_flags_a_pasted_key() {
        let input = serde_json::json!({"prompt": "my openai key is sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"});
        let out = handle("prompt", &input).unwrap();
        assert_eq!(
            out["hookSpecificOutput"]["hookEventName"],
            "UserPromptSubmit"
        );
        assert!(out["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap()
            .contains("credential_set"));
    }

    #[test]
    fn handle_prompt_mode_is_silent_for_ordinary_text() {
        let input = serde_json::json!({"prompt": "what's the weather like today"});
        assert!(handle("prompt", &input).is_none());
    }

    #[test]
    fn handle_tool_mode_asks_before_a_key_is_written_to_a_file() {
        let input = serde_json::json!({
            "tool_name": "Write",
            "tool_input": {"content": "KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"},
        });
        let out = handle("tool", &input).unwrap();
        assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "ask");
    }

    #[test]
    fn handle_tool_mode_is_silent_for_an_ordinary_write() {
        let input =
            serde_json::json!({"tool_name": "Write", "tool_input": {"content": "fn main() {}"}});
        assert!(handle("tool", &input).is_none());
    }

    #[test]
    fn handle_unknown_mode_is_silent() {
        assert!(handle("something-else", &serde_json::json!({})).is_none());
    }

    #[test]
    fn missing_run_dir_yields_no_hits_without_panicking() {
        assert!(load_returned_secrets_from(std::path::Path::new("/no/such/dir")).is_empty());
    }

    #[test]
    fn a_fresh_redact_file_is_loaded_and_an_exact_match_is_flagged() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("session1.redact"),
            "sk-live-abcdefghijklmnop\nother-secret-value\n",
        )
        .unwrap();
        let loaded = load_returned_secrets_from(dir.path());
        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains("sk-live-abcdefghijklmnop"));
    }

    #[test]
    fn a_non_redact_file_in_the_run_dir_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("notes.txt"), "sk-live-abcdefghijklmnop\n").unwrap();
        assert!(load_returned_secrets_from(dir.path()).is_empty());
    }

    #[test]
    fn a_stale_redact_file_past_the_24h_cutoff_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.redact");
        std::fs::write(&path, "sk-live-abcdefghijklmnop\n").unwrap();
        let two_days_ago = SystemTime::now() - Duration::from_secs(48 * 60 * 60);
        filetime_touch(&path, two_days_ago);
        assert!(load_returned_secrets_from(dir.path()).is_empty());
    }

    /// `std::fs::set_file_mtime` isn't in std; `touch -t`-equivalent via the file API without a
    /// new crate dependency just for one test -- open, set_modified via `File::set_modified` is
    /// stable since Rust 1.75.
    fn filetime_touch(path: &std::path::Path, t: SystemTime) {
        let f = std::fs::File::options().write(true).open(path).unwrap();
        f.set_modified(t).unwrap();
    }

    #[test]
    fn detect_returned_secrets_matches_exact_values_regardless_of_shape() {
        // Doesn't need to look like a known key format (unlike `detect`) -- any exact substring
        // match against something KeyValet itself handed out counts.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("s.redact"),
            "not-a-recognizable-key-format-at-all\n",
        )
        .unwrap();
        let hits: Vec<_> = load_returned_secrets_from(dir.path())
            .into_iter()
            .filter(|v| {
                "the value is not-a-recognizable-key-format-at-all here".contains(v.as_str())
            })
            .collect();
        assert_eq!(hits.len(), 1);
    }
}
