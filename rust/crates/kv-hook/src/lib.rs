//! KeyValet hook for agent coding runtimes (Claude Code, Codex, Cursor, …): notices secrets so
//! they end up in KeyValet instead of the chat, files or shell.
//!
//! Direct port of `claude-plugin/hooks/secrets.mjs`, which this binary replaces as the thing the
//! Claude Code plugin (and, best-effort, Codex) actually invokes. The modes:
//!
//!   kv-hook prompt         UserPromptSubmit: the user pasted a key -> tell the agent to store it
//!                          in KeyValet.
//!   kv-hook tool           PreToolUse (Write/Edit/MultiEdit/NotebookEdit/Bash): a literal key is
//!                          about to be written to a file or a command -> ask the user first and
//!                          point the agent to KeyValet.
//!   kv-hook cursor-shell   Cursor `beforeShellExecution`.
//!   kv-hook cursor-mcp     Cursor `beforeMCPExecution`.
//!   kv-hook cursor-tool    Cursor `preToolUse` (file-write tools; the dedicated events only
//!                          cover shell commands and MCP calls, not agent file edits).
//!   kv-hook cursor-session Cursor `sessionStart` (injects a pointer to the KeyValet flow into
//!                          the session's initial context).
//!   kv-hook grok-tool      Grok Build `PreToolUse`.
//!   kv-hook devin-tool     Devin CLI `PreToolUse`.
//!
//! Cursor and Grok each get their own mode(s), not a translation of `prompt`/`tool`'s output,
//! because neither speaks Claude Code's `hookSpecificOutput` shape even though both can *load*
//! Claude Code's hook config:
//!
//! - Cursor's schema for its two blocking events is `{permission: "allow"|"deny"|"ask",
//!   user_message, agent_message}` (cursor.com/docs/hooks, checked 2026-10); `"ask"` is accepted
//!   by the schema but not enforced today, so anything `tool` mode would show as "ask" has to
//!   become "deny" here instead -- an unenforced ask is the same as a silent allow. `main.rs`
//!   also treats Cursor's two modes specially: a missing or schema-invalid response blocks the
//!   gated action there, the opposite of Claude Code's fail-open-on-no-output convention -- so
//!   every early return for these two modes prints an explicit `allow` rather than nothing.
//! - Grok reads hook *config* from `~/.claude/settings.json` for compatibility but, per 2026-10
//!   field reports (docs.x.ai/build/features/hooks; independent testing writeups), does not
//!   parse the nested `hookSpecificOutput.permissionDecision` *output* -- an unrecognized
//!   decision is silently treated as absent, i.e. allow. Its actual contract is exit code (0 =
//!   allow, 2 = deny); `main.rs` does the `exit(2)` when `handle_grok_tool` returns `Some`.
//! - Devin's hook stdin carries the same `tool_name`/`tool_input` fields as Claude Code, but
//!   its built-in tool vocabulary is lowercase and different (`exec`, `write`, `edit`,
//!   `apply_patch`, `notebook_edit`, `write_to_process`, plus `mcp_call_tool` wrapping every
//!   MCP call), and its stdout contract is a top-level `{"decision": "approve"|"block",
//!   "reason"}` -- no "ask" equivalent exists (Devin CLI hook docs, checked 2026-10), so a flag
//!   becomes a block, same trade-off as Cursor and Grok. `prompt` mode's output is already
//!   Devin-compatible (`UserPromptSubmit` + `additionalContext`), so only the tool side gets a
//!   dedicated mode.
//!
//! Hooks use format detection only; raw credential values are never logged for matching.
//!
//! Never prints the secret itself (only a masked preview). `KEYVALET_HOOKS=off` disables it.

use regex::Regex;
use serde_json::Value;
use std::collections::HashSet;

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
    detect_with_values(text, generic)
        .into_iter()
        .map(|(_, h)| h)
        .collect()
}

/// Same matching as `detect`, but also returns the real, unmasked matched text alongside each
/// `Hit` -- needed only by `kv-cli scan`'s import step (to store the real value and find it in
/// the file to remove it). Kept out of `Hit` itself so the common case (the `tool`/`prompt`
/// hooks, which only ever need the masked `preview`) never carries a live secret in a struct that
/// derives `Debug` -- one stray `{:?}` of a `Hit` must not be able to leak a real value.
pub fn detect_with_values(text: &str, generic: bool) -> Vec<(String, Hit)> {
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
            hits.push((
                v.to_string(),
                Hit {
                    id: Some(p.id.to_string()),
                    label: p.label.to_string(),
                    preview: if p.no_entropy { v.to_string() } else { mask(v) },
                    tool: p.tool.map(str::to_string),
                    ambiguous: p.ambiguous,
                },
            ));
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
            hits.push((
                v.to_string(),
                Hit {
                    id: None,
                    label: "secret (password / token)".to_string(),
                    preview: mask(v),
                    tool: None,
                    ambiguous: false,
                },
            ));
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

fn flatten_strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(items) => items.iter().for_each(|i| flatten_strings(i, out)),
        Value::Object(obj) => obj.values().for_each(|i| flatten_strings(i, out)),
        _ => {}
    }
}

/// Does this tool/server name refer to the keyvalet MCP server? The same server shows up under
/// runtime-specific spellings (`mcp__keyvalet__credential_set`, `keyvalet__credential_set`,
/// `MCP:keyvalet:credential_set`, a bare `keyvalet` server field, ...), so split on
/// non-alphanumerics and look for a whole `keyvalet` segment rather than guess a prefix shape.
/// A "keyvalet-ish" name like `my-keyvalet-clone` is exempted too -- a false exemption only
/// means one user-named server skips secret scanning, while a missed exemption would block
/// `credential_set`, the very path this hook exists to promote.
fn is_keyvalet_ref(name: &str) -> bool {
    name.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|seg| seg == "keyvalet")
}

/// Any of the server-identifying fields a runtime's MCP-tool event might carry
/// (Cursor's documented `mcp_server_name`, plus the spellings other runtimes use).
fn mcp_server_field(input: &Value) -> &str {
    input
        .get("mcp_server_name")
        .or_else(|| input.get("server_name"))
        .or_else(|| input.get("serverName"))
        .or_else(|| input.get("server"))
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// Is this Cursor `beforeMCPExecution` event aimed at the keyvalet server? The documented
/// identifier is `mcp_server_name`, but the payload also carries the stdio `command` (our own
/// binary path contains a `keyvalet` segment), a `url`, and a `tool_name` that may itself be
/// namespaced (`keyvalet__credential_set`) -- probe them all.
fn cursor_mcp_targets_keyvalet(input: &Value) -> bool {
    [
        "tool_name",
        "mcp_server_name",
        "server_name",
        "serverName",
        "server",
        "command",
        "url",
        "mcp_server_url",
    ]
    .iter()
    .any(|f| {
        input
            .get(*f)
            .and_then(Value::as_str)
            .is_some_and(is_keyvalet_ref)
    })
}

/// Every string value anywhere in an arbitrary MCP tool call's params, depth-first. Used instead
/// of `tool_text` for Cursor's `beforeMCPExecution` (and any other "gate every MCP tool call, not
/// just five named shapes" caller): the tool being gated there can be any MCP server's tool, with
/// a param shape `tool_text` has no name-based case for, so scanning every string field is a
/// strictly broader net that still costs little for the small param objects these calls carry.
fn mcp_tool_text(input: &Value) -> String {
    let mut out = Vec::new();
    flatten_strings(input, &mut out);
    out.join("\n")
}

/// Where-label for the Claude-Code-shaped tool names (Grok's observed names look the same, and
/// Cursor's `preToolUse` reports the same PascalCase vocabulary).
fn tool_where(tool_name: &str) -> &'static str {
    match tool_name {
        "Bash" | "Shell" => "this shell command",
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => "this file",
        // An MCP tool call or an unrecognized name -- neither "file" nor "shell command"
        // describes it accurately.
        _ => "this tool call",
    }
}

/// Shared first half of a flag message: what was found and where it belongs instead.
fn flag_reason(where_: &str, hits: &[Hit]) -> String {
    let list = hits
        .iter()
        .map(|h| format!("{} ({})", h.label, h.preview))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{where_} contains a literal secret — {list}. Keep secrets in KeyValet: call APIs with credential_http_request, run SDKs/scripts with credential_gateway (env file with a local base URL and a gateway token), and read env vars in code instead of hard-coding keys."
    )
}

pub fn tool_reason(tool_name: &str, hits: &[Hit]) -> String {
    let mut parts = Vec::new();
    if !hits.is_empty() {
        parts.push(flag_reason(tool_where(tool_name), hits));
    }
    parts.push("Approve only if you really want this.".to_string());
    parts.join(" ")
}

/// Reason text for runtimes whose only verdict is deny/block (Cursor, Grok): there is no
/// "approve" step for the user, so instead of Claude Code's "Approve only if..." tail the
/// escape hatch is disabling the hook.
fn deny_reason(tool_name: &str, hits: &[Hit], runtime: &str) -> String {
    format!(
        "{} If you really want a literal secret here, set KEYVALET_HOOKS=off in {runtime}'s environment.",
        flag_reason(tool_where(tool_name), hits)
    )
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
            if hits.is_empty() {
                return None;
            }
            let mut additional_context =
                String::from("KeyValet flagged a secret in this tool call. ");
            if !hits.is_empty() {
                additional_context.push_str("If the user hasn't stored it yet, store it with credential_set (template + value), then use credential_http_request / credential_gateway or read it from env vars instead of hard-coding it. ");
            }
            Some(serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": tool_reason(name, &hits),
                    "additionalContext": additional_context,
                }
            }))
        }
        _ => None,
    }
}

/// `{"permission": "allow"}` -- Cursor's schema for `beforeShellExecution`/`beforeMCPExecution`
/// (see the module doc comment); the only field every caller below needs when there's nothing to
/// flag.
fn cursor_allow() -> Value {
    serde_json::json!({"permission": "allow"})
}

fn cursor_deny(reason: &str) -> Value {
    serde_json::json!({"permission": "deny", "user_message": reason, "agent_message": reason})
}

/// Cursor `beforeShellExecution`: input `{"command": "...", "cwd": "...", ...}`. Always returns a
/// decision (never `None`) -- see the module doc comment on why Cursor needs that.
pub fn handle_cursor_shell(input: &Value) -> Value {
    let command = input
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let hits = detect(command, false);
    if hits.is_empty() {
        return cursor_allow();
    }
    cursor_deny(&deny_reason("Bash", &hits, "Cursor"))
}

/// Cursor `beforeMCPExecution`: input `{"tool_name": "...", "tool_input": "<json-encoded
/// string>", "mcp_server_name": "<key in mcp.json>", ...}` (checked against cursor.com/docs/hooks
/// 2026-10 -- `mcp_server_name` is the documented way to recognize a server). `tool_input` is a
/// JSON string here, not an object, so it needs its own parse step; if it's already an object or
/// an unparseable string it is still scanned rather than skipped. Always returns a decision.
///
/// Calls on the `keyvalet` server itself are always allowed: `credential_set`'s `value`,
/// `credential_setup_aws`'s `secret_access_key` and friends legitimately carry secrets, and
/// gating them would break the very flow this hook exists to promote.
pub fn handle_cursor_mcp(input: &Value) -> Value {
    if cursor_mcp_targets_keyvalet(input) {
        return cursor_allow();
    }
    let text = match input.get("tool_input") {
        Some(Value::String(raw)) => match serde_json::from_str::<Value>(raw) {
            Ok(v) => mcp_tool_text(&v),
            Err(_) => raw.clone(),
        },
        Some(v) => mcp_tool_text(v),
        None => String::new(),
    };
    let hits = detect(&text, false);
    if hits.is_empty() {
        return cursor_allow();
    }
    let name = input
        .get("tool_name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    cursor_deny(&deny_reason(name, &hits, "Cursor"))
}

/// Cursor `sessionStart`: fire-and-forget; output `{"additional_context": ...}` lands in the
/// session's initial system context. Emits a compact pointer to the KeyValet flow so the agent
/// knows the credential path even before the `keyvalet` skill's description triggers.
pub fn handle_cursor_session() -> Value {
    serde_json::json!({
        "additional_context": "KeyValet (MCP server `keyvalet`) manages the user's credentials: secrets stay in the local vault and every use is Touch ID-approved and audited. Store keys the user shares with `credential_set` (omit `value` to have the user type it into a private dialog; never ask them to paste a key). Use credentials via `credential_http_request` / `credential_gateway`, or `credential_export_file` when a program needs a file; `credential_get` only as a last resort. Never write secrets into files, shell commands, memory or notes. Commands: /keyvalet-add, /keyvalet-mode, /keyvalet-status, /keyvalet-lock, /keyvalet-audit."
    })
}

/// Cursor `preToolUse`: the generic event that fires for every tool type, including the
/// file-write tools (`Write`, `Edit`, `StrReplace`, `Delete`, ...) that the dedicated
/// `beforeShellExecution`/`beforeMCPExecution` events don't cover. Input is the same
/// `tool_name`/`tool_input` shape as Claude Code's, with PascalCase names; `tool_input` is an
/// object here. Unknown tool names fall back to scanning every string field, so a new write-ish
/// tool name still gets gated. Always returns a decision.
pub fn handle_cursor_tool(input: &Value) -> Value {
    let name = input
        .get("tool_name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    // The matcher shouldn't route MCP calls here, but if one arrives under an `MCP:...` or
    // namespaced name anyway, keyvalet's own tools stay exempt.
    if is_keyvalet_ref(name) || is_keyvalet_ref(mcp_server_field(input)) {
        return cursor_allow();
    }
    let empty = Value::Null;
    let tool_input = input.get("tool_input").unwrap_or(&empty);
    // Known Claude-Code-style shapes get field-precise extraction (Edit: new_string only, so
    // removing a hard-coded key doesn't flag). Anything else -- unknown names, or a non-object
    // tool_input -- gets the recursive net.
    let known_shape = matches!(
        name,
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" | "Bash"
    );
    let text = if known_shape && tool_input.is_object() {
        tool_text(name, tool_input)
    } else {
        mcp_tool_text(tool_input)
    };
    let hits = detect(&text, false);
    if hits.is_empty() {
        return cursor_allow();
    }
    cursor_deny(&deny_reason(name, &hits, "Cursor"))
}

/// Grok Build `PreToolUse` -- the only Grok hook event that can actually block anything
/// (docs.x.ai/build/features/hooks, and independently confirmed by testing: 2026-10 writeups
/// report Grok reads Claude Code's hook *config* but does not parse Claude's nested
/// `hookSpecificOutput.permissionDecision` *output*, silently treating an unrecognized decision
/// as absent, i.e. allow -- so this deliberately does not reuse `handle`'s Claude Code JSON
/// shape. Grok's own contract: exit code (0 = allow, 2 = deny) is primary; this also prints a
/// top-level `{"decision": "deny", "reason": ...}` as a secondary channel some docs describe, in
/// case Grok reads stdout JSON too -- harmless if it doesn't. `main.rs` is responsible for the
/// actual `exit(2)` when this returns `Some`.
///
/// Field casing on the input (`tool_name`/`tool_input` vs `toolName`/`toolInput`) isn't
/// consistently confirmed across sources, so both are tried. Uses `mcp_tool_text`'s recursive
/// scan rather than `tool_text`'s per-tool-name extraction: Grok's own tool-name vocabulary for
/// its built-in tools isn't confirmed to match Claude Code's either, and scanning every string
/// field doesn't depend on getting that guess right.
pub fn handle_grok_tool(input: &Value) -> Option<Value> {
    let name = input
        .get("tool_name")
        .or_else(|| input.get("toolName"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    // KeyValet's own tools legitimately take secrets as parameters (credential_set's value,
    // credential_setup_aws's secret_access_key, ...) -- Grok names MCP tools `server__tool` and
    // fires PreToolUse for them, so without this exemption the hook would deny the very flow it
    // exists to promote.
    if is_keyvalet_ref(name) || is_keyvalet_ref(mcp_server_field(input)) {
        return None;
    }
    let empty = Value::Null;
    let tool_input = input
        .get("tool_input")
        .or_else(|| input.get("toolInput"))
        .unwrap_or(&empty);
    let text = mcp_tool_text(tool_input);
    let hits = detect(&text, false);
    if hits.is_empty() {
        return None;
    }
    Some(serde_json::json!({"decision": "deny", "reason": deny_reason(name, &hits, "Grok")}))
}

/// Pulls the text a Devin tool call is about to write/execute, per tool shape. Devin's tool
/// names are lowercase (`exec`, `write`, `edit`, `apply_patch`, `notebook_edit`,
/// `write_to_process`). MCP calls can show up in either of two shapes: wrapped in the
/// `mcp_call_tool` builtin (`{server_name, tool_name, arguments}`) or reported directly as
/// `mcp__<server>__<tool>` with the arguments as `tool_input` -- both are handled.
/// `edit` reads `new_string` only -- an edit *removing* a hard-coded key must not flag.
/// Calls to the `keyvalet` server itself (either shape) return "": `credential_set`'s `value`
/// parameter legitimately carries a secret, and gating it would break the very flow this hook
/// exists to promote. Unknown tools fall back to the recursive scan.
fn devin_tool_text(tool_name: &str, input: &Value) -> String {
    // Namespaced MCP tool calls on keyvalet are exempt regardless of payload shape.
    if is_keyvalet_ref(tool_name) {
        return String::new();
    }
    let Some(obj) = input.as_object() else {
        // tool_input isn't the usual {field: value} object -- scan whatever it is.
        return mcp_tool_text(input);
    };
    let s = |v: Option<&Value>| v.and_then(Value::as_str).unwrap_or_default().to_string();
    match tool_name {
        // `command` plus the `env` values Devin injects into the command's process tree --
        // a literal key passed via env is the same leak as one inlined in the command.
        "exec" => {
            let empty = Value::Null;
            format!(
                "{}\n{}",
                s(obj.get("command")),
                mcp_tool_text(obj.get("env").unwrap_or(&empty))
            )
        }
        "write" => s(obj.get("content")),
        "edit" => s(obj.get("new_string")),
        "notebook_edit" => s(obj.get("new_source")),
        "write_to_process" => format!(
            "{}\n{}",
            s(obj.get("text_input")),
            s(obj.get("bytes_input"))
        ),
        "mcp_call_tool" => {
            // A missed exemption would block KeyValet's own credential_set (the sanctioned
            // path), so probe the wrapped payload's server field under every spelling seen in
            // the wild.
            if is_keyvalet_ref(mcp_server_field(input)) {
                return String::new();
            }
            // Scan the whole wrapped input, not just `arguments`: server/tool names aren't
            // secret-shaped so this is a strictly broader net that doesn't depend on
            // guessing the argument field's name.
            mcp_tool_text(input)
        }
        // apply_patch, other mcp__* servers (the namespaced-name shape), and anything else:
        // scan every string field.
        _ => mcp_tool_text(input),
    }
}

fn devin_tool_reason(tool_name: &str, hits: &[Hit]) -> String {
    let where_ = match tool_name {
        "exec" | "write_to_process" => "this shell command",
        "write" | "edit" | "apply_patch" | "notebook_edit" => "this file",
        _ => "this tool call",
    };
    let list = hits
        .iter()
        .map(|h| format!("{} ({})", h.label, h.preview))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "KeyValet blocked {where_}: it contains a literal secret — {list}. Keep secrets in KeyValet: store with credential_set, call APIs with credential_http_request, run SDKs/scripts with credential_gateway (env file with a local base URL and a gateway token), and read env vars in code instead of hard-coding keys. If the user really wants a literal secret here, they can set KEYVALET_HOOKS=off in Devin's environment."
    )
}

/// Devin CLI `PreToolUse`. Stdin has the same `tool_name`/`tool_input` fields as Claude Code;
/// the output contract is a top-level `{"decision": "block", "reason"}` (Devin has no "ask"
/// decision, only approve/block -- checked 2026-10), so a flag blocks outright and the reason
/// points the agent at the KeyValet path instead. Silent (`None`) when nothing is flagged,
/// which Devin treats as proceed -- the same fail-open convention as `handle`'s `tool` mode.
pub fn handle_devin_tool(input: &Value) -> Option<Value> {
    let name = input
        .get("tool_name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let empty = Value::Null;
    let tool_input = input.get("tool_input").unwrap_or(&empty);
    let text = devin_tool_text(name, tool_input);
    let hits = detect(&text, false);
    if hits.is_empty() {
        return None;
    }
    Some(serde_json::json!({"decision": "block", "reason": devin_tool_reason(name, &hits)}))
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
    fn cursor_shell_allows_an_ordinary_command() {
        let input = serde_json::json!({"command": "echo hi", "cwd": "/tmp"});
        assert_eq!(
            handle_cursor_shell(&input),
            serde_json::json!({"permission": "allow"})
        );
    }

    #[test]
    fn cursor_shell_denies_a_command_carrying_a_key() {
        let input = serde_json::json!({
            "command": "curl -H 'x-api-key: sk-ant-api03-Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0FeDcBa-9z8y7x6w5v4u3t2' https://api.anthropic.com",
        });
        let out = handle_cursor_shell(&input);
        assert_eq!(out["permission"], "deny");
        assert!(out["user_message"]
            .as_str()
            .unwrap()
            .contains("shell command"));
        assert!(!out["user_message"]
            .as_str()
            .unwrap()
            .contains("sk-ant-api03-Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0FeDcBa-9z8y7x6w5v4u3t2"));
    }

    #[test]
    fn cursor_shell_never_returns_ask_even_internally() {
        // Cursor's schema accepts "ask" but doesn't enforce it -- this hook must never emit it.
        let input =
            serde_json::json!({"command": "echo sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"});
        let out = handle_cursor_shell(&input);
        assert_ne!(out["permission"], "ask");
    }

    #[test]
    fn cursor_mcp_allows_a_tool_call_with_no_secret() {
        let input = serde_json::json!({
            "tool_name": "some_mcp_server__do_thing",
            "tool_input": serde_json::to_string(&serde_json::json!({"query": "hello"})).unwrap(),
        });
        assert_eq!(
            handle_cursor_mcp(&input),
            serde_json::json!({"permission": "allow"})
        );
    }

    #[test]
    fn cursor_mcp_denies_a_tool_call_carrying_a_key_in_a_nested_param() {
        // tool_input's param names aren't any of the five Claude Code tool shapes, and the key is
        // nested inside an object -- mcp_tool_text has to find it by scanning every string field.
        let input = serde_json::json!({
            "tool_name": "some_mcp_server__do_thing",
            "tool_input": serde_json::to_string(&serde_json::json!({
                "config": {"env": {"OPENAI_API_KEY": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"}},
            })).unwrap(),
        });
        let out = handle_cursor_mcp(&input);
        assert_eq!(out["permission"], "deny");
        assert!(out["agent_message"]
            .as_str()
            .unwrap()
            .contains("this tool call"));
    }

    #[test]
    fn cursor_mcp_allows_when_tool_input_is_malformed() {
        let input = serde_json::json!({"tool_name": "x", "tool_input": "not valid json"});
        assert_eq!(
            handle_cursor_mcp(&input),
            serde_json::json!({"permission": "allow"})
        );
    }

    #[test]
    fn cursor_mcp_allows_keyvalets_own_calls() {
        // credential_set's value legitimately carries a secret -- gating it would break the
        // sanctioned path. `mcp_server_name` is Cursor's documented server field.
        let input = serde_json::json!({
            "tool_name": "credential_set",
            "tool_input": serde_json::to_string(&serde_json::json!({
                "template": "openai", "value": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"
            })).unwrap(),
            "mcp_server_name": "keyvalet",
            "command": "/usr/local/lib/keyvalet/bin/kv-mcp",
        });
        assert_eq!(
            handle_cursor_mcp(&input),
            serde_json::json!({"permission": "allow"})
        );
    }

    #[test]
    fn cursor_mcp_denies_a_key_in_a_non_json_tool_input_string() {
        // If tool_input ever arrives as a raw string that isn't JSON, its content is scanned
        // instead of silently skipped.
        let input = serde_json::json!({
            "tool_name": "x", "mcp_server_name": "other",
            "tool_input": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789",
        });
        assert_eq!(handle_cursor_mcp(&input)["permission"], "deny");
    }

    #[test]
    fn cursor_mcp_denies_a_key_in_an_object_tool_input() {
        // Defensive: a Cursor version that passes tool_input already-parsed still gets scanned.
        let input = serde_json::json!({
            "tool_name": "x", "mcp_server_name": "other",
            "tool_input": {"params": {"key": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"}},
        });
        assert_eq!(handle_cursor_mcp(&input)["permission"], "deny");
    }

    #[test]
    fn cursor_tool_denies_a_write_carrying_a_key() {
        let input = serde_json::json!({
            "tool_name": "Write",
            "tool_input": {"path": "/tmp/x", "content": "KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"},
        });
        assert_eq!(handle_cursor_tool(&input)["permission"], "deny");
    }

    #[test]
    fn cursor_tool_ignores_an_edit_that_removes_a_key() {
        let input = serde_json::json!({
            "tool_name": "Edit",
            "tool_input": {"old_string": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789", "new_string": "os.environ['KEY']"},
        });
        assert_eq!(
            handle_cursor_tool(&input),
            serde_json::json!({"permission": "allow"})
        );
        // A pure deletion (empty/missing new_string) must not fall back to the recursive scan
        // and flag the secret that is being *removed*.
        let deletion = serde_json::json!({
            "tool_name": "Edit",
            "tool_input": {"old_string": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789", "new_string": ""},
        });
        assert_eq!(
            handle_cursor_tool(&deletion),
            serde_json::json!({"permission": "allow"})
        );
    }

    #[test]
    fn cursor_mcp_exempts_keyvalet_via_the_launch_command_field() {
        // No mcp_server_name at all -- the stdio `command` still identifies our server.
        let input = serde_json::json!({
            "tool_name": "credential_set",
            "tool_input": serde_json::to_string(&serde_json::json!({
                "value": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"
            })).unwrap(),
            "command": "/usr/local/lib/keyvalet/bin/kv-mcp",
        });
        assert_eq!(
            handle_cursor_mcp(&input),
            serde_json::json!({"permission": "allow"})
        );
    }

    #[test]
    fn cursor_session_injects_the_keyvalet_pointer() {
        let ctx = handle_cursor_session()["additional_context"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(ctx.contains("credential_set"));
    }

    #[test]
    fn cursor_tool_scans_unknown_tool_names_recursively() {
        // A write-ish Cursor tool name outside the Claude-Code five still gets gated.
        let input = serde_json::json!({
            "tool_name": "StrReplace",
            "tool_input": {"new_str": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"},
        });
        assert_eq!(handle_cursor_tool(&input)["permission"], "deny");
    }

    #[test]
    fn grok_tool_is_silent_for_an_ordinary_call() {
        let input = serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "echo hi"}});
        assert!(handle_grok_tool(&input).is_none());
    }

    #[test]
    fn grok_tool_denies_with_grok_native_shape_not_claude_codes() {
        let input = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "curl -H 'x-api-key: sk-ant-api03-Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0FeDcBa-9z8y7x6w5v4u3t2' https://api.anthropic.com"},
        });
        let out = handle_grok_tool(&input).unwrap();
        assert_eq!(out["decision"], "deny");
        assert!(
            out.get("hookSpecificOutput").is_none(),
            "must not use Claude Code's output shape -- Grok doesn't parse it"
        );
        assert!(out["reason"].as_str().unwrap().contains("shell command"));
    }

    #[test]
    fn grok_tool_accepts_camelcase_field_names_too() {
        let input = serde_json::json!({
            "toolName": "Bash",
            "toolInput": {"command": "echo sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"},
        });
        assert!(handle_grok_tool(&input).is_some());
    }

    #[test]
    fn grok_tool_scans_nested_params_regardless_of_tool_name() {
        let input = serde_json::json!({
            "tool_name": "some_unrecognized_native_tool_name",
            "tool_input": {"config": {"env": {"KEY": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"}}},
        });
        assert!(handle_grok_tool(&input).is_some());
    }

    #[test]
    fn grok_tool_skips_keyvalets_own_mcp_tools() {
        // Grok names MCP tools `server__tool` and fires PreToolUse for them; credential_set's
        // value legitimately carries a secret.
        let input = serde_json::json!({
            "tool_name": "keyvalet__credential_set",
            "tool_input": {"template": "openai", "value": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"},
        });
        assert!(handle_grok_tool(&input).is_none());
    }

    #[test]
    fn grok_tool_skips_a_keyvalet_server_field() {
        let input = serde_json::json!({
            "tool_name": "credential_set",
            "server_name": "keyvalet",
            "tool_input": {"value": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"},
        });
        assert!(handle_grok_tool(&input).is_none());
    }

    #[test]
    fn deny_reasons_offer_the_escape_hatch_not_an_approve_button() {
        // Cursor/Grok have no "approve" step for a denied call -- the message must point at
        // KEYVALET_HOOKS=off instead.
        let input =
            serde_json::json!({"command": "echo sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"});
        let msg = handle_cursor_shell(&input)["user_message"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(msg.contains("KEYVALET_HOOKS=off") && !msg.contains("Approve only if"));
        let out = handle_grok_tool(&serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {"command": "echo sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"},
        }))
        .unwrap();
        let reason = out["reason"].as_str().unwrap();
        assert!(reason.contains("KEYVALET_HOOKS=off") && !reason.contains("Approve only if"));
    }

    #[test]
    fn devin_tool_is_silent_for_an_ordinary_exec() {
        let input = serde_json::json!({"tool_name": "exec", "tool_input": {"command": "echo hi"}});
        assert!(handle_devin_tool(&input).is_none());
    }

    #[test]
    fn devin_tool_blocks_with_devin_native_shape_not_claude_codes() {
        let input = serde_json::json!({
            "tool_name": "exec",
            "tool_input": {"command": "curl -H 'x-api-key: sk-ant-api03-Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0FeDcBa-9z8y7x6w5v4u3t2' https://api.anthropic.com"},
        });
        let out = handle_devin_tool(&input).unwrap();
        assert_eq!(out["decision"], "block");
        assert!(
            out.get("hookSpecificOutput").is_none(),
            "must not use Claude Code's output shape -- Devin reads top-level decision/reason"
        );
        assert!(out["reason"].as_str().unwrap().contains("shell command"));
    }

    #[test]
    fn devin_tool_flags_write_and_edit_by_their_field_names() {
        let write = serde_json::json!({"tool_name": "write", "tool_input": {"content": "KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"}});
        assert!(handle_devin_tool(&write).is_some());
        // new_string is what an edit adds; a key sitting in old_string is being *removed*.
        let removing = serde_json::json!({"tool_name": "edit", "tool_input": {"old_string": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789", "new_string": "os.environ['KEY']"}});
        assert!(handle_devin_tool(&removing).is_none());
        let adding = serde_json::json!({"tool_name": "edit", "tool_input": {"old_string": "x", "new_string": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"}});
        assert!(handle_devin_tool(&adding).is_some());
    }

    #[test]
    fn devin_tool_flags_a_secret_passed_via_exec_env() {
        let input = serde_json::json!({"tool_name": "exec", "tool_input": {"command": "./deploy.sh", "env": {"API_KEY": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"}}});
        assert!(handle_devin_tool(&input).is_some());
    }

    #[test]
    fn devin_tool_flags_write_to_process_input() {
        let input = serde_json::json!({"tool_name": "write_to_process", "tool_input": {"text_input": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"}});
        assert!(handle_devin_tool(&input).is_some());
    }

    #[test]
    fn devin_tool_skips_keyvalets_own_mcp_calls() {
        // credential_set's value parameter legitimately carries a secret -- gating it would
        // break the sanctioned path this hook exists to promote.
        let input = serde_json::json!({
            "tool_name": "mcp_call_tool",
            "tool_input": {"server_name": "keyvalet", "tool_name": "credential_set",
                "arguments": {"template": "openai", "value": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"}},
        });
        assert!(handle_devin_tool(&input).is_none());
    }

    #[test]
    fn devin_tool_scans_other_mcp_calls_arguments() {
        let input = serde_json::json!({
            "tool_name": "mcp_call_tool",
            "tool_input": {"server_name": "github", "tool_name": "create_issue",
                "arguments": {"env": {"TOKEN": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"}}},
        });
        assert!(handle_devin_tool(&input).is_some());
    }

    #[test]
    fn devin_tool_exempts_namespaced_keyvalet_tool_names() {
        // The other MCP name shape Devin can report: tool_name IS mcp__keyvalet__<tool>.
        // credential_set's value legitimately carries a secret -- exempt like the wrapped form.
        let input = serde_json::json!({
            "tool_name": "mcp__keyvalet__credential_set",
            "tool_input": {"template": "openai", "value": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"},
        });
        assert!(handle_devin_tool(&input).is_none());
    }

    #[test]
    fn devin_tool_scans_namespaced_mcp_tool_arguments() {
        let input = serde_json::json!({
            "tool_name": "mcp__github__create_issue",
            "tool_input": {"env": {"TOKEN": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"}},
        });
        assert!(handle_devin_tool(&input).is_some());
    }

    #[test]
    fn devin_tool_scans_non_object_tool_input() {
        // A tool whose tool_input isn't the usual {field: value} object still gets scanned.
        let input = serde_json::json!({
            "tool_name": "apply_patch",
            "tool_input": "patch text with sk-proj-abcdefghijklmnopqrstuvwxyz0123456789 in it",
        });
        assert!(handle_devin_tool(&input).is_some());
    }
}
