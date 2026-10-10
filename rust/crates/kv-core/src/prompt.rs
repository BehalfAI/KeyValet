//! Minimal reasons for the narrow native authentication sheet. Show the credential and scope;
//! add an operation only for per-use approval or when it changes the credential's exposure.
//! Purpose and source context belong in the audit log.

use crate::summarize::BodyLine;
use crate::GrantMode;

/// Keep untrusted text on one line and remove invisible direction/format overrides. These
/// affect display only; the original purpose and context remain available in the audit log.
pub(crate) fn single_line(text: &str) -> String {
    let mut out = String::new();
    let mut space = false;
    for c in text.chars() {
        if kv_ipc::is_invisible_format(c) {
            continue;
        }
        if c.is_control() || c.is_whitespace() {
            space = !out.is_empty();
        } else {
            if space {
                out.push(' ');
                space = false;
            }
            out.push(c);
        }
    }
    out
}

pub(crate) fn shorten(text: &str, limit: usize) -> String {
    let chars: Vec<_> = text.chars().collect();
    if chars.len() <= limit {
        return text.to_string();
    }
    chars[..limit - 1].iter().chain(['…'].iter()).collect()
}

pub fn session_unlock(mode: GrantMode) -> String {
    match mode {
        GrantMode::PerUse => kv_i18n::t("解锁凭证库（逐次授权）", "unlock vault; approve each use"),
        GrantMode::PerCredential => kv_i18n::t(
            "解锁凭证库（按凭证授权）",
            "unlock vault; approve each credential",
        ),
        GrantMode::PerSession => kv_i18n::t(
            "解锁凭证库（本会话全部凭证）",
            "unlock vault for all credentials this session",
        ),
        GrantMode::Remember => kv_i18n::t(
            "解锁凭证库（记住全部凭证授权）",
            "unlock vault; remember all credential approvals",
        ),
    }
}

pub fn credential_grant(key: &str, per_use: bool, request: Option<&str>) -> String {
    // The generic API-key type adds no useful identity; keep service namespaces intact.
    let key = key.strip_prefix("api_key/").unwrap_or(key);
    let title = if per_use {
        kv_i18n::t(
            &format!("使用 {key}（仅此一次）"),
            &format!("use {key} once"),
        )
    } else {
        kv_i18n::t(
            &format!("使用 {key}（本会话）"),
            &format!("use {key} for this session"),
        )
    };
    // This description comes from the helper, never from the agent's stated purpose.
    if let Some(request) = request.filter(|s| !s.is_empty()) {
        return format!("{title}\n{request}");
    }
    title
}

/// A proxied request as shown in a per-use prompt: the target, plus every other part the approval
/// is bound to (query, agent headers, body), each kept to one shortened line.
pub fn http_request(
    method: &str,
    target: &str,
    query: Option<&str>,
    headers: &[(String, String)],
    body: BodyLine,
) -> String {
    let mut lines = vec![shorten(&single_line(&format!("{method} {target}")), 120)];
    if let Some(query) = query.filter(|q| !q.is_empty()) {
        lines.push(shorten(&single_line(&format!("?{query}")), 80));
    }
    if !headers.is_empty() {
        let joined: Vec<String> = headers.iter().map(|(k, v)| format!("{k}: {v}")).collect();
        let label = kv_i18n::t("请求头 ", "headers ");
        lines.push(shorten(
            &single_line(&format!("{label}{}", joined.join(", "))),
            80,
        ));
    }
    let label = kv_i18n::t("请求体 ", "body ");
    match body {
        BodyLine::None => {}
        BodyLine::Summary(s) => lines.push(shorten(&single_line(&format!("{label}{s}")), 80)),
        BodyLine::SizeOnly(n) => lines.push(format!("{label}({n} B)")),
        BodyLine::Preview(body) if !body.is_empty() => {
            let flat = single_line(&body);
            let preview = shorten(&flat, 60);
            let size = if preview == flat {
                String::new()
            } else {
                format!(" ({} B)", body.len())
            };
            lines.push(format!("{label}{preview}{size}"));
        }
        BodyLine::Preview(_) => {}
    }
    lines.join("\n")
}

/// One extra shortened line of details (scopes, permissions, lifetime) under an operation.
pub fn detail_line(operation: &str, details: &[String]) -> String {
    if details.is_empty() {
        return operation.to_string();
    }
    format!(
        "{operation}\n{}",
        shorten(&single_line(&details.join(" · ")), 100)
    )
}

pub fn settings_change(description: &str) -> String {
    kv_i18n::t(
        &format!("修改授权设置\n{description}"),
        &format!("change credential approvals\n{description}"),
    )
}

pub fn terminal_unlock(command: &str) -> String {
    let command = shorten(&single_line(command), 24);
    kv_i18n::t(
        &format!("在终端执行 {command}"),
        &format!("run vault command: {command}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_command_cannot_inject_lines_or_reverse_trusted_labels() {
        let reason = terminal_unlock(
            "Read\u{2028}\u{0085}files\u{2066} safely\u{2069}\r\n\u{202e}Scope: all\u{202c}\0",
        );
        assert_eq!(reason.lines().count(), 1);
        assert!(!reason.chars().any(|c| c.is_control()));
        assert!(!reason.contains('\u{202e}'));
        assert!(!reason.contains('\u{2066}'));
    }

    #[test]
    fn http_prompts_show_query_headers_and_body_on_single_lines() {
        let body = format!(
            "{{\"query\":\"mutation {{ deleteRepository }}\"\n,\"pad\":\"{}\"}}",
            "x".repeat(200)
        );
        let shown = http_request(
            "POST",
            "api.github.com/graphql",
            Some("a=1&b=2"),
            &[("X-HTTP-Method-Override".into(), "DELETE\u{202e}".into())],
            BodyLine::Preview(body.clone()),
        );
        let lines: Vec<&str> = shown.lines().collect();
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0], "POST api.github.com/graphql");
        assert_eq!(lines[1], "?a=1&b=2");
        assert!(lines[2].contains("X-HTTP-Method-Override: DELETE"));
        assert!(lines[3].contains("deleteRepository"));
        assert!(lines[3].ends_with(&format!("({} B)", body.len())));
        assert!(!shown.contains('\u{202e}'));
    }

    #[test]
    fn summary_and_size_only_bodies_render_as_one_labelled_line() {
        let shown = http_request(
            "POST",
            "api.openai.com/v1/chat/completions",
            None,
            &[],
            BodyLine::Summary("model=gpt-5 · stream=true".into()),
        );
        let line = shown.lines().nth(1).unwrap();
        assert!(line.contains("model=gpt-5 · stream=true"));

        let shown = http_request(
            "POST",
            "api.openai.com/v1/x",
            None,
            &[],
            BodyLine::SizeOnly(13),
        );
        assert!(shown.lines().nth(1).unwrap().ends_with("(13 B)"));
    }

    #[test]
    fn per_use_approval_preserves_the_credential_namespace_and_request() {
        let key = "openai/production";
        let request = format!("POST api.example.com/{}", "real-path/".repeat(25));
        let reason = credential_grant(key, true, Some(&request));
        assert!(reason.contains(key));
        assert!(reason.contains(&request));
        assert_eq!(reason.lines().count(), 2);
    }
}
