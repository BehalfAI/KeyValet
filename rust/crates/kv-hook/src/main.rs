//! CLI entry: `kv-hook <mode>`, reads the hook event JSON on stdin, writes the JSON the calling
//! runtime wants on stdout.
//!
//! For `prompt`/`tool` (Claude Code), a hook must never break the session: every failure mode
//! below is "print nothing and exit 0", which Claude Code treats as "no opinion, proceed."
//!
//! For `cursor-shell`/`cursor-mcp` (Cursor), it's the opposite: Cursor's docs say a missing or
//! schema-invalid response *blocks* the gated action, so every failure mode for these two modes
//! instead prints an explicit `{"permission": "allow"}` -- see the module doc comment in `lib.rs`.
//!
//! For `grok-tool` (Grok Build), a deny is the exit code, not the JSON -- `exit(2)` on a hit,
//! falling through to the default "print nothing, exit 0" otherwise, which is also Grok's own
//! allow case -- see the module doc comment in `lib.rs`.

use std::io::Read;

const CURSOR_ALLOW: &str = r#"{"permission":"allow"}"#;

fn is_cursor_mode(mode: &str) -> bool {
    matches!(mode, "cursor-shell" | "cursor-mcp")
}

fn main() {
    let mode = std::env::args().nth(1);
    if matches!(
        std::env::var("KEYVALET_HOOKS")
            .unwrap_or_default()
            .to_lowercase()
            .as_str(),
        "off" | "0" | "false" | "no"
    ) {
        if mode.as_deref().is_some_and(is_cursor_mode) {
            print!("{CURSOR_ALLOW}");
        }
        return;
    }
    let Some(mode) = mode else {
        return;
    };
    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        if is_cursor_mode(&mode) {
            print!("{CURSOR_ALLOW}");
        }
        return;
    }
    let Ok(input) = serde_json::from_str::<serde_json::Value>(&raw) else {
        if is_cursor_mode(&mode) {
            print!("{CURSOR_ALLOW}");
        }
        return;
    };
    match mode.as_str() {
        "cursor-shell" => print!("{}", kv_hook::handle_cursor_shell(&input)),
        "cursor-mcp" => print!("{}", kv_hook::handle_cursor_mcp(&input)),
        "grok-tool" => {
            if let Some(out) = kv_hook::handle_grok_tool(&input) {
                print!("{out}");
                std::process::exit(2);
            }
        }
        _ => {
            if let Some(out) = kv_hook::handle(&mode, &input) {
                print!("{out}");
            }
        }
    }
}
