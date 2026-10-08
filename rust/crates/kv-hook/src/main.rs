//! CLI entry: `kv-hook prompt` or `kv-hook tool`, reads the hook event JSON on stdin, writes the
//! JSON KeyValet wants the runtime to see on stdout (nothing, if it has nothing to flag). A hook
//! must never break the session, so every failure mode here is "print nothing and exit 0."

use std::io::Read;

fn main() {
    if matches!(
        std::env::var("KEYVALET_HOOKS")
            .unwrap_or_default()
            .to_lowercase()
            .as_str(),
        "off" | "0" | "false" | "no"
    ) {
        return;
    }
    let Some(mode) = std::env::args().nth(1) else {
        return;
    };
    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        return;
    }
    let Ok(input) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return;
    };
    if let Some(out) = kv_hook::handle(&mode, &input) {
        print!("{out}");
    }
}
