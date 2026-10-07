//! Session-private files: written to a location only the user can read (~/.keyvalet/run, directory
//! 0700, files 0600), deleted when the session (MCP server) exits.
//! - Gateway environment variable file: the token is written to a file, and the agent loads it with
//!   `set -a; . <file>; set +a; <command>` -- the token never appears in command-line arguments (ps
//!   is visible to all users), nor does it appear in the agent's context.
//! - Secret file (write_secret_file): some programs must read the secret itself from a local file
//!   (e.g. an ssh -i private key). There's no proxy-style approach here like the gateway's "only
//!   forward, the real value never leaves root" -- writing the file is the point where the secret
//!   leaves the root helper; the best we can do here is keep the content out of the agent's context
//!   and hand back only the path.
//! - Record of returned values (record_secrets): tools like credential_get / credential_totp_code /
//!   credential_access_token / credential_aws_credentials are, by design, meant to hand the raw
//!   secret to the agent (there's no choice when no proxy channel is available). We log each value
//!   handed out to <session>.redact, so Claude Code's PreToolUse hook can intercept it before the
//!   agent actually splices it into a shell command or writes it to a file -- regardless of whether
//!   the value looks like an "API key," anything KeyValet itself handed out is worth flagging if it
//!   shows up in a command line or file.
//!
//! Direct port of src/server/gateway-env.ts.

use std::collections::HashSet;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Mutex;

static CREATED: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

fn run_dir() -> std::io::Result<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_default();
    let dir = std::path::Path::new(&home).join(".keyvalet").join("run");
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(
        dir.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | ':' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn quote(v: &str) -> String {
    format!("'{}'", v.replace('\'', r"'\''"))
}

fn write_exclusive(file: &PathBuf, content: &[u8]) -> std::io::Result<()> {
    let _ = std::fs::remove_file(file);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(file)?;
    f.write_all(content)
}

pub fn write_gateway_env(
    session: &str,
    ty: &str,
    name: &str,
    env: &[(String, String)],
) -> std::io::Result<PathBuf> {
    let dir = run_dir()?;
    let file = dir.join(sanitize(&format!("{session}-{ty}-{name}.env")));
    let body: String = env
        .iter()
        .map(|(k, v)| format!("export {k}={}\n", quote(v)))
        .collect();
    write_exclusive(&file, body.as_bytes())?;
    CREATED.lock().unwrap().push(file.clone());
    Ok(file)
}

/// Write a secret's raw content to a file only the user can read (same directory, also 0600), for
/// programs that need a local file (e.g. ssh -i, certificates). The content itself is never
/// returned to the agent, only the path is. Deleted along with the gateway environment variable
/// files when the session ends.
pub fn write_secret_file(
    session: &str,
    ty: &str,
    name: &str,
    field: Option<&str>,
    content: &str,
) -> std::io::Result<PathBuf> {
    let dir = run_dir()?;
    let suffix = field.map(|f| format!("-{f}")).unwrap_or_default();
    let file = dir.join(sanitize(&format!("{session}-{ty}-{name}{suffix}.key")));
    write_exclusive(&file, content.as_bytes())?;
    CREATED.lock().unwrap().push(file.clone());
    Ok(file)
}

/// Values this short (e.g. a 6-digit TOTP code) cause too many false positives and are meant to be
/// used freely anyway, so they're not worth recording.
const MIN_REDACT_LENGTH: usize = 12;

/// Record one secret value returned to the agent, for the PreToolUse hook to match exactly (see
/// above). Appends to a file dedicated to this session (rather than overwriting it wholesale like
/// `write_secret_file`), since a single session may call credential_get / credential_access_token
/// etc. multiple times. Deleted along with the other session files when the session ends.
pub fn record_secrets(session: &str, values: impl IntoIterator<Item = Option<String>>) {
    let vals: HashSet<String> = values
        .into_iter()
        .flatten()
        .filter(|v| v.trim().len() >= MIN_REDACT_LENGTH)
        .collect();
    if vals.is_empty() {
        return;
    }
    let Ok(dir) = run_dir() else { return };
    let file = dir.join(sanitize(&format!("{session}.redact")));
    CREATED.lock().unwrap().push(file.clone());
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&file)
    {
        for v in vals {
            let _ = writeln!(f, "{v}");
        }
    }
    let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600));
}

/// Delete the environment variable files this session wrote, when the session ends.
pub fn cleanup_gateway_env() {
    for f in CREATED.lock().unwrap().drain(..) {
        let _ = std::fs::remove_file(f);
    }
}
