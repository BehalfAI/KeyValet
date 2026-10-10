// Unix-only for now: these tests assert POSIX mode bits / unix-specific behaviors. The Windows
// equivalents (DACLs) land with W2/W3; the crate itself builds cross-platform.
#![cfg(unix)]
//! Cross-implementation compatibility: the Rust rewrite plan requires reading the existing
//! vault.enc/master.key produced by the TS implementation without migration, and vice versa during
//! the transition. This drives the REAL compiled `src/helper/vault.ts` (via node), not a simulation,
//! so it only runs where that's available -- skips cleanly otherwise (e.g. once the TS helper is
//! eventually removed, or on a machine without node/the build).

use kv_vault::{SetParams, Vault};
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    // crates/kv-vault -> rust -> <repo root>
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

/// None if node or the compiled TS vault module isn't available here -- the test using this skips
/// with a printed reason instead of failing, so it doesn't break on a machine without Node.
fn ts_vault_js() -> Option<PathBuf> {
    let node_available = Command::new("node")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !node_available {
        return None;
    }
    let p = repo_root().join("dist/helper/vault.js");
    p.exists().then_some(p)
}

fn run_ts_cli(vault_js: &Path, args: &[&str]) -> String {
    let cli = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ts_vault_cli.mjs");
    let out = Command::new("node")
        .arg(&cli)
        .arg(vault_js)
        .args(args)
        .output()
        .expect("failed to run node");
    assert!(
        out.status.success(),
        "ts_vault_cli.mjs failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn rust_can_read_a_vault_written_by_the_ts_implementation() {
    let Some(vault_js) = ts_vault_js() else {
        eprintln!("skipping: node or dist/helper/vault.js not available");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("vault");

    run_ts_cli(
        &vault_js,
        &[
            "set",
            dir.to_str().unwrap(),
            "api_key",
            "openai",
            "sk-from-ts-abc123",
        ],
    );

    let vault = Vault::new(&dir);
    vault.prepare().unwrap();
    if !vault.dir.join("master.key").exists() {
        // Explicit legacy fixture: production code never creates this file.
        std::fs::write(vault.dir.join("master.key"), [7u8; 32]).unwrap();
        std::fs::set_permissions(
            vault.dir.join("master.key"),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .unwrap();
    }
    vault.init_legacy().unwrap();
    assert_eq!(
        vault.get("api_key", "openai").unwrap().value,
        "sk-from-ts-abc123"
    );
}

#[test]
fn ts_can_read_a_vault_written_by_rust_including_after_a_rust_write_following_a_ts_write() {
    let Some(vault_js) = ts_vault_js() else {
        eprintln!("skipping: node or dist/helper/vault.js not available");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("vault");

    // 1. TS creates the vault and writes a credential.
    run_ts_cli(
        &vault_js,
        &[
            "set",
            dir.to_str().unwrap(),
            "token",
            "github",
            "ghp-from-ts",
        ],
    );

    // 2. Rust opens the SAME vault (master key + vault.enc already on disk) and writes another one.
    let vault = Vault::new(&dir);
    vault.prepare().unwrap();
    if !vault.dir.join("master.key").exists() {
        // Explicit legacy fixture: production code never creates this file.
        std::fs::write(vault.dir.join("master.key"), [7u8; 32]).unwrap();
        std::fs::set_permissions(
            vault.dir.join("master.key"),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .unwrap();
    }
    vault.init_legacy().unwrap();
    vault
        .set(SetParams {
            r#type: "token".into(),
            name: "gitlab".into(),
            value: Some("glpat-from-rust".into()),
            ..Default::default()
        })
        .unwrap();

    // 3. TS reads both back -- the one it wrote itself, and the one Rust just added to the same file.
    let from_ts_original = run_ts_cli(
        &vault_js,
        &["get", dir.to_str().unwrap(), "token", "github"],
    );
    assert!(from_ts_original.contains("ghp-from-ts"));
    let from_ts_new = run_ts_cli(
        &vault_js,
        &["get", dir.to_str().unwrap(), "token", "gitlab"],
    );
    assert!(from_ts_new.contains("glpat-from-rust"));

    // 4. Rust still reads its own write back correctly too.
    assert_eq!(
        vault.get("token", "gitlab").unwrap().value,
        "glpat-from-rust"
    );
}
