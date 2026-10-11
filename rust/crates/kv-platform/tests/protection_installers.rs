//! Execute the packaged Linux installer with fake system commands. No command reaches sudo,
//! systemd, a TPM, installed KeyValet binaries, user configuration, or the network.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

fn executable(path: &Path, script: &str) {
    std::fs::write(path, script).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn install(
    initial: &str,
    resource_manager: &str,
    args: &[&str],
    setup_fails: bool,
) -> (Output, String) {
    let temp = tempfile::tempdir().unwrap();
    let package = temp.path().join("package with spaces");
    let mocks = temp.path().join("commands");
    for directory in ["scripts/linux", "templates", "bin"] {
        std::fs::create_dir_all(package.join(directory)).unwrap();
    }
    std::fs::create_dir(&mocks).unwrap();
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap();
    for file in [
        "scripts/install-linux.sh",
        "scripts/install-linux-root.sh",
        "scripts/linux/keyvalet.service",
        "scripts/linux/dev.keyvalet.policy",
        "templates/catalog.json",
    ] {
        std::fs::copy(repo.join(file), package.join(file)).unwrap();
    }
    for binary in ["kv-helper", "kv-cli", "kv-mcp", "kv-hook"] {
        executable(&package.join("bin").join(binary), "#!/bin/sh\nexit 88\n");
    }
    executable(&mocks.join("uname"), "#!/bin/sh\nprintf 'Linux\\n'\n");
    executable(
        &mocks.join("id"),
        "#!/bin/sh\n[ \"${1:-}\" = -u ] || exit 88\nprintf '1001\\n'\n",
    );
    executable(&mocks.join("getent"), "#!/bin/sh\nexit 2\n");
    for command in ["systemctl", "pkcheck", "pkttyagent", "tpm2_ecdhzgen"] {
        executable(&mocks.join(command), "#!/bin/sh\nexit 88\n");
    }
    executable(
        &mocks.join("sudo"),
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$KV_TEST_LOG"
case "${1:-}" in
  /bin/sh)
    [ "$2" = "$KV_TEST_PACKAGE/scripts/install-linux-root.sh" ] || exit 88
    exit 0 ;;
  -k) exit 0 ;;
  /usr/local/lib/keyvalet/bin/kv-cli) shift ;;
  *) echo 'Unexpected privileged command in test' >&2; exit 88 ;;
esac
[ "$1" = --lang ] || exit 88
shift 2
kv_test_provider=$(cat "$KV_TEST_STATE")
case "$1" in
  status)
    [ "${2:-}" = --summary ] || exit 88
    printf '=== Protection summary: %s ===\n' "$kv_test_provider"
    case "$kv_test_provider" in
      software_key) echo 'SOFTWARE PROTECTION ONLY' ;;
      tpm2) echo 'TPM interface: UNCONFIRMED (unknown)' ;;
      uninitialized) echo 'NOT CONFIGURED' ;;
      *) exit 88 ;;
    esac ;;
  protection)
    printf '{\n  "provider": "%s",\n  "tpm": {"resource_manager_present": %s}\n}\n' "$kv_test_provider" "$KV_TEST_RESOURCE_MANAGER" ;;
  setup-software|setup-tpm)
    if [ "$KV_TEST_SETUP_FAILS" = 1 ]; then echo 'Simulated setup refusal' >&2; exit 19; fi
    case "$1" in setup-software) echo software_key ;; setup-tpm) echo tpm2 ;; esac > "$KV_TEST_STATE" ;;
  *) echo 'Unexpected CLI command in test' >&2; exit 88 ;;
esac
"#,
    );
    let state = temp.path().join("provider");
    let log = temp.path().join("calls");
    std::fs::write(&state, initial).unwrap();
    let output = Command::new("/bin/sh")
        .arg(package.join("scripts/install-linux.sh"))
        .args(args)
        .arg("--no-register")
        .env("PATH", format!("{}:/usr/bin:/bin", mocks.display()))
        .env("KEYVALET_LANG", "en")
        .env("KV_TEST_PACKAGE", &package)
        .env("KV_TEST_STATE", &state)
        .env("KV_TEST_LOG", &log)
        .env("KV_TEST_RESOURCE_MANAGER", resource_manager)
        .env("KV_TEST_SETUP_FAILS", if setup_fails { "1" } else { "0" })
        .output()
        .unwrap();
    let calls = std::fs::read_to_string(log).unwrap();
    (output, calls)
}

#[test]
fn explicit_software_install_shows_actual_state_before_and_after_setup() {
    let (output, calls) = install("uninitialized", "false", &["--software"], false);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let before = stdout.find("Protection summary: uninitialized").unwrap();
    let after = stdout.find("Protection summary: software_key").unwrap();
    assert!(before < after);
    assert!(stdout.contains("SOFTWARE PROTECTION ONLY"));
    assert_eq!(calls.matches("status --summary").count(), 2);
    assert_eq!(calls.matches("setup-software").count(), 1);
    assert!(!calls.contains("setup-tpm"));
}

#[test]
fn tpm_setup_uses_the_reported_device_and_never_claims_physical_hardware() {
    let (output, calls) = install("uninitialized", "true", &[], false);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Protection summary: tpm2"));
    assert!(stdout.contains("UNCONFIRMED (unknown)"));
    assert_eq!(calls.matches("setup-tpm").count(), 1);
    assert!(!calls.contains("setup-software"));
}

#[test]
fn upgrades_display_the_saved_provider_without_changing_it_to_match_install_flags() {
    for (provider, args) in [("tpm2", vec!["--software"]), ("software_key", vec![])] {
        let (output, calls) = install(provider, "false", &args, false);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            stdout
                .matches(&format!("Protection summary: {provider}"))
                .count(),
            2
        );
        assert!(!calls.contains("setup-software") && !calls.contains("setup-tpm"));
    }
}

#[test]
fn skipped_setup_still_displays_protection_and_never_queries_or_configures_keys() {
    for provider in ["uninitialized", "software_key", "tpm2"] {
        let (output, calls) = install(provider, "false", &["--no-setup"], false);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains(&format!("Protection summary: {provider}")));
        assert_eq!(calls.matches("status --summary").count(), 1);
        assert!(
            !calls.contains("protection")
                && !calls.contains("setup-software")
                && !calls.contains("setup-tpm")
        );
    }
}

#[test]
fn absent_or_unknown_tpm_and_failed_setup_do_not_print_installation_success() {
    for present in ["false", "null"] {
        let (output, calls) = install("uninitialized", present, &[], false);
        assert!(!output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("Protection summary: uninitialized"));
        assert!(!stdout.contains("KeyValet installed"));
        assert!(!calls.contains("setup-tpm") && !calls.contains("setup-software"));
    }
    let (output, calls) = install("uninitialized", "false", &["--software"], true);
    assert!(!output.status.success());
    assert!(!String::from_utf8(output.stdout)
        .unwrap()
        .contains("KeyValet installed"));
    assert_eq!(calls.matches("status --summary").count(), 1);
    assert_eq!(calls.matches("setup-software").count(), 1);
}
