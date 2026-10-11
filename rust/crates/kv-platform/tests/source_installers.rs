//! Exercise the source-build sections of the real installers. The script ends before staging,
//! signing, sudo, setup, services or runtime registration. Cargo is a temporary fake executable.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn executable(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn source_build(platform: &str, target: Option<&str>, configured_target: bool) {
    let temp = tempfile::tempdir().unwrap();
    let package = temp.path().join("source with spaces");
    let mocks = temp.path().join("commands");
    let working_directory = temp.path().join("unrelated working directory");
    for path in [
        package.join("scripts"),
        package.join("rust"),
        mocks.clone(),
        working_directory.clone(),
    ] {
        std::fs::create_dir_all(path).unwrap();
    }
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap();
    let source = std::fs::read_to_string(repo.join(if platform == "Darwin" {
        "scripts/install.sh"
    } else {
        "scripts/install-linux.sh"
    }))
    .unwrap();
    let (prefix, _) = source
        .split_once("STAGE=$(mktemp -d)")
        .expect("installer staging boundary changed");
    // Use the actual source-build logic, stopping before any installation operation.
    let script = package.join("scripts/source-build.sh");
    executable(&script, &format!("{prefix}\nprintf '%s\\n' \"$BIN_DIR\"\n"));
    executable(
        &mocks.join("uname"),
        &format!("#!/bin/sh\nprintf '%s\\n' {platform}\n"),
    );
    executable(
        &mocks.join("id"),
        "#!/bin/sh\n[ \"${1:-}\" = -u ] || exit 88\nprintf '1001\\n'\n",
    );
    for name in ["sudo", "systemctl", "pkcheck", "pkttyagent"] {
        executable(&mocks.join(name), "#!/bin/sh\nexit 88\n");
    }
    executable(
        &mocks.join("cargo"),
        r#"#!/bin/sh
set -eu
printf '%s\n' "$@" > "$KV_TEST_BUILD_ARGS"
[ "${1:-}" = build ] || exit 88
shift
kv_test_target=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --release|--locked|--workspace) shift ;;
    --target-dir) kv_test_target=$2; shift 2 ;;
    *) exit 88 ;;
  esac
done
# Model Cargo's own directory selection, which happens after the installer cd into rust.
if [ -z "$kv_test_target" ]; then
  kv_test_target=${CARGO_TARGET_DIR:-${KV_TEST_CONFIGURED_TARGET:-target}}
fi
case "$kv_test_target" in /*) ;; *) kv_test_target="$PWD/$kv_test_target" ;; esac
mkdir -p "$kv_test_target/release"
for binary in kv-helper kv-touchid kv-mcp kv-cli kv-hook; do
  printf '#!/bin/sh\nexit 88\n' > "$kv_test_target/release/$binary"
  chmod 0700 "$kv_test_target/release/$binary"
done
"#,
    );
    let arguments = temp.path().join("cargo-arguments");
    let mut command = Command::new("/bin/sh");
    command
        .arg(&script)
        .current_dir(&working_directory)
        .env("PATH", format!("{}:/usr/bin:/bin", mocks.display()))
        .env("KEYVALET_LANG", "en")
        .env("KV_TEST_BUILD_ARGS", &arguments)
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("KV_TEST_CONFIGURED_TARGET");
    let selected = target.map(|target| {
        if target == "absolute" {
            temp.path()
                .join("absolute build cache")
                .display()
                .to_string()
        } else {
            target.to_owned()
        }
    });
    if let Some(target) = &selected {
        command.env("CARGO_TARGET_DIR", target);
    }
    if configured_target {
        command.env(
            "KV_TEST_CONFIGURED_TARGET",
            temp.path().join("configured Cargo cache"),
        );
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{platform}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let binary_directory = Path::new(stdout.lines().last().unwrap());
    for binary in ["kv-helper", "kv-mcp", "kv-cli", "kv-hook"] {
        let path = binary_directory.join(binary);
        assert!(
            path.is_file(),
            "{platform}: installer looked for {binary} in the wrong directory: {}",
            path.display()
        );
        assert_ne!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o100,
            0
        );
    }
    if let Some(selected) = selected {
        let selected = Path::new(&selected);
        let expected = if selected.is_absolute() {
            selected.to_path_buf()
        } else {
            package.join("rust").join(selected)
        };
        assert_eq!(
            binary_directory.canonicalize().unwrap(),
            expected.join("release").canonicalize().unwrap()
        );
    }
    assert!(std::fs::read_to_string(arguments)
        .unwrap()
        .starts_with("build\n"));
}

#[test]
fn source_installers_find_binaries_in_relative_and_absolute_build_directories() {
    for platform in ["Darwin", "Linux"] {
        for target in [
            Some("relative build cache"),
            Some("../parent build cache"),
            Some("absolute"),
            None,
        ] {
            source_build(platform, target, false);
        }
    }
}

#[test]
fn source_installers_find_the_output_when_cargo_has_a_configured_build_directory() {
    for platform in ["Darwin", "Linux"] {
        source_build(platform, None, true);
    }
}
