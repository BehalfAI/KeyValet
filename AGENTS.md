# AGENTS.md

## Verify changes (same as CI, run in `rust/`)

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --locked
cargo test --workspace --locked
```

CI (`.github/workflows/test.yml`) runs these on a clean `macos-latest` runner with the latest stable
Rust. Run clippy with the current stable too when the local toolchain is older (`cargo +<version>`).

## Tests must not depend on this machine's KeyValet install

The CI runner has no `/usr/local/lib/keyvalet`, `/var/db/keyvalet`, `/var/run/keyvalet`, sudoers rule
or GUI session. A test that reads installed templates, trust-checks an installed binary, or talks to
the daemon passes locally and fails in CI. Load repo files via `env!("CARGO_MANIFEST_DIR")`, keep
trust checks inside the real process runner (not in logic that tests drive with a fake runner), and
mark tests that need root, sudo or Touch ID `#[ignore]` with how to run them.

## scripts/install.sh

The root part is one single-quoted `sh -eu -c '...'` string: never put a single quote (apostrophe)
anywhere inside it, comments included, and assign every variable it uses from its positional
arguments. `sh -n` does not catch either mistake.

## Code signing and daemon mode

Team `PWCRJPY7YC` (Simvito Limited). The installer enables the launchd daemon + per-user agent only
when `kv-helper` and `kv-touchid` are signed by that team; otherwise it installs the sudo mode. The
daemon trusts the agent only after checking its audit-token code signature (`AGENT_REQUIREMENT` in
`kv-platform/src/paths.rs`).

## Releases

Push a `vX.Y.Z` tag matching `rust/crates/kv-cli/Cargo.toml`; `.github/workflows/release.yml`
builds `keyvalet-<tag>-macos-arm64.tar.gz` + `SHA256SUMS` into a draft release, with notes from
`.github/release-notes/<tag>.md` (`marketing/` is gitignored). A maintainer publishes the draft.

The job runs in the protected `release` environment (a reviewer approves each run; its secrets
hold the Developer ID p12, imported into a temporary keychain that the run deletes at the end). Every binary in a workflow
package is signed with the Simvito Limited Developer ID (`PWCRJPY7YC`, hardened runtime,
timestamped; not notarized). `REQUIRE_SIGNED=1` makes signing mandatory;
`SIGN_IDENTITY=<sha1> scripts/package-release.sh <tag>` signs a local package.
Dry run without a tag: **Actions → release → Run workflow** (`workflow_dispatch`) builds and
signs the package and uploads it as an artifact — no release is created.
