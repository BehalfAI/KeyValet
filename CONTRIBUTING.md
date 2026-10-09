# Contributing to KeyValet

Thanks for your interest! KeyValet handles secrets and runs code as root, so changes are reviewed with security first.

## Setup

The live implementation is the Rust workspace in `rust/` (what `scripts/install.sh` actually builds and ships):

```sh
cd rust
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --locked
cargo test --workspace --locked
```

CI runs exactly these four commands; a PR with `cargo clippy` warnings or unformatted code will not pass. Tests run as your normal user in temporary directories with local mock servers — no root, no network, no Touch ID needed. Install (`./scripts/install.sh`) only when you want to try the real flow.

There used to be a TypeScript implementation under `src/`; it's gone now that the Rust rewrite in `rust/` is the only implementation. All new work goes there.

## Ground rules

- **Security checks belong in the root helper (`rust/crates/kv-helper`)**, never only in the MCP server (`rust/crates/kv-mcp`): an agent can talk to the helper directly.
- Never put agent-controlled free text into secret-input dialogs; only validated identifiers/hosts.
- Never return, log or include in error messages any secret (or a string built from one).
- Keep the helper's dependency list small; justify any new crate in the PR description.
- Every security-relevant change needs a regression test.
- Keep `README.md`, `README.zh-CN.md`, `site/guide.md`, `site/guide.zh-CN.md` and `SECURITY.md` in sync with behavior changes.

## Sign-off (DCO)

Every commit must be signed off (`git commit -s`), certifying you have the right to submit the change under [the Developer Certificate of Origin](https://developercertificate.org/). This is a `Signed-off-by: Name <email>` trailer, not a cryptographic signature — most contributors just add `-s` to their usual `git commit`. PRs with unsigned commits will be asked to amend before merge.

## Templates

The catalog lives in `scripts/build-catalog.mjs` (regenerate with `npm run templates:build`). Each template must come from the service's **official API documentation** — please link the docs in your PR. Do not copy templates from projects whose license forbids redistribution (e.g. n8n's Sustainable Use License).

## Localization

User-facing text is bilingual: wrap it with `kv_i18n::t("中文", "English")` (`rust/crates/kv-i18n`). In the root helper, call `t()` at the point of use (the language is set during the handshake), never in module-level constants. Tests run with `KEYVALET_LANG=zh`. Outside of `t()` calls, source code (comments, identifiers, non-bilingual strings) is English only.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — please report privately.
