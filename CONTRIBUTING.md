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

The TypeScript tree under `src/` predates the Rust rewrite and is kept for now; `npm install && npm test` still exercises it. New work goes in `rust/`.

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

User-facing text is bilingual: wrap it with `t("中文", "English")` from `src/shared/i18n.ts`. In the root helper, call `t()` at the point of use (the language is set during the handshake), never in module-level constants. Tests run with `KEYVALET_LANG=zh`; `src/test/i18n.test.ts` checks that the English UI contains no Chinese.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — please report privately.
