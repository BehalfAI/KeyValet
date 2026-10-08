## What this changes and why

<!-- One or two sentences. Link the issue this closes, if any. -->

## Checklist

- [ ] Commits are signed off (`git commit -s`) — see [CONTRIBUTING.md](../CONTRIBUTING.md#sign-off-dco)
- [ ] `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace --locked` pass locally (in `rust/`)
- [ ] Added or updated a test for any security-relevant change
- [ ] Updated `README.md` / `README.zh-CN.md` / `docs/guide.md` / `docs/guide.zh-CN.md` / `SECURITY.md` if behavior changed
- [ ] If this is a new credential template: the service's official auth docs are linked below, and it isn't copied from a source whose license forbids redistribution

## Anything reviewers should look at closely

<!-- e.g. "this touches the root helper's trust check", "this changes the vault file format" -->
