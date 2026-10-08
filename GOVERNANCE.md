# Governance

KeyValet is developed in the open on GitHub and operated by **Simvito
Limited**. Decisions are made in public issues, discussions, and pull
requests — there is no private roadmap.

## Promises

- **Everything released under Apache-2.0 stays Apache-2.0.** We will not
  move a feature that has shipped under Apache-2.0 into a more restrictive
  license, and we will not relicense past releases.
- **All local functionality is free forever**, without time limits, feature
  gates, or degraded security compared to any paid tier we introduce.
- **A self-hosted deployment will always be available** and will never
  require an account with us or phone-home licensing.
- **If the project is discontinued**, we will announce it at least 90 days
  in advance and publish a final version that can be fully self-hosted,
  with no functionality held back.

## Roles

- **Maintainers** triage issues and review/merge pull requests. KeyValet
  has one maintainer at the time of writing; see
  [CONTRIBUTING.md](CONTRIBUTING.md) if you'd like to help and become one.
- **Release keys and trademarks** (see [TRADEMARK.md](TRADEMARK.md)) are
  held by Simvito Limited, independent of any individual maintainer.

## How decisions get made

- **Day-to-day changes** (bug fixes, templates, documentation, small
  features) are reviewed and merged by a maintainer like any normal PR.
- **Protocol-level changes** — anything that changes the IPC protocol, the
  vault file format, the policy/approval model, or another
  backward-compatibility-sensitive surface — go through a design discussion
  in a public issue (tag it `rfc`), open for at least 7 days, before being
  implemented. The outcome is recorded as a short ADR under `docs/adr/`.
- **Security issues** follow [SECURITY.md](SECURITY.md), not the public
  process above, until a fix is ready to disclose.

## Versioning

KeyValet follows [Semantic Versioning](https://semver.org/). While the
project is in `0.x`, a minor version bump may still carry a breaking change
to the protocol or vault format; such changes are called out in the release
notes with a migration note. From `1.0` onward, breaking changes require a
major version bump.

## Changing this document

Proposed changes to this file go through the same `rfc`-tagged issue
process described above.
