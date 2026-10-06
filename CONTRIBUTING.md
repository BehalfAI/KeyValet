# Contributing to KeyValet

Thanks for your interest! KeyValet handles secrets and runs code as root, so changes are reviewed with security first.

## Setup

```sh
npm install
npm test
```

Tests run as your normal user in temporary directories with local mock servers — no root, no network, no Touch ID needed. Install (`./scripts/install.sh`) only when you want to try the real flow.

## Ground rules

- **Security checks belong in the root helper (`src/helper`)**, never only in the MCP server (`src/server`): an agent can talk to the helper directly.
- Never put agent-controlled free text into secret-input dialogs; only validated identifiers/hosts.
- Never return, log or include in error messages any secret (or a string built from one).
- The helper depends only on Node.js built-ins.
- Every security-relevant change needs a regression test.
- Keep `README.md`, `README.zh-CN.md` and `SECURITY.md` in sync with behavior changes.

## Templates

The catalog lives in `scripts/build-catalog.mjs` (regenerate with `npm run templates:build`). Each template must come from the service's **official API documentation** — please link the docs in your PR. Do not copy templates from projects whose license forbids redistribution (e.g. n8n's Sustainable Use License).

## Localization

User-facing text is bilingual: wrap it with `t("中文", "English")` from `src/shared/i18n.ts`. In the root helper, call `t()` at the point of use (the language is set during the handshake), never in module-level constants. Tests run with `KEYVALET_LANG=zh`; `src/test/i18n.test.ts` checks that the English UI contains no Chinese.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — please report privately.
