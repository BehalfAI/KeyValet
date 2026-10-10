+++
title = "KeyValet vs 1Password for AI agents"
description = "1Password manages your logins; KeyValet manages your agent’s API calls. A detailed, honest comparison — including where 1Password is ahead."
+++

**Short version: 1Password manages your logins. KeyValet manages your agent's API calls.** They're not really competing — most KeyValet users should keep using 1Password for what it's good at, and a 1Password storage backend (reading `op://` references live) is on our roadmap.

This page is specific about where that line is, because "it's complementary" is the kind of thing every vendor says and almost never backs up with detail. Here's the detail.

## What 1Password actually does for agents today

As of October 2026, 1Password's agent-facing features are real but narrow:

- **1Password for Claude** (beta, July 2026): when Claude needs to log into a website in Chrome, 1Password shows a biometric prompt naming the credential and the stated reason, then fills the form — Claude never sees the password. Requires a Mac, Claude Desktop, and the 1Password browser extension. It doesn't cover Claude Code.
- **Agentic Autofill** (early access, via Browserbase): the same idea for browser-automation agents — approve once per autofill, the agent gets a filled form, not a password.
- **Environments MCP** (Codex, Cursor): lets an agent see variable *names* in a 1Password Environment, never the values. The program itself still reads the real value from a local `.env`-style file at runtime.
- **op CLI**: a single Touch ID unlock authorizes the **entire account**, bound to that terminal session, for up to 12 hours. Inside that window, anything running in that shell — including a compromised dependency's postinstall script — can read any credential in the vault with `op read`.
- **SSH Agent**: the closest thing 1Password has to KeyValet's model. You can require approval per key, per app, or per request — but the prompt shows *which process* is asking, not *what it's about to do with the key*, and there's no purpose field.
- **Credential Broker** (enterprise, preview): issues static vault secrets to CI workloads via OIDC. Enterprise-only, and it's issuing the same long-lived credential, not a short-lived one.

None of this is a knock on 1Password — browser login is a hard, well-solved problem for them, and it's not what KeyValet is trying to solve.

## Where the gap is

| | 1Password | KeyValet |
|---|---|---|
| **What it's built for** | A human logging into a website | An agent calling an API |
| **Approval granularity** | Browser: per autofill. CLI: per *account*, up to 12h | Per credential, per call, or per session — your choice |
| **Does the agent ever see the key?** | In the browser flow, no. Via `op read` in an unlocked shell, or Environments' injected `.env`, yes | No — `credential_http_request` makes the call and returns only the response |
| **Shows *why* / *what* in the approval prompt** | Only in the Claude browser beta; not logged to a queryable audit trail as far as we could confirm | The prompt shows *what* — the real request — rather than the agent's free-text reason; the stated purpose is recorded in the audit log with every use |
| **Shows *what request* in the approval prompt** | No | Yes, in per-use mode — method, host, path, built from the actual outbound call |
| **Issues short-lived tokens** (OAuth refresh, JWT, GitHub App installation tokens, AWS STS) | No — distributes long-lived static secrets and TOTP codes | Yes — OAuth refresh, GitHub App installation tokens, Google service-account tokens, signed JWTs, TOTP codes, AWS STS; the agent only ever holds the short-lived result |
| **Blocks a secret from being written into a shell command or file** | No | Yes — hook adapters for Claude Code, Codex, Cursor, Grok Build and Devin CLI flag it before it lands |
| **Where it runs** | Account unlocks in a shared desktop session or terminal | Local macOS vault; per-MCP-session authorization |

The pattern: 1Password's agent features are extensions of its core job — a human authenticating to open something. KeyValet's job starts after that: an *agent*, not a human, making repeated, automated calls, where "approve once, trust for 12 hours" is exactly the wrong shape, because the agent — not you — is the one making decisions about when to use the key next.

## Where 1Password is ahead, honestly

- **Ecosystem and distribution.** 1Password is an official integration partner for Anthropic, OpenAI, and Cursor. If you just need "Claude can log into my accounts in the browser," it's already there and well-supported.
- **Browser login, full stop.** Agentic Autofill and 1Password for Claude solve a real, different problem — filling forms with credentials a human would otherwise type — better than anything we build, because it's not what KeyValet does.
- **Multi-device sync and team vaults.** 1Password's cross-device sync and shared-vault UX are years more mature than anything KeyValet offers today (our Team features are still in development — see the roadmap).
- **SSH agent approval granularity** is genuinely good, and close in spirit to what KeyValet does for API calls.

## Use both

If you're already a 1Password user, nothing here asks you to leave. A 1Password storage backend is planned: when it ships, you'll point a credential at an `op://vault/item/field` reference and KeyValet will read it live — rotate the value in 1Password and KeyValet picks up the change automatically, with no copy to keep in sync. Until then, 1Password keeps handling what it's good at (your logins, your team's shared vaults); KeyValet handles the part 1Password's own docs say is still on their roadmap — short-lived, purpose-scoped, per-call authorization for things that aren't a human typing a password into a browser.

---

**Sources:** [1Password for Claude press release](https://1password.com/press/2026/july/1password-for-claude) · [1Password Agentic Autofill](https://www.1password.dev/agentic-autofill) · [1Password Environments MCP](https://1password.com/blog/the-1password-environments-mcp-server-is-now-on-cursor-marketplace) · [op CLI security model](https://www.1password.dev/cli/app-integration-security/) · [1Password SSH Agent security](https://www.1password.dev/ssh/agent/security/) · [1Password Credential Broker](https://1password.com/blog/1password-credential-broker-public-preview) · [1Password Activity Log](https://support.1password.com/activity-log/)

*Found something on this page that's changed since we checked? [Open an issue](https://github.com/KeyValet/KeyValet/issues/new) — 1Password ships new agent features fast and we'd rather be corrected than stale.*
