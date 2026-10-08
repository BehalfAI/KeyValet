# KeyValet

**Give your AI agents a valet key, not your master key.**

KeyValet is a local credential broker for AI agents on macOS. It lets agents such as Claude Code, Cursor and Codex *use* your API keys, OAuth accounts and other secrets over [MCP](https://modelcontextprotocol.io) — without the secrets ever entering the model's context. You approve each credential with Touch ID, and every use is logged with its stated purpose.

[简体中文](guide.zh-CN.md) · [Security model](../SECURITY.md)

> **Status:** early (0.1). macOS only. UI in English and 简体中文 — follows your macOS language; override with `KEYVALET_LANG=en|zh`.

---

## Why

AI agents increasingly call real services on your behalf. Today the options are poor:

| Approach | Problem |
|---|---|
| `.env` files / pasting keys into chat | The agent reads plaintext keys; they leak into logs, commits, prompt injections |
| Password-manager CLIs | Not agent-aware: no purpose, no per-use approval, still returns plaintext |
| Hosted agent-auth platforms | Your tokens live in someone else's cloud |
| Team secret managers | Built for servers and teams, heavy for one developer |

KeyValet's answer: **secrets stay on your machine, owned by root. Agents ask; you approve with a fingerprint; the broker makes the call.**

## How it works

```
 AI agent ──MCP──▶ KeyValet server (your user)
                        │  sudo -n (rule allows ONLY the helper)
                        ▼
                  root helper ── Touch ID gate ("Use credential X — purpose: …")
                        │
          ┌─────────────┼───────────────────────┐
   encrypted vault   HTTPS proxy            protocol engines
   /var/db/keyvalet  (inject key/token,     (OAuth refresh, service accounts,
   (root, 0700)       allowed hosts only,    GitHub App, JWT, TOTP, AWS STS)
                      redact responses)
```

- **Use, don't see.** `credential_http_request` makes the HTTP call inside the root helper with the key/token injected; the agent only gets the (redacted) response.
- **SDKs and streaming too.** `credential_gateway` gives programs that can't speak MCP a per-session local endpoint (`OPENAI_BASE_URL=…`). Streaming responses flow through, redacted on the fly; the program never holds the real key.
- **You're in the loop.** By default every credential needs its own Touch ID approval, and the prompt shows *which* credential and *why*.
- **Audited.** Every unlock, read, token fetch and proxied call is logged with session, purpose and result (never the secret). Agents can query the log.
- **Local and root-isolated.** AES-256-GCM vault readable only by root; code that runs as root is installed root-owned and self-verifies before running.
- **Speaks every auth.** OAuth 2.0 (auth code + PKCE, device code, client credentials, auto-refresh), Google service accounts, GitHub Apps, signed JWTs (e.g. App Store Connect), TOTP, AWS STS (AssumeRole + MFA), IMAP XOAUTH2 — plus a template catalog of common APIs.

## What it is not

- Not a password manager for humans (no UI, sync or browser autofill).
- Not a team secret manager.
- Not a sandbox: once you grant a session a credential, a malicious agent with shell access could misuse *that* grant. KeyValet narrows the blast radius (per-credential grants, proxy-only, host allowlists, short-lived tokens) and records everything. See [SECURITY.md](../SECURITY.md).

## Requirements

- macOS (Touch ID recommended; without it the system prompt asks for your login password — handled by macOS, never seen by KeyValet)
- Node.js ≥ 20 from nvm or nodejs.org (Homebrew's node links user-writable libraries and is refused for root use)
- Xcode Command Line Tools (`xcode-select --install`) for the Swift Touch ID helper

## Install

```sh
curl -fsSL https://keyvalet.dev/install.sh | sh
```

This downloads the latest release (or `main`), checks the requirements, runs the installer (it asks for your password once) and registers KeyValet with Claude Code if it is installed. Re-run it to upgrade; uninstall with `curl -fsSL https://keyvalet.dev/install.sh | sh -s -- --uninstall`. From a clone you can run `./scripts/install.sh` directly.

The installer builds everything, copies it to root-owned `/usr/local/lib/keyvalet`, creates the vault at `/var/db/keyvalet`, installs the `keyvalet` CLI, and adds **one** sudoers rule (`/etc/sudoers.d/keyvalet`) that lets your user start *only* the KeyValet helper without a password — the helper then requires Touch ID before doing anything. The rule is validated with `visudo` before and after installation.

If Claude Code isn't installed (or you set `KEYVALET_NO_REGISTER=1`), register manually, e.g.:

```sh
claude mcp add keyvalet --scope user -- /usr/local/lib/keyvalet/bin/node /usr/local/lib/keyvalet/app/dist/server/index.js
```

Other clients (Cursor, etc.): add a stdio server with command `/usr/local/lib/keyvalet/bin/node` and argument `/usr/local/lib/keyvalet/app/dist/server/index.js`.

Your vault is kept across upgrades. `./scripts/uninstall.sh --purge` (from a clone) also deletes the vault.

## Quick start (what your agent does)

```text
credential_templates    { query: "openai" }
credential_set          { template: "openai", name: "main", purpose: "Store my OpenAI key" }
                          → a native dialog asks YOU for the key (not the agent); proxy + test are configured and the key is verified
credential_http_request { name: "main", url: "https://api.openai.com/v1/models", purpose: "List models" }
                          → Touch ID: "Request: GET api.openai.com/v1/models — Purpose: List models" → response returned, key never shown
credential_audit_log    { this_session_only: true }
```

Programs and SDKs (streaming works):

```text
credential_gateway { name: "main", purpose: "Run the summarizer script" }
  → { sdk_env: { OPENAI_BASE_URL: "http://127.0.0.1:52011/<session-token>/api.openai.com/v1", OPENAI_API_KEY: "keyvalet" } }
```
```sh
OPENAI_BASE_URL=… OPENAI_API_KEY=keyvalet python summarize.py   # streams; the script never sees the real key
```

OAuth example (browser flow with PKCE; the refresh token stays in the vault):

```text
credential_oauth_login    { provider: "google", client_id: "…", name: "work", scopes: ["https://www.googleapis.com/auth/drive.readonly"], purpose: "…" }
credential_configure_http { name: "work", allowed_hosts: ["www.googleapis.com"], purpose: "…" }   # you confirm in a dialog
credential_http_request   { name: "work", url: "https://www.googleapis.com/drive/v3/files", purpose: "…" }
```

## Key concepts

### Grant modes

| Mode | Touch ID |
|---|---|
| `per_use` | every time a credential is used |
| `per_credential` (**default**) | once per credential per session; credentials you create in the session are granted automatically |
| `per_session` | once per session, then every credential |
| `remember` | once, then no prompts in **any** session for `remember_hours` (default 8; `0` = forever) |

Listing, templates and audit queries never need Touch ID.

**Change it from inside Claude Code** with the plugin's slash commands (installed by the one-line installer):

```text
/keyvalet:mode remember 8      # Touch ID once, then remembered for 8 hours
/keyvalet:mode per-use         # strictest
/keyvalet:status               # current mode, remembered-until, grants of this session
/keyvalet:lock                 # lock now and forget the remembered authorization
/keyvalet:audit 20             # recent usage
/keyvalet:add stripe           # store a new key via the private dialog
```

Rules that keep this safe:

- The mode lives in the root-only `/var/db/keyvalet/settings.json`. **Loosening** (a more permissive mode or a longer remember window) requires your **Touch ID** — not a clickable dialog — so an agent can't loosen it on its own. Tightening applies immediately. Changes take effect in the current session as well.
- A client can only make it **stricter**: e.g. register Codex with `KEYVALET_GRANT_MODE=per_use`; the stricter of the global and the client setting wins.
- In `remember` mode any local process can use your credentials without a prompt until the window ends (secrets still stay hidden and every use is audited). `/keyvalet:lock` ends it early.
- From a terminal: `keyvalet grant-mode remember 8`, `keyvalet grant-mode forget`.

### Keeping KeyValet up to date (Claude Code plugin)

The plugin makes Claude Code maintain your vault for you:

- **Paste a key in the chat** ("here's my Stripe key: sk_live_…") and Claude stores it in KeyValet with the matching template, then uses it through the proxy or gateway instead of a `.env` file. A `UserPromptSubmit` hook recognizes ~25 key formats (OpenAI, Anthropic, GitHub, AWS, Stripe, Slack, Google, …) and tells Claude what to store, showing only a masked preview.
- **Better: `/keyvalet:add openai`** — you type the key into KeyValet's private dialog, so it never passes through the chat or the model provider's logs.
- **Before a literal key is written to a file or shell command**, a `PreToolUse` hook asks you to confirm and points Claude to KeyValet instead. This also catches values KeyValet itself already handed back this session (via `credential_get`, `credential_totp_code`, `credential_access_token`, `credential_aws_credentials`) by exact match, not just known key formats — so a value with no recognizable prefix (an app password, an authorization code) is still caught if Claude tries to put it in a command or a file.
- Claude also offers to move secrets it finds in `.env`/config files into KeyValet, and to replace a stored key when it stops working (401/403).

Disable the hooks with `KEYVALET_HOOKS=off` in the environment Claude Code runs in.

### Purpose and audit

Every tool that reads, uses or changes a credential **requires** a `purpose`. It is shown in the Touch ID prompt and written to the audit log (`/var/db/keyvalet/audit.log`, root-only, rotated at 10 MB). The root helper enforces this too. For `credential_http_request`/`credential_test`, the prompt also shows a request line (method, host, path — never the query string) built from the call about to be made. Both the purpose and the request line are the agent's *claim* — read them before approving.

### Proxy calls

- HTTPS only, port 443, and the hostname must be in the credential's `allowed_hosts` (domains only — no IPs or localhost).
- Redirects are not followed.
- Secrets (and common encodings: URL, form, JSON, base64, hex; case-insensitive) are replaced with `[REDACTED]` in responses and error messages; binary responses containing a secret are refused.
- Works for static credentials (template or manual injection rule) and for OAuth / service-account / GitHub App / JWT credentials (bearer token injected automatically).
- `proxy_only: true` makes `credential_get` and `credential_access_token` refuse to return the raw secret.
- Expanding exposure (new hosts, changed injection, turning off proxy-only, removing the config), overwriting and deleting credentials all require **your** confirmation in a dialog shown by the root helper itself — not just by the MCP server.

### Streaming and the local gateway

- `credential_http_request` reads streaming (SSE) responses in full and returns the text assembled from LLM deltas in `stream.text` (OpenAI Chat Completions and Responses, Anthropic, Gemini formats).
- `credential_gateway` opens a per-session gateway on `127.0.0.1` for programs: `http://127.0.0.1:<port>/<token>/<host>/<path>` → `https://<host>/<path>`. The gateway drops whatever auth headers the program sends, injects the real credential, enforces the host allowlist, never follows redirects, and redacts responses while streaming (it holds back only bytes that could be the start of a secret). The token is random per credential and session, requests must target `127.0.0.1`/`localhost` (DNS-rebinding protection), and every request is audited. For known templates it returns ready-to-use SDK environment variables.

When a tool needs the secret as a local file to work (the typical example: an SSH private key used with `ssh -i`), use `credential_export_file` — only the file path goes back to the agent, never the content, and the file is deleted automatically when the session ends.
When neither fits and the raw value itself is genuinely needed (e.g. a database password), `credential_get` still returns the value after your approval.

### Templates

- **Built-in:** `bearer`, `header`, `query`, `basic` for any HTTP API.
- **Catalog** (`templates/catalog.json`, Apache-2.0): ~50 common services — OpenAI, Anthropic, Gemini, Mistral, Groq, DeepSeek, GitHub, GitLab, Cloudflare, Vercel, Stripe, Slack, Notion, Jira, Linear, Twilio, SendGrid and more. Edit `scripts/build-catalog.mjs` and run `npm run templates:build`. Corrections and additions are welcome.
- **Optional n8n import:** if you have an n8n checkout, `npm run templates:import -- /path/to/n8n` generates `templates/n8n-catalog.json` (~400 more services) **for your own use only** — n8n's Sustainable Use License does not allow redistributing it, so it is git-ignored and never shipped.

### Credential kinds

| Kind | Set up with | Agent receives |
|---|---|---|
| `static` | `credential_set` (template or value) | proxied responses, or the value via `credential_get` |
| `oauth2` | `credential_oauth_login` (presets: google, github, microsoft, outlook, outlook_graph, gitlab, dropbox; any OIDC issuer; manual endpoints) | access token (auto-refreshed) or proxied responses |
| `google_service_account` | `credential_setup_google_service_account` | 1-hour access token (scopes limited to those configured) |
| `github_app` | `credential_setup_github_app` | 1-hour installation token (optionally narrowed) |
| `jwt` | `credential_setup_jwt` | short-lived signed JWT |
| `totp` | `credential_setup_totp` | the current code |
| `aws` | `credential_setup_aws` | STS temporary credentials (AssumeRole, TOTP-based MFA) |

Long-term secrets of protocol credentials (client secrets, refresh tokens, private keys, TOTP seeds, AWS secret keys) never leave the root helper.

> Personal Outlook.com accounts: IMAP with OAuth is currently broken on Microsoft's side ("User is authenticated but not connected", since Dec 2024). Use the `outlook_graph` preset (Microsoft Graph) instead.

## Tools

| Tool | Purpose |
|---|---|
| `credential_status` / `credential_unlock` / `credential_lock` | Session state; Touch ID unlock (optionally granting a credential); lock |
| `credential_settings` | View / change the grant mode |
| `credential_audit_log` | Query the audit log |
| `credential_list` / `credential_list_types` / `credential_get` | List metadata; read a static value (unless proxy-only) |
| `credential_export_file` | Write a static credential's raw value to a private temp file, returning only the path; for SSH keys and other secrets that must be a local file |
| `credential_set` / `credential_delete` / `credential_create_type` / `credential_delete_type` | Manage credentials |
| `credential_templates` | Search templates |
| `credential_http_request` / `credential_test` / `credential_configure_http` | Proxy calls (incl. SSE), verification, proxy configuration |
| `credential_gateway` | Local gateway URL for SDKs/CLIs, with streaming |
| `credential_oauth_login` / `credential_access_token` | OAuth authorization; short-lived tokens |
| `credential_setup_google_service_account` / `_github_app` / `_jwt` / `_totp` / `_aws` | Protocol credentials |
| `credential_totp_code` / `credential_aws_credentials` | TOTP code; AWS temporary credentials |
| `credential_imap_test` / `credential_graph_mail_test` | Verify mailbox access (IMAP XOAUTH2 / Microsoft Graph) |

## CLI (for you, in a terminal)

```sh
keyvalet set api_key openai               # hidden input; or: pbpaste | keyvalet set token github
keyvalet list
keyvalet get api_key openai
keyvalet audit 20
keyvalet grant-mode per-credential        # or: all
```

Each command runs through `sudo -k`, so it asks for your password every time.

## Development

```sh
npm install
npm test          # unit + integration tests in temp dirs with local mock servers; no root needed
```

Layout: `src/server` (MCP server, runs as you) · `src/helper` (root helper: vault, protocols, proxy, Touch ID gate) · `src/native/touchid.swift` · `src/cli` · `scripts/` (install, catalog build, optional n8n import).

See [CONTRIBUTING.md](../CONTRIBUTING.md).

## License

[Apache-2.0](../LICENSE). The optional n8n-derived catalog you may generate locally is subject to n8n's license and is not part of this project.
