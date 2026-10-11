+++
title = "Guide"
description = "How KeyValet works: vault, approvals, proxy calls, hooks and the audit log."
+++

# KeyValet

**Give your AI agents a valet key, not your master key.**

KeyValet is a local credential broker for AI agents on macOS. It lets agents such as Claude Code, Cursor and Codex *use* your API keys, OAuth accounts and other secrets over [MCP](https://modelcontextprotocol.io) — without the secrets ever entering the model's context. You approve each credential with Touch ID, and every use is logged with its stated purpose.

[Security model](https://github.com/KeyValet/KeyValet/blob/main/SECURITY.md)

> **Status:** macOS releases are available. Windows 11 is a development preview; Hello, service and installer code are implemented, with signed packages and native verification pending. See the [Windows support record](https://github.com/KeyValet/KeyValet/blob/main/docs/windows.md). This guide covers the macOS release. UI in English and 简体中文; override with `KEYVALET_LANG=en|zh`.

Linux local support is implemented with systemd, polkit and TPM 2.0, with explicit software
protection for machines without TPM. Install the source checkout with `sh scripts/install.sh`;
see [Linux setup, SSH approval and recovery](https://github.com/KeyValet/KeyValet/blob/main/docs/linux.md).

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
                  root helper ── Touch ID gate ("use credential X for this session")
                        │
          ┌─────────────┼───────────────────────┐
   encrypted vault   HTTPS proxy            protocol engines
   /var/db/keyvalet  (inject key/token,     (OAuth refresh, service accounts,
   (root, 0700)       allowed hosts only,    GitHub App, JWT, TOTP, AWS STS)
                      redact responses)
```

- **Use, don't see.** `credential_http_request` makes the HTTP call inside the root helper with the key/token injected; the agent only gets the (redacted) response.
- **SDKs and streaming too.** `credential_gateway` gives programs that can't speak MCP a per-session local endpoint (`OPENAI_BASE_URL=…`). Streaming responses flow through, redacted on the fly; the program never holds the real key.
- **You're in the loop.** By default every credential needs its own Touch ID approval, and the prompt shows *which* credential and *for how long*.
- **Audited.** Every unlock, read, token fetch and proxied call is logged with session, purpose and result (never the secret). Agents can query the log.
- **Local and root-isolated.** AES-256-GCM vault readable only by root; code that runs as root is installed root-owned and self-verifies before running.
- **Speaks every auth.** OAuth 2.0 (auth code + PKCE, device code, client credentials, auto-refresh), Google service accounts, GitHub Apps, signed JWTs (e.g. App Store Connect), TOTP, AWS STS (AssumeRole + MFA), IMAP XOAUTH2 — plus a template catalog of common APIs.

## What it is not

- Not a password manager for humans (no UI, sync or browser autofill).
- Not a team secret manager.
- Not a sandbox: once you grant a session a credential, a malicious agent with shell access could misuse *that* grant. KeyValet narrows the blast radius (per-credential grants, proxy-only, host allowlists, short-lived tokens) and records everything. See [SECURITY.md](https://github.com/KeyValet/KeyValet/blob/main/SECURITY.md).

## Requirements

- macOS (Touch ID recommended; without it the system prompt asks for your login password — handled by macOS, never seen by KeyValet)
- macOS 14 or later on an Apple Silicon Mac (prebuilt binaries are installed from the release archive; no toolchain needed)
- Intel Macs, or `KEYVALET_VERSION` pointed at a ref with no release assets, build from source: a Rust toolchain (`cargo` from [rustup.rs](https://rustup.rs)) and Xcode Command Line Tools (`xcode-select --install`) for the Swift Secure Enclave helper are required then

## Install

```sh
curl -fsSL https://keyvalet.dev/install.sh | sh
```

This downloads the latest release (or `main`), checks the requirements, runs the installer (it asks for your password once) and registers KeyValet with Claude Code if it is installed. Re-run it to upgrade; uninstall with `curl -fsSL https://keyvalet.dev/install.sh | sh -s -- --uninstall`. From a clone you can run `./scripts/install.sh` directly.

The installer builds everything, copies it to root-owned `/usr/local/lib/keyvalet`, creates the vault at `/var/db/keyvalet`, installs the `keyvalet` CLI, and adds **one** sudoers rule (`/etc/sudoers.d/keyvalet`) that lets your user start *only* the KeyValet helper without a password — the helper then requires Touch ID before doing anything. The rule is validated with `visudo` before and after installation.

If Claude Code isn't installed (or you set `KEYVALET_NO_REGISTER=1`), register manually, e.g.:

```sh
claude mcp add keyvalet --scope user -- /usr/local/lib/keyvalet/bin/kv-mcp
```

Cursor: the installer also copies the KeyValet plugin to `~/.cursor/plugins/local/keyvalet` (restart Cursor to load it) — it brings the MCP server, the secret-detection hooks and the `/keyvalet-*` commands. Other clients: add a stdio server whose command is `/usr/local/lib/keyvalet/bin/kv-mcp`.

Your vault is kept across upgrades. `./scripts/uninstall.sh --purge` (from a clone) also deletes the vault.

## Quick start (what your agent does)

```text
credential_templates    { query: "openai" }
credential_set          { template: "openai", name: "main", purpose: "Store my OpenAI key" }
                          → a native dialog asks YOU for the key (not the agent); proxy + test are configured and the key is verified
credential_http_request { name: "main", url: "https://api.openai.com/v1/models", purpose: "List models" }
                          → Touch ID: "use openai/main for this session" → response returned, key never shown
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
| `remember` | one credential authorization for `remember_hours` (default 8; `0` = forever); Secure Enclave still authenticates each new session |

Listing and audit queries need no additional credential grant after session unlock. Templates need no vault session. Every new session authenticates Secure Enclave, including while a `remember` window is active.

**Change it from inside Claude Code, Cursor or Devin** with the plugin's slash commands (Claude Code: installed by the one-line installer; Cursor: installed to `~/.cursor/plugins/local/` by the installer, spelled `/keyvalet-mode` etc.; Devin CLI: `devin plugins install KeyValet/KeyValet#devin-plugin`):

```text
/keyvalet:mode remember 8      # Remember credential grants for 8 hours; each new session authenticates
/keyvalet:mode per-use         # strictest
/keyvalet:status               # current mode, remembered-until, grants of this session
/keyvalet:lock                 # lock now and forget the remembered authorization
/keyvalet:audit 20             # recent usage
/keyvalet:add stripe           # store a new key via the private dialog
```

Rules that keep this safe:

- The mode lives in the root-only `/var/db/keyvalet/settings.json`. **Loosening** (a more permissive mode or a longer remember window) requires your **Touch ID** — not a clickable dialog — so an agent can't loosen it on its own. Tightening applies immediately. Changes take effect in the current session as well.
- A client can only make it **stricter**: e.g. register Codex with `KEYVALET_GRANT_MODE=per_use`; the stricter of the global and the client setting wins.
- In `remember` mode, an unlocked session can use credentials without further prompts until the window ends. Every new session still authenticates the hardware key. `/keyvalet:lock` ends the window early.
- From a terminal: `keyvalet grant-mode remember 8`, `keyvalet grant-mode forget`.

### Keeping KeyValet up to date (Claude Code / Cursor / Devin plugin)

The plugin makes the agent maintain your vault for you:

- **Paste a key in the chat** ("here's my Stripe key: sk_live_…") and the agent stores it in KeyValet with the matching template, then uses it through the proxy or gateway instead of a `.env` file. A `UserPromptSubmit` hook recognizes ~25 key formats (OpenAI, Anthropic, GitHub, AWS, Stripe, Slack, Google, …) and tells the agent what to store, showing only a masked preview.
- **Better: `/keyvalet:add openai`** — you type the key into KeyValet's private dialog, so it never passes through the chat or the model provider's logs.
- **Before a literal key is written to a file or shell command**, a `PreToolUse` hook intervenes and points the agent to KeyValet instead — in Claude Code it asks you to confirm first; in Cursor and Devin (whose hook contracts have no "ask") it blocks the call. Hooks detect formats without retaining returned secrets or a plaintext matching cache. Arbitrary strings without a recognizable format may not be detected.
- The agent also offers to move secrets it finds in `.env`/config files into KeyValet, and to replace a stored key when it stops working (401/403).

Native plugins exist for Cursor (`cursor-plugin/`, installed to `~/.cursor/plugins/local/` by the installer — same commands spelled `/keyvalet-add` etc., plus `sessionStart`/`preToolUse`/`beforeShellExecution`/`beforeMCPExecution` hooks and the MCP server) and for Devin CLI (`devin plugins install KeyValet/KeyValet#devin-plugin` — same `/keyvalet:*` commands, `UserPromptSubmit`/`PreToolUse` hooks and the `keyvalet` MCP server, shipped in `devin-plugin/`).

Disable the hooks with `KEYVALET_HOOKS=off` in the environment the agent runs in.

### Purpose and audit

Every tool that reads, uses or changes a credential **requires** a `purpose`. The root helper enforces this too. Session approval prompts show the credential and what the grant exposes (for example a plaintext-readable warning for credentials that aren't `proxy_only`); per-use prompts also show the exact request; session unlocks show the vault scope. The purpose is not shown in prompts. Source directories and the full purpose remain in the audit log (`/var/db/keyvalet/audit.log`, root-only, rotated at 10 MB).

A session approval covers that credential for the session, rather than a particular HTTP endpoint. A per-use approval covers exactly one matching operation and shows every parameter it is bound to: for HTTP requests the method, host, path, query, agent-set headers and a body line (for known APIs — OpenAI, Anthropic, GitHub, Stripe, Slack, AWS — built by the helper from a fixed whitelist of business fields such as `model`, `amount` or `channel`, never arbitrary body content; other hosts get a shortened raw preview); for tokens the scopes, repositories and permissions; for AWS the lifetime. The root helper derives this from the complete operation; agent-provided display hints cannot replace it. Unsupported methods, hosts outside the allowlist and operations the credential kind can't perform are refused before any prompt.

### Proxy calls

- HTTPS only, port 443, and the hostname must be in the credential's `allowed_hosts` (domains only — no IPs or localhost).
- Redirects are not followed.
- Secrets (and common encodings: URL, form, JSON, base64, hex; case-insensitive) are replaced with `[REDACTED]` in responses and error messages; binary responses containing a secret are refused.
- Works for static credentials (template or manual injection rule) and for OAuth / service-account / GitHub App / JWT credentials (bearer token injected automatically).
- `proxy_only: true` makes `credential_get` and `credential_access_token` refuse to return the raw secret.
- Expanding exposure (new hosts, changed injection, turning off proxy-only, removing the config), overwriting and deleting credentials all require **your** confirmation in a dialog shown by the root helper itself — not just by the MCP server.

### Streaming and the local gateway

- `credential_http_request` reads streaming (SSE) responses in full and returns the text assembled from LLM deltas in `stream.text` (OpenAI Chat Completions and Responses, Anthropic, Gemini formats).
- `credential_gateway` opens a per-session gateway on `127.0.0.1` for programs: `http://127.0.0.1:<port>/<host>/<path>` → `https://<host>/<path>`. The gateway drops whatever auth headers the program sends, injects the real credential, enforces the host allowlist, never follows redirects, and redacts responses while streaming (it holds back only bytes that could be the start of a secret). The token is random per credential and session, requests must target `127.0.0.1`/`localhost` (DNS-rebinding protection), and every request is audited. For known templates it returns ready-to-use SDK environment variables.

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

Each command runs through `sudo -k`, so it asks for your password every time. Protected vault commands also require system authentication to unlock the Secure Enclave key.

### Key protection and TPM status

Installers prominently show the configured scheme, hardware evidence, current TPM detection and
key-use authorization. View the same information later without unlocking:

```sh
keyvalet status                 # JSON; protection is an alias
keyvalet status --summary       # readable protection summary
```

`credential_status` and the plugin status command include `vault_protection` even while locked,
without biometric/PIN authentication or credential grants. The macOS/Linux CLI still needs sudo;
the Windows owner can query the running service without UAC. An unavailable helper is reported
as `protection_error`, with no guessed hardware status.

Secure Enclave is hardware protection, not a TPM. Windows Hello separates OS-reported TPM
attestation from `unknown`. Linux TPM mode cannot establish physical backing from a device node,
and explicit software mode is labelled as software. A detected TPM can be discrete, integrated,
firmware or virtual; current probes report the implementation as unknown. Configured protection
and current device detection are separate, and status does not test the key. See the
[complete protection matrix and fields](https://github.com/KeyValet/KeyValet/blob/main/docs/key-protection.md).

### Secure Enclave master key

Secure Enclave is the only supported macOS vault mode (Apple silicon or supported T2 Macs). Installation runs `setup-enclave`: new vaults start with hardware protection; existing file-key vaults are migrated after privately entering a recovery passphrase. Hardware unavailability or cancelled setup leaves the vault unavailable for normal operation, with no software fallback. KeyValet uses a device-bound, encrypted CryptoKit key representation with a `userPresence` ACL: Touch ID or the device password is checked by macOS during the key operation. No plaintext hardware private key is stored in a file or Keychain item.

Run from a logged-in Mac GUI session. Headless / SSH authentication contexts may fail; hardware failures never enable a software fallback. The local validation used Apple silicon and macOS 26.5.1; T2 hardware and password fallback without enrolled fingerprints still need separate device validation.

```sh
keyvalet protection             # provider, hardware_required, recovery_configured, legacy_key_present
keyvalet enclave-test           # two system prompts; disposable key, vault unchanged
keyvalet setup-enclave          # initialize or migrate; hidden recovery passphrase twice, two system prompts
keyvalet migrate-to-enclave     # alias for setup-enclave
keyvalet rotate-recovery        # new hardware key, vault key and recovery passphrase; adds device binding
keyvalet recovery-check         # verify the recovery passphrase; no hardware, no changes, no values
keyvalet recovery-read list     # emergency read-only access with the passphrase (types / list / get)
```

Use a separate strong recovery passphrase, preferably six or more randomly chosen words, and keep it offline. KeyValet accepts 12–1024 bytes, but length alone does not ensure strength. Without a terminal, a hidden native dialog returns the passphrase directly to the root CLI; it never enters the agent, command arguments, environment or a file. Recovery wraps the AES key with Argon2id (64 MiB, three iterations, one lane) and AES-256-GCM. **Anyone with the encrypted vault and this passphrase can decrypt without the original Mac or Touch ID**; a weak passphrase can be attacked offline.

The installer ends existing KeyValet helper/MCP sessions before replacing executables and migrating. Manual setup requires closing those sessions first. Migration verifies that a newly created hardware key can be restored in a fresh subprocess, rotates the AES key, commits ciphertext and key metadata together, and removes `master.key`. `vault.migration-backup.enc` is an encrypted snapshot of the credentials at migration, already protected by the new key and recovery passphrase. Existing backup files are never overwritten. If a failed migration leaves a partial backup while `protection` still reports `migration_required`, preserve the intact `vault.enc` and `master.key` and move that partial backup before retrying. `uninitialized` means setup has not completed; neither state can serve normal operations. After a crash, if protection reports `secure_enclave` and `legacy_key_present: true`, run `keyvalet finish-enclave-migration` to authenticate and remove the leftover file key. Setup also performs this cleanup after authentication. Older KeyValet versions cannot read the migrated vault.

Back up the **latest** `/var/db/keyvalet/vault.enc` using an administrator account; it contains the encrypted key representation and recovery wrapper. Keep every copy readable only by root, or inside an encrypted archive. Vaults set up or rotated by this version are device-bound: their key also depends on `/var/db/keyvalet/device-binding.key`, which is root-only and excluded from Time Machine, so a copy of `vault.enc` alone can't be decrypted with one approved system prompt. Don't back up `device-binding.key` together with the vault. If `keyvalet protection` shows `device_binding: false`, run `keyvalet rotate-recovery` once. Restoring `vault.enc` on the same Mac works while the binding file is still present; otherwise use `keyvalet recover-vault`. Store settings separately if needed. On a replacement Mac, install KeyValet, restore `vault.enc` as root with mode `0600` under the root-owned `0700` vault directory, close all sessions, then run `keyvalet recover-vault`. Recovery uses the hidden passphrase, creates and verifies a fresh hardware key on that Mac, and re-encrypts the vault. To restore the migration snapshot, substitute `vault.migration-backup.enc` for `vault.enc` before recovery; it only contains data present at migration. Losing both device access and the recovery passphrase means the vault cannot be recovered.

Run `keyvalet recovery-check` once after setup, and again whenever you are unsure of the passphrase. It decrypts with the passphrase in the root CLI and reports only a credential count. If Secure Enclave stops working on this Mac (for example, system authentication fails after an OS update), the vault does not fall back to a file key. `keyvalet recovery-read types|list|get <type> <name>` reads credentials with the recovery passphrase instead; writes are rejected, the helper and AI sessions cannot use this mode, and each use is audited. To resume normal use, run `keyvalet recover-vault` on a Mac where Secure Enclave works. If the recovery passphrase may have been exposed, run `keyvalet rotate-recovery`: after a hardware unlock it replaces the hardware key, vault key and passphrase together, so the old passphrase no longer opens the current vault (older backups still open with it).

Secure Enclave protection keeps the hardware private key nonexportable and prevents copied current vault files from being decrypted using the old file key. The derived AES key and credential plaintext still enter ordinary process memory. The encrypted key representation is bound to this Mac's Secure Enclave, not to KeyValet, so compromised root does not need to wait for an unlock: it can request a derivation itself, with any prompt text, and one approval yields the AES key (device binding doesn't help here, since root can read the binding file). It can also capture the key or plaintext during an approved unlock. Capturing the AES key permits offline decryption until rotation. Treat an unexpected system authentication prompt as a warning sign. Old `master.key` copies plus old vault backups remain decryptable, and deletion cannot guarantee forensic erasure from APFS snapshots or SSDs. See [SECURITY.md](https://github.com/KeyValet/KeyValet/blob/main/SECURITY.md).

## Development

```sh
cd rust
cargo test --workspace --locked   # unit + integration tests in temp dirs with local mock servers; no root needed
```

Layout: `rust/crates/kv-mcp` (MCP server, runs as you) · `kv-helper` (root helper: vault, protocols, proxy, Touch ID gate) · `kv-touchid` · `kv-cli` · `kv-hook` (secret-detection hook) · `scripts/` (install, catalog build, optional n8n import).

See [CONTRIBUTING.md](../CONTRIBUTING.md).

## License

[Apache-2.0](../LICENSE). The optional n8n-derived catalog you may generate locally is subject to n8n's license and is not part of this project.

### Password retrieval and use

The root helper derives each `per_use` prompt and binding from the complete operation, parameters and stored credential configuration. Changing the operation, request or stored test, or replaying approval, is rejected. Reusable gateways are disabled in this mode; a change to the effective grant mode revokes existing gateway tokens.

Raw tool results are never cached on disk. Explicit secret exports and gateway environment files use private directories, 0600 files and symlink rejection. Locking, expiry and helper disconnect delete them; a subsequent MCP startup cleans up files from crashed processes. Values already returned to a caller cannot be revoked. OAuth errors return status and fixed error codes, never potentially sensitive upstream diagnostics.
