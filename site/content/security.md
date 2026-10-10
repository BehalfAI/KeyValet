+++
title = "Security"
description = "KeyValet's security model in plain terms: what it protects, the trust boundary, what it guarantees — and the full list of what it does not protect against."
+++

This page is a readable digest of [SECURITY.md](https://github.com/KeyValet/KeyValet/blob/main/SECURITY.md), which remains the authoritative document. A credential tool that runs code as root should be precise about its limits — so the "does not protect" list below is complete, not a summary of the flattering half.

## What's protected

- Static secrets: API keys, passwords, tokens, and their extra secret fields.
- Long-term protocol secrets: OAuth client secrets and refresh tokens, Google service-account private keys, GitHub App private keys, JWT signing keys, TOTP seeds, AWS secret access keys.
- The vault master key, and the integrity of the audit log and settings.

## The trust boundary

The AI agent or MCP client is *semi-trusted*: it may be prompt-injected, may speak MCP to the KeyValet server, and may run arbitrary commands as your user. The KeyValet MCP server is a convenience layer — **security checks never rely on it alone**. Every enforcement decision is made by the root helper (or the `dev.keyvalet.helper` launchd daemon), which holds no vault key while idle. Touch ID and Secure Enclave work happens in the per-user agent `dev.keyvalet.agent`, which the daemon only accepts after verifying its peer uid and its code signature (`dev.keyvalet.touchid`, team `PWCRJPY7YC`, exact installed path) — so a same-user process can't impersonate it and approve prompts for you.

## What KeyValet guarantees

Assuming macOS and the installed files are not compromised:

1. **No secret without the device owner.** The vault (`/var/db/keyvalet`, root-only, AES-256-GCM) requires Touch ID or login-password authentication before serving anything.
2. **You set the cadence, and only you can loosen it.** Grant modes — per-use, per-credential (default), per-session, remember — live in root-only settings; loosening requires your Touch ID, so an agent can't do it by itself.
3. **Long-term protocol secrets never leave the root helper.** Agents get derived, short-lived material or proxied responses.
4. **Proxy-only credentials are never revealed** through reads, tokens, error messages, or (best effort) proxied responses.
5. **Secrets go only where you allowed.** HTTPS on port 443 to an exact/wildcard domain allowlist — no IPs, no localhost, no redirects.
6. **The local gateway is token-gated and loopback-only.** Every route needs a random token bound to one credential and the current session; reusable gateways don't exist in per-use mode.
7. **Exposure can only grow with your consent, enforced in the helper.** Adding hosts, loosening rules, overwriting or deleting each need a confirmation dialog from the root process. Bypassing the MCP server doesn't bypass them.
8. **Secrets you type don't pass through the agent** — they go into native dialogs or are imported from files you confirm.
9. **Every use is recorded.** Unlocks, grants, reads, token fetches, proxied calls and config changes go to a root-only audit log; secret values are never logged.
10. **The helper builds the authorization prompt and binding itself** from the complete operation — client-provided hints can't substitute for it. Per-use prompts show the real request: method, host, path, query, agent headers, and for known APIs a body line built from a fixed whitelist of business fields, never arbitrary body content. In per-use mode one approval runs exactly that operation once.
11. **Session-bound.** When the agent session ends, the grant ends.
12. **Secure Enclave is required on macOS.** The vault key is derived per session from a Secure Enclave P-256 key mixed with a root-only device-binding secret, so a copied vault file plus one approved prompt isn't enough; an Argon2id recovery passphrase is the offline path.

## What KeyValet does NOT protect against

- **Misuse of a grant you approved** — once a session holds a grant, a malicious or prompt-injected agent can use it within its scope. `proxy_only`, narrow `allowed_hosts`, scoped tokens and per-use mode shrink it.
- **Gateway tokens authorize repeated calls** until lock, session exit or a grant-mode change.
- **`remember` mode trades prompts for exposure** during the window.
- **The stated purpose is unverified** — it's the agent's claim, recorded (not shown in prompts), never checked against what actually happens afterward.
- **Approving a malicious prompt** — malware as your user can trigger the same Touch ID prompt; if you approve it, it gets the grant.
- **Upstream reflection beyond redaction** — an allowed host that echoes a secret in an encoding the redactor doesn't know could leak it. Only allow hosts you trust.
- **Compromise of root or macOS**, physical attacks, or a compromised build.
- **Compromised root at any time**, not only during an unlock — it can request a Secure Enclave derivation itself or capture the derived key from the helper.
- **Recovery passphrase compromise** — encrypted `vault.enc` plus the passphrase suffice offline. Argon2id slows guesses; it can't make weak passphrases safe.
- **Historical copies and rollback** — old file keys plus old vault copies remain decryptable; APFS snapshots and backups aren't securely erased.
- **Secrets after they are handed out** — values returned by `credential_get` and short-lived tokens are in the agent's context.
- **Denial of service** — an agent can spam requests (rate-limited prompts, 30 s cooldown after failed authentication).

## Release integrity

Release archives are built by GitHub Actions from the tagged commit. Every binary in a workflow-built package is codesigned with the Simvito Limited Developer ID (team `PWCRJPY7YC`, hardened runtime, timestamped); the installer verifies that signature — and the published `SHA256SUMS` — before enabling daemon mode. The build-from-source path (Intel Macs, or releases without assets) has neither signature nor checksum on the downloaded source — audit the release or the source yourself if that matters to you.

## Reporting a vulnerability

Please **do not** open a public issue. Use GitHub's [private vulnerability reporting](https://github.com/KeyValet/KeyValet/security/advisories/new) (Security tab → "Report a vulnerability") with steps to reproduce and the affected version. Reports are acknowledged within a few days.

The full, authoritative model — including design notes and the exact cryptographic construction — is in [SECURITY.md](https://github.com/KeyValet/KeyValet/blob/main/SECURITY.md).
