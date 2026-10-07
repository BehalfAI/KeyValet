# Security Model

KeyValet installs a sudoers rule and runs code as root, so it is important to be precise about what it protects against and what it does not.

## Reporting a vulnerability

Please **do not** open a public issue. Use GitHub's private vulnerability reporting ("Security" tab → "Report a vulnerability") on this repository. Include steps to reproduce and the affected version/commit. We aim to acknowledge reports within a few days.

## Assets

- Static secrets (API keys, passwords, tokens) and their extra secret fields.
- Long-term protocol secrets: OAuth client secrets and refresh tokens, Google service-account private keys, GitHub App private keys, JWT signing keys, TOTP seeds, AWS secret access keys.
- The vault master key, and the integrity of the audit log and settings.

## Trust boundaries

| Component | Runs as | Trusted? |
|---|---|---|
| AI agent / MCP client | your user | **Semi-trusted.** May be prompt-injected. May speak MCP to the KeyValet server *and* may run arbitrary commands as your user (including talking to the helper directly). |
| KeyValet MCP server (`src/server`) | your user | Convenience layer. **Security checks never rely on it alone.** |
| Root helper (`src/helper`) | root | Trusted. Enforces every security decision. |
| Touch ID program (`touchid`) | your user (dropped from root) | Trusted binary: root-owned, hardened-runtime signed; result returned to the helper via exit code. |
| macOS (sudo, LocalAuthentication, osascript) | — | Trusted. |

## What KeyValet guarantees

Assuming macOS and the installed files are not compromised:

1. **No secret without the device owner.** The vault (`/var/db/keyvalet`, root, `0700`, AES-256-GCM) is only readable by root. The only passwordless sudo rule allows exactly `/usr/local/lib/keyvalet/bin/node /usr/local/lib/keyvalet/app/dist/helper/main.js`. Before serving any request the helper requires device-owner authentication (Touch ID, or the login password in the system dialog) with the stated purpose shown.
2. **You set the cadence, and only you can loosen it.** Grant modes: `per_use`, `per_credential` (default; approving one credential does not unlock others), `per_session`, `remember` (N hours across sessions). The mode lives in root-only settings; loosening requires device-owner authentication (Touch ID) in the root helper, so an agent cannot loosen it by itself — not even via the `/keyvalet:mode` slash command it may be asked to run. Clients can only tighten it (`KEYVALET_GRANT_MODE`).
3. **Long-term protocol secrets never leave the root helper.** Agents receive only derived, short-lived material (access tokens, installation tokens, signed JWTs, TOTP codes, STS credentials) or proxied responses.
4. **Proxy-only credentials are never revealed** through `get`, `accessToken`, error messages or (best effort, see below) proxied responses.
5. **Secrets go only where you allowed.** Proxied requests: HTTPS, port 443, exact/wildcard domain allowlist (no IPs, no localhost), no redirects. OAuth/service-account/GitHub/AWS endpoints must be HTTPS; changing an OAuth credential's endpoints or client requires re-entering the client secret.
6. **The local gateway is token-gated and loopback-only.** `credential_gateway` listens on `127.0.0.1` inside the root helper. Each route needs a 32-byte random token bound to one credential and the current session; requests must target `127.0.0.1`/`localhost` (DNS-rebinding protection); client-supplied auth headers are dropped; the host allowlist, no-redirect rule and (streaming) redaction apply exactly as for proxy calls; every request is audited without the token or query string.
7. **Exposure can only grow with your consent, enforced in the helper.** Adding allowed hosts, changing the injection rule, disabling proxy-only, removing the proxy config, overwriting or deleting a credential, and switching to `all` grant mode each require a confirmation dialog shown by the root helper (as your user via `osascript`). Bypassing the MCP server does not bypass these.
8. **Secrets typed by you don't pass through the agent.** Values are entered in native dialogs (whose text contains only validated identifiers and hosts) or imported from files after you confirm the path.
9. **Every use is recorded.** Unlocks, grants, reads, token fetches, proxied calls (method, host, path — not the query) and configuration changes are appended to a root-only audit log with session ID, purpose and result. Secret values are never logged.
10. **Session-bound.** The helper lives only as long as the MCP server's stdio pipe; when the agent session ends, the grant ends.

## What KeyValet does NOT protect against

- **Misuse of a grant you approved.** Once a session holds a grant, a malicious or prompt-injected agent can use that credential (e.g. make proxied calls to allowed hosts, or read the value of a non-proxy-only static credential). Use `proxy_only`, narrow `allowed_hosts`, scoped tokens and per-credential mode to limit this, and read the purpose in the Touch ID prompt.
- **Anyone holding a gateway URL can use that credential through the gateway until the session ends** — treat the URL like a session cookie (don't write it to files or logs).
- **`remember` mode trades prompts for exposure.** While the window is open, any process running as you can use your credentials without a prompt (secrets stay hidden from it and every use is audited). Keep the window short; `/keyvalet:lock` ends it.
- **The stated purpose is unverified.** It is the agent's claim; it is shown and logged, not checked.
- **Approving a malicious prompt.** Malware running as your user can trigger the same Touch ID prompt (the source directory shown is supplied by the client). If you approve it, it gets the grant.
- **Upstream reflection beyond redaction.** Responses are redacted for the exact secret and common encodings (URL, form, JSON escapes, base64/base64url, hex, case-insensitive), and binary responses containing a secret are refused — but an allowed host that transforms and echoes a secret in some other encoding could still leak it. Only allow hosts you trust.
- **Compromise of root or macOS**, physical attacks, or a compromised Node.js runtime at install time (the installer copies a statically linked Node binary into a root-owned directory and refuses Homebrew's node).
- **Secrets after they are handed out.** Values returned by `credential_get` and short-lived tokens are in the agent's context and may be retained by the model provider.
- **Denial of service.** An agent can delete nothing without your confirmation, but it can spam requests (rate-limited prompts, 30 s cooldown after failed authentication).

## Design notes

- The helper verifies at startup that it, all of its code, and the Node binary are root-owned, not group/other-writable and not symlinked; otherwise it refuses to run.
- Concurrent changes are guarded: credential records carry a random generation ID so that a refresh that completes after the record was replaced cannot write tokens into the new (possibly attacker-controlled) configuration; proxy-config changes re-check the configuration after the confirmation dialog.
- Root-helper hardening: bounded line size, bounded in-flight requests, bounded response sizes (streamed with limits), no automatic decompression.
- The legacy `credential-mcp` vault format (pre-rename) is still readable and is upgraded on the next write.

## Hardening tips

- Keep the default `per_credential` grant mode.
- Store HTTP API keys with templates and set `proxy_only: true` for sensitive ones.
- Prefer OAuth/service accounts/GitHub Apps (short-lived tokens) over long-lived personal tokens.
- Review `keyvalet audit` periodically.
