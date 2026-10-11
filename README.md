# KeyValet

**Give your AI agents a valet key, not your master key.**

KeyValet lets Claude Code, Cursor, Devin and other AI agents use your API keys and OAuth accounts through authorized proxy calls. You approve access with Touch ID on macOS, Windows Hello on Windows, or polkit on Linux; KeyValet makes the call and logs its use.

[Website](https://keyvalet.dev/) · [Guide](https://keyvalet.dev/guide/) · [Security](SECURITY.md) · [简体中文](README.zh-CN.md)

## Install

```sh
curl -fsSL https://keyvalet.dev/install.sh | sh
```

An Apple Silicon Mac on macOS 14 or later (the installer uses the release's prebuilt arm64 binaries; Intel Macs build from source instead, which needs a Rust toolchain (`cargo` from [rustup.rs](https://rustup.rs)) and Xcode Command Line Tools). You'll be asked for your password once. Claude Code is configured automatically; the installer also installs the Cursor plugin (`~/.cursor/plugins/local/keyvalet`, restart Cursor) when Cursor is present; for Devin CLI, install the plugin with `devin plugins install KeyValet/KeyValet#devin-plugin`; for other MCP clients see the [guide](site/guide.md#install).

Windows 11 support is a **development preview**: Hello, the service, UI agent and local package
installer are implemented; signed public packages and real Windows validation are pending.
See [Windows build, installation and verification](docs/windows.md). WSL support is still open.

Linux local support is implemented with a systemd service, polkit approval and TPM 2.0 keys.
Without TPM, software protection requires explicit opt-in; hardware failures never trigger
automatic fallback. Install the source checkout with `sh scripts/install.sh` (or `--software`
on a machine without TPM). See [Linux installation, SSH approval and recovery](docs/linux.md).
The v0.3.0 release workflow builds Linux x64 and ARM64 archives, with checksums, alongside the
notarized macOS archive. The command above installs the matching Linux package. Linux requires
systemd, polkit, sudo and `tpm2-tools` for TPM protection; use `sh -s -- --software` with the online
installer when explicitly choosing software protection on a host without TPM.
The WSL-to-Windows vault bridge remains pending.

The macOS and Linux source installers use `CARGO_TARGET_DIR` when set; relative paths are resolved
from `rust/`. Otherwise they build into `rust/target`. This explicit directory overrides Cargo's
configured `build.target-dir` so installation always uses the output of the current build.

Installation displays the configured key protection scheme, hardware evidence and current TPM
detection. Check it later with `keyvalet status --summary` or the AI client's `credential_status`,
even while locked. `unknown` means hardware protection is unconfirmed. See the
[macOS / Windows / Linux protection matrix](docs/key-protection.md).

## Use it

Just ask your agent:

> /keyvalet:add openai

A native dialog asks **you** for the key — it never passes through the chat. Pasted a key into the chat anyway? Claude stores it in KeyValet for you instead of a `.env` file.

> Use KeyValet to list my OpenAI models.

Touch ID asks to "use openai for this session". KeyValet makes the request; the agent only gets the response.

Session prompts show the credential and what the grant exposes, derived from the stored credential (credentials that aren't `proxy_only` always carry a plaintext-readable warning). Per-use approvals add the exact operation and its parameters. Request details, purposes and sources remain in the audit log.

> Connect my GitHub account through KeyValet and create a repo called demo.

OAuth, refresh tokens and private keys stay in KeyValet; the agent only ever gets short-lived tokens.

## Why

- **Use, don't see** — proxy calls inject credentials inside the privileged helper or isolated Linux service; the agent receives responses. Explicit plaintext reads and exports follow their separate authorization policy.
- **You choose the credential approval cadence** — per use, per credential (default), per session, or remembered for hours. Every new session still authenticates the hardware key. Switch with `/keyvalet:mode` in Claude Code or Devin (`/keyvalet-mode` in Cursor); loosening always needs your fingerprint.
- **SDKs and streaming** — a local gateway lets scripts and SDKs (`OPENAI_BASE_URL=…`) stream without holding the real key. In `per_use` mode, use individual proxied requests; reusable gateways are disabled.
- **Every auth flow** — API keys (~50 templates), OAuth 2.0, Google service accounts, GitHub Apps, JWT, TOTP, AWS STS.
- **Maintained for you** — in Claude Code, Cursor and Devin, keys you share are stored automatically, and a hook flags or blocks a key that's about to be hard-coded into a file or command.
- **Private handling** — raw tool results are never cached on disk; locking removes explicit temporary exports. The helper binds each `per_use` approval to the complete operation.
- **Audit log** — every unlock, read and call, with its purpose. Local only, nothing in the cloud.

**Secure Enclave is required on macOS.** Installation initializes a hardware vault or migrates an existing file-key vault, using a recovery passphrase entered privately in a terminal or native dialog. Each new session requires Touch ID or system password authentication, including in `remember` mode. File-key operation and software fallback have been removed. The hardware private key cannot be exported, but the derived AES key enters helper memory and compromised root can request a derivation itself, so this does not promise protection from compromised root. If Secure Enclave becomes unusable, `keyvalet recovery-read` gives read-only access with the recovery passphrase. See the [setup and recovery instructions](site/guide.md#secure-enclave-master-key).

## Learn more

- [Guide](https://keyvalet.dev/guide/) — concepts, all tools, templates, gateway, CLI
- [Security model](SECURITY.md) — what KeyValet guarantees, and what it doesn't
- [Contributing](CONTRIBUTING.md) · [Code of Conduct](CODE_OF_CONDUCT.md) · [Governance](GOVERNANCE.md) · [Trademark policy](TRADEMARK.md)

Uninstall: `curl -fsSL https://keyvalet.dev/install.sh | sh -s -- --uninstall`

Apache-2.0 · by [Simvito Limited](https://github.com/KeyValet)
