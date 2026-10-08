# KeyValet

**Give your AI agents a valet key, not your master key.**

KeyValet lets Claude Code, Cursor and other AI agents use your API keys and OAuth accounts — without ever seeing them. You approve each credential with Touch ID, KeyValet makes the call, and every use is logged.

[Website](https://keyvalet.dev/) · [Guide](docs/guide.md) · [Security](SECURITY.md) · [简体中文](README.zh-CN.md)

## Install

```sh
curl -fsSL https://keyvalet.dev/install.sh | sh
```

macOS, Node.js 20+ ([nodejs.org](https://nodejs.org) or nvm) and Xcode Command Line Tools. You'll be asked for your password once. Claude Code is configured automatically; for other MCP clients see the [guide](docs/guide.md#install).

## Use it

Just ask your agent:

> /keyvalet:add openai

A native dialog asks **you** for the key — it never passes through the chat. Pasted a key into the chat anyway? Claude stores it in KeyValet for you instead of a `.env` file.

> Use KeyValet to list my OpenAI models.

Touch ID shows *which* credential and *why*. KeyValet makes the request; the agent only gets the response.

> Connect my GitHub account through KeyValet and create a repo called demo.

OAuth, refresh tokens and private keys stay in KeyValet; the agent only ever gets short-lived tokens.

## Why

- **Use, don't see** — keys are injected inside a root-owned helper; the agent gets responses, not secrets.
- **You choose how often to touch** — per use, per credential (default), per session, or once and remembered for hours. Switch with `/keyvalet:mode` in Claude Code; loosening always needs your fingerprint.
- **SDKs and streaming** — a local gateway lets scripts and SDKs (`OPENAI_BASE_URL=…`) stream without holding the real key.
- **Every auth flow** — API keys (~50 templates), OAuth 2.0, Google service accounts, GitHub Apps, JWT, TOTP, AWS STS.
- **Maintained for you** — in Claude Code, keys you share are stored automatically, and you're asked before a key gets hard-coded into a file or command.
- **Audit log** — every unlock, read and call, with its purpose. Local only, nothing in the cloud.

## Learn more

- [Guide](docs/guide.md) — concepts, all tools, templates, gateway, CLI
- [Security model](SECURITY.md) — what KeyValet guarantees, and what it doesn't
- [Contributing](CONTRIBUTING.md)

Uninstall: `curl -fsSL https://keyvalet.dev/install.sh | sh -s -- --uninstall`

Apache-2.0 · by [Simvito Limited](https://github.com/KeyValet)
