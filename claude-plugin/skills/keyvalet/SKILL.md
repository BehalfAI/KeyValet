---
name: keyvalet
description: Use KeyValet whenever a task involves an API key, token, password, OAuth account or other credential — the user shares a key, a call or SDK needs one, a .env or config file holds one, or a key stops working. Store and use secrets through KeyValet instead of .env files, code or the chat.
---

# Working with credentials through KeyValet

KeyValet (MCP server `keyvalet`) lets you use the user's credentials without seeing them. Keep its contents up to date on the user's behalf.

## Keep KeyValet up to date (proactively)

- **The user shares a secret in the chat** (API key, token, password, connection string): store it right away with `credential_set` — find the template with `credential_templates`, pass the secret as `value`, and use a short name (`default`, or the project/account). Check `credential_list` first; if one exists for that service, ask before replacing it (`overwrite: true`). AWS key pairs go to `credential_setup_aws`. Then confirm in one line, don't repeat the secret, and mention once that `/keyvalet:add` keeps keys out of the chat next time.
- **A task needs a key that isn't stored:** don't ask the user to paste it. Call `credential_set` with the template and no `value` — the user types it into KeyValet's private dialog.
- **You find secrets in `.env`, config files or code** while working: tell the user and offer to move them into KeyValet (`credential_set` with `value_file` for files such as private keys), then replace hard-coded keys with env vars filled by `credential_gateway`.
- **A stored key fails** (401/403, "invalid key"): say which credential failed and offer to replace it (`credential_set` with `overwrite: true`, no `value`).
- Never write secrets into files, shell commands, commit messages, memory or notes.

## Using credentials

- Each call that uses a credential needs a concrete, honest `purpose` — it is shown in the user's Touch ID prompt and written to the audit log.
- **Calling an HTTP API:** `credential_http_request` (KeyValet injects the credential and returns only the response). For streaming LLM responses the assembled text is in `stream.text`.
- **Programs and SDKs** (Python/Node scripts, CLIs): `credential_gateway`, then run the program with `set -a; . <env_file>; set +a; <command>`. Never print the env file or put its values in command arguments.
- **OAuth accounts:** `credential_oauth_login`, then `credential_http_request` or `credential_access_token`.
- Use `credential_get` (raw value) only when neither the proxy nor the gateway can work, e.g. a database password.
- Don't read `.env` files, keychains or config files just to obtain a secret for yourself.
- Only change KeyValet settings (`credential_settings`) when the user explicitly asks; `/keyvalet:mode` exists for that.
