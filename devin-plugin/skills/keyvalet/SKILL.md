---
name: keyvalet
description: Use KeyValet whenever a task involves an API key, token, password, OAuth account or other credential — the user shares a key, a call or SDK needs one, a .env or config file holds one, or a key stops working. Store and use secrets through KeyValet instead of .env files, code or the chat.
---

# Working with credentials through KeyValet

KeyValet (MCP server `keyvalet`) lets you use the user's credentials without seeing them. Keep its contents up to date on the user's behalf.

## Keep KeyValet up to date (proactively)

- **The user shares a secret in the chat** (API key, token, password, connection string, SSH private key, certificate): store it right away with `credential_set` — find the template with `credential_templates`, pass the secret as `value` (or `value_file` for a key that's already a local file), and use a short name (`default`, or the project/account). Check `credential_list` first; if one exists for that service, ask before replacing it (`overwrite: true`). AWS key pairs go to `credential_setup_aws`. Then confirm in one line, don't repeat the secret, and mention once that `/keyvalet:add` keeps keys out of the chat next time.
- **This also covers things that aren't HTTP APIs** — an SSH host/alias the user mentions wanting to reuse, a database password, a certificate — not just "API key"-shaped secrets. For an SSH key specifically, a conventional type name is `ssh_key`, with non-secret details (`host`, `user`, `port`) in `attributes` — don't duplicate those details into your own memory/notes afterward; the credential's `attributes` is the single place to keep them, since they'll drift against your notes otherwise.
- **A task needs a key that isn't stored:** don't ask the user to paste it. Call `credential_set` with the template and no `value` — the user types it into KeyValet's private dialog.
- **You find secrets in `.env`, config files or code** while working: tell the user and offer to move them into KeyValet (`credential_set` with `value_file` for files such as private keys — add `delete_source_file: true` to have the user confirm deleting the original file once the import succeeds, so the plaintext doesn't end up in two places), then replace hard-coded keys with env vars filled by `credential_gateway`.
- **A stored key fails** (401/403, "invalid key"): say which credential failed and offer to replace it (`credential_set` with `overwrite: true`, no `value`).
- Never write secrets into files, shell commands, commit messages, memory or notes.

## Using credentials

- Each call that uses a credential needs a concrete, honest `purpose` — it is written to the audit log the user reviews. The Touch ID prompt itself shows the credential and scope, built by KeyValet.
- **Calling an HTTP API:** `credential_http_request` (KeyValet injects the credential and returns only the response). For streaming LLM responses the assembled text is in `stream.text`.
- **Programs and SDKs** (Python/Node scripts, CLIs): `credential_gateway`, then run the program with `set -a; . <env_file>; set +a; <command>`. Never print the env file or put its values in command arguments.
- **OAuth accounts:** `credential_oauth_login`, then `credential_http_request` or `credential_access_token`.
- **A local program needs the secret as a file** (SSH private key for `ssh -i`, a certificate, anything that can't take a header or env var): `credential_export_file` — it writes the value to a private file and returns only the path, never the content. Prefer this over `credential_get` whenever the end use is "pass a file to a command."
- Use `credential_get` (raw value, returned to you) only when neither the proxy, the gateway, nor a file export can work — e.g. a database password that goes inline into a connection string.
- Don't read `.env` files, keychains or config files just to obtain a secret for yourself.
- Only change KeyValet settings (`credential_settings`) when the user explicitly asks; `/keyvalet:mode` exists for that.
