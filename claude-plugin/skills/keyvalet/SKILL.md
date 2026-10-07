---
name: keyvalet
description: Use KeyValet whenever a task needs an API key, token, password, OAuth account or other credential — calling an external API, configuring an SDK, running a script that needs a key, or storing a new secret. Prefer it over reading .env files or asking the user to paste secrets.
---

# Working with credentials through KeyValet

KeyValet (MCP server `keyvalet`) lets you use the user's credentials without seeing them.

- **Never** read `.env` files, keychains or config files to obtain secrets, and never ask the user to paste a secret into the chat.
- Find what exists with `credential_list`. Each call that uses a credential needs a concrete, honest `purpose` — it is shown in the user's Touch ID prompt and written to the audit log.
- **Calling an HTTP API:** use `credential_http_request` (KeyValet injects the credential and returns only the response). For streaming LLM responses the assembled text is in `stream.text`.
- **Programs and SDKs** (Python/Node scripts, CLIs): use `credential_gateway`, then run the program with `set -a; . <env_file>; set +a; <command>`. Never print the env file or put its values in command arguments.
- **Storing a new secret:** search `credential_templates` and save with `credential_set` + `template`; the user types secret values into a native dialog. Don't pass secret values yourself.
- **OAuth accounts:** `credential_oauth_login`, then `credential_http_request` or `credential_access_token`.
- Use `credential_get` (raw value) only when neither the proxy nor the gateway can work, e.g. a database password.
- Only change KeyValet settings (`credential_settings`) when the user explicitly asks; the `/keyvalet:mode` command exists for that.
