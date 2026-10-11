---
description: Show key protection, TPM evidence and session authorization
allowed-tools: mcp__keyvalet__credential_status
---

Call `credential_status` and summarize briefly for the user:

- the configured key protection scheme, hardware evidence and current TPM detection from `vault_protection`, including while locked,
- whether the vault is unlocked in this session,
- the authorization mode (and, for `remember`, until when it is remembered),
- which credentials this session has been granted.

Explain `unknown` as unconfirmed hardware protection, and keep current TPM detection separate from the backing of the configured key. If `protection_error` is present, say protection status is unavailable instead of guessing.

Do not unlock the vault or request any credential.
