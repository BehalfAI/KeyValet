---
name: status
description: Show KeyValet's authorization mode and what this session is allowed to use
triggers:
  - user
allowed-tools:
  - mcp__keyvalet__credential_status
---

Call `credential_status` and summarize briefly for the user:

- whether the vault is unlocked in this session,
- the authorization mode (and, for `remember`, until when it is remembered),
- which credentials this session has been granted.

Do not unlock the vault or request any credential.
