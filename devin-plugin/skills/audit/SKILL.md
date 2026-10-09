---
name: audit
description: Show recent KeyValet credential usage (who used what, when, and why)
argument-hint: "[number of entries, default 20]"
triggers:
  - user
allowed-tools:
  - mcp__keyvalet__credential_audit_log
---

Call `credential_audit_log` with `limit` set to `$ARGUMENTS` if it is a number, otherwise `20`. Present the entries as a compact table with time, operation, credential (`type/name`), purpose and result. Point out anything unusual, such as failed or denied attempts.
