---
name: keyvalet-audit
description: Show recent KeyValet credential usage (who used what, when, and why)
---

The user may have included a number after the command for how many entries to show.

Call `credential_audit_log` with `limit` set to that number, otherwise `20`. Present the entries as a compact table with time, operation, credential (`type/name`), purpose and result. Point out anything unusual, such as failed or denied attempts.
