---
description: Set how often KeyValet asks for Touch ID (per-use, per-credential, per-session, or remember for N hours)
argument-hint: "[per-use | per-credential | per-session | remember [hours|forever]]"
allowed-tools: mcp__keyvalet__credential_settings
---

The user ran `/keyvalet:mode` with arguments: `$ARGUMENTS`

If the arguments are empty, call `credential_settings` with no changes and show the current mode, then list the four options in one short table:

| Mode | Touch ID |
|---|---|
| `per-use` | every time a credential is used |
| `per-credential` | once per credential per session (default) |
| `per-session` | once per session, then all credentials |
| `remember [hours]` | once, then no prompts in any session for that many hours (`forever` = no expiry) |

Otherwise map the first argument to `grant_mode` (`per-use` → `per_use`, `per-credential` → `per_credential`, `per-session` → `per_session`, `remember` → `remember`). For `remember`, set `remember_hours` from the second argument (a number of hours; `forever` or `0` → `0`; default `8`). Call `credential_settings` with `purpose` set to `User ran /keyvalet:mode $ARGUMENTS`.

Tell the user in one or two sentences what the new behavior is. If it is more permissive than before, mention that KeyValet asked for their Touch ID to approve it. Do not change the mode unless the arguments ask for it.
