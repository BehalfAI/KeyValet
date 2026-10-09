---
name: keyvalet-mode
description: Set how often KeyValet asks for Touch ID (per-use, per-credential, per-session, or remember for N hours)
---

The user ran `/keyvalet-mode`. The arguments are any text after the command (e.g. `per-use`, `per-credential`, `per-session`, or `remember 8`).

If there are no arguments, call `credential_settings` with no changes and show the current mode, then list the four options in one short table:

| Mode | Touch ID |
|---|---|
| `per-use` | every time a credential is used |
| `per-credential` | once per credential per session (default) |
| `per-session` | once per session, then all credentials |
| `remember [hours]` | once, then no prompts in any session for that many hours (`forever` = no expiry) |

Otherwise map the first word to `grant_mode` (`per-use` → `per_use`, `per-credential` → `per_credential`, `per-session` → `per_session`, `remember` → `remember`). For `remember`, set `remember_hours` from the second word (a number of hours; `forever` or `0` → `0`; default `8`). Call `credential_settings` with `purpose` set to the command the user ran.

Tell the user in one or two sentences what the new behavior is. If it is more permissive than before, mention that KeyValet asked for their Touch ID to approve it. Do not change the mode unless the arguments ask for it.
