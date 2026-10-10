# Runtime support status

What KeyValet's `kv-hook` secret-detection hook actually does in each AI coding runtime, and how
confident we are in that, as of 2026-10. This is an internal tracking note (action-plan 4.3), not
user-facing docs.

| Runtime | MCP | Hooks | `kv-hook` mode | Confidence |
| --- | --- | --- | --- | --- |
| Claude Code | Yes (reference implementation) | Yes (`UserPromptSubmit`, `PreToolUse`) | `prompt`, `tool` | High — this is the primary target, exercised directly every session. |
| Codex | Yes — standard stdio server (`codex mcp add` or `config.toml`) | Yes, native — `~/.codex/hooks.json` `PreToolUse` (matcher `Bash\|apply_patch\|mcp__.*`) | `codex-tool` | Medium — contract taken from the official docs (developers.openai.com/codex/hooks, 2026-10-10): deny via `hookSpecificOutput.permissionDecision: "deny"` or exit 2 + stderr — `codex-tool` emits both; `ask` is parsed but unsupported (the hook run is marked failed and the call proceeds), so it is never emitted. `apply_patch` carries the patch text in `tool_input.command`; MCP calls arrive as `mcp__<server>__<tool>` with the arguments object and keyvalet's own server is exempt; matcher values `Edit`/`Write` are aliases for `apply_patch`. Non-managed hooks are skipped until the user trusts them via `/hooks` inside Codex. Not yet watched end-to-end in a live Codex session. |
| Cursor | Yes — plugin `cursor-plugin/mcp.json`, `cursor mcp add`, or `~/.cursor/mcp.json` | Yes, native — plugin `cursor-plugin/hooks/hooks.json` and/or `~/.cursor/hooks.json`: `beforeShellExecution`, `beforeMCPExecution`, `preToolUse` (file-write tools via matcher), `sessionStart` (context pointer) | `cursor-shell`, `cursor-mcp`, `cursor-tool`, `cursor-session` | Medium-high — contract confirmed from cursor.com/docs/hooks: stdout JSON `{permission, user_message, agent_message}`, exit 2 = deny, `ask` accepted but not enforced so it is never emitted. `beforeMCPExecution` carries `mcp_server_name` — keyvalet's own calls (`credential_set` & co. legitimately carry secrets) are exempted on it. `tool_input` is a JSON-encoded string per docs, parsed-or-scanned regardless of actual shape. The full plugin bundle (commands `/keyvalet-*`, `keyvalet` skill, hooks, MCP) installs to `~/.cursor/plugins/local/keyvalet`. Not run against a live Cursor session. Caveats: `beforeMCPExecution` doesn't run in cloud agents (Cursor's own deferral); `beforeSubmitPrompt` exists but is block-only (no context injection), so the prompt-side nudge isn't possible — a pasted key in the message relies on the skill/sessionStart context. |
| Grok Build | Yes, native (`grok mcp add`, namespaced `server__tool`) | Yes, native — only `PreToolUse` can block (`~/.grok/hooks/*.json`) | `grok-tool` | Low-medium — docs.x.ai/build/features/hooks gives the config shape (same `hooks.PreToolUse[].hooks[]` structure as Claude Code's `hooks.json`); independent 2026-10 field reports say Grok reads Claude Code's hook *config* for compatibility but does not parse the nested `hookSpecificOutput.permissionDecision` *output* — an unrecognized decision is silently treated as absent (allow). Grok's actual contract is exit code (0 = allow, 2 = deny), which `grok-tool` uses; it also prints a secondary `{"decision": "deny", "reason": ...}` JSON some docs describe, in case that's read too. Input field casing (`tool_name`/`tool_input` vs `toolName`/`toolInput`) wasn't consistently confirmed across sources, so both are accepted. The matcher is `.*` — every tool incl. MCP calls, so keyvalet's own tools (`keyvalet__credential_set` & co.) are exempted by server/tool name. Not run against a real Grok Build install. |
| Devin CLI | Yes — `.mcp.json` in `devin-plugin/`, `devin mcp add`, or auto-imported from `~/.claude.json` when Claude Code is configured | Yes, native — plugin `hooks.json` (`UserPromptSubmit`, `PreToolUse`); project/user equivalents are `.devin/hooks.v1.json` and the `"hooks"` key in `config.json` | `prompt`, `devin-tool` | Medium — contract from Devin CLI's own docs (stdin `tool_name`/`tool_input`, stdout `{"decision": "approve"\|"block", "reason"}`, `hookSpecificOutput.additionalContext`; exit 2 also blocks). `devin-tool` is exercised against Devin-shaped payloads in unit tests but hasn't been watched end-to-end in a live session. Devin's decision vocabulary has no "ask" (approve/block only), so a flag blocks — same trade-off as Cursor. Devin documents plugin hooks as best-effort/fail-open, i.e. a hook failure just skips the check. Tool names are Devin's own (`exec`, `write`, `edit`, `apply_patch`, `notebook_edit`, `write_to_process`, plus MCP calls in either shape: the `mcp_call_tool` builtin or the namespaced `mcp__<server>__<tool>`); calls on the `keyvalet` server are exempt in both shapes since `credential_set`'s `value` legitimately carries a secret. `exec` scans `env` values too. |

## Why Cursor, Grok, Devin and Codex don't just reuse Claude Code's hook output

All four runtimes can *load* a hook registered the Claude Code way (`.claude/settings.json` or,
for Grok, apparently similar; Devin imports `.claude/settings*.json` too, and Codex's
`hooks.json` shape is deliberately Claude-Code-like), which might suggest
zero new code is needed. In practice none of them *enforces* Claude Code's decision format when
it does:

- Cursor's schema is a different shape entirely (`permission`/`user_message`/`agent_message`) and
  doesn't enforce `"ask"`.
- Grok reads the config but field reports say it ignores `hookSpecificOutput.permissionDecision`
  specifically, falling back to "no decision understood = allow" -- which would make KeyValet's
  hook silently inert on Grok if it only ever spoke Claude Code's dialect.
- Devin *does* parse `hookSpecificOutput.additionalContext` (its documented context-injection
  channel), but its documented decision vocabulary is only `approve`/`block` — `permissionDecision`
  is a Claude-ism it doesn't read, so `tool` mode's "ask" would silently allow there as well.
- Codex *does* parse `hookSpecificOutput.permissionDecision`, but only honours `"deny"`: `"ask"`
  is parsed yet unsupported — the hook run is marked failed and the tool call proceeds — so
  `tool` mode's "ask" is a silent allow on Codex too. `codex-tool` emits `deny` via the JSON
  *and* exits 2 with the reason on stderr, the other documented deny channel.

So each gets its own `kv-hook` mode speaking its native contract, sharing the same detection core
(`detect`, `tool_reason`, the returned-secret exact-match check) rather than reusing `handle`'s
Claude-Code-shaped output.

## What's still open

- None of the five non-Claude-Code adapters have been run against a real install of that
  runtime end-to-end (Devin's is exercised against its documented payload shapes in unit tests)
  -- everything above is built from documentation and independent testing writeups, not
  from watching it work. If you hit a runtime where KeyValet's hook isn't firing or isn't being
  obeyed, that's the first thing to check.
- Grok's tool-name vocabulary for its own built-in tools (editing, shell) isn't confirmed to match
  Claude Code's (`Write`/`Edit`/`Bash`/...), so `grok-tool` and `cursor-mcp` both use a recursive
  scan of every string field in the tool call's params instead of extracting by known field name --
  broader but not dependent on guessing the right tool name or field name.
- Grok's MCP support is real and namespaces server tools as `server__tool`; KeyValet's own MCP
  server should work there unmodified (no runtime-specific code needed for the MCP side, only for
  the hook side covered above).
