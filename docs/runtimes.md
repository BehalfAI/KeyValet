# Runtime support status

What KeyValet's `kv-hook` secret-detection hook actually does in each AI coding runtime, and how
confident we are in that, as of 2026-10. This is an internal tracking note (action-plan 4.3), not
user-facing docs.

| Runtime | MCP | Hooks | `kv-hook` mode | Confidence |
| --- | --- | --- | --- | --- |
| Claude Code | Yes (reference implementation) | Yes (`UserPromptSubmit`, `PreToolUse`) | `prompt`, `tool` | High — this is the primary target, exercised directly every session. |
| Codex | Yes | Best-effort: `~/.codex/hooks.json`, `PreToolUse` | `tool` (same Claude Code JSON shape, reused as-is) | Low — written to the assumption that Codex's hook config is "the same JSON structure" as Claude Code's (architecture doc §5.2's words); not independently verified against a real Codex install this round. If wrong, Codex just ignores the file; doesn't break the install. |
| Cursor | Yes | Yes, native — `beforeShellExecution`/`beforeMCPExecution` (`.cursor/hooks.json`) | `cursor-shell`, `cursor-mcp` | Medium-high — contract confirmed from cursor.com/docs/hooks and independent writeups: stdout JSON `{permission, user_message, agent_message}`, exit 2 as an equivalent shortcut for deny, `beforeReadFile` is observe-only (can't deny), `"ask"` is in the schema but not enforced. Not run against a real Cursor install. |
| Grok Build | Yes, native (`grok mcp add`, namespaced `server__tool`) | Yes, native — only `PreToolUse` can block (`~/.grok/hooks/*.json`) | `grok-tool` | Low-medium — docs.x.ai/build/features/hooks gives the config shape (same `hooks.PreToolUse[].hooks[]` structure as Claude Code's `hooks.json`); independent 2026-10 field reports say Grok reads Claude Code's hook *config* for compatibility but does not parse the nested `hookSpecificOutput.permissionDecision` *output* — an unrecognized decision is silently treated as absent (allow). Grok's actual contract is exit code (0 = allow, 2 = deny), which `grok-tool` uses; it also prints a secondary `{"decision": "deny", "reason": ...}` JSON some docs describe, in case that's read too. Input field casing (`tool_name`/`tool_input` vs `toolName`/`toolInput`) wasn't consistently confirmed across sources, so both are accepted. Not run against a real Grok Build install. |

## Why Cursor and Grok don't just reuse Claude Code's hook output

Both runtimes can *load* a hook registered the Claude Code way (`.claude/settings.json` or, for
Grok, apparently similar), which might suggest zero new code is needed. In practice neither
*enforces* Claude Code's decision format when it does:

- Cursor's schema is a different shape entirely (`permission`/`user_message`/`agent_message`) and
  doesn't enforce `"ask"`.
- Grok reads the config but field reports say it ignores `hookSpecificOutput.permissionDecision`
  specifically, falling back to "no decision understood = allow" -- which would make KeyValet's
  hook silently inert on Grok if it only ever spoke Claude Code's dialect.

So each gets its own `kv-hook` mode speaking its native contract, sharing the same detection core
(`detect`, `tool_reason`, the returned-secret exact-match check) rather than reusing `handle`'s
Claude-Code-shaped output.

## What's still open

- None of the three non-Claude-Code adapters have been run against a real install of that
  runtime -- everything above is built from documentation and independent testing writeups, not
  from watching it work. If you hit a runtime where KeyValet's hook isn't firing or isn't being
  obeyed, that's the first thing to check.
- Grok's tool-name vocabulary for its own built-in tools (editing, shell) isn't confirmed to match
  Claude Code's (`Write`/`Edit`/`Bash`/...), so `grok-tool` and `cursor-mcp` both use a recursive
  scan of every string field in the tool call's params instead of extracting by known field name --
  broader but not dependent on guessing the right tool name or field name.
- Grok's MCP support is real and namespaces server tools as `server__tool`; KeyValet's own MCP
  server should work there unmodified (no runtime-specific code needed for the MCP side, only for
  the hook side covered above).
