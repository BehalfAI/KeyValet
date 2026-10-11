#!/bin/sh
# Sourced by the Unix installers as the regular user. Requires SRC_DIR, INSTALL_DIR and say.
# Codex adapter (action-plan 2.4): contract confirmed from the official docs
# (developers.openai.com/codex/hooks, 2026-10-10) -- ~/.codex/hooks.json PreToolUse, deny via
# hookSpecificOutput.permissionDecision or exit 2 (permissionDecision "ask" is parsed but
# unsupported: the hook run is marked failed and the call proceeds, so codex-tool never emits
# it). Codex skips a non-managed hook until the user reviews and trusts it via /hooks inside
# Codex -- the say message tells the user that. Never fails the install. Three cases: no file
# -> write ours; a file pointing at the old `kv-hook tool` command (only this installer ever
# wrote that into a Codex hooks file) -> rewrite it, since that mode emits an "ask" Codex
# treats as allow; any other existing file -> leave it and print a manual-merge hint.
write_codex_hooks() {
  cat > "$HOME/.codex/hooks.json" <<EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|apply_patch|mcp__.*",
        "hooks": [
          { "type": "command", "command": "$INSTALL_DIR/bin/kv-hook codex-tool", "timeout": 10 }
        ]
      }
    ]
  }
}
EOF
}
if [ -d "$HOME/.codex" ]; then
  if [ ! -e "$HOME/.codex/hooks.json" ]; then
    write_codex_hooks
    say "已为 Codex 写入 ~/.codex/hooks.json（密钥检测 hook）。Codex 会先要求你在 Codex 里运行 /hooks 审核并信任这个 hook，之后才会生效。" "Wrote ~/.codex/hooks.json for Codex (secret-detection hook). Codex will ask you to review and trust it with /hooks inside Codex before it takes effect."
  elif grep -qF "$INSTALL_DIR/bin/kv-hook tool\"" "$HOME/.codex/hooks.json" 2>/dev/null; then
    write_codex_hooks
    say "已把 ~/.codex/hooks.json 里旧的 KeyValet hook 更新为 kv-hook codex-tool；Codex 会要求你在 /hooks 里重新信任它。" "Updated the old KeyValet hook in ~/.codex/hooks.json to kv-hook codex-tool; Codex will ask you to trust it again in /hooks."
  else
    say "检测到已有 ~/.codex/hooks.json，未覆盖；如需启用 KeyValet 的密钥检测，请手动在 PreToolUse 里加一条 command: \"$INSTALL_DIR/bin/kv-hook codex-tool\"" "Found an existing ~/.codex/hooks.json, left untouched; to enable KeyValet's secret detection, manually add a PreToolUse command: \"$INSTALL_DIR/bin/kv-hook codex-tool\""
  fi
fi

# Cursor adapter (action-plan 4.2): native hooks.json schema (not the Claude Code one), gating
# beforeShellExecution, beforeMCPExecution and preToolUse (file-write tools). Same
# never-overwrite/never-fail-the-install rule as the Codex block above. The sessionStart hook
# only ships in the plugin bundle below (it points at /keyvalet-* commands the plugin defines).
if [ -d "$HOME/.cursor" ]; then
  if [ ! -e "$HOME/.cursor/hooks.json" ]; then
    cat > "$HOME/.cursor/hooks.json" <<EOF
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      { "command": "$INSTALL_DIR/bin/kv-hook cursor-shell", "timeout": 10 }
    ],
    "beforeMCPExecution": [
      { "command": "$INSTALL_DIR/bin/kv-hook cursor-mcp", "timeout": 10 }
    ],
    "preToolUse": [
      { "command": "$INSTALL_DIR/bin/kv-hook cursor-tool", "timeout": 10,
        "matcher": "Write|Edit|StrReplace|MultiEdit|Delete|Notebook|Create|Patch" }
    ]
  }
}
EOF
    say "已为 Cursor 写入 ~/.cursor/hooks.json（密钥检测 hook）" "Wrote ~/.cursor/hooks.json for Cursor (secret-detection hook)"
  else
    say "检测到已有 ~/.cursor/hooks.json，未覆盖；如需启用 KeyValet 的密钥检测，请手动加上 beforeShellExecution/beforeMCPExecution/preToolUse，command 用 \"$INSTALL_DIR/bin/kv-hook cursor-shell\" / \"cursor-mcp\" / \"cursor-tool\"" "Found an existing ~/.cursor/hooks.json, left untouched; to enable KeyValet's secret detection, manually add beforeShellExecution/beforeMCPExecution/preToolUse entries with command \"$INSTALL_DIR/bin/kv-hook cursor-shell\" / \"cursor-mcp\" / \"cursor-tool\""
  fi

  # Cursor plugin bundle (MCP server, /keyvalet-* commands, the keyvalet skill, hooks, and the
  # sessionStart context pointer). Copied into ~/.cursor/plugins/local/ -- a copy, not a
  # symlink, so it survives if this source checkout is removed; re-running install.sh refreshes
  # it, keeping the plugin and the kv-hook binary versions in lock-step.
  if [ -d "$SRC_DIR/cursor-plugin" ]; then
    if rm -rf "$HOME/.cursor/plugins/local/keyvalet" 2>/dev/null \
      && mkdir -p "$HOME/.cursor/plugins/local" \
      && cp -R "$SRC_DIR/cursor-plugin" "$HOME/.cursor/plugins/local/keyvalet" 2>/dev/null; then
      say "已安装 Cursor 插件到 ~/.cursor/plugins/local/keyvalet（重启 Cursor 生效）" "Installed the Cursor plugin to ~/.cursor/plugins/local/keyvalet (restart Cursor to load it)"
    else
      say "Cursor 插件复制失败，跳过（不影响安装）；可手动复制 $SRC_DIR/cursor-plugin 到 ~/.cursor/plugins/local/keyvalet" "Failed to copy the Cursor plugin, skipping (install unaffected); copy $SRC_DIR/cursor-plugin to ~/.cursor/plugins/local/keyvalet manually"
    fi
  fi
fi

# Grok Build adapter (action-plan 4.3/4.2): personal hooks live in ~/.grok/hooks/*.json (one of
# possibly several files in that directory, unlike Codex/Cursor's single hooks.json), always
# trusted with no per-project gate. Writes KeyValet's own file there; never touches any other
# file that directory might already have. See docs/runtimes.md for how confident we are in this.
if [ -d "$HOME/.grok" ] && [ ! -e "$HOME/.grok/hooks/keyvalet.json" ]; then
  mkdir -p "$HOME/.grok/hooks"
  cat > "$HOME/.grok/hooks/keyvalet.json" <<EOF
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          { "type": "command", "command": "$INSTALL_DIR/bin/kv-hook grok-tool", "timeout": 10 }
        ]
      }
    ]
  }
}
EOF
  say "已为 Grok Build 写入 ~/.grok/hooks/keyvalet.json（密钥检测 hook，未独立核实 Grok 的 hook 行为，见 docs/runtimes.md）" "Wrote ~/.grok/hooks/keyvalet.json for Grok Build (secret-detection hook; Grok's hook behavior hasn't been independently verified, see docs/runtimes.md)"
elif [ -d "$HOME/.grok" ]; then
  say "检测到已有 ~/.grok/hooks/keyvalet.json，未覆盖" "Found an existing ~/.grok/hooks/keyvalet.json, left untouched"
fi

# Devin CLI adapter: registers the MCP server when no Devin MCP config exists yet; the secret
# hook and the /keyvalet:* slash commands come from the devin-plugin/ folder in this repo,
# which Devin installs as a plugin (printed below). Same never-overwrite/never-fail rule.
# (Devin also imports keyvalet from ~/.claude.json automatically when Claude Code is set up.)
if [ -d "$HOME/.config/devin" ]; then
  if [ ! -e "$HOME/.config/devin/mcp_config.json" ]; then
    cat > "$HOME/.config/devin/mcp_config.json" <<EOF
{
  "mcpServers": {
    "keyvalet": { "command": "$INSTALL_DIR/bin/kv-mcp" }
  }
}
EOF
    say "已写入 ~/.config/devin/mcp_config.json（注册 KeyValet MCP server）" "Wrote ~/.config/devin/mcp_config.json (registered the KeyValet MCP server)"
  else
    say "检测到已有 ~/.config/devin/mcp_config.json，未改动；手动注册：devin mcp add -s user keyvalet -- $INSTALL_DIR/bin/kv-mcp" "Found an existing ~/.config/devin/mcp_config.json, left untouched; register manually: devin mcp add -s user keyvalet -- $INSTALL_DIR/bin/kv-mcp"
  fi
fi
