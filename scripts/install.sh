#!/bin/sh
# Installs KeyValet. Runs as a regular user; steps that need privileges go through sudo (prompts for a password).
#
# Layout after install (all root:wheel, not writable by a regular user / AI agent):
#   /usr/local/lib/keyvalet/bin/kv-helper   root helper (Touch ID gated): launchd daemon at
#                                           /var/run/keyvalet/helper.sock when signed for our
#                                           team (PWCRJPY7YC), else the sudo -n fallback
#   /usr/local/lib/keyvalet/bin/kv-touchid  Touch ID authentication helper (also the per-user
#                                           LaunchAgent dev.keyvalet.agent in daemon mode)
#   /usr/local/lib/keyvalet/bin/kv-touchid  Touch ID authentication helper (hardened runtime signature)
#   /usr/local/lib/keyvalet/bin/kv-mcp      MCP server (runs unprivileged, one process per AI session)
#   /usr/local/lib/keyvalet/bin/kv-cli      terminal management CLI (runs as root via sudo)
#   /usr/local/lib/keyvalet/bin/kv-hook     secret-detection hook for AI runtimes (Claude Code, Codex), runs unprivileged
#   /usr/local/lib/keyvalet/templates/      bundled credential template catalog
#   /usr/local/bin/keyvalet                 wrapper script that execs kv-cli via sudo
#   /var/db/keyvalet/                       the encrypted credential vault (0700)
#   /var/run/keyvalet/                      daemon + agent Unix sockets (daemon mode)
#   /Library/LaunchDaemons/dev.keyvalet.helper.plist / /Library/LaunchAgents/dev.keyvalet.agent.plist
#   /etc/sudoers.d/keyvalet                 lets only the current user run the helper passwordlessly (it still requires Touch ID once started)
#
# Upgrading from the pre-rename credential-mcp: automatically migrates /var/db/credential-mcp to /var/db/keyvalet and removes the old install.
set -eu

# UI language: KEYVALET_LANG=en|zh takes priority, otherwise fall back to the macOS UI language
KV_LANG=${KEYVALET_LANG:-}
case "$KV_LANG" in zh*) KV_LANG=zh ;; en*) KV_LANG=en ;; *) KV_LANG= ;; esac
if [ -z "$KV_LANG" ]; then
  if /usr/bin/defaults read -g AppleLanguages 2>/dev/null | /usr/bin/sed -n 2p | /usr/bin/grep -q zh; then KV_LANG=zh; else KV_LANG=en; fi
fi
say() { if [ "$KV_LANG" = zh ]; then printf '%s\n' "$1"; else printf '%s\n' "$2"; fi; }

INSTALL_DIR=/usr/local/lib/keyvalet
VAULT_DIR=/var/db/keyvalet
CLI_LINK=/usr/local/bin/keyvalet
SUDOERS_FILE=/etc/sudoers.d/keyvalet
SRC_DIR=$(cd "$(dirname "$0")/.." && pwd)

if [ "$(id -u)" = 0 ]; then
  say "请以普通用户运行（脚本会在需要时调用 sudo）：./scripts/install.sh" "Run as a regular user (the script calls sudo when needed): ./scripts/install.sh" >&2
  exit 1
fi

if [ -x "$SRC_DIR/bin/kv-helper" ] && [ ! -d "$SRC_DIR/rust" ]; then
  # Release package: prebuilt Apple Silicon binaries, no source tree. Only /usr/bin/codesign
  # is needed below (the kv-touchid ad-hoc hardened-runtime signature); no Xcode CLT/cargo.
  say "==> 使用发行包内的预编译二进制（Apple Silicon）" "==> Using the release package's prebuilt binaries (Apple Silicon)"
  PREBUILT=1
  BIN_DIR="$SRC_DIR/bin"
  for b in kv-helper kv-touchid kv-mcp kv-cli kv-hook; do
    [ -x "$BIN_DIR/$b" ] || { say "发行包不完整：缺少 $b" "Incomplete release package: missing $b" >&2; exit 1; }
    [ "$(/usr/bin/lipo -archs "$BIN_DIR/$b" 2>/dev/null)" = arm64 ] || { say "$b 不是 arm64 二进制，此发行包只支持 Apple Silicon；请改用源码安装" "$b is not an arm64 binary; this release package supports Apple Silicon only -- install from source instead" >&2; exit 1; }
  done
  # hw.optional.arm64, not uname -m: a Rosetta-translated shell reports x86_64 on Apple Silicon.
  [ "$(/usr/sbin/sysctl -n hw.optional.arm64 2>/dev/null)" = 1 ] || { say "此发行包只支持 Apple Silicon；Intel Mac 请改用源码安装" "This release package supports Apple Silicon only; on Intel Macs please install from source" >&2; exit 1; }
else
  CARGO_BIN=$(command -v cargo || true)
  [ -n "$CARGO_BIN" ] || { say "找不到 cargo，请先安装 Rust 工具链（https://rustup.rs）" "cargo not found; install the Rust toolchain first (https://rustup.rs)" >&2; exit 1; }

  PREBUILT=0
  say "==> 构建（cargo build --release）" "==> Building (cargo build --release)"
  cd "$SRC_DIR/rust"
  cargo build --release --locked
  BIN_DIR="$SRC_DIR/rust/target/release"
  for b in kv-helper kv-touchid kv-mcp kv-cli kv-hook; do
    [ -x "$BIN_DIR/$b" ] || { say "构建产物缺失：$b" "Build artifact missing: $b" >&2; exit 1; }
  done
fi

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/bin" "$STAGE/templates"
cp "$BIN_DIR/kv-helper" "$BIN_DIR/kv-touchid" "$BIN_DIR/kv-mcp" "$BIN_DIR/kv-cli" "$BIN_DIR/kv-hook" "$STAGE/bin/"
cp -R "$SRC_DIR/templates/." "$STAGE/templates/" 2>/dev/null || true
TEAM_ID=PWCRJPY7YC
team_of() { /usr/bin/codesign -dv --verbose=4 "$1" 2>&1 | /usr/bin/sed -n 's/^TeamIdentifier=\(.*\)/\1/p'; }

# A codesigning identity owned by our team: prefer "Developer ID Application", accept
# "Apple Development" (the developer's machine). Prints the SHA-1 to sign with, nothing if none.
pick_signing_identity() {
  want=$1
  /usr/bin/security find-identity -v -p codesigning 2>/dev/null \
    | /usr/bin/sed -n "s/^ *[0-9]*) \([0-9A-Fa-f]\{40\}\) \"\($want: [^\"]*\)\"/\1|\2/p" \
    | while IFS='|' read -r hash name; do
        ou=$(/usr/bin/security find-certificate -c "$name" -a -p 2>/dev/null \
          | /usr/bin/openssl x509 -noout -subject -nameopt sep_multiline 2>/dev/null \
          | /usr/bin/sed -n 's/^ *OU=\(.*\)/\1/p' | /usr/bin/head -1)
        if [ "$ou" = "$TEAM_ID" ]; then echo "$hash"; break; fi
      done
}
IDENTITY_SHA=$( { pick_signing_identity "Developer ID Application"; pick_signing_identity "Apple Development"; } | /usr/bin/head -1 )

# Hardened runtime everywhere: a real team signature when we have one (required for the launchd
# daemon mode below -- the daemon verifies the agent's Apple-anchored identity before trusting
# its prompts). Without an identity, fall back to the ad-hoc kv-touchid signature as before.
if [ "$PREBUILT" = 1 ] && [ "$(team_of "$BIN_DIR/kv-helper")" = "$TEAM_ID" ] && [ "$(team_of "$BIN_DIR/kv-touchid")" = "$TEAM_ID" ]; then
  say "发行包自带 $TEAM_ID 签名，保持原样" "The release package already carries the $TEAM_ID signature; keeping it"
elif [ -n "$IDENTITY_SHA" ]; then
  say "==> 使用 $TEAM_ID 身份为二进制签名" "==> Signing binaries with the $TEAM_ID identity"
  for b in helper touchid mcp cli hook; do
    /usr/bin/codesign --force --options runtime --identifier "dev.keyvalet.$b" -s "$IDENTITY_SHA" "$STAGE/bin/kv-$b" >/dev/null \
      || { say "签名失败：kv-$b" "Signing failed: kv-$b" >&2; exit 1; }
  done
else
  codesign -s - -o runtime -f "$STAGE/bin/kv-touchid" >/dev/null
fi

# Daemon mode requires verifiable code identity on BOTH the daemon (it must not be spoofable)
# and the agent (the daemon verifies it before trusting its prompt answers).
DAEMON_MODE=0
if /usr/bin/codesign --verify --strict "$STAGE/bin/kv-helper" 2>/dev/null \
   && /usr/bin/codesign --verify --strict "$STAGE/bin/kv-touchid" 2>/dev/null \
   && [ "$(team_of "$STAGE/bin/kv-helper")" = "$TEAM_ID" ] \
   && [ "$(team_of "$STAGE/bin/kv-touchid")" = "$TEAM_ID" ]; then
  DAEMON_MODE=1
  say "==> 启用 launchd 守护进程模式（dev.keyvalet.helper + dev.keyvalet.agent）" "==> Enabling launchd daemon mode (dev.keyvalet.helper + dev.keyvalet.agent)"
else
  say "未检测到可用的 $TEAM_ID 签名身份，按 sudo 模式安装（功能相同，每个会话经 sudo 起 helper）" "No usable $TEAM_ID signing identity found; installing in sudo mode (same features -- each session spawns the helper via sudo)"
fi

USER_NAME=$(id -un)
case "$USER_NAME" in
  *[!A-Za-z0-9_.-]*|"") say "用户名 $USER_NAME 含有不支持的字符" "User name $USER_NAME contains unsupported characters" >&2; exit 1 ;;
esac

if [ "$DAEMON_MODE" = 1 ]; then
  UID_NUM=$(id -u)
  cat > "$STAGE/dev.keyvalet.helper.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.keyvalet.helper</string>
  <key>ProgramArguments</key><array>
    <string>$INSTALL_DIR/bin/kv-helper</string><string>--daemon</string><string>--uid</string><string>$UID_NUM</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
EOF
  cat > "$STAGE/dev.keyvalet.agent.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.keyvalet.agent</string>
  <key>ProgramArguments</key><array>
    <string>$INSTALL_DIR/bin/kv-touchid</string><string>--agent</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
  <key>ProcessType</key><string>Interactive</string>
</dict></plist>
EOF
fi

cat > "$STAGE/sudoers" <<SUDOERS
# KeyValet: only $USER_NAME may run the vault helper without a password (arguments must match exactly).
# After starting, the helper requires Touch ID (device owner authentication) before providing any service.
$USER_NAME ALL=(root) NOPASSWD: $INSTALL_DIR/bin/kv-helper
SUDOERS
/usr/sbin/visudo -cqf "$STAGE/sudoers" || { say "生成的 sudoers 规则校验失败" "Validation of the generated sudoers rule failed" >&2; exit 1; }
cat > "$STAGE/keyvalet" <<EOF
#!/bin/sh
# Detect the UI language as the user (root can't read the user's language preference), pass it to the CLI via --lang
KV_LANG=\${KEYVALET_LANG:-}
if [ -z "\$KV_LANG" ]; then
  # The first entry of AppleLanguages (line 2 of the output) is the current UI language
  if /usr/bin/defaults read -g AppleLanguages 2>/dev/null | /usr/bin/sed -n 2p | /usr/bin/grep -q zh; then KV_LANG=zh; else KV_LANG=en; fi
fi
exec /usr/bin/sudo -k -- $INSTALL_DIR/bin/kv-cli --lang "\$KV_LANG" "\$@"
EOF

say "==> 安装到 ${INSTALL_DIR}（需要 sudo）" "==> Installing to ${INSTALL_DIR} (requires sudo)"
sudo -k
if [ -t 0 ]; then
  SUDO="sudo"
else
  # No terminal (e.g. run on the user's behalf by an AI agent): ask for the password with a native macOS dialog
  # Dialog text is chosen by UI language (fixed strings, no single quotes), written into the generated script single-quoted
  ASKPASS_MSG=$(say "安装 KeyValet 需要管理员权限。请输入 macOS 登录密码（sudo）：" "Installing KeyValet requires administrator privileges. Enter your macOS login password (sudo):")
  ASKPASS_TITLE=$(say "KeyValet · 安装" "KeyValet · Install")
  ASKPASS_CANCEL=$(say "取消" "Cancel")
  ASKPASS_OK=$(say "安装" "Install")
  cat > "$STAGE/install-askpass" <<'EOF'
#!/bin/sh
exec /usr/bin/osascript \
  -e 'on run argv' \
  -e 'set r to display dialog (item 1 of argv) with title (item 2 of argv) default answer "" with hidden answer buttons {item 3 of argv, item 4 of argv} default button 2 cancel button 1 with icon caution giving up after 180' \
  -e 'if gave up of r then error number -128' \
  -e 'return text returned of r' \
  -e 'end run' \
EOF
  cat >> "$STAGE/install-askpass" <<EOF
  -- '$ASKPASS_MSG' '$ASKPASS_TITLE' '$ASKPASS_CANCEL' '$ASKPASS_OK' 2>/dev/null
EOF
  chmod 0700 "$STAGE/install-askpass"
  export SUDO_ASKPASS="$STAGE/install-askpass"
  SUDO="sudo -A"
fi
# This whole root script is ONE single-quoted string: never use a single quote (apostrophe)
# anywhere inside it, not even in a comment -- it would end the string early.
$SUDO /bin/sh -eu -c '
  INSTALL_DIR="$1"; VAULT_DIR="$2"; CLI_LINK="$3"; STAGE="$4"; SUDOERS_FILE="$5"; KV_LANG="$6"; DAEMON_MODE="$7"
  say() { if [ "$KV_LANG" = zh ]; then printf "%s\n" "$1"; else printf "%s\n" "$2"; fi; }
  rm -rf "$INSTALL_DIR.new"
  mkdir -p "$INSTALL_DIR.new"
  cp -R "$STAGE/bin" "$STAGE/templates" "$INSTALL_DIR.new/"
  xattr -cr "$INSTALL_DIR.new" 2>/dev/null || true
  chown -R root:wheel "$INSTALL_DIR.new"
  chmod -R u=rwX,go=rX "$INSTALL_DIR.new"
  chmod 0755 "$INSTALL_DIR.new"/bin/*
  # Stop the daemon and the per-user agent before switching binaries; the agent lives in the
  # GUI domain of the installing user.
  /bin/launchctl bootout "system/dev.keyvalet.helper" 2>/dev/null || true
  /bin/launchctl bootout "gui/$SUDO_UID/dev.keyvalet.agent" 2>/dev/null || true
  # Revoke sessions before switching the installed executables and rotating the vault key.
  /usr/bin/pkill -TERM -x kv-helper || [ "$?" -eq 1 ]
  /usr/bin/pkill -TERM -u "$SUDO_UID" -x kv-mcp || [ "$?" -eq 1 ]
  rm -rf "$INSTALL_DIR.old"
  if [ -e "$INSTALL_DIR" ]; then mv "$INSTALL_DIR" "$INSTALL_DIR.old"; fi
  mv "$INSTALL_DIR.new" "$INSTALL_DIR"

  mkdir -p "$(dirname "$CLI_LINK")"
  install -o root -g wheel -m 0755 "$STAGE/keyvalet" "$CLI_LINK"

  # Migrate from credential-mcp (the pre-rename name): move the whole vault (master key, credentials, audit log, settings), then remove the old install
  if [ -d /var/db/credential-mcp ] && [ ! -e "$VAULT_DIR" ]; then
    mv /var/db/credential-mcp "$VAULT_DIR"
    say "已迁移凭证库：/var/db/credential-mcp -> $VAULT_DIR" "Migrated vault: /var/db/credential-mcp -> $VAULT_DIR"
  fi
  rm -rf /usr/local/lib/credential-mcp /usr/local/bin/credential-vault /etc/sudoers.d/credential-mcp

  if [ ! -d "$VAULT_DIR" ]; then mkdir -m 0700 "$VAULT_DIR"; fi
  chown root:wheel "$VAULT_DIR"
  chmod 0700 "$VAULT_DIR"

  install -o root -g wheel -m 0440 "$STAGE/sudoers" "$SUDOERS_FILE"
  /usr/sbin/visudo -cq || { rm -f "$SUDOERS_FILE"; say "sudoers 整体校验失败，已撤销规则" "Overall sudoers validation failed; the rule was removed" >&2; exit 1; }

  # macOS supports only hardware-protected vaults. The CLI directly collects the recovery
  # passphrase from a hidden terminal/native dialog, and never returns it to the installer.
  say "==> 初始化或迁移 Secure Enclave 凭证库" "==> Initializing or migrating the Secure Enclave vault"
  "$INSTALL_DIR/bin/kv-cli" --lang "$KV_LANG" setup-enclave
  rm -rf "$INSTALL_DIR.old"

  if [ "$DAEMON_MODE" = 1 ]; then
    install -o root -g wheel -m 0644 "$STAGE/dev.keyvalet.helper.plist" /Library/LaunchDaemons/dev.keyvalet.helper.plist
    install -o root -g wheel -m 0644 "$STAGE/dev.keyvalet.agent.plist" /Library/LaunchAgents/dev.keyvalet.agent.plist
    /bin/launchctl bootstrap system /Library/LaunchDaemons/dev.keyvalet.helper.plist
    /bin/launchctl bootstrap "gui/$SUDO_UID" /Library/LaunchAgents/dev.keyvalet.agent.plist
    /bin/launchctl print system/dev.keyvalet.helper >/dev/null
    /bin/launchctl print "gui/$SUDO_UID/dev.keyvalet.agent" >/dev/null
    say "launchd 守护进程已启动：dev.keyvalet.helper + dev.keyvalet.agent" "launchd daemon started: dev.keyvalet.helper + dev.keyvalet.agent"
  fi
' sh "$INSTALL_DIR" "$VAULT_DIR" "$CLI_LINK" "$STAGE" "$SUDOERS_FILE" "$KV_LANG" "$DAEMON_MODE"
sudo -k

# Verify the passwordless rule took effect: the helper exits immediately on reading EOF (no Touch ID prompt)
if ! /usr/bin/sudo -n -- "$INSTALL_DIR/bin/kv-helper" </dev/null >/dev/null 2>&1; then
  say "⚠️  免密规则未生效：请确认 /etc/sudoers 包含 #includedir /private/etc/sudoers.d" "⚠️  The passwordless sudo rule is not in effect: make sure /etc/sudoers contains #includedir /private/etc/sudoers.d" >&2
  exit 1
fi

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

echo
say "安装完成。" "Installation complete."
echo
say "在 Claude Code 中注册（用户级，所有项目可用）：" "Register it in Claude Code (user scope, available in all projects):"
echo "  claude mcp add keyvalet --scope user -- $INSTALL_DIR/bin/kv-mcp"
say "（如之前注册过旧名字：claude mcp remove credential --scope user）" "(If you registered it under the old name before: claude mcp remove credential --scope user)"
echo
say "在 Devin CLI 中安装插件（含密钥检测 hook 和 /keyvalet:* 命令）：" "Install the plugin in Devin CLI (includes the secret-detection hook and /keyvalet:* commands):"
echo "  devin plugins install KeyValet/KeyValet#devin-plugin"
echo
say "在终端中管理凭证：" "Manage credentials from the terminal:"
echo "  keyvalet help"
