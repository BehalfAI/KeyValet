#!/bin/sh
# Installs KeyValet. Runs as a regular user; steps that need privileges go through sudo (prompts for a password).
#
# Layout after install (all root:wheel, not writable by a regular user / AI agent):
#   /usr/local/lib/keyvalet/bin/kv-helper   root helper (Touch ID gated), launched via sudo -n
#   /usr/local/lib/keyvalet/bin/kv-touchid  Touch ID authentication helper (hardened runtime signature)
#   /usr/local/lib/keyvalet/bin/kv-mcp      MCP server (runs unprivileged, one process per AI session)
#   /usr/local/lib/keyvalet/bin/kv-cli      terminal management CLI (runs as root via sudo)
#   /usr/local/lib/keyvalet/templates/      bundled credential template catalog
#   /usr/local/bin/keyvalet                 wrapper script that execs kv-cli via sudo
#   /var/db/keyvalet/                       the encrypted credential vault (0700)
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

CARGO_BIN=$(command -v cargo || true)
[ -n "$CARGO_BIN" ] || { say "找不到 cargo，请先安装 Rust 工具链（https://rustup.rs）" "cargo not found; install the Rust toolchain first (https://rustup.rs)" >&2; exit 1; }

say "==> 构建（cargo build --release）" "==> Building (cargo build --release)"
cd "$SRC_DIR/rust"
cargo build --release --locked
BIN_DIR="$SRC_DIR/rust/target/release"
for b in kv-helper kv-touchid kv-mcp kv-cli; do
  [ -x "$BIN_DIR/$b" ] || { say "构建产物缺失：$b" "Build artifact missing: $b" >&2; exit 1; }
done

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/bin" "$STAGE/templates"
cp "$BIN_DIR/kv-helper" "$BIN_DIR/kv-touchid" "$BIN_DIR/kv-mcp" "$BIN_DIR/kv-cli" "$STAGE/bin/"
cp -R "$SRC_DIR/templates/." "$STAGE/templates/" 2>/dev/null || true
# Hardened runtime: processes owned by the same user (including an AI agent) cannot debug or inject into this binary
codesign -s - -o runtime -f "$STAGE/bin/kv-touchid" >/dev/null

USER_NAME=$(id -un)
case "$USER_NAME" in
  *[!A-Za-z0-9_.-]*|"") say "用户名 $USER_NAME 含有不支持的字符" "User name $USER_NAME contains unsupported characters" >&2; exit 1 ;;
esac

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
$SUDO /bin/sh -eu -c '
  INSTALL_DIR="$1"; VAULT_DIR="$2"; CLI_LINK="$3"; STAGE="$4"; SUDOERS_FILE="$5"; KV_LANG="$6"
  say() { if [ "$KV_LANG" = zh ]; then printf "%s\n" "$1"; else printf "%s\n" "$2"; fi; }
  rm -rf "$INSTALL_DIR.new"
  mkdir -p "$INSTALL_DIR.new"
  cp -R "$STAGE/bin" "$STAGE/templates" "$INSTALL_DIR.new/"
  xattr -cr "$INSTALL_DIR.new" 2>/dev/null || true
  chown -R root:wheel "$INSTALL_DIR.new"
  chmod -R u=rwX,go=rX "$INSTALL_DIR.new"
  chmod 0755 "$INSTALL_DIR.new"/bin/*
  rm -rf "$INSTALL_DIR.old"
  if [ -e "$INSTALL_DIR" ]; then mv "$INSTALL_DIR" "$INSTALL_DIR.old"; fi
  mv "$INSTALL_DIR.new" "$INSTALL_DIR"
  rm -rf "$INSTALL_DIR.old"

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
' sh "$INSTALL_DIR" "$VAULT_DIR" "$CLI_LINK" "$STAGE" "$SUDOERS_FILE" "$KV_LANG"
sudo -k

# Verify the passwordless rule took effect: the helper exits immediately on reading EOF (no Touch ID prompt)
if ! /usr/bin/sudo -n -- "$INSTALL_DIR/bin/kv-helper" </dev/null >/dev/null 2>&1; then
  say "⚠️  免密规则未生效：请确认 /etc/sudoers 包含 #includedir /private/etc/sudoers.d" "⚠️  The passwordless sudo rule is not in effect: make sure /etc/sudoers contains #includedir /private/etc/sudoers.d" >&2
  exit 1
fi

echo
say "安装完成。" "Installation complete."
echo
say "在 Claude Code 中注册（用户级，所有项目可用）：" "Register it in Claude Code (user scope, available in all projects):"
echo "  claude mcp add keyvalet --scope user -- $INSTALL_DIR/bin/kv-mcp"
say "（如之前注册过旧名字：claude mcp remove credential --scope user）" "(If you registered it under the old name before: claude mcp remove credential --scope user)"
echo
say "在终端中管理凭证：" "Manage credentials from the terminal:"
echo "  keyvalet help"
