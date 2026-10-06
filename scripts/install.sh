#!/bin/sh
# 安装 KeyValet。以普通用户运行，需要特权的步骤会通过 sudo 执行（会提示输入密码）。
#
# 安装后的布局（全部 root:wheel，不可被普通用户/AI agent 修改）：
#   /usr/local/lib/keyvalet/bin/node       node 副本（root helper 用它运行）
#   /usr/local/lib/keyvalet/bin/touchid    Touch ID 认证程序（强化运行时签名）
#   /usr/local/lib/keyvalet/app/           编译后的代码 + 模板库 + 生产依赖
#   /usr/local/bin/keyvalet                终端管理 CLI
#   /var/db/keyvalet/                      加密凭证库（0700）
#   /etc/sudoers.d/keyvalet                只允许当前用户免密运行 helper（helper 启动后必须先通过 Touch ID）
#
# 从改名前的 credential-mcp 升级：自动把 /var/db/credential-mcp 迁移为 /var/db/keyvalet，并删除旧的安装。
set -eu

# 界面语言：KEYVALET_LANG=en|zh 优先，否则看 macOS 界面语言
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

NODE_SRC=$(command -v node || true)
[ -n "$NODE_SRC" ] || { say "找不到 node" "node not found" >&2; exit 1; }
NODE_SRC=$(cd "$(dirname "$NODE_SRC")" && pwd -P)/$(basename "$NODE_SRC")
NODE_MAJOR=$("$NODE_SRC" -p 'process.versions.node.split(".")[0]')
[ "$NODE_MAJOR" -ge 20 ] || { say "需要 node >= 20（当前 $("$NODE_SRC" -v)）" "node >= 20 is required (current: $("$NODE_SRC" -v))" >&2; exit 1; }

# root helper 会用这个 node 运行；如果它依赖用户可写的动态库（如 Homebrew 版 node），
# 任何用户态进程都能通过替换动态库获得 root —— 拒绝安装。
if otool -L "$NODE_SRC" | tail -n +2 | awk '{print $1}' | grep -Ev '^(/usr/lib/|/System/Library/)' >/dev/null; then
  say "node ($NODE_SRC) 链接了系统目录以外的动态库，不能安全地以 root 运行。" "node ($NODE_SRC) links dynamic libraries outside system directories and cannot safely run as root." >&2
  say "请改用 nvm 或 nodejs.org 官方安装包提供的 node。" "Please use node from nvm or the official nodejs.org installer instead." >&2
  exit 1
fi

SWIFTC=$(command -v swiftc || true)
[ -n "$SWIFTC" ] || { say "需要 Swift 编译器：请先运行 xcode-select --install" "The Swift compiler is required: run xcode-select --install first" >&2; exit 1; }

USER_NAME=$(id -un)
case "$USER_NAME" in
  *[!A-Za-z0-9_.-]*|"") say "用户名 $USER_NAME 含有不支持的字符" "User name $USER_NAME contains unsupported characters" >&2; exit 1 ;;
esac

say "==> 构建" "==> Building"
cd "$SRC_DIR"
npm ci --silent
npm run --silent build

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/app" "$STAGE/bin"
cp -R dist templates package.json package-lock.json "$STAGE/app/"
rm -rf "$STAGE/app/dist/test"
(cd "$STAGE/app" && npm ci --omit=dev --silent --ignore-scripts)
cp "$NODE_SRC" "$STAGE/bin/node"
"$SWIFTC" -O -o "$STAGE/bin/touchid" src/native/touchid.swift
# 强化运行时：同用户的进程（包括 AI agent）无法调试或注入该程序
codesign -s - -o runtime -f "$STAGE/bin/touchid" >/dev/null
cat > "$STAGE/sudoers" <<SUDOERS
# KeyValet: only $USER_NAME may run the vault helper without a password (arguments must match exactly).
# After starting, the helper requires Touch ID (device owner authentication) before providing any service.
$USER_NAME ALL=(root) NOPASSWD: $INSTALL_DIR/bin/node $INSTALL_DIR/app/dist/helper/main.js
SUDOERS
/usr/sbin/visudo -cqf "$STAGE/sudoers" || { say "生成的 sudoers 规则校验失败" "Validation of the generated sudoers rule failed" >&2; exit 1; }
cat > "$STAGE/keyvalet" <<EOF
#!/bin/sh
# 以用户身份检测界面语言（root 读不到用户的语言偏好），通过 --lang 传给 CLI
KV_LANG=\${KEYVALET_LANG:-}
if [ -z "\$KV_LANG" ]; then
  # AppleLanguages 的第一项（输出第 2 行）是当前界面语言
  if /usr/bin/defaults read -g AppleLanguages 2>/dev/null | /usr/bin/sed -n 2p | /usr/bin/grep -q zh; then KV_LANG=zh; else KV_LANG=en; fi
fi
exec /usr/bin/sudo -k -- $INSTALL_DIR/bin/node $INSTALL_DIR/app/dist/cli/main.js --lang "\$KV_LANG" "\$@"
EOF

say "==> 安装到 ${INSTALL_DIR}（需要 sudo）" "==> Installing to ${INSTALL_DIR} (requires sudo)"
sudo -k
if [ -t 0 ]; then
  SUDO="sudo"
else
  # 没有终端（例如由 AI agent 代为运行）：用 macOS 原生密码框向用户要密码
  # 对话框文案按界面语言选择（固定文案，不含单引号），以单引号写入生成的脚本
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
  cp -R "$STAGE/app" "$STAGE/bin" "$INSTALL_DIR.new/"
  xattr -cr "$INSTALL_DIR.new" 2>/dev/null || true
  chown -R root:wheel "$INSTALL_DIR.new"
  chmod -R u=rwX,go=rX "$INSTALL_DIR.new"
  chmod 0755 "$INSTALL_DIR.new/bin/node" "$INSTALL_DIR.new/bin/touchid"
  rm -rf "$INSTALL_DIR.old"
  if [ -e "$INSTALL_DIR" ]; then mv "$INSTALL_DIR" "$INSTALL_DIR.old"; fi
  mv "$INSTALL_DIR.new" "$INSTALL_DIR"
  rm -rf "$INSTALL_DIR.old"

  mkdir -p "$(dirname "$CLI_LINK")"
  install -o root -g wheel -m 0755 "$STAGE/keyvalet" "$CLI_LINK"

  # 从 credential-mcp（改名前）迁移：凭证库整体搬迁（主密钥、凭证、审计日志、设置），再删除旧安装
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

# 验证免密规则生效：helper 启动后读到 EOF 会立即退出（不会弹 Touch ID）
if ! /usr/bin/sudo -n -- "$INSTALL_DIR/bin/node" "$INSTALL_DIR/app/dist/helper/main.js" </dev/null >/dev/null 2>&1; then
  say "⚠️  免密规则未生效：请确认 /etc/sudoers 包含 #includedir /private/etc/sudoers.d" "⚠️  The passwordless sudo rule is not in effect: make sure /etc/sudoers contains #includedir /private/etc/sudoers.d" >&2
  exit 1
fi

echo
say "安装完成。" "Installation complete."
echo
say "在 Claude Code 中注册（用户级，所有项目可用）：" "Register it in Claude Code (user scope, available in all projects):"
echo "  claude mcp add keyvalet --scope user -- $INSTALL_DIR/bin/node $INSTALL_DIR/app/dist/server/index.js"
say "（如之前注册过旧名字：claude mcp remove credential --scope user）" "(If you registered it under the old name before: claude mcp remove credential --scope user)"
echo
say "在终端中管理凭证：" "Manage credentials from the terminal:"
echo "  keyvalet help"
