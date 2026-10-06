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

INSTALL_DIR=/usr/local/lib/keyvalet
VAULT_DIR=/var/db/keyvalet
CLI_LINK=/usr/local/bin/keyvalet
SUDOERS_FILE=/etc/sudoers.d/keyvalet
SRC_DIR=$(cd "$(dirname "$0")/.." && pwd)

if [ "$(id -u)" = 0 ]; then
  echo "请以普通用户运行（脚本会在需要时调用 sudo）：./scripts/install.sh" >&2
  exit 1
fi

NODE_SRC=$(command -v node || true)
[ -n "$NODE_SRC" ] || { echo "找不到 node" >&2; exit 1; }
NODE_SRC=$(cd "$(dirname "$NODE_SRC")" && pwd -P)/$(basename "$NODE_SRC")
NODE_MAJOR=$("$NODE_SRC" -p 'process.versions.node.split(".")[0]')
[ "$NODE_MAJOR" -ge 20 ] || { echo "需要 node >= 20（当前 $("$NODE_SRC" -v)）" >&2; exit 1; }

# root helper 会用这个 node 运行；如果它依赖用户可写的动态库（如 Homebrew 版 node），
# 任何用户态进程都能通过替换动态库获得 root —— 拒绝安装。
if otool -L "$NODE_SRC" | tail -n +2 | awk '{print $1}' | grep -Ev '^(/usr/lib/|/System/Library/)' >/dev/null; then
  echo "node ($NODE_SRC) 链接了系统目录以外的动态库，不能安全地以 root 运行。" >&2
  echo "请改用 nvm 或 nodejs.org 官方安装包提供的 node。" >&2
  exit 1
fi

SWIFTC=$(command -v swiftc || true)
[ -n "$SWIFTC" ] || { echo "需要 Swift 编译器：请先运行 xcode-select --install" >&2; exit 1; }

USER_NAME=$(id -un)
case "$USER_NAME" in
  *[!A-Za-z0-9_.-]*|"") echo "用户名 $USER_NAME 含有不支持的字符" >&2; exit 1 ;;
esac

echo "==> 构建"
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
# KeyValet：只允许 $USER_NAME 免密运行凭证库 helper（参数必须完全一致）。
# helper 启动后必须先通过 Touch ID（设备所有者认证）才会提供任何服务。
$USER_NAME ALL=(root) NOPASSWD: $INSTALL_DIR/bin/node $INSTALL_DIR/app/dist/helper/main.js
SUDOERS
/usr/sbin/visudo -cqf "$STAGE/sudoers" || { echo "生成的 sudoers 规则校验失败" >&2; exit 1; }
cat > "$STAGE/keyvalet" <<EOF
#!/bin/sh
exec /usr/bin/sudo -k -- $INSTALL_DIR/bin/node $INSTALL_DIR/app/dist/cli/main.js "\$@"
EOF

echo "==> 安装到 ${INSTALL_DIR}（需要 sudo）"
sudo -k
if [ -t 0 ]; then
  SUDO="sudo"
else
  # 没有终端（例如由 AI agent 代为运行）：用 macOS 原生密码框向用户要密码
  cat > "$STAGE/install-askpass" <<'EOF'
#!/bin/sh
exec /usr/bin/osascript \
  -e 'on run argv' \
  -e 'set r to display dialog (item 1 of argv) with title (item 2 of argv) default answer "" with hidden answer buttons {item 3 of argv, item 4 of argv} default button 2 cancel button 1 with icon caution giving up after 180' \
  -e 'if gave up of r then error number -128' \
  -e 'return text returned of r' \
  -e 'end run' \
  -- "安装 KeyValet 需要管理员权限。请输入 macOS 登录密码（sudo）：" "KeyValet · 安装" "取消" "安装" 2>/dev/null
EOF
  chmod 0700 "$STAGE/install-askpass"
  export SUDO_ASKPASS="$STAGE/install-askpass"
  SUDO="sudo -A"
fi
$SUDO /bin/sh -eu -c '
  INSTALL_DIR="$1"; VAULT_DIR="$2"; CLI_LINK="$3"; STAGE="$4"; SUDOERS_FILE="$5"
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
    echo "已迁移凭证库：/var/db/credential-mcp -> $VAULT_DIR"
  fi
  rm -rf /usr/local/lib/credential-mcp /usr/local/bin/credential-vault /etc/sudoers.d/credential-mcp

  if [ ! -d "$VAULT_DIR" ]; then mkdir -m 0700 "$VAULT_DIR"; fi
  chown root:wheel "$VAULT_DIR"
  chmod 0700 "$VAULT_DIR"

  install -o root -g wheel -m 0440 "$STAGE/sudoers" "$SUDOERS_FILE"
  /usr/sbin/visudo -cq || { rm -f "$SUDOERS_FILE"; echo "sudoers 整体校验失败，已撤销规则" >&2; exit 1; }
' sh "$INSTALL_DIR" "$VAULT_DIR" "$CLI_LINK" "$STAGE" "$SUDOERS_FILE"
sudo -k

# 验证免密规则生效：helper 启动后读到 EOF 会立即退出（不会弹 Touch ID）
if ! /usr/bin/sudo -n -- "$INSTALL_DIR/bin/node" "$INSTALL_DIR/app/dist/helper/main.js" </dev/null >/dev/null 2>&1; then
  echo "⚠️  免密规则未生效：请确认 /etc/sudoers 包含 #includedir /private/etc/sudoers.d" >&2
  exit 1
fi

echo
echo "安装完成。"
echo
echo "在 Claude Code 中注册（用户级，所有项目可用）："
echo "  claude mcp add keyvalet --scope user -- $INSTALL_DIR/bin/node $INSTALL_DIR/app/dist/server/index.js"
echo "（如之前注册过旧名字：claude mcp remove credential --scope user）"
echo
echo "在终端中管理凭证："
echo "  keyvalet help"
