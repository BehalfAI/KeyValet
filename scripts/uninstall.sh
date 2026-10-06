#!/bin/sh
# 卸载 KeyValet。默认保留凭证库；加 --purge 同时删除凭证库（不可恢复）。
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

sudo -k
sudo rm -rf "$INSTALL_DIR" "$CLI_LINK" "$SUDOERS_FILE"
say "已删除 $INSTALL_DIR、$CLI_LINK 和 sudoers 规则 $SUDOERS_FILE" "Removed $INSTALL_DIR, $CLI_LINK and the sudoers rule $SUDOERS_FILE"

if [ "${1:-}" = "--purge" ]; then
  if [ "$KV_LANG" = zh ]; then
    printf "确定要永久删除凭证库 %s 吗？输入 yes 确认：" "$VAULT_DIR"
  else
    printf "Permanently delete the vault %s? Type yes to confirm: " "$VAULT_DIR"
  fi
  read -r answer
  if [ "$answer" = "yes" ]; then
    sudo rm -rf "$VAULT_DIR"
    say "已删除凭证库" "Vault deleted"
  fi
else
  say "凭证库保留在 ${VAULT_DIR}（如需删除：./scripts/uninstall.sh --purge）" "The vault was kept at ${VAULT_DIR} (to delete it: ./scripts/uninstall.sh --purge)"
fi
sudo -k
