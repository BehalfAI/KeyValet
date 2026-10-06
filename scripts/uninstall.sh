#!/bin/sh
# 卸载 KeyValet。默认保留凭证库；加 --purge 同时删除凭证库（不可恢复）。
set -eu

INSTALL_DIR=/usr/local/lib/keyvalet
VAULT_DIR=/var/db/keyvalet
CLI_LINK=/usr/local/bin/keyvalet
SUDOERS_FILE=/etc/sudoers.d/keyvalet

sudo -k
sudo rm -rf "$INSTALL_DIR" "$CLI_LINK" "$SUDOERS_FILE"
echo "已删除 $INSTALL_DIR、$CLI_LINK 和 sudoers 规则 $SUDOERS_FILE"

if [ "${1:-}" = "--purge" ]; then
  printf "确定要永久删除凭证库 %s 吗？输入 yes 确认：" "$VAULT_DIR"
  read -r answer
  if [ "$answer" = "yes" ]; then
    sudo rm -rf "$VAULT_DIR"
    echo "已删除凭证库"
  fi
else
  echo "凭证库保留在 ${VAULT_DIR}（如需删除：./scripts/uninstall.sh --purge）"
fi
sudo -k
