#!/bin/sh
# Uninstalls KeyValet. Keeps the vault by default; add --purge to also delete the vault (cannot be undone).
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

sudo -k
# Stop the launchd daemon and the per-user agent (a no-op when they were never installed).
sudo /bin/launchctl bootout system/dev.keyvalet.helper 2>/dev/null || true
sudo /bin/launchctl bootout "gui/$(id -u)/dev.keyvalet.agent" 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/dev.keyvalet.helper.plist /Library/LaunchAgents/dev.keyvalet.agent.plist
sudo rm -rf /var/run/keyvalet
sudo rm -rf "$INSTALL_DIR" "$CLI_LINK" "$SUDOERS_FILE"
say "已删除 $INSTALL_DIR、$CLI_LINK、launchd 配置和 sudoers 规则 $SUDOERS_FILE" "Removed $INSTALL_DIR, $CLI_LINK, the launchd plists and the sudoers rule $SUDOERS_FILE"

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
