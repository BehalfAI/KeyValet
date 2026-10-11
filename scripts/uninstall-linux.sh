#!/bin/sh
# Keep the vault and service account by default, so reinstall preserves its owner.
set -eu
[ "$(uname -s)" = Linux ] || exit 1
case "${1:-}" in ''|--purge) ;; *) echo 'usage: uninstall.sh [--purge]' >&2; exit 1 ;; esac
sudo systemctl disable --now keyvalet.service 2>/dev/null || true
sudo rm -f /etc/systemd/system/keyvalet.service /usr/share/polkit-1/actions/dev.keyvalet.policy /usr/local/bin/keyvalet
sudo rm -rf /usr/local/lib/keyvalet
sudo systemctl daemon-reload
if [ "${1:-}" = --purge ]; then
  printf 'Permanently delete /var/lib/keyvalet? Type yes: '
  read -r answer
  if [ "$answer" = yes ]; then
    sudo rm -rf /var/lib/keyvalet /etc/keyvalet
    echo 'Vault deleted.'
  fi
else
  echo 'Vault preserved at /var/lib/keyvalet; owner configuration preserved at /etc/keyvalet.'
fi
sudo -k
