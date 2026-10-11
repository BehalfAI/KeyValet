#!/bin/sh
# Privileged installation only. Secrets and recovery passphrases never enter this script.
set -eu
[ "$(id -u)" = 0 ] || { echo 'Root required' >&2; exit 1; }
STAGE=$1
OWNER_UID=$2
case "$OWNER_UID" in ''|*[!0-9]*|0) echo 'Invalid owner uid' >&2; exit 1 ;; esac
getent passwd "$OWNER_UID" >/dev/null || { echo 'Owner does not exist' >&2; exit 1; }
INSTALL_DIR=/usr/local/lib/keyvalet
VAULT_DIR=/var/lib/keyvalet
for directory in /usr/local /usr/local/lib /usr/local/bin /etc/keyvalet "$VAULT_DIR" "$INSTALL_DIR"; do
  [ ! -L "$directory" ] || { echo "Refusing symlink: $directory" >&2; exit 1; }
done
if ! getent passwd keyvalet >/dev/null; then
  /usr/sbin/useradd --system --user-group --home-dir "$VAULT_DIR" --no-create-home --shell /usr/sbin/nologin keyvalet
fi
SERVICE_UID=$(id -u keyvalet)
[ "$SERVICE_UID" -gt 0 ] && [ "$SERVICE_UID" -lt 1000 ] || { echo 'keyvalet must be a system service user' >&2; exit 1; }
getent passwd keyvalet | grep -Eq ':(/usr/sbin/nologin|/sbin/nologin|/bin/false)$' || { echo 'keyvalet must have a non-login shell' >&2; exit 1; }
if [ -e /etc/keyvalet/owner.uid ]; then
  [ ! -L /etc/keyvalet/owner.uid ] && [ -f /etc/keyvalet/owner.uid ] && [ "$(stat -c %u /etc/keyvalet/owner.uid)" = 0 ] || { echo 'Untrusted owner file' >&2; exit 1; }
  [ "$(cat /etc/keyvalet/owner.uid)" = "$OWNER_UID" ] || { echo 'Vault belongs to a different user; explicit migration is required.' >&2; exit 1; }
fi
[ ! -L /etc/keyvalet/owner.uid ] || { echo 'Refusing owner-file symlink' >&2; exit 1; }
if [ -d "$VAULT_DIR" ]; then
  [ "$(stat -c %u "$VAULT_DIR")" = "$SERVICE_UID" ] || { echo 'Existing vault has a different owner; refusing to adopt it.' >&2; exit 1; }
  [ "$(stat -c %a "$VAULT_DIR")" = 700 ] || { echo 'Existing vault must have mode 0700.' >&2; exit 1; }
else
  install -d -o keyvalet -g keyvalet -m 0700 "$VAULT_DIR"
fi
install -d -o root -g root -m 0755 /usr/local/lib /usr/local/bin /etc/keyvalet
NEXT=$(mktemp -d /usr/local/lib/keyvalet.new.XXXXXX)
trap 'rm -rf "$NEXT"' EXIT
cp -R "$STAGE/bin" "$STAGE/templates" "$NEXT/"
chown -R root:root "$NEXT"
chmod -R u=rwX,go=rX "$NEXT"
chmod 0755 "$NEXT" "$NEXT/bin/"*
systemctl stop keyvalet.service 2>/dev/null || true
if [ -e "$INSTALL_DIR" ]; then
  [ -d "$INSTALL_DIR" ] || { echo 'Install path is not a directory' >&2; exit 1; }
  rm -rf "$INSTALL_DIR.old"
  mv "$INSTALL_DIR" "$INSTALL_DIR.old"
fi
mv "$NEXT" "$INSTALL_DIR"
install -o root -g root -m 0755 "$STAGE/keyvalet" /usr/local/bin/keyvalet
printf '%s\n' "$OWNER_UID" > /etc/keyvalet/owner.uid
chown root:root /etc/keyvalet/owner.uid
chmod 0644 /etc/keyvalet/owner.uid
install -o root -g root -m 0644 "$STAGE/dev.keyvalet.policy" /usr/share/polkit-1/actions/dev.keyvalet.policy
install -o root -g root -m 0644 "$STAGE/keyvalet.service" /etc/systemd/system/keyvalet.service
systemctl daemon-reload
systemctl enable --now keyvalet.service
systemctl is-active --quiet keyvalet.service
rm -rf "$INSTALL_DIR.old"
