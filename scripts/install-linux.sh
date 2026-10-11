#!/bin/sh
# Linux source or native release installation. Run as the regular vault owner.
set -eu
[ "$(uname -s)" = Linux ] || { echo 'Linux is required' >&2; exit 1; }
[ "$(id -u)" != 0 ] || { echo 'Run as a regular user; the installer uses sudo.' >&2; exit 1; }
SRC_DIR=$(cd "$(dirname "$0")/.." && pwd)
MODE=tpm
DO_SETUP=1
REGISTER=1
KV_LANG=${KEYVALET_LANG:-${LANG:-en}}
case "$KV_LANG" in zh*) KV_LANG=zh ;; *) KV_LANG=en ;; esac
for option in "$@"; do
  case "$option" in
    --software) MODE=software ;;
    --no-setup) DO_SETUP=0 ;;
    --no-register) REGISTER=0 ;;
    *) echo "Unknown option: $option" >&2; exit 1 ;;
  esac
done
for executable in sudo systemctl pkcheck pkttyagent; do
  command -v "$executable" >/dev/null 2>&1 || { echo "Missing $executable. Ubuntu/Debian: sudo apt install sudo policykit-1" >&2; exit 1; }
done
if [ -x "$SRC_DIR/bin/kv-helper" ] && [ ! -d "$SRC_DIR/rust" ]; then
  BIN_DIR="$SRC_DIR/bin"
else
  command -v cargo >/dev/null 2>&1 || { echo 'Install Rust from https://rustup.rs first.' >&2; exit 1; }
  # Use one absolute directory for both Cargo and artifact lookup, including relative overrides.
  case "${CARGO_TARGET_DIR:-target}" in
    /*) KV_BUILD_TARGET_DIR=$CARGO_TARGET_DIR ;;
    *) KV_BUILD_TARGET_DIR="$SRC_DIR/rust/${CARGO_TARGET_DIR:-target}" ;;
  esac
  (cd "$SRC_DIR/rust" && cargo build --release --workspace --locked --target-dir "$KV_BUILD_TARGET_DIR")
  BIN_DIR="$KV_BUILD_TARGET_DIR/release"
fi
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/bin" "$STAGE/templates"
for binary in kv-helper kv-cli kv-mcp kv-hook; do
  [ -x "$BIN_DIR/$binary" ] || { echo "Missing build artifact: $binary" >&2; exit 1; }
  cp "$BIN_DIR/$binary" "$STAGE/bin/"
done
cp "$SRC_DIR/templates/catalog.json" "$STAGE/templates/"
cp "$SRC_DIR/scripts/linux/keyvalet.service" "$SRC_DIR/scripts/linux/dev.keyvalet.policy" "$STAGE/"
if getent group tss >/dev/null 2>&1; then
  # Add within [Service], not after [Install].
  sed '/^User=keyvalet$/a SupplementaryGroups=tss' "$STAGE/keyvalet.service" > "$STAGE/keyvalet.service.new"
  mv "$STAGE/keyvalet.service.new" "$STAGE/keyvalet.service"
fi
cat > "$STAGE/keyvalet" <<'WRAPPER'
#!/bin/sh
set -eu
if [ "${1:-}" = approve ]; then
  exec /usr/local/lib/keyvalet/bin/kv-cli "$@"
fi
KV_CLI_LANG=${KEYVALET_LANG:-${LANG:-en}}
case "$KV_CLI_LANG" in zh*) KV_CLI_LANG=zh ;; *) KV_CLI_LANG=en ;; esac
exec /usr/bin/sudo -k -- /usr/local/lib/keyvalet/bin/kv-cli --lang "$KV_CLI_LANG" "$@"
WRAPPER
sudo /bin/sh "$SRC_DIR/scripts/install-linux-root.sh" "$STAGE" "$(id -u)"
sudo /usr/local/lib/keyvalet/bin/kv-cli --lang "$KV_LANG" status --summary
if [ "$DO_SETUP" = 1 ]; then
  STATUS=$(sudo /usr/local/lib/keyvalet/bin/kv-cli --lang "$KV_LANG" protection)
  if printf '%s\n' "$STATUS" | grep -q '"provider": "uninitialized"'; then
    if [ "$MODE" = tpm ]; then
      printf '%s\n' "$STATUS" | grep -q '"resource_manager_present": true' || { echo 'TPM 2.0 availability could not be confirmed. To explicitly enable software protection, run scripts/install.sh --software, or keyvalet setup-software.' >&2; exit 1; }
      command -v tpm2_ecdhzgen >/dev/null 2>&1 || { echo 'Install TPM tools: sudo apt install tpm2-tools. Then run keyvalet setup-tpm.' >&2; exit 1; }
      sudo /usr/local/lib/keyvalet/bin/kv-cli --lang "$KV_LANG" setup-tpm
    else
      sudo /usr/local/lib/keyvalet/bin/kv-cli --lang "$KV_LANG" setup-software
    fi
  else
    printf 'Existing vault protection preserved:\n%s\n' "$STATUS"
  fi
  sudo /usr/local/lib/keyvalet/bin/kv-cli --lang "$KV_LANG" status --summary
fi
if [ "$REGISTER" = 1 ] && [ "${KEYVALET_NO_REGISTER:-0}" != 1 ]; then
  INSTALL_DIR=/usr/local/lib/keyvalet
  say() { if [ "$KV_LANG" = zh ]; then printf '%s\n' "$1"; else printf '%s\n' "$2"; fi; }
  . "$SRC_DIR/scripts/configure-runtimes.sh"
  if command -v claude >/dev/null 2>&1 && ! claude mcp get keyvalet >/dev/null 2>&1; then
    claude mcp add keyvalet --scope user -- "$INSTALL_DIR/bin/kv-mcp"
  fi
fi
echo 'KeyValet installed (systemd, User=keyvalet). Restart your MCP clients.'
echo 'MCP command: /usr/local/lib/keyvalet/bin/kv-mcp'
echo 'SSH approvals: keyvalet approve <kv-mcp-pid> in a separate user terminal.'
sudo -k
