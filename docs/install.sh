#!/bin/sh
# KeyValet one-line installer (macOS).
#
#   curl -fsSL https://behalfai.github.io/KeyValet/install.sh | sh
#
# Downloads KeyValet from GitHub into a temporary directory, runs its installer
# (which asks for your password once), registers it with Claude Code if present,
# and cleans up. Re-run to upgrade.
#
#   Uninstall:          curl -fsSL https://behalfai.github.io/KeyValet/install.sh | sh -s -- --uninstall
#   Pin a version:      KEYVALET_VERSION=v0.1.0 sh install.sh      (default: latest release, else main)
#   Skip registration:  KEYVALET_NO_REGISTER=1 sh install.sh
set -eu

REPO="BehalfAI/KeyValet"
INSTALL_DIR=/usr/local/lib/keyvalet
ACTION=install
[ "${1:-}" = "--uninstall" ] && ACTION=uninstall

say()  { printf '\033[1m==>\033[0m %s\n' "$1"; }
fail() { printf '\033[31mError:\033[0m %s\n' "$1" >&2; exit 1; }

[ "$(uname -s)" = Darwin ] || fail "KeyValet currently supports macOS only."
[ "$(id -u)" != 0 ] || fail "Run as your normal user (not root); you'll be asked for your password when needed."

if [ "$ACTION" = install ]; then
  command -v cargo >/dev/null 2>&1 || fail "The Rust toolchain (cargo) is required. Install it from https://rustup.rs"
fi

# Version: explicit > latest release > main
REF="${KEYVALET_VERSION:-}"
if [ -z "$REF" ]; then
  REF=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1 || true)
fi
if [ -n "$REF" ]; then
  URL="https://github.com/$REPO/archive/refs/tags/$REF.tar.gz"
else
  REF=main
  URL="https://github.com/$REPO/archive/refs/heads/main.tar.gz"
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
say "Downloading KeyValet ($REF)"
curl -fsSL "$URL" | tar -xz -C "$TMP" --strip-components 1 || fail "Download failed: $URL"

[ "${KEYVALET_DRY_RUN:-}" = 1 ] && { say "Dry run: downloaded to $TMP, stopping here."; ls "$TMP"; exit 0; }

# Give the installer a real terminal for the sudo password when we have one (curl | sh pipes stdin);
# without a terminal it falls back to a native macOS password dialog.
run() {
  # Can't just check -r/-w: without a controlling terminal (e.g. run by an agent), /dev/tty exists but can't be opened
  if (: </dev/tty) 2>/dev/null; then (cd "$TMP" && "$@" </dev/tty); else (cd "$TMP" && "$@"); fi
}

if [ "$ACTION" = uninstall ]; then
  run sh scripts/uninstall.sh
  if command -v claude >/dev/null 2>&1; then
    if claude mcp get keyvalet >/dev/null 2>&1; then
      claude mcp remove keyvalet --scope user >/dev/null 2>&1 || true
      say "Removed the keyvalet MCP server from Claude Code."
    fi
    claude plugin uninstall keyvalet@keyvalet >/dev/null 2>&1 && say "Removed the KeyValet plugin." || true
  fi
  exit 0
fi

run sh scripts/install.sh

if [ -z "${KEYVALET_NO_REGISTER:-}" ] && command -v claude >/dev/null 2>&1; then
  if claude mcp get keyvalet >/dev/null 2>&1; then
    say "Claude Code already has the keyvalet MCP server."
  else
    claude mcp add keyvalet --scope user -- "$INSTALL_DIR/bin/kv-mcp" >/dev/null
    say "Registered KeyValet with Claude Code."
  fi
  # Plugin: /keyvalet:add, /keyvalet:mode, /keyvalet:status, /keyvalet:lock, /keyvalet:audit, plus usage guidance
  if claude plugin marketplace list 2>/dev/null | grep -q keyvalet; then
    claude plugin marketplace update keyvalet >/dev/null 2>&1 || true
  else
    claude plugin marketplace add "$REPO" >/dev/null 2>&1 || true
  fi
  if claude plugin list 2>/dev/null | grep -q "keyvalet@keyvalet"; then
    claude plugin update keyvalet@keyvalet >/dev/null 2>&1 || true
    say "Updated the KeyValet plugin for Claude Code."
  elif claude plugin install keyvalet@keyvalet >/dev/null 2>&1; then
    say "Installed the KeyValet plugin (/keyvalet:add, /keyvalet:mode, /keyvalet:status, /keyvalet:lock, /keyvalet:audit)."
  else
    say "Could not install the Claude Code plugin automatically; run: claude plugin marketplace add $REPO && claude plugin install keyvalet@keyvalet"
  fi
  say "Restart open Claude Code sessions to load KeyValet."
else
  say "Add KeyValet to your MCP client as a stdio server:"
  echo "    command: $INSTALL_DIR/bin/kv-mcp"
fi

echo
say "Done. In Claude Code, run /keyvalet:add openai to store your first key."
