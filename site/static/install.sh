#!/bin/sh
# KeyValet one-line installer (macOS and GNU/Linux).
#
#   curl -fsSL https://keyvalet.dev/install.sh | sh
#
# On Apple Silicon (or a Rosetta shell) it downloads the release's prebuilt
# package (arm64 binaries) and verifies it against the SHA256SUMS
# published with the same release; on Intel, or when no release exists, it
# downloads the source and builds it locally. Requires macOS 14 or later.
# Runs its installer (which asks for your password once), registers it with
# Claude Code if present, and cleans up. Re-run to upgrade.
#
#   Uninstall:          curl -fsSL https://keyvalet.dev/install.sh | sh -s -- --uninstall
#   Pin a version:      KEYVALET_VERSION=v0.1.0 sh install.sh      (default: latest release, else main)
#   Local package:      KEYVALET_ARCHIVE=/path/to/keyvalet-vX.Y.Z-macos-arm64.tar.gz sh install.sh
#   Skip registration:  KEYVALET_NO_REGISTER=1 sh install.sh
set -eu

REPO="KeyValet/KeyValet"
INSTALL_DIR=/usr/local/lib/keyvalet
ACTION=install
[ "${1:-}" = "--uninstall" ] && ACTION=uninstall

say()  { printf '\033[1m==>\033[0m %s\n' "$1"; }
fail() { printf '\033[31mError:\033[0m %s\n' "$1" >&2; exit 1; }

PLATFORM=$(uname -s)
case "$PLATFORM" in Darwin|Linux) ;; *) fail "Use install.ps1 on Windows; this installer supports macOS and Linux." ;; esac
[ "$(id -u)" != 0 ] || fail "Run as your normal user (not root); you'll be asked for your password when needed."

if [ "$PLATFORM" = Darwin ]; then
  OS_MAJOR=$(sw_vers -productVersion | cut -d. -f1)
  [ "$OS_MAJOR" -ge 14 ] 2>/dev/null || fail "KeyValet requires macOS 14 or later."
fi

# Version: explicit > latest release > main
REF="${KEYVALET_VERSION:-}"
if [ -z "$REF" ]; then
  REF=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1 || true)
fi
[ -n "$REF" ] || REF=main

# Install mode: prebuilt release binaries on Apple Silicon (a Rosetta-translated
# shell still runs the arm64 install fine), source build on Intel or for main.
MODE=source
if [ "$ACTION" = install ]; then
  ARCH=$(uname -m)
  if [ "$PLATFORM" = Linux ]; then
    case "$ARCH" in x86_64) PACKAGE_ARCH=x64 ;; aarch64) PACKAGE_ARCH=arm64 ;; *) fail "Linux packages support x86_64 and aarch64; use a source checkout for another architecture." ;; esac
    if [ "$REF" != main ] || [ -n "${KEYVALET_ARCHIVE:-}" ]; then MODE=prebuilt; fi
  else
    TRANSLATED=$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)
    if [ "$ARCH" = arm64 ] || [ "$TRANSLATED" = 1 ]; then
    if [ "$REF" != main ] || [ -n "${KEYVALET_ARCHIVE:-}" ]; then
      MODE=prebuilt
    fi
    else
    say "Intel Mac: building from source (Secure Enclave on T2 Macs is untested)."
    fi
  fi
fi

require_source_toolchain() {
  command -v cargo >/dev/null 2>&1 || fail "The Rust toolchain (cargo) is required. Install it from https://rustup.rs"
  if [ "$PLATFORM" = Darwin ]; then
    xcrun --find swiftc >/dev/null 2>&1 || fail "Xcode Command Line Tools (swiftc) are required. Install them with: xcode-select --install"
  else
    command -v cc >/dev/null 2>&1 || fail "A C compiler is required; on Ubuntu/Debian: sudo apt install build-essential"
  fi
}

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [ "$MODE" = prebuilt ]; then
  ASSET="keyvalet-$REF-macos-arm64.tar.gz"
  [ "$PLATFORM" != Linux ] || ASSET="keyvalet-$REF-linux-$PACKAGE_ARCH.tar.gz"
  mkdir -p "$TMP/pkg"
  if [ -n "${KEYVALET_ARCHIVE:-}" ]; then
    [ -f "$KEYVALET_ARCHIVE" ] || fail "KEYVALET_ARCHIVE not found: $KEYVALET_ARCHIVE"
    cp "$KEYVALET_ARCHIVE" "$TMP/pkg/$ASSET"
    say "Using local package $KEYVALET_ARCHIVE (checksum NOT verified)"
  else
    say "Downloading KeyValet release $REF ($PLATFORM)"
    ASSET_URL="https://github.com/$REPO/releases/download/$REF/$ASSET"
    SUMS_URL="https://github.com/$REPO/releases/download/$REF/SHA256SUMS"
    [ "$PLATFORM" != Linux ] || SUMS_URL="https://github.com/$REPO/releases/download/$REF/${ASSET%.tar.gz}.sha256"
    if ! curl -fsSL "$ASSET_URL" -o "$TMP/pkg/$ASSET"; then
      say "No prebuilt package at $ASSET_URL (release without assets?); falling back to a source build"
      MODE=source
      # Before Linux assets are published, an unpinned Linux install builds main.
      if [ "$PLATFORM" = Linux ] && [ -z "${KEYVALET_VERSION:-}" ]; then REF=main; fi
    else
      curl -fsSL "$SUMS_URL" -o "$TMP/SHA256SUMS" || fail "Could not download SHA256SUMS for release $REF"
      grep " $ASSET\$" "$TMP/SHA256SUMS" > "$TMP/check" || fail "SHA256SUMS has no entry for $ASSET"
      if [ "$PLATFORM" = Linux ]; then
        (cd "$TMP/pkg" && sha256sum -c "$TMP/check" >/dev/null) || fail "Checksum mismatch for $ASSET -- aborting (no fallback)"
      else
        (cd "$TMP/pkg" && shasum -a 256 -c "$TMP/check" >/dev/null) || fail "Checksum mismatch for $ASSET -- aborting (no fallback)"
      fi
      say "Checksum verified against SHA256SUMS from release $REF"
    fi
  fi
  if [ "$MODE" = prebuilt ]; then
    tar -xzf "$TMP/pkg/$ASSET" -C "$TMP" --strip-components 1 || fail "Could not extract $ASSET"
  fi
fi

if [ "$MODE" = source ]; then
  [ "$ACTION" = install ] && require_source_toolchain
  if [ "$REF" = main ]; then
    URL="https://github.com/$REPO/archive/refs/heads/main.tar.gz"
  else
    URL="https://github.com/$REPO/archive/refs/tags/$REF.tar.gz"
  fi
  say "Downloading KeyValet source ($REF)"
  curl -fsSL "$URL" -o "$TMP/source.tar.gz" || fail "Download failed: $URL"
  tar -xzf "$TMP/source.tar.gz" -C "$TMP" --strip-components 1 || fail "Could not extract the source archive"
fi

[ "${KEYVALET_DRY_RUN:-}" = 1 ] && { say "Dry run ($MODE mode): downloaded to $TMP, stopping here."; ls "$TMP"; exit 0; }

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

run sh scripts/install.sh "$@"

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
