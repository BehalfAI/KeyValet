#!/bin/sh
# Builds the macOS Apple Silicon release package and checksum:
#   dist/keyvalet-<tag>-macos-arm64.tar.gz + dist/SHA256SUMS
# Run from anywhere: ./scripts/package-release.sh v0.1.0
# The tag must equal the crate version in rust/crates/kv-cli/Cargo.toml.
#
# Signing: set SIGN_IDENTITY to a codesigning identity SHA-1 to sign every binary
# (hardened runtime, timestamped, dev.keyvalet.* identifiers); TeamIdentifier must verify as
# PWCRJPY7YC or the build fails. REQUIRE_SIGNED=1 makes SIGN_IDENTITY mandatory.
set -eu

SRC_DIR=$(cd "$(dirname "$0")/.." && pwd)
TAG=${1:-}

VERSION=$(/usr/bin/sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$SRC_DIR/rust/crates/kv-cli/Cargo.toml" | head -1)
[ "$TAG" = "v$VERSION" ] || { echo "Tag must be v$VERSION (rust/crates/kv-cli/Cargo.toml version), got '${TAG:-<none>}'" >&2; exit 1; }

[ "$(uname -s)" = Darwin ] || { echo "The release package must be built on macOS" >&2; exit 1; }

cd "$SRC_DIR/rust"
MACOSX_DEPLOYMENT_TARGET=14.0 cargo build --release --locked --target aarch64-apple-darwin

NAME="keyvalet-$TAG-macos-arm64"
STAGE="$SRC_DIR/dist/$NAME"
rm -rf "$STAGE" "$SRC_DIR/dist/$NAME.tar.gz" "$SRC_DIR/dist/SHA256SUMS"
mkdir -p "$STAGE/bin" "$STAGE/templates" "$STAGE/scripts"

BIN_DIR="$SRC_DIR/rust/target/aarch64-apple-darwin/release"
for b in kv-helper kv-touchid kv-mcp kv-cli kv-hook; do
  [ -x "$BIN_DIR/$b" ] || { echo "Build artifact missing: $b" >&2; exit 1; }
  [ "$(/usr/bin/lipo -archs "$BIN_DIR/$b")" = arm64 ] || { echo "$b is not a single-arch arm64 binary" >&2; exit 1; }
  minos=$(/usr/bin/otool -l "$BIN_DIR/$b" | /usr/bin/awk '/LC_BUILD_VERSION/,/sdk/ { if ($1 == "minos") print $2 }')
  [ "$minos" = "14.0" ] || { echo "$b targets minos $minos, expected 14.0" >&2; exit 1; }
  cp "$BIN_DIR/$b" "$STAGE/bin/"
done

if [ "${REQUIRE_SIGNED:-0}" = 1 ] && [ -z "${SIGN_IDENTITY:-}" ]; then
  echo "REQUIRE_SIGNED=1 but no SIGN_IDENTITY given" >&2
  exit 1
fi
if [ -n "${SIGN_IDENTITY:-}" ]; then
  # Same team check as install.sh: a package is only shipped if every binary verifies strict
  # AND carries our team identifier.
  team_of() { /usr/bin/codesign -dv --verbose=4 "$1" 2>&1 | /usr/bin/sed -n 's/^TeamIdentifier=\(.*\)/\1/p'; }
  for b in kv-helper kv-touchid kv-mcp kv-cli kv-hook; do
    case "$b" in kv-*) ident=${b#kv-};; esac
    /usr/bin/codesign --force --options runtime --timestamp \
      --identifier "dev.keyvalet.$ident" -s "$SIGN_IDENTITY" "$STAGE/bin/$b" >/dev/null
    /usr/bin/codesign --verify --strict "$STAGE/bin/$b" || { echo "$b failed codesign --verify --strict" >&2; exit 1; }
    [ "$(team_of "$STAGE/bin/$b")" = "PWCRJPY7YC" ] || { echo "$b is not signed for team PWCRJPY7YC" >&2; exit 1; }
  done
  echo "Signed all binaries with $SIGN_IDENTITY (team PWCRJPY7YC)"
fi

# Only the committed catalog; templates/n8n-catalog.json is a gitignored local, personal-use import.
cp "$SRC_DIR/templates/catalog.json" "$STAGE/templates/"
cp -R "$SRC_DIR/cursor-plugin" "$STAGE/cursor-plugin"
cp "$SRC_DIR/scripts/install.sh" "$SRC_DIR/scripts/uninstall.sh" "$STAGE/scripts/"
[ -f "$SRC_DIR/LICENSE" ] && cp "$SRC_DIR/LICENSE" "$STAGE/"
cp "$SRC_DIR/README.md" "$SRC_DIR/SECURITY.md" "$STAGE/"

cd "$SRC_DIR/dist"
COPYFILE_DISABLE=1 tar -czf "$NAME.tar.gz" "$NAME"
shasum -a 256 "$NAME.tar.gz" > SHA256SUMS
echo "Built dist/$NAME.tar.gz"
cat SHA256SUMS
