#!/bin/sh
# Builds the macOS Apple Silicon release package and checksum:
#   dist/keyvalet-<tag>-macos-arm64.tar.gz + dist/SHA256SUMS
# Run from anywhere: ./scripts/package-release.sh v0.1.0
# The tag must equal the crate version in rust/crates/kv-cli/Cargo.toml.
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
