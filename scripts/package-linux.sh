#!/bin/sh
# Build a native GNU/Linux release; TPM and polkit remain system dependencies.
set -eu
[ "$(uname -s)" = Linux ] || { echo 'Build Linux packages on Linux.' >&2; exit 1; }
SRC_DIR=$(cd "$(dirname "$0")/.." && pwd)
TAG=${1:-}
VERSION=$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$SRC_DIR/rust/crates/kv-cli/Cargo.toml" | head -1)
[ "$TAG" = "v$VERSION" ] || { echo "Expected tag v$VERSION" >&2; exit 1; }
case "$(uname -m)" in x86_64) ARCH=x64 ;; aarch64) ARCH=arm64 ;; *) echo 'Supported: x86_64 and aarch64' >&2; exit 1 ;; esac
(cd "$SRC_DIR/rust" && cargo build --release --workspace --locked)
NAME="keyvalet-$TAG-linux-$ARCH"
STAGE="$SRC_DIR/dist/$NAME"
mkdir -p "$SRC_DIR/dist"
rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/templates" "$STAGE/scripts/linux" "$STAGE/docs"
BIN_DIR="${CARGO_TARGET_DIR:-$SRC_DIR/rust/target}/release"
for binary in kv-helper kv-cli kv-mcp kv-hook; do cp "$BIN_DIR/$binary" "$STAGE/bin/"; done
cp "$SRC_DIR/templates/catalog.json" "$STAGE/templates/"
cp "$SRC_DIR/scripts/install.sh" "$SRC_DIR/scripts/uninstall.sh" "$SRC_DIR/scripts/install-linux.sh" "$SRC_DIR/scripts/install-linux-root.sh" "$SRC_DIR/scripts/uninstall-linux.sh" "$SRC_DIR/scripts/configure-runtimes.sh" "$STAGE/scripts/"
cp "$SRC_DIR/scripts/linux/"* "$STAGE/scripts/linux/"
cp -R "$SRC_DIR/cursor-plugin" "$STAGE/cursor-plugin"
cp "$SRC_DIR/README.md" "$SRC_DIR/SECURITY.md" "$SRC_DIR/LICENSE" "$STAGE/"
cp "$SRC_DIR/docs/linux.md" "$SRC_DIR/docs/key-protection.md" "$SRC_DIR/docs/key-protection.zh-CN.md" "$SRC_DIR/docs/windows.md" "$STAGE/docs/"
(cd "$SRC_DIR/dist" && tar -czf "$NAME.tar.gz" "$NAME" && sha256sum "$NAME.tar.gz" > "$NAME.sha256")
echo "Built dist/$NAME.tar.gz and dist/$NAME.sha256"
