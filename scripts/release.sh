#!/usr/bin/env bash
# Pincer Release Builder
#
# Builds optimized release binaries and creates a distributable tar.gz package.
#
# Usage: ./scripts/release.sh
# Output: ./dist/pincer-<version>-<target>.tar.gz

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="${PROJECT_DIR}/dist"

# Get version from Cargo.toml
VERSION=$(grep '^version' "${PROJECT_DIR}/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
TARGET=$(rustc -vV | grep host: | awk '{print $2}')
PKG_NAME="pincer-${VERSION}-${TARGET}"

echo "🦞 Pincer Release Builder"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Version: ${VERSION}"
echo "  Target:  ${TARGET}"
echo "  Package: ${PKG_NAME}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# --- 1. Build release binary ---
echo "🔨 Building release binary..."
cd "$PROJECT_DIR"
cargo build --release 2>&1

BINARY="${PROJECT_DIR}/target/release/pincer"
if [ ! -f "$BINARY" ]; then
    echo "❌ Release binary not found at: $BINARY"
    exit 1
fi

# Get binary size
BINARY_SIZE=$(du -h "$BINARY" | cut -f1)
echo "  Binary size: ${BINARY_SIZE}"
echo ""

# --- 2. Run tests ---
echo "🧪 Running tests..."
cargo test 2>&1
echo "  ✅ All tests passed"
echo ""

# --- 3. Create distribution package ---
echo "📦 Creating distribution package..."
mkdir -p "$DIST_DIR/${PKG_NAME}"

# Copy files
cp "$BINARY" "$DIST_DIR/${PKG_NAME}/"
cp "${PROJECT_DIR}/README.md" "$DIST_DIR/${PKG_NAME}/"
cp -r "${PROJECT_DIR}/scripts" "$DIST_DIR/${PKG_NAME}/"

# Make scripts executable
chmod +x "$DIST_DIR/${PKG_NAME}"/scripts/*.sh

# Create the tarball
cd "$DIST_DIR"
tar -czf "${PKG_NAME}.tar.gz" "${PKG_NAME}/"

# Clean up staging directory
rm -rf "$DIST_DIR/${PKG_NAME}"

# Get package size
PKG_SIZE=$(du -h "$DIST_DIR/${PKG_NAME}.tar.gz" | cut -f1)

echo ""
echo "✅ Release built successfully!"
echo ""
echo "  Package: ${DIST_DIR}/${PKG_NAME}.tar.gz"
echo "  Size:    ${PKG_SIZE}"
echo ""
echo "  Install:"
echo "    tar xzf ${PKG_NAME}.tar.gz"
echo "    sudo cp ${PKG_NAME}/pincer /usr/local/bin/"
echo ""
