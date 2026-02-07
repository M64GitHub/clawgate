#!/bin/bash
# ClawGate release builder - cross-compile for all targets
set -e

VERSION="${1:-0.2.2}"
DIST_DIR="dist"

echo "Building ClawGate ${VERSION}..."
mkdir -p "$DIST_DIR"

build_target() {
    local target=$1
    local os=$2
    local arch=$3

    echo "==> ${os}-${arch}"
    zig build -Dtarget=${target} -Doptimize=ReleaseSafe

    local binary="zig-out/bin/clawgate"
    local name="clawgate-${VERSION}-${os}-${arch}"

    cp "$binary" "${DIST_DIR}/clawgate"
    tar -czf "${DIST_DIR}/${name}.tar.gz" -C "$DIST_DIR" clawgate
    mv "${DIST_DIR}/clawgate" "${DIST_DIR}/${name}"
}

# Linux x86_64
build_target "x86_64-linux" "linux" "x86_64"

# Linux aarch64
build_target "aarch64-linux" "linux" "aarch64"

# macOS x86_64
build_target "x86_64-macos" "darwin" "x86_64"

# macOS aarch64 (Apple Silicon)
build_target "aarch64-macos" "darwin" "aarch64"

echo ""
echo "Built all targets in ${DIST_DIR}/"
echo ""
ls -lh "${DIST_DIR}"/*.tar.gz
echo ""
echo "Upload these to https://clawgate.io/releases/"
