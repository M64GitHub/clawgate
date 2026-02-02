#!/bin/bash
# ClawGate installer - https://clawgate.io
# Usage: curl -sSL https://clawgate.io/install.sh | sh
set -e

VERSION="${CLAWGATE_VERSION:-0.1.0}"
INSTALL_DIR="${CLAWGATE_INSTALL_DIR:-/usr/local/bin}"

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
    linux|darwin) ;;
    *) echo "Error: Unsupported OS: $OS"; exit 1 ;;
esac

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *) echo "Error: Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "==> Installing ClawGate ${VERSION} for ${OS}/${ARCH}..."

URL="https://clawgate.io/releases/clawgate-${VERSION}-${OS}-${ARCH}.tar.gz"
TMP=$(mktemp -d)
trap "rm -rf $TMP" EXIT

echo "==> Downloading from ${URL}..."
curl -sSL "$URL" -o "$TMP/clawgate.tar.gz"

echo "==> Extracting..."
tar -xzf "$TMP/clawgate.tar.gz" -C "$TMP"

echo "==> Installing to ${INSTALL_DIR}..."
if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP/clawgate" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/clawgate"
else
    sudo mv "$TMP/clawgate" "$INSTALL_DIR/"
    sudo chmod +x "$INSTALL_DIR/clawgate"
fi

# Check for NATS server
if ! command -v nats-server &> /dev/null; then
    echo ""
    echo "Warning: NATS server not found!"
    echo ""
    echo "ClawGate requires nats-server. Install it:"
    echo ""
    if [[ "$OS" == "darwin" ]]; then
        echo "    brew install nats-server"
    else
        echo "    # Debian/Ubuntu:"
        echo "    sudo apt install nats-server"
        echo ""
        echo "    # Or download from:"
        echo "    https://github.com/nats-io/nats-server/releases"
    fi
    echo ""
fi

echo ""
echo "ClawGate ${VERSION} installed successfully!"
echo ""
echo "Next steps:"
echo "  1. clawgate keygen           Generate Ed25519 keys"
echo "  2. clawgate --mode resource  Start resource daemon (laptop)"
echo "  3. clawgate grant --read ... Create capability token"
echo "  4. clawgate --mode agent     Start agent daemon (isolated machine)"
echo ""
echo "Documentation: https://clawgate.io/docs"
echo ""
