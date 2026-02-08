#!/bin/sh
# ClawGate installer - https://clawgate.io
# Usage: curl -sSL https://clawgate.io/install.sh | sh

set -e

VERSION="${CLAWGATE_VERSION:-0.3.0}"
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

echo ""
echo "! ClawGate ${VERSION} installed successfully !"
echo ""
echo "Quick start (on your laptop):"
echo "  clawgate keygen"
echo "  clawgate grant --read '~/projects/**' --ttl 24h > token.txt"
echo "  # Or with git access:"
echo "  clawgate grant --git '~/projects/**' --ttl 24h > token.txt"
echo "  scp token.txt ~/.clawgate/keys/public.key agent-machine:"
echo ""
echo "Quick start (on agent machine):"
echo "  clawgate token add \"\$(cat token.txt)\""
echo "  clawgate --mode agent"
echo ""
echo "Then connect from laptop:"
echo "  clawgate --mode resource --connect <agent-ip>:4223"
echo "---"
echo ""
echo "Steps 1-3 are one-time setup. After that, add new tokens anytime:"
echo "  clawgate grant ... > token.txt && scp token.txt agent:"
echo "  clawgate token add \"\$(cat token.txt)\"   # hot-reload, no restart!"
echo "---"
echo ""
echo "Docs:   https://clawgate.io/docs"
echo "GitHub: https://github.com/M64GitHub/clawgate"
echo ""
