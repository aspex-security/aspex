#!/bin/sh
# Aspex installer — downloads aspex-scan and aspex-trace for your platform.
# Usage: curl -fsSL https://raw.githubusercontent.com/stevend-dotcom/aspex/main/install.sh | sh

set -e

REPO="stevend-dotcom/aspex"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${VERSION:-latest}"

# Detect OS
case "$(uname -s)" in
  Darwin) OS="darwin" ;;
  Linux)  OS="linux"  ;;
  MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
  *) echo "Unsupported OS: $(uname -s)" && exit 1 ;;
esac

# Detect arch
case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "Unsupported arch: $(uname -m)" && exit 1 ;;
esac

EXT=""
[ "$OS" = "windows" ] && EXT=".exe"

# Resolve latest version if needed
if [ "$VERSION" = "latest" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
fi

BASE="https://github.com/${REPO}/releases/download/${VERSION}"

echo "Installing Aspex ${VERSION} (${OS}/${ARCH}) to ${INSTALL_DIR}"

install_binary() {
  NAME="$1"
  URL="${BASE}/${NAME}_${OS}_${ARCH}${EXT}"
  DEST="${INSTALL_DIR}/${NAME}${EXT}"

  echo "  Downloading ${NAME}..."
  curl -fsSL "$URL" -o "$DEST"
  chmod +x "$DEST"
  echo "  Installed: $DEST"
}

# Create install dir if needed (may need sudo)
if [ ! -d "$INSTALL_DIR" ]; then
  mkdir -p "$INSTALL_DIR" 2>/dev/null || sudo mkdir -p "$INSTALL_DIR"
fi

# Try without sudo first, fall back to sudo
if [ -w "$INSTALL_DIR" ]; then
  install_binary aspex-scan
  install_binary aspex-trace
else
  echo "  (${INSTALL_DIR} requires sudo)"
  install_binary() {
    NAME="$1"
    URL="${BASE}/${NAME}_${OS}_${ARCH}${EXT}"
    DEST="${INSTALL_DIR}/${NAME}${EXT}"
    echo "  Downloading ${NAME}..."
    curl -fsSL "$URL" | sudo tee "$DEST" > /dev/null
    sudo chmod +x "$DEST"
    echo "  Installed: $DEST"
  }
  install_binary aspex-scan
  install_binary aspex-trace
fi

echo ""
echo "Done. Verify with:"
echo "  aspex-scan version"
echo "  aspex-trace version"
