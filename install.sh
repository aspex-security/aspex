#!/bin/sh
# Aspex installer — works with both public and private repos.
# Requires: gh CLI (https://cli.github.com) or curl (public repo only).
#
# Usage:
#   gh release download v0.1.0 --repo stevend-dotcom/aspex -p "install.sh" -O - | sh
#   VERSION=v0.1.0 INSTALL_DIR=~/.local/bin sh install.sh

set -e

REPO="${REPO:-stevend-dotcom/aspex}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${VERSION:-}"

# Detect OS
case "$(uname -s)" in
  Darwin) OS="darwin" ;;
  Linux)  OS="linux"  ;;
  MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
  *) echo "Unsupported OS: $(uname -s)" && exit 1 ;;
esac

# Detect arch
case "$(uname -m)" in
  x86_64|amd64)  ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "Unsupported arch: $(uname -m)" && exit 1 ;;
esac

EXT=""
[ "$OS" = "windows" ] && EXT=".exe"

# Resolve latest version
if [ -z "$VERSION" ]; then
  if command -v gh >/dev/null 2>&1; then
    VERSION=$(gh release list --repo "$REPO" --limit 1 --json tagName -q '.[0].tagName' 2>/dev/null)
  fi
  if [ -z "$VERSION" ]; then
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
  fi
  if [ -z "$VERSION" ]; then
    echo "Could not resolve latest version. Set VERSION=v0.1.0 and retry."
    exit 1
  fi
fi

echo "Installing Aspex ${VERSION} (${OS}/${ARCH}) to ${INSTALL_DIR}"

# Create install dir
if [ ! -d "$INSTALL_DIR" ]; then
  mkdir -p "$INSTALL_DIR" 2>/dev/null || sudo mkdir -p "$INSTALL_DIR"
fi

download_binary() {
  NAME="$1"
  ASSET="${NAME}_${OS}_${ARCH}${EXT}"
  DEST="${INSTALL_DIR}/${NAME}${EXT}"

  echo "  Downloading ${ASSET}..."

  if command -v gh >/dev/null 2>&1; then
    # gh works for both public and private repos
    if [ -w "$INSTALL_DIR" ]; then
      gh release download "$VERSION" --repo "$REPO" -p "$ASSET" -O "$DEST" --clobber
    else
      TMP=$(mktemp)
      gh release download "$VERSION" --repo "$REPO" -p "$ASSET" -O "$TMP" --clobber
      sudo mv "$TMP" "$DEST"
    fi
  else
    # curl — only works when repo is public
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
    if [ -w "$INSTALL_DIR" ]; then
      curl -fsSL "$URL" -o "$DEST"
    else
      curl -fsSL "$URL" | sudo tee "$DEST" > /dev/null
    fi
  fi

  chmod +x "$DEST" 2>/dev/null || sudo chmod +x "$DEST"
  echo "  Installed: $DEST"
}

download_binary aspex-scan
download_binary aspex-trace

echo ""
echo "Done. Try it:"
echo "  aspex-scan version"
echo "  aspex-trace version"
