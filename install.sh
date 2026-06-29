#!/bin/sh
# Aspex installer — works with both public and private repos.
# Requires: gh CLI (https://cli.github.com) or curl (public repo only).
#
# Usage:
#   sh <(curl -fsSL https://github.com/aspex-security/aspex/releases/latest/download/install.sh)
#   VERSION=v0.1.0 INSTALL_DIR=~/.local/bin sh install.sh

set -e

REPO="aspex-security/aspex"
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

# verify_checksum downloads checksums.txt for the release and verifies the
# given file matches the expected SHA-256. Aborts on mismatch.
verify_checksum() {
  FILE="$1"
  ASSET_NAME="$2"
  CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

  TMP_CHECKSUMS=$(mktemp)
  if command -v gh >/dev/null 2>&1; then
    gh release download "$VERSION" --repo "$REPO" -p "checksums.txt" -O "$TMP_CHECKSUMS" --clobber 2>/dev/null || \
      curl -fsSL "$CHECKSUMS_URL" -o "$TMP_CHECKSUMS"
  else
    curl -fsSL "$CHECKSUMS_URL" -o "$TMP_CHECKSUMS"
  fi

  # Extract expected hash for this asset
  EXPECTED=$(grep " ${ASSET_NAME}$" "$TMP_CHECKSUMS" | awk '{print $1}')
  rm -f "$TMP_CHECKSUMS"

  if [ -z "$EXPECTED" ]; then
    echo "ERROR: No checksum found for ${ASSET_NAME} in checksums.txt"
    exit 1
  fi

  # Compute actual hash
  if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL=$(sha256sum "$FILE" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    ACTUAL=$(shasum -a 256 "$FILE" | awk '{print $1}')
  else
    echo "WARNING: Neither sha256sum nor shasum found — skipping checksum verification"
    return 0
  fi

  if [ "$ACTUAL" != "$EXPECTED" ]; then
    echo "ERROR: Checksum mismatch for ${ASSET_NAME}"
    echo "  expected: ${EXPECTED}"
    echo "  actual:   ${ACTUAL}"
    exit 1
  fi
  echo "  Checksum verified: ${ASSET_NAME}"
}

download_binary() {
  NAME="$1"
  ASSET="${NAME}_${OS}_${ARCH}${EXT}"
  DEST="${INSTALL_DIR}/${NAME}${EXT}"

  echo "  Downloading ${ASSET}..."

  # Always download to a temp file first so we can verify the checksum before
  # writing to the install directory (and before any sudo invocation).
  TMP=$(mktemp)
  trap 'rm -f "$TMP"' EXIT

  if command -v gh >/dev/null 2>&1; then
    gh release download "$VERSION" --repo "$REPO" -p "$ASSET" -O "$TMP" --clobber
  else
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
    curl -fsSL "$URL" -o "$TMP"
  fi

  verify_checksum "$TMP" "$ASSET"

  if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP" "$DEST"
  else
    sudo mv "$TMP" "$DEST"
  fi
  chmod +x "$DEST" 2>/dev/null || sudo chmod +x "$DEST"
  echo "  Installed: $DEST"
}

download_binary aspex
download_binary aspex-scan
download_binary aspex-trace
download_binary aspex-attack
download_binary aspex-doctor

echo ""
echo "Done. Try it:"
echo "  aspex"
echo "  aspex-scan version"
echo "  aspex-trace version"
echo "  aspex-attack --help"
echo "  aspex-doctor"
