#!/usr/bin/env bash
# install.sh — one-line installer for hostage
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/cyeezy08/HostageLVX/main/install.sh | sh
#   curl -sSL https://raw.githubusercontent.com/cyeezy08/HostageLVX/main/install.sh | sh -s -- -b /usr/local/bin
#   curl -sSL https://raw.githubusercontent.com/cyeezy08/HostageLVX/main/install.sh | sh -s -- --version v0.3.0
#
set -euo pipefail

# --- config ---
REPO="cyeezy08/HostageLVX"
BINARY_NAME="hostage"
DEFAULT_INSTALL_DIR="${HOME}/.local/bin"
VERSION="latest"

# --- helpers ---
info()  { printf '\033[1;34m[i]\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
fatal() { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# --- arg parsing ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -b|--bin-dir)   INSTALL_DIR="$2"; shift 2 ;;
        --version)      VERSION="$2"; shift 2 ;;
        -h|--help)
            cat <<EOF
hostage installer
  -b, --bin-dir <path>   install directory (default: ~/.local/bin)
      --version <ver>    release version (default: latest)
  -h, --help             show this help
EOF
            exit 0 ;;
        *) fatal "unknown flag: $1" ;;
    esac
done
INSTALL_DIR="${INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"

# --- detect platform ---
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$OS" in
    linux*)  OS="linux" ;;
    darwin*) OS="darwin" ;;
    mingw*|msys*|cygwin*) OS="windows" ;;
    *) fatal "unsupported OS: $OS" ;;
esac
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *) fatal "unsupported arch: $ARCH" ;;
esac

# --- resolve version ---
if [[ "$VERSION" == "latest" ]]; then
    info "fetching latest release tag..."
    VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep -m1 '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/' | sed 's/^v//')"
    [[ -z "$VERSION" ]] && fatal "could not resolve latest version"
fi
info "installing hostage ${VERSION} for ${OS}/${ARCH}"

# --- download ---
if [[ "$OS" == "windows" ]]; then
    ASSET="hostage-windows-amd64.exe"
    BIN_PATH="${INSTALL_DIR}/${BINARY_NAME}.exe"
else
    ASSET="hostage-${OS}-${ARCH}"
    BIN_PATH="${INSTALL_DIR}/${BINARY_NAME}"
fi
URL="https://github.com/${REPO}/releases/download/v${VERSION}/${ASSET}"

mkdir -p "$INSTALL_DIR"
info "downloading $URL"
curl -fsSL "$URL" -o "$BIN_PATH" || fatal "download failed"
chmod +x "$BIN_PATH"

# --- checksum verify (if .sha256 exists) ---
SHA_URL="${URL}.sha256"
if curl -fsSL "$SHA_URL" -o /tmp/hostage.sha256 2>/dev/null; then
    expected="$(awk '{print $1}' /tmp/hostage.sha256)"
    actual="$(sha256sum "$BIN_PATH" | awk '{print $1}')"
    if [[ "$expected" == "$actual" ]]; then
        ok "checksum verified: ${actual:0:16}..."
    else
        warn "checksum mismatch — expected ${expected:0:16}, got ${actual:0:16}"
        warn "the binary may have been tampered with. refusing to install."
        rm -f "$BIN_PATH" /tmp/hostage.sha256
        exit 1
    fi
    rm -f /tmp/hostage.sha256
fi

# --- PATH hint ---
case ":$PATH:" in
    *":${INSTALL_DIR}:"*) ;;
    *) warn "${INSTALL_DIR} is not in PATH"
       echo '  add this to your shell rc:'
       echo "    export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
esac

# --- verify ---
"$BIN_PATH" -V || true
ok "hostage ${VERSION} installed at ${BIN_PATH}"
