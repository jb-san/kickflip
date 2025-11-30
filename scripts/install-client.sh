#!/bin/bash
# Kickflip Client Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/jb-san/kickflip/main/scripts/install-client.sh | bash

set -e

REPO="jb-san/kickflip"
BINARY_NAME="kickflip-client"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Detect target triple (Rust-style)
detect_target() {
    local os arch
    
    case "$(uname -s)" in
        Linux*)  os="unknown-linux-gnu" ;;
        Darwin*) os="apple-darwin" ;;
        *)       error "Unsupported OS: $(uname -s)" ;;
    esac
    
    case "$(uname -m)" in
        x86_64|amd64)  arch="x86_64" ;;
        arm64|aarch64) arch="aarch64" ;;
        *)             error "Unsupported architecture: $(uname -m)" ;;
    esac
    
    echo "${arch}-${os}"
}

# Get latest release version
get_latest_version() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | \
        grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     Kickflip Client Installer         ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
echo ""

# Detect platform
TARGET=$(detect_target)
info "Detected platform: ${TARGET}"

# Get latest version
info "Fetching latest release..."
VERSION=$(get_latest_version)
if [ -z "$VERSION" ]; then
    error "Could not determine latest version"
fi
info "Latest version: ${VERSION}"

# Construct download URL
# Tarball naming: kickflip-{version_without_v}-{target}.tar.gz
VERSION_NUM="${VERSION#v}"  # Strip leading 'v' if present
TARBALL_NAME="kickflip-${VERSION_NUM}-${TARGET}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL_NAME}"

info "Downloading ${TARBALL_NAME}..."

# Create temp directory
TMP_DIR=$(mktemp -d)
trap "rm -rf ${TMP_DIR}" EXIT

# Download tarball
if ! curl -fsSL -o "${TMP_DIR}/${TARBALL_NAME}" "${DOWNLOAD_URL}"; then
    error "Failed to download from ${DOWNLOAD_URL}"
fi

# Extract
info "Extracting..."
tar -xzf "${TMP_DIR}/${TARBALL_NAME}" -C "${TMP_DIR}"

# Find the binary (it's in a subdirectory named after the target)
BINARY_PATH="${TMP_DIR}/${TARGET}/${BINARY_NAME}"
if [ ! -f "${BINARY_PATH}" ]; then
    error "Binary not found in tarball at ${BINARY_PATH}"
fi

# Make executable
chmod +x "${BINARY_PATH}"

# Verify it runs
if ! "${BINARY_PATH}" --version &>/dev/null; then
    warn "Binary verification failed, but continuing anyway..."
fi

# Install
info "Installing to ${INSTALL_DIR}..."
if [ -w "${INSTALL_DIR}" ]; then
    mv "${BINARY_PATH}" "${INSTALL_DIR}/${BINARY_NAME}"
else
    sudo mv "${BINARY_PATH}" "${INSTALL_DIR}/${BINARY_NAME}"
fi

success "Installed ${BINARY_NAME} to ${INSTALL_DIR}/${BINARY_NAME}"

# Check if alias already exists
SHELL_RC=""
case "${SHELL}" in
    */zsh)  SHELL_RC="$HOME/.zshrc" ;;
    */bash) SHELL_RC="$HOME/.bashrc" ;;
    *)      SHELL_RC="" ;;
esac

# Offer to add alias
if [ -n "${SHELL_RC}" ]; then
    echo ""
    echo -e "${YELLOW}Would you like to add a 'kf' alias for kickflip-client?${NC}"
    echo -e "This will add: ${BLUE}alias kf='kickflip-client'${NC} to ${SHELL_RC}"
    echo ""
    echo -n "Add alias? [y/N] "
    read -n 1 -r REPLY < /dev/tty
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if ! grep -q "alias kf=" "${SHELL_RC}" 2>/dev/null; then
            echo "" >> "${SHELL_RC}"
            echo "# Kickflip client alias" >> "${SHELL_RC}"
            echo "alias kf='kickflip-client'" >> "${SHELL_RC}"
            success "Added alias to ${SHELL_RC}"
            warn "Run 'source ${SHELL_RC}' or restart your shell to use the alias"
        else
            info "Alias 'kf' already exists in ${SHELL_RC}"
        fi
    fi
fi

echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Installation complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo "Next steps:"
echo "  1. Run 'kickflip-client setup' to configure your client"
echo "  2. Run 'kickflip-client connect http --subdomain myapp -p 3000' to start a tunnel"
echo ""
echo "Documentation: https://github.com/${REPO}"
echo ""

