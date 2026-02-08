#!/bin/sh
# Preflight CLI Installer
# Usage: curl -sSL https://preflight.sh/install | sh

set -e

REPO="preflightsh/preflight"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="preflight"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    printf "${GREEN}[INFO]${NC} %s\n" "$1"
}

warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1"
    exit 1
}

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)     echo "linux";;
        Darwin*)    echo "darwin";;
        MINGW*|MSYS*|CYGWIN*) echo "windows";;
        *)          error "Unsupported operating system: $(uname -s)";;
    esac
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "amd64";;
        arm64|aarch64)  echo "arm64";;
        *)              error "Unsupported architecture: $(uname -m)";;
    esac
}

# Get latest version from GitHub
get_latest_version() {
    curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | \
        grep '"tag_name":' | \
        sed -E 's/.*"([^"]+)".*/\1/'
}

# Download and install
install() {
    OS=$(detect_os)
    ARCH=$(detect_arch)

    info "Detected OS: ${OS}, Arch: ${ARCH}"

    VERSION=$(get_latest_version)
    if [ -z "$VERSION" ]; then
        error "Could not determine latest version"
    fi

    info "Latest version: ${VERSION}"

    # Build download URL
    FILENAME="preflight_${VERSION#v}_${OS}_${ARCH}.tar.gz"
    if [ "$OS" = "windows" ]; then
        FILENAME="preflight_${VERSION#v}_${OS}_${ARCH}.zip"
    fi

    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${FILENAME}"

    info "Downloading from: ${DOWNLOAD_URL}"

    # Create temp directory
    TMP_DIR=$(mktemp -d)
    trap "rm -rf ${TMP_DIR}" EXIT

    # Download
    curl -fsSL "${DOWNLOAD_URL}" -o "${TMP_DIR}/${FILENAME}"

    # Extract
    cd "${TMP_DIR}"
    if [ "$OS" = "windows" ]; then
        unzip -q "${FILENAME}"
    else
        tar -xzf "${FILENAME}"
    fi

    # Install
    if [ -w "${INSTALL_DIR}" ]; then
        mv "${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    else
        info "Requesting sudo access to install to ${INSTALL_DIR}"
        sudo mv "${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

    info "Installed ${BINARY_NAME} to ${INSTALL_DIR}/${BINARY_NAME}"
    info "Run 'preflight --help' to get started"
}

# Main
main() {
    echo ""
    echo "  ✈️  Preflight CLI Installer"
    echo ""

    # Check for required tools
    command -v curl >/dev/null 2>&1 || error "curl is required but not installed"
    command -v tar >/dev/null 2>&1 || error "tar is required but not installed"

    install

    echo ""
    printf "${GREEN}Installation complete!${NC}\n"
    echo ""
    echo "  Get started:"
    echo "    cd your-project"
    echo "    preflight init"
    echo "    preflight scan"
    echo ""
}

main
