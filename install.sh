#!/bin/sh
# Preflight CLI Installer
# Usage: curl -sSL https://preflight.sh/install.sh | sh

set -e

REPO="preflightsh/preflight"
# Optional: install somewhere else, e.g. PREFLIGHT_INSTALL_DIR="$HOME/.local/bin"
# on a machine without sudo.
INSTALL_DIR="${PREFLIGHT_INSTALL_DIR:-/usr/local/bin}"
BINARY_NAME="preflight"
# Optional: pin a specific release by setting PREFLIGHT_VERSION (e.g. v0.15.1).
PREFLIGHT_VERSION="${PREFLIGHT_VERSION:-}"

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

# Errors go to stderr: detect_os and friends run inside $(...), where a
# message on stdout would be captured into the variable and never shown.
error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1" >&2
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

# Get the latest version from the releases/latest redirect. The REST API
# allows 60 unauthenticated requests per hour per IP, which shared CI runners
# exhaust; the redirect has no such limit.
get_latest_version() {
    url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest") || return 0
    case "$url" in
        */releases/tag/*) echo "${url##*/}";;
    esac
}

# Download and install
install() {
    OS=$(detect_os)
    ARCH=$(detect_arch)

    info "Detected OS: ${OS}, Arch: ${ARCH}"

    if [ -n "$PREFLIGHT_VERSION" ]; then
        VERSION="$PREFLIGHT_VERSION"
        info "Using pinned version: ${VERSION}"
    else
        VERSION=$(get_latest_version)
        if [ -z "$VERSION" ]; then
            error "Could not determine latest version"
        fi
        info "Latest version: ${VERSION}"
    fi

    # The version string ends up in URLs and the archive filename; reject
    # anything that isn't a plain semver tag so a malformed or hostile API
    # response can't smuggle paths or shell metacharacters into them.
    case "$VERSION" in
        v[0-9]*.[0-9]*.[0-9]* | [0-9]*.[0-9]*.[0-9]*) ;;
        *) error "Unexpected version format: ${VERSION}";;
    esac
    case "$VERSION" in
        *[!A-Za-z0-9.-]*) error "Unexpected version format: ${VERSION}";;
    esac

    # Build download URL
    FILENAME="preflight_${VERSION#v}_${OS}_${ARCH}.tar.gz"
    if [ "$OS" = "windows" ]; then
        FILENAME="preflight_${VERSION#v}_${OS}_${ARCH}.zip"
        # The Windows archive holds preflight.exe.
        BINARY_NAME="preflight.exe"
        command -v unzip >/dev/null 2>&1 || error "unzip is required but not installed"
    fi

    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${FILENAME}"

    info "Downloading from: ${DOWNLOAD_URL}"

    # Create temp directory
    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"' EXIT

    # Download binary and checksums (checksums are mandatory).
    curl -fsSL "${DOWNLOAD_URL}" -o "${TMP_DIR}/${FILENAME}"
    CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
    curl -fsSL "${CHECKSUMS_URL}" -o "${TMP_DIR}/checksums.txt" \
        || error "Could not download checksums file from ${CHECKSUMS_URL}"

    # Verify checksum (hard fail if anything is missing).
    cd "${TMP_DIR}"
    expected=$(grep -F "${FILENAME}" checksums.txt | awk '{print $1}' | head -n 1)
    if [ -z "$expected" ]; then
        error "No checksum entry for ${FILENAME} in checksums.txt"
    fi
    case "$expected" in
        *[!a-f0-9]*) error "Malformed checksum entry for ${FILENAME}";;
    esac
    if [ "${#expected}" -ne 64 ]; then
        error "Malformed checksum entry for ${FILENAME}"
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "${FILENAME}" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "${FILENAME}" | awk '{print $1}')
    else
        error "sha256sum or shasum is required to verify the download"
    fi
    if [ "$actual" != "$expected" ]; then
        error "Checksum verification failed! Expected: ${expected}, Got: ${actual}"
    fi
    info "Checksum verified"

    # Extract
    cd "${TMP_DIR}"
    if [ "$OS" = "windows" ]; then
        unzip -q "${FILENAME}"
    else
        tar -xzf "${FILENAME}"
    fi

    # Set the mode while we still own the file. When the temp dir is on a
    # different filesystem (tmpfs), a sudo mv copies and the result is
    # root-owned, so a chmod after the move fails and set -e aborts the
    # script after the install already succeeded.
    chmod +x "${BINARY_NAME}"

    # Install. A fresh Apple Silicon Mac without Homebrew has no
    # /usr/local/bin, so create the directory first.
    if [ ! -d "${INSTALL_DIR}" ]; then
        if mkdir -p "${INSTALL_DIR}" 2>/dev/null; then
            :
        else
            info "Requesting sudo access to create ${INSTALL_DIR}"
            sudo mkdir -p "${INSTALL_DIR}"
        fi
    fi
    if [ -w "${INSTALL_DIR}" ]; then
        mv "${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    else
        info "Requesting sudo access to install to ${INSTALL_DIR}"
        sudo mv "${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    fi

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
