#!/bin/bash
set -e

REPO="victorarias/rm-guard"
BINARY_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY_NAME="rm-guard"

# Detect OS and architecture
detect_platform() {
    local os arch suffix

    case "$(uname -s)" in
        Linux*)  os="linux" ;;
        Darwin*) os="darwin" ;;
        MINGW*|MSYS*|CYGWIN*) os="windows" ;;
        *) echo "Unsupported OS: $(uname -s)" >&2; exit 1 ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64) arch="amd64" ;;
        arm64|aarch64) arch="arm64" ;;
        *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
    esac

    suffix="${os}-${arch}"
    if [ "$os" = "windows" ]; then
        suffix="${suffix}.exe"
    fi

    echo "$suffix"
}

# Get the latest release version from GitHub
get_latest_version() {
    curl -sL "https://api.github.com/repos/${REPO}/releases/latest" | \
        grep '"tag_name"' | \
        sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
}

# Download the binary for the current platform
download_binary() {
    local platform="$1"
    local version="$2"
    local url="https://github.com/${REPO}/releases/download/${version}/${BINARY_NAME}-${platform}"
    local target="${BINARY_DIR}/${BINARY_NAME}"

    echo "Downloading ${BINARY_NAME} ${version} for ${platform}..." >&2

    if command -v curl &> /dev/null; then
        curl -sL "$url" -o "$target"
    elif command -v wget &> /dev/null; then
        wget -q "$url" -O "$target"
    else
        echo "Error: neither curl nor wget found" >&2
        exit 1
    fi

    chmod +x "$target"
    echo "Downloaded to ${target}" >&2
}

# Check if binary exists and is executable
binary_path="${BINARY_DIR}/${BINARY_NAME}"

if [ ! -x "$binary_path" ]; then
    platform=$(detect_platform)
    version=$(get_latest_version)

    if [ -z "$version" ]; then
        echo "Error: Could not determine latest version" >&2
        exit 1
    fi

    download_binary "$platform" "$version"
fi

# Run the binary, passing through stdin and all arguments
exec "$binary_path" "$@"
