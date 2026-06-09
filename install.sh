#!/bin/sh
# Burnwall installer for macOS and Linux.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/intbot/burnwall/main/install.sh | sh
#
# Environment variables:
#   BURNWALL_VERSION       Install a specific version (e.g. "0.3.1"). Defaults to latest.
#   BURNWALL_INSTALL_DIR   Where to place the binary. Defaults to $HOME/.local/bin.

set -eu

REPO="intbot/burnwall"
INSTALL_DIR="${BURNWALL_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${BURNWALL_VERSION:-latest}"

info() { printf "burnwall: %s\n" "$*"; }
die() { printf "burnwall installer error: %s\n" "$*" >&2; exit 1; }

# Need curl and tar
command -v curl >/dev/null 2>&1 || die "curl is required but not installed"
command -v tar >/dev/null 2>&1 || die "tar is required but not installed"

# Detect OS
uname_s=$(uname -s)
case "$uname_s" in
    Darwin) os_part="apple-darwin" ;;
    Linux)  os_part="unknown-linux-gnu" ;;
    *) die "unsupported OS: $uname_s. See https://github.com/${REPO}/releases for prebuilt binaries." ;;
esac

# Detect arch
uname_m=$(uname -m)
case "$uname_m" in
    aarch64|arm64) arch_part="aarch64" ;;
    x86_64|amd64)  arch_part="x86_64" ;;
    *) die "unsupported architecture: $uname_m. Try 'cargo install burnwall' or build from source." ;;
esac

# Published targets: aarch64-darwin, x86_64-darwin, aarch64-linux, x86_64-linux.
target="${arch_part}-${os_part}"

# Resolve version → tag
if [ "$VERSION" = "latest" ]; then
    info "resolving latest release..."
    tag=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | head -n 1 \
        | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
    [ -n "$tag" ] || die "could not resolve latest release tag from the GitHub API"
else
    # Accept "0.3.1" or "v0.3.1"
    tag="v${VERSION#v}"
fi

url="https://github.com/${REPO}/releases/download/${tag}/burnwall-${target}.tar.xz"

# Tempdir + cleanup
tmp=$(mktemp -d 2>/dev/null || mktemp -d -t burnwall)
trap 'rm -rf "$tmp"' EXIT INT HUP TERM

info "downloading ${tag} for ${target}..."
if ! curl -fsSL -o "${tmp}/burnwall.tar.xz" "$url"; then
    die "download failed: ${url}"
fi

info "extracting..."
tar -xJf "${tmp}/burnwall.tar.xz" -C "$tmp"
# The archive extracts to a `burnwall-<target>/` subdir — locate the binary
# rather than assuming a flat layout.
bin_path=$(find "$tmp" -type f -name burnwall | head -n 1)
[ -n "$bin_path" ] || die "archive did not contain a 'burnwall' binary"

mkdir -p "$INSTALL_DIR"
mv "$bin_path" "${INSTALL_DIR}/burnwall"
chmod 755 "${INSTALL_DIR}/burnwall"

info ""
info "installed ${tag} to ${INSTALL_DIR}/burnwall"
"${INSTALL_DIR}/burnwall" --version 2>/dev/null || true

# PATH hint
case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
        info ""
        info "NOTE: ${INSTALL_DIR} is not on your PATH."
        info "Add this line to your shell rc (~/.zshrc, ~/.bashrc, ~/.profile):"
        info ""
        info "    export PATH=\"${INSTALL_DIR}:\$PATH\""
        ;;
esac

info ""
info "next steps:"
info "  burnwall init --apply    # detect AI tools and configure env vars"
info "  burnwall start           # run the proxy"
