#!/usr/bin/env bash
# Install the pinned toolchain Convergence's checks need on Ubuntu 24.04.
#
# Runs as the normal user; nothing here needs root. Every download is pinned by version and
# verified against a SHA-256 recorded in this file, not one fetched next to the download.
set -euo pipefail

UV_VERSION="0.13.6"
declare -A UV_SHA256=(
    [aarch64]="229e194255c7958d86d56e8790d969a6f74736592133f0dfd0076f754c642c1d"
    [x86_64]="f29c3e94ffabd7e6f3ba521dba169a9b7ec12100bf3257087f0f24f6123f3645"
)

install_uv() {
    local arch bin tmp name url
    arch="$(uname -m)"
    bin="$HOME/.local/bin"

    if [[ -z "${UV_SHA256[$arch]:-}" ]]; then
        echo "error: no pinned uv checksum for architecture '$arch'" >&2
        exit 1
    fi

    if [[ -x "$bin/uv" ]] && [[ "$("$bin/uv" --version)" == "uv $UV_VERSION"* ]]; then
        echo "uv $UV_VERSION already installed at $bin/uv"
        return
    fi

    name="uv-$arch-unknown-linux-gnu"
    url="https://github.com/astral-sh/uv/releases/download/$UV_VERSION/$name.tar.gz"
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN

    echo "downloading $url"
    curl --proto '=https' --tlsv1.2 -fsSL -o "$tmp/uv.tar.gz" "$url"
    echo "${UV_SHA256[$arch]}  $tmp/uv.tar.gz" | sha256sum --check --strict -

    tar -xzf "$tmp/uv.tar.gz" -C "$tmp"
    mkdir -p "$bin"
    install -m 0755 "$tmp/$name/uv" "$tmp/$name/uvx" "$bin/"
    echo "installed $("$bin/uv" --version) to $bin"
}

install_uv
