#!/usr/bin/env sh
set -eu

sudo -n apt-get update

base_packages="
    bpftool
    clang
    gcc
    iproute2
    libbpf-dev
    libelf-dev
    llvm
    make
    pkg-config
    python3
    python3-venv
    zlib1g-dev
"

kernel_headers="linux-headers-$(uname -r)"

if sudo -n apt-get install -y $base_packages "$kernel_headers"; then
    exit 0
fi

echo "Exact kernel headers package '$kernel_headers' was not available."
echo "Installing generic headers instead; BPF build may still work for this project."

sudo -n apt-get install -y $base_packages linux-headers-generic

