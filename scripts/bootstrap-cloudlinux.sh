#!/usr/bin/env sh
set -eu

sudo -n dnf install -y \
    bpftool \
    clang \
    gcc \
    kernel-headers \
    libbpf-devel \
    llvm \
    make

