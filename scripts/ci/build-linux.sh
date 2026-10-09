#!/usr/bin/env bash
# Build a binary for the host architecture inside a pinned Debian Bookworm Rust image.
#
# Replaces `cross` for CI builds: x86_64 and aarch64 are each built natively on a
# runner of that architecture. Bookworm's glibc (2.36) sets the minimum glibc
# required by the resulting binary.
#
# Usage: scripts/ci/build-linux.sh <binary> <profile> [features]
set -euo pipefail

# Multi-arch image index; bump together with the Rust version.
RUST_IMAGE="rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6"

binary=$1
profile=$2
features="portable${3:+,$3}"

env_args=()
case "$(uname -m)" in
    x86_64) target=x86_64-unknown-linux-gnu ;;
    aarch64)
        target=aarch64-unknown-linux-gnu
        # Support up to 64-KiB pages, see https://github.com/sigp/lighthouse/issues/5244
        env_args+=(-e JEMALLOC_SYS_WITH_LG_PAGE=16)
        ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

docker run --rm "${env_args[@]}" -v "$PWD:/lighthouse" -w /lighthouse "$RUST_IMAGE" bash -euc "
    apt-get update
    apt-get install -y --no-install-recommends cmake clang libclang-dev
    cargo build --bin $binary --features '$features' --profile $profile --locked --target $target
    chown -R $(id -u):$(id -g) target
"

echo "Built target/$target/$profile/$binary"
