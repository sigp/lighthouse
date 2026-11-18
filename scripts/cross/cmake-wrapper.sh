#!/bin/sh
# CMake wrapper used inside `cross` containers (see `Cross.toml`).
#
# LevelDB's CMake probe for `-Wthread-safety` is defeated by the `-w` flag that
# the `cc` crate (>= 1.2.62) emits, so GCC is later handed a Clang-only option.
# Native builds avoid this by using Clang (see `.cargo/config.toml`), but the
# cross images only ship GCC, so pre-seed the probe result instead.
case "$1" in
    --build | --version | -E) exec cmake "$@" ;;
esac
exec cmake -DHAVE_CLANG_THREAD_SAFETY=OFF "$@"
