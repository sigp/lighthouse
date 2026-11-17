#!/usr/bin/env bash
#
# Regenerate the Lean translation of the voluntary-exit packing cores.
#
#   Rust --Charon--> LLBC --Aeneas--> {OperationPool,StateProcessing}/{Types,Funs}.lean
#
# Two crates hold the cores, and each is extracted from its own crate:
#
#   operation_pool    filter_limit_operations, insert_proposer_slashing_indices,
#                     insert_common_attesting_indices
#   state_processing  verify_exit_validator_checks, verify_exit_pending_balance
#
# One run rooted in `operation_pool` cannot cover both: Aeneas emits a function of another crate
# only when an extracted body calls it, and nothing extracted calls the `verify_exit` cores.
#
# Requires the Aeneas release for commit 5a392f4b (Lean v4.35.0), which bundles the `aeneas` and
# `charon` binaries and the Lean library. Point `AENEAS_DIR` at the unpacked release.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
AENEAS_DIR="${AENEAS_DIR:-$HERE/../deps/aeneas-release-5a392f4}"

mkdir -p "$HERE/.lake"

# Run Charon on the crate in directory $1, writing LLBC to $2. The remaining arguments select
# what to extract.
#
# Charon builds the dependencies with its own pinned nightly, so it gets its own target directory.
#
# `--sysroot default`: Charon's default (Miri) sysroot is not needed, because no standard library
# body is translated.
#
# `--opaque crate`: everything in the crate stays opaque except what `--include` adds back, and
# nothing generic over `EthSpec` is reachable from the entry points.
#
# Feature unification across the workspace: these crates do not build on their own, because
# `eth2_network_config` uses `enr` items behind features that only other workspace members
# enable. Unifying features as a whole-workspace build does avoids that. Charon runs a nightly
# cargo, so the unstable flag is available.
run_charon() {
    local crate_dir="$1" llbc="$2"
    shift 2
    (
        cd "$REPO/$crate_dir"
        CARGO_TARGET_DIR="${CHARON_TARGET_DIR:-$REPO/target/charon-454586e9}" \
        CARGO_RESOLVER_FEATURE_UNIFICATION=workspace \
            "$AENEAS_DIR/charon" cargo \
            --preset=aeneas \
            --sysroot default \
            --opaque crate \
            "$@" \
            --dest-file "$llbc" \
            -- --lib -Zfeature-unification
    )
}

# Run Aeneas on the LLBC file $1, writing the Lean files to directory $2.
#
# `-loops-to-rec`: translate loops to recursive functions, the form the proofs unfold.
# `-use-lean-modules false`: plain files, so the hand-written external models can import them.
run_aeneas() {
    local llbc="$1" dest="$2"
    "$AENEAS_DIR/aeneas" -backend lean "$llbc" \
        -dest "$dest" \
        -split-files \
        -loops-to-rec \
        -filter-trait-methods \
        -use-lean-modules false \
        -no-progress-bar
}

run_charon beacon_node/operation_pool "$HERE/.lake/operation_pool.llbc" \
    --start-from 'crate::filter_limit_operations' \
    --start-from 'crate::insert_proposer_slashing_indices' \
    --start-from 'crate::insert_common_attesting_indices' \
    --include 'crate::filter_limit_operations' \
    --include 'crate::insert_proposer_slashing_indices' \
    --include 'crate::insert_common_attesting_indices'
run_aeneas "$HERE/.lake/operation_pool.llbc" "$HERE/OperationPool"

VERIFY_EXIT='crate::per_block_processing::verify_exit'
run_charon consensus/state_processing "$HERE/.lake/state_processing.llbc" \
    --start-from "$VERIFY_EXIT::verify_exit_validator_checks" \
    --start-from "$VERIFY_EXIT::verify_exit_pending_balance" \
    --include "$VERIFY_EXIT" \
    --include 'crate::per_block_processing::errors' \
    --include 'types::validator::validator' \
    --include 'types::core::slot_epoch' \
    --opaque 'types::state::beacon_state::BeaconStateError' \
    --opaque 'crate::per_block_processing::signature_sets::Error' \
    --opaque 'crate::consensus_context::ContextError' \
    --opaque 'ssz_types::Error' \
    --opaque 'ssz::BitfieldError'
run_aeneas "$HERE/.lake/state_processing.llbc" "$HERE/StateProcessing"
