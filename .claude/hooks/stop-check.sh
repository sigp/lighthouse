#!/bin/bash
# Block agent from finishing if code doesn't compile.
# Only runs if .rs files were actually modified.

set -uo pipefail

MODIFIED_RS=$(git diff --name-only HEAD -- '*.rs' 2>/dev/null | head -1)
if [ -z "$MODIFIED_RS" ]; then
    exit 0 # No Rust files changed, allow stop
fi

# Run cargo fmt (fast, fixes formatting silently)
cargo fmt --all --quiet 2>/dev/null

# Run cargo check (the real test)
OUTPUT=$(cargo check 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "cargo check failed. Fix compilation errors before finishing:" >&2
    echo "$OUTPUT" | tail -50 >&2
    exit 2 # Block stop
fi

exit 0
