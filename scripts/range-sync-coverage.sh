#!/usr/bin/env bash
#
# Range sync test coverage for Lighthouse
#
# Usage:
#   ./scripts/range-sync-coverage.sh              # Run all range tests, show summary
#   ./scripts/range-sync-coverage.sh --html        # Also generate HTML report  
#   ./scripts/range-sync-coverage.sh --detail      # Show 0-hit lines in range_sync/ files
#   ./scripts/range-sync-coverage.sh --forks       # Run across all network test forks
#   ./scripts/range-sync-coverage.sh -- <filter>   # Filter to specific test(s)
#
# Examples:
#   ./scripts/range-sync-coverage.sh -- head_chain
#   ./scripts/range-sync-coverage.sh --html --forks
#   ./scripts/range-sync-coverage.sh --detail -- finalized
#
# Prerequisites: cargo-llvm-cov, rustup component add llvm-tools-preview

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

HTML=false
DETAIL=false
ALL_FORKS=false
TEST_FILTER="sync::tests::range"

# Use SSD for builds if available
if [[ -d /mnt/ssd/builds ]]; then
    export CARGO_TARGET_DIR="/mnt/ssd/builds/lighthouse-range-sync-cov"
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --html)   HTML=true; shift ;;
        --detail) DETAIL=true; shift ;;
        --forks)  ALL_FORKS=true; shift ;;
        --)       shift; TEST_FILTER="${1:-sync::tests::range}"; shift || true ;;
        -h|--help) head -15 "$0" | tail -14; exit 0 ;;
        *) echo "Unknown: $1" >&2; exit 1 ;;
    esac
done

if $ALL_FORKS; then
    FORKS=(phase0 electra fulu)
else
    FORKS=(base)
fi

# Grep pattern for range-sync-relevant source files (anchored to network/src/sync/)
SYNC_FILES="network/src/sync/range_sync/\|network/src/sync/batch\.rs\|network/src/sync/manager\.rs\|network/src/sync/block_sidecar\|network/src/sync/network_context\|network/src/sync/peer_sync"

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║     Range Sync Test Coverage         ║"
echo "  ╠══════════════════════════════════════╣"
echo "  ║  Filter: $(printf '%-27s' "$TEST_FILTER")║"
echo "  ║  Forks:  $(printf '%-27s' "${FORKS[*]}")║"
echo "  ╚══════════════════════════════════════╝"
echo ""

# Clean previous data
cargo llvm-cov clean --workspace 2>/dev/null || true

# Run tests for each fork (accumulates profraw data)
for fork in "${FORKS[@]}"; do
    echo "▶ FORK_NAME=$fork"
    FORK_NAME="$fork" cargo llvm-cov test \
        --no-report \
        --features "network/fake_crypto,network/fork_from_env" \
        -p network \
        -- "$TEST_FILTER" \
        2>&1 | grep -E "^(running|test .*\.\.\.|test result)" || true
    echo ""
done

# Summary: extract range-sync-relevant files
echo "┌──────────────────────────────────────────────────────────────────────┐"
echo "│  Coverage Summary                                                   │"
echo "├──────────────────────────────────────────────────────────────────────┤"
printf "│  %-42s  %6s  %6s  %5s  │\n" "File" "Lines" "Missed" "Cover"
echo "├──────────────────────────────────────────────────────────────────────┤"

cargo llvm-cov report --summary-only 2>&1 | grep "$SYNC_FILES" | while IFS= read -r line; do
    # Parse the llvm-cov summary line
    # Format: <filepath>  <regions> <missed_regions> <cover%>  <functions> <missed_functions> <cover%>  <lines> <missed_lines> <cover%>  ...
    filepath=$(echo "$line" | awk '{print $1}')
    
    # Extract just the meaningful part of the path
    shortpath=$(echo "$filepath" | sed 's|.*/network/src/sync/||')
    
    # Extract lines, missed lines, line cover% (columns 14, 15, 16 in the summary)
    # The columns are: regions missed_regions cover% functions missed_functions cover% lines missed_lines cover%
    lines=$(echo "$line" | awk '{print $(NF-5)}')
    missed=$(echo "$line" | awk '{print $(NF-4)}')
    cover=$(echo "$line" | awk '{print $(NF-3)}')
    
    printf "│  %-42s  %6s  %6s  %5s  │\n" "$shortpath" "$lines" "$missed" "$cover"
done

echo "└──────────────────────────────────────────────────────────────────────┘"
echo ""

# Detailed: show uncovered functions in range_sync/
if $DETAIL; then
    echo "┌──────────────────────────────────────────────────────────────────────┐"
    echo "│  Uncovered lines in range_sync/ (0-hit)                             │"
    echo "└──────────────────────────────────────────────────────────────────────┘"
    echo ""
    
    cargo llvm-cov report --text 2>&1 | awk '
        /sync\/range_sync\// {
            current_file = $0
            sub(/^.*sync\/range_sync\//, "range_sync/", current_file)
            sub(/:$/, "", current_file)
            printing = 1
            next
        }
        /^\/.*\.rs:/ { printing = 0; next }
        printing && /\|      0\|.*fn / {
            gsub(/^[[:space:]]+/, "")
            printf "  %-35s %s\n", current_file, $0
        }
    '
    echo ""
fi

# HTML report
if $HTML; then
    OUT_DIR="${REPO_DIR}/coverage-html"
    echo "▶ Generating HTML report → $OUT_DIR/html/index.html"
    cargo llvm-cov report --html --output-dir "$OUT_DIR"
    echo "  Open: file://$OUT_DIR/html/index.html"
    echo ""
fi

echo "Done ✓"
