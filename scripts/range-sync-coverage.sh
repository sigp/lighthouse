#!/bin/bash
# Aggregate range sync test coverage across all forks
# Usage: ./scripts/range-sync-coverage.sh [--html]
set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

TARGET_DIR="${CARGO_TARGET_DIR:-/mnt/ssd/builds/lighthouse-range-sync-tests}"
FORKS=(base altair bellatrix capella deneb electra fulu)
LCOV_DIR="/tmp/range-cov-forks"
MERGED="/tmp/range-cov-merged.lcov"

rm -rf "$LCOV_DIR"
mkdir -p "$LCOV_DIR"

echo "=== Running coverage for each fork ==="
for fork in "${FORKS[@]}"; do
    echo "--- $fork ---"
    CARGO_TARGET_DIR="$TARGET_DIR" FORK_NAME="$fork" \
        cargo llvm-cov --features "network/fake_crypto,network/fork_from_env" \
        -p network --lib --lcov --output-path "$LCOV_DIR/$fork.lcov" \
        -- "sync::tests::range" 2>&1 | grep -E "test result|running"
done

echo ""
echo "=== Merging lcov files ==="

# Merge all lcov files: for each source file, take max hit count per line
python3 - "$LCOV_DIR" "$MERGED" << 'PYEOF'
import sys, os, glob
from collections import defaultdict

lcov_dir = sys.argv[1]
output = sys.argv[2]

# Parse all lcov files: file -> line -> max hits
coverage = defaultdict(lambda: defaultdict(int))
fn_coverage = defaultdict(lambda: defaultdict(int))
current_sf = None

for lcov_file in sorted(glob.glob(os.path.join(lcov_dir, "*.lcov"))):
    with open(lcov_file) as f:
        for line in f:
            line = line.strip()
            if line.startswith("SF:"):
                current_sf = line[3:]
            elif line.startswith("DA:") and current_sf:
                parts = line[3:].split(",")
                lineno = int(parts[0])
                hits = int(parts[1])
                coverage[current_sf][lineno] = max(coverage[current_sf][lineno], hits)
            elif line.startswith("FNDA:") and current_sf:
                parts = line[5:].split(",", 1)
                hits = int(parts[0])
                fn_name = parts[1]
                fn_coverage[current_sf][fn_name] = max(fn_coverage[current_sf][fn_name], hits)

# Write merged lcov
with open(output, "w") as f:
    for sf in sorted(coverage.keys()):
        f.write(f"SF:{sf}\n")
        for fn_name, hits in sorted(fn_coverage.get(sf, {}).items()):
            f.write(f"FNDA:{hits},{fn_name}\n")
        for lineno in sorted(coverage[sf].keys()):
            f.write(f"DA:{lineno},{coverage[sf][lineno]}\n")
        total = len(coverage[sf])
        covered = sum(1 for h in coverage[sf].values() if h > 0)
        f.write(f"LH:{covered}\n")
        f.write(f"LF:{total}\n")
        f.write("end_of_record\n")

print(f"Merged {len(glob.glob(os.path.join(lcov_dir, '*.lcov')))} lcov files -> {output}")
PYEOF

echo ""
echo "=== Range sync coverage (merged across all forks) ==="

# Extract and display range sync files
python3 - "$MERGED" << 'PYEOF'
import sys
from collections import defaultdict

current_sf = None
files = {}  # short_name -> (total_lines, covered_lines)
lines = defaultdict(dict)

with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if line.startswith("SF:"):
            current_sf = line[3:]
        elif line.startswith("DA:") and current_sf:
            parts = line[3:].split(",")
            lineno, hits = int(parts[0]), int(parts[1])
            lines[current_sf][lineno] = hits

# Filter to range sync files
targets = [
    "range_sync/chain.rs",
    "range_sync/chain_collection.rs", 
    "range_sync/range.rs",
    "requests/blocks_by_range.rs",
    "requests/blobs_by_range.rs",
    "requests/data_columns_by_range.rs",
]

print(f"{'File':<45} {'Lines':>6} {'Covered':>8} {'Missed':>7} {'Coverage':>9}")
print("-" * 80)

total_all = 0
covered_all = 0

for sf in sorted(lines.keys()):
    short = sf.split("sync/")[-1] if "sync/" in sf else sf.split("/")[-1]
    if not any(t in sf for t in targets):
        continue
    total = len(lines[sf])
    covered = sum(1 for h in lines[sf].values() if h > 0)
    missed = total - covered
    pct = covered / total * 100 if total > 0 else 0
    total_all += total
    covered_all += covered
    print(f"{short:<45} {total:>6} {covered:>8} {missed:>7} {pct:>8.1f}%")

print("-" * 80)
pct_all = covered_all / total_all * 100 if total_all > 0 else 0
print(f"{'TOTAL':<45} {total_all:>6} {covered_all:>8} {total_all - covered_all:>7} {pct_all:>8.1f}%")
PYEOF

if [ "$1" = "--html" ]; then
    echo ""
    echo "=== Generating HTML report ==="
    genhtml "$MERGED" -o /tmp/range-cov-html --ignore-errors source 2>/dev/null
    echo "HTML report: /tmp/range-cov-html/index.html"
fi
