#!/usr/bin/env bash
# scripts/compliance-fc-report.sh
#
# Run the consensus-specs fork-choice compliance suites against this branch and
# print an aggregated pass/fail summary. Test-only — no production code changes.
# See --help for data-source options.

set -uo pipefail

# ---- defaults (overridable via flags or env) ---------------------------------

PRESET="${COMPLIANCE_FC_PRESET:-minimal}"
DIR="${COMPLIANCE_FC_DIR:-}"
TARBALL="${COMPLIANCE_FC_TARBALL:-}"
URL="${COMPLIANCE_FC_URL:-}"
RUN_ID="${COMPLIANCE_FC_RUN_ID:-}"
CACHE_ROOT="${COMPLIANCE_FC_CACHE_DIR:-/var/tmp/compliance_fc_cache}"
SUITE_FILTER="${COMPLIANCE_FC_SUITE:-}"

ALL_SUITES=(
  attester_slashing_test
  block_cover_test
  block_tree_test
  block_weight_test
  invalid_message_test
  shuffling_test
)
ALL_FORKS=(fulu gloas)

usage() {
  cat <<'EOF'
Run the fork-choice compliance suites and print a pass/fail report.

USAGE
  scripts/compliance-fc-report.sh [options] [-- cargo_args...]

DATA SOURCE (first non-empty wins)
  --dir PATH        Use a pre-extracted tree at PATH (must contain tests/).
  --tarball PATH    Use a local .tar.gz; extracted to cache on first use.
  --url URL         Download tarball via curl; cached + extracted.
  --run-id ID       Pin to a consensus-specs run id; download via gh.
  (default)         Resolve the latest successful run of the consensus-specs
                    "Compliance Tests" workflow on master via gh.

OTHER OPTIONS
  --preset NAME     Preset: minimal or mainnet (default: minimal).
                    Only minimal currently ships compliance data.
  --suite NAME      Run only one suite (e.g. block_tree_test). Repeatable
                    via comma-separated list.
  --cache-dir PATH  Cache root (default: /var/tmp/compliance_fc_cache).
  -h, --help        Print this help and exit.

ENVIRONMENT (each flag has a matching env var; the flag wins if both are set)
  COMPLIANCE_FC_PRESET, COMPLIANCE_FC_DIR, COMPLIANCE_FC_TARBALL,
  COMPLIANCE_FC_URL, COMPLIANCE_FC_RUN_ID, COMPLIANCE_FC_CACHE_DIR,
  COMPLIANCE_FC_SUITE
  GITHUB_TOKEN      Required only for --run-id and the default auto-fetch path
                    (GitHub Actions artifact downloads return 403 to anonymous
                    requests, even on public repos). Use --tarball or --url to
                    avoid the token entirely.

Anything after '--' is forwarded verbatim to 'cargo test'.

EXAMPLES
  # Auto-fetch latest (needs token)
  GITHUB_TOKEN=... scripts/compliance-fc-report.sh

  # Use a manually-downloaded tarball — no token, no gh
  scripts/compliance-fc-report.sh --tarball ~/Downloads/small.tar.gz

  # Pull the artifact through a public mirror via curl — no token
  scripts/compliance-fc-report.sh --url https://example.org/small.tar.gz

  # Re-use an already-extracted tree
  scripts/compliance-fc-report.sh --dir /var/tmp/compliance_fc_root

  # Run only one suite
  scripts/compliance-fc-report.sh --tarball ./small.tar.gz --suite block_tree_test
EOF
}

# ---- argument parsing --------------------------------------------------------

while (( $# > 0 )); do
  case "$1" in
    --preset)    PRESET="$2"; shift 2 ;;
    --dir)       DIR="$2"; shift 2 ;;
    --tarball)   TARBALL="$2"; shift 2 ;;
    --url)       URL="$2"; shift 2 ;;
    --run-id)    RUN_ID="$2"; shift 2 ;;
    --suite)     SUITE_FILTER="$2"; shift 2 ;;
    --cache-dir) CACHE_ROOT="$2"; shift 2 ;;
    -h|--help)   usage; exit 0 ;;
    --)          shift; break ;;
    -*)          echo "error: unknown option: $1" >&2; usage >&2; exit 1 ;;
    *)           echo "error: unexpected positional arg: $1 (use -- to forward to cargo)" >&2; exit 1 ;;
  esac
done
CARGO_EXTRA_ARGS=("$@")

case "$PRESET" in
  minimal|mainnet) ;;
  *) echo "error: --preset must be minimal or mainnet (got: $PRESET)" >&2; exit 1 ;;
esac

if [[ "$PRESET" == "mainnet" ]]; then
  echo "error: the consensus-specs Compliance Tests workflow ships only minimal preset" >&2
  exit 1
fi

# Resolve repo root (script may be invoked from any cwd).
REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)
TESTS_DST="${REPO_ROOT}/testing/ef_tests/consensus-spec-tests"

# ---- data source resolution --------------------------------------------------

extract_into() {
  # extract_into <tarball> <cache-key>; sets DIR to the cache target.
  local tarball="$1" key="$2" target="$CACHE_ROOT/$key"
  if [[ -d "$target/tests" ]]; then
    echo "Reusing cached compliance data at $target"
  else
    mkdir -p "$target"
    echo "Extracting $tarball -> $target..."
    tar -xzf "$tarball" -C "$target"
  fi
  DIR="$target"
}

require_token() {
  : "${GITHUB_TOKEN:?required for gh artifact download (use --tarball or --url to avoid)}"
  command -v gh >/dev/null || {
    echo "error: gh CLI required for auto-fetch (brew install gh, or use --tarball/--url/--dir)" >&2
    exit 1
  }
}

if [[ -n "$DIR" ]]; then
  : # use as-is
elif [[ -n "$TARBALL" ]]; then
  [[ -f "$TARBALL" ]] || { echo "error: tarball not found: $TARBALL" >&2; exit 1; }
  key="tarball-$(shasum -a 256 "$TARBALL" | awk '{print $1}')"
  extract_into "$TARBALL" "$key"
elif [[ -n "$URL" ]]; then
  command -v curl >/dev/null || { echo "error: curl required for --url" >&2; exit 1; }
  key="url-$(printf '%s' "$URL" | shasum -a 256 | awk '{print $1}')"
  target="$CACHE_ROOT/$key"
  if [[ -d "$target/tests" ]]; then
    echo "Reusing cached compliance data at $target"
    DIR="$target"
  else
    tmpfile="$(mktemp)"
    trap 'rm -f "$tmpfile"' EXIT
    echo "Downloading $URL..."
    curl -fL --output "$tmpfile" "$URL"
    extract_into "$tmpfile" "$key"
    rm -f "$tmpfile"
    trap - EXIT
  fi
elif [[ -n "$RUN_ID" || -n "${GITHUB_TOKEN:-}" ]]; then
  require_token
  if [[ -z "$RUN_ID" ]]; then
    # 261432977 = "Compliance Tests" workflow on ethereum/consensus-specs
    echo "Resolving latest successful Compliance Tests run on master..."
    RUN_ID=$(gh api \
      'repos/ethereum/consensus-specs/actions/workflows/261432977/runs?branch=master&status=success&per_page=1' \
      --jq '.workflow_runs[0].id // empty')
    [[ -n "$RUN_ID" ]] || { echo "error: no successful runs found" >&2; exit 1; }
    echo "Latest run: $RUN_ID"
  fi
  target="$CACHE_ROOT/run-$RUN_ID"
  if [[ -d "$target/tests" ]]; then
    echo "Reusing cached compliance data at $target"
    DIR="$target"
  else
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT
    echo "Downloading artifact from run $RUN_ID..."
    gh run download "$RUN_ID" --repo ethereum/consensus-specs --name small.tar.gz --dir "$tmpdir"
    [[ -f "$tmpdir/small.tar.gz" ]] || { echo "error: small.tar.gz not present in artifact" >&2; exit 1; }
    extract_into "$tmpdir/small.tar.gz" "run-$RUN_ID"
    rm -rf "$tmpdir"
    trap - EXIT
  fi
else
  echo "error: no data source given." >&2
  echo "       Pass --dir / --tarball / --url / --run-id, or set GITHUB_TOKEN" >&2
  echo "       to auto-fetch the latest run. See --help for details." >&2
  exit 1
fi

if [[ ! -d "$DIR/tests/$PRESET" ]]; then
  echo "error: no $PRESET-preset compliance data at $DIR/tests/$PRESET" >&2
  exit 1
fi

# ---- stage data into the ef_tests crate --------------------------------------
#
# `testing/ef_tests` resolves test paths from `env!("CARGO_MANIFEST_DIR")` at
# compile time, so the corpus must live under the crate. We copy only the
# fork_choice_compliance subtree to avoid clobbering any existing test corpus.

echo "Staging compliance data under ${TESTS_DST}/tests/${PRESET}/..."
mkdir -p "${TESTS_DST}/tests/${PRESET}"
for fork in "${ALL_FORKS[@]}"; do
  src="${DIR}/tests/${PRESET}/${fork}/fork_choice_compliance"
  if [[ ! -d "$src" ]]; then
    echo "  skip ${fork}: no fork_choice_compliance directory in source"
    continue
  fi
  dst="${TESTS_DST}/tests/${PRESET}/${fork}"
  mkdir -p "$dst"
  rm -rf "${dst}/fork_choice_compliance"
  cp -R "$src" "${dst}/fork_choice_compliance"
done

# ---- run ---------------------------------------------------------------------

# Resolve which suites to run.
SUITES=()
if [[ -n "$SUITE_FILTER" ]]; then
  IFS=',' read -ra SUITES <<< "$SUITE_FILTER"
else
  SUITES=("${ALL_SUITES[@]}")
fi

LOGS_DIR="${COMPLIANCE_FC_LOGS_DIR:-/tmp/compliance_fc_logs}"
rm -rf "$LOGS_DIR"
mkdir -p "$LOGS_DIR"

declare -a results=()  # tab-separated rows: handler\tfork\ttotal\tpass\tfail\tskipped

run_one() {
  local handler="$1" fork="$2"
  local fn="fork_choice_compliance_${handler}_${fork}"
  local log="${LOGS_DIR}/${handler}_${fork}.log"
  echo "==> ${fn}"

  RUST_MIN_STACK=8388608 \
    cargo test --release --features "ef_tests,fake_crypto" \
      -p ef_tests --test tests "$fn" \
      ${CARGO_EXTRA_ARGS[@]+"${CARGO_EXTRA_ARGS[@]}"} \
      -- --nocapture --include-ignored \
      > "$log" 2>&1 || true

  # Parse the harness summary. Two cases:
  #   1. "N tests, F failed, K skipped (known failure), B skipped (bls), P passed."
  #   2. "Passed N tests in <path>" (when nothing failed at all).
  local total=0 pass=0 fail=0 skip=0
  local summary
  summary=$(grep -E "^[0-9]+ tests, " "$log" | head -1)
  if [[ -n "$summary" ]]; then
    # shellcheck disable=SC2001
    read -r total fail kfail bls pass <<< \
      "$(sed -E 's/^([0-9]+) tests, ([0-9]+) failed, ([0-9]+) skipped \(known failure\), ([0-9]+) skipped \(bls\), ([0-9]+) passed.*/\1 \2 \3 \4 \5/' <<< "$summary")"
    skip=$((kfail + bls))
  else
    summary=$(grep -E "^Passed [0-9]+ tests in " "$log" | head -1)
    if [[ -n "$summary" ]]; then
      total=$(awk '{print $2}' <<< "$summary")
      pass="$total"
    else
      total=0; pass=0; fail=0; skip=0
    fi
  fi

  results+=("$(printf '%s\t%s\t%d\t%d\t%d\t%d' "$handler" "$fork" "$total" "$pass" "$fail" "$skip")")
}

for handler in "${SUITES[@]}"; do
  for fork in "${ALL_FORKS[@]}"; do
    run_one "$handler" "$fork"
  done
done

# ---- aggregate report --------------------------------------------------------

echo
echo "=== Fork-choice compliance report ($PRESET) ==="
printf '%-32s %-8s %8s %8s %8s %8s\n' "Suite" "Fork" "Total" "Pass" "Fail" "Skip"
printf '%-32s %-8s %8s %8s %8s %8s\n' "-----" "----" "-----" "----" "----" "----"
tt=0; tp=0; tf=0; ts=0
for row in "${results[@]}"; do
  IFS=$'\t' read -r handler fork total pass fail skip <<< "$row"
  printf '%-32s %-8s %8d %8d %8d %8d\n' "$handler" "$fork" "$total" "$pass" "$fail" "$skip"
  tt=$((tt+total)); tp=$((tp+pass)); tf=$((tf+fail)); ts=$((ts+skip))
done
printf '%-32s %-8s %8s %8s %8s %8s\n' "-----" "----" "-----" "----" "----" "----"
printf '%-32s %-8s %8d %8d %8d %8d\n' "TOTAL" "" "$tt" "$tp" "$tf" "$ts"

echo
echo "Per-suite logs (look here for failure details):"
echo "  ${LOGS_DIR}/<suite>_<fork>.log"

# Exit non-zero if any case failed.
(( tf == 0 ))
