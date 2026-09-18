#!/usr/bin/env bash
# Regenerate SlashingProofs/Generated.lean from ../src/attestation_rules.rs.
#
# Needs Charon and Aeneas built at the pinned revisions. See README.md for the build steps
# and .github/workflows/proofs.yml for the pins. Point CHARON and AENEAS at the binaries if
# they are not on PATH. The Aeneas binary is src/_build/default/main.exe in its checkout.
set -euo pipefail

CHARON=${CHARON:-charon}
AENEAS=${AENEAS:-aeneas}

proofs_dir=$(cd "$(dirname "$0")" && pwd)
crate_dir=$(dirname "$proofs_dir")
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

# `-- --lib`: without it Charon picks up src/bin/test_generator.rs and emits a file with
# opaque bodies and no error.
(cd "$crate_dir" && "$CHARON" cargo --preset=aeneas \
  --start-from slashing_protection::attestation_rules::check_attestation \
  --dest-file "$out/pure.llbc" -- --lib)

# Aeneas names the output after the llbc file.
"$AENEAS" -backend lean "$out/pure.llbc" -dest "$out"
mv "$out/Pure.lean" "$proofs_dir/SlashingProofs/Generated.lean"
echo "wrote $proofs_dir/SlashingProofs/Generated.lean"
