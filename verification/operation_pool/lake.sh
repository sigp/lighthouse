#!/usr/bin/env bash
#
# Run `lake` for this project, e.g. `./lake.sh build` or `./lake.sh env lean OperationPool/Foo.lean`.
#
# Lake must start inside the Etheorem checkout: the lakefile of Etheorem's `LeanHazmatKzg` package
# finds the BLS library by walking up from the current directory, so a build started here fails to
# link (`unable to find library -l:libleanhazmat_bls.so`). `lake -d` keeps the current directory
# and takes this project as the workspace root. Relative `.lean` file arguments are resolved
# against this directory.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ETHEOREM_DIR="${ETHEOREM_DIR:-$HERE/../deps/etheorem-lean4.35}"

# `~/.cache` is not always writable; keep the Mathlib cache inside the project.
export MATHLIB_CACHE_DIR="${MATHLIB_CACHE_DIR:-$HERE/.lake/mathlib-cache}"

args=()
for arg in "$@"; do
    if [[ "$arg" == *.lean && -f "$HERE/$arg" ]]; then
        args+=("$HERE/$arg")
    else
        args+=("$arg")
    fi
done

cd "$ETHEOREM_DIR"
exec lake -d "$HERE" "${args[@]}"
