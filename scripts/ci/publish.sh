#!/usr/bin/env bash

# Based on: https://github.com/tokio-rs/tokio/blob/master/bin/publish

set -e
USAGE="Publish a new release of a lighthouse crate
USAGE:
    $(basename "$0") [OPTIONS] [CRATE_PATH] [CRATE] [TAG_NAME]
OPTIONS:
    -v, --verbose       Use verbose Cargo output
    -d, --dry-run       Perform a dry run (do not publish the release)
    -h, --help          Show this help text and exit
        --allow-dirty   Allow dirty working directories to be packaged"

DRY_RUN=""
DIRTY=""
VERBOSE=""

verify() {
    echo "Verifying if $CRATE v$VERSION can be released"

    # `cargo pkgid` has different formats based on whether the `[lib]` name and `[package]` name
    # are the same, necessitating the following logic.
    #
    # Try to match on `#`
    ACTUAL=$(cargo pkgid | sed -n 's/.*#\([0-9]\)/\1/p' )
    if [ -z "$ACTUAL" ]; then
        # Match on the final `:`
        ACTUAL=$(cargo pkgid | sed -n 's/.*:\(.*\)/\1/p')
    fi

    if [ "$ACTUAL" != "$VERSION" ]; then
        echo "expected to release version $VERSION, but Cargo.toml contained $ACTUAL"
        exit 1
    fi
}

release() {
    echo  "Releasing $CRATE v$VERSION"
    cargo package $VERBOSE $DIRTY
    cargo publish $VERBOSE $DRY_RUN $DIRTY
}

while [[ $# -gt 0 ]]
do

case "$1" in
    -h|--help)
    echo "$USAGE"
    exit 0
    ;;
    -v|--verbose)
    VERBOSE="--verbose"
    set +x
    shift
    ;;
    --allow-dirty)
    DIRTY="--allow-dirty"
    shift
    ;;
    -d|--dry-run)
    DRY_RUN="--dry-run"
    shift
    ;;
    -*)
    echo "unknown flag \"$1\""
    echo "$USAGE"
    exit 1
    ;;
    *) # crate, crate path, or version
    if [ -z "$CRATE_PATH" ]; then
        CRATE_PATH="$1"
    elif [ -z "$CRATE" ]; then
        CRATE="$1"
    elif [ -z "$TAG_NAME" ]; then
        TAG_NAME="$1"
        VERSION=$(sed -e 's#.*-v\([0-9]\)#\1#' <<< "$TAG_NAME")
    else
        echo "unknown positional argument \"$1\""
        echo "$USAGE"
        exit 1
    fi
    shift
    ;;
esac
done
# set -- "${POSITIONAL[@]}"

if [ -z "$VERSION" ]; then
    echo "no version specified!"
    HELP=1
fi

if [ -z "$CRATE" ]; then
    echo "no crate specified!"
    HELP=1
fi

if [ -n "$HELP" ]; then
    echo "$USAGE"
    exit 1
fi

if [ -d "$CRATE_PATH" ]; then
    (cd "$CRATE_PATH" && verify && release )
else
    echo "no such dir \"$CRATE_PATH\""
    exit 1
fi
