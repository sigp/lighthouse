#!/usr/bin/env bash

check_version () {
    # Check whether the crate has changed.
    echo "Checking $1"
    git diff --quiet unstable $1
    DIFF_EXIT_CODE=$?

    if [[ $DIFF_EXIT_CODE -eq 1 ]]
    then
        # If there have been changes, ensure the version has been updated.
        # This does NOT verify if the version was updated correctly.
        echo "  Changes detected!"
        git diff unstable $1/Cargo.toml | grep -q +version
        VERSION_EXIT_CODE=$?

        if [[ $VERSION_EXIT_CODE -eq 1 ]]
        then
            # If the version was not updated, fail.
            echo "  The version has not been updated! Update the version and publish the crate!"
            exit 1
        else
            # If the version was updated, verify the new version exists on crates.io.
            echo "  The version has changed. Verifying the detected version exists on crates.io."
            VERSION=$(cargo pkgid --manifest-path $1/Cargo.toml | sed  -n -e 's/^.*#//p')
            echo "  Local version: $VERSION"
            cargo search $2 | grep -q '$2 = "$VERSION"'
            CRATES_EXIT_CODE=$?
            if [[ $CRATES_EXIT_CODE -eq 1 ]]
            then
                echo "  $VERSION not found on crates.io."
                exit 1
            else
                echo "  $VERSION found on crates.io."
            fi
        fi
    else
        echo "  No changes detected."
    fi
}

check_version ../../consensus/tree_hash tree_hash
check_version ../../consensus/tree_hash_derive tree_hash_derive
check_version ../../consensus/ssz ssz
check_version ../../consensus/ssz_derive ssz_derive
check_version ../../consensus/ssz_types ssz_types
check_version ../../crypto/eth2_hashing eth2_hashing
