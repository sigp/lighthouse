#! /usr/bin/env bash

# IMPORTANT
# This script should NOT be run directly.
# Run `make mdlint` from the root of the repository instead.

# use markdownlint-cli to check for markdown files
docker run --rm -v ./book:/workdir ghcr.io/igorshubovych/markdownlint-cli:latest '**/*.md' --ignore node_modules

# exit code
exit_code=$(echo $?)

if [[ $exit_code == 0 ]]; then
    echo "All markdown files are properly formatted."
    exit 0
elif [[ $exit_code == 1 ]]; then
    echo "Exiting with errors. Run 'make mdlint' locally and commit the changes. Note that not all errors can be fixed automatically, if there are still errors after running 'make mdlint', look for the errors and fix manually."    
    docker run --rm -v ./book:/workdir ghcr.io/igorshubovych/markdownlint-cli:latest '**/*.md' --ignore node_modules --fix
    exit 1
else
    echo "Exiting with exit code >1. Check for the error logs and fix them accordingly."
    exit 1
fi