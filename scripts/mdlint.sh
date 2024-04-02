#! /usr/bin/env bash

#set -e

# use markdownlint-cli docker to check for markdown file s
docker run -v ./book:/workdir ghcr.io/igorshubovych/markdownlint-cli:latest '**/*.md' --ignore node_modules

# exit code
exit_code=$(echo $?)

if [[ $exit_code == 1 ]]; then
    echo "Exiting with error to indicate changes required. To fix, run 'make mdlint' and commit the changes."
    exit $exit_code
else
    echo "All markdown files are properly formatted."
    exit $exit_code
fi
