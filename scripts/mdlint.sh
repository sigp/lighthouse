#! /usr/bin/env bash

#set -e

# use markdownlint-cli docker to check for markdown file s
docker run -v ./book:/workdir ghcr.io/igorshubovych/markdownlint-cli:latest '**/*.md' --ignore node_modules --fix --disable MD013 MD033 MD040 MD029 MD055

# exit code
exit_code=$(echo $?)
echo $exit_code

if [[ $exit_code == 0 ]]; then
    echo "All markdown files are properly formatted."
    exit $exit_code
else
    echo "Exiting with exit code $exit_code. If the exit code is 1, run 'make mdlint' and commit the changes."
    exit $exit_code
fi
