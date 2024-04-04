#! /usr/bin/env bash

#set -e

# use markdownlint-cli docker to check for markdown file s
docker run -v ./book:/workdir ghcr.io/igorshubovych/markdownlint-cli:latest '**/*.md' --ignore node_modules --fix --disable MD013 MD033 MD040 MD029 MD055 MD024 MD028 MD001 MD045 MD036 MD025 MD041

# exit code
exit_code=$(echo $?)

if [[ $exit_code == 1 ]]; then
    echo "Exiting with error to indicate changes required. To fix, run 'make mdlint' and commit the changes."
    exit $exit_code
else
    echo "All markdown files are properly formatted."
    exit $exit_code
fi
