#! /usr/bin/env bash

#set -e

# use markdownlint-cli to check for markdown files
docker run -v ./book:/workdir ghcr.io/igorshubovych/markdownlint-cli:latest '**/*.md' --ignore node_modules


# exit code
exit_code=$(echo $?)
echo $exit_code

if [[ $exit_code == 0 ]]; then
    echo "All markdown files are properly formatted."
elif [[ $exit_code == 1 ]]; then
    echo "Exiting with exit code $exit_code. Run 'make mdlint' locally and commit the changes."    
    docker run -v ./book:/workdir ghcr.io/igorshubovych/markdownlint-cli:latest '**/*.md' --ignore node_modules --fix
else
    echo "Exiting with exit code >1. Check for the error logs and fix them accordingly."
fi
