#! /usr/bin/env bash

#set -e

# use markdownlint-cli docker to check for markdown file s
docker run -v ./book:/workdir ghcr.io/igorshubovych/markdownlint-cli:latest '**/*.md' --ignore node_modules

# exit code
echo $?
