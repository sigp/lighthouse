#!/usr/bin/env bash

set -euf -o pipefail

YAML=$1
NEEDS=$2
SUCCESS_JOB=$3

yq '... comments="" | .jobs | map(. | key)' < "$YAML" | grep -v "$SUCCESS_JOB" | sort > all_jobs.txt
echo "$NEEDS" | jq -r 'keys | join(",")' | tr "," "\n" | sort > dep_jobs.txt
diff all_jobs.txt dep_jobs.txt
rm all_jobs.txt dep_jobs.txt
