#!/usr/bin/env bash
# Check that $SUCCESS_JOB depends on all other jobs in the given $YAML

set -euf -o pipefail

YAML=$1
SUCCESS_JOB=$2

yq '... comments="" | .jobs | map(. | key) | .[]' < "$YAML" | grep -v "$SUCCESS_JOB" | sort > all_jobs.txt
yq "... comments=\"\" | .jobs.$SUCCESS_JOB.needs[]" < "$YAML" | grep -v "$SUCCESS_JOB" | sort > dep_jobs.txt
diff all_jobs.txt dep_jobs.txt || (echo "COMPLETENESS CHECK FAILED" && exit 1)
rm all_jobs.txt dep_jobs.txt
echo "COMPLETENESS CHECK PASSED"
