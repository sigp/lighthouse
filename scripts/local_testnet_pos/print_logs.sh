#!/bin/bash

# Print the tail of all the logs output from local testnet

set -Eeuo pipefail

source ./vars.env

for f in "$TESTNET_DIR"/*.log
do
  [[ -e "$f" ]] || break # handle the case of no *.log files
  echo "============================================================================="
  echo "$f"
  echo "============================================================================="
  tail "$f"
  echo ""
done
