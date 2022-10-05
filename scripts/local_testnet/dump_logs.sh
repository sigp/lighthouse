#!/usr/bin/env bash

# Print all the logs output from local testnet

set -Eeuo pipefail

source ./vars.env

for f in "$TESTNET_DIR"/*.log
do
  [[ -e "$f" ]] || break # handle the case of no *.log files
  echo "============================================================================="
  echo "$f"
  echo "============================================================================="
  cat "$f"
  echo ""
done
