#!/bin/bash

# Print the tail of all the logs output from local testnet

set -Eeuo pipefail

source ./vars.env

multitail --mergeall "$TESTNET_DIR"/*.log
