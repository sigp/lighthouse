#!/bin/bash

#
# Resets the beacon state genesis time to now.
#

set -Eeuo pipefail

source ./vars.env

NOW=$(date +%s)

lcli \
	change-genesis-time \
	$TESTNET_DIR/genesis.ssz \
	$(date +%s)

echo "Reset genesis time to now ($NOW)"
