#!/bin/bash

#
# Resets the beacon state genesis time to now.
#

source ./vars.env

NOW=$(date +%s)

lcli \
	change-genesis-time \
	$TESTNET_DIR/genesis.ssz \
	$(date +%s)

echo "Reset genesis time to now ($NOW)"
