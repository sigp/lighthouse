#!/usr/bin/env bash

#
# Generates a bootnode enr and saves it in $TESTNET/boot_enr.yaml
# Starts a bootnode from the generated enr.
#

set -Eeuo pipefail

source ./vars.env

DEBUG_LEVEL=${1:-info}

echo "Starting bootnode"

exec lighthouse \
    --debug-level $DEBUG_LEVEL \
    boot_node \
    --testnet-dir $TESTNET_DIR \
    --port $BOOTNODE_PORT \
    --listen-address 127.0.0.1 \
	--disable-packet-filter \
    --network-dir $DATADIR/bootnode \
