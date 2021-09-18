#!/usr/bin/env bash

#
# Generates a bootnode enr and saves it in $TESTNET/boot_enr.yaml
# Starts a bootnode from the generated enr.
#

source ./vars.env

echo "Generating bootnode enr"

lcli \
	generate-bootnode-enr \
	--ip 127.0.0.1 \
	--udp-port $BOOTNODE_PORT \
	--tcp-port $BOOTNODE_PORT \
	--genesis-fork-version $GENESIS_FORK_VERSION \
	--output-dir $DATADIR/bootnode

bootnode_enr=`cat $DATADIR/bootnode/enr.dat`
echo "- $bootnode_enr" > $TESTNET_DIR/boot_enr.yaml

echo "Generated bootnode enr and written to $TESTNET_DIR/boot_enr.yaml"

DEBUG_LEVEL=${1:-info}

echo "Starting bootnode"

exec lighthouse boot_node \
    --testnet-dir $TESTNET_DIR \
    --port $BOOTNODE_PORT \
    --listen-address 127.0.0.1 \
	--disable-packet-filter \
    --network-dir $DATADIR/bootnode \
