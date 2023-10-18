#!/usr/bin/env bash

set -Eeuo pipefail

source ./vars.env

genesis_file=$1

# Update future hardforks time in the EL genesis file based on the CL genesis time
GENESIS_TIME=$(lcli pretty-ssz --spec $SPEC_PRESET --testnet-dir $TESTNET_DIR BeaconState $TESTNET_DIR/genesis.ssz | jq | grep -Po 'genesis_time": "\K.*\d')
echo $GENESIS_TIME
CAPELLA_TIME=$((GENESIS_TIME + (CAPELLA_FORK_EPOCH * 32 * SECONDS_PER_SLOT)))
echo $CAPELLA_TIME
sed -i 's/"shanghaiTime".*$/"shanghaiTime": '"$CAPELLA_TIME"',/g' $genesis_file
