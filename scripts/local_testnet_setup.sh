#!/bin/bash

#
# Produces a testnet specification and a genesis state where the genesis time
# is now.
#
# Optionally, supply an integer as the first argument to override the default
# validator count of 1024.
#

TESTNET_DIR=~/.lighthouse/local-testnet/testnet
VALIDATOR_COUNT=${1:-1024}

lcli \
	--spec mainnet \
	new-testnet \
	--deposit-contract-address 0000000000000000000000000000000000000000 \
	--testnet-dir $TESTNET_DIR \
	--min-genesis-active-validator-count $VALIDATOR_COUNT \
	--force

echo Created tesnet directory at $TESTNET_DIR
echo "Building genesis state... (this might take a while)"

lcli \
	--spec mainnet \
	interop-genesis \
	--testnet-dir $TESTNET_DIR \
	$VALIDATOR_COUNT

echo Created genesis state in $TESTNET_DIR

echo $VALIDATOR_COUNT > $TESTNET_DIR/validator_count.txt
