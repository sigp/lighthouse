#!/usr/bin/env bash

#
# Produces a testnet specification and a genesis state where the genesis time
# is now.
#

source ./vars.env

lcli \
	deploy-deposit-contract \
	--eth1-http http://localhost:8545 \
	--confirmations 1 \
	--validator-count $VALIDATOR_COUNT

lcli \
	--spec mainnet \
	new-testnet \
	--deposit-contract-address $DEPOSIT_CONTRACT_ADDRESS \
	--testnet-dir $TESTNET_DIR \
	--min-genesis-active-validator-count $VALIDATOR_COUNT \
	--genesis-delay $GENESIS_DELAY
	--genesis-fork-version $GENESIS_FORK_VERSION \
	--eth1-id 4242 \
	--force

echo Specification generated at $TESTNET_DIR.
echo "Generating $VALIDATOR_COUNT validators concurrently... (this may take a while)"

lcli \
	insecure-validators \
	--count $VALIDATOR_COUNT \
	--base-dir $DATADIR \
	--node-count $BEACON_NODE_COUNT

echo Validators generated at $VALIDATORS_DIR with keystore passwords at $SECRETS_DIR.
echo "Building genesis state... (this might take a while)"

lcli \
	--spec mainnet \
	interop-genesis \
	--testnet-dir $TESTNET_DIR \
	$VALIDATOR_COUNT

echo Created genesis state in $TESTNET_DIR
