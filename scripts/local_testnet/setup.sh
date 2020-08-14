#!/usr/bin/env bash

#
# Produces a testnet specification and a genesis state where the genesis time
# is now.
#

source ./vars.env

lcli \
	--spec mainnet \
	new-testnet \
	--deposit-contract-address 0000000000000000000000000000000000000000 \
	--testnet-dir $TESTNET_DIR \
	--min-genesis-active-validator-count $VALIDATOR_COUNT \
	--force

echo Specification generated at $TESTNET_DIR.
echo "Generating $VALIDATOR_COUNT validators concurrently... (this may take a while)"

lcli \
	insecure-validators \
	--count $VALIDATOR_COUNT \
	--validators-dir $VALIDATORS_DIR \
	--secrets-dir $SECRETS_DIR

echo Validators generated at $VALIDATORS_DIR with keystore passwords at $SECRETS_DIR.
echo "Building genesis state... (this might take a while)"

lcli \
	--spec mainnet \
	interop-genesis \
	--testnet-dir $TESTNET_DIR \
	$VALIDATOR_COUNT

echo Created genesis state in $TESTNET_DIR
