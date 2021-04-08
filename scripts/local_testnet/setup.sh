#!/usr/bin/env bash

#
# Deploys the deposit contract and makes deposits for $VALIDATOR_COUNT insecure deterministic validators.
# Produces a testnet specification and a genesis state where the genesis time
# is now + $GENESIS_DELAY.
#
# Generates datadirs for multiple validator keys according to the 
# $VALIDATOR_COUNT and $NODE_COUNT variables.
#

source ./vars.env

lcli \
	deploy-deposit-contract \
	--eth1-http http://localhost:8545 \
	--confirmations 1 \
	--validator-count $VALIDATOR_COUNT

NOW=`date +%s`
GENESIS_TIME=`expr $NOW + $GENESIS_DELAY`


lcli \
	--spec mainnet \
	new-testnet \
	--deposit-contract-address $DEPOSIT_CONTRACT_ADDRESS \
	--testnet-dir $TESTNET_DIR \
	--min-genesis-active-validator-count $GENESIS_VALIDATOR_COUNT \
	--min-genesis-time $GENESIS_TIME \
	--genesis-delay $GENESIS_DELAY \
	--genesis-fork-version $GENESIS_FORK_VERSION \
	--eth1-id $BOOTNODE_PORT \
	--eth1-follow-distance 1 \
	--seconds-per-eth1-block 1 \
	--force

echo Specification generated at $TESTNET_DIR.
echo "Generating $VALIDATOR_COUNT validators concurrently... (this may take a while)"

lcli \
	insecure-validators \
	--count $VALIDATOR_COUNT \
	--base-dir $DATADIR \
	--node-count $NODE_COUNT

echo Validators generated with keystore passwords at $DATADIR.
echo "Building genesis state... (this might take a while)"

lcli \
	--spec mainnet \
	interop-genesis \
	--genesis-time $GENESIS_TIME \
	--testnet-dir $TESTNET_DIR \
	$GENESIS_VALIDATOR_COUNT

echo Created genesis state in $TESTNET_DIR