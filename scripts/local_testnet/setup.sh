#!/usr/bin/env bash

#
# Produces a testnet specification and a genesis state where the genesis time
# is now + $GENESIS_DELAY.
#
# Generates datadirs for multiple validator keys according to the
# $VALIDATOR_COUNT and $BN_COUNT variables.
#

set -o nounset -o errexit -o pipefail

source ./vars.env


NOW=`date +%s`
GENESIS_TIME=`expr $NOW + $GENESIS_DELAY`

lcli \
	new-testnet \
	--spec $SPEC_PRESET \
	--deposit-contract-address $DEPOSIT_CONTRACT_ADDRESS \
	--testnet-dir $TESTNET_DIR \
	--min-genesis-active-validator-count $GENESIS_VALIDATOR_COUNT \
	--min-genesis-time $GENESIS_TIME \
	--genesis-delay $GENESIS_DELAY \
	--genesis-fork-version $GENESIS_FORK_VERSION \
	--altair-fork-epoch $ALTAIR_FORK_EPOCH \
	--bellatrix-fork-epoch $BELLATRIX_FORK_EPOCH \
	--capella-fork-epoch $CAPELLA_FORK_EPOCH \
	--ttd $TTD \
	--eth1-block-hash $ETH1_BLOCK_HASH \
	--eth1-id $CHAIN_ID \
	--eth1-follow-distance 128 \
	--seconds-per-slot $SECONDS_PER_SLOT \
	--seconds-per-eth1-block $SECONDS_PER_ETH1_BLOCK \
	--proposer-score-boost "$PROPOSER_SCORE_BOOST" \
	--validator-count $GENESIS_VALIDATOR_COUNT \
	--interop-genesis-state \
	--force

echo Specification and genesis.ssz generated at $TESTNET_DIR.
echo "Generating $VALIDATOR_COUNT validators concurrently... (this may take a while)"

lcli \
	insecure-validators \
	--count $VALIDATOR_COUNT \
	--base-dir $DATADIR \
	--node-count $VC_COUNT

echo Validators generated with keystore passwords at $DATADIR.
