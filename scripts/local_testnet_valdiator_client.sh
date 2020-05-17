#!/bin/bash

#
# Starts a validator client based upon a genesis state created by
# `./local_testnet_genesis_state`.
#

TESTNET_DIR=~/.lighthouse/local-testnet/testnet
DATADIR=~/.lighthouse/local-testnet/validator
DEBUG_LEVEL=${1:-info}

exec lighthouse \
	--debug-level $DEBUG_LEVEL \
	vc \
	--datadir $DATADIR \
	--testnet-dir $TESTNET_DIR \
	testnet \
	insecure \
	0 \
	$(cat $TESTNET_DIR/validator_count.txt)
