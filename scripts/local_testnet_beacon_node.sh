#!/bin/bash

#
# Starts a beacon node based upon a genesis state created by
# `./local_testnet_genesis_state`.
#

TESTNET_DIR=~/.lighthouse/local-testnet/testnet
DATADIR=~/.lighthouse/local-testnet/beacon
DEBUG_LEVEL=${1:-info}

exec lighthouse \
	--debug-level $DEBUG_LEVEL \
	bn \
	--datadir $DATADIR \
	--testnet-dir $TESTNET_DIR \
	--dummy-eth1 \
	--http
