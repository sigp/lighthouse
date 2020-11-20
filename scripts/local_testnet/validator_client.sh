#!/usr/bin/env bash

#
# Starts a validator client based upon a genesis state created by
# `./local_testnet_genesis_state`.
#

source ./vars.env

DEBUG_LEVEL=${1:-info}

exec lighthouse \
	--debug-level $DEBUG_LEVEL \
	vc \
	--datadir $DATADIR \
	--testnet-dir $TESTNET_DIR \
	--init-slashing-protection \
	--allow-unsynced
