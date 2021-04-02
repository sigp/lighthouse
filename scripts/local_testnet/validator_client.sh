#!/usr/bin/env bash

#
# Starts a validator client based upon a genesis state created by
# `./setup.sh`.
#
# Usage: ./validator_client.sh <DATADIR> <BEACON-NODE-HTTP> <OPTIONAL-DEBUG-LEVEL>

source ./vars.env

DEBUG_LEVEL=${3:-info}

exec lighthouse \
	--debug-level $DEBUG_LEVEL \
	vc \
	--datadir $1 \
	--testnet-dir $TESTNET_DIR \
	--init-slashing-protection \
	--beacon-nodes $2 \
	$VC_ARGS
