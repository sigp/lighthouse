#!/bin/bash

#
# Starts a validator client based upon a genesis state created by
# `./local_testnet_genesis_state`.
#

source ./vars.env

DEBUG_LEVEL=${1:-info}

exec lighthouse \
	--debug-level $DEBUG_LEVEL \
	vc \
	--datadir $VALIDATORS_DIR \
	--secrets-dir $SECRETS_DIR \
	--testnet-dir $TESTNET_DIR \
	--auto-register
