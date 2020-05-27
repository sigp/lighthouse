#!/bin/bash

#
# Starts a beacon node based upon a genesis state created by
# `./local_testnet_genesis_state`.
#

source ./vars.env

DEBUG_LEVEL=${1:-info}

exec lighthouse \
	--debug-level $DEBUG_LEVEL \
	bn \
	--datadir $BEACON_DIR-2 \
	--testnet-dir $TESTNET_DIR \
	--dummy-eth1 \
	--http \
	--http-port 6052 \
	--boot-nodes $(cat $BEACON_DIR/beacon/network/enr.dat)
