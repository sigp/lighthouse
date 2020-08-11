#!/usr/bin/env bash

#
# Starts a beacon node based upon a genesis state created by
# `./local_testnet_genesis_state`.
#

source ./vars.env

DEBUG_LEVEL=${1:-info}

exec lighthouse \
	--debug-level $DEBUG_LEVEL \
	bn \
	--datadir $BEACON_DIR \
	--testnet-dir $TESTNET_DIR \
	--dummy-eth1 \
	--http \
	--enr-address 127.0.0.1 \
	--enr-udp-port 9000 \
	--enr-tcp-port 9000 \
