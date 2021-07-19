#!/usr/bin/env bash

#
# Starts a beacon node based upon a genesis state created by
# `./setup.sh`.
#
# Usage: ./beacon_node.sh <DATADIR> <NETWORK-PORT> <HTTP-PORT> <OPTIONAL-DEBUG-LEVEL>

source ./vars.env

DEBUG_LEVEL=${4:-info}

exec lighthouse \
	--debug-level $DEBUG_LEVEL \
	bn \
	--datadir $1 \
	--testnet-dir $TESTNET_DIR \
	--staking \
	--enr-address 127.0.0.1 \
	--enr-udp-port $2 \
	--enr-tcp-port $2 \
	--port $2 \
	--http-port $3
