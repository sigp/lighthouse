#!/usr/bin/env bash

#
# Starts a validator client based upon a genesis state created by
# `./setup.sh`.
#
# Usage: ./validator_client.sh <DATADIR> <BEACON-NODE-HTTP> <OPTIONAL-DEBUG-LEVEL>

set -Eeuo pipefail

source ./vars.env

DEBUG_LEVEL=info

PRIVATE_TX_PROPOSALS=

# Get options
while getopts "pd:" flag; do
  case "${flag}" in
    p) PRIVATE_TX_PROPOSALS="--builder-proposals";;
    d) DEBUG_LEVEL=${OPTARG};;
  esac
done

exec lighthouse \
	--debug-level $DEBUG_LEVEL \
	vc \
	$PRIVATE_TX_PROPOSALS \
	--datadir ${@:$OPTIND:1} \
	--testnet-dir $TESTNET_DIR \
	--init-slashing-protection \
	--beacon-nodes ${@:$OPTIND+1:1} \
	$VC_ARGS
