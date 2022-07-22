#!/usr/bin/env bash

#
# Starts geth.
#
# Usage: ./geth_node.sh <DATADIR> <PORT> <HTTP-PORT> <EL-PORT>

set -Eeuo pipefail

source ./vars.env

rm -rf $1 || true

$GETH_BIN_DIR/geth --datadir $1 init ./config/geth.json 

cp ./config/be733bb2629b84d29570a5ff64569d1aa8f97f86 $1/keystore/

exec $GETH_BIN_DIR/geth \
  --datadir $1 \
  --networkid 4242 \
  --discovery.dns "" \
  --port $2 \
  --http \
  --http.port $3 \
  --authrpc.port $4 \
  --authrpc.jwtsecret ./config/jwtsecret \
  --authrpc.addr localhost \
  --bootnodes enode://$(cat $DATADIR/geth_bootnode.addr)@127.0.0.1:30301 \
  --mine \
  --miner.etherbase 0xbe733bb2629B84D29570A5fF64569d1Aa8f97f86 \
  --miner.threads 1 \
  --miner.gaslimit 1000000000  \
  --unlock 0xbe733bb2629B84D29570A5fF64569d1Aa8f97f86 \
  --password ./config/password \
  --allow-insecure-unlock
