#!/usr/bin/env bash

set -Eeuo pipefail

source ./vars.env

exec anvil \
	--balance 1000000000 \
	--gas-limit 1000000000 \
	--accounts 10 \
	--mnemonic "$ETH1_NETWORK_MNEMONIC" \
	--block-time $SECONDS_PER_ETH1_BLOCK \
	--port 8545 \
	--chain-id "$CHAIN_ID"
