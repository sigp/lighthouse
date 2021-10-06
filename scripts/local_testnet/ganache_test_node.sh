#!/usr/bin/env bash

source ./vars.env

ganache-cli \
	--host "0.0.0.0" \
	--defaultBalanceEther 1000000000 \
	--gasLimit 1000000000 \
	--accounts 10 \
	--mnemonic "$ETH1_NETWORK_MNEMONIC" \
	--port 8545 \
	--blockTime 3 \
	--networkId "$NETWORK_ID" \
	--chainId "$NETWORK_ID"
