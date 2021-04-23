#!/usr/bin/env bash

source ./vars.env

ganache-cli \
	--defaultBalanceEther 1000000000 \
	--gasLimit 1000000000 \
	--accounts 10 \
	--mnemonic "$ETH1_NETWORK_MNEMONIC" \
	--port 8545 \
	--blockTime 3 \
	--networkId 4242 \
	--chainId 4242
