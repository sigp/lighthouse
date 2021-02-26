#!/usr/bin/env bash

ganache-cli \
	--defaultBalanceEther 1000000000 \
	--gasLimit 1000000000 \
	--accounts 10 \
	--mnemonic "vast thought differ pull jewel broom cook wrist tribe word before omit" \
	--port 8545 \
	--blockTime 3 \
	--networkId 4242 \
	--chainId 4242
