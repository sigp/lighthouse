#!/usr/bin/env bash

cp ../local_testnet/vars.env ../local_testnet/vars.env.bkp
cp ./vars.env ../local_testnet/vars.env
../local_testnet/clean.sh

../local_testnet/ganache_test_node.sh &
GANACHE_PID=$!

# wait for ganache to start
sleep 5

../local_testnet/setup.sh

# Duplicate this directory so slashing protection doesn't keep us from re-using validator keys
cp -R $HOME/.lighthouse/local-testnet/node_1 $HOME/.lighthouse/local-testnet/node_1_doppelganger

../local_testnet/bootnode.sh &
BOOT_PID=$!

# wait for the bootnode to start
sleep 5

../local_testnet/beacon_node.sh $HOME/.lighthouse/local-testnet/node_1 9000 8000 &
BEACON_PID=$!
../local_testnet/beacon_node.sh $HOME/.lighthouse/local-testnet/node_2 9100 8100 &
BEACON2_PID=$!
../local_testnet/beacon_node.sh $HOME/.lighthouse/local-testnet/node_3 9200 8200 &
BEACON3_PID=$!
../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_1 http://localhost:8000 &
VALIDATOR_1_PID=$!
../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_2 http://localhost:8100 &
VALIDATOR_2_PID=$!
../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_3 http://localhost:8200 &
VALIDATOR_3_PID=$!

# Wait an epoch before starting a validator for doppelganger detection
sleep 64

# Use same keys as keys from VC1, but connect to BN2
# This process should not last longer than an 2 epochs
timeout 128 ../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_1_doppelganger http://localhost:8100
DOPPELGANGER_EXIT=$?

# Cleanup
kill $BOOT_PID $BEACON_PID $BEACON2_PID $GANACHE_PID $VALIDATOR_1_PID $VALIDATOR_2_PID $VALIDATOR_3_PID $BEACON3_PID
mv ../local_testnet/vars.env.bkp ../local_testnet/vars.env

exit $DOPPELGANGER_EXIT