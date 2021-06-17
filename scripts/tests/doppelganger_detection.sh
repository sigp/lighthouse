#!/usr/bin/env bash

cp ../local_testnet/vars.env ../local_testnet/vars.env.bkp
cp ./vars.env ../local_testnet/vars.env
../local_testnet/clean.sh

echo "Starting ganache"

../local_testnet/ganache_test_node.sh &
GANACHE_PID=$!

# wait for ganache to start
sleep 5

echo "Setting up local testnet"

../local_testnet/setup.sh

# Duplicate this directory so slashing protection doesn't keep us from re-using validator keys
cp -R $HOME/.lighthouse/local-testnet/node_1 $HOME/.lighthouse/local-testnet/node_1_doppelganger

echo "Starting bootnode"

../local_testnet/bootnode.sh &
BOOT_PID=$!

# wait for the bootnode to start
sleep 5

echo "Starting local beacon nodes"

../local_testnet/beacon_node.sh $HOME/.lighthouse/local-testnet/node_1 9000 8000 &
BEACON_PID=$!
../local_testnet/beacon_node.sh $HOME/.lighthouse/local-testnet/node_2 9100 8100 &
BEACON2_PID=$!
../local_testnet/beacon_node.sh $HOME/.lighthouse/local-testnet/node_3 9200 8200 &
BEACON3_PID=$!

echo "Starting local validator clients"

../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_1 http://localhost:8000 &
VALIDATOR_1_PID=$!
../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_2 http://localhost:8100 &
VALIDATOR_2_PID=$!
../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_3 http://localhost:8200 &
VALIDATOR_3_PID=$!

echo "Waiting an epoch before starting the duplicate validator client"

# Wait an epoch before starting a validator for doppelganger detection
sleep 64

echo "Starting the doppelganger validator client"

# Use same keys as keys from VC1, but connect to BN2
# This process should not last longer than 2 epochs
timeout 128 ../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_1_doppelganger http://localhost:8100
DOPPELGANGER_EXIT=$?

echo "Shutting down"

# Cleanup
kill $BOOT_PID $BEACON_PID $BEACON2_PID $GANACHE_PID $VALIDATOR_1_PID $VALIDATOR_2_PID $VALIDATOR_3_PID $BEACON3_PID
mv ../local_testnet/vars.env.bkp ../local_testnet/vars.env

echo "Done"

if [ $DOPPELGANGER_EXIT -eq 124 ]; then
    exit 1
fi

exit 0
