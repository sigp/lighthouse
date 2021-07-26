#!/usr/bin/env bash

# Requires `lighthouse`, ``lcli`, `ganache-cli`, `curl`, `jq`

BEHAVIOR=$1

if [[ "$BEHAVIOR" != "success" ]] && [[ "$BEHAVIOR" != "failure" ]]; then
    echo "Usage: doppelganger_protection.sh [success|failure]"
    exit 1
fi

cp ./vars_$BEHAVIOR.env ./vars.env

../local_testnet/clean.sh

echo "Starting ganache"

../local_testnet/ganache_test_node.sh &> /dev/null &
GANACHE_PID=$!

# wait for ganache to start
sleep 5

echo "Setting up local testnet"

../local_testnet/setup.sh

# Duplicate this directory so slashing protection doesn't keep us from re-using validator keys
cp -R $HOME/.lighthouse/local-testnet/node_1 $HOME/.lighthouse/local-testnet/node_1_doppelganger

echo "Starting bootnode"

../local_testnet/bootnode.sh &> /dev/null &
BOOT_PID=$!

# wait for the bootnode to start
sleep 5

echo "Starting local beacon nodes"

../local_testnet/beacon_node.sh $HOME/.lighthouse/local-testnet/node_1 9000 8000 &> /dev/null &
BEACON_PID=$!
../local_testnet/beacon_node.sh $HOME/.lighthouse/local-testnet/node_2 9100 8100 &> /dev/null &
BEACON2_PID=$!
../local_testnet/beacon_node.sh $HOME/.lighthouse/local-testnet/node_3 9200 8200 &> /dev/null &
BEACON3_PID=$!

echo "Starting local validator clients"

../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_1 http://localhost:8000 &> /dev/null &
VALIDATOR_1_PID=$!
../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_2 http://localhost:8100 &> /dev/null &
VALIDATOR_2_PID=$!
../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_3 http://localhost:8200 &> /dev/null &
VALIDATOR_3_PID=$!

echo "Waiting an epoch before starting the next validator client"
BANANA=$(( $SECONDS_PER_SLOT * 32 ))
echo "banana: $BANANA"
sleep 64

if [[ "$BEHAVIOR" == "failure" ]]; then

    echo "Starting the doppelganger validator client"

    # Use same keys as keys from VC1, but connect to BN2
    # This process should not last longer than 2 epochs
    timeout 128 ../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_1_doppelganger http://localhost:8100
    DOPPELGANGER_EXIT=$?

    echo "Shutting down"

    # Cleanup
    kill $BOOT_PID $BEACON_PID $BEACON2_PID $GANACHE_PID $VALIDATOR_1_PID $VALIDATOR_2_PID $VALIDATOR_3_PID $BEACON3_PID
    rm ./vars.env

    echo "Done"

    if [[ $DOPPELGANGER_EXIT -eq 124 ]]; then
        exit 1
    fi
fi

if [[ "$BEHAVIOR" == "success" ]]; then

    echo "Starting the last validator client"

    # This process should last longer than 3 epochs
    # start in epoch 1, last till end of epoch 3
    ../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_4 http://localhost:8100 &
    VALIDATOR_4_PID=$!
    DOPPELGANGER_FAILURE=0

    # Sleep two epochs, then make sure all validators were NOT active in epoch 2.
    echo "Waiting two epochs..."
    sleep 128

    PREVIOUS_DIR=$(pwd)
    cd $HOME/.lighthouse/local-testnet/node_4/validators
    for val in 0x*; do
        [[ -e $val ]] || continue
        curl -s localhost:8100/lighthouse/validator_inclusion/2/$val | jq | grep -q '"is_current_epoch_attester": false'
        IS_ATTESTER=$?
        if [[ $IS_ATTESTER -eq 0 ]]; then
            echo "$val did not attest in epoch 2."
        else
            echo "ERROR! $val did attest in epoch 2."
            DOPPELGANGER_FAILURE=1
        fi
    done

    # Sleep two epochs, then make sure all validators were active in epoch 4.
    echo "Waiting two more epochs..."
    sleep 128
    for val in 0x*; do
        [[ -e $val ]] || continue
        curl -s localhost:8100/lighthouse/validator_inclusion/4/$val | jq | grep -q '"is_current_epoch_attester": true'
        IS_ATTESTER=$?
        if [[ $IS_ATTESTER -eq 0 ]]; then
            echo "$val attested in epoch 4."
        else
            echo "ERROR! $val did not attest in epoch 4."
            DOPPELGANGER_FAILURE=1
        fi
    done

    cd $PREVIOUS_DIR

    echo "Shutting down"

    # Cleanup
    kill $BOOT_PID $BEACON_PID $BEACON_PID2 $BEACON_PID3 $GANACHE_PID $VALIDATOR_1_PID $VALIDATOR_2_PID $VALIDATOR_3_PID $VALIDATOR_4_PID
    rm ./vars.env

    echo "Done"

    if [[ $DOPPELGANGER_FAILURE -eq 1 ]]; then
        exit 1
    fi
fi

exit 0
