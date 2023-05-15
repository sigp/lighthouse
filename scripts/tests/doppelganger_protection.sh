#!/usr/bin/env bash

# Requires `lighthouse`, ``lcli`, `anvil`, `curl`, `jq`


BEHAVIOR=$1

if [[ "$BEHAVIOR" != "success" ]] && [[ "$BEHAVIOR" != "failure" ]]; then
    echo "Usage: doppelganger_protection.sh [success|failure]"
    exit 1
fi

exit_if_fails() {
    echo $@
    $@
    EXIT_CODE=$?
    if [[ $EXIT_CODE -eq 1 ]]; then
        exit 111
    fi
}

source ./vars.env

exit_if_fails ../local_testnet/clean.sh

echo "Starting anvil"

exit_if_fails ../local_testnet/anvil_test_node.sh &> /dev/null &
ANVIL_PID=$!

# Wait for anvil to start
sleep 5

echo "Setting up local testnet"

exit_if_fails ../local_testnet/setup.sh

# Duplicate this directory so slashing protection doesn't keep us from re-using validator keys
exit_if_fails cp -R $HOME/.lighthouse/local-testnet/node_1 $HOME/.lighthouse/local-testnet/node_1_doppelganger

echo "Starting bootnode"

exit_if_fails ../local_testnet/bootnode.sh &> /dev/null &
BOOT_PID=$!

# wait for the bootnode to start
sleep 10

echo "Starting local beacon nodes"

exit_if_fails ../local_testnet/beacon_node.sh $HOME/.lighthouse/local-testnet/node_1 9000 8000 &> /dev/null &
BEACON_PID=$!
exit_if_fails ../local_testnet/beacon_node.sh $HOME/.lighthouse/local-testnet/node_2 9100 8100 &> /dev/null &
BEACON_PID2=$!
exit_if_fails ../local_testnet/beacon_node.sh $HOME/.lighthouse/local-testnet/node_3 9200 8200 &> /dev/null &
BEACON_PID3=$!

echo "Starting local validator clients"

exit_if_fails ../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_1 http://localhost:8000 &> /dev/null &
VALIDATOR_1_PID=$!
exit_if_fails ../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_2 http://localhost:8100 &> /dev/null &
VALIDATOR_2_PID=$!
exit_if_fails ../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_3 http://localhost:8200 &> /dev/null &
VALIDATOR_3_PID=$!

echo "Waiting an epoch before starting the next validator client"
sleep $(( $SECONDS_PER_SLOT * 32 ))

if [[ "$BEHAVIOR" == "failure" ]]; then

    echo "Starting the doppelganger validator client"

    # Use same keys as keys from VC1, but connect to BN2
    # This process should not last longer than 2 epochs
    timeout $(( $SECONDS_PER_SLOT * 32 * 2 )) ../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_1_doppelganger http://localhost:8100
    DOPPELGANGER_EXIT=$?

    echo "Shutting down"

    # Cleanup
    kill $BOOT_PID $BEACON_PID $BEACON_PID2 $BEACON_PID3 $ANVIL_PID $VALIDATOR_1_PID $VALIDATOR_2_PID $VALIDATOR_3_PID

    echo "Done"

    # We expect to find a doppelganger, exit with success error code if doppelganger was found
    # and failure if no doppelganger was found.
    if [[ $DOPPELGANGER_EXIT -eq 1 ]]; then
        exit 0
    else
        exit 1
    fi

fi

if [[ "$BEHAVIOR" == "success" ]]; then

    echo "Starting the last validator client"

    ../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_4 http://localhost:8100 &
    VALIDATOR_4_PID=$!
    DOPPELGANGER_FAILURE=0

    # Sleep three epochs, then make sure all validators were active in epoch 2. Use
    # `is_previous_epoch_target_attester` from epoch 3 for a complete view of epoch 2 inclusion.
    #
    # See: https://lighthouse-book.sigmaprime.io/validator-inclusion.html
    echo "Waiting three epochs..."
    sleep $(( $SECONDS_PER_SLOT * 32 * 3 ))

    PREVIOUS_DIR=$(pwd)
    cd $HOME/.lighthouse/local-testnet/node_4/validators
    for val in 0x*; do
        [[ -e $val ]] || continue
        curl -s localhost:8100/lighthouse/validator_inclusion/3/$val | jq | grep -q '"is_previous_epoch_target_attester": false'
        IS_ATTESTER=$?
        if [[ $IS_ATTESTER -eq 0 ]]; then
            echo "$val did not attest in epoch 2."
        else
            echo "ERROR! $val did attest in epoch 2."
            DOPPELGANGER_FAILURE=1
        fi
    done

    # Sleep two epochs, then make sure all validators were active in epoch 4. Use
    # `is_previous_epoch_target_attester` from epoch 5 for a complete view of epoch 4 inclusion.
    #
    # See: https://lighthouse-book.sigmaprime.io/validator-inclusion.html
    echo "Waiting two more epochs..."
    sleep $(( $SECONDS_PER_SLOT * 32 * 2 ))
    for val in 0x*; do
        [[ -e $val ]] || continue
        curl -s localhost:8100/lighthouse/validator_inclusion/5/$val | jq | grep -q '"is_previous_epoch_target_attester": true'
        IS_ATTESTER=$?
        if [[ $IS_ATTESTER -eq 0 ]]; then
            echo "$val attested in epoch 4."
        else
            echo "ERROR! $val did not attest in epoch 4."
            DOPPELGANGER_FAILURE=1
        fi
    done

    echo "Shutting down"

    # Cleanup
    cd $PREVIOUS_DIR
    kill $BOOT_PID $BEACON_PID $BEACON_PID2 $BEACON_PID3 $ANVIL_PID $VALIDATOR_1_PID $VALIDATOR_2_PID $VALIDATOR_3_PID $VALIDATOR_4_PID

    echo "Done"

    if [[ $DOPPELGANGER_FAILURE -eq 1 ]]; then
        exit 1
    fi
fi

exit 0
