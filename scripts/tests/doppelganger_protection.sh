#!/usr/bin/env bash

# Requires `lighthouse`, `lcli`, `geth`, `bootnode`, `curl`, `jq`


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
        exit 1
    fi
}
genesis_file=$2

source ./vars.env

exit_if_fails ../local_testnet/clean.sh


echo "Setting up local testnet"

exit_if_fails ../local_testnet/setup.sh

# Duplicate this directory so slashing protection doesn't keep us from re-using validator keys
exit_if_fails cp -R $HOME/.lighthouse/local-testnet/node_1 $HOME/.lighthouse/local-testnet/node_1_doppelganger

echo "Starting bootnode"

exit_if_fails ../local_testnet/bootnode.sh &> /dev/null &

exit_if_fails ../local_testnet/el_bootnode.sh &> /dev/null &

# wait for the bootnode to start
sleep 10

echo "Starting local execution nodes"

exit_if_fails ../local_testnet/geth.sh $HOME/.lighthouse/local-testnet/geth_datadir1 6000 5000 4000 $genesis_file &> geth.log &
exit_if_fails ../local_testnet/geth.sh $HOME/.lighthouse/local-testnet/geth_datadir2 6100 5100 4100 $genesis_file &> /dev/null &
exit_if_fails ../local_testnet/geth.sh $HOME/.lighthouse/local-testnet/geth_datadir3 6200 5200 4200 $genesis_file &> /dev/null &

sleep 20

echo "Starting local beacon nodes"

exit_if_fails ../local_testnet/beacon_node.sh -d debug $HOME/.lighthouse/local-testnet/node_1 8000 7000 9000 http://localhost:4000 $HOME/.lighthouse/local-testnet/geth_datadir1/geth/jwtsecret &> /dev/null &
exit_if_fails ../local_testnet/beacon_node.sh $HOME/.lighthouse/local-testnet/node_2 8100 7100 9100 http://localhost:4100 $HOME/.lighthouse/local-testnet/geth_datadir2/geth/jwtsecret &> /dev/null &
exit_if_fails ../local_testnet/beacon_node.sh $HOME/.lighthouse/local-testnet/node_3 8200 7200 9200 http://localhost:4200 $HOME/.lighthouse/local-testnet/geth_datadir3/geth/jwtsecret &> /dev/null &

echo "Starting local validator clients"

exit_if_fails ../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_1 http://localhost:9000 &> /dev/null &
exit_if_fails ../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_2 http://localhost:9100 &> /dev/null &
exit_if_fails ../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_3 http://localhost:9200 &> /dev/null &

echo "Waiting an epoch before starting the next validator client"
sleep $(( $SECONDS_PER_SLOT * 32 ))

if [[ "$BEHAVIOR" == "failure" ]]; then

    echo "Starting the doppelganger validator client"

    # Use same keys as keys from VC1 and connect to BN2
    # This process should not last longer than 2 epochs
    timeout $(( $SECONDS_PER_SLOT * 32 * 2 )) ../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_1_doppelganger http://localhost:9100
    DOPPELGANGER_EXIT=$?

    echo "Shutting down"

    # Cleanup
    killall geth
    killall lighthouse
    killall bootnode

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

    ../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_4 http://localhost:9100 &
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
        curl -s localhost:9100/lighthouse/validator_inclusion/3/$val | jq | grep -q '"is_previous_epoch_target_attester": false'
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
        curl -s localhost:9100/lighthouse/validator_inclusion/5/$val | jq | grep -q '"is_previous_epoch_target_attester": true'
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

    killall geth
    killall lighthouse
    killall bootnode

    echo "Done"

    if [[ $DOPPELGANGER_FAILURE -eq 1 ]]; then
        exit 1
    fi
fi

exit 0
