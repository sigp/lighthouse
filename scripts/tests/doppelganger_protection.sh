#!/usr/bin/env bash

# Requires `lighthouse`, ``lcli`, `geth`, `curl`, `jq`


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

exit_if_fails ../local_testnet/geth.sh $HOME/.lighthouse/local-testnet/geth_datadir1 7000 6000 5000 $genesis_file &> geth.log &
exit_if_fails ../local_testnet/geth.sh $HOME/.lighthouse/local-testnet/geth_datadir2 7100 6100 5100 $genesis_file &> /dev/null &
exit_if_fails ../local_testnet/geth.sh $HOME/.lighthouse/local-testnet/geth_datadir3 7200 6200 5200 $genesis_file &> /dev/null &

sleep 20

# Reset the `genesis.json` config file fork times.
sed -i 's/"shanghaiTime".*$/"shanghaiTime": 0,/g' genesis.json
sed -i 's/"shardingForkTime".*$/"shardingForkTime": 0,/g' genesis.json

# Manually set the network key for the BN that will be connected to the doppelganger validator
# The hardcoded peer id is derived from the hardcoded secret key
# We set this peer id as a trusted peer for the remaining BNs.
# This is to ensure that the doppelganger BN doesn't get downscored by lighthouse's peer scoring system
# which happens because of excessive posting of duplicate messages.
PEER_ID='16Uiu2HAmTRYTvvc33UdwhJMRhkCeQZW6JVjzNCDPjNkdDncWX8LU'
SECRET_KEY="\\x2e\\x31\\xf6\\x60\\x0c\\x30\\xbe\\x32\\x34\\x8d\\xff\\x4c\\xad\\x66\\x51\\x8e\\x23\\xd2\\x0e\\x18\\x09\\x76\\x87\\xd1\\x70\\xce\\x4b\\xab\\xdd\\x0f\\xfb\\x78"
mkdir -p $HOME/.lighthouse/local-testnet/node_2/beacon/network

echo -n -e $SECRET_KEY > $HOME/.lighthouse/local-testnet/node_2/beacon/network/key

echo "Starting local beacon nodes"

exit_if_fails ../local_testnet/beacon_node.sh -t $PEER_ID -d debug $HOME/.lighthouse/local-testnet/node_1 9000 8000 http://localhost:5000 $HOME/.lighthouse/local-testnet/geth_datadir1/geth/jwtsecret &> beacon1.log &
exit_if_fails ../local_testnet/beacon_node.sh $HOME/.lighthouse/local-testnet/node_2 9100 8100 http://localhost:5100 $HOME/.lighthouse/local-testnet/geth_datadir2/geth/jwtsecret &> /dev/null &
exit_if_fails ../local_testnet/beacon_node.sh -t $PEER_ID $HOME/.lighthouse/local-testnet/node_3 9200 8200 http://localhost:5200 $HOME/.lighthouse/local-testnet/geth_datadir3/geth/jwtsecret &> /dev/null &

echo "Starting local validator clients"

exit_if_fails ../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_1 http://localhost:8000 &> /dev/null &
exit_if_fails ../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_2 http://localhost:8100 &> /dev/null &
exit_if_fails ../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_3 http://localhost:8200 &> /dev/null &

echo "Waiting an epoch before starting the next validator client"
sleep $(( $SECONDS_PER_SLOT * 32 ))

if [[ "$BEHAVIOR" == "failure" ]]; then

    echo "Starting the doppelganger validator client"

    # Use same keys as keys from VC1 and connect to BN2
    # This process should not last longer than 2 epochs
    timeout $(( $SECONDS_PER_SLOT * 32 * 2 )) ../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_1_doppelganger http://localhost:8100
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

    ../local_testnet/validator_client.sh $HOME/.lighthouse/local-testnet/node_4 http://localhost:8300 &
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

    killall geth
    killall lighthouse
    killall bootnode

    echo "Done"

    if [[ $DOPPELGANGER_FAILURE -eq 1 ]]; then
        exit 1
    fi
fi

exit 0
