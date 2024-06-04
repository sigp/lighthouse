#!/usr/bin/env bash

# Requires `docker`, `kurtosis`, `yq`, `curl`, `jq`

set -Eeuo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
NETWORK_PARAMS_FILE=$SCRIPT_DIR/network_params.yaml
BEHAVIOR=$1
ENCLAVE_NAME=local-testnet-$BEHAVIOR

SECONDS_PER_SLOT=$(yq eval ".network_params.seconds_per_slot" $NETWORK_PARAMS_FILE)
KEYS_PER_NODE=$(yq eval ".network_params.num_validator_keys_per_node" $NETWORK_PARAMS_FILE)
LH_IMAGE_NAME=$(yq eval ".participants[0].cl_image" $NETWORK_PARAMS_FILE)

if [[ "$BEHAVIOR" != "success" ]] && [[ "$BEHAVIOR" != "failure" ]]; then
    echo "Usage: doppelganger_protection.sh [success|failure]"
    exit 1
fi

function exit_and_dump_logs() {
    local exit_code=$1
    echo "Shutting down..."
    $SCRIPT_DIR/../local_testnet/stop_local_testnet.sh $ENCLAVE_NAME
    echo "Test completed with exit code $exit_code."
    exit $exit_code
}

function get_service_status() {
    local service_name=$1
    kurtosis service inspect $ENCLAVE_NAME $service_name | grep Status | cut -d':' -f2 | xargs
}

function run_command_without_exit() {
    local command=$1
    set +e
    eval "$command"
    local exit_code=$?
    set -e
    echo $exit_code
}

# Start local testnet
$SCRIPT_DIR/../local_testnet/start_local_testnet.sh -e $ENCLAVE_NAME -b false -c -n $NETWORK_PARAMS_FILE

# Immediately stop node 4 (as we only need the node 4 validator keys generated for later use)
kurtosis service stop $ENCLAVE_NAME cl-4-lighthouse-geth el-4-geth-lighthouse vc-4-geth-lighthouse > /dev/null

# Get the http port to get the config
BN1_HTTP_ADDRESS=`kurtosis port print $ENCLAVE_NAME cl-1-lighthouse-geth http`

# Get the genesis time and genesis delay
MIN_GENESIS_TIME=`curl -s $BN1_HTTP_ADDRESS/eth/v1/config/spec | jq '.data.MIN_GENESIS_TIME|tonumber'`
GENESIS_DELAY=`curl -s $BN1_HTTP_ADDRESS/eth/v1/config/spec | jq '.data.GENESIS_DELAY|tonumber'`

CURRENT_TIME=`date +%s`
# Note: doppelganger protection can only be started post epoch 0
echo "Waiting until next epoch before starting the next validator client..."
DELAY=$(( $SECONDS_PER_SLOT * 32 + $GENESIS_DELAY + $MIN_GENESIS_TIME - $CURRENT_TIME))
sleep $DELAY

# Use BN2 for the next validator client
bn_2_url=$(kurtosis service inspect $ENCLAVE_NAME cl-2-lighthouse-geth | grep 'enr-address' | cut -d'=' -f2)
bn_2_port=4000

if [[ "$BEHAVIOR" == "failure" ]]; then

    echo "Starting the doppelganger validator client."

    # Use same keys as keys from VC1 and connect to BN2
    # This process should not last longer than 2 epochs
    vc_1_range_start=0
    vc_1_range_end=$(($KEYS_PER_NODE - 1))
    vc_1_keys_artifact_id="1-lighthouse-geth-$vc_1_range_start-$vc_1_range_end-0"
    service_name=vc-1-doppelganger

    kurtosis service add \
      --files /validator_keys:$vc_1_keys_artifact_id,/testnet:el_cl_genesis_data \
      $ENCLAVE_NAME $service_name $LH_IMAGE_NAME -- lighthouse \
      vc \
      --debug-level debug \
      --testnet-dir=/testnet \
      --validators-dir=/validator_keys/keys \
      --secrets-dir=/validator_keys/secrets \
      --init-slashing-protection \
      --beacon-nodes=http://$bn_2_url:$bn_2_port \
      --enable-doppelganger-protection \
      --suggested-fee-recipient 0x690B9A9E9aa1C9dB991C7721a92d351Db4FaC990

    # Check if doppelganger VC has stopped and exited. Exit code 1 means the check timed out and VC is still running.
    check_exit_cmd="until [ \$(get_service_status $service_name) != 'RUNNING' ]; do sleep 1; done"
    doppelganger_exit=$(run_command_without_exit "timeout $(( $SECONDS_PER_SLOT * 32 * 2 )) bash -c \"$check_exit_cmd\"")

    if [[ $doppelganger_exit -eq 1 ]]; then
        echo "Test failed: expected doppelganger but VC is still running. Check the logs for details."
        exit_and_dump_logs 1
    else
        echo "Test passed: doppelganger found and VC process stopped successfully."
        exit_and_dump_logs 0
    fi

fi

if [[ "$BEHAVIOR" == "success" ]]; then

    echo "Starting the last validator client."

    vc_4_range_start=$(($KEYS_PER_NODE * 3))
    vc_4_range_end=$(($KEYS_PER_NODE * 4 - 1))
    vc_4_keys_artifact_id="4-lighthouse-geth-$vc_4_range_start-$vc_4_range_end-0"
    service_name=vc-4

    kurtosis service add \
          --files /validator_keys:$vc_4_keys_artifact_id,/testnet:el_cl_genesis_data \
          $ENCLAVE_NAME $service_name $LH_IMAGE_NAME -- lighthouse \
          vc \
          --debug-level debug \
          --testnet-dir=/testnet \
          --validators-dir=/validator_keys/keys \
          --secrets-dir=/validator_keys/secrets \
          --init-slashing-protection \
          --beacon-nodes=http://$bn_2_url:$bn_2_port \
          --enable-doppelganger-protection \
          --suggested-fee-recipient 0x690B9A9E9aa1C9dB991C7721a92d351Db4FaC990

    doppelganger_failure=0

    # Sleep three epochs, then make sure all validators were active in epoch 2. Use
    # `is_previous_epoch_target_attester` from epoch 3 for a complete view of epoch 2 inclusion.
    #
    # See: https://lighthouse-book.sigmaprime.io/validator-inclusion.html
    echo "Waiting three epochs..."
    sleep $(( $SECONDS_PER_SLOT * 32 * 3 ))

    # Get VC4 validator keys
    keys_path=$SCRIPT_DIR/$ENCLAVE_NAME/node_4/validators
    rm -rf $keys_path && mkdir -p $keys_path
    kurtosis files download $ENCLAVE_NAME $vc_4_keys_artifact_id $keys_path
    cd $keys_path/keys

    for val in 0x*; do
        [[ -e $val ]] || continue
        is_attester=$(run_command_without_exit "curl -s $BN1_HTTP_ADDRESS/lighthouse/validator_inclusion/3/$val | jq | grep -q '\"is_previous_epoch_target_attester\": false'")
        if [[ $is_attester -eq 0 ]]; then
            echo "$val did not attest in epoch 2."
        else
            echo "ERROR! $val did attest in epoch 2."
            doppelganger_failure=1
        fi
    done

    if [[ $doppelganger_failure -eq 1 ]]; then
        exit_and_dump_logs 1
    fi

    # Sleep two epochs, then make sure all validators were active in epoch 4. Use
    # `is_previous_epoch_target_attester` from epoch 5 for a complete view of epoch 4 inclusion.
    #
    # See: https://lighthouse-book.sigmaprime.io/validator-inclusion.html
    echo "Waiting two more epochs..."
    sleep $(( $SECONDS_PER_SLOT * 32 * 2 ))
    for val in 0x*; do
        [[ -e $val ]] || continue
        is_attester=$(run_command_without_exit "curl -s $BN1_HTTP_ADDRESS/lighthouse/validator_inclusion/5/$val | jq | grep -q '\"is_previous_epoch_target_attester\": true'")
        if [[ $is_attester -eq 0 ]]; then
            echo "$val attested in epoch 4."
        else
            echo "ERROR! $val did not attest in epoch 4."
            doppelganger_failure=1
        fi
    done

    if [[ $doppelganger_failure -eq 1 ]]; then
        exit_and_dump_logs 1
    fi
fi

exit_and_dump_logs 0
