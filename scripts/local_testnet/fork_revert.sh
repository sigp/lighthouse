#!/usr/bin/env bash

source ./start_local_testnet.sh genesis.json

./download_lighthouse.sh v4.6.0 -b lh-stale

n=2
node_id=$(($BN_COUNT+1))

stale_testnet_dir=$DATADIR/stale_testnet

cp -r $TESTNET_DIR $stale_testnet_dir

sed -i '/DENEB_FORK_VERSION/d' $stale_testnet_dir/config.yaml
sed -i '/DENEB_FORK_EPOCH/d' $stale_testnet_dir/config.yaml
sed -i '/MAX_REQUEST_BLOCKS_DENEB/d' $stale_testnet_dir/config.yaml

for ((i = 0; i < n; i++)); do
    current_id=$(($node_id+i))
    execute_command_add_PID geth_$current_id.log ./geth.sh $DATADIR/geth_datadir$current_id $((EL_base_network + $current_id)) $((EL_base_http + current_id)) $((EL_base_auth_http + $current_id)) $genesis_file
done

sleeping 20

for ((i = 0; i < n; i++)); do
    current_id=$(($node_id+i))
    secret=$DATADIR/geth_datadir$current_id/geth/jwtsecret
    echo $secret
    execute_command_add_PID beacon_node_$current_id.log ./beacon_node.sh $SAS -d $DEBUG_LEVEL $DATADIR/node_$current_id $((BN_udp_tcp_base + $current_id)) $((BN_udp_tcp_base + $current_id + 100)) $((BN_http_port_base + $current_id)) http://localhost:$((EL_base_auth_http + $current_id)) $secret $stale_testnet_dir -b lh-stale

    execute_command_add_PID validator_node_$current_id.log ./validator_client.sh $BUILDER_PROPOSALS -d $DEBUG_LEVEL $DATADIR/node_$current_id http://localhost:$((BN_http_port_base + $current_id))

    tail ~/.lighthouse/local-testnet/testnet/PIDS.pid --lines 2 >> $stale_testnet_dir/stale_pids.pid
done

# Wait for the two chains to split
sleeping $(($DENEB_FORK_EPOCH*32*$SECONDS_PER_SLOT))

echo "Sending a transaction on the stale chain"
./transaction.sh

sleeping 30

./kill_processes.sh $stale_testnet_dir/stale_pids.pid

sleeping 5

for ((i = 0; i < n; i++)); do
    current_id=$(($node_id+i))
    secret=$DATADIR/geth_datadir$current_id/geth/jwtsecret
    echo $secret
    execute_command_add_PID beacon_node_$current_id.log ./beacon_node.sh $SAS -d $DEBUG_LEVEL $DATADIR/node_$current_id $((BN_udp_tcp_base + $current_id)) $((BN_udp_tcp_base + $current_id + 100)) $((BN_http_port_base + $current_id)) http://localhost:$((EL_base_auth_http + $current_id)) $secret $TESTNET_DIR

    execute_command_add_PID validator_node_$current_id.log ./validator_client.sh $BUILDER_PROPOSALS -d $DEBUG_LEVEL $DATADIR/node_$current_id http://localhost:$((BN_http_port_base + $current_id))
done
