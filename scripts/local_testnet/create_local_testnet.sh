#!/usr/bin/env bash
# Start all processes necessary to create a
# local testnet with 1 eth1 client,
# 4 beacon nodes and 1 validator with 20 vc's.

source ./vars.env

PID_FILE=$TESTNET_DIR/PIDS.pid

# Kill processes we previously started
./kill_processes.sh $PID_FILE

# Clean $TESTNET_DIR and recreate an empty one
./clean.sh
mkdir -p $TESTNET_DIR

# First parameter is log file name
# Second parameter is executable name
execute_command() {
    LOG_NAME=$1
    EX_NAME=$2
    shift
    shift
    CMD="$EX_NAME $@ &>> $TESTNET_DIR/$LOG_NAME"
    echo "executing: $CMD"
    echo "$CMD" > "$TESTNET_DIR/$LOG_NAME"
    eval "$CMD &"
}

sleeping() {
   echo sleeping $1
   sleep $1
}

# First parameter is executable name
execute_command_add_PID() {
    execute_command $@
    echo "$!" >> $PID_FILE
}

execute_command_add_PID ganache_test_node.log ./ganache_test_node.sh
sleeping 2
execute_command setup.log ./setup.sh
sleeping 15
execute_command_add_PID bootnode.log ./bootnode.sh

sleeping 1
execute_command_add_PID becacon_node_1.log ./beacon_node.sh $TESTNET_DIR/node_1 9001 8001
sleeping 0
execute_command_add_PID becacon_node_2.log ./beacon_node.sh $TESTNET_DIR/node_2 9002 8002
sleeping 0
execute_command_add_PID becacon_node_3.log ./beacon_node.sh $TESTNET_DIR/node_3 9003 8003
sleeping 0
execute_command_add_PID becacon_node_4.log ./beacon_node.sh $TESTNET_DIR/node_4 9004 8004

sleeping 0
execute_command_add_PID validator.log ./validator_client.sh $TESTNET_DIR/node_1 http://localhost:8001

echo "DONE!"

