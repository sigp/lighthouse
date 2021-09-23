#!/usr/bin/env bash
# Start all processes necessary to create a
# local testnet with 1 eth1 client,
# 4 beacon nodes and 1 validator with 20 vc's.
#
# Takes three optional parameters:
#   -c which is VC_COUNT which should be <= NODE_COUNT defaults to 1
#   -d which id DEBUG_LEVEL and should be one of [log::Level](https://docs.rs/log/0.4.14/log/enum.Level.html)
#   -h help

source ./vars.env

# Parse parameters
while getopts "c:d:h" flag; do
  case "${flag}" in
    c) VC_COUNT=${OPTARG};;
    d) DEBUG_LEVEL=${OPTARG};;
    h)
        echo "usage: $0 <options>"
        echo " options:"
        echo "   -c: VC_COUNT default: 1"
        echo "   -d: DEBUG_LEVEL default: info"
        echo "   -h: this help"
        exit
        ;;
  esac
done

VC_COUNT=${VC_COUNT:-1}
DEBUG_LEVEL=${DEBUG_LEVEL:-info}

if (( $VC_COUNT > $NODE_COUNT )); then
    echo "Error $VC_COUNT is too large, must be <= NODE_COUNT=$NODE_COUNT"
    exit
fi

# Init some constants
PID_FILE=$TESTNET_DIR/PIDS.pid
LOG_DIR=$TESTNET_DIR

# Stop local testnet and remove $PID_FILE
./stop_local_testnet.sh

# Clean $DATADIR and create empty log files so the
# user can "tail -f" right after starting this script
# even before its done.
./clean.sh
mkdir -p $LOG_DIR
for (( node=1; node<=$NODE_COUNT; node++ )); do
    touch $LOG_DIR/becacon_node_$node.log
done
for (( vc=1; vc<=$VC_COUNT; vc++ )); do
    touch $LOG_DIR/validator_node_$vc.log
done 

# Sleep with a message
sleeping() {
   echo sleeping $1
   sleep $1
}

# Execute the command with logs saved to a file.
#
# First parameter is log file name
# Second parameter is executable name
# Remaining parameters are passed to executable
execute_command() {
    LOG_NAME=$1
    EX_NAME=$2
    shift
    shift
    CMD="$EX_NAME $@ &>> $LOG_DIR/$LOG_NAME"
    echo "executing: $CMD"
    echo "$CMD" > "$LOG_DIR/$LOG_NAME"
    eval "$CMD &"
}

# Execute the command with logs saved to a file
# and is PID is saved to $PID_FILE.
#
# First parameter is log file name
# Second parameter is executable name
# Remaining parameters are passed to executable
execute_command_add_PID() {
    execute_command $@
    echo "$!" >> $PID_FILE
}

# Start ganache-cli, setup things up and start the bootnode.
# The delays are necessary, hopefully there is a better way :(

# Delay to let ganache-cli to get started
execute_command_add_PID ganache_test_node.log ./ganache_test_node.sh
sleeping 2

# Delay to get data setup
execute_command setup.log ./setup.sh
sleeping 15

# Delay to let boot_enr.yaml to be created
execute_command_add_PID bootnode.log ./bootnode.sh
sleeping 1

# Start beacon nodes
BN_udp_tcp_base=9000
BN_http_port_base=8000

for (( node=1; node<=$NODE_COUNT; node++ )); do
    execute_command_add_PID becacon_node_$node.log ./beacon_node.sh $DATADIR/node_$node $((BN_udp_tcp_base + $node)) $((BN_http_port_base + $node)) $DEBUG_LEVEL
done

# Start requested number of validator clients
for (( vc=1; vc<=$VC_COUNT; vc++ )); do
    execute_command_add_PID validator_node_$vc.log ./validator_client.sh $DATADIR/node_$vc http://localhost:$((BN_http_port_base + $vc)) $DEBUG_LEVEL
done

echo "Started!"
