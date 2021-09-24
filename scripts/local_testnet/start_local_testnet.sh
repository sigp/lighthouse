#!/usr/bin/env bash
# Start all processes necessary to create a local testnet

source ./vars.env

# VC_COUNT is defaulted in vars.env
DEBUG_LEVEL=${DEBUG_LEVEL:-info}

# Get options
while getopts "v:d:h" flag; do
  case "${flag}" in
    v) VC_COUNT=${OPTARG};;
    d) DEBUG_LEVEL=${OPTARG};;
    h)
        validators=$(( $VALIDATOR_COUNT / $BN_COUNT ))
        echo "Start local testnet, defaults: 1 eth1 node, $BN_COUNT beacon nodes,"
        echo "and $VC_COUNT validator clients with each vc having $validators validators."
        echo
        echo "usage: $0 <Options>"
        echo
        echo "Options:"
        echo "   -v: VC_COUNT    default: $VC_COUNT"
        echo "   -d: DEBUG_LEVEL default: info"
        echo "   -h:             this help"
        exit
        ;;
  esac
done

if (( $VC_COUNT > $BN_COUNT )); then
    echo "Error $VC_COUNT is too large, must be <= BN_COUNT=$BN_COUNT"
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
for (( bn=1; bn<=$BN_COUNT; bn++ )); do
    touch $LOG_DIR/beacon_node_$bn.log
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

(( $VC_COUNT < $BN_COUNT )) && SAS=-s || SAS=

for (( bn=1; bn<=$BN_COUNT; bn++ )); do
    execute_command_add_PID beacon_node_$bn.log ./beacon_node.sh $SAS -d $DEBUG_LEVEL $DATADIR/node_$bn $((BN_udp_tcp_base + $bn)) $((BN_http_port_base + $bn))
done

# Start requested number of validator clients
for (( vc=1; vc<=$VC_COUNT; vc++ )); do
    execute_command_add_PID validator_node_$vc.log ./validator_client.sh $DATADIR/node_$vc http://localhost:$((BN_http_port_base + $vc)) $DEBUG_LEVEL
done

echo "Started!"
