#!/usr/bin/env bash
# Stop all processes that were started with start_local_testnet.sh

source ./vars.env

PID_FILE=$TESTNET_DIR/PIDS.pid
./kill_processes.sh $PID_FILE
rm -f $PID_FILE
