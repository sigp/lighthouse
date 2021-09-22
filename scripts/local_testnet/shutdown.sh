#!/usr/bin/env bash
# Shutdown the processes that were started for local testnets

source ./vars.env

PID_FILE=$TESTNET_DIR/PIDS.pid
./kill_processes.sh $PID_FILE
rm -f $PID_FILE
