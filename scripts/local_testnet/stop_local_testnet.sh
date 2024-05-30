#!/usr/bin/env bash
set -Eeuo pipefail

ENCLAVE_NAME=local-testnet
LOGS_PATH=logs

rm -rf $LOGS_PATH

kurtosis enclave dump $ENCLAVE_NAME $LOGS_PATH
echo "Local testnet logs stored to $LOGS_PATH."

kurtosis enclave rm -f $ENCLAVE_NAME
echo "Local testnet stopped."
