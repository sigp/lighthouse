#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ENCLAVE_NAME=${1:-local-testnet}
LOGS_PATH=$SCRIPT_DIR/logs
LOGS_SUBDIR=$LOGS_PATH/$ENCLAVE_NAME

# Delete existing logs directory and make sure parent directory exists.
rm -rf $LOGS_SUBDIR && mkdir -p $LOGS_PATH
kurtosis enclave dump $ENCLAVE_NAME $LOGS_SUBDIR
echo "Local testnet logs stored to $LOGS_SUBDIR."

kurtosis enclave rm -f $ENCLAVE_NAME
echo "Local testnet stopped."
