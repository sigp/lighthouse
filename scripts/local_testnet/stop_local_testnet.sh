#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ENCLAVE_NAME=${1:-local-testnet}
LOGS_PATH=$SCRIPT_DIR/logs/$ENCLAVE_NAME

rm -rf $LOGS_PATH
mkdir -p $LOGS_PATH
kurtosis enclave dump $ENCLAVE_NAME $LOGS_PATH
echo "Local testnet logs stored to $LOGS_PATH."

kurtosis enclave rm -f $ENCLAVE_NAME
echo "Local testnet stopped."
