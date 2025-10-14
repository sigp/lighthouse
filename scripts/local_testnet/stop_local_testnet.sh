#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ENCLAVE_NAME=${1:-local-testnet}
LOGS_PATH=$SCRIPT_DIR/logs
LOGS_SUBDIR=$LOGS_PATH/$ENCLAVE_NAME

# Extract the service names of Lighthouse beacon nodes that start with "cl-".
services=$(kurtosis enclave inspect "$ENCLAVE_NAME" | awk '/^=+ User Services =+$/ { in_section=1; next }
                                              /^=+/ { in_section=0 }
                                              in_section && /^[0-9a-f]{12}/ { print $2 }' | grep '^cl-')

# Store logs (including dependency logs) to Kurtosis Files Artifacts. These are downloaded locally by `kurtosis enclave dump`.
for service in $services; do
  kurtosis files storeservice --name "$service-logs" "$ENCLAVE_NAME" "$service" /data/lighthouse/beacon-data/beacon/logs/
done

# Delete existing logs directory and make sure parent directory exists.
rm -rf $LOGS_SUBDIR && mkdir -p $LOGS_PATH
kurtosis enclave dump $ENCLAVE_NAME $LOGS_SUBDIR
echo "Local testnet logs stored to $LOGS_SUBDIR."
echo "The lighthouse beacon nodes' logs (including dependency logs) can be found in $LOGS_SUBDIR/files/cl-*-lighthouse-geth-logs."

kurtosis enclave rm -f $ENCLAVE_NAME
kurtosis engine stop
echo "Local testnet stopped."
