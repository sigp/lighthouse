#!/usr/bin/env bash
#
# Genesis sync test on a local network.
#
# Start a local testnet, shut down non-validator nodes for a period, then restart them
# and monitor their sync progress from genesis to head.
# This test ensures we cover all sync components and measures sync speed.
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

ENCLAVE_NAME=${1:-genesis-sync-testnet}
CONFIG=${2:-$SCRIPT_DIR/genesis-sync-config-electra.yaml}
FORK_TYPE=${3:-electra}  # electra or fulu

# Test configuration
# ------------------------------------------------------
# Interval for polling the /lighthouse/syncing endpoint for sync status
# Syncing to head is fast, reduce the polling time
POLL_INTERVAL_SECS=0.1
# Time to keep non-validator nodes offline (in seconds)
OFFLINE_DURATION_SECS=120
# Target number of slots to sync to complete this test (will be set dynamically)
TARGET_SYNC_SLOTS=100
# Timeout for this test, if the nodes fail to sync, fail the test.
TIMEOUT_MINS=15
TIMEOUT_SECS=$((TIMEOUT_MINS * 60))
# ------------------------------------------------------

# Determine config file based on fork type
if [ "$FORK_TYPE" = "fulu" ]; then
    CONFIG=${CONFIG/electra/fulu}
fi

# Polls a single node's sync status
poll_node() {
  local node_type=$1
  local url=${node_urls[$node_type]}

  response=$(curl -s "${url}/lighthouse/syncing" 2>/dev/null)

  if [ -z "$response" ] || [ "$response" = "null" ]; then
    echo "${node_type} status: No response or null response"
    return
  fi
  
  # Print syncing status
  sync_state=$(echo "$response" | jq -r 'if (.data | type) == "object" then "object" else "string" end' 2>/dev/null)

  if [ "$sync_state" = "object" ]; then
    status=$(echo "$response" | jq -r '.data | keys[0] // "Unknown"')
    fields=$(echo "$response" | jq -r ".data.${status} | to_entries | map(\"\(.key): \(.value)\") | join(\", \")")
    echo "${node_type} status: ${status}, ${fields}"
  else
    status=$(echo "$response" | jq -r '.data' 2>/dev/null)
    echo "${node_type} status: ${status:-Unknown}"
    
    # The test is complete when the node is synced
    if [ "$status" = "Synced" ]; then
      mark_node_complete "$node_type"
    fi
  fi
}

# Marks a node as complete and record time
mark_node_complete() {
  local node_type=$1
  if [ "${node_completed[$node_type]}" = false ]; then
    node_completed[$node_type]=true
    node_complete_time[$node_type]=$(date +%s)
    echo "${node_type} completed sync in $((node_complete_time[$node_type] - sync_start_time)) seconds"
  fi
}

exit_and_dump_logs() {
    local exit_code=$1
    echo "Shutting down..."
    $SCRIPT_DIR/../local_testnet/stop_local_testnet.sh $ENCLAVE_NAME
    echo "Test completed with exit code $exit_code."
    exit $exit_code
}

# Start the nodes
$SCRIPT_DIR/../local_testnet/start_local_testnet.sh -e $ENCLAVE_NAME -b false -n $CONFIG
if [ $? -ne 0 ]; then
  echo "Failed to start local testnet"
  exit_and_dump_logs 1
fi

# Wait for 10s before stopping non-validating nodes
sleep 10

# These are non validating nodes
supernode="cl-3-lighthouse-geth"
fullnode="cl-4-lighthouse-geth"

# Stop the non-validator nodes
kurtosis service stop $ENCLAVE_NAME $supernode
kurtosis service stop $ENCLAVE_NAME $fullnode

echo "Non-validator nodes stopped. Waiting ${OFFLINE_DURATION_SECS} seconds..."

# Display the time every 10s when the nodes are stopped
remaining_time=$OFFLINE_DURATION_SECS
while [ $remaining_time -gt 0 ]; do
    sleep 10
    remaining_time=$((remaining_time - 10))
    echo "Nodes are stopped for $((OFFLINE_DURATION_SECS - remaining_time))s, ${remaining_time}s remains..."
done

echo "Resuming non-validator nodes..."

# Resume the non validating nodes
kurtosis service start $ENCLAVE_NAME $supernode
kurtosis service start $ENCLAVE_NAME $fullnode

# The time at which syncing starts after the node was stopped
sync_start_time=$(date +%s)

# Get beacon API URLs for non validating nodes for query
supernode_url=$(kurtosis port print $ENCLAVE_NAME $supernode http)
fullnode_url=$(kurtosis port print $ENCLAVE_NAME $fullnode http)

# Initialize statuses
declare -A node_completed
declare -A node_complete_time
declare -A node_urls

node_urls["supernode"]="$supernode_url"
node_urls["fullnode"]="$fullnode_url"
node_completed["supernode"]=false
node_completed["fullnode"]=false

echo "Polling sync status until backfill reaches ${TARGET_BACKFILL_SLOTS} slots or timeout of ${TIMEOUT_MINS} mins"

while [ "${node_completed[supernode]}" = false ] || [ "${node_completed[fullnode]}" = false ]; do
  current_time=$(date +%s)
  elapsed=$((current_time - sync_start_time))

  if [ "$elapsed" -ge "$TIMEOUT_SECS" ]; then
    echo "ERROR: Nodes timed out syncing after ${TIMEOUT_MINS} minutes. Exiting."
    exit_and_dump_logs 1
  fi

  # Poll each node that hasn't completed yet
  for node in "supernode" "fullnode"; do
    if [ "${node_completed[$node]}" = false ]; then
      poll_node "$node"
    fi
  done

  sleep $POLL_INTERVAL_SECS
done

echo "Genesis sync test complete! Both supernode and fullnode have synced successfully."
echo "Supernode time: $((node_complete_time[supernode] - sync_start_time)) seconds"
echo "Fullnode time: $((node_complete_time[fullnode] - sync_start_time)) seconds"
exit_and_dump_logs 0