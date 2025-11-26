#!/usr/bin/env bash
#
# Checkpoint sync to a live network.
#
# Start with checkpoint sync and let the node(s) sync to head and perform backfill for a specified number of slots.
# This test ensures we cover all sync components (range, lookup, backfill) and measures sync speed
# to detect any performance regressions.
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

ENCLAVE_NAME=${1:-sync-testnet}
CONFIG=${2:-$SCRIPT_DIR/checkpoint-sync-config-sepolia.yaml}

# Test configuration
# ------------------------------------------------------
# Interval for polling the /lighthouse/syncing endpoint for sync status
POLL_INTERVAL_SECS=5
# Target number of slots to backfill to complete this test.
TARGET_BACKFILL_SLOTS=256
# Timeout for this test, if the node(s) fail to backfill `TARGET_BACKFILL_SLOTS` slots, fail the test.
TIMEOUT_MINS=10
TIMEOUT_SECS=$((TIMEOUT_MINS * 60))
# ------------------------------------------------------

# Polls a single node's sync status
poll_node() {
  local node_type=$1
  local url=${node_urls[$node_type]}

  response=$(curl -s "${url}/lighthouse/syncing")

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
  fi

  # Check for completion criteria
  if [ "$status" = "BackFillSyncing" ]; then
    completed=$(echo "$response" | jq -r ".data.${status}.completed // 0")
    if [ "$completed" -ge "$TARGET_BACKFILL_SLOTS" ]; then
      mark_node_complete "$node_type"
    fi
  fi
  # For other states (Synced, SyncingFinalized, SyncingHead, SyncTransition, Stalled, Unknown),
  # we continue polling
  # NOTE: there is a bug where Lighthouse briefly switch to "Synced" before completing backfilling. We ignore this state
  # as it's unlikely a node is fully synced without going through backfilling `TARGET_BACKFILL_SLOTS` slots (only
  # possible on a new network).
}

# Marks a node as complete and record time
mark_node_complete() {
  local node_type=$1
  if [ "${node_completed[$node_type]}" = false ]; then
    node_completed[$node_type]=true
    node_complete_time[$node_type]=$(date +%s)
    echo "${node_type} completed backfill in $((node_complete_time[$node_type] - start_time)) seconds"
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

start_time=$(date +%s)

# Get all beacon API URLs
supernode_url=$(kurtosis port print $ENCLAVE_NAME cl-1-lighthouse-geth http)
fullnode_url=$(kurtosis port print $ENCLAVE_NAME cl-2-lighthouse-geth http)

# Initialize statuses
declare -A node_completed
declare -A node_complete_time
declare -A node_urls

node_urls["supernode"]="$supernode_url"
node_urls["fullnode"]="$fullnode_url"
node_completed["supernode"]=false
node_completed["fullnode"]=false

echo "Polling sync status until backfill reaches ${TARGET_BACKFILL_SLOTS} slots or timeout of ${TIMEOUT_MINS} mins"

# while [ "${node_completed[supernode]}" = false ] || [ "${node_completed[fullnode]}" = false ]; do
while [ "${node_completed[fullnode]}" = false ]; do
  current_time=$(date +%s)
  elapsed=$((current_time - start_time))

  if [ "$elapsed" -ge "$TIMEOUT_SECS" ]; then
    echo "ERROR: Nodes timed out syncing after ${TIMEOUT_MINS} minutes. Exiting."
    exit_and_dump_logs 1
  fi

  # Poll each node that hasn't completed yet
  # for node in "supernode" "fullnode"; do
  for node in "fullnode"; do
    if [ "${node_completed[$node]}" = false ]; then
      poll_node "$node"
    fi
  done

  sleep $POLL_INTERVAL_SECS
done

echo "Sync test complete! Fullnode has synced to HEAD and backfilled ${TARGET_BACKFILL_SLOTS} slots."
# echo "Supernode time: $((node_complete_time[supernode] - start_time)) seconds"
echo "Fullnode time: $((node_complete_time[fullnode] - start_time)) seconds"
exit_and_dump_logs 0