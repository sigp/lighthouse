#!/usr/bin/env bash
#
# Checkpoint sync to a live network (Sepolia).
#
# Start with checkpoint sync and let the node(s) sync to head and perform backfill for a specified number of slots.
# This test ensures we cover all sync components (range, lookup, backfill) and measures sync speed
# to detect any performance regressions.
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ENCLAVE_NAME=sync-testnet
CONFIG=$SCRIPT_DIR/checkpoint-sync-config.yaml
POLL_INTERVAL_SECS=5
TARGET_BACKFILL_SLOTS=256
TIMEOUT_MINS=10
TIMEOUT_SECS=$((TIMEOUT_MINS * 60))
start_time=$(date +%s)

# Start the nodes
kurtosis run github.com/ethpandaops/ethereum-package --enclave "$ENCLAVE_NAME" --args-file "$CONFIG" \
  --image-download always --non-blocking-tasks

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

# Polls a single node's sync status
poll_node() {
  local node_type=$1
  local url=${node_urls[$node_type]}

  response=$(curl -s "${url}/lighthouse/syncing")
  status=$(echo "$response" | jq -r '.data | keys[0] // "Unknown"')

  # Print syncing status
  if [ "$status" != "null" ] && [ "$status" != "Unknown" ]; then
    fields=$(echo "$response" | jq -r ".data.${status} | to_entries | map(\"\(.key): \(.value)\") | join(\", \")")
    echo "${node_type} status: ${status}, ${fields}"
  else
    echo "${node_type} status: Unknown sync state"
  fi

  # Check for completion criteria
  if [ "$status" = "BackFillSyncing" ]; then
    completed=$(echo "$response" | jq -r ".data.${status}.completed")
    if [ "$completed" -ge "$TARGET_BACKFILL_SLOTS" ]; then
      mark_node_complete "$node_type"
    fi
  elif [ "$status" = "Synced" ]; then
    mark_node_complete "$node_type"
  fi

  # For other states (SyncingFinalized, SyncingHead, SyncTransition, Stalled, Unknown),
  # we continue polling
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

while [ "${node_completed[supernode]}" = false ] || [ "${node_completed[fullnode]}" = false ]; do
  current_time=$(date +%s)
  elapsed=$((current_time - start_time))

  if [ "$elapsed" -ge "$TIMEOUT_SECS" ]; then
    echo "ERROR: Nodes timed out syncing after ${TIMEOUT_MINS} minutes. Exiting."
    exit 1
  fi

  # Poll each node that hasn't completed yet
  for node in "supernode" "fullnode"; do
    if [ "${node_completed[$node]}" = false ]; then
      poll_node "$node"
    fi
  done

  sleep $POLL_INTERVAL_SECS
done

echo "Sync test complete! Both supernode and fullnode have synced to HEAD and backfilled ${TARGET_BACKFILL_SLOTS} slots."
echo "Supernode time: $((node_complete_time[supernode] - start_time)) seconds"
echo "Fullnode time: $((node_complete_time[fullnode] - start_time)) seconds"
