use crate::Work;
use logging::TimeLatch;
use std::collections::VecDeque;
use tracing::error;
use types::{BeaconState, ChainSpec, EthSpec, RelativeEpoch};

/// Over-provision queues based on active validator count by some factor. The beacon chain has
/// strict churns that prevent the validator set size from changing rapidly. By over-provisioning
/// slightly, we don't need to adjust the queues during the lifetime of a process.
const ACTIVE_VALIDATOR_COUNT_OVERPROVISION_PERCENT: usize = 110;

/// Minimum size of dynamically sized queues. Due to integer division we don't want 0 length queues
/// as the processor won't process that message type. 128 is an arbitrary value value >= 1 that
/// seems reasonable.
const MIN_QUEUE_LEN: usize = 128;

/// A simple first-in-first-out queue with a maximum length.
pub struct FifoQueue<T> {
    queue: VecDeque<T>,
    max_length: usize,
}

impl<T> FifoQueue<T> {
    /// Create a new, empty queue with the given length.
    pub fn new(max_length: usize) -> Self {
        Self {
            queue: VecDeque::default(),
            max_length,
        }
    }

    /// Add a new item to the queue.
    ///
    /// Drops `item` if the queue is full.
    pub fn push(&mut self, item: T, item_desc: &str) {
        if self.queue.len() == self.max_length {
            error!(
                queue = item_desc,
                queue_len = self.max_length,
                msg = "the system has insufficient resources for load",
                "Work queue is full",
            )
        } else {
            self.queue.push_back(item);
        }
    }

    /// Remove the next item from the queue.
    pub fn pop(&mut self) -> Option<T> {
        self.queue.pop_front()
    }

    /// Returns the current length of the queue.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// A simple last-in-first-out queue with a maximum length.
pub struct LifoQueue<T> {
    queue: VecDeque<T>,
    pub max_length: usize,
}

impl<T> LifoQueue<T> {
    /// Create a new, empty queue with the given length.
    pub fn new(max_length: usize) -> Self {
        Self {
            queue: VecDeque::default(),
            max_length,
        }
    }

    /// Add a new item to the front of the queue.
    ///
    /// If the queue is full, the item at the back of the queue is dropped.
    pub fn push(&mut self, item: T) {
        if self.queue.len() == self.max_length {
            self.queue.pop_back();
        }
        self.queue.push_front(item);
    }

    /// Remove the next item from the queue.
    pub fn pop(&mut self) -> Option<T> {
        self.queue.pop_front()
    }

    /// Returns `true` if the queue is full.
    pub fn is_full(&self) -> bool {
        self.queue.len() >= self.max_length
    }

    /// Returns the current length of the queue.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// Maximum number of queued items that will be stored before dropping them
pub struct BeaconProcessorQueueLengths {
    aggregate_queue: usize,
    attestation_queue: usize,
    unknown_block_aggregate_queue: usize,
    unknown_block_attestation_queue: usize,
    sync_message_queue: usize,
    sync_contribution_queue: usize,
    gossip_voluntary_exit_queue: usize,
    gossip_proposer_slashing_queue: usize,
    gossip_attester_slashing_queue: usize,
    unknown_light_client_update_queue: usize,
    rpc_block_queue: usize,
    rpc_blob_queue: usize,
    rpc_custody_column_queue: usize,
    column_reconstruction_queue: usize,
    chain_segment_queue: usize,
    backfill_chain_segment: usize,
    gossip_block_queue: usize,
    gossip_blob_queue: usize,
    gossip_data_column_queue: usize,
    delayed_block_queue: usize,
    status_queue: usize,
    block_brange_queue: usize,
    block_broots_queue: usize,
    blob_broots_queue: usize,
    blob_brange_queue: usize,
    dcbroots_queue: usize,
    dcbrange_queue: usize,
    gossip_bls_to_execution_change_queue: usize,
    gossip_execution_payload_queue: usize,
    gossip_execution_payload_bid_queue: usize,
    gossip_payload_attestation_queue: usize,
    gossip_proposer_preferences_queue: usize,
    lc_bootstrap_queue: usize,
    lc_rpc_optimistic_update_queue: usize,
    lc_rpc_finality_update_queue: usize,
    lc_gossip_finality_update_queue: usize,
    lc_gossip_optimistic_update_queue: usize,
    lc_update_range_queue: usize,
    api_request_p0_queue: usize,
    api_request_p1_queue: usize,
}

impl BeaconProcessorQueueLengths {
    pub fn from_state<E: EthSpec>(
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<Self, String> {
        let active_validator_count =
            match state.get_cached_active_validator_indices(RelativeEpoch::Current) {
                Ok(indices) => indices.len(),
                Err(_) => state
                    .get_active_validator_indices(state.current_epoch(), spec)
                    .map_err(|e| format!("Error computing active indices: {:?}", e))?
                    .len(),
            };
        let active_validator_count =
            (ACTIVE_VALIDATOR_COUNT_OVERPROVISION_PERCENT * active_validator_count) / 100;
        let slots_per_epoch = E::slots_per_epoch() as usize;

        Ok(Self {
            aggregate_queue: 4096,
            unknown_block_aggregate_queue: 1024,
            // Capacity for a full slot's worth of attestations if subscribed to all subnets
            attestation_queue: std::cmp::max(
                active_validator_count / slots_per_epoch,
                MIN_QUEUE_LEN,
            ),
            // Capacity for a full slot's worth of attestations if subscribed to all subnets
            unknown_block_attestation_queue: std::cmp::max(
                active_validator_count / slots_per_epoch,
                MIN_QUEUE_LEN,
            ),
            sync_message_queue: 2048,
            sync_contribution_queue: 1024,
            gossip_voluntary_exit_queue: 4096,
            gossip_proposer_slashing_queue: 4096,
            gossip_attester_slashing_queue: 4096,
            unknown_light_client_update_queue: 128,
            rpc_block_queue: 1024,
            rpc_blob_queue: 1024,
            // We don't request more than `PARENT_DEPTH_TOLERANCE` (32) lookups, so we can limit
            // this queue size. With 48 max blobs per block, each column sidecar list could be up to 12MB.
            rpc_custody_column_queue: 64,
            column_reconstruction_queue: 1,
            chain_segment_queue: 64,
            backfill_chain_segment: 64,
            gossip_block_queue: 1024,
            gossip_blob_queue: 1024,
            gossip_data_column_queue: 1024,
            delayed_block_queue: 1024,
            status_queue: 1024,
            block_brange_queue: 1024,
            block_broots_queue: 1024,
            blob_broots_queue: 1024,
            blob_brange_queue: 1024,
            dcbroots_queue: 1024,
            dcbrange_queue: 1024,
            gossip_bls_to_execution_change_queue: 16384,
            // TODO(EIP-7732): verify 1024 is preferable. I used same value as `gossip_block_queue` and `gossip_blob_queue`
            gossip_execution_payload_queue: 1024,
            // TODO(EIP-7732) how big should this queue be?
            gossip_execution_payload_bid_queue: 1024,
            // PTC size ~512 per slot, buffer 2-3 slots for reorgs and processing delays (512 * 3 = 1536)
            // TODO(EIP-7732): verify if this is preferable queue length or otherwise
            gossip_payload_attestation_queue: 1536,
            // TODO(EIP-7732): verify if this is preferable queue length
            gossip_proposer_preferences_queue: 1024,
            lc_gossip_finality_update_queue: 1024,
            lc_gossip_optimistic_update_queue: 1024,
            lc_bootstrap_queue: 1024,
            lc_rpc_optimistic_update_queue: 512,
            lc_rpc_finality_update_queue: 512,
            lc_update_range_queue: 512,
            api_request_p0_queue: 1024,
            api_request_p1_queue: 1024,
        })
    }
}

pub struct WorkQueues<E: EthSpec> {
    pub aggregate_queue: LifoQueue<Work<E>>,
    pub aggregate_debounce: TimeLatch,
    pub attestation_queue: LifoQueue<Work<E>>,
    pub attestation_to_convert_queue: LifoQueue<Work<E>>,
    pub attestation_debounce: TimeLatch,
    pub unknown_block_aggregate_queue: LifoQueue<Work<E>>,
    pub unknown_block_attestation_queue: LifoQueue<Work<E>>,
    pub sync_message_queue: LifoQueue<Work<E>>,
    pub sync_contribution_queue: LifoQueue<Work<E>>,
    pub gossip_voluntary_exit_queue: FifoQueue<Work<E>>,
    pub gossip_proposer_slashing_queue: FifoQueue<Work<E>>,
    pub gossip_attester_slashing_queue: FifoQueue<Work<E>>,
    pub unknown_light_client_update_queue: FifoQueue<Work<E>>,
    pub rpc_block_queue: FifoQueue<Work<E>>,
    pub rpc_blob_queue: FifoQueue<Work<E>>,
    pub rpc_custody_column_queue: FifoQueue<Work<E>>,
    pub column_reconstruction_queue: LifoQueue<Work<E>>,
    pub chain_segment_queue: FifoQueue<Work<E>>,
    pub backfill_chain_segment: FifoQueue<Work<E>>,
    pub gossip_block_queue: FifoQueue<Work<E>>,
    pub gossip_blob_queue: FifoQueue<Work<E>>,
    pub gossip_data_column_queue: FifoQueue<Work<E>>,
    pub delayed_block_queue: FifoQueue<Work<E>>,
    pub status_queue: FifoQueue<Work<E>>,
    pub block_brange_queue: FifoQueue<Work<E>>,
    pub block_broots_queue: FifoQueue<Work<E>>,
    pub blob_broots_queue: FifoQueue<Work<E>>,
    pub blob_brange_queue: FifoQueue<Work<E>>,
    pub dcbroots_queue: FifoQueue<Work<E>>,
    pub dcbrange_queue: FifoQueue<Work<E>>,
    pub gossip_bls_to_execution_change_queue: FifoQueue<Work<E>>,
    pub gossip_execution_payload_queue: FifoQueue<Work<E>>,
    pub gossip_execution_payload_bid_queue: FifoQueue<Work<E>>,
    pub gossip_payload_attestation_queue: FifoQueue<Work<E>>,
    pub gossip_proposer_preferences_queue: FifoQueue<Work<E>>,
    pub lc_gossip_finality_update_queue: FifoQueue<Work<E>>,
    pub lc_gossip_optimistic_update_queue: FifoQueue<Work<E>>,
    pub lc_bootstrap_queue: FifoQueue<Work<E>>,
    pub lc_rpc_optimistic_update_queue: FifoQueue<Work<E>>,
    pub lc_rpc_finality_update_queue: FifoQueue<Work<E>>,
    pub lc_update_range_queue: FifoQueue<Work<E>>,
    pub api_request_p0_queue: FifoQueue<Work<E>>,
    pub api_request_p1_queue: FifoQueue<Work<E>>,
}

impl<E: EthSpec> WorkQueues<E> {
    pub fn new(queue_lengths: BeaconProcessorQueueLengths) -> Self {
        // Using LIFO queues for attestations since validator profits rely upon getting fresh
        // attestations into blocks. Additionally, later attestations contain more information than
        // earlier ones, so we consider them more valuable.
        let aggregate_queue = LifoQueue::new(queue_lengths.aggregate_queue);
        let aggregate_debounce = TimeLatch::default();
        let attestation_queue = LifoQueue::new(queue_lengths.attestation_queue);
        let attestation_to_convert_queue = LifoQueue::new(queue_lengths.attestation_queue);
        let attestation_debounce = TimeLatch::default();
        let unknown_block_aggregate_queue =
            LifoQueue::new(queue_lengths.unknown_block_aggregate_queue);
        let unknown_block_attestation_queue =
            LifoQueue::new(queue_lengths.unknown_block_attestation_queue);

        let sync_message_queue = LifoQueue::new(queue_lengths.sync_message_queue);
        let sync_contribution_queue = LifoQueue::new(queue_lengths.sync_contribution_queue);

        // Using a FIFO queue for voluntary exits since it prevents exit censoring. I don't have
        // a strong feeling about queue type for exits.
        let gossip_voluntary_exit_queue = FifoQueue::new(queue_lengths.gossip_voluntary_exit_queue);

        // Using a FIFO queue for slashing to prevent people from flushing their slashings from the
        // queues with lots of junk messages.
        let gossip_proposer_slashing_queue =
            FifoQueue::new(queue_lengths.gossip_proposer_slashing_queue);
        let gossip_attester_slashing_queue =
            FifoQueue::new(queue_lengths.gossip_attester_slashing_queue);

        // Using a FIFO queue for light client updates to maintain sequence order.
        let unknown_light_client_update_queue =
            FifoQueue::new(queue_lengths.unknown_light_client_update_queue);
        // Using a FIFO queue since blocks need to be imported sequentially.
        let rpc_block_queue = FifoQueue::new(queue_lengths.rpc_block_queue);
        let rpc_blob_queue = FifoQueue::new(queue_lengths.rpc_blob_queue);
        let rpc_custody_column_queue = FifoQueue::new(queue_lengths.rpc_custody_column_queue);
        let column_reconstruction_queue = LifoQueue::new(queue_lengths.column_reconstruction_queue);
        let chain_segment_queue = FifoQueue::new(queue_lengths.chain_segment_queue);
        let backfill_chain_segment = FifoQueue::new(queue_lengths.backfill_chain_segment);
        let gossip_block_queue = FifoQueue::new(queue_lengths.gossip_block_queue);
        let gossip_blob_queue = FifoQueue::new(queue_lengths.gossip_blob_queue);
        let gossip_data_column_queue = FifoQueue::new(queue_lengths.gossip_data_column_queue);
        let delayed_block_queue = FifoQueue::new(queue_lengths.delayed_block_queue);

        let status_queue = FifoQueue::new(queue_lengths.status_queue);
        let block_brange_queue = FifoQueue::new(queue_lengths.block_brange_queue);
        let block_broots_queue = FifoQueue::new(queue_lengths.block_broots_queue);
        let blob_broots_queue = FifoQueue::new(queue_lengths.blob_broots_queue);
        let blob_brange_queue = FifoQueue::new(queue_lengths.blob_brange_queue);
        let dcbroots_queue = FifoQueue::new(queue_lengths.dcbroots_queue);
        let dcbrange_queue = FifoQueue::new(queue_lengths.dcbrange_queue);

        let gossip_bls_to_execution_change_queue =
            FifoQueue::new(queue_lengths.gossip_bls_to_execution_change_queue);

        let gossip_execution_payload_queue =
            FifoQueue::new(queue_lengths.gossip_execution_payload_queue);
        let gossip_execution_payload_bid_queue =
            FifoQueue::new(queue_lengths.gossip_execution_payload_bid_queue);
        let gossip_payload_attestation_queue =
            FifoQueue::new(queue_lengths.gossip_payload_attestation_queue);
        let gossip_proposer_preferences_queue =
            FifoQueue::new(queue_lengths.gossip_proposer_preferences_queue);

        let lc_gossip_optimistic_update_queue =
            FifoQueue::new(queue_lengths.lc_gossip_optimistic_update_queue);
        let lc_gossip_finality_update_queue =
            FifoQueue::new(queue_lengths.lc_gossip_finality_update_queue);
        let lc_bootstrap_queue = FifoQueue::new(queue_lengths.lc_bootstrap_queue);
        let lc_rpc_optimistic_update_queue =
            FifoQueue::new(queue_lengths.lc_rpc_optimistic_update_queue);
        let lc_rpc_finality_update_queue =
            FifoQueue::new(queue_lengths.lc_rpc_finality_update_queue);
        let lc_update_range_queue: FifoQueue<Work<E>> =
            FifoQueue::new(queue_lengths.lc_update_range_queue);

        let api_request_p0_queue = FifoQueue::new(queue_lengths.api_request_p0_queue);
        let api_request_p1_queue = FifoQueue::new(queue_lengths.api_request_p1_queue);

        WorkQueues {
            aggregate_queue,
            aggregate_debounce,
            attestation_queue,
            attestation_to_convert_queue,
            attestation_debounce,
            unknown_block_aggregate_queue,
            unknown_block_attestation_queue,
            sync_message_queue,
            sync_contribution_queue,
            gossip_voluntary_exit_queue,
            gossip_proposer_slashing_queue,
            gossip_attester_slashing_queue,
            unknown_light_client_update_queue,
            rpc_block_queue,
            rpc_blob_queue,
            rpc_custody_column_queue,
            chain_segment_queue,
            column_reconstruction_queue,
            backfill_chain_segment,
            gossip_block_queue,
            gossip_blob_queue,
            gossip_data_column_queue,
            delayed_block_queue,
            status_queue,
            block_brange_queue,
            block_broots_queue,
            blob_broots_queue,
            blob_brange_queue,
            dcbroots_queue,
            dcbrange_queue,
            gossip_bls_to_execution_change_queue,
            gossip_execution_payload_queue,
            gossip_execution_payload_bid_queue,
            gossip_payload_attestation_queue,
            gossip_proposer_preferences_queue,
            lc_gossip_optimistic_update_queue,
            lc_gossip_finality_update_queue,
            lc_bootstrap_queue,
            lc_rpc_optimistic_update_queue,
            lc_rpc_finality_update_queue,
            lc_update_range_queue,
            api_request_p0_queue,
            api_request_p1_queue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{BeaconState, ChainSpec, Eth1Data, ForkName, MainnetEthSpec};

    #[test]
    fn min_queue_len() {
        // State with no validators.
        let spec = ForkName::latest().make_genesis_spec(ChainSpec::mainnet());
        let genesis_time = 0;
        let state = BeaconState::<MainnetEthSpec>::new(genesis_time, Eth1Data::default(), &spec);
        assert_eq!(state.validators().len(), 0);
        let queue_lengths = BeaconProcessorQueueLengths::from_state(&state, &spec).unwrap();
        assert_eq!(queue_lengths.attestation_queue, MIN_QUEUE_LEN);
        assert_eq!(queue_lengths.unknown_block_attestation_queue, MIN_QUEUE_LEN);
    }
}
