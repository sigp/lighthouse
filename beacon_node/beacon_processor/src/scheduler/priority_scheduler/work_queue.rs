use std::collections::VecDeque;

use crate::Work;
use logging::TimeLatch;
use slog::{error, Logger};
use types::{BeaconState, ChainSpec, EthSpec, RelativeEpoch};

/// Over-provision queues based on active validator count by some factor. The beacon chain has
/// strict churns that prevent the validator set size from changing rapidly. By over-provisioning
/// slightly, we don't need to adjust the queues during the lifetime of a process.
const ACTIVE_VALIDATOR_COUNT_OVERPROVISION_PERCENT: usize = 110;

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
    pub fn push(&mut self, item: T, item_desc: &str, log: &Logger) {
        if self.queue.len() == self.max_length {
            error!(
                log,
                "Work queue is full";
                "msg" => "the system has insufficient resources for load",
                "queue_len" => self.max_length,
                "queue" => item_desc,
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
    finality_update_queue: usize,
    optimistic_update_queue: usize,
    unknown_light_client_update_queue: usize,
    unknown_block_sampling_request_queue: usize,
    rpc_block_queue: usize,
    rpc_blob_queue: usize,
    rpc_custody_column_queue: usize,
    rpc_verify_data_column_queue: usize,
    sampling_result_queue: usize,
    chain_segment_queue: usize,
    backfill_chain_segment: usize,
    gossip_block_queue: usize,
    gossip_blob_queue: usize,
    gossip_data_column_queue: usize,
    delayed_block_queue: usize,
    status_queue: usize,
    bbrange_queue: usize,
    bbroots_queue: usize,
    blbroots_queue: usize,
    blbrange_queue: usize,
    dcbroots_queue: usize,
    dcbrange_queue: usize,
    gossip_bls_to_execution_change_queue: usize,
    lc_bootstrap_queue: usize,
    lc_optimistic_update_queue: usize,
    lc_finality_update_queue: usize,
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
            attestation_queue: active_validator_count / slots_per_epoch,
            // Capacity for a full slot's worth of attestations if subscribed to all subnets
            unknown_block_attestation_queue: active_validator_count / slots_per_epoch,
            sync_message_queue: 2048,
            sync_contribution_queue: 1024,
            gossip_voluntary_exit_queue: 4096,
            gossip_proposer_slashing_queue: 4096,
            gossip_attester_slashing_queue: 4096,
            finality_update_queue: 1024,
            optimistic_update_queue: 1024,
            unknown_block_sampling_request_queue: 16384,
            unknown_light_client_update_queue: 128,
            rpc_block_queue: 1024,
            rpc_blob_queue: 1024,
            // TODO(das): Placeholder values
            rpc_custody_column_queue: 1000,
            rpc_verify_data_column_queue: 1000,
            sampling_result_queue: 1000,
            chain_segment_queue: 64,
            backfill_chain_segment: 64,
            gossip_block_queue: 1024,
            gossip_blob_queue: 1024,
            gossip_data_column_queue: 1024,
            delayed_block_queue: 1024,
            status_queue: 1024,
            bbrange_queue: 1024,
            bbroots_queue: 1024,
            blbroots_queue: 1024,
            blbrange_queue: 1024,
            // TODO(das): pick proper values
            dcbroots_queue: 1024,
            dcbrange_queue: 1024,
            gossip_bls_to_execution_change_queue: 16384,
            lc_bootstrap_queue: 1024,
            lc_optimistic_update_queue: 512,
            lc_finality_update_queue: 512,
            api_request_p0_queue: 1024,
            api_request_p1_queue: 1024,
        })
    }
}

pub struct WorkQueues<E: EthSpec> {
    pub aggregate_queue: LifoQueue<Work<E>>,
    pub aggregate_debounce: TimeLatch,
    pub attestation_queue: LifoQueue<Work<E>>,
    pub attestation_debounce: TimeLatch,
    pub unknown_block_aggregate_queue: LifoQueue<Work<E>>,
    pub unknown_block_attestation_queue: LifoQueue<Work<E>>,
    pub sync_message_queue: LifoQueue<Work<E>>,
    pub sync_contribution_queue: LifoQueue<Work<E>>,
    pub gossip_voluntary_exit_queue: FifoQueue<Work<E>>,
    pub gossip_proposer_slashing_queue: FifoQueue<Work<E>>,
    pub gossip_attester_slashing_queue: FifoQueue<Work<E>>,
    pub finality_update_queue: FifoQueue<Work<E>>,
    pub optimistic_update_queue: FifoQueue<Work<E>>,
    pub unknown_light_client_update_queue: FifoQueue<Work<E>>,
    pub unknown_block_sampling_request_queue: FifoQueue<Work<E>>,
    pub rpc_block_queue: FifoQueue<Work<E>>,
    pub rpc_blob_queue: FifoQueue<Work<E>>,
    pub rpc_custody_column_queue: FifoQueue<Work<E>>,
    pub rpc_verify_data_column_queue: FifoQueue<Work<E>>,
    pub sampling_result_queue: FifoQueue<Work<E>>,
    pub chain_segment_queue: FifoQueue<Work<E>>,
    pub backfill_chain_segment: FifoQueue<Work<E>>,
    pub gossip_block_queue: FifoQueue<Work<E>>,
    pub gossip_blob_queue: FifoQueue<Work<E>>,
    pub gossip_data_column_queue: FifoQueue<Work<E>>,
    pub delayed_block_queue: FifoQueue<Work<E>>,
    pub status_queue: FifoQueue<Work<E>>,
    pub bbrange_queue: FifoQueue<Work<E>>,
    pub bbroots_queue: FifoQueue<Work<E>>,
    pub blbroots_queue: FifoQueue<Work<E>>,
    pub blbrange_queue: FifoQueue<Work<E>>,
    pub dcbroots_queue: FifoQueue<Work<E>>,
    pub dcbrange_queue: FifoQueue<Work<E>>,
    pub gossip_bls_to_execution_change_queue: FifoQueue<Work<E>>,
    pub lc_bootstrap_queue: FifoQueue<Work<E>>,
    pub lc_optimistic_update_queue: FifoQueue<Work<E>>,
    pub lc_finality_update_queue: FifoQueue<Work<E>>,
    pub api_request_p0_queue: FifoQueue<Work<E>>,
    pub api_request_p1_queue: FifoQueue<Work<E>>,
}

impl<E: EthSpec> WorkQueues<E> {
    pub fn new(queue_lengths: BeaconProcessorQueueLengths) -> Self {
        let aggregate_queue = LifoQueue::new(queue_lengths.aggregate_queue);
        let aggregate_debounce = TimeLatch::default();
        let attestation_queue = LifoQueue::new(queue_lengths.attestation_queue);
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
        let finality_update_queue = FifoQueue::new(queue_lengths.finality_update_queue);
        let optimistic_update_queue = FifoQueue::new(queue_lengths.optimistic_update_queue);
        let unknown_light_client_update_queue =
            FifoQueue::new(queue_lengths.unknown_light_client_update_queue);
        let unknown_block_sampling_request_queue =
            FifoQueue::new(queue_lengths.unknown_block_sampling_request_queue);

        // Using a FIFO queue since blocks need to be imported sequentially.
        let rpc_block_queue = FifoQueue::new(queue_lengths.rpc_block_queue);
        let rpc_blob_queue = FifoQueue::new(queue_lengths.rpc_blob_queue);
        let rpc_custody_column_queue = FifoQueue::new(queue_lengths.rpc_custody_column_queue);
        let rpc_verify_data_column_queue =
            FifoQueue::new(queue_lengths.rpc_verify_data_column_queue);
        let sampling_result_queue = FifoQueue::new(queue_lengths.sampling_result_queue);
        let chain_segment_queue = FifoQueue::new(queue_lengths.chain_segment_queue);
        let backfill_chain_segment = FifoQueue::new(queue_lengths.backfill_chain_segment);
        let gossip_block_queue = FifoQueue::new(queue_lengths.gossip_block_queue);
        let gossip_blob_queue = FifoQueue::new(queue_lengths.gossip_blob_queue);
        let gossip_data_column_queue = FifoQueue::new(queue_lengths.gossip_data_column_queue);
        let delayed_block_queue = FifoQueue::new(queue_lengths.delayed_block_queue);

        let status_queue = FifoQueue::new(queue_lengths.status_queue);
        let bbrange_queue = FifoQueue::new(queue_lengths.bbrange_queue);
        let bbroots_queue = FifoQueue::new(queue_lengths.bbroots_queue);
        let blbroots_queue = FifoQueue::new(queue_lengths.blbroots_queue);
        let blbrange_queue = FifoQueue::new(queue_lengths.blbrange_queue);
        let dcbroots_queue = FifoQueue::new(queue_lengths.dcbroots_queue);
        let dcbrange_queue = FifoQueue::new(queue_lengths.dcbrange_queue);

        let gossip_bls_to_execution_change_queue =
            FifoQueue::new(queue_lengths.gossip_bls_to_execution_change_queue);

        let lc_bootstrap_queue = FifoQueue::new(queue_lengths.lc_bootstrap_queue);
        let lc_optimistic_update_queue = FifoQueue::new(queue_lengths.lc_optimistic_update_queue);
        let lc_finality_update_queue = FifoQueue::new(queue_lengths.lc_finality_update_queue);

        let api_request_p0_queue = FifoQueue::new(queue_lengths.api_request_p0_queue);
        let api_request_p1_queue = FifoQueue::new(queue_lengths.api_request_p1_queue);

        WorkQueues {
            aggregate_queue,
            aggregate_debounce,
            attestation_queue,
            attestation_debounce,
            unknown_block_aggregate_queue,
            unknown_block_attestation_queue,
            sync_message_queue,
            sync_contribution_queue,
            gossip_voluntary_exit_queue,
            gossip_proposer_slashing_queue,
            gossip_attester_slashing_queue,
            finality_update_queue,
            optimistic_update_queue,
            unknown_light_client_update_queue,
            unknown_block_sampling_request_queue,
            rpc_block_queue,
            rpc_blob_queue,
            rpc_custody_column_queue,
            rpc_verify_data_column_queue,
            sampling_result_queue,
            chain_segment_queue,
            backfill_chain_segment,
            gossip_block_queue,
            gossip_blob_queue,
            gossip_data_column_queue,
            delayed_block_queue,
            status_queue,
            bbrange_queue,
            bbroots_queue,
            blbroots_queue,
            blbrange_queue,
            dcbroots_queue,
            dcbrange_queue,
            gossip_bls_to_execution_change_queue,
            lc_bootstrap_queue,
            lc_optimistic_update_queue,
            lc_finality_update_queue,
            api_request_p0_queue,
            api_request_p1_queue,
        }
    }
}
