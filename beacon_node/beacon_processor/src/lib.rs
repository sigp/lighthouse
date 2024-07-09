//! Provides the `BeaconProcessor`, a multi-threaded processor for messages received on the network
//! that need to be processed by the `BeaconChain`.
//!
//! Uses `tokio` tasks (instead of raw threads) to provide the following tasks:
//!
//! - A "manager" task, which either spawns worker tasks or enqueues work.
//! - One or more "worker" tasks which perform time-intensive work on the `BeaconChain`.
//! - A task managing the scheduling of work that needs to be re-processed.
//!
//! ## Purpose
//!
//! The purpose of the `BeaconProcessor` is to provide two things:
//!
//! 1. Moving long-running, blocking tasks off the main `tokio` executor.
//! 2. A fixed-length buffer for consensus messages.
//!
//! (1) ensures that we don't clog up the networking stack with long-running tasks, potentially
//! causing timeouts. (2) means that we can easily and explicitly reject messages when we're
//! overloaded and also distribute load across time.
//!
//! ## Detail
//!
//! There is a single "manager" thread who listens to three event channels. These events are
//! either:
//!
//! - A new parcel of work (work event).
//! - Indication that a worker has finished a parcel of work (worker idle).
//! - A work ready for reprocessing (work event).
//!
//! Then, there is a maximum of `n` "worker" blocking threads, where `n` is the CPU count.
//!
//! Whenever the manager receives a new parcel of work, it is either:
//!
//! - Provided to a newly-spawned worker tasks (if we are not already at `n` workers).
//! - Added to a queue.
//!
//! Whenever the manager receives a notification that a worker has finished a parcel of work, it
//! checks the queues to see if there are more parcels of work that can be spawned in a new worker
//! task.

use crate::work_reprocessing_queue::{
    QueuedBackfillBatch, QueuedGossipBlock, ReprocessQueueMessage,
};
use futures::stream::{Stream, StreamExt};
use futures::task::Poll;
use lighthouse_network::{MessageId, NetworkGlobals, PeerId};
use logging::TimeLatch;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use slog::{crit, debug, error, trace, warn, Logger};
use slot_clock::SlotClock;
use std::cmp;
use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::time::Duration;
use task_executor::TaskExecutor;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use types::{
    Attestation, BeaconState, ChainSpec, Hash256, RelativeEpoch, SignedAggregateAndProof, SubnetId,
};
use types::{EthSpec, Slot};
use work_reprocessing_queue::IgnoredRpcBlock;
use work_reprocessing_queue::{
    spawn_reprocess_scheduler, QueuedAggregate, QueuedLightClientUpdate, QueuedRpcBlock,
    QueuedUnaggregate, ReadyWork,
};

mod metrics;
pub mod work_reprocessing_queue;

/// The maximum size of the channel for work events to the `BeaconProcessor`.
///
/// Setting this too low will cause consensus messages to be dropped.
const DEFAULT_MAX_WORK_EVENT_QUEUE_LEN: usize = 16_384;

/// The maximum size of the channel for idle events to the `BeaconProcessor`.
///
/// Setting this too low will prevent new workers from being spawned. It *should* only need to be
/// set to the CPU count, but we set it high to be safe.
const MAX_IDLE_QUEUE_LEN: usize = 16_384;

/// The maximum size of the channel for re-processing work events.
const DEFAULT_MAX_SCHEDULED_WORK_QUEUE_LEN: usize = 3 * DEFAULT_MAX_WORK_EVENT_QUEUE_LEN / 4;

/// Over-provision queues based on active validator count by some factor. The beacon chain has
/// strict churns that prevent the validator set size from changing rapidly. By over-provisioning
/// slightly, we don't need to adjust the queues during the lifetime of a process.
const ACTIVE_VALIDATOR_COUNT_OVERPROVISION_PERCENT: usize = 110;

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
    rpc_block_queue: usize,
    rpc_blob_queue: usize,
    chain_segment_queue: usize,
    backfill_chain_segment: usize,
    gossip_block_queue: usize,
    gossip_blob_queue: usize,
    delayed_block_queue: usize,
    status_queue: usize,
    bbrange_queue: usize,
    bbroots_queue: usize,
    blbroots_queue: usize,
    blbrange_queue: usize,
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
            unknown_light_client_update_queue: 128,
            rpc_block_queue: 1024,
            rpc_blob_queue: 1024,
            chain_segment_queue: 64,
            backfill_chain_segment: 64,
            gossip_block_queue: 1024,
            gossip_blob_queue: 1024,
            delayed_block_queue: 1024,
            status_queue: 1024,
            bbrange_queue: 1024,
            bbroots_queue: 1024,
            blbroots_queue: 1024,
            blbrange_queue: 1024,
            gossip_bls_to_execution_change_queue: 16384,
            lc_bootstrap_queue: 1024,
            lc_optimistic_update_queue: 512,
            lc_finality_update_queue: 512,
            api_request_p0_queue: 1024,
            api_request_p1_queue: 1024,
        })
    }
}

/// The name of the manager tokio task.
const MANAGER_TASK_NAME: &str = "beacon_processor_manager";

/// The name of the worker tokio tasks.
const WORKER_TASK_NAME: &str = "beacon_processor_worker";

/// The `MAX_..._BATCH_SIZE` variables define how many attestations can be included in a single
/// batch.
///
/// Choosing these values is difficult since there is a trade-off between:
///
/// - It is faster to verify one large batch than multiple smaller batches.
/// - "Poisoning" attacks have a larger impact as the batch size increases.
///
/// Poisoning occurs when an invalid signature is included in a batch of attestations. A single
/// invalid signature causes the entire batch to fail. When a batch fails, we fall-back to
/// individually verifying each attestation signature.
const DEFAULT_MAX_GOSSIP_ATTESTATION_BATCH_SIZE: usize = 64;
const DEFAULT_MAX_GOSSIP_AGGREGATE_BATCH_SIZE: usize = 64;

/// Unique IDs used for metrics and testing.
pub const WORKER_FREED: &str = "worker_freed";
pub const NOTHING_TO_DO: &str = "nothing_to_do";
pub const GOSSIP_ATTESTATION: &str = "gossip_attestation";
pub const GOSSIP_ATTESTATION_BATCH: &str = "gossip_attestation_batch";
pub const GOSSIP_AGGREGATE: &str = "gossip_aggregate";
pub const GOSSIP_AGGREGATE_BATCH: &str = "gossip_aggregate_batch";
pub const GOSSIP_BLOCK: &str = "gossip_block";
pub const GOSSIP_BLOBS_SIDECAR: &str = "gossip_blobs_sidecar";
pub const DELAYED_IMPORT_BLOCK: &str = "delayed_import_block";
pub const GOSSIP_VOLUNTARY_EXIT: &str = "gossip_voluntary_exit";
pub const GOSSIP_PROPOSER_SLASHING: &str = "gossip_proposer_slashing";
pub const GOSSIP_ATTESTER_SLASHING: &str = "gossip_attester_slashing";
pub const GOSSIP_SYNC_SIGNATURE: &str = "gossip_sync_signature";
pub const GOSSIP_SYNC_CONTRIBUTION: &str = "gossip_sync_contribution";
pub const GOSSIP_LIGHT_CLIENT_FINALITY_UPDATE: &str = "light_client_finality_update";
pub const GOSSIP_LIGHT_CLIENT_OPTIMISTIC_UPDATE: &str = "light_client_optimistic_update";
pub const RPC_BLOCK: &str = "rpc_block";
pub const IGNORED_RPC_BLOCK: &str = "ignored_rpc_block";
pub const RPC_BLOBS: &str = "rpc_blob";
pub const CHAIN_SEGMENT: &str = "chain_segment";
pub const CHAIN_SEGMENT_BACKFILL: &str = "chain_segment_backfill";
pub const STATUS_PROCESSING: &str = "status_processing";
pub const BLOCKS_BY_RANGE_REQUEST: &str = "blocks_by_range_request";
pub const BLOCKS_BY_ROOTS_REQUEST: &str = "blocks_by_roots_request";
pub const BLOBS_BY_RANGE_REQUEST: &str = "blobs_by_range_request";
pub const BLOBS_BY_ROOTS_REQUEST: &str = "blobs_by_roots_request";
pub const LIGHT_CLIENT_BOOTSTRAP_REQUEST: &str = "light_client_bootstrap";
pub const LIGHT_CLIENT_FINALITY_UPDATE_REQUEST: &str = "light_client_finality_update_request";
pub const LIGHT_CLIENT_OPTIMISTIC_UPDATE_REQUEST: &str = "light_client_optimistic_update_request";
pub const UNKNOWN_BLOCK_ATTESTATION: &str = "unknown_block_attestation";
pub const UNKNOWN_BLOCK_AGGREGATE: &str = "unknown_block_aggregate";
pub const UNKNOWN_LIGHT_CLIENT_UPDATE: &str = "unknown_light_client_update";
pub const GOSSIP_BLS_TO_EXECUTION_CHANGE: &str = "gossip_bls_to_execution_change";
pub const API_REQUEST_P0: &str = "api_request_p0";
pub const API_REQUEST_P1: &str = "api_request_p1";

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct BeaconProcessorConfig {
    pub max_workers: usize,
    pub max_work_event_queue_len: usize,
    pub max_scheduled_work_queue_len: usize,
    pub max_gossip_attestation_batch_size: usize,
    pub max_gossip_aggregate_batch_size: usize,
    pub enable_backfill_rate_limiting: bool,
}

impl Default for BeaconProcessorConfig {
    fn default() -> Self {
        Self {
            max_workers: cmp::max(1, num_cpus::get()),
            max_work_event_queue_len: DEFAULT_MAX_WORK_EVENT_QUEUE_LEN,
            max_scheduled_work_queue_len: DEFAULT_MAX_SCHEDULED_WORK_QUEUE_LEN,
            max_gossip_attestation_batch_size: DEFAULT_MAX_GOSSIP_ATTESTATION_BATCH_SIZE,
            max_gossip_aggregate_batch_size: DEFAULT_MAX_GOSSIP_AGGREGATE_BATCH_SIZE,
            enable_backfill_rate_limiting: true,
        }
    }
}

// The channels necessary to instantiate a `BeaconProcessor`.
pub struct BeaconProcessorChannels<E: EthSpec> {
    pub beacon_processor_tx: BeaconProcessorSend<E>,
    pub beacon_processor_rx: mpsc::Receiver<WorkEvent<E>>,
    pub work_reprocessing_tx: mpsc::Sender<ReprocessQueueMessage>,
    pub work_reprocessing_rx: mpsc::Receiver<ReprocessQueueMessage>,
}

impl<E: EthSpec> BeaconProcessorChannels<E> {
    pub fn new(config: &BeaconProcessorConfig) -> Self {
        let (beacon_processor_tx, beacon_processor_rx) =
            mpsc::channel(config.max_work_event_queue_len);
        let (work_reprocessing_tx, work_reprocessing_rx) =
            mpsc::channel(config.max_scheduled_work_queue_len);

        Self {
            beacon_processor_tx: BeaconProcessorSend(beacon_processor_tx),
            beacon_processor_rx,
            work_reprocessing_rx,
            work_reprocessing_tx,
        }
    }
}

impl<E: EthSpec> Default for BeaconProcessorChannels<E> {
    fn default() -> Self {
        Self::new(&BeaconProcessorConfig::default())
    }
}

/// A simple first-in-first-out queue with a maximum length.
struct FifoQueue<T> {
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
struct LifoQueue<T> {
    queue: VecDeque<T>,
    max_length: usize,
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

/// A handle that sends a message on the provided channel to a receiver when it gets dropped.
///
/// The receiver task is responsible for removing the provided `entry` from the `DuplicateCache`
/// and perform any other necessary cleanup.
pub struct DuplicateCacheHandle {
    entry: Hash256,
    cache: DuplicateCache,
}

impl Drop for DuplicateCacheHandle {
    fn drop(&mut self) {
        self.cache.remove(&self.entry);
    }
}

/// A simple  cache for detecting duplicate block roots across multiple threads.
#[derive(Clone, Default)]
pub struct DuplicateCache {
    inner: Arc<Mutex<HashSet<Hash256>>>,
}

impl DuplicateCache {
    /// Checks if the given block_root exists and inserts it into the cache if
    /// it doesn't exist.
    ///
    /// Returns a `Some(DuplicateCacheHandle)` if the block_root was successfully
    /// inserted and `None` if the block root already existed in the cache.
    ///
    /// The handle removes the entry from the cache when it is dropped. This ensures that any unclean
    /// shutdowns in the worker tasks does not leave inconsistent state in the cache.
    pub fn check_and_insert(&self, block_root: Hash256) -> Option<DuplicateCacheHandle> {
        let mut inner = self.inner.lock();
        if inner.insert(block_root) {
            Some(DuplicateCacheHandle {
                entry: block_root,
                cache: self.clone(),
            })
        } else {
            None
        }
    }

    /// Remove the given block_root from the cache.
    pub fn remove(&self, block_root: &Hash256) {
        let mut inner = self.inner.lock();
        inner.remove(block_root);
    }
}

/// An event to be processed by the manager task.
#[derive(Debug)]
pub struct WorkEvent<E: EthSpec> {
    pub drop_during_sync: bool,
    pub work: Work<E>,
}

impl<E: EthSpec> WorkEvent<E> {
    /// Get a `str` representation of the type of work this `WorkEvent` contains.
    pub fn work_type(&self) -> &'static str {
        self.work.str_id()
    }
}

impl<E: EthSpec> From<ReadyWork> for WorkEvent<E> {
    fn from(ready_work: ReadyWork) -> Self {
        match ready_work {
            ReadyWork::Block(QueuedGossipBlock {
                beacon_block_slot,
                beacon_block_root,
                process_fn,
            }) => Self {
                drop_during_sync: false,
                work: Work::DelayedImportBlock {
                    beacon_block_slot,
                    beacon_block_root,
                    process_fn,
                },
            },
            ReadyWork::RpcBlock(QueuedRpcBlock {
                beacon_block_root: _,
                process_fn,
                ignore_fn: _,
            }) => Self {
                drop_during_sync: false,
                work: Work::RpcBlock { process_fn },
            },
            ReadyWork::IgnoredRpcBlock(IgnoredRpcBlock { process_fn }) => Self {
                drop_during_sync: false,
                work: Work::IgnoredRpcBlock { process_fn },
            },
            ReadyWork::Unaggregate(QueuedUnaggregate {
                beacon_block_root: _,
                process_fn,
            }) => Self {
                drop_during_sync: true,
                work: Work::UnknownBlockAttestation { process_fn },
            },
            ReadyWork::Aggregate(QueuedAggregate {
                process_fn,
                beacon_block_root: _,
            }) => Self {
                drop_during_sync: true,
                work: Work::UnknownBlockAggregate { process_fn },
            },
            ReadyWork::LightClientUpdate(QueuedLightClientUpdate {
                parent_root,
                process_fn,
            }) => Self {
                drop_during_sync: true,
                work: Work::UnknownLightClientOptimisticUpdate {
                    parent_root,
                    process_fn,
                },
            },
            ReadyWork::BackfillSync(QueuedBackfillBatch(process_fn)) => Self {
                drop_during_sync: false,
                work: Work::ChainSegmentBackfill(process_fn),
            },
        }
    }
}

/// Items required to verify a batch of unaggregated gossip attestations.
#[derive(Debug)]
pub struct GossipAttestationPackage<E: EthSpec> {
    pub message_id: MessageId,
    pub peer_id: PeerId,
    pub attestation: Box<Attestation<E>>,
    pub subnet_id: SubnetId,
    pub should_import: bool,
    pub seen_timestamp: Duration,
}

/// Items required to verify a batch of aggregated gossip attestations.
#[derive(Debug)]
pub struct GossipAggregatePackage<E: EthSpec> {
    pub message_id: MessageId,
    pub peer_id: PeerId,
    pub aggregate: Box<SignedAggregateAndProof<E>>,
    pub beacon_block_root: Hash256,
    pub seen_timestamp: Duration,
}

#[derive(Clone)]
pub struct BeaconProcessorSend<E: EthSpec>(pub mpsc::Sender<WorkEvent<E>>);

impl<E: EthSpec> BeaconProcessorSend<E> {
    pub fn try_send(&self, message: WorkEvent<E>) -> Result<(), TrySendError<WorkEvent<E>>> {
        let work_type = message.work_type();
        match self.0.try_send(message) {
            Ok(res) => Ok(res),
            Err(e) => {
                metrics::inc_counter_vec(
                    &metrics::BEACON_PROCESSOR_SEND_ERROR_PER_WORK_TYPE,
                    &[work_type],
                );
                Err(e)
            }
        }
    }
}

pub type AsyncFn = Pin<Box<dyn Future<Output = ()> + Send + Sync>>;
pub type BlockingFn = Box<dyn FnOnce() + Send + Sync>;
pub type BlockingFnWithManualSendOnIdle = Box<dyn FnOnce(SendOnDrop) + Send + Sync>;
pub enum BlockingOrAsync {
    Blocking(BlockingFn),
    Async(AsyncFn),
}

/// Indicates the type of work to be performed and therefore its priority and
/// queuing specifics.
pub enum Work<E: EthSpec> {
    GossipAttestation {
        attestation: Box<GossipAttestationPackage<E>>,
        process_individual: Box<dyn FnOnce(GossipAttestationPackage<E>) + Send + Sync>,
        process_batch: Box<dyn FnOnce(Vec<GossipAttestationPackage<E>>) + Send + Sync>,
    },
    UnknownBlockAttestation {
        process_fn: BlockingFn,
    },
    GossipAttestationBatch {
        attestations: Vec<GossipAttestationPackage<E>>,
        process_batch: Box<dyn FnOnce(Vec<GossipAttestationPackage<E>>) + Send + Sync>,
    },
    GossipAggregate {
        aggregate: Box<GossipAggregatePackage<E>>,
        process_individual: Box<dyn FnOnce(GossipAggregatePackage<E>) + Send + Sync>,
        process_batch: Box<dyn FnOnce(Vec<GossipAggregatePackage<E>>) + Send + Sync>,
    },
    UnknownBlockAggregate {
        process_fn: BlockingFn,
    },
    UnknownLightClientOptimisticUpdate {
        parent_root: Hash256,
        process_fn: BlockingFn,
    },
    GossipAggregateBatch {
        aggregates: Vec<GossipAggregatePackage<E>>,
        process_batch: Box<dyn FnOnce(Vec<GossipAggregatePackage<E>>) + Send + Sync>,
    },
    GossipBlock(AsyncFn),
    GossipBlobSidecar(AsyncFn),
    DelayedImportBlock {
        beacon_block_slot: Slot,
        beacon_block_root: Hash256,
        process_fn: AsyncFn,
    },
    GossipVoluntaryExit(BlockingFn),
    GossipProposerSlashing(BlockingFn),
    GossipAttesterSlashing(BlockingFn),
    GossipSyncSignature(BlockingFn),
    GossipSyncContribution(BlockingFn),
    GossipLightClientFinalityUpdate(BlockingFn),
    GossipLightClientOptimisticUpdate(BlockingFn),
    RpcBlock {
        process_fn: AsyncFn,
    },
    RpcBlobs {
        process_fn: AsyncFn,
    },
    IgnoredRpcBlock {
        process_fn: BlockingFn,
    },
    ChainSegment(AsyncFn),
    ChainSegmentBackfill(AsyncFn),
    Status(BlockingFn),
    BlocksByRangeRequest(AsyncFn),
    BlocksByRootsRequest(AsyncFn),
    BlobsByRangeRequest(BlockingFn),
    BlobsByRootsRequest(BlockingFn),
    GossipBlsToExecutionChange(BlockingFn),
    LightClientBootstrapRequest(BlockingFn),
    LightClientOptimisticUpdateRequest(BlockingFn),
    LightClientFinalityUpdateRequest(BlockingFn),
    ApiRequestP0(BlockingOrAsync),
    ApiRequestP1(BlockingOrAsync),
}

impl<E: EthSpec> fmt::Debug for Work<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.str_id())
    }
}

impl<E: EthSpec> Work<E> {
    /// Provides a `&str` that uniquely identifies each enum variant.
    fn str_id(&self) -> &'static str {
        match self {
            Work::GossipAttestation { .. } => GOSSIP_ATTESTATION,
            Work::GossipAttestationBatch { .. } => GOSSIP_ATTESTATION_BATCH,
            Work::GossipAggregate { .. } => GOSSIP_AGGREGATE,
            Work::GossipAggregateBatch { .. } => GOSSIP_AGGREGATE_BATCH,
            Work::GossipBlock(_) => GOSSIP_BLOCK,
            Work::GossipBlobSidecar(_) => GOSSIP_BLOBS_SIDECAR,
            Work::DelayedImportBlock { .. } => DELAYED_IMPORT_BLOCK,
            Work::GossipVoluntaryExit(_) => GOSSIP_VOLUNTARY_EXIT,
            Work::GossipProposerSlashing(_) => GOSSIP_PROPOSER_SLASHING,
            Work::GossipAttesterSlashing(_) => GOSSIP_ATTESTER_SLASHING,
            Work::GossipSyncSignature(_) => GOSSIP_SYNC_SIGNATURE,
            Work::GossipSyncContribution(_) => GOSSIP_SYNC_CONTRIBUTION,
            Work::GossipLightClientFinalityUpdate(_) => GOSSIP_LIGHT_CLIENT_FINALITY_UPDATE,
            Work::GossipLightClientOptimisticUpdate(_) => GOSSIP_LIGHT_CLIENT_OPTIMISTIC_UPDATE,
            Work::RpcBlock { .. } => RPC_BLOCK,
            Work::RpcBlobs { .. } => RPC_BLOBS,
            Work::IgnoredRpcBlock { .. } => IGNORED_RPC_BLOCK,
            Work::ChainSegment { .. } => CHAIN_SEGMENT,
            Work::ChainSegmentBackfill(_) => CHAIN_SEGMENT_BACKFILL,
            Work::Status(_) => STATUS_PROCESSING,
            Work::BlocksByRangeRequest(_) => BLOCKS_BY_RANGE_REQUEST,
            Work::BlocksByRootsRequest(_) => BLOCKS_BY_ROOTS_REQUEST,
            Work::BlobsByRangeRequest(_) => BLOBS_BY_RANGE_REQUEST,
            Work::BlobsByRootsRequest(_) => BLOBS_BY_ROOTS_REQUEST,
            Work::LightClientBootstrapRequest(_) => LIGHT_CLIENT_BOOTSTRAP_REQUEST,
            Work::LightClientOptimisticUpdateRequest(_) => LIGHT_CLIENT_OPTIMISTIC_UPDATE_REQUEST,
            Work::LightClientFinalityUpdateRequest(_) => LIGHT_CLIENT_FINALITY_UPDATE_REQUEST,
            Work::UnknownBlockAttestation { .. } => UNKNOWN_BLOCK_ATTESTATION,
            Work::UnknownBlockAggregate { .. } => UNKNOWN_BLOCK_AGGREGATE,
            Work::GossipBlsToExecutionChange(_) => GOSSIP_BLS_TO_EXECUTION_CHANGE,
            Work::UnknownLightClientOptimisticUpdate { .. } => UNKNOWN_LIGHT_CLIENT_UPDATE,
            Work::ApiRequestP0 { .. } => API_REQUEST_P0,
            Work::ApiRequestP1 { .. } => API_REQUEST_P1,
        }
    }
}

/// Unifies all the messages processed by the `BeaconProcessor`.
enum InboundEvent<E: EthSpec> {
    /// A worker has completed a task and is free.
    WorkerIdle,
    /// There is new work to be done.
    WorkEvent(WorkEvent<E>),
    /// A work event that was queued for re-processing has become ready.
    ReprocessingWork(WorkEvent<E>),
}

/// Combines the various incoming event streams for the `BeaconProcessor` into a single stream.
///
/// This struct has a similar purpose to `tokio::select!`, however it allows for more fine-grained
/// control (specifically in the ordering of event processing).
struct InboundEvents<E: EthSpec> {
    /// Used by workers when they finish a task.
    idle_rx: mpsc::Receiver<()>,
    /// Used by upstream processes to send new work to the `BeaconProcessor`.
    event_rx: mpsc::Receiver<WorkEvent<E>>,
    /// Used internally for queuing work ready to be re-processed.
    reprocess_work_rx: mpsc::Receiver<ReadyWork>,
}

impl<E: EthSpec> Stream for InboundEvents<E> {
    type Item = InboundEvent<E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Always check for idle workers before anything else. This allows us to ensure that a big
        // stream of new events doesn't suppress the processing of existing events.
        match self.idle_rx.poll_recv(cx) {
            Poll::Ready(Some(())) => {
                return Poll::Ready(Some(InboundEvent::WorkerIdle));
            }
            Poll::Ready(None) => {
                return Poll::Ready(None);
            }
            Poll::Pending => {}
        }

        // Poll for delayed blocks before polling for new work. It might be the case that a delayed
        // block is required to successfully process some new work.
        match self.reprocess_work_rx.poll_recv(cx) {
            Poll::Ready(Some(ready_work)) => {
                return Poll::Ready(Some(InboundEvent::ReprocessingWork(ready_work.into())));
            }
            Poll::Ready(None) => {
                return Poll::Ready(None);
            }
            Poll::Pending => {}
        }

        match self.event_rx.poll_recv(cx) {
            Poll::Ready(Some(event)) => {
                return Poll::Ready(Some(InboundEvent::WorkEvent(event)));
            }
            Poll::Ready(None) => {
                return Poll::Ready(None);
            }
            Poll::Pending => {}
        }

        Poll::Pending
    }
}

/// A mutli-threaded processor for messages received on the network
/// that need to be processed by the `BeaconChain`
///
/// See module level documentation for more information.
pub struct BeaconProcessor<E: EthSpec> {
    pub network_globals: Arc<NetworkGlobals<E>>,
    pub executor: TaskExecutor,
    pub current_workers: usize,
    pub config: BeaconProcessorConfig,
    pub log: Logger,
}

impl<E: EthSpec> BeaconProcessor<E> {
    /// Spawns the "manager" task which checks the receiver end of the returned `Sender` for
    /// messages which contain some new work which will be:
    ///
    /// - Performed immediately, if a worker is available.
    /// - Queued for later processing, if no worker is currently available.
    ///
    /// Only `self.config.max_workers` will ever be spawned at one time. Each worker is a `tokio` task
    /// started with `spawn_blocking`.
    ///
    /// The optional `work_journal_tx` allows for an outside process to receive a log of all work
    /// events processed by `self`. This should only be used during testing.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_manager<S: SlotClock + 'static>(
        mut self,
        event_rx: mpsc::Receiver<WorkEvent<E>>,
        work_reprocessing_tx: mpsc::Sender<ReprocessQueueMessage>,
        work_reprocessing_rx: mpsc::Receiver<ReprocessQueueMessage>,
        work_journal_tx: Option<mpsc::Sender<&'static str>>,
        slot_clock: S,
        maximum_gossip_clock_disparity: Duration,
        queue_lengths: BeaconProcessorQueueLengths,
    ) -> Result<(), String> {
        // Used by workers to communicate that they are finished a task.
        let (idle_tx, idle_rx) = mpsc::channel::<()>(MAX_IDLE_QUEUE_LEN);

        // Using LIFO queues for attestations since validator profits rely upon getting fresh
        // attestations into blocks. Additionally, later attestations contain more information than
        // earlier ones, so we consider them more valuable.
        let mut aggregate_queue = LifoQueue::new(queue_lengths.aggregate_queue);
        let mut aggregate_debounce = TimeLatch::default();
        let mut attestation_queue = LifoQueue::new(queue_lengths.attestation_queue);
        let mut attestation_debounce = TimeLatch::default();
        let mut unknown_block_aggregate_queue =
            LifoQueue::new(queue_lengths.unknown_block_aggregate_queue);
        let mut unknown_block_attestation_queue =
            LifoQueue::new(queue_lengths.unknown_block_attestation_queue);

        let mut sync_message_queue = LifoQueue::new(queue_lengths.sync_message_queue);
        let mut sync_contribution_queue = LifoQueue::new(queue_lengths.sync_contribution_queue);

        // Using a FIFO queue for voluntary exits since it prevents exit censoring. I don't have
        // a strong feeling about queue type for exits.
        let mut gossip_voluntary_exit_queue =
            FifoQueue::new(queue_lengths.gossip_voluntary_exit_queue);

        // Using a FIFO queue for slashing to prevent people from flushing their slashings from the
        // queues with lots of junk messages.
        let mut gossip_proposer_slashing_queue =
            FifoQueue::new(queue_lengths.gossip_proposer_slashing_queue);
        let mut gossip_attester_slashing_queue =
            FifoQueue::new(queue_lengths.gossip_attester_slashing_queue);

        // Using a FIFO queue for light client updates to maintain sequence order.
        let mut finality_update_queue = FifoQueue::new(queue_lengths.finality_update_queue);
        let mut optimistic_update_queue = FifoQueue::new(queue_lengths.optimistic_update_queue);
        let mut unknown_light_client_update_queue =
            FifoQueue::new(queue_lengths.unknown_light_client_update_queue);

        // Using a FIFO queue since blocks need to be imported sequentially.
        let mut rpc_block_queue = FifoQueue::new(queue_lengths.rpc_block_queue);
        let mut rpc_blob_queue = FifoQueue::new(queue_lengths.rpc_blob_queue);
        let mut chain_segment_queue = FifoQueue::new(queue_lengths.chain_segment_queue);
        let mut backfill_chain_segment = FifoQueue::new(queue_lengths.backfill_chain_segment);
        let mut gossip_block_queue = FifoQueue::new(queue_lengths.gossip_block_queue);
        let mut gossip_blob_queue = FifoQueue::new(queue_lengths.gossip_blob_queue);
        let mut delayed_block_queue = FifoQueue::new(queue_lengths.delayed_block_queue);

        let mut status_queue = FifoQueue::new(queue_lengths.status_queue);
        let mut bbrange_queue = FifoQueue::new(queue_lengths.bbrange_queue);
        let mut bbroots_queue = FifoQueue::new(queue_lengths.bbroots_queue);
        let mut blbroots_queue = FifoQueue::new(queue_lengths.blbroots_queue);
        let mut blbrange_queue = FifoQueue::new(queue_lengths.blbrange_queue);

        let mut gossip_bls_to_execution_change_queue =
            FifoQueue::new(queue_lengths.gossip_bls_to_execution_change_queue);

        let mut lc_bootstrap_queue = FifoQueue::new(queue_lengths.lc_bootstrap_queue);
        let mut lc_optimistic_update_queue =
            FifoQueue::new(queue_lengths.lc_optimistic_update_queue);
        let mut lc_finality_update_queue = FifoQueue::new(queue_lengths.lc_finality_update_queue);

        let mut api_request_p0_queue = FifoQueue::new(queue_lengths.api_request_p0_queue);
        let mut api_request_p1_queue = FifoQueue::new(queue_lengths.api_request_p1_queue);

        // Channels for sending work to the re-process scheduler (`work_reprocessing_tx`) and to
        // receive them back once they are ready (`ready_work_rx`).
        let (ready_work_tx, ready_work_rx) =
            mpsc::channel::<ReadyWork>(self.config.max_scheduled_work_queue_len);
        spawn_reprocess_scheduler(
            ready_work_tx,
            work_reprocessing_rx,
            &self.executor,
            Arc::new(slot_clock),
            self.log.clone(),
            maximum_gossip_clock_disparity,
        )?;

        let executor = self.executor.clone();

        // The manager future will run on the core executor and delegate tasks to worker
        // threads on the blocking executor.
        let manager_future = async move {
            let mut inbound_events = InboundEvents {
                idle_rx,
                event_rx,
                reprocess_work_rx: ready_work_rx,
            };

            let enable_backfill_rate_limiting = self.config.enable_backfill_rate_limiting;

            loop {
                let work_event = match inbound_events.next().await {
                    Some(InboundEvent::WorkerIdle) => {
                        self.current_workers = self.current_workers.saturating_sub(1);
                        None
                    }
                    Some(InboundEvent::WorkEvent(event)) if enable_backfill_rate_limiting => {
                        match QueuedBackfillBatch::try_from(event) {
                            Ok(backfill_batch) => {
                                match work_reprocessing_tx
                                    .try_send(ReprocessQueueMessage::BackfillSync(backfill_batch))
                                {
                                    Err(e) => {
                                        warn!(
                                            self.log,
                                            "Unable to queue backfill work event. Will try to process now.";
                                            "error" => %e
                                        );
                                        match e {
                                            TrySendError::Full(reprocess_queue_message)
                                            | TrySendError::Closed(reprocess_queue_message) => {
                                                match reprocess_queue_message {
                                                    ReprocessQueueMessage::BackfillSync(
                                                        backfill_batch,
                                                    ) => Some(backfill_batch.into()),
                                                    other => {
                                                        crit!(
                                                            self.log,
                                                            "Unexpected queue message type";
                                                            "message_type" => other.as_ref()
                                                        );
                                                        // This is an unhandled exception, drop the message.
                                                        continue;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Ok(..) => {
                                        // backfill work sent to "reprocessing" queue. Process the next event.
                                        continue;
                                    }
                                }
                            }
                            Err(event) => Some(event),
                        }
                    }
                    Some(InboundEvent::WorkEvent(event))
                    | Some(InboundEvent::ReprocessingWork(event)) => Some(event),
                    None => {
                        debug!(
                            self.log,
                            "Gossip processor stopped";
                            "msg" => "stream ended"
                        );
                        break;
                    }
                };

                let _event_timer =
                    metrics::start_timer(&metrics::BEACON_PROCESSOR_EVENT_HANDLING_SECONDS);
                if let Some(event) = &work_event {
                    metrics::inc_counter_vec(
                        &metrics::BEACON_PROCESSOR_WORK_EVENTS_RX_COUNT,
                        &[event.work.str_id()],
                    );
                } else {
                    metrics::inc_counter(&metrics::BEACON_PROCESSOR_IDLE_EVENTS_TOTAL);
                }

                if let Some(work_journal_tx) = &work_journal_tx {
                    let id = work_event
                        .as_ref()
                        .map(|event| event.work.str_id())
                        .unwrap_or(WORKER_FREED);

                    // We don't care if this message was successfully sent, we only use the journal
                    // during testing.
                    let _ = work_journal_tx.try_send(id);
                }

                let can_spawn = self.current_workers < self.config.max_workers;
                let drop_during_sync = work_event
                    .as_ref()
                    .map_or(false, |event| event.drop_during_sync);

                let idle_tx = idle_tx.clone();
                match work_event {
                    // There is no new work event, but we are able to spawn a new worker.
                    //
                    // We don't check the `work.drop_during_sync` here. We assume that if it made
                    // it into the queue at any point then we should process it.
                    None if can_spawn => {
                        // Check for chain segments first, they're the most efficient way to get
                        // blocks into the system.
                        if let Some(item) = chain_segment_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        // Check sync blocks before gossip blocks, since we've already explicitly
                        // requested these blocks.
                        } else if let Some(item) = rpc_block_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        } else if let Some(item) = rpc_blob_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        // Check delayed blocks before gossip blocks, the gossip blocks might rely
                        // on the delayed ones.
                        } else if let Some(item) = delayed_block_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        // Check gossip blocks before gossip attestations, since a block might be
                        // required to verify some attestations.
                        } else if let Some(item) = gossip_block_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        } else if let Some(item) = gossip_blob_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        // Check the priority 0 API requests after blocks and blobs, but before attestations.
                        } else if let Some(item) = api_request_p0_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        // Check the aggregates, *then* the unaggregates since we assume that
                        // aggregates are more valuable to local validators and effectively give us
                        // more information with less signature verification time.
                        } else if aggregate_queue.len() > 0 {
                            let batch_size = cmp::min(
                                aggregate_queue.len(),
                                self.config.max_gossip_aggregate_batch_size,
                            );

                            if batch_size < 2 {
                                // One single aggregate is in the queue, process it individually.
                                if let Some(item) = aggregate_queue.pop() {
                                    self.spawn_worker(item, idle_tx);
                                }
                            } else {
                                // Collect two or more aggregates into a batch, so they can take
                                // advantage of batch signature verification.
                                //
                                // Note: this will convert the `Work::GossipAggregate` item into a
                                // `Work::GossipAggregateBatch` item.
                                let mut aggregates = Vec::with_capacity(batch_size);
                                let mut process_batch_opt = None;
                                for _ in 0..batch_size {
                                    if let Some(item) = aggregate_queue.pop() {
                                        match item {
                                            Work::GossipAggregate {
                                                aggregate,
                                                process_individual: _,
                                                process_batch,
                                            } => {
                                                aggregates.push(*aggregate);
                                                if process_batch_opt.is_none() {
                                                    process_batch_opt = Some(process_batch);
                                                }
                                            }
                                            _ => {
                                                error!(self.log, "Invalid item in aggregate queue");
                                            }
                                        }
                                    }
                                }

                                if let Some(process_batch) = process_batch_opt {
                                    // Process all aggregates with a single worker.
                                    self.spawn_worker(
                                        Work::GossipAggregateBatch {
                                            aggregates,
                                            process_batch,
                                        },
                                        idle_tx,
                                    )
                                } else {
                                    // There is no good reason for this to
                                    // happen, it is a serious logic error.
                                    // Since we only form batches when multiple
                                    // work items exist, we should always have a
                                    // work closure at this point.
                                    crit!(self.log, "Missing aggregate work");
                                }
                            }
                        // Check the unaggregated attestation queue.
                        //
                        // Potentially use batching.
                        } else if attestation_queue.len() > 0 {
                            let batch_size = cmp::min(
                                attestation_queue.len(),
                                self.config.max_gossip_attestation_batch_size,
                            );

                            if batch_size < 2 {
                                // One single attestation is in the queue, process it individually.
                                if let Some(item) = attestation_queue.pop() {
                                    self.spawn_worker(item, idle_tx);
                                }
                            } else {
                                // Collect two or more attestations into a batch, so they can take
                                // advantage of batch signature verification.
                                //
                                // Note: this will convert the `Work::GossipAttestation` item into a
                                // `Work::GossipAttestationBatch` item.
                                let mut attestations = Vec::with_capacity(batch_size);
                                let mut process_batch_opt = None;
                                for _ in 0..batch_size {
                                    if let Some(item) = attestation_queue.pop() {
                                        match item {
                                            Work::GossipAttestation {
                                                attestation,
                                                process_individual: _,
                                                process_batch,
                                            } => {
                                                attestations.push(*attestation);
                                                if process_batch_opt.is_none() {
                                                    process_batch_opt = Some(process_batch);
                                                }
                                            }
                                            _ => error!(
                                                self.log,
                                                "Invalid item in attestation queue"
                                            ),
                                        }
                                    }
                                }

                                if let Some(process_batch) = process_batch_opt {
                                    // Process all attestations with a single worker.
                                    self.spawn_worker(
                                        Work::GossipAttestationBatch {
                                            attestations,
                                            process_batch,
                                        },
                                        idle_tx,
                                    )
                                } else {
                                    // There is no good reason for this to
                                    // happen, it is a serious logic error.
                                    // Since we only form batches when multiple
                                    // work items exist, we should always have a
                                    // work closure at this point.
                                    crit!(self.log, "Missing attestations work");
                                }
                            }
                        // Check sync committee messages after attestations as their rewards are lesser
                        // and they don't influence fork choice.
                        } else if let Some(item) = sync_contribution_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        } else if let Some(item) = sync_message_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        // Aggregates and unaggregates queued for re-processing are older and we
                        // care about fresher ones, so check those first.
                        } else if let Some(item) = unknown_block_aggregate_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        } else if let Some(item) = unknown_block_attestation_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        // Check RPC methods next. Status messages are needed for sync so
                        // prioritize them over syncing requests from other peers (BlocksByRange
                        // and BlocksByRoot)
                        } else if let Some(item) = status_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        } else if let Some(item) = bbrange_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        } else if let Some(item) = bbroots_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        } else if let Some(item) = blbrange_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        } else if let Some(item) = blbroots_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        // Check slashings after all other consensus messages so we prioritize
                        // following head.
                        //
                        // Check attester slashings before proposer slashings since they have the
                        // potential to slash multiple validators at once.
                        } else if let Some(item) = gossip_attester_slashing_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        } else if let Some(item) = gossip_proposer_slashing_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        // Check exits and address changes late since our validators don't get
                        // rewards from them.
                        } else if let Some(item) = gossip_voluntary_exit_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        } else if let Some(item) = gossip_bls_to_execution_change_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        // Check the priority 1 API requests after we've
                        // processed all the interesting things from the network
                        // and things required for us to stay in good repute
                        // with our P2P peers.
                        } else if let Some(item) = api_request_p1_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        // Handle backfill sync chain segments.
                        } else if let Some(item) = backfill_chain_segment.pop() {
                            self.spawn_worker(item, idle_tx);
                        // Handle light client requests.
                        } else if let Some(item) = lc_bootstrap_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        } else if let Some(item) = lc_optimistic_update_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                        } else if let Some(item) = lc_finality_update_queue.pop() {
                            self.spawn_worker(item, idle_tx);
                            // This statement should always be the final else statement.
                        } else {
                            // Let the journal know that a worker is freed and there's nothing else
                            // for it to do.
                            if let Some(work_journal_tx) = &work_journal_tx {
                                // We don't care if this message was successfully sent, we only use the journal
                                // during testing.
                                let _ = work_journal_tx.try_send(NOTHING_TO_DO);
                            }
                        }
                    }
                    // There is no new work event and we are unable to spawn a new worker.
                    //
                    // I cannot see any good reason why this would happen.
                    None => {
                        warn!(
                            self.log,
                            "Unexpected gossip processor condition";
                            "msg" => "no new work and cannot spawn worker"
                        );
                    }
                    // The chain is syncing and this event should be dropped during sync.
                    Some(work_event)
                        if self.network_globals.sync_state.read().is_syncing()
                            && drop_during_sync =>
                    {
                        let work_id = work_event.work.str_id();
                        metrics::inc_counter_vec(
                            &metrics::BEACON_PROCESSOR_WORK_EVENTS_IGNORED_COUNT,
                            &[work_id],
                        );
                        trace!(
                            self.log,
                            "Gossip processor skipping work";
                            "msg" => "chain is syncing",
                            "work_id" => work_id
                        );
                    }
                    // There is a new work event and the chain is not syncing. Process it or queue
                    // it.
                    Some(WorkEvent { work, .. }) => {
                        let work_id = work.str_id();

                        match work {
                            _ if can_spawn => self.spawn_worker(work, idle_tx),
                            Work::GossipAttestation { .. } => attestation_queue.push(work),
                            // Attestation batches are formed internally within the
                            // `BeaconProcessor`, they are not sent from external services.
                            Work::GossipAttestationBatch { .. } => crit!(
                                    self.log,
                                    "Unsupported inbound event";
                                    "type" => "GossipAttestationBatch"
                            ),
                            Work::GossipAggregate { .. } => aggregate_queue.push(work),
                            // Aggregate batches are formed internally within the `BeaconProcessor`,
                            // they are not sent from external services.
                            Work::GossipAggregateBatch { .. } => crit!(
                                    self.log,
                                    "Unsupported inbound event";
                                    "type" => "GossipAggregateBatch"
                            ),
                            Work::GossipBlock { .. } => {
                                gossip_block_queue.push(work, work_id, &self.log)
                            }
                            Work::GossipBlobSidecar { .. } => {
                                gossip_blob_queue.push(work, work_id, &self.log)
                            }
                            Work::DelayedImportBlock { .. } => {
                                delayed_block_queue.push(work, work_id, &self.log)
                            }
                            Work::GossipVoluntaryExit { .. } => {
                                gossip_voluntary_exit_queue.push(work, work_id, &self.log)
                            }
                            Work::GossipProposerSlashing { .. } => {
                                gossip_proposer_slashing_queue.push(work, work_id, &self.log)
                            }
                            Work::GossipAttesterSlashing { .. } => {
                                gossip_attester_slashing_queue.push(work, work_id, &self.log)
                            }
                            Work::GossipSyncSignature { .. } => sync_message_queue.push(work),
                            Work::GossipSyncContribution { .. } => {
                                sync_contribution_queue.push(work)
                            }
                            Work::GossipLightClientFinalityUpdate { .. } => {
                                finality_update_queue.push(work, work_id, &self.log)
                            }
                            Work::GossipLightClientOptimisticUpdate { .. } => {
                                optimistic_update_queue.push(work, work_id, &self.log)
                            }
                            Work::RpcBlock { .. } | Work::IgnoredRpcBlock { .. } => {
                                rpc_block_queue.push(work, work_id, &self.log)
                            }
                            Work::RpcBlobs { .. } => rpc_blob_queue.push(work, work_id, &self.log),
                            Work::ChainSegment { .. } => {
                                chain_segment_queue.push(work, work_id, &self.log)
                            }
                            Work::ChainSegmentBackfill { .. } => {
                                backfill_chain_segment.push(work, work_id, &self.log)
                            }
                            Work::Status { .. } => status_queue.push(work, work_id, &self.log),
                            Work::BlocksByRangeRequest { .. } => {
                                bbrange_queue.push(work, work_id, &self.log)
                            }
                            Work::BlocksByRootsRequest { .. } => {
                                bbroots_queue.push(work, work_id, &self.log)
                            }
                            Work::BlobsByRangeRequest { .. } => {
                                blbrange_queue.push(work, work_id, &self.log)
                            }
                            Work::LightClientBootstrapRequest { .. } => {
                                lc_bootstrap_queue.push(work, work_id, &self.log)
                            }
                            Work::LightClientOptimisticUpdateRequest { .. } => {
                                lc_optimistic_update_queue.push(work, work_id, &self.log)
                            }
                            Work::LightClientFinalityUpdateRequest { .. } => {
                                lc_finality_update_queue.push(work, work_id, &self.log)
                            }
                            Work::UnknownBlockAttestation { .. } => {
                                unknown_block_attestation_queue.push(work)
                            }
                            Work::UnknownBlockAggregate { .. } => {
                                unknown_block_aggregate_queue.push(work)
                            }
                            Work::GossipBlsToExecutionChange { .. } => {
                                gossip_bls_to_execution_change_queue.push(work, work_id, &self.log)
                            }
                            Work::BlobsByRootsRequest { .. } => {
                                blbroots_queue.push(work, work_id, &self.log)
                            }
                            Work::UnknownLightClientOptimisticUpdate { .. } => {
                                unknown_light_client_update_queue.push(work, work_id, &self.log)
                            }
                            Work::ApiRequestP0 { .. } => {
                                api_request_p0_queue.push(work, work_id, &self.log)
                            }
                            Work::ApiRequestP1 { .. } => {
                                api_request_p1_queue.push(work, work_id, &self.log)
                            }
                        }
                    }
                }

                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_WORKERS_ACTIVE_TOTAL,
                    self.current_workers as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_UNAGGREGATED_ATTESTATION_QUEUE_TOTAL,
                    attestation_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_AGGREGATED_ATTESTATION_QUEUE_TOTAL,
                    aggregate_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_SYNC_MESSAGE_QUEUE_TOTAL,
                    sync_message_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_SYNC_CONTRIBUTION_QUEUE_TOTAL,
                    sync_contribution_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_GOSSIP_BLOCK_QUEUE_TOTAL,
                    gossip_block_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_GOSSIP_BLOB_QUEUE_TOTAL,
                    gossip_blob_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_RPC_BLOCK_QUEUE_TOTAL,
                    rpc_block_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_RPC_BLOB_QUEUE_TOTAL,
                    rpc_blob_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_CHAIN_SEGMENT_QUEUE_TOTAL,
                    chain_segment_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_BACKFILL_CHAIN_SEGMENT_QUEUE_TOTAL,
                    backfill_chain_segment.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_EXIT_QUEUE_TOTAL,
                    gossip_voluntary_exit_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_PROPOSER_SLASHING_QUEUE_TOTAL,
                    gossip_proposer_slashing_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_ATTESTER_SLASHING_QUEUE_TOTAL,
                    gossip_attester_slashing_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_BLS_TO_EXECUTION_CHANGE_QUEUE_TOTAL,
                    gossip_bls_to_execution_change_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_API_REQUEST_P0_QUEUE_TOTAL,
                    api_request_p0_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_API_REQUEST_P1_QUEUE_TOTAL,
                    api_request_p1_queue.len() as i64,
                );

                if aggregate_queue.is_full() && aggregate_debounce.elapsed() {
                    error!(
                        self.log,
                        "Aggregate attestation queue full";
                        "msg" => "the system has insufficient resources for load",
                        "queue_len" => aggregate_queue.max_length,
                    )
                }

                if attestation_queue.is_full() && attestation_debounce.elapsed() {
                    error!(
                        self.log,
                        "Attestation queue full";
                        "msg" => "the system has insufficient resources for load",
                        "queue_len" => attestation_queue.max_length,
                    )
                }
            }
        };

        // Spawn on the core executor.
        executor.spawn(manager_future, MANAGER_TASK_NAME);
        Ok(())
    }

    /// Spawns a blocking worker thread to process some `Work`.
    ///
    /// Sends an message on `idle_tx` when the work is complete and the task is stopping.
    fn spawn_worker(&mut self, work: Work<E>, idle_tx: mpsc::Sender<()>) {
        let work_id = work.str_id();
        let worker_timer =
            metrics::start_timer_vec(&metrics::BEACON_PROCESSOR_WORKER_TIME, &[work_id]);
        metrics::inc_counter(&metrics::BEACON_PROCESSOR_WORKERS_SPAWNED_TOTAL);
        metrics::inc_counter_vec(
            &metrics::BEACON_PROCESSOR_WORK_EVENTS_STARTED_COUNT,
            &[work.str_id()],
        );

        // Wrap the `idle_tx` in a struct that will fire the idle message whenever it is dropped.
        //
        // This helps ensure that the worker is always freed in the case of an early exit or panic.
        // As such, this instantiation should happen as early in the function as possible.
        let send_idle_on_drop = SendOnDrop {
            tx: idle_tx,
            _worker_timer: worker_timer,
            log: self.log.clone(),
        };

        let worker_id = self.current_workers;
        self.current_workers = self.current_workers.saturating_add(1);

        let executor = self.executor.clone();

        trace!(
            self.log,
            "Spawning beacon processor worker";
            "work" => work_id,
            "worker" => worker_id,
        );

        let task_spawner = TaskSpawner {
            executor,
            send_idle_on_drop,
        };

        match work {
            Work::GossipAttestation {
                attestation,
                process_individual,
                process_batch: _,
            } => task_spawner.spawn_blocking(move || {
                process_individual(*attestation);
            }),
            Work::GossipAttestationBatch {
                attestations,
                process_batch,
            } => task_spawner.spawn_blocking(move || {
                process_batch(attestations);
            }),
            Work::GossipAggregate {
                aggregate,
                process_individual,
                process_batch: _,
            } => task_spawner.spawn_blocking(move || {
                process_individual(*aggregate);
            }),
            Work::GossipAggregateBatch {
                aggregates,
                process_batch,
            } => task_spawner.spawn_blocking(move || {
                process_batch(aggregates);
            }),
            Work::ChainSegment(process_fn) => task_spawner.spawn_async(async move {
                process_fn.await;
            }),
            Work::UnknownBlockAttestation { process_fn } => task_spawner.spawn_blocking(process_fn),
            Work::UnknownBlockAggregate { process_fn } => task_spawner.spawn_blocking(process_fn),
            Work::UnknownLightClientOptimisticUpdate {
                parent_root: _,
                process_fn,
            } => task_spawner.spawn_blocking(process_fn),
            Work::DelayedImportBlock {
                beacon_block_slot: _,
                beacon_block_root: _,
                process_fn,
            } => task_spawner.spawn_async(process_fn),
            Work::RpcBlock { process_fn } | Work::RpcBlobs { process_fn } => {
                task_spawner.spawn_async(process_fn)
            }
            Work::IgnoredRpcBlock { process_fn } => task_spawner.spawn_blocking(process_fn),
            Work::GossipBlock(work) | Work::GossipBlobSidecar(work) => {
                task_spawner.spawn_async(async move {
                    work.await;
                })
            }
            Work::BlobsByRangeRequest(process_fn) | Work::BlobsByRootsRequest(process_fn) => {
                task_spawner.spawn_blocking(process_fn)
            }
            Work::BlocksByRangeRequest(work) | Work::BlocksByRootsRequest(work) => {
                task_spawner.spawn_async(work)
            }
            Work::ChainSegmentBackfill(process_fn) => task_spawner.spawn_async(process_fn),
            Work::ApiRequestP0(process_fn) | Work::ApiRequestP1(process_fn) => match process_fn {
                BlockingOrAsync::Blocking(process_fn) => task_spawner.spawn_blocking(process_fn),
                BlockingOrAsync::Async(process_fn) => task_spawner.spawn_async(process_fn),
            },
            Work::GossipVoluntaryExit(process_fn)
            | Work::GossipProposerSlashing(process_fn)
            | Work::GossipAttesterSlashing(process_fn)
            | Work::GossipSyncSignature(process_fn)
            | Work::GossipSyncContribution(process_fn)
            | Work::GossipLightClientFinalityUpdate(process_fn)
            | Work::GossipLightClientOptimisticUpdate(process_fn)
            | Work::Status(process_fn)
            | Work::GossipBlsToExecutionChange(process_fn)
            | Work::LightClientBootstrapRequest(process_fn)
            | Work::LightClientOptimisticUpdateRequest(process_fn)
            | Work::LightClientFinalityUpdateRequest(process_fn) => {
                task_spawner.spawn_blocking(process_fn)
            }
        };
    }
}

/// Spawns tasks that are either:
///
/// - Blocking (i.e. intensive methods that shouldn't run on the core `tokio` executor)
/// - Async (i.e. `async` methods)
///
/// Takes a `SendOnDrop` and ensures it is dropped after the task completes. This frees the beacon
/// processor worker so a new task can be started.
struct TaskSpawner {
    executor: TaskExecutor,
    send_idle_on_drop: SendOnDrop,
}

impl TaskSpawner {
    /// Spawn an async task, dropping the `SendOnDrop` after the task has completed.
    fn spawn_async(self, task: impl Future<Output = ()> + Send + 'static) {
        self.executor.spawn(
            async {
                task.await;
                drop(self.send_idle_on_drop)
            },
            WORKER_TASK_NAME,
        )
    }

    /// Spawn a blocking task, dropping the `SendOnDrop` after the task has completed.
    fn spawn_blocking<F>(self, task: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.executor.spawn_blocking(
            || {
                task();
                drop(self.send_idle_on_drop)
            },
            WORKER_TASK_NAME,
        )
    }
}

/// This struct will send a message on `self.tx` when it is dropped. An error will be logged on
/// `self.log` if the send fails (this happens when the node is shutting down).
///
/// ## Purpose
///
/// This is useful for ensuring that a worker-freed message is still sent if a worker panics.
///
/// The Rust docs for `Drop` state that `Drop` is called during an unwind in a panic:
///
/// https://doc.rust-lang.org/std/ops/trait.Drop.html#panics
pub struct SendOnDrop {
    tx: mpsc::Sender<()>,
    // The field is unused, but it's here to ensure the timer is dropped once the task has finished.
    _worker_timer: Option<metrics::HistogramTimer>,
    log: Logger,
}

impl Drop for SendOnDrop {
    fn drop(&mut self) {
        if let Err(e) = self.tx.try_send(()) {
            warn!(
                self.log,
                "Unable to free worker";
                "msg" => "did not free worker, shutdown may be underway",
                "error" => %e
            )
        }
    }
}
