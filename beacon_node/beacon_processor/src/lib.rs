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
mod scheduler;
use crate::scheduler::interface::SchedulerType;
use lighthouse_network::{MessageId, NetworkGlobals, PeerId};
use parking_lot::Mutex;
use scheduler::interface::Scheduler;
use serde::{Deserialize, Serialize};
use slog::{warn, Logger};
use slot_clock::SlotClock;
use std::cmp;
use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use strum::AsRefStr;
use strum::IntoStaticStr;
use task_executor::TaskExecutor;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use types::{Attestation, BeaconState, ChainSpec, Hash256, SignedAggregateAndProof, SubnetId};
use types::{EthSpec, Slot};
mod metrics;

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
}

impl<E: EthSpec> BeaconProcessorChannels<E> {
    pub fn new(config: &BeaconProcessorConfig) -> Self {
        let (beacon_processor_tx, beacon_processor_rx) =
            mpsc::channel(config.max_work_event_queue_len);

        Self {
            beacon_processor_tx: BeaconProcessorSend(beacon_processor_tx),
            beacon_processor_rx,
        }
    }
}

impl<E: EthSpec> Default for BeaconProcessorChannels<E> {
    fn default() -> Self {
        Self::new(&BeaconProcessorConfig::default())
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

#[derive(IntoStaticStr, PartialEq, Eq, Debug)]
#[strum(serialize_all = "snake_case")]
pub enum WorkType {
    GossipAttestation,
    UnknownBlockAttestation,
    GossipAttestationBatch,
    GossipAggregate,
    UnknownBlockAggregate,
    UnknownLightClientOptimisticUpdate,
    UnknownBlockSamplingRequest,
    GossipAggregateBatch,
    GossipBlock,
    GossipBlobSidecar,
    GossipDataColumnSidecar,
    DelayedImportBlock,
    GossipVoluntaryExit,
    GossipProposerSlashing,
    GossipAttesterSlashing,
    GossipSyncSignature,
    GossipSyncContribution,
    GossipLightClientFinalityUpdate,
    GossipLightClientOptimisticUpdate,
    RpcBlock,
    RpcBlobs,
    RpcCustodyColumn,
    RpcVerifyDataColumn,
    SamplingResult,
    IgnoredRpcBlock,
    ChainSegment,
    ChainSegmentBackfill,
    Status,
    BlocksByRangeRequest,
    BlocksByRootsRequest,
    BlobsByRangeRequest,
    BlobsByRootsRequest,
    DataColumnsByRootsRequest,
    DataColumnsByRangeRequest,
    GossipBlsToExecutionChange,
    LightClientBootstrapRequest,
    LightClientOptimisticUpdateRequest,
    LightClientFinalityUpdateRequest,
    ApiRequestP0,
    ApiRequestP1,
    Reprocess,
}

impl<E: EthSpec> Work<E> {
    pub fn str_id(&self) -> &'static str {
        self.to_type().into()
    }

    /// Provides a `&str` that uniquely identifies each enum variant.
    pub fn to_type(&self) -> WorkType {
        match self {
            Work::GossipAttestation { .. } => WorkType::GossipAttestation,
            Work::GossipAttestationBatch { .. } => WorkType::GossipAttestationBatch,
            Work::GossipAggregate { .. } => WorkType::GossipAggregate,
            Work::GossipAggregateBatch { .. } => WorkType::GossipAggregateBatch,
            Work::GossipBlock(_) => WorkType::GossipBlock,
            Work::GossipBlobSidecar(_) => WorkType::GossipBlobSidecar,
            Work::GossipDataColumnSidecar(_) => WorkType::GossipDataColumnSidecar,
            Work::DelayedImportBlock { .. } => WorkType::DelayedImportBlock,
            Work::GossipVoluntaryExit(_) => WorkType::GossipVoluntaryExit,
            Work::GossipProposerSlashing(_) => WorkType::GossipProposerSlashing,
            Work::GossipAttesterSlashing(_) => WorkType::GossipAttesterSlashing,
            Work::GossipSyncSignature(_) => WorkType::GossipSyncSignature,
            Work::GossipSyncContribution(_) => WorkType::GossipSyncContribution,
            Work::GossipLightClientFinalityUpdate(_) => WorkType::GossipLightClientFinalityUpdate,
            Work::GossipLightClientOptimisticUpdate(_) => {
                WorkType::GossipLightClientOptimisticUpdate
            }
            Work::GossipBlsToExecutionChange(_) => WorkType::GossipBlsToExecutionChange,
            Work::RpcBlock { .. } => WorkType::RpcBlock,
            Work::RpcBlobs { .. } => WorkType::RpcBlobs,
            Work::RpcCustodyColumn { .. } => WorkType::RpcCustodyColumn,
            Work::RpcVerifyDataColumn { .. } => WorkType::RpcVerifyDataColumn,
            Work::SamplingResult { .. } => WorkType::SamplingResult,
            Work::IgnoredRpcBlock { .. } => WorkType::IgnoredRpcBlock,
            Work::ChainSegment { .. } => WorkType::ChainSegment,
            Work::ChainSegmentBackfill(_) => WorkType::ChainSegmentBackfill,
            Work::Status(_) => WorkType::Status,
            Work::BlocksByRangeRequest(_) => WorkType::BlocksByRangeRequest,
            Work::BlocksByRootsRequest(_) => WorkType::BlocksByRootsRequest,
            Work::BlobsByRangeRequest(_) => WorkType::BlobsByRangeRequest,
            Work::BlobsByRootsRequest(_) => WorkType::BlobsByRootsRequest,
            Work::DataColumnsByRootsRequest(_) => WorkType::DataColumnsByRootsRequest,
            Work::DataColumnsByRangeRequest(_) => WorkType::DataColumnsByRangeRequest,
            Work::LightClientBootstrapRequest(_) => WorkType::LightClientBootstrapRequest,
            Work::LightClientOptimisticUpdateRequest(_) => {
                WorkType::LightClientOptimisticUpdateRequest
            }
            Work::LightClientFinalityUpdateRequest(_) => WorkType::LightClientFinalityUpdateRequest,
            Work::UnknownBlockAttestation { .. } => WorkType::UnknownBlockAttestation,
            Work::UnknownBlockAggregate { .. } => WorkType::UnknownBlockAggregate,
            Work::UnknownBlockSamplingRequest { .. } => WorkType::UnknownBlockSamplingRequest,
            Work::UnknownLightClientOptimisticUpdate { .. } => {
                WorkType::UnknownLightClientOptimisticUpdate
            }
            Work::ApiRequestP0 { .. } => WorkType::ApiRequestP0,
            Work::ApiRequestP1 { .. } => WorkType::ApiRequestP1,
            Work::Reprocess { .. } => WorkType::Reprocess,
        }
    }
}

/// An event to be processed by the manager task.
#[derive(Debug)]
pub struct WorkEvent<E: EthSpec> {
    pub drop_during_sync: bool,
    pub work: Work<E>,
}

impl<E: EthSpec> WorkEvent<E> {
    /// Get a representation of the type of work this `WorkEvent` contains.
    pub fn work_type(&self) -> WorkType {
        self.work.to_type()
    }

    /// Get a `str` representation of the type of work this `WorkEvent` contains.
    pub fn work_type_str(&self) -> &'static str {
        self.work_type().into()
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
                println!("{e}");
                metrics::inc_counter_vec(
                    &metrics::BEACON_PROCESSOR_SEND_ERROR_PER_WORK_TYPE,
                    &[work_type.into()],
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

/// Messages that the scheduler can receive.
#[derive(AsRefStr)]
pub enum ReprocessQueueMessage {
    /// A block that has been received early and we should queue for later processing.
    EarlyBlock(QueuedGossipBlock),
    /// A gossip block for hash `X` is being imported, we should queue the rpc block for the same
    /// hash until the gossip block is imported.
    RpcBlock(QueuedRpcBlock),
    /// A block that was successfully processed. We use this to handle attestations updates
    /// for unknown blocks.
    BlockImported {
        block_root: Hash256,
        parent_root: Hash256,
    },
    /// A new `LightClientOptimisticUpdate` has been produced. We use this to handle light client
    /// updates for unknown parent blocks.
    NewLightClientOptimisticUpdate { parent_root: Hash256 },
    /// An unaggregated attestation that references an unknown block.
    UnknownBlockUnaggregate(QueuedUnaggregate),
    /// An aggregated attestation that references an unknown block.
    UnknownBlockAggregate(QueuedAggregate),
    /// A light client optimistic update that references a parent root that has not been seen as a parent.
    UnknownLightClientOptimisticUpdate(QueuedLightClientUpdate),
    /// A sampling request that references an unknown block.
    UnknownBlockSamplingRequest(QueuedSamplingRequest),
    /// A new backfill batch that needs to be scheduled for processing.
    BackfillSync(QueuedBackfillBatch),
}

/// An Attestation for which the corresponding block was not seen while processing, queued for
/// later.
pub struct QueuedUnaggregate {
    pub beacon_block_root: Hash256,
    pub process_fn: BlockingFn,
}

/// An aggregated attestation for which the corresponding block was not seen while processing, queued for
/// later.
pub struct QueuedAggregate {
    pub beacon_block_root: Hash256,
    pub process_fn: BlockingFn,
}

/// A light client update for which the corresponding parent block was not seen while processing,
/// queued for later.
pub struct QueuedLightClientUpdate {
    pub parent_root: Hash256,
    pub process_fn: BlockingFn,
}

/// A sampling request for which the corresponding block is not known while processing.
pub struct QueuedSamplingRequest {
    pub beacon_block_root: Hash256,
    pub process_fn: BlockingFn,
}

/// A block that arrived early and has been queued for later import.
pub struct QueuedGossipBlock {
    pub beacon_block_slot: Slot,
    pub beacon_block_root: Hash256,
    pub process_fn: AsyncFn,
}

/// A block that arrived for processing when the same block was being imported over gossip.
/// It is queued for later import.
pub struct QueuedRpcBlock {
    pub beacon_block_root: Hash256,
    /// Processes/imports the block.
    pub process_fn: AsyncFn,
    /// Ignores the block.
    pub ignore_fn: BlockingFn,
}

/// A block that arrived for processing when the same block was being imported over gossip.
/// It is queued for later import.
pub struct IgnoredRpcBlock {
    pub process_fn: BlockingFn,
}

/// A backfill batch work that has been queued for processing later.
pub struct QueuedBackfillBatch(pub AsyncFn);

impl<E: EthSpec> TryFrom<WorkEvent<E>> for QueuedBackfillBatch {
    type Error = WorkEvent<E>;

    fn try_from(event: WorkEvent<E>) -> Result<Self, WorkEvent<E>> {
        match event {
            WorkEvent {
                work: Work::ChainSegmentBackfill(process_fn),
                ..
            } => Ok(QueuedBackfillBatch(process_fn)),
            _ => Err(event),
        }
    }
}

impl<E: EthSpec> From<QueuedBackfillBatch> for WorkEvent<E> {
    fn from(queued_backfill_batch: QueuedBackfillBatch) -> WorkEvent<E> {
        WorkEvent {
            drop_during_sync: false,
            work: Work::ChainSegmentBackfill(queued_backfill_batch.0),
        }
    }
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
    UnknownBlockSamplingRequest {
        process_fn: BlockingFn,
    },
    GossipAggregateBatch {
        aggregates: Vec<GossipAggregatePackage<E>>,
        process_batch: Box<dyn FnOnce(Vec<GossipAggregatePackage<E>>) + Send + Sync>,
    },
    GossipBlock(AsyncFn),
    GossipBlobSidecar(AsyncFn),
    GossipDataColumnSidecar(AsyncFn),
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
    RpcCustodyColumn(AsyncFn),
    RpcVerifyDataColumn(AsyncFn),
    SamplingResult(AsyncFn),
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
    DataColumnsByRootsRequest(BlockingFn),
    DataColumnsByRangeRequest(BlockingFn),
    GossipBlsToExecutionChange(BlockingFn),
    LightClientBootstrapRequest(BlockingFn),
    LightClientOptimisticUpdateRequest(BlockingFn),
    LightClientFinalityUpdateRequest(BlockingFn),
    ApiRequestP0(BlockingOrAsync),
    ApiRequestP1(BlockingOrAsync),
    Reprocess(ReprocessQueueMessage),
}

impl<E: EthSpec> fmt::Debug for Work<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Into::<&'static str>::into(self.to_type()))
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
        self,
        beacon_state: &BeaconState<E>,
        event_rx: mpsc::Receiver<WorkEvent<E>>,
        work_journal_tx: Option<mpsc::Sender<&'static str>>,
        slot_clock: S,
        spec: &ChainSpec,
    ) -> Result<(), String> {
        let scheduler = SchedulerType::<E, S>::new(self, beacon_state, spec)?;
        scheduler.run(
            event_rx,
            work_journal_tx,
            slot_clock,
            spec.maximum_gossip_clock_disparity(),
        )
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
