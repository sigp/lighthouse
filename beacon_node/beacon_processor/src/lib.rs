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

pub use crate::scheduler::BeaconProcessorQueueLengths;
use crate::scheduler::work_queue::{LifoQueue, WorkQueues};
use crate::work_reprocessing_queue::{
    QueuedBackfillBatch, QueuedColumnReconstruction, QueuedGossipBlock, QueuedGossipDataColumn,
    QueuedGossipEnvelope, ReprocessQueueMessage,
};
use futures::stream::{Stream, StreamExt};
use futures::task::Poll;
use lighthouse_network::{MessageId, NetworkGlobals, PeerId};
use logging::crit;
use parking_lot::Mutex;
pub use scheduler::work_reprocessing_queue;
use serde::{Deserialize, Serialize};
use slot_clock::SlotClock;
use std::cmp;
use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::time::{Duration, Instant};
use strum::IntoStaticStr;
use task_executor::{RayonPoolType, TaskExecutor};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tracing::{debug, error, trace, warn};
use types::{EthSpec, Hash256, SignedAggregateAndProof, SingleAttestation, Slot, SubnetId};
use work_reprocessing_queue::IgnoredRpcBlock;
use work_reprocessing_queue::{
    QueuedAggregate, QueuedLightClientUpdate, QueuedPayloadAttestation, QueuedRpcBlock,
    QueuedUnaggregate, ReadyWork, spawn_reprocess_scheduler,
};

mod metrics;
pub mod scheduler;

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
pub const ATTESTATION_BATCH_TIMEOUT: &str = "attestation_batch_timeout";

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct BeaconProcessorConfig {
    pub max_workers: usize,
    pub max_work_event_queue_len: usize,
    pub max_scheduled_work_queue_len: usize,
    pub max_gossip_attestation_batch_size: usize,
    pub max_gossip_aggregate_batch_size: usize,
    /// Hold gossip attestations in the queue until this many are pending (or the oldest reaches
    /// `attestation_batch_max_age`), then verify them together as one folded batch. This controls
    /// *when* to dispatch; `max_gossip_attestation_batch_size` caps *how many* per batch. The
    /// trigger is clamped to that cap and to the queue capacity. `1` (the default) removes the
    /// trigger: each attestation is verified as soon as a worker is free. Queued attestations are
    /// still folded together when all workers are busy.
    ///
    /// Values above `1` require `attestation_batch_max_age`, sinces small queues would wait
    /// forever. If it is not provided the processor falls back to `1`.
    pub attestation_batch_trigger: usize,
    /// How long a queued attestation may wait before it is dispatched even though fewer than
    /// `attestation_batch_trigger` are pending. Bounds the latency added by batch collection. Required
    /// when `attestation_batch_trigger` is above `1`, otherwise it is ignored.
    pub attestation_batch_max_age: Option<Duration>,
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
            attestation_batch_trigger: 1,
            attestation_batch_max_age: None,
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
            ReadyWork::Envelope(QueuedGossipEnvelope {
                beacon_block_slot,
                beacon_block_root,
                process_fn,
            }) => Self {
                drop_during_sync: false,
                work: Work::DelayedImportEnvelope {
                    beacon_block_slot,
                    beacon_block_root,
                    process_fn,
                },
            },
            ReadyWork::RpcBlock(QueuedRpcBlock {
                beacon_block_root,
                process_fn,
                ignore_fn: _,
            }) => Self {
                drop_during_sync: false,
                work: Work::RpcBlock {
                    process_fn,
                    beacon_block_root,
                },
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
            ReadyWork::PayloadAttestation(QueuedPayloadAttestation {
                beacon_block_root: _,
                process_fn,
            }) => Self {
                drop_during_sync: true,
                work: Work::UnknownBlockPayloadAttestation { process_fn },
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
            ReadyWork::ColumnReconstruction(QueuedColumnReconstruction { process_fn, .. }) => {
                Self {
                    drop_during_sync: true,
                    work: Work::ColumnReconstruction(process_fn),
                }
            }
            ReadyWork::DataColumn(QueuedGossipDataColumn { process_fn, .. }) => Self {
                drop_during_sync: true,
                work: Work::UnknownBlockDataColumn { process_fn },
            },
        }
    }
}

/// Items required to verify a batch of unaggregated gossip attestations.
#[derive(Debug)]
pub struct GossipAttestationPackage<T> {
    pub message_id: MessageId,
    pub peer_id: PeerId,
    pub attestation: Box<T>,
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
pub type GossipAttestationBatch = Vec<GossipAttestationPackage<SingleAttestation>>;

/// Indicates the type of work to be performed and therefore its priority and
/// queuing specifics.
pub enum Work<E: EthSpec> {
    GossipAttestation {
        attestation: Box<GossipAttestationPackage<SingleAttestation>>,
        process_individual:
            Box<dyn FnOnce(GossipAttestationPackage<SingleAttestation>) + Send + Sync>,
        process_batch: Box<dyn FnOnce(GossipAttestationBatch) + Send + Sync>,
    },
    UnknownBlockAttestation {
        process_fn: BlockingFn,
    },
    UnknownBlockDataColumn {
        process_fn: BlockingFn,
    },
    GossipAttestationBatch {
        attestations: GossipAttestationBatch,
        process_batch: Box<dyn FnOnce(GossipAttestationBatch) + Send + Sync>,
    },
    GossipAggregate {
        aggregate: Box<GossipAggregatePackage<E>>,
        process_individual: Box<dyn FnOnce(GossipAggregatePackage<E>) + Send + Sync>,
        process_batch: Box<dyn FnOnce(Vec<GossipAggregatePackage<E>>) + Send + Sync>,
    },
    UnknownBlockAggregate {
        process_fn: BlockingFn,
    },
    UnknownBlockPayloadAttestation {
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
    GossipDataColumnSidecar(AsyncFn),
    GossipPartialDataColumnSidecar(AsyncFn),
    DelayedImportBlock {
        beacon_block_slot: Slot,
        beacon_block_root: Hash256,
        process_fn: AsyncFn,
    },
    DelayedImportEnvelope {
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
        beacon_block_root: Hash256,
        process_fn: AsyncFn,
    },
    RpcBlobs {
        process_fn: AsyncFn,
    },
    RpcCustodyColumn(AsyncFn),
    RpcEnvelope(AsyncFn),
    ColumnReconstruction(AsyncFn),
    IgnoredRpcBlock {
        process_fn: BlockingFn,
    },
    ChainSegment {
        process_fn: AsyncFn,
        /// (chain_id, batch_epoch) for test observability
        process_id: (u32, u64),
    },
    ChainSegmentBackfill(BlockingFn),
    Status(BlockingFn),
    BlocksByRangeRequest(AsyncFn),
    BlocksByRootsRequest(AsyncFn),
    BlocksByHeadRequest(AsyncFn),
    PayloadEnvelopesByRangeRequest(AsyncFn),
    PayloadEnvelopesByRootRequest(AsyncFn),
    BlobsByRangeRequest(BlockingFn),
    BlobsByRootsRequest(BlockingFn),
    DataColumnsByRootsRequest(BlockingFn),
    DataColumnsByRangeRequest(BlockingFn),
    GossipBlsToExecutionChange(BlockingFn),
    GossipExecutionPayload(AsyncFn),
    GossipExecutionPayloadBid(BlockingFn),
    GossipPayloadAttestation(BlockingFn),
    GossipProposerPreferences(BlockingFn),
    LightClientBootstrapRequest(BlockingFn),
    LightClientOptimisticUpdateRequest(BlockingFn),
    LightClientFinalityUpdateRequest(BlockingFn),
    LightClientUpdatesByRangeRequest(BlockingFn),
    ApiRequestP0(BlockingOrAsync),
    ApiRequestP1(BlockingOrAsync),
    Reprocess(ReprocessQueueMessage),
}

impl<E: EthSpec> fmt::Debug for Work<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Into::<&'static str>::into(self.to_type()))
    }
}

#[derive(IntoStaticStr, PartialEq, Eq, Debug, Clone)]
#[strum(serialize_all = "snake_case")]
pub enum WorkType {
    GossipAttestation,
    UnknownBlockAttestation,
    UnknownBlockDataColumn,
    GossipAttestationBatch,
    GossipAggregate,
    UnknownBlockAggregate,
    UnknownBlockPayloadAttestation,
    UnknownLightClientOptimisticUpdate,
    GossipAggregateBatch,
    GossipBlock,
    GossipDataColumnSidecar,
    GossipPartialDataColumnSidecar,
    DelayedImportBlock,
    DelayedImportEnvelope,
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
    RpcEnvelope,
    ColumnReconstruction,
    IgnoredRpcBlock,
    ChainSegment,
    ChainSegmentBackfill,
    Status,
    BlocksByRangeRequest,
    BlocksByRootsRequest,
    BlocksByHeadRequest,
    PayloadEnvelopesByRangeRequest,
    PayloadEnvelopesByRootRequest,
    BlobsByRangeRequest,
    BlobsByRootsRequest,
    DataColumnsByRootsRequest,
    DataColumnsByRangeRequest,
    GossipBlsToExecutionChange,
    GossipExecutionPayload,
    GossipExecutionPayloadBid,
    GossipPayloadAttestation,
    GossipProposerPreferences,
    LightClientBootstrapRequest,
    LightClientOptimisticUpdateRequest,
    LightClientFinalityUpdateRequest,
    LightClientUpdatesByRangeRequest,
    ApiRequestP0,
    ApiRequestP1,
    Reprocess,
}

impl<E: EthSpec> Work<E> {
    pub fn str_id(&self) -> &'static str {
        self.to_type().into()
    }

    /// Provides a `&str` that uniquely identifies each enum variant.
    fn to_type(&self) -> WorkType {
        match self {
            Work::GossipAttestation { .. } => WorkType::GossipAttestation,
            Work::GossipAttestationBatch { .. } => WorkType::GossipAttestationBatch,
            Work::GossipAggregate { .. } => WorkType::GossipAggregate,
            Work::GossipAggregateBatch { .. } => WorkType::GossipAggregateBatch,
            Work::GossipBlock(_) => WorkType::GossipBlock,
            Work::GossipDataColumnSidecar(_) => WorkType::GossipDataColumnSidecar,
            Work::GossipPartialDataColumnSidecar(_) => WorkType::GossipPartialDataColumnSidecar,
            Work::DelayedImportBlock { .. } => WorkType::DelayedImportBlock,
            Work::DelayedImportEnvelope { .. } => WorkType::DelayedImportEnvelope,
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
            Work::GossipExecutionPayload(_) => WorkType::GossipExecutionPayload,
            Work::GossipExecutionPayloadBid(_) => WorkType::GossipExecutionPayloadBid,
            Work::GossipPayloadAttestation(_) => WorkType::GossipPayloadAttestation,
            Work::GossipProposerPreferences(_) => WorkType::GossipProposerPreferences,
            Work::RpcBlock { .. } => WorkType::RpcBlock,
            Work::RpcBlobs { .. } => WorkType::RpcBlobs,
            Work::RpcCustodyColumn { .. } => WorkType::RpcCustodyColumn,
            Work::RpcEnvelope(_) => WorkType::RpcEnvelope,
            Work::ColumnReconstruction(_) => WorkType::ColumnReconstruction,
            Work::IgnoredRpcBlock { .. } => WorkType::IgnoredRpcBlock,
            Work::ChainSegment { .. } => WorkType::ChainSegment,
            Work::ChainSegmentBackfill(_) => WorkType::ChainSegmentBackfill,
            Work::Status(_) => WorkType::Status,
            Work::BlocksByRangeRequest(_) => WorkType::BlocksByRangeRequest,
            Work::BlocksByRootsRequest(_) => WorkType::BlocksByRootsRequest,
            Work::BlocksByHeadRequest(_) => WorkType::BlocksByHeadRequest,
            Work::PayloadEnvelopesByRangeRequest(_) => WorkType::PayloadEnvelopesByRangeRequest,
            Work::PayloadEnvelopesByRootRequest(_) => WorkType::PayloadEnvelopesByRootRequest,
            Work::BlobsByRangeRequest(_) => WorkType::BlobsByRangeRequest,
            Work::BlobsByRootsRequest(_) => WorkType::BlobsByRootsRequest,
            Work::DataColumnsByRootsRequest(_) => WorkType::DataColumnsByRootsRequest,
            Work::DataColumnsByRangeRequest(_) => WorkType::DataColumnsByRangeRequest,
            Work::LightClientBootstrapRequest(_) => WorkType::LightClientBootstrapRequest,
            Work::LightClientOptimisticUpdateRequest(_) => {
                WorkType::LightClientOptimisticUpdateRequest
            }
            Work::LightClientFinalityUpdateRequest(_) => WorkType::LightClientFinalityUpdateRequest,
            Work::LightClientUpdatesByRangeRequest(_) => WorkType::LightClientUpdatesByRangeRequest,
            Work::UnknownBlockAttestation { .. } => WorkType::UnknownBlockAttestation,
            Work::UnknownBlockDataColumn { .. } => WorkType::UnknownBlockDataColumn,
            Work::UnknownBlockAggregate { .. } => WorkType::UnknownBlockAggregate,
            Work::UnknownBlockPayloadAttestation { .. } => WorkType::UnknownBlockPayloadAttestation,
            Work::UnknownLightClientOptimisticUpdate { .. } => {
                WorkType::UnknownLightClientOptimisticUpdate
            }
            Work::ApiRequestP0 { .. } => WorkType::ApiRequestP0,
            Work::ApiRequestP1 { .. } => WorkType::ApiRequestP1,
            Work::Reprocess { .. } => WorkType::Reprocess,
        }
    }
}

/// Unifies all the messages processed by the `BeaconProcessor`.
enum InboundEvent<E: EthSpec> {
    /// A worker has completed a task and is free.
    WorkerIdle,
    /// The oldest queued attestation reached its max age and should be dispatched even though
    /// fewer than `attestation_batch_trigger` are queued.
    AttestationBatchTimeout,
    /// There is new work to be done.
    WorkEvent((WorkEvent<E>, Instant)),
    /// A work event that was queued for re-processing has become ready.
    ReprocessingWork((WorkEvent<E>, Instant)),
}

/// Combines the various incoming event streams for the `BeaconProcessor` into a single stream.
///
/// This struct has a similar purpose to `tokio::select!`, however it allows for more fine-grained
/// control (specifically in the ordering of event processing).
struct InboundEvents<E: EthSpec> {
    /// Used by workers when they finish a task.
    idle_rx: mpsc::Receiver<WorkType>,
    /// Used by upstream processes to send new work to the `BeaconProcessor`.
    event_rx: mpsc::Receiver<WorkEvent<E>>,
    /// Used internally for queuing work ready to be re-processed.
    ready_work_rx: mpsc::Receiver<ReadyWork>,
    /// Fires when the oldest queued attestation reaches its max age, so a sub-trigger batch is
    /// still dispatched under light load. (Re)set each loop iteration by `set_attestation_timer`.
    attestation_timer: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<E: EthSpec> InboundEvents<E> {
    /// (Re)arm the attestation age-bound timer for `deadline`, or clear it when `None`. Cheap to
    /// call every iteration: unchanged deadlines are a no-op, and changed ones reuse the existing
    /// allocation via `Sleep::reset`.
    fn set_attestation_timer(&mut self, deadline: Option<tokio::time::Instant>) {
        let Some(deadline) = deadline else {
            self.attestation_timer = None;
            return;
        };
        if let Some(timer) = self.attestation_timer.as_mut() {
            if timer.deadline() != deadline {
                timer.as_mut().reset(deadline);
            }
        } else {
            self.attestation_timer = Some(Box::pin(tokio::time::sleep_until(deadline)));
        }
    }
}

impl<E: EthSpec> Stream for InboundEvents<E> {
    type Item = InboundEvent<E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Always check for idle workers before anything else. This allows us to ensure that a big
        // stream of new events doesn't suppress the processing of existing events.
        match self.idle_rx.poll_recv(cx) {
            Poll::Ready(Some(_)) => {
                return Poll::Ready(Some(InboundEvent::WorkerIdle));
            }
            Poll::Ready(None) => {
                return Poll::Ready(None);
            }
            Poll::Pending => {}
        }

        // Poll for delayed blocks before polling for new work. It might be the case that a delayed
        // block is required to successfully process some new work.
        match self.ready_work_rx.poll_recv(cx) {
            Poll::Ready(Some(ready_work)) => {
                return Poll::Ready(Some(InboundEvent::ReprocessingWork((
                    ready_work.into(),
                    Instant::now(),
                ))));
            }
            Poll::Ready(None) => {
                return Poll::Ready(None);
            }
            Poll::Pending => {}
        }

        match self.event_rx.poll_recv(cx) {
            Poll::Ready(Some(event)) => {
                return Poll::Ready(Some(InboundEvent::WorkEvent((event, Instant::now()))));
            }
            Poll::Ready(None) => {
                return Poll::Ready(None);
            }
            Poll::Pending => {}
        }

        // Poll the age-bound timer last, so it never suppresses real work.
        if let Some(timer) = self.attestation_timer.as_mut()
            && timer.as_mut().poll(cx).is_ready()
        {
            self.attestation_timer = None;
            return Poll::Ready(Some(InboundEvent::AttestationBatchTimeout));
        }

        Poll::Pending
    }
}

/// Take up to `batch_cap` items from the front of `queue` as one `Work` item: unchanged if only
/// one is taken, otherwise folded via `make_batch` so they share a single signature verification.
///
/// `unpack` pulls the package and batch closure out of the queue's work variant; items of any
/// other variant are logged and dropped. Returns `None` if the queue is empty.
fn take_work_batch<E: EthSpec, Item, BatchFn>(
    queue: &mut LifoQueue<(Instant, Work<E>)>,
    batch_cap: usize,
    invalid_item_msg: &'static str,
    missing_work_msg: &'static str,
    unpack: impl Fn(Work<E>) -> Option<(Item, BatchFn)>,
    make_batch: impl FnOnce(Vec<Item>, BatchFn) -> Work<E>,
) -> Option<Work<E>> {
    let batch_size = cmp::min(queue.len(), batch_cap.max(1));

    // Zero or one item: pop the single item (or `None` if the queue is empty).
    if batch_size < 2 {
        return queue.pop().map(|(_, work)| work);
    }

    let mut items = Vec::with_capacity(batch_size);
    let mut process_batch_opt = None;
    for _ in 0..batch_size {
        if let Some((_, work)) = queue.pop() {
            if let Some((item, process_batch)) = unpack(work) {
                items.push(item);
                process_batch_opt.get_or_insert(process_batch);
            } else {
                error!("{}", invalid_item_msg);
            }
        }
    }

    if let Some(process_batch) = process_batch_opt {
        Some(make_batch(items, process_batch))
    } else {
        // We only batch when two or more items exist, so a closure should always be present.
        // Missing one is a serious logic error.
        crit!("{}", missing_work_msg);
        None
    }
}

/// Take up to `batch_cap` attestations as one `Work` item: a `GossipAttestation` if only one is
/// taken, otherwise a folded `GossipAttestationBatch`. `None` if the queue is empty.
fn take_attestation_batch<E: EthSpec>(
    attestation_queue: &mut LifoQueue<(Instant, Work<E>)>,
    batch_cap: usize,
) -> Option<Work<E>> {
    take_work_batch(
        attestation_queue,
        batch_cap,
        "Invalid item in attestation queue",
        "Missing attestations work",
        |work| match work {
            Work::GossipAttestation {
                attestation,
                process_individual: _,
                process_batch,
            } => Some((*attestation, process_batch)),
            _ => None,
        },
        |attestations, process_batch| Work::GossipAttestationBatch {
            attestations,
            process_batch,
        },
    )
}

/// Take up to `batch_cap` aggregates as one `Work` item: a `GossipAggregate` if only one is taken,
/// otherwise a folded `GossipAggregateBatch`. `None` if the queue is empty.
fn take_aggregate_batch<E: EthSpec>(
    aggregate_queue: &mut LifoQueue<(Instant, Work<E>)>,
    batch_cap: usize,
) -> Option<Work<E>> {
    take_work_batch(
        aggregate_queue,
        batch_cap,
        "Invalid item in aggregate queue",
        "Missing aggregate work",
        |work| match work {
            Work::GossipAggregate {
                aggregate,
                process_individual: _,
                process_batch,
            } => Some((*aggregate, process_batch)),
            _ => None,
        },
        |aggregates, process_batch| Work::GossipAggregateBatch {
            aggregates,
            process_batch,
        },
    )
}

/// Whether the attestation queue should be flushed now: at least `trigger` are pending (a
/// `trigger` of `1` means any non-empty queue), or the oldest reached `max_age`.
fn attestation_flush_ready<E: EthSpec>(
    attestation_queue: &LifoQueue<(Instant, Work<E>)>,
    trigger: usize,
    max_age: Option<Duration>,
) -> bool {
    let queue_len = attestation_queue.len();
    if queue_len == 0 {
        return false;
    }
    if queue_len >= trigger {
        return true;
    }
    match (max_age, attestation_queue.back()) {
        (Some(max_age), Some((enqueued_at, _))) => enqueued_at.elapsed() >= max_age,
        _ => false,
    }
}

/// Flush the attestation queue if the batch-collection trigger or age bound is met, taking up to
/// `batch_cap` attestations as a single `Work` item.
fn take_ready_attestation_batch<E: EthSpec>(
    attestation_queue: &mut LifoQueue<(Instant, Work<E>)>,
    trigger: usize,
    max_age: Option<Duration>,
    batch_cap: usize,
) -> Option<Work<E>> {
    if attestation_flush_ready(attestation_queue, trigger, max_age) {
        take_attestation_batch(attestation_queue, batch_cap)
    } else {
        None
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
        work_journal_tx: Option<mpsc::Sender<&'static str>>,
        slot_clock: S,
        maximum_gossip_clock_disparity: Duration,
        queue_lengths: BeaconProcessorQueueLengths,
    ) -> Result<(), String> {
        // Used by workers to communicate that they are finished a task.
        let (idle_tx, idle_rx) = mpsc::channel::<WorkType>(MAX_IDLE_QUEUE_LEN);

        // Initialize the worker queues.
        let mut work_queues: WorkQueues<E> = WorkQueues::new(queue_lengths);

        // Channels for sending work to the re-process scheduler (`work_reprocessing_tx`) and to
        // receive them back once they are ready (`ready_work_rx`).
        let (ready_work_tx, ready_work_rx) =
            mpsc::channel::<ReadyWork>(self.config.max_scheduled_work_queue_len);

        let (reprocess_work_tx, reprocess_work_rx) =
            mpsc::channel::<ReprocessQueueMessage>(self.config.max_scheduled_work_queue_len);

        spawn_reprocess_scheduler(
            ready_work_tx,
            reprocess_work_rx,
            &self.executor,
            Arc::new(slot_clock),
            maximum_gossip_clock_disparity,
        )?;

        let executor = self.executor.clone();

        // The manager future will run on the core executor and delegate tasks to worker
        // threads on the blocking executor.
        let manager_future = async move {
            let mut inbound_events = InboundEvents {
                idle_rx,
                event_rx,
                ready_work_rx,
                attestation_timer: None,
            };

            let enable_backfill_rate_limiting = self.config.enable_backfill_rate_limiting;

            // Attestation batch collection. See `BeaconProcessorConfig::attestation_batch_trigger`.
            // `att_batch_cap` caps how many are taken per batch.
            let att_batch_cap = self.config.max_gossip_attestation_batch_size;
            let att_batch_max_age = self.config.attestation_batch_max_age;
            let att_batch_trigger = {
                let configured = self.config.attestation_batch_trigger;
                // Clamp to the batch cap (so an age-triggered flush takes the whole sub-trigger
                // queue) and to the queue capacity (so the trigger is reachable at all).
                let clamped = configured
                    .max(1)
                    .min(att_batch_cap.max(1))
                    .min(work_queues.attestation_queue.max_length.max(1));
                // A sub-trigger batch needs an age bound or it waits forever.
                // The CLI should reject this but guard here anyway.
                let effective = if clamped > 1 && att_batch_max_age.is_none() {
                    1
                } else {
                    clamped
                };
                if effective != configured {
                    warn!(
                        configured,
                        effective, "Attestation batch trigger adjusted to a safe value"
                    );
                }
                effective
            };
            let att_batch_trigger_enabled = att_batch_trigger > 1;

            loop {
                let mut attestation_timer_fired = false;
                let (work_event, created_timestamp) = match inbound_events.next().await {
                    Some(InboundEvent::WorkerIdle) => {
                        self.current_workers = self.current_workers.saturating_sub(1);
                        (None, Instant::now())
                    }
                    // The age bound elapsed. Fall through to the dispatch ladder (as if a worker
                    // freed) to flush the oldest attestations. A no-op if no worker is free; the
                    // batch then waits for the next `WorkerIdle`.
                    Some(InboundEvent::AttestationBatchTimeout) => {
                        attestation_timer_fired = true;
                        (None, Instant::now())
                    }
                    Some(InboundEvent::WorkEvent((event, created_timestamp)))
                        if enable_backfill_rate_limiting =>
                    {
                        match QueuedBackfillBatch::try_from(event) {
                            Ok(backfill_batch) => {
                                match reprocess_work_tx
                                    .try_send(ReprocessQueueMessage::BackfillSync(backfill_batch))
                                {
                                    Err(e) => {
                                        warn!(
                                            error = %e,
                                            "Unable to queue backfill work event. Will try to process now."
                                        );
                                        match e {
                                            TrySendError::Full(reprocess_queue_message)
                                            | TrySendError::Closed(reprocess_queue_message) => {
                                                match reprocess_queue_message {
                                                    ReprocessQueueMessage::BackfillSync(
                                                        backfill_batch,
                                                    ) => (
                                                        Some(backfill_batch.into()),
                                                        created_timestamp,
                                                    ),
                                                    other => {
                                                        crit!(
                                                            message_type = other.as_ref(),
                                                            "Unexpected queue message type"
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
                            Err(event) => (Some(event), created_timestamp),
                        }
                    }
                    Some(InboundEvent::WorkEvent((event, created_timestamp)))
                    | Some(InboundEvent::ReprocessingWork((event, created_timestamp))) => {
                        (Some(event), created_timestamp)
                    }
                    None => {
                        debug!(msg = "stream ended", "Gossip processor stopped");
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
                } else if !attestation_timer_fired {
                    // A batch timeout is also a `None` work event, but no worker freed.
                    metrics::inc_counter(&metrics::BEACON_PROCESSOR_IDLE_EVENTS_TOTAL);
                }

                if let Some(work_journal_tx) = &work_journal_tx {
                    let id = work_event
                        .as_ref()
                        .map(|event| event.work.str_id())
                        .unwrap_or(if attestation_timer_fired {
                            ATTESTATION_BATCH_TIMEOUT
                        } else {
                            WORKER_FREED
                        });

                    // We don't care if this message was successfully sent, we only use the journal
                    // during testing. We also ignore reprocess messages to ensure our test cases can pass.
                    if id != "reprocess" {
                        let _ = work_journal_tx.try_send(id);
                    }
                }

                let can_spawn = self.current_workers < self.config.max_workers;
                let drop_during_sync = work_event
                    .as_ref()
                    .is_some_and(|event| event.drop_during_sync);

                let idle_tx = idle_tx.clone();
                let modified_queue_id = match work_event {
                    // There is no new work event, but we are able to spawn a new worker.
                    //
                    // We don't check the `work.drop_during_sync` here. We assume that if it made
                    // it into the queue at any point then we should process it.
                    None if can_spawn => {
                        // Check for chain segments first, they're the most efficient way to get
                        // blocks into the system.
                        let work_event: Option<Work<E>> = if let Some(item) =
                            work_queues.chain_segment_queue.pop()
                        {
                            Some(item)
                        // Check sync blocks before gossip blocks, since we've already explicitly
                        // requested these blocks.
                        } else if let Some(item) = work_queues.rpc_block_queue.pop() {
                            Some(item)
                        } else if let Some(item) = work_queues.rpc_blob_queue.pop() {
                            Some(item)
                        } else if let Some(item) = work_queues.rpc_custody_column_queue.pop() {
                            Some(item)
                        } else if let Some(item) = work_queues.rpc_envelope_queue.pop() {
                            Some(item)
                        // Check delayed blocks before gossip blocks, the gossip blocks might rely
                        // on the delayed ones.
                        } else if let Some(item) = work_queues.delayed_block_queue.pop() {
                            Some(item)
                        } else if let Some(item) = work_queues.delayed_envelope_queue.pop() {
                            Some(item)
                        // Check gossip blocks and payloads before gossip attestations, since a block might be
                        // required to verify some attestations.
                        } else if let Some(item) = work_queues.gossip_block_queue.pop() {
                            Some(item)
                        } else if let Some(item) = work_queues.gossip_execution_payload_queue.pop()
                        {
                            Some(item)
                        } else if let Some(item) = work_queues.gossip_data_column_queue.pop() {
                            Some(item)
                        } else if let Some(item) = work_queues.unknown_block_data_column_queue.pop()
                        {
                            Some(item)
                        } else if let Some(item) =
                            work_queues.gossip_partial_data_column_queue.pop()
                        {
                            Some(item)
                        } else if let Some(item) = work_queues.column_reconstruction_queue.pop() {
                            Some(item)
                        // Check the priority 0 API requests after blocks and blobs, but before attestations.
                        } else if let Some(item) = work_queues.api_request_p0_queue.pop() {
                            Some(item)
                        // Check the aggregates, *then* the unaggregates since we assume that
                        // aggregates are more valuable to local validators and effectively give us
                        // more information with less signature verification time.
                        } else if let Some(item) = take_aggregate_batch(
                            &mut work_queues.aggregate_queue,
                            self.config.max_gossip_aggregate_batch_size,
                        ) {
                            Some(item)
                        // Check the unaggregated attestations, subject to the batch-collection trigger.
                        } else if let Some(batch) = take_ready_attestation_batch(
                            &mut work_queues.attestation_queue,
                            att_batch_trigger,
                            att_batch_max_age,
                            att_batch_cap,
                        ) {
                            Some(batch)
                        // Check payload attestation messages after attestations. They dont give rewards
                        // but they influence fork choice.
                        } else if let Some(item) =
                            work_queues.gossip_payload_attestation_queue.pop()
                        {
                            Some(item)
                        // Check sync committee messages after attestations as their rewards are lesser
                        // and they don't influence fork choice.
                        } else if let Some(item) = work_queues.sync_contribution_queue.pop() {
                            Some(item)
                        } else if let Some(item) = work_queues.sync_message_queue.pop() {
                            Some(item)
                        // Aggregates and unaggregates queued for re-processing are older and we
                        // care about fresher ones, so check those first.
                        } else if let Some(item) = work_queues.unknown_block_aggregate_queue.pop() {
                            Some(item)
                        } else if let Some(item) = work_queues.unknown_block_attestation_queue.pop()
                        {
                            Some(item)
                        } else if let Some(item) =
                            work_queues.unknown_block_payload_attestation_queue.pop()
                        {
                            Some(item)
                        // Check execution payload bids. Most proposers will request bids directly from builders
                        // instead of receiving them over gossip.
                        } else if let Some(item) =
                            work_queues.gossip_execution_payload_bid_queue.pop()
                        {
                            Some(item)
                        // Check proposer preferences.
                        } else if let Some(item) =
                            work_queues.gossip_proposer_preferences_queue.pop()
                        {
                            Some(item)
                        // Check RPC methods next. Status messages are needed for sync so
                        // prioritize them over syncing requests from other peers (BlocksByRange
                        // and BlocksByRoot)
                        } else if let Some(item) = work_queues.status_queue.pop() {
                            Some(item)
                        } else if let Some(item) = work_queues.block_brange_queue.pop() {
                            Some(item)
                        } else if let Some(item) = work_queues.block_broots_queue.pop() {
                            Some(item)
                        } else if let Some(item) = work_queues.block_bhead_queue.pop() {
                            Some(item)
                        } else if let Some(item) = work_queues.blob_brange_queue.pop() {
                            Some(item)
                        } else if let Some(item) = work_queues.blob_broots_queue.pop() {
                            Some(item)
                        } else if let Some(item) = work_queues.dcbroots_queue.pop() {
                            Some(item)
                        } else if let Some(item) = work_queues.dcbrange_queue.pop() {
                            Some(item)
                        } else if let Some(item) = work_queues.payload_envelopes_brange_queue.pop()
                        {
                            Some(item)
                        } else if let Some(item) = work_queues.payload_envelopes_broots_queue.pop()
                        {
                            Some(item)
                        // Check slashings after all other consensus messages so we prioritize
                        // following head.
                        //
                        // Check attester slashings before proposer slashings since they have the
                        // potential to slash multiple validators at once.
                        } else if let Some(item) = work_queues.gossip_attester_slashing_queue.pop()
                        {
                            Some(item)
                        } else if let Some(item) = work_queues.gossip_proposer_slashing_queue.pop()
                        {
                            Some(item)
                        // Check exits and address changes late since our validators don't get
                        // rewards from them.
                        } else if let Some(item) = work_queues.gossip_voluntary_exit_queue.pop() {
                            Some(item)
                        } else if let Some(item) =
                            work_queues.gossip_bls_to_execution_change_queue.pop()
                        {
                            Some(item)
                        // Check the priority 1 API requests after we've
                        // processed all the interesting things from the network
                        // and things required for us to stay in good repute
                        // with our P2P peers.
                        } else if let Some(item) = work_queues.api_request_p1_queue.pop() {
                            Some(item)
                        // Handle backfill sync chain segments.
                        } else if let Some(item) = work_queues.backfill_chain_segment.pop() {
                            Some(item)
                            // Handle light client requests.
                        } else if let Some(item) = work_queues.lc_gossip_finality_update_queue.pop()
                        {
                            Some(item)
                        } else if let Some(item) =
                            work_queues.lc_gossip_optimistic_update_queue.pop()
                        {
                            Some(item)
                        } else if let Some(item) =
                            work_queues.unknown_light_client_update_queue.pop()
                        {
                            Some(item)
                        } else if let Some(item) = work_queues.lc_bootstrap_queue.pop() {
                            Some(item)
                        } else if let Some(item) = work_queues.lc_rpc_optimistic_update_queue.pop()
                        {
                            Some(item)
                        } else if let Some(item) = work_queues.lc_rpc_finality_update_queue.pop() {
                            Some(item)
                        } else if let Some(item) = work_queues.lc_update_range_queue.pop() {
                            Some(item)
                            // This statement should always be the final else statement.
                        } else {
                            // Let the journal know that a worker is freed and there's nothing else
                            // for it to do.
                            if let Some(work_journal_tx) = &work_journal_tx {
                                // We don't care if this message was successfully sent, we only use the journal
                                // during testing.
                                let _ = work_journal_tx.try_send(NOTHING_TO_DO);
                            }
                            None
                        };

                        if let Some(work_event) = work_event {
                            let work_type = work_event.to_type();
                            self.spawn_worker(work_event, created_timestamp, idle_tx);
                            Some(work_type)
                        } else {
                            None
                        }
                    }
                    // There is no new work event and we are unable to spawn a new worker.
                    None => {
                        if attestation_timer_fired {
                            // The age bound elapsed while all workers are busy. The batch
                            // flushes when a worker next frees. This is fine.
                            trace!(
                                msg = "no new work and cannot spawn worker",
                                "Attestation batch timeout with no free worker"
                            );
                        } else {
                            // A worker-idle event with no spawn capacity means broken worker
                            // accounting; there is no good reason for this to happen.
                            warn!(
                                msg = "no new work and cannot spawn worker",
                                "Unexpected gossip processor condition"
                            );
                        }
                        None
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
                            msg = "chain is syncing",
                            work_id = work_id,
                            "Gossip processor skipping work"
                        );
                        None
                    }
                    // There is a new work event and the chain is not syncing. Process it or queue
                    // it.
                    Some(WorkEvent { work, .. }) => {
                        let work_id = work.str_id();
                        let work_type = work.to_type();

                        match work {
                            Work::Reprocess(work_event) => {
                                if let Err(e) = reprocess_work_tx.try_send(work_event) {
                                    error!(
                                        error = ?e,
                                        "Failed to reprocess work event"
                                    )
                                }
                            }
                            // Batch trigger disabled. Verify immediately.
                            Work::GossipAttestation { .. }
                                if !att_batch_trigger_enabled && can_spawn =>
                            {
                                self.spawn_worker(work, created_timestamp, idle_tx)
                            }
                            // Otherwise queue it to join a batch, and dispatch right away if that
                            // made a batch ready and a worker is free.
                            Work::GossipAttestation { .. } => {
                                work_queues
                                    .attestation_queue
                                    .push((created_timestamp, work));
                                if can_spawn
                                    && let Some(batch) = take_ready_attestation_batch(
                                        &mut work_queues.attestation_queue,
                                        att_batch_trigger,
                                        att_batch_max_age,
                                        att_batch_cap,
                                    )
                                {
                                    self.spawn_worker(batch, created_timestamp, idle_tx);
                                }
                            }
                            _ if can_spawn => self.spawn_worker(work, created_timestamp, idle_tx),
                            // Attestation batches are formed internally within the
                            // `BeaconProcessor`, they are not sent from external services.
                            Work::GossipAttestationBatch { .. } => crit!(
                                work_type = "GossipAttestationBatch",
                                "Unsupported inbound event"
                            ),
                            Work::GossipAggregate { .. } => {
                                work_queues.aggregate_queue.push((created_timestamp, work))
                            }
                            // Aggregate batches are formed internally within the `BeaconProcessor`,
                            // they are not sent from external services.
                            Work::GossipAggregateBatch { .. } => {
                                crit!(
                                    work_type = "GossipAggregateBatch",
                                    "Unsupported inbound event"
                                )
                            }
                            Work::GossipBlock { .. } => {
                                work_queues.gossip_block_queue.push(work, work_id)
                            }
                            Work::GossipDataColumnSidecar { .. } => {
                                work_queues.gossip_data_column_queue.push(work, work_id)
                            }
                            Work::GossipPartialDataColumnSidecar { .. } => work_queues
                                .gossip_partial_data_column_queue
                                .push(work, work_id),
                            Work::DelayedImportBlock { .. } => {
                                work_queues.delayed_block_queue.push(work, work_id)
                            }
                            Work::DelayedImportEnvelope { .. } => {
                                work_queues.delayed_envelope_queue.push(work, work_id)
                            }
                            Work::GossipVoluntaryExit { .. } => {
                                work_queues.gossip_voluntary_exit_queue.push(work, work_id)
                            }
                            Work::GossipProposerSlashing { .. } => work_queues
                                .gossip_proposer_slashing_queue
                                .push(work, work_id),
                            Work::GossipAttesterSlashing { .. } => work_queues
                                .gossip_attester_slashing_queue
                                .push(work, work_id),
                            Work::GossipSyncSignature { .. } => {
                                work_queues.sync_message_queue.push(work)
                            }
                            Work::GossipSyncContribution { .. } => {
                                work_queues.sync_contribution_queue.push(work)
                            }
                            Work::GossipLightClientFinalityUpdate { .. } => work_queues
                                .lc_gossip_finality_update_queue
                                .push(work, work_id),
                            Work::GossipLightClientOptimisticUpdate { .. } => work_queues
                                .lc_gossip_optimistic_update_queue
                                .push(work, work_id),
                            Work::RpcBlock { .. } | Work::IgnoredRpcBlock { .. } => {
                                work_queues.rpc_block_queue.push(work, work_id)
                            }
                            Work::RpcBlobs { .. } => work_queues.rpc_blob_queue.push(work, work_id),
                            Work::RpcEnvelope(_) => {
                                work_queues.rpc_envelope_queue.push(work, work_id)
                            }
                            Work::RpcCustodyColumn { .. } => {
                                work_queues.rpc_custody_column_queue.push(work, work_id)
                            }
                            Work::ColumnReconstruction(_) => {
                                work_queues.column_reconstruction_queue.push(work)
                            }
                            Work::ChainSegment { .. } => {
                                work_queues.chain_segment_queue.push(work, work_id)
                            }
                            Work::ChainSegmentBackfill { .. } => {
                                work_queues.backfill_chain_segment.push(work, work_id)
                            }
                            Work::Status { .. } => work_queues.status_queue.push(work, work_id),
                            Work::BlocksByRangeRequest { .. } => {
                                work_queues.block_brange_queue.push(work, work_id)
                            }
                            Work::BlocksByRootsRequest { .. } => {
                                work_queues.block_broots_queue.push(work, work_id)
                            }
                            Work::BlocksByHeadRequest { .. } => {
                                work_queues.block_bhead_queue.push(work, work_id)
                            }
                            Work::PayloadEnvelopesByRangeRequest { .. } => work_queues
                                .payload_envelopes_brange_queue
                                .push(work, work_id),
                            Work::PayloadEnvelopesByRootRequest { .. } => work_queues
                                .payload_envelopes_broots_queue
                                .push(work, work_id),
                            Work::BlobsByRangeRequest { .. } => {
                                work_queues.blob_brange_queue.push(work, work_id)
                            }
                            Work::LightClientBootstrapRequest { .. } => {
                                work_queues.lc_bootstrap_queue.push(work, work_id)
                            }
                            Work::LightClientOptimisticUpdateRequest { .. } => work_queues
                                .lc_rpc_optimistic_update_queue
                                .push(work, work_id),
                            Work::LightClientFinalityUpdateRequest { .. } => {
                                work_queues.lc_rpc_finality_update_queue.push(work, work_id)
                            }
                            Work::LightClientUpdatesByRangeRequest { .. } => {
                                work_queues.lc_update_range_queue.push(work, work_id)
                            }
                            Work::UnknownBlockAttestation { .. } => {
                                work_queues.unknown_block_attestation_queue.push(work)
                            }
                            Work::UnknownBlockDataColumn { .. } => work_queues
                                .unknown_block_data_column_queue
                                .push(work, work_id),
                            Work::UnknownBlockAggregate { .. } => {
                                work_queues.unknown_block_aggregate_queue.push(work)
                            }
                            Work::UnknownBlockPayloadAttestation { .. } => work_queues
                                .unknown_block_payload_attestation_queue
                                .push(work),
                            Work::GossipBlsToExecutionChange { .. } => work_queues
                                .gossip_bls_to_execution_change_queue
                                .push(work, work_id),
                            Work::GossipExecutionPayload { .. } => work_queues
                                .gossip_execution_payload_queue
                                .push(work, work_id),
                            Work::GossipExecutionPayloadBid { .. } => work_queues
                                .gossip_execution_payload_bid_queue
                                .push(work, work_id),
                            Work::GossipPayloadAttestation { .. } => work_queues
                                .gossip_payload_attestation_queue
                                .push(work, work_id),
                            Work::GossipProposerPreferences { .. } => work_queues
                                .gossip_proposer_preferences_queue
                                .push(work, work_id),
                            Work::BlobsByRootsRequest { .. } => {
                                work_queues.blob_broots_queue.push(work, work_id)
                            }
                            Work::DataColumnsByRootsRequest { .. } => {
                                work_queues.dcbroots_queue.push(work, work_id)
                            }
                            Work::DataColumnsByRangeRequest { .. } => {
                                work_queues.dcbrange_queue.push(work, work_id)
                            }
                            Work::UnknownLightClientOptimisticUpdate { .. } => work_queues
                                .unknown_light_client_update_queue
                                .push(work, work_id),
                            Work::ApiRequestP0 { .. } => {
                                work_queues.api_request_p0_queue.push(work, work_id)
                            }
                            Work::ApiRequestP1 { .. } => {
                                work_queues.api_request_p1_queue.push(work, work_id)
                            }
                        };
                        Some(work_type)
                    }
                };

                if let Some(modified_queue_id) = modified_queue_id {
                    let queue_len = match modified_queue_id {
                        WorkType::GossipAttestation => work_queues.attestation_queue.len(),
                        WorkType::UnknownBlockAttestation => {
                            work_queues.unknown_block_attestation_queue.len()
                        }
                        WorkType::UnknownBlockDataColumn => {
                            work_queues.unknown_block_data_column_queue.len()
                        }
                        WorkType::GossipAttestationBatch => 0, // No queue
                        WorkType::GossipAggregate => work_queues.aggregate_queue.len(),
                        WorkType::UnknownBlockAggregate => {
                            work_queues.unknown_block_aggregate_queue.len()
                        }
                        WorkType::UnknownBlockPayloadAttestation => {
                            work_queues.unknown_block_payload_attestation_queue.len()
                        }
                        WorkType::UnknownLightClientOptimisticUpdate => {
                            work_queues.unknown_light_client_update_queue.len()
                        }
                        WorkType::GossipAggregateBatch => 0, // No queue
                        WorkType::GossipBlock => work_queues.gossip_block_queue.len(),
                        WorkType::GossipDataColumnSidecar => {
                            work_queues.gossip_data_column_queue.len()
                        }
                        WorkType::GossipPartialDataColumnSidecar => {
                            work_queues.gossip_partial_data_column_queue.len()
                        }
                        WorkType::DelayedImportBlock => work_queues.delayed_block_queue.len(),
                        WorkType::DelayedImportEnvelope => work_queues.delayed_envelope_queue.len(),
                        WorkType::GossipVoluntaryExit => {
                            work_queues.gossip_voluntary_exit_queue.len()
                        }
                        WorkType::GossipProposerSlashing => {
                            work_queues.gossip_proposer_slashing_queue.len()
                        }
                        WorkType::GossipAttesterSlashing => {
                            work_queues.gossip_attester_slashing_queue.len()
                        }
                        WorkType::GossipSyncSignature => work_queues.sync_message_queue.len(),
                        WorkType::GossipSyncContribution => {
                            work_queues.sync_contribution_queue.len()
                        }
                        WorkType::GossipLightClientFinalityUpdate => {
                            work_queues.lc_gossip_finality_update_queue.len()
                        }
                        WorkType::GossipLightClientOptimisticUpdate => {
                            work_queues.lc_gossip_optimistic_update_queue.len()
                        }
                        WorkType::RpcBlock => work_queues.rpc_block_queue.len(),
                        WorkType::RpcBlobs | WorkType::IgnoredRpcBlock => {
                            work_queues.rpc_blob_queue.len()
                        }
                        WorkType::RpcEnvelope => work_queues.rpc_envelope_queue.len(),
                        WorkType::RpcCustodyColumn => work_queues.rpc_custody_column_queue.len(),
                        WorkType::ColumnReconstruction => {
                            work_queues.column_reconstruction_queue.len()
                        }
                        WorkType::ChainSegment => work_queues.chain_segment_queue.len(),
                        WorkType::ChainSegmentBackfill => work_queues.backfill_chain_segment.len(),
                        WorkType::Status => work_queues.status_queue.len(),
                        WorkType::BlocksByRangeRequest => work_queues.block_brange_queue.len(),
                        WorkType::BlocksByRootsRequest => work_queues.block_broots_queue.len(),
                        WorkType::BlocksByHeadRequest => work_queues.block_bhead_queue.len(),
                        WorkType::PayloadEnvelopesByRangeRequest => {
                            work_queues.payload_envelopes_brange_queue.len()
                        }
                        WorkType::PayloadEnvelopesByRootRequest => {
                            work_queues.payload_envelopes_broots_queue.len()
                        }
                        WorkType::BlobsByRangeRequest => work_queues.blob_brange_queue.len(),
                        WorkType::BlobsByRootsRequest => work_queues.blob_broots_queue.len(),
                        WorkType::DataColumnsByRootsRequest => work_queues.dcbroots_queue.len(),
                        WorkType::DataColumnsByRangeRequest => work_queues.dcbrange_queue.len(),
                        WorkType::GossipBlsToExecutionChange => {
                            work_queues.gossip_bls_to_execution_change_queue.len()
                        }
                        WorkType::GossipExecutionPayload => {
                            work_queues.gossip_execution_payload_queue.len()
                        }
                        WorkType::GossipExecutionPayloadBid => {
                            work_queues.gossip_execution_payload_bid_queue.len()
                        }
                        WorkType::GossipPayloadAttestation => {
                            work_queues.gossip_payload_attestation_queue.len()
                        }
                        WorkType::GossipProposerPreferences => {
                            work_queues.gossip_proposer_preferences_queue.len()
                        }
                        WorkType::LightClientBootstrapRequest => {
                            work_queues.lc_bootstrap_queue.len()
                        }
                        WorkType::LightClientOptimisticUpdateRequest => {
                            work_queues.lc_rpc_optimistic_update_queue.len()
                        }
                        WorkType::LightClientFinalityUpdateRequest => {
                            work_queues.lc_rpc_finality_update_queue.len()
                        }
                        WorkType::LightClientUpdatesByRangeRequest => {
                            work_queues.lc_update_range_queue.len()
                        }
                        WorkType::ApiRequestP0 => work_queues.api_request_p0_queue.len(),
                        WorkType::ApiRequestP1 => work_queues.api_request_p1_queue.len(),
                        WorkType::Reprocess => 0,
                    };
                    metrics::observe_vec(
                        &metrics::BEACON_PROCESSOR_QUEUE_LENGTH,
                        &[modified_queue_id.into()],
                        queue_len as f64,
                    );
                }

                if work_queues.aggregate_queue.is_full() && work_queues.aggregate_debounce.elapsed()
                {
                    error!(
                        msg = "the system has insufficient resources for load",
                        queue_len = work_queues.aggregate_queue.max_length,
                        "Aggregate attestation queue full"
                    )
                }

                if work_queues.attestation_queue.is_full()
                    && work_queues.attestation_debounce.elapsed()
                {
                    error!(
                        msg = "the system has insufficient resources for load",
                        queue_len = work_queues.attestation_queue.max_length,
                        "Attestation queue full"
                    )
                }

                // (Re)arm the age-bound timer.
                let attestation_timer_deadline =
                    match (att_batch_max_age, work_queues.attestation_queue.back()) {
                        (Some(max_age), Some((enqueued_at, _)))
                            if work_queues.attestation_queue.len() < att_batch_trigger =>
                        {
                            let deadline = tokio::time::Instant::from_std(*enqueued_at + max_age);
                            (deadline > tokio::time::Instant::now()).then_some(deadline)
                        }
                        _ => None,
                    };
                inbound_events.set_attestation_timer(attestation_timer_deadline);
            }
        };

        // Spawn on the core executor.
        executor.spawn(manager_future, MANAGER_TASK_NAME);
        Ok(())
    }

    /// Spawns a blocking worker thread to process some `Work`.
    ///
    /// Sends an message on `idle_tx` when the work is complete and the task is stopping.
    fn spawn_worker(
        &mut self,
        work: Work<E>,
        created_timestamp: Instant,
        idle_tx: mpsc::Sender<WorkType>,
    ) {
        let work_id = work.str_id();
        let work_type = work.to_type();

        // This metric tracks how long a work event has been in the queue
        metrics::observe_timer_vec(
            &metrics::BEACON_PROCESSOR_QUEUE_TIME,
            &[work_type.into()],
            Instant::now() - created_timestamp,
        );

        let worker_timer =
            metrics::start_timer_vec(&metrics::BEACON_PROCESSOR_WORKER_TIME, &[work_id]);
        metrics::inc_counter(&metrics::BEACON_PROCESSOR_WORKERS_SPAWNED_TOTAL);
        metrics::inc_counter_vec(
            &metrics::BEACON_PROCESSOR_WORK_EVENTS_STARTED_COUNT,
            &[work.str_id()],
        );

        metrics::inc_gauge_vec(
            &metrics::BEACON_PROCESSOR_WORKERS_ACTIVE_GAUGE_BY_TYPE,
            &[work_id],
        );

        // Wrap the `idle_tx` in a struct that will fire the idle message whenever it is dropped.
        //
        // This helps ensure that the worker is always freed in the case of an early exit or panic.
        // As such, this instantiation should happen as early in the function as possible.
        let send_idle_on_drop = SendOnDrop {
            tx: idle_tx,
            work_type: work.to_type(),
            _worker_timer: worker_timer,
        };

        let worker_id = self.current_workers;
        self.current_workers = self.current_workers.saturating_add(1);

        let executor = self.executor.clone();

        trace!(
            work = work_id,
            worker = worker_id,
            "Spawning beacon processor worker"
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
            Work::ChainSegment { process_fn, .. } => task_spawner.spawn_async(async move {
                process_fn.await;
            }),
            Work::UnknownBlockAttestation { process_fn }
            | Work::UnknownBlockAggregate { process_fn }
            | Work::UnknownBlockPayloadAttestation { process_fn }
            | Work::UnknownBlockDataColumn { process_fn }
            | Work::UnknownLightClientOptimisticUpdate { process_fn, .. } => {
                task_spawner.spawn_blocking(process_fn)
            }
            Work::DelayedImportBlock {
                beacon_block_slot: _,
                beacon_block_root: _,
                process_fn,
            }
            | Work::DelayedImportEnvelope {
                beacon_block_slot: _,
                beacon_block_root: _,
                process_fn,
            } => task_spawner.spawn_async(process_fn),
            Work::RpcBlock {
                process_fn,
                beacon_block_root: _,
            }
            | Work::RpcBlobs { process_fn }
            | Work::RpcCustodyColumn(process_fn)
            | Work::RpcEnvelope(process_fn)
            | Work::ColumnReconstruction(process_fn) => task_spawner.spawn_async(process_fn),
            Work::IgnoredRpcBlock { process_fn } => task_spawner.spawn_blocking(process_fn),
            Work::GossipBlock(work)
            | Work::GossipDataColumnSidecar(work)
            | Work::GossipPartialDataColumnSidecar(work)
            | Work::GossipExecutionPayload(work) => task_spawner.spawn_async(async move {
                work.await;
            }),
            Work::BlobsByRangeRequest(process_fn)
            | Work::BlobsByRootsRequest(process_fn)
            | Work::DataColumnsByRootsRequest(process_fn)
            | Work::DataColumnsByRangeRequest(process_fn) => {
                task_spawner.spawn_blocking(process_fn)
            }
            Work::BlocksByRangeRequest(work)
            | Work::BlocksByRootsRequest(work)
            | Work::BlocksByHeadRequest(work)
            | Work::PayloadEnvelopesByRangeRequest(work)
            | Work::PayloadEnvelopesByRootRequest(work) => task_spawner.spawn_async(work),
            Work::ChainSegmentBackfill(process_fn) => {
                if self.config.enable_backfill_rate_limiting {
                    task_spawner.spawn_blocking_with_rayon(RayonPoolType::LowPriority, process_fn)
                } else {
                    // use the global rayon thread pool if backfill rate limiting is disabled.
                    task_spawner.spawn_blocking(process_fn)
                }
            }
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
            | Work::GossipExecutionPayloadBid(process_fn)
            | Work::GossipPayloadAttestation(process_fn)
            | Work::GossipProposerPreferences(process_fn)
            | Work::LightClientBootstrapRequest(process_fn)
            | Work::LightClientOptimisticUpdateRequest(process_fn)
            | Work::LightClientFinalityUpdateRequest(process_fn)
            | Work::LightClientUpdatesByRangeRequest(process_fn) => {
                task_spawner.spawn_blocking(process_fn)
            }
            Work::Reprocess(_) => {}
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

    /// Spawns a blocking task on a rayon thread pool, dropping the `SendOnDrop` after task completion.
    fn spawn_blocking_with_rayon<F>(self, rayon_pool_type: RayonPoolType, task: F)
    where
        F: FnOnce() + Send + 'static,
    {
        self.executor.spawn_blocking_with_rayon(
            move || {
                task();
                drop(self.send_idle_on_drop)
            },
            rayon_pool_type,
            WORKER_TASK_NAME,
        )
    }
}

/// This struct will send a message on `self.tx` when it is dropped. An error will be logged
/// if the send fails (this happens when the node is shutting down).
///
/// ## Purpose
///
/// This is useful for ensuring that a worker-freed message is still sent if a worker panics.
///
/// The Rust docs for `Drop` state that `Drop` is called during an unwind in a panic:
///
/// https://doc.rust-lang.org/std/ops/trait.Drop.html#panics
pub struct SendOnDrop {
    tx: mpsc::Sender<WorkType>,
    work_type: WorkType,
    // The field is unused, but it's here to ensure the timer is dropped once the task has finished.
    _worker_timer: Option<metrics::HistogramTimer>,
}

impl Drop for SendOnDrop {
    fn drop(&mut self) {
        metrics::dec_gauge_vec(
            &metrics::BEACON_PROCESSOR_WORKERS_ACTIVE_GAUGE_BY_TYPE,
            &[self.work_type.clone().into()],
        );

        if let Err(e) = self.tx.try_send(self.work_type.clone()) {
            warn!(
                msg = "did not free worker, shutdown may be underway",
                error = %e,
                "Unable to free worker"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::AggregateSignature;
    use types::{AttestationData, MainnetEthSpec};

    fn dummy_attestation_work(attester_index: u64) -> Work<MainnetEthSpec> {
        let package = GossipAttestationPackage {
            message_id: MessageId::new(&[]),
            peer_id: PeerId::random(),
            attestation: Box::new(SingleAttestation {
                committee_index: 0,
                attester_index,
                data: AttestationData::default(),
                signature: AggregateSignature::empty(),
            }),
            subnet_id: SubnetId::new(0),
            should_import: true,
            seen_timestamp: Duration::from_secs(0),
        };
        Work::GossipAttestation {
            attestation: Box::new(package),
            process_individual: Box::new(|_| {}),
            process_batch: Box::new(|_| {}),
        }
    }

    fn attestation_queue_with(n: u64) -> LifoQueue<(Instant, Work<MainnetEthSpec>)> {
        let mut queue = LifoQueue::new(1024);
        for i in 0..n {
            queue.push((Instant::now(), dummy_attestation_work(i)));
        }
        queue
    }

    /// The `attester_index` of each attestation in a folded batch, in batch order.
    fn batch_attester_indices(work: Work<MainnetEthSpec>) -> Vec<u64> {
        match work {
            Work::GossipAttestationBatch { attestations, .. } => attestations
                .iter()
                .map(|package| package.attestation.attester_index)
                .collect(),
            other => panic!("expected a batch, got {}", other.str_id()),
        }
    }

    /// The `attester_index` of each attestation left in the queue, in pop (front-to-back) order.
    fn queued_attester_indices(queue: &mut LifoQueue<(Instant, Work<MainnetEthSpec>)>) -> Vec<u64> {
        std::iter::from_fn(|| queue.pop())
            .map(|(_, work)| match work {
                Work::GossipAttestation { attestation, .. } => {
                    attestation.attestation.attester_index
                }
                other => panic!("expected an attestation, got {}", other.str_id()),
            })
            .collect()
    }

    #[test]
    fn take_attestation_batch_empty_queue_returns_none() {
        let mut queue = attestation_queue_with(0);
        assert!(take_attestation_batch(&mut queue, 16).is_none());
    }

    #[test]
    fn take_attestation_batch_single_item_is_individual() {
        let mut queue = attestation_queue_with(1);
        let work = take_attestation_batch(&mut queue, 16).expect("some work");
        assert!(matches!(work, Work::GossipAttestation { .. }));
        assert!(queue.is_empty());
    }

    #[test]
    fn take_attestation_batch_folds_multiple() {
        let mut queue = attestation_queue_with(5);
        let work = take_attestation_batch(&mut queue, 16).expect("some work");
        // The whole queue is folded into one batch, newest (LIFO front) first.
        assert_eq!(batch_attester_indices(work), vec![4, 3, 2, 1, 0]);
        assert!(queue.is_empty());
    }

    #[test]
    fn take_attestation_batch_caps_size_and_leaves_remainder() {
        let mut queue = attestation_queue_with(20);
        let work = take_attestation_batch(&mut queue, 16).expect("some work");
        // The batch takes the 16 newest items.
        assert_eq!(
            batch_attester_indices(work),
            (4..20).rev().collect::<Vec<_>>()
        );
        // The remainder (the 4 oldest) stays queued for the next dispatch, so a burst
        // spreads across workers.
        assert_eq!(queued_attester_indices(&mut queue), vec![3, 2, 1, 0]);
    }

    #[test]
    fn take_attestation_batch_cap_zero_is_clamped_to_one() {
        let mut queue = attestation_queue_with(3);
        // A cap of 0 must not stall the queue; it is clamped to at least 1.
        let work = take_attestation_batch(&mut queue, 0).expect("some work");
        assert!(matches!(work, Work::GossipAttestation { .. }));
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn take_attestation_batch_grows_to_cap_under_deep_queue() {
        // With the cap decoupled from the trigger, a deep queue folds up to `max_batch` (64) into
        // one batch rather than being pinned at the trigger.
        let mut queue = attestation_queue_with(200);
        match take_attestation_batch(&mut queue, 64).expect("some work") {
            Work::GossipAttestationBatch { attestations, .. } => assert_eq!(attestations.len(), 64),
            other => panic!("expected a batch, got {}", other.str_id()),
        }
        assert_eq!(queue.len(), 136);
    }

    #[test]
    fn flush_not_ready_when_queue_empty() {
        let queue = attestation_queue_with(0);
        assert!(!attestation_flush_ready(&queue, 1, None));
        assert!(!attestation_flush_ready(&queue, 16, Some(Duration::ZERO)));
    }

    #[test]
    fn flush_ready_for_any_nonempty_queue_with_trigger_one() {
        // Legacy behaviour (no batch trigger): dispatch whenever the queue is non-empty.
        let queue = attestation_queue_with(1);
        assert!(attestation_flush_ready(&queue, 1, None));
    }

    #[test]
    fn flush_ready_when_trigger_reached() {
        let queue = attestation_queue_with(16);
        assert!(attestation_flush_ready(&queue, 16, None));
    }

    #[test]
    fn flush_not_ready_below_trigger_without_age_bound() {
        let queue = attestation_queue_with(15);
        assert!(!attestation_flush_ready(&queue, 16, None));
    }

    #[test]
    fn flush_readiness_below_trigger_follows_age_bound() {
        let queue = attestation_queue_with(15);
        // The items were just enqueued: not ready under a large age bound, ready once the oldest
        // exceeds the bound (zero here, so immediately).
        assert!(!attestation_flush_ready(
            &queue,
            16,
            Some(Duration::from_secs(3600))
        ));
        assert!(attestation_flush_ready(&queue, 16, Some(Duration::ZERO)));
    }
}
