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

use crate::{metrics, service::NetworkMessage, sync::SyncMessage};
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockError, GossipVerifiedBlock};
use eth2_libp2p::{
    rpc::{BlocksByRangeRequest, BlocksByRootRequest, StatusMessage},
    Client, MessageId, NetworkGlobals, PeerId, PeerRequestId,
};
use futures::stream::{Stream, StreamExt};
use futures::task::Poll;
use slog::{crit, debug, error, trace, warn, Logger};
use std::cmp;
use std::collections::VecDeque;
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::Context;
use std::time::{Duration, Instant};
use task_executor::TaskExecutor;
use tokio::sync::{mpsc, oneshot};
use types::{
    Attestation, AttesterSlashing, Hash256, ProposerSlashing, SignedAggregateAndProof,
    SignedBeaconBlock, SignedContributionAndProof, SignedVoluntaryExit, SubnetId,
    SyncCommitteeMessage, SyncSubnetId,
};
use work_reprocessing_queue::{
    spawn_reprocess_scheduler, QueuedAggregate, QueuedBlock, QueuedUnaggregate, ReadyWork,
};

use worker::{Toolbox, Worker};

mod tests;
mod work_reprocessing_queue;
mod worker;

pub use worker::{GossipAggregatePackage, GossipAttestationPackage, ProcessId};

/// The maximum size of the channel for work events to the `BeaconProcessor`.
///
/// Setting this too low will cause consensus messages to be dropped.
pub const MAX_WORK_EVENT_QUEUE_LEN: usize = 16_384;

/// The maximum size of the channel for idle events to the `BeaconProcessor`.
///
/// Setting this too low will prevent new workers from being spawned. It *should* only need to be
/// set to the CPU count, but we set it high to be safe.
const MAX_IDLE_QUEUE_LEN: usize = 16_384;

/// The maximum size of the channel for re-processing work events.
const MAX_SCHEDULED_WORK_QUEUE_LEN: usize = 16_384;

/// The maximum number of queued `Attestation` objects that will be stored before we start dropping
/// them.
const MAX_UNAGGREGATED_ATTESTATION_QUEUE_LEN: usize = 16_384;

/// The maximum number of queued `Attestation` objects that will be stored before we start dropping
/// them.
const MAX_UNAGGREGATED_ATTESTATION_REPROCESS_QUEUE_LEN: usize = 8_192;

/// The maximum number of queued `SignedAggregateAndProof` objects that will be stored before we
/// start dropping them.
const MAX_AGGREGATED_ATTESTATION_QUEUE_LEN: usize = 4_096;

/// The maximum number of queued `SignedAggregateAndProof` objects that will be stored before we
/// start dropping them.
const MAX_AGGREGATED_ATTESTATION_REPROCESS_QUEUE_LEN: usize = 1_024;

/// The maximum number of queued `SignedBeaconBlock` objects received on gossip that will be stored
/// before we start dropping them.
const MAX_GOSSIP_BLOCK_QUEUE_LEN: usize = 1_024;

/// The maximum number of queued `SignedBeaconBlock` objects received prior to their slot (but
/// within acceptable clock disparity) that will be queued before we start dropping them.
const MAX_DELAYED_BLOCK_QUEUE_LEN: usize = 1_024;

/// The maximum number of queued `SignedVoluntaryExit` objects received on gossip that will be stored
/// before we start dropping them.
const MAX_GOSSIP_EXIT_QUEUE_LEN: usize = 4_096;

/// The maximum number of queued `ProposerSlashing` objects received on gossip that will be stored
/// before we start dropping them.
const MAX_GOSSIP_PROPOSER_SLASHING_QUEUE_LEN: usize = 4_096;

/// The maximum number of queued `AttesterSlashing` objects received on gossip that will be stored
/// before we start dropping them.
const MAX_GOSSIP_ATTESTER_SLASHING_QUEUE_LEN: usize = 4_096;

/// The maximum number of queued `SyncCommitteeMessage` objects that will be stored before we start dropping
/// them.
const MAX_SYNC_MESSAGE_QUEUE_LEN: usize = 2048;

/// The maximum number of queued `SignedContributionAndProof` objects that will be stored before we
/// start dropping them.
const MAX_SYNC_CONTRIBUTION_QUEUE_LEN: usize = 1024;

/// The maximum number of queued `SignedBeaconBlock` objects received from the network RPC that
/// will be stored before we start dropping them.
const MAX_RPC_BLOCK_QUEUE_LEN: usize = 1_024;

/// The maximum number of queued `Vec<SignedBeaconBlock>` objects received during syncing that will
/// be stored before we start dropping them.
const MAX_CHAIN_SEGMENT_QUEUE_LEN: usize = 64;

/// The maximum number of queued `StatusMessage` objects received from the network RPC that will be
/// stored before we start dropping them.
const MAX_STATUS_QUEUE_LEN: usize = 1_024;

/// The maximum number of queued `BlocksByRangeRequest` objects received from the network RPC that
/// will be stored before we start dropping them.
const MAX_BLOCKS_BY_RANGE_QUEUE_LEN: usize = 1_024;

/// The maximum number of queued `BlocksByRootRequest` objects received from the network RPC that
/// will be stored before we start dropping them.
const MAX_BLOCKS_BY_ROOTS_QUEUE_LEN: usize = 1_024;

/// The name of the manager tokio task.
const MANAGER_TASK_NAME: &str = "beacon_processor_manager";

/// The name of the worker tokio tasks.
const WORKER_TASK_NAME: &str = "beacon_processor_worker";

/// The minimum interval between log messages indicating that a queue is full.
const LOG_DEBOUNCE_INTERVAL: Duration = Duration::from_secs(30);

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
const MAX_GOSSIP_ATTESTATION_BATCH_SIZE: usize = 64;
const MAX_GOSSIP_AGGREGATE_BATCH_SIZE: usize = 64;

/// Unique IDs used for metrics and testing.
pub const WORKER_FREED: &str = "worker_freed";
pub const NOTHING_TO_DO: &str = "nothing_to_do";
pub const GOSSIP_ATTESTATION: &str = "gossip_attestation";
pub const GOSSIP_ATTESTATION_BATCH: &str = "gossip_attestation_batch";
pub const GOSSIP_AGGREGATE: &str = "gossip_aggregate";
pub const GOSSIP_AGGREGATE_BATCH: &str = "gossip_aggregate_batch";
pub const GOSSIP_BLOCK: &str = "gossip_block";
pub const DELAYED_IMPORT_BLOCK: &str = "delayed_import_block";
pub const GOSSIP_VOLUNTARY_EXIT: &str = "gossip_voluntary_exit";
pub const GOSSIP_PROPOSER_SLASHING: &str = "gossip_proposer_slashing";
pub const GOSSIP_ATTESTER_SLASHING: &str = "gossip_attester_slashing";
pub const GOSSIP_SYNC_SIGNATURE: &str = "gossip_sync_signature";
pub const GOSSIP_SYNC_CONTRIBUTION: &str = "gossip_sync_contribution";
pub const RPC_BLOCK: &str = "rpc_block";
pub const CHAIN_SEGMENT: &str = "chain_segment";
pub const STATUS_PROCESSING: &str = "status_processing";
pub const BLOCKS_BY_RANGE_REQUEST: &str = "blocks_by_range_request";
pub const BLOCKS_BY_ROOTS_REQUEST: &str = "blocks_by_roots_request";
pub const UNKNOWN_BLOCK_ATTESTATION: &str = "unknown_block_attestation";
pub const UNKNOWN_BLOCK_AGGREGATE: &str = "unknown_block_aggregate";

/// Used to send/receive results from a rpc block import in a blocking task.
pub type BlockResultSender<E> = oneshot::Sender<Result<Hash256, BlockError<E>>>;
pub type BlockResultReceiver<E> = oneshot::Receiver<Result<Hash256, BlockError<E>>>;

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

/// An event to be processed by the manager task.
pub struct WorkEvent<T: BeaconChainTypes> {
    drop_during_sync: bool,
    work: Work<T>,
}

impl<T: BeaconChainTypes> fmt::Debug for WorkEvent<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl<T: BeaconChainTypes> WorkEvent<T> {
    /// Create a new `Work` event for some unaggregated attestation.
    pub fn unaggregated_attestation(
        message_id: MessageId,
        peer_id: PeerId,
        attestation: Attestation<T::EthSpec>,
        subnet_id: SubnetId,
        should_import: bool,
        seen_timestamp: Duration,
    ) -> Self {
        Self {
            drop_during_sync: true,
            work: Work::GossipAttestation {
                message_id,
                peer_id,
                attestation: Box::new(attestation),
                subnet_id,
                should_import,
                seen_timestamp,
            },
        }
    }

    /// Create a new `Work` event for some aggregated attestation.
    pub fn aggregated_attestation(
        message_id: MessageId,
        peer_id: PeerId,
        aggregate: SignedAggregateAndProof<T::EthSpec>,
        seen_timestamp: Duration,
    ) -> Self {
        Self {
            drop_during_sync: true,
            work: Work::GossipAggregate {
                message_id,
                peer_id,
                aggregate: Box::new(aggregate),
                seen_timestamp,
            },
        }
    }

    /// Create a new `Work` event for some block.
    pub fn gossip_beacon_block(
        message_id: MessageId,
        peer_id: PeerId,
        peer_client: Client,
        block: Box<SignedBeaconBlock<T::EthSpec>>,
        seen_timestamp: Duration,
    ) -> Self {
        Self {
            drop_during_sync: false,
            work: Work::GossipBlock {
                message_id,
                peer_id,
                peer_client,
                block,
                seen_timestamp,
            },
        }
    }

    /// Create a new `Work` event for some sync committee signature.
    pub fn gossip_sync_signature(
        message_id: MessageId,
        peer_id: PeerId,
        sync_signature: SyncCommitteeMessage,
        subnet_id: SyncSubnetId,
        seen_timestamp: Duration,
    ) -> Self {
        Self {
            drop_during_sync: true,
            work: Work::GossipSyncSignature {
                message_id,
                peer_id,
                sync_signature: Box::new(sync_signature),
                subnet_id,
                seen_timestamp,
            },
        }
    }

    /// Create a new `Work` event for some sync committee contribution.
    pub fn gossip_sync_contribution(
        message_id: MessageId,
        peer_id: PeerId,
        sync_contribution: SignedContributionAndProof<T::EthSpec>,
        seen_timestamp: Duration,
    ) -> Self {
        Self {
            drop_during_sync: true,
            work: Work::GossipSyncContribution {
                message_id,
                peer_id,
                sync_contribution: Box::new(sync_contribution),
                seen_timestamp,
            },
        }
    }

    /// Create a new `Work` event for some exit.
    pub fn gossip_voluntary_exit(
        message_id: MessageId,
        peer_id: PeerId,
        voluntary_exit: Box<SignedVoluntaryExit>,
    ) -> Self {
        Self {
            drop_during_sync: false,
            work: Work::GossipVoluntaryExit {
                message_id,
                peer_id,
                voluntary_exit,
            },
        }
    }

    /// Create a new `Work` event for some proposer slashing.
    pub fn gossip_proposer_slashing(
        message_id: MessageId,
        peer_id: PeerId,
        proposer_slashing: Box<ProposerSlashing>,
    ) -> Self {
        Self {
            drop_during_sync: false,
            work: Work::GossipProposerSlashing {
                message_id,
                peer_id,
                proposer_slashing,
            },
        }
    }

    /// Create a new `Work` event for some attester slashing.
    pub fn gossip_attester_slashing(
        message_id: MessageId,
        peer_id: PeerId,
        attester_slashing: Box<AttesterSlashing<T::EthSpec>>,
    ) -> Self {
        Self {
            drop_during_sync: false,
            work: Work::GossipAttesterSlashing {
                message_id,
                peer_id,
                attester_slashing,
            },
        }
    }

    /// Create a new `Work` event for some block, where the result from computation (if any) is
    /// sent to the other side of `result_tx`.
    pub fn rpc_beacon_block(
        block: Box<SignedBeaconBlock<T::EthSpec>>,
    ) -> (Self, BlockResultReceiver<T::EthSpec>) {
        let (result_tx, result_rx) = oneshot::channel();
        let event = Self {
            drop_during_sync: false,
            work: Work::RpcBlock { block, result_tx },
        };
        (event, result_rx)
    }

    /// Create a new work event to import `blocks` as a beacon chain segment.
    pub fn chain_segment(
        process_id: ProcessId,
        blocks: Vec<SignedBeaconBlock<T::EthSpec>>,
    ) -> Self {
        Self {
            drop_during_sync: false,
            work: Work::ChainSegment { process_id, blocks },
        }
    }

    /// Create a new work event to process `StatusMessage`s from the RPC network.
    pub fn status_message(peer_id: PeerId, message: StatusMessage) -> Self {
        Self {
            drop_during_sync: false,
            work: Work::Status { peer_id, message },
        }
    }

    /// Create a new work event to process `BlocksByRangeRequest`s from the RPC network.
    pub fn blocks_by_range_request(
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlocksByRangeRequest,
    ) -> Self {
        Self {
            drop_during_sync: false,
            work: Work::BlocksByRangeRequest {
                peer_id,
                request_id,
                request,
            },
        }
    }

    /// Create a new work event to process `BlocksByRootRequest`s from the RPC network.
    pub fn blocks_by_roots_request(
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlocksByRootRequest,
    ) -> Self {
        Self {
            drop_during_sync: false,
            work: Work::BlocksByRootsRequest {
                peer_id,
                request_id,
                request,
            },
        }
    }

    /// Get a `str` representation of the type of work this `WorkEvent` contains.
    pub fn work_type(&self) -> &'static str {
        self.work.str_id()
    }
}

impl<T: BeaconChainTypes> std::convert::From<ReadyWork<T>> for WorkEvent<T> {
    fn from(ready_work: ReadyWork<T>) -> Self {
        match ready_work {
            ReadyWork::Block(QueuedBlock {
                peer_id,
                block,
                seen_timestamp,
            }) => Self {
                drop_during_sync: false,
                work: Work::DelayedImportBlock {
                    peer_id,
                    block: Box::new(block),
                    seen_timestamp,
                },
            },
            ReadyWork::Unaggregate(QueuedUnaggregate {
                peer_id,
                message_id,
                attestation,
                subnet_id,
                should_import,
                seen_timestamp,
            }) => Self {
                drop_during_sync: true,
                work: Work::UnknownBlockAttestation {
                    message_id,
                    peer_id,
                    attestation,
                    subnet_id,
                    should_import,
                    seen_timestamp,
                },
            },
            ReadyWork::Aggregate(QueuedAggregate {
                peer_id,
                message_id,
                attestation,
                seen_timestamp,
            }) => Self {
                drop_during_sync: true,
                work: Work::UnknownBlockAggregate {
                    message_id,
                    peer_id,
                    aggregate: attestation,
                    seen_timestamp,
                },
            },
        }
    }
}

/// A consensus message (or multiple) from the network that requires processing.
#[derive(Debug)]
pub enum Work<T: BeaconChainTypes> {
    GossipAttestation {
        message_id: MessageId,
        peer_id: PeerId,
        attestation: Box<Attestation<T::EthSpec>>,
        subnet_id: SubnetId,
        should_import: bool,
        seen_timestamp: Duration,
    },
    UnknownBlockAttestation {
        message_id: MessageId,
        peer_id: PeerId,
        attestation: Box<Attestation<T::EthSpec>>,
        subnet_id: SubnetId,
        should_import: bool,
        seen_timestamp: Duration,
    },
    GossipAttestationBatch {
        packages: Vec<GossipAttestationPackage<T::EthSpec>>,
    },
    GossipAggregate {
        message_id: MessageId,
        peer_id: PeerId,
        aggregate: Box<SignedAggregateAndProof<T::EthSpec>>,
        seen_timestamp: Duration,
    },
    UnknownBlockAggregate {
        message_id: MessageId,
        peer_id: PeerId,
        aggregate: Box<SignedAggregateAndProof<T::EthSpec>>,
        seen_timestamp: Duration,
    },
    GossipAggregateBatch {
        packages: Vec<GossipAggregatePackage<T::EthSpec>>,
    },
    GossipBlock {
        message_id: MessageId,
        peer_id: PeerId,
        peer_client: Client,
        block: Box<SignedBeaconBlock<T::EthSpec>>,
        seen_timestamp: Duration,
    },
    DelayedImportBlock {
        peer_id: PeerId,
        block: Box<GossipVerifiedBlock<T>>,
        seen_timestamp: Duration,
    },
    GossipVoluntaryExit {
        message_id: MessageId,
        peer_id: PeerId,
        voluntary_exit: Box<SignedVoluntaryExit>,
    },
    GossipProposerSlashing {
        message_id: MessageId,
        peer_id: PeerId,
        proposer_slashing: Box<ProposerSlashing>,
    },
    GossipAttesterSlashing {
        message_id: MessageId,
        peer_id: PeerId,
        attester_slashing: Box<AttesterSlashing<T::EthSpec>>,
    },
    GossipSyncSignature {
        message_id: MessageId,
        peer_id: PeerId,
        sync_signature: Box<SyncCommitteeMessage>,
        subnet_id: SyncSubnetId,
        seen_timestamp: Duration,
    },
    GossipSyncContribution {
        message_id: MessageId,
        peer_id: PeerId,
        sync_contribution: Box<SignedContributionAndProof<T::EthSpec>>,
        seen_timestamp: Duration,
    },
    RpcBlock {
        block: Box<SignedBeaconBlock<T::EthSpec>>,
        result_tx: BlockResultSender<T::EthSpec>,
    },
    ChainSegment {
        process_id: ProcessId,
        blocks: Vec<SignedBeaconBlock<T::EthSpec>>,
    },
    Status {
        peer_id: PeerId,
        message: StatusMessage,
    },
    BlocksByRangeRequest {
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlocksByRangeRequest,
    },
    BlocksByRootsRequest {
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlocksByRootRequest,
    },
}

impl<T: BeaconChainTypes> Work<T> {
    /// Provides a `&str` that uniquely identifies each enum variant.
    fn str_id(&self) -> &'static str {
        match self {
            Work::GossipAttestation { .. } => GOSSIP_ATTESTATION,
            Work::GossipAttestationBatch { .. } => GOSSIP_ATTESTATION_BATCH,
            Work::GossipAggregate { .. } => GOSSIP_AGGREGATE,
            Work::GossipAggregateBatch { .. } => GOSSIP_AGGREGATE_BATCH,
            Work::GossipBlock { .. } => GOSSIP_BLOCK,
            Work::DelayedImportBlock { .. } => DELAYED_IMPORT_BLOCK,
            Work::GossipVoluntaryExit { .. } => GOSSIP_VOLUNTARY_EXIT,
            Work::GossipProposerSlashing { .. } => GOSSIP_PROPOSER_SLASHING,
            Work::GossipAttesterSlashing { .. } => GOSSIP_ATTESTER_SLASHING,
            Work::GossipSyncSignature { .. } => GOSSIP_SYNC_SIGNATURE,
            Work::GossipSyncContribution { .. } => GOSSIP_SYNC_CONTRIBUTION,
            Work::RpcBlock { .. } => RPC_BLOCK,
            Work::ChainSegment { .. } => CHAIN_SEGMENT,
            Work::Status { .. } => STATUS_PROCESSING,
            Work::BlocksByRangeRequest { .. } => BLOCKS_BY_RANGE_REQUEST,
            Work::BlocksByRootsRequest { .. } => BLOCKS_BY_ROOTS_REQUEST,
            Work::UnknownBlockAttestation { .. } => UNKNOWN_BLOCK_ATTESTATION,
            Work::UnknownBlockAggregate { .. } => UNKNOWN_BLOCK_AGGREGATE,
        }
    }
}

/// Provides de-bounce functionality for logging.
#[derive(Default)]
struct TimeLatch(Option<Instant>);

impl TimeLatch {
    /// Only returns true once every `LOG_DEBOUNCE_INTERVAL`.
    fn elapsed(&mut self) -> bool {
        let now = Instant::now();

        let is_elapsed = self.0.map_or(false, |elapse_time| now > elapse_time);

        if is_elapsed || self.0.is_none() {
            self.0 = Some(now + LOG_DEBOUNCE_INTERVAL);
        }

        is_elapsed
    }
}

/// Unifies all the messages processed by the `BeaconProcessor`.
enum InboundEvent<T: BeaconChainTypes> {
    /// A worker has completed a task and is free.
    WorkerIdle,
    /// There is new work to be done.
    WorkEvent(WorkEvent<T>),
    /// A work event that was queued for re-processing has become ready.
    ReprocessingWork(WorkEvent<T>),
}

/// Combines the various incoming event streams for the `BeaconProcessor` into a single stream.
///
/// This struct has a similar purpose to `tokio::select!`, however it allows for more fine-grained
/// control (specifically in the ordering of event processing).
struct InboundEvents<T: BeaconChainTypes> {
    /// Used by workers when they finish a task.
    idle_rx: mpsc::Receiver<()>,
    /// Used by upstream processes to send new work to the `BeaconProcessor`.
    event_rx: mpsc::Receiver<WorkEvent<T>>,
    /// Used internally for queuing work ready to be re-processed.
    reprocess_work_rx: mpsc::Receiver<ReadyWork<T>>,
}

impl<T: BeaconChainTypes> Stream for InboundEvents<T> {
    type Item = InboundEvent<T>;

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
pub struct BeaconProcessor<T: BeaconChainTypes> {
    pub beacon_chain: Weak<BeaconChain<T>>,
    pub network_tx: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    pub sync_tx: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
    pub network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    pub executor: TaskExecutor,
    pub max_workers: usize,
    pub current_workers: usize,
    pub log: Logger,
}

impl<T: BeaconChainTypes> BeaconProcessor<T> {
    /// Spawns the "manager" task which checks the receiver end of the returned `Sender` for
    /// messages which contain some new work which will be:
    ///
    /// - Performed immediately, if a worker is available.
    /// - Queued for later processing, if no worker is currently available.
    ///
    /// Only `self.max_workers` will ever be spawned at one time. Each worker is a `tokio` task
    /// started with `spawn_blocking`.
    ///
    /// The optional `work_journal_tx` allows for an outside process to receive a log of all work
    /// events processed by `self`. This should only be used during testing.
    pub fn spawn_manager(
        mut self,
        event_rx: mpsc::Receiver<WorkEvent<T>>,
        work_journal_tx: Option<mpsc::Sender<&'static str>>,
    ) {
        // Used by workers to communicate that they are finished a task.
        let (idle_tx, idle_rx) = mpsc::channel::<()>(MAX_IDLE_QUEUE_LEN);

        // Using LIFO queues for attestations since validator profits rely upon getting fresh
        // attestations into blocks. Additionally, later attestations contain more information than
        // earlier ones, so we consider them more valuable.
        let mut aggregate_queue = LifoQueue::new(MAX_AGGREGATED_ATTESTATION_QUEUE_LEN);
        let mut aggregate_debounce = TimeLatch::default();
        let mut attestation_queue = LifoQueue::new(MAX_UNAGGREGATED_ATTESTATION_QUEUE_LEN);
        let mut attestation_debounce = TimeLatch::default();
        let mut unknown_block_aggregate_queue =
            LifoQueue::new(MAX_AGGREGATED_ATTESTATION_REPROCESS_QUEUE_LEN);
        let mut unknown_block_attestation_queue =
            LifoQueue::new(MAX_UNAGGREGATED_ATTESTATION_REPROCESS_QUEUE_LEN);

        let mut sync_message_queue = LifoQueue::new(MAX_SYNC_MESSAGE_QUEUE_LEN);
        let mut sync_contribution_queue = LifoQueue::new(MAX_SYNC_CONTRIBUTION_QUEUE_LEN);

        // Using a FIFO queue for voluntary exits since it prevents exit censoring. I don't have
        // a strong feeling about queue type for exits.
        let mut gossip_voluntary_exit_queue = FifoQueue::new(MAX_GOSSIP_EXIT_QUEUE_LEN);

        // Using a FIFO queue for slashing to prevent people from flushing their slashings from the
        // queues with lots of junk messages.
        let mut gossip_proposer_slashing_queue =
            FifoQueue::new(MAX_GOSSIP_PROPOSER_SLASHING_QUEUE_LEN);
        let mut gossip_attester_slashing_queue =
            FifoQueue::new(MAX_GOSSIP_ATTESTER_SLASHING_QUEUE_LEN);

        // Using a FIFO queue since blocks need to be imported sequentially.
        let mut rpc_block_queue = FifoQueue::new(MAX_RPC_BLOCK_QUEUE_LEN);
        let mut chain_segment_queue = FifoQueue::new(MAX_CHAIN_SEGMENT_QUEUE_LEN);
        let mut gossip_block_queue = FifoQueue::new(MAX_GOSSIP_BLOCK_QUEUE_LEN);
        let mut delayed_block_queue = FifoQueue::new(MAX_DELAYED_BLOCK_QUEUE_LEN);

        let mut status_queue = FifoQueue::new(MAX_STATUS_QUEUE_LEN);
        let mut bbrange_queue = FifoQueue::new(MAX_BLOCKS_BY_RANGE_QUEUE_LEN);
        let mut bbroots_queue = FifoQueue::new(MAX_BLOCKS_BY_ROOTS_QUEUE_LEN);

        // Channels for sending work to the re-process scheduler (`work_reprocessing_tx`) and to
        // receive them back once they are ready (`ready_work_rx`).
        let (ready_work_tx, ready_work_rx) = mpsc::channel(MAX_SCHEDULED_WORK_QUEUE_LEN);
        let work_reprocessing_tx = {
            if let Some(chain) = self.beacon_chain.upgrade() {
                spawn_reprocess_scheduler(
                    ready_work_tx,
                    &self.executor,
                    chain.slot_clock.clone(),
                    self.log.clone(),
                )
            } else {
                // No need to proceed any further if the beacon chain has been dropped, the client
                // is shutting down.
                return;
            }
        };

        let executor = self.executor.clone();

        // The manager future will run on the core executor and delegate tasks to worker
        // threads on the blocking executor.
        let manager_future = async move {
            let mut inbound_events = InboundEvents {
                idle_rx,
                event_rx,
                reprocess_work_rx: ready_work_rx,
            };

            loop {
                let work_event = match inbound_events.next().await {
                    Some(InboundEvent::WorkerIdle) => {
                        self.current_workers = self.current_workers.saturating_sub(1);
                        None
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

                let can_spawn = self.current_workers < self.max_workers;
                let drop_during_sync = work_event
                    .as_ref()
                    .map_or(false, |event| event.drop_during_sync);

                match work_event {
                    // There is no new work event, but we are able to spawn a new worker.
                    //
                    // We don't check the `work.drop_during_sync` here. We assume that if it made
                    // it into the queue at any point then we should process it.
                    None if can_spawn => {
                        let toolbox = Toolbox {
                            idle_tx: idle_tx.clone(),
                            work_reprocessing_tx: work_reprocessing_tx.clone(),
                        };

                        // Check for chain segments first, they're the most efficient way to get
                        // blocks into the system.
                        if let Some(item) = chain_segment_queue.pop() {
                            self.spawn_worker(item, toolbox);
                        // Check sync blocks before gossip blocks, since we've already explicitly
                        // requested these blocks.
                        } else if let Some(item) = rpc_block_queue.pop() {
                            self.spawn_worker(item, toolbox);
                        // Check delayed blocks before gossip blocks, the gossip blocks might rely
                        // on the delayed ones.
                        } else if let Some(item) = delayed_block_queue.pop() {
                            self.spawn_worker(item, toolbox);
                        // Check gossip blocks before gossip attestations, since a block might be
                        // required to verify some attestations.
                        } else if let Some(item) = gossip_block_queue.pop() {
                            self.spawn_worker(item, toolbox);
                        // Check the aggregates, *then* the unaggregates since we assume that
                        // aggregates are more valuable to local validators and effectively give us
                        // more information with less signature verification time.
                        } else if aggregate_queue.len() > 0 {
                            let batch_size =
                                cmp::min(aggregate_queue.len(), MAX_GOSSIP_AGGREGATE_BATCH_SIZE);

                            if batch_size < 2 {
                                // One single aggregate is in the queue, process it individually.
                                if let Some(item) = aggregate_queue.pop() {
                                    self.spawn_worker(item, toolbox);
                                }
                            } else {
                                // Collect two or more aggregates into a batch, so they can take
                                // advantage of batch signature verification.
                                //
                                // Note: this will convert the `Work::GossipAggregate` item into a
                                // `Work::GossipAggregateBatch` item.
                                let mut packages = Vec::with_capacity(batch_size);
                                for _ in 0..batch_size {
                                    if let Some(item) = aggregate_queue.pop() {
                                        match item {
                                            Work::GossipAggregate {
                                                message_id,
                                                peer_id,
                                                aggregate,
                                                seen_timestamp,
                                            } => {
                                                packages.push(GossipAggregatePackage::new(
                                                    message_id,
                                                    peer_id,
                                                    aggregate,
                                                    seen_timestamp,
                                                ));
                                            }
                                            _ => {
                                                error!(self.log, "Invalid item in aggregate queue")
                                            }
                                        }
                                    }
                                }

                                // Process all aggregates with a single worker.
                                self.spawn_worker(Work::GossipAggregateBatch { packages }, toolbox)
                            }
                        // Check the unaggregated attestation queue.
                        //
                        // Potentially use batching.
                        } else if attestation_queue.len() > 0 {
                            let batch_size = cmp::min(
                                attestation_queue.len(),
                                MAX_GOSSIP_ATTESTATION_BATCH_SIZE,
                            );

                            if batch_size < 2 {
                                // One single attestation is in the queue, process it individually.
                                if let Some(item) = attestation_queue.pop() {
                                    self.spawn_worker(item, toolbox);
                                }
                            } else {
                                // Collect two or more attestations into a batch, so they can take
                                // advantage of batch signature verification.
                                //
                                // Note: this will convert the `Work::GossipAttestation` item into a
                                // `Work::GossipAttestationBatch` item.
                                let mut packages = Vec::with_capacity(batch_size);
                                for _ in 0..batch_size {
                                    if let Some(item) = attestation_queue.pop() {
                                        match item {
                                            Work::GossipAttestation {
                                                message_id,
                                                peer_id,
                                                attestation,
                                                subnet_id,
                                                should_import,
                                                seen_timestamp,
                                            } => {
                                                packages.push(GossipAttestationPackage::new(
                                                    message_id,
                                                    peer_id,
                                                    attestation,
                                                    subnet_id,
                                                    should_import,
                                                    seen_timestamp,
                                                ));
                                            }
                                            _ => error!(
                                                self.log,
                                                "Invalid item in attestation queue"
                                            ),
                                        }
                                    }
                                }

                                // Process all attestations with a single worker.
                                self.spawn_worker(
                                    Work::GossipAttestationBatch { packages },
                                    toolbox,
                                )
                            }
                        // Check sync committee messages after attestations as their rewards are lesser
                        // and they don't influence fork choice.
                        } else if let Some(item) = sync_contribution_queue.pop() {
                            self.spawn_worker(item, toolbox);
                        } else if let Some(item) = sync_message_queue.pop() {
                            self.spawn_worker(item, toolbox);
                        // Aggregates and unaggregates queued for re-processing are older and we
                        // care about fresher ones, so check those first.
                        } else if let Some(item) = unknown_block_aggregate_queue.pop() {
                            self.spawn_worker(item, toolbox);
                        } else if let Some(item) = unknown_block_attestation_queue.pop() {
                            self.spawn_worker(item, toolbox);
                        // Check RPC methods next. Status messages are needed for sync so
                        // prioritize them over syncing requests from other peers (BlocksByRange
                        // and BlocksByRoot)
                        } else if let Some(item) = status_queue.pop() {
                            self.spawn_worker(item, toolbox);
                        } else if let Some(item) = bbrange_queue.pop() {
                            self.spawn_worker(item, toolbox);
                        } else if let Some(item) = bbroots_queue.pop() {
                            self.spawn_worker(item, toolbox);
                        // Check slashings after all other consensus messages so we prioritize
                        // following head.
                        //
                        // Check attester slashings before proposer slashings since they have the
                        // potential to slash multiple validators at once.
                        } else if let Some(item) = gossip_attester_slashing_queue.pop() {
                            self.spawn_worker(item, toolbox);
                        } else if let Some(item) = gossip_proposer_slashing_queue.pop() {
                            self.spawn_worker(item, toolbox);
                        // Check exits last since our validators don't get rewards from them.
                        } else if let Some(item) = gossip_voluntary_exit_queue.pop() {
                            self.spawn_worker(item, toolbox);
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
                        let toolbox = Toolbox {
                            idle_tx: idle_tx.clone(),
                            work_reprocessing_tx: work_reprocessing_tx.clone(),
                        };

                        match work {
                            _ if can_spawn => self.spawn_worker(work, toolbox),
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
                            Work::RpcBlock { .. } => rpc_block_queue.push(work, work_id, &self.log),
                            Work::ChainSegment { .. } => {
                                chain_segment_queue.push(work, work_id, &self.log)
                            }
                            Work::Status { .. } => status_queue.push(work, work_id, &self.log),
                            Work::BlocksByRangeRequest { .. } => {
                                bbrange_queue.push(work, work_id, &self.log)
                            }
                            Work::BlocksByRootsRequest { .. } => {
                                bbroots_queue.push(work, work_id, &self.log)
                            }
                            Work::UnknownBlockAttestation { .. } => {
                                unknown_block_attestation_queue.push(work)
                            }
                            Work::UnknownBlockAggregate { .. } => {
                                unknown_block_aggregate_queue.push(work)
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
                    &metrics::BEACON_PROCESSOR_RPC_BLOCK_QUEUE_TOTAL,
                    rpc_block_queue.len() as i64,
                );
                metrics::set_gauge(
                    &metrics::BEACON_PROCESSOR_CHAIN_SEGMENT_QUEUE_TOTAL,
                    chain_segment_queue.len() as i64,
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
    }

    /// Spawns a blocking worker thread to process some `Work`.
    ///
    /// Sends an message on `idle_tx` when the work is complete and the task is stopping.
    fn spawn_worker(&mut self, work: Work<T>, toolbox: Toolbox<T>) {
        let idle_tx = toolbox.idle_tx;
        let work_reprocessing_tx = toolbox.work_reprocessing_tx;

        // Wrap the `idle_tx` in a struct that will fire the idle message whenever it is dropped.
        //
        // This helps ensure that the worker is always freed in the case of an early exit or panic.
        // As such, this instantiation should happen as early in the function as possible.
        let send_idle_on_drop = SendOnDrop {
            tx: idle_tx,
            log: self.log.clone(),
        };

        let work_id = work.str_id();
        let worker_timer =
            metrics::start_timer_vec(&metrics::BEACON_PROCESSOR_WORKER_TIME, &[work_id]);
        metrics::inc_counter(&metrics::BEACON_PROCESSOR_WORKERS_SPAWNED_TOTAL);
        metrics::inc_counter_vec(
            &metrics::BEACON_PROCESSOR_WORK_EVENTS_STARTED_COUNT,
            &[work.str_id()],
        );

        let worker_id = self.current_workers;
        self.current_workers = self.current_workers.saturating_add(1);

        let chain = if let Some(chain) = self.beacon_chain.upgrade() {
            chain
        } else {
            debug!(
                self.log,
                "Beacon chain dropped, shutting down";
            );
            return;
        };

        let log = self.log.clone();
        let executor = self.executor.clone();

        let worker = Worker {
            chain,
            network_tx: self.network_tx.clone(),
            sync_tx: self.sync_tx.clone(),
            log: self.log.clone(),
        };

        trace!(
            self.log,
            "Spawning beacon processor worker";
            "work" => work_id,
            "worker" => worker_id,
        );

        executor.spawn_blocking(
            move || {
                let _worker_timer = worker_timer;

                match work {
                    /*
                     * Individual unaggregated attestation verification.
                     */
                    Work::GossipAttestation {
                        message_id,
                        peer_id,
                        attestation,
                        subnet_id,
                        should_import,
                        seen_timestamp,
                    } => worker.process_gossip_attestation(
                        message_id,
                        peer_id,
                        attestation,
                        subnet_id,
                        should_import,
                        Some(work_reprocessing_tx),
                        seen_timestamp,
                    ),
                    /*
                     * Batched unaggregated attestation verification.
                     */
                    Work::GossipAttestationBatch { packages } => worker
                        .process_gossip_attestation_batch(packages, Some(work_reprocessing_tx)),
                    /*
                     * Individual aggregated attestation verification.
                     */
                    Work::GossipAggregate {
                        message_id,
                        peer_id,
                        aggregate,
                        seen_timestamp,
                    } => worker.process_gossip_aggregate(
                        message_id,
                        peer_id,
                        aggregate,
                        Some(work_reprocessing_tx),
                        seen_timestamp,
                    ),
                    /*
                     * Batched aggregated attestation verification.
                     */
                    Work::GossipAggregateBatch { packages } => {
                        worker.process_gossip_aggregate_batch(packages, Some(work_reprocessing_tx))
                    }
                    /*
                     * Verification for beacon blocks received on gossip.
                     */
                    Work::GossipBlock {
                        message_id,
                        peer_id,
                        peer_client,
                        block,
                        seen_timestamp,
                    } => worker.process_gossip_block(
                        message_id,
                        peer_id,
                        peer_client,
                        *block,
                        work_reprocessing_tx,
                        seen_timestamp,
                    ),
                    /*
                     * Import for blocks that we received earlier than their intended slot.
                     */
                    Work::DelayedImportBlock {
                        peer_id,
                        block,
                        seen_timestamp,
                    } => worker.process_gossip_verified_block(
                        peer_id,
                        *block,
                        work_reprocessing_tx,
                        seen_timestamp,
                    ),
                    /*
                     * Voluntary exits received on gossip.
                     */
                    Work::GossipVoluntaryExit {
                        message_id,
                        peer_id,
                        voluntary_exit,
                    } => worker.process_gossip_voluntary_exit(message_id, peer_id, *voluntary_exit),
                    /*
                     * Proposer slashings received on gossip.
                     */
                    Work::GossipProposerSlashing {
                        message_id,
                        peer_id,
                        proposer_slashing,
                    } => worker.process_gossip_proposer_slashing(
                        message_id,
                        peer_id,
                        *proposer_slashing,
                    ),
                    /*
                     * Attester slashings received on gossip.
                     */
                    Work::GossipAttesterSlashing {
                        message_id,
                        peer_id,
                        attester_slashing,
                    } => worker.process_gossip_attester_slashing(
                        message_id,
                        peer_id,
                        *attester_slashing,
                    ),
                    /*
                     * Sync committee message verification.
                     */
                    Work::GossipSyncSignature {
                        message_id,
                        peer_id,
                        sync_signature,
                        subnet_id,
                        seen_timestamp,
                    } => worker.process_gossip_sync_committee_signature(
                        message_id,
                        peer_id,
                        *sync_signature,
                        subnet_id,
                        seen_timestamp,
                    ),
                    /*
                     * Syn contribution verification.
                     */
                    Work::GossipSyncContribution {
                        message_id,
                        peer_id,
                        sync_contribution,
                        seen_timestamp,
                    } => worker.process_sync_committee_contribution(
                        message_id,
                        peer_id,
                        *sync_contribution,
                        seen_timestamp,
                    ),
                    /*
                     * Verification for beacon blocks received during syncing via RPC.
                     */
                    Work::RpcBlock { block, result_tx } => {
                        worker.process_rpc_block(*block, result_tx, work_reprocessing_tx)
                    }
                    /*
                     * Verification for a chain segment (multiple blocks).
                     */
                    Work::ChainSegment { process_id, blocks } => {
                        worker.process_chain_segment(process_id, blocks)
                    }
                    /*
                     * Processing of Status Messages.
                     */
                    Work::Status { peer_id, message } => worker.process_status(peer_id, message),
                    /*
                     * Processing of range syncing requests from other peers.
                     */
                    Work::BlocksByRangeRequest {
                        peer_id,
                        request_id,
                        request,
                    } => worker.handle_blocks_by_range_request(peer_id, request_id, request),
                    /*
                     * Processing of blocks by roots requests from other peers.
                     */
                    Work::BlocksByRootsRequest {
                        peer_id,
                        request_id,
                        request,
                    } => worker.handle_blocks_by_root_request(peer_id, request_id, request),
                    Work::UnknownBlockAttestation {
                        message_id,
                        peer_id,
                        attestation,
                        subnet_id,
                        should_import,
                        seen_timestamp,
                    } => worker.process_gossip_attestation(
                        message_id,
                        peer_id,
                        attestation,
                        subnet_id,
                        should_import,
                        None, // Do not allow this attestation to be re-processed beyond this point.
                        seen_timestamp,
                    ),
                    Work::UnknownBlockAggregate {
                        message_id,
                        peer_id,
                        aggregate,
                        seen_timestamp,
                    } => worker.process_gossip_aggregate(
                        message_id,
                        peer_id,
                        aggregate,
                        None,
                        seen_timestamp,
                    ),
                };

                trace!(
                    log,
                    "Beacon processor worker done";
                    "work" => work_id,
                    "worker" => worker_id,
                );

                // This explicit `drop` is used to remind the programmer that this variable must
                // not be dropped until the worker is complete. Dropping it early will cause the
                // worker to be marked as "free" and cause an over-spawning of workers.
                drop(send_idle_on_drop);
            },
            WORKER_TASK_NAME,
        );
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
