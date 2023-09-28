use crate::attestation_verification::{
    batch_verify_aggregated_attestations, batch_verify_unaggregated_attestations,
    Error as AttestationError, VerifiedAggregatedAttestation, VerifiedAttestation,
    VerifiedUnaggregatedAttestation,
};
use crate::attester_cache::{AttesterCache, AttesterCacheKey};
use crate::beacon_block_streamer::{BeaconBlockStreamer, CheckEarlyAttesterCache};
use crate::beacon_proposer_cache::compute_proposer_duties_from_head;
use crate::beacon_proposer_cache::BeaconProposerCache;
use crate::block_times_cache::BlockTimesCache;
use crate::block_verification::{
    check_block_is_finalized_checkpoint_or_descendant, check_block_relevancy, get_block_root,
    signature_verify_chain_segment, BlockError, ExecutionPendingBlock, GossipVerifiedBlock,
    IntoExecutionPendingBlock, PayloadVerificationOutcome, POS_PANDA_BANNER,
};
pub use crate::canonical_head::{CanonicalHead, CanonicalHeadRwLock};
use crate::chain_config::ChainConfig;
use crate::early_attester_cache::EarlyAttesterCache;
use crate::errors::{BeaconChainError as Error, BlockProductionError};
use crate::eth1_chain::{Eth1Chain, Eth1ChainBackend};
use crate::eth1_finalization_cache::{Eth1FinalizationCache, Eth1FinalizationData};
use crate::events::ServerSentEventHandler;
use crate::execution_payload::{get_execution_payload, NotifyExecutionLayer, PreparePayloadHandle};
use crate::fork_choice_signal::{ForkChoiceSignalRx, ForkChoiceSignalTx, ForkChoiceWaitResult};
use crate::head_tracker::HeadTracker;
use crate::historical_blocks::HistoricalBlockError;
use crate::light_client_finality_update_verification::{
    Error as LightClientFinalityUpdateError, VerifiedLightClientFinalityUpdate,
};
use crate::light_client_optimistic_update_verification::{
    Error as LightClientOptimisticUpdateError, VerifiedLightClientOptimisticUpdate,
};
use crate::migrate::BackgroundMigrator;
use crate::naive_aggregation_pool::{
    AggregatedAttestationMap, Error as NaiveAggregationError, NaiveAggregationPool,
    SyncContributionAggregateMap,
};
use crate::observed_aggregates::{
    Error as AttestationObservationError, ObservedAggregateAttestations, ObservedSyncContributions,
};
use crate::observed_attesters::{
    ObservedAggregators, ObservedAttesters, ObservedSyncAggregators, ObservedSyncContributors,
};
use crate::observed_block_producers::ObservedBlockProducers;
use crate::observed_operations::{ObservationOutcome, ObservedOperations};
use crate::persisted_beacon_chain::{PersistedBeaconChain, DUMMY_CANONICAL_HEAD_BLOCK_ROOT};
use crate::persisted_fork_choice::PersistedForkChoice;
use crate::pre_finalization_cache::PreFinalizationBlockCache;
use crate::shuffling_cache::{BlockShufflingIds, ShufflingCache};
use crate::snapshot_cache::{BlockProductionPreState, SnapshotCache};
use crate::sync_committee_verification::{
    Error as SyncCommitteeError, VerifiedSyncCommitteeMessage, VerifiedSyncContribution,
};
use crate::timeout_rw_lock::TimeoutRwLock;
use crate::validator_monitor::{
    get_slot_delay_ms, timestamp_now, ValidatorMonitor,
    HISTORIC_EPOCHS as VALIDATOR_MONITOR_HISTORIC_EPOCHS,
};
use crate::validator_pubkey_cache::ValidatorPubkeyCache;
use crate::{metrics, BeaconChainError, BeaconForkChoiceStore, BeaconSnapshot, CachedHead};
use eth2::types::{EventKind, SseBlock, SseExtendedPayloadAttributes, SyncDuty};
use execution_layer::{
    BlockProposalContents, BuilderParams, ChainHealth, ExecutionLayer, FailedCondition,
    PayloadAttributes, PayloadStatus,
};
use fork_choice::{
    AttestationFromBlock, ExecutionStatus, ForkChoice, ForkchoiceUpdateParameters,
    InvalidationOperation, PayloadVerificationStatus, ResetPayloadStatuses,
};
use futures::channel::mpsc::Sender;
use itertools::process_results;
use itertools::Itertools;
use operation_pool::{AttestationRef, OperationPool, PersistedOperationPool, ReceivedPreCapella};
use parking_lot::{Mutex, RwLock};
use proto_array::{DoNotReOrg, ProposerHeadError};
use safe_arith::SafeArith;
use slasher::Slasher;
use slog::{crit, debug, error, info, trace, warn, Logger};
use slot_clock::SlotClock;
use ssz::Encode;
use state_processing::{
    common::get_attesting_indices_from_state,
    per_block_processing,
    per_block_processing::{
        errors::AttestationValidationError, get_expected_withdrawals,
        verify_attestation_for_block_inclusion, VerifySignatures,
    },
    per_slot_processing,
    state_advance::{complete_state_advance, partial_state_advance},
    BlockSignatureStrategy, ConsensusContext, SigVerifiedOp, StateProcessingStrategy,
    VerifyBlockRoot, VerifyOperation,
};
use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::prelude::*;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::iter::{BlockRootsIterator, ParentRootBlockIterator, StateRootsIterator};
use store::{
    DatabaseBlock, Error as DBError, HotColdDB, KeyValueStore, KeyValueStoreOp, StoreItem, StoreOp,
};
use task_executor::{ShutdownReason, TaskExecutor};
use tokio_stream::Stream;
use tree_hash::TreeHash;
use types::beacon_state::CloneConfig;
use types::*;

pub type ForkChoiceError = fork_choice::Error<crate::ForkChoiceStoreError>;

/// Alias to appease clippy.
type HashBlockTuple<E> = (Hash256, Arc<SignedBeaconBlock<E>>);

/// The time-out before failure during an operation to take a read/write RwLock on the block
/// processing cache.
pub const BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(1);
/// The time-out before failure during an operation to take a read/write RwLock on the
/// attestation cache.
pub const ATTESTATION_CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(1);

/// The time-out before failure during an operation to take a read/write RwLock on the
/// validator pubkey cache.
pub const VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(1);

/// The timeout for the eth1 finalization cache
pub const ETH1_FINALIZATION_CACHE_LOCK_TIMEOUT: Duration = Duration::from_millis(200);

// These keys are all zero because they get stored in different columns, see `DBColumn` type.
pub const BEACON_CHAIN_DB_KEY: Hash256 = Hash256::zero();
pub const OP_POOL_DB_KEY: Hash256 = Hash256::zero();
pub const ETH1_CACHE_DB_KEY: Hash256 = Hash256::zero();
pub const FORK_CHOICE_DB_KEY: Hash256 = Hash256::zero();

/// Defines how old a block can be before it's no longer a candidate for the early attester cache.
const EARLY_ATTESTER_CACHE_HISTORIC_SLOTS: u64 = 4;

/// Defines a distance between the head block slot and the current slot.
///
/// If the head block is older than this value, don't bother preparing beacon proposers.
const PREPARE_PROPOSER_HISTORIC_EPOCHS: u64 = 4;

/// If the head is more than `MAX_PER_SLOT_FORK_CHOICE_DISTANCE` slots behind the wall-clock slot, DO NOT
/// run the per-slot tasks (primarily fork choice).
///
/// This prevents unnecessary work during sync.
///
/// The value is set to 256 since this would be just over one slot (12.8s) when syncing at
/// 20 slots/second. Having a single fork-choice run interrupt syncing would have very little
/// impact whilst having 8 epochs without a block is a comfortable grace period.
const MAX_PER_SLOT_FORK_CHOICE_DISTANCE: u64 = 256;

/// Reported to the user when the justified block has an invalid execution payload.
pub const INVALID_JUSTIFIED_PAYLOAD_SHUTDOWN_REASON: &str =
    "Justified block has an invalid execution payload.";

pub const INVALID_FINALIZED_MERGE_TRANSITION_BLOCK_SHUTDOWN_REASON: &str =
    "Finalized merge transition block is invalid.";

/// Defines the behaviour when a block/block-root for a skipped slot is requested.
pub enum WhenSlotSkipped {
    /// If the slot is a skip slot, return `None`.
    ///
    /// This is how the HTTP API behaves.
    None,
    /// If the slot is a skip slot, return the previous non-skipped block.
    ///
    /// This is generally how the specification behaves.
    Prev,
}

/// The result of a chain segment processing.
pub enum ChainSegmentResult<T: EthSpec> {
    /// Processing this chain segment finished successfully.
    Successful { imported_blocks: usize },
    /// There was an error processing this chain segment. Before the error, some blocks could
    /// have been imported.
    Failed {
        imported_blocks: usize,
        error: BlockError<T>,
    },
}

/// Configure the signature verification of produced blocks.
pub enum ProduceBlockVerification {
    VerifyRandao,
    NoVerification,
}

/// Payload attributes for which the `beacon_chain` crate is responsible.
pub struct PrePayloadAttributes {
    pub proposer_index: u64,
    pub prev_randao: Hash256,
    /// The parent block number is not part of the payload attributes sent to the EL, but *is*
    /// sent to builders via SSE.
    pub parent_block_number: u64,
}

/// Information about a state/block at a specific slot.
#[derive(Debug, Clone, Copy)]
pub struct FinalizationAndCanonicity {
    /// True if the slot of the state or block is finalized.
    ///
    /// This alone DOES NOT imply that the state/block is finalized, use `self.is_finalized()`.
    pub slot_is_finalized: bool,
    /// True if the state or block is canonical at its slot.
    pub canonical: bool,
}

/// Define whether a forkchoiceUpdate needs to be checked for an override (`Yes`) or has already
/// been checked (`AlreadyApplied`). It is safe to specify `Yes` even if re-orgs are disabled.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum OverrideForkchoiceUpdate {
    #[default]
    Yes,
    AlreadyApplied,
}

#[derive(Debug, PartialEq)]
pub enum AttestationProcessingOutcome {
    Processed,
    EmptyAggregationBitfield,
    UnknownHeadBlock {
        beacon_block_root: Hash256,
    },
    /// The attestation is attesting to a state that is later than itself. (Viz., attesting to the
    /// future).
    AttestsToFutureBlock {
        block: Slot,
        attestation: Slot,
    },
    /// The slot is finalized, no need to import.
    FinalizedSlot {
        attestation: Slot,
        finalized: Slot,
    },
    FutureEpoch {
        attestation_epoch: Epoch,
        current_epoch: Epoch,
    },
    PastEpoch {
        attestation_epoch: Epoch,
        current_epoch: Epoch,
    },
    BadTargetEpoch,
    UnknownTargetRoot(Hash256),
    InvalidSignature,
    NoCommitteeForSlotAndIndex {
        slot: Slot,
        index: CommitteeIndex,
    },
    Invalid(AttestationValidationError),
}

/// Defines how a `BeaconState` should be "skipped" through skip-slots.
pub enum StateSkipConfig {
    /// Calculate the state root during each skip slot, producing a fully-valid `BeaconState`.
    WithStateRoots,
    /// Don't calculate the state root at each slot, instead just use the zero hash. This is orders
    /// of magnitude faster, however it produces a partially invalid state.
    ///
    /// This state is useful for operations that don't use the state roots; e.g., for calculating
    /// the shuffling.
    WithoutStateRoots,
}

pub trait BeaconChainTypes: Send + Sync + 'static {
    type HotStore: store::ItemStore<Self::EthSpec>;
    type ColdStore: store::ItemStore<Self::EthSpec>;
    type SlotClock: slot_clock::SlotClock;
    type Eth1Chain: Eth1ChainBackend<Self::EthSpec>;
    type EthSpec: types::EthSpec;
}

/// Used internally to split block production into discrete functions.
struct PartialBeaconBlock<E: EthSpec, Payload: AbstractExecPayload<E>> {
    state: BeaconState<E>,
    slot: Slot,
    proposer_index: u64,
    parent_root: Hash256,
    randao_reveal: Signature,
    eth1_data: Eth1Data,
    graffiti: Graffiti,
    proposer_slashings: Vec<ProposerSlashing>,
    attester_slashings: Vec<AttesterSlashing<E>>,
    attestations: Vec<Attestation<E>>,
    deposits: Vec<Deposit>,
    voluntary_exits: Vec<SignedVoluntaryExit>,
    sync_aggregate: Option<SyncAggregate<E>>,
    prepare_payload_handle: Option<PreparePayloadHandle<E, Payload>>,
    bls_to_execution_changes: Vec<SignedBlsToExecutionChange>,
}

pub type BeaconForkChoice<T> = ForkChoice<
    BeaconForkChoiceStore<
        <T as BeaconChainTypes>::EthSpec,
        <T as BeaconChainTypes>::HotStore,
        <T as BeaconChainTypes>::ColdStore,
    >,
    <T as BeaconChainTypes>::EthSpec,
>;

pub type BeaconStore<T> = Arc<
    HotColdDB<
        <T as BeaconChainTypes>::EthSpec,
        <T as BeaconChainTypes>::HotStore,
        <T as BeaconChainTypes>::ColdStore,
    >,
>;

/// Represents the "Beacon Chain" component of Ethereum 2.0. Allows import of blocks and block
/// operations and chooses a canonical head.
pub struct BeaconChain<T: BeaconChainTypes> {
    pub spec: ChainSpec,
    /// Configuration for `BeaconChain` runtime behaviour.
    pub config: ChainConfig,
    /// Persistent storage for blocks, states, etc. Typically an on-disk store, such as LevelDB.
    pub store: BeaconStore<T>,
    /// Used for spawning async and blocking tasks.
    pub task_executor: TaskExecutor,
    /// Database migrator for running background maintenance on the store.
    pub store_migrator: BackgroundMigrator<T::EthSpec, T::HotStore, T::ColdStore>,
    /// Reports the current slot, typically based upon the system clock.
    pub slot_clock: T::SlotClock,
    /// Stores all operations (e.g., `Attestation`, `Deposit`, etc) that are candidates for
    /// inclusion in a block.
    pub op_pool: OperationPool<T::EthSpec>,
    /// A pool of attestations dedicated to the "naive aggregation strategy" defined in the eth2
    /// specs.
    ///
    /// This pool accepts `Attestation` objects that only have one aggregation bit set and provides
    /// a method to get an aggregated `Attestation` for some `AttestationData`.
    pub naive_aggregation_pool: RwLock<NaiveAggregationPool<AggregatedAttestationMap<T::EthSpec>>>,
    /// A pool of `SyncCommitteeContribution` dedicated to the "naive aggregation strategy" defined in the eth2
    /// specs.
    ///
    /// This pool accepts `SyncCommitteeContribution` objects that only have one aggregation bit set and provides
    /// a method to get an aggregated `SyncCommitteeContribution` for some `SyncCommitteeContributionData`.
    pub naive_sync_aggregation_pool:
        RwLock<NaiveAggregationPool<SyncContributionAggregateMap<T::EthSpec>>>,
    /// Contains a store of attestations which have been observed by the beacon chain.
    pub(crate) observed_attestations: RwLock<ObservedAggregateAttestations<T::EthSpec>>,
    /// Contains a store of sync contributions which have been observed by the beacon chain.
    pub(crate) observed_sync_contributions: RwLock<ObservedSyncContributions<T::EthSpec>>,
    /// Maintains a record of which validators have been seen to publish gossip attestations in
    /// recent epochs.
    pub observed_gossip_attesters: RwLock<ObservedAttesters<T::EthSpec>>,
    /// Maintains a record of which validators have been seen to have attestations included in
    /// blocks in recent epochs.
    pub observed_block_attesters: RwLock<ObservedAttesters<T::EthSpec>>,
    /// Maintains a record of which validators have been seen sending sync messages in recent epochs.
    pub(crate) observed_sync_contributors: RwLock<ObservedSyncContributors<T::EthSpec>>,
    /// Maintains a record of which validators have been seen to create `SignedAggregateAndProofs`
    /// in recent epochs.
    pub observed_aggregators: RwLock<ObservedAggregators<T::EthSpec>>,
    /// Maintains a record of which validators have been seen to create `SignedContributionAndProofs`
    /// in recent epochs.
    pub(crate) observed_sync_aggregators: RwLock<ObservedSyncAggregators<T::EthSpec>>,
    /// Maintains a record of which validators have proposed blocks for each slot.
    pub observed_block_producers: RwLock<ObservedBlockProducers<T::EthSpec>>,
    /// Maintains a record of which validators have submitted voluntary exits.
    pub(crate) observed_voluntary_exits: Mutex<ObservedOperations<SignedVoluntaryExit, T::EthSpec>>,
    /// Maintains a record of which validators we've seen proposer slashings for.
    pub(crate) observed_proposer_slashings: Mutex<ObservedOperations<ProposerSlashing, T::EthSpec>>,
    /// Maintains a record of which validators we've seen attester slashings for.
    pub(crate) observed_attester_slashings:
        Mutex<ObservedOperations<AttesterSlashing<T::EthSpec>, T::EthSpec>>,
    /// Maintains a record of which validators we've seen BLS to execution changes for.
    pub(crate) observed_bls_to_execution_changes:
        Mutex<ObservedOperations<SignedBlsToExecutionChange, T::EthSpec>>,
    /// The most recently validated light client finality update received on gossip.
    pub latest_seen_finality_update: Mutex<Option<LightClientFinalityUpdate<T::EthSpec>>>,
    /// The most recently validated light client optimistic update received on gossip.
    pub latest_seen_optimistic_update: Mutex<Option<LightClientOptimisticUpdate<T::EthSpec>>>,
    /// Provides information from the Ethereum 1 (PoW) chain.
    pub eth1_chain: Option<Eth1Chain<T::Eth1Chain, T::EthSpec>>,
    /// Interfaces with the execution client.
    pub execution_layer: Option<ExecutionLayer<T::EthSpec>>,
    /// Stores information about the canonical head and finalized/justified checkpoints of the
    /// chain. Also contains the fork choice struct, for computing the canonical head.
    pub canonical_head: CanonicalHead<T>,
    /// The root of the genesis block.
    pub genesis_block_root: Hash256,
    /// The root of the genesis state.
    pub genesis_state_root: Hash256,
    /// The root of the list of genesis validators, used during syncing.
    pub genesis_validators_root: Hash256,
    /// Transmitter used to indicate that slot-start fork choice has completed running.
    pub fork_choice_signal_tx: Option<ForkChoiceSignalTx>,
    /// Receiver used by block production to wait on slot-start fork choice.
    pub fork_choice_signal_rx: Option<ForkChoiceSignalRx>,
    /// The genesis time of this `BeaconChain` (seconds since UNIX epoch).
    pub genesis_time: u64,
    /// A handler for events generated by the beacon chain. This is only initialized when the
    /// HTTP server is enabled.
    pub event_handler: Option<ServerSentEventHandler<T::EthSpec>>,
    /// Used to track the heads of the beacon chain.
    pub(crate) head_tracker: Arc<HeadTracker>,
    /// A cache dedicated to block processing.
    pub(crate) snapshot_cache: TimeoutRwLock<SnapshotCache<T::EthSpec>>,
    /// Caches the attester shuffling for a given epoch and shuffling key root.
    pub shuffling_cache: TimeoutRwLock<ShufflingCache>,
    /// A cache of eth1 deposit data at epoch boundaries for deposit finalization
    pub eth1_finalization_cache: TimeoutRwLock<Eth1FinalizationCache>,
    /// Caches the beacon block proposer shuffling for a given epoch and shuffling key root.
    pub beacon_proposer_cache: Arc<Mutex<BeaconProposerCache>>,
    /// Caches a map of `validator_index -> validator_pubkey`.
    pub(crate) validator_pubkey_cache: TimeoutRwLock<ValidatorPubkeyCache<T>>,
    /// A cache used when producing attestations.
    pub(crate) attester_cache: Arc<AttesterCache>,
    /// A cache used when producing attestations whilst the head block is still being imported.
    pub early_attester_cache: EarlyAttesterCache<T::EthSpec>,
    /// A cache used to keep track of various block timings.
    pub block_times_cache: Arc<RwLock<BlockTimesCache>>,
    /// A cache used to track pre-finalization block roots for quick rejection.
    pub pre_finalization_block_cache: PreFinalizationBlockCache,
    /// Sender given to tasks, so that if they encounter a state in which execution cannot
    /// continue they can request that everything shuts down.
    pub shutdown_sender: Sender<ShutdownReason>,
    /// Logging to CLI, etc.
    pub(crate) log: Logger,
    /// Arbitrary bytes included in the blocks.
    pub(crate) graffiti: Graffiti,
    /// Optional slasher.
    pub slasher: Option<Arc<Slasher<T::EthSpec>>>,
    /// Provides monitoring of a set of explicitly defined validators.
    pub validator_monitor: RwLock<ValidatorMonitor<T::EthSpec>>,
    /// The slot at which blocks are downloaded back to.
    pub genesis_backfill_slot: Slot,
}

type BeaconBlockAndState<T, Payload> = (BeaconBlock<T, Payload>, BeaconState<T>);

impl FinalizationAndCanonicity {
    pub fn is_finalized(self) -> bool {
        self.slot_is_finalized && self.canonical
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Checks if a block is finalized.
    /// The finalization check is done with the block slot. The block root is used to verify that
    /// the finalized slot is in the canonical chain.
    pub fn is_finalized_block(
        &self,
        block_root: &Hash256,
        block_slot: Slot,
    ) -> Result<bool, Error> {
        let finalized_slot = self
            .canonical_head
            .cached_head()
            .finalized_checkpoint()
            .epoch
            .start_slot(T::EthSpec::slots_per_epoch());
        let is_canonical = self
            .block_root_at_slot(block_slot, WhenSlotSkipped::None)?
            .map_or(false, |canonical_root| block_root == &canonical_root);
        Ok(block_slot <= finalized_slot && is_canonical)
    }

    /// Checks if a state is finalized.
    /// The finalization check is done with the slot. The state root is used to verify that
    /// the finalized state is in the canonical chain.
    pub fn is_finalized_state(
        &self,
        state_root: &Hash256,
        state_slot: Slot,
    ) -> Result<bool, Error> {
        self.state_finalization_and_canonicity(state_root, state_slot)
            .map(FinalizationAndCanonicity::is_finalized)
    }

    /// Fetch the finalization and canonicity status of the state with `state_root`.
    pub fn state_finalization_and_canonicity(
        &self,
        state_root: &Hash256,
        state_slot: Slot,
    ) -> Result<FinalizationAndCanonicity, Error> {
        let finalized_slot = self
            .canonical_head
            .cached_head()
            .finalized_checkpoint()
            .epoch
            .start_slot(T::EthSpec::slots_per_epoch());
        let slot_is_finalized = state_slot <= finalized_slot;
        let canonical = self
            .state_root_at_slot(state_slot)?
            .map_or(false, |canonical_root| state_root == &canonical_root);
        Ok(FinalizationAndCanonicity {
            slot_is_finalized,
            canonical,
        })
    }

    /// Persists the head tracker and fork choice.
    ///
    /// We do it atomically even though no guarantees need to be made about blocks from
    /// the head tracker also being present in fork choice.
    pub fn persist_head_and_fork_choice(&self) -> Result<(), Error> {
        let mut batch = vec![];

        let _head_timer = metrics::start_timer(&metrics::PERSIST_HEAD);
        batch.push(self.persist_head_in_batch());

        let _fork_choice_timer = metrics::start_timer(&metrics::PERSIST_FORK_CHOICE);
        batch.push(self.persist_fork_choice_in_batch());

        self.store.hot_db.do_atomically(batch)?;

        Ok(())
    }

    /// Return a `PersistedBeaconChain` without reference to a `BeaconChain`.
    pub fn make_persisted_head(
        genesis_block_root: Hash256,
        head_tracker: &HeadTracker,
    ) -> PersistedBeaconChain {
        PersistedBeaconChain {
            _canonical_head_block_root: DUMMY_CANONICAL_HEAD_BLOCK_ROOT,
            genesis_block_root,
            ssz_head_tracker: head_tracker.to_ssz_container(),
        }
    }

    /// Return a database operation for writing the beacon chain head to disk.
    pub fn persist_head_in_batch(&self) -> KeyValueStoreOp {
        Self::persist_head_in_batch_standalone(self.genesis_block_root, &self.head_tracker)
    }

    pub fn persist_head_in_batch_standalone(
        genesis_block_root: Hash256,
        head_tracker: &HeadTracker,
    ) -> KeyValueStoreOp {
        Self::make_persisted_head(genesis_block_root, head_tracker)
            .as_kv_store_op(BEACON_CHAIN_DB_KEY)
    }

    /// Load fork choice from disk, returning `None` if it isn't found.
    pub fn load_fork_choice(
        store: BeaconStore<T>,
        reset_payload_statuses: ResetPayloadStatuses,
        spec: &ChainSpec,
        log: &Logger,
    ) -> Result<Option<BeaconForkChoice<T>>, Error> {
        let persisted_fork_choice =
            match store.get_item::<PersistedForkChoice>(&FORK_CHOICE_DB_KEY)? {
                Some(fc) => fc,
                None => return Ok(None),
            };

        let fc_store =
            BeaconForkChoiceStore::from_persisted(persisted_fork_choice.fork_choice_store, store)?;

        Ok(Some(ForkChoice::from_persisted(
            persisted_fork_choice.fork_choice,
            reset_payload_statuses,
            fc_store,
            spec,
            log,
        )?))
    }

    /// Persists `self.op_pool` to disk.
    ///
    /// ## Notes
    ///
    /// This operation is typically slow and causes a lot of allocations. It should be used
    /// sparingly.
    pub fn persist_op_pool(&self) -> Result<(), Error> {
        let _timer = metrics::start_timer(&metrics::PERSIST_OP_POOL);

        self.store.put_item(
            &OP_POOL_DB_KEY,
            &PersistedOperationPool::from_operation_pool(&self.op_pool),
        )?;

        Ok(())
    }

    /// Persists `self.eth1_chain` and its caches to disk.
    pub fn persist_eth1_cache(&self) -> Result<(), Error> {
        let _timer = metrics::start_timer(&metrics::PERSIST_ETH1_CACHE);

        if let Some(eth1_chain) = self.eth1_chain.as_ref() {
            self.store
                .put_item(&ETH1_CACHE_DB_KEY, &eth1_chain.as_ssz_container())?;
        }

        Ok(())
    }

    /// Returns the slot _right now_ according to `self.slot_clock`. Returns `Err` if the slot is
    /// unavailable.
    ///
    /// The slot might be unavailable due to an error with the system clock, or if the present time
    /// is before genesis (i.e., a negative slot).
    pub fn slot(&self) -> Result<Slot, Error> {
        self.slot_clock.now().ok_or(Error::UnableToReadSlot)
    }

    /// Returns the epoch _right now_ according to `self.slot_clock`. Returns `Err` if the epoch is
    /// unavailable.
    ///
    /// The epoch might be unavailable due to an error with the system clock, or if the present time
    /// is before genesis (i.e., a negative epoch).
    pub fn epoch(&self) -> Result<Epoch, Error> {
        self.slot()
            .map(|slot| slot.epoch(T::EthSpec::slots_per_epoch()))
    }

    /// Iterates across all `(block_root, slot)` pairs from `start_slot`
    /// to the head of the chain (inclusive).
    ///
    /// ## Notes
    ///
    /// - `slot` always increases by `1`.
    /// - Skipped slots contain the root of the closest prior
    ///     non-skipped slot (identical to the way they are stored in `state.block_roots`).
    /// - Iterator returns `(Hash256, Slot)`.
    ///
    /// Will return a `BlockOutOfRange` error if the requested start slot is before the period of
    /// history for which we have blocks stored. See `get_oldest_block_slot`.
    pub fn forwards_iter_block_roots(
        &self,
        start_slot: Slot,
    ) -> Result<impl Iterator<Item = Result<(Hash256, Slot), Error>> + '_, Error> {
        let oldest_block_slot = self.store.get_oldest_block_slot();
        if start_slot < oldest_block_slot {
            return Err(Error::HistoricalBlockError(
                HistoricalBlockError::BlockOutOfRange {
                    slot: start_slot,
                    oldest_block_slot,
                },
            ));
        }

        let local_head = self.head_snapshot();

        let iter = self.store.forwards_block_roots_iterator(
            start_slot,
            local_head.beacon_state.clone_with(CloneConfig::none()),
            local_head.beacon_block_root,
            &self.spec,
        )?;

        Ok(iter.map(|result| result.map_err(Into::into)))
    }

    /// Even more efficient variant of `forwards_iter_block_roots` that will avoid cloning the head
    /// state if it isn't required for the requested range of blocks.
    /// The range [start_slot, end_slot] is inclusive (ie `start_slot <= end_slot`)
    pub fn forwards_iter_block_roots_until(
        &self,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Result<impl Iterator<Item = Result<(Hash256, Slot), Error>> + '_, Error> {
        let oldest_block_slot = self.store.get_oldest_block_slot();
        if start_slot < oldest_block_slot {
            return Err(Error::HistoricalBlockError(
                HistoricalBlockError::BlockOutOfRange {
                    slot: start_slot,
                    oldest_block_slot,
                },
            ));
        }

        self.with_head(move |head| {
            let iter = self.store.forwards_block_roots_iterator_until(
                start_slot,
                end_slot,
                || {
                    (
                        head.beacon_state.clone_with_only_committee_caches(),
                        head.beacon_block_root,
                    )
                },
                &self.spec,
            )?;
            Ok(iter
                .map(|result| result.map_err(Into::into))
                .take_while(move |result| {
                    result.as_ref().map_or(true, |(_, slot)| *slot <= end_slot)
                }))
        })
    }

    /// Traverse backwards from `block_root` to find the block roots of its ancestors.
    ///
    /// ## Notes
    ///
    /// - `slot` always decreases by `1`.
    /// - Skipped slots contain the root of the closest prior
    ///     non-skipped slot (identical to the way they are stored in `state.block_roots`) .
    /// - Iterator returns `(Hash256, Slot)`.
    /// - The provided `block_root` is included as the first item in the iterator.
    pub fn rev_iter_block_roots_from(
        &self,
        block_root: Hash256,
    ) -> Result<impl Iterator<Item = Result<(Hash256, Slot), Error>> + '_, Error> {
        let block = self
            .get_blinded_block(&block_root)?
            .ok_or(Error::MissingBeaconBlock(block_root))?;
        let state = self
            .get_state(&block.state_root(), Some(block.slot()))?
            .ok_or_else(|| Error::MissingBeaconState(block.state_root()))?;
        let iter = BlockRootsIterator::owned(&self.store, state);
        Ok(std::iter::once(Ok((block_root, block.slot())))
            .chain(iter)
            .map(|result| result.map_err(|e| e.into())))
    }

    /// Iterates backwards across all `(state_root, slot)` pairs starting from
    /// an arbitrary `BeaconState` to the earliest reachable ancestor (may or may not be genesis).
    ///
    /// ## Notes
    ///
    /// - `slot` always decreases by `1`.
    /// - Iterator returns `(Hash256, Slot)`.
    /// - As this iterator starts at the `head` of the chain (viz., the best block), the first slot
    ///     returned may be earlier than the wall-clock slot.
    pub fn rev_iter_state_roots_from<'a>(
        &'a self,
        state_root: Hash256,
        state: &'a BeaconState<T::EthSpec>,
    ) -> impl Iterator<Item = Result<(Hash256, Slot), Error>> + 'a {
        std::iter::once(Ok((state_root, state.slot())))
            .chain(StateRootsIterator::new(&self.store, state))
            .map(|result| result.map_err(Into::into))
    }

    /// Iterates across all `(state_root, slot)` pairs from `start_slot`
    /// to the head of the chain (inclusive).
    ///
    /// ## Notes
    ///
    /// - `slot` always increases by `1`.
    /// - Iterator returns `(Hash256, Slot)`.
    pub fn forwards_iter_state_roots(
        &self,
        start_slot: Slot,
    ) -> Result<impl Iterator<Item = Result<(Hash256, Slot), Error>> + '_, Error> {
        let local_head = self.head_snapshot();

        let iter = self.store.forwards_state_roots_iterator(
            start_slot,
            local_head.beacon_state_root(),
            local_head.beacon_state.clone_with(CloneConfig::none()),
            &self.spec,
        )?;

        Ok(iter.map(|result| result.map_err(Into::into)))
    }

    /// Super-efficient forwards state roots iterator that avoids cloning the head if the state
    /// roots lie entirely within the freezer database.
    ///
    /// The iterator returned will include roots for `start_slot..=end_slot`, i.e.  it
    /// is endpoint inclusive.
    pub fn forwards_iter_state_roots_until(
        &self,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Result<impl Iterator<Item = Result<(Hash256, Slot), Error>> + '_, Error> {
        self.with_head(move |head| {
            let iter = self.store.forwards_state_roots_iterator_until(
                start_slot,
                end_slot,
                || {
                    (
                        head.beacon_state.clone_with_only_committee_caches(),
                        head.beacon_state_root(),
                    )
                },
                &self.spec,
            )?;
            Ok(iter
                .map(|result| result.map_err(Into::into))
                .take_while(move |result| {
                    result.as_ref().map_or(true, |(_, slot)| *slot <= end_slot)
                }))
        })
    }

    /// Returns the block at the given slot, if any. Only returns blocks in the canonical chain.
    ///
    /// Use the `skips` parameter to define the behaviour when `request_slot` is a skipped slot.
    ///
    /// ## Errors
    ///
    /// May return a database error.
    pub fn block_at_slot(
        &self,
        request_slot: Slot,
        skips: WhenSlotSkipped,
    ) -> Result<Option<SignedBlindedBeaconBlock<T::EthSpec>>, Error> {
        let root = self.block_root_at_slot(request_slot, skips)?;

        if let Some(block_root) = root {
            Ok(self.store.get_blinded_block(&block_root)?)
        } else {
            Ok(None)
        }
    }

    /// Returns the state root at the given slot, if any. Only returns state roots in the canonical chain.
    ///
    /// ## Errors
    ///
    /// May return a database error.
    pub fn state_root_at_slot(&self, request_slot: Slot) -> Result<Option<Hash256>, Error> {
        if request_slot > self.slot()? {
            return Ok(None);
        } else if request_slot == self.spec.genesis_slot {
            return Ok(Some(self.genesis_state_root));
        }

        // Check limits w.r.t historic state bounds.
        let (historic_lower_limit, historic_upper_limit) = self.store.get_historic_state_limits();
        if request_slot > historic_lower_limit && request_slot < historic_upper_limit {
            return Ok(None);
        }

        // Try an optimized path of reading the root directly from the head state.
        let fast_lookup: Option<Hash256> = self.with_head(|head| {
            if head.beacon_block.slot() <= request_slot {
                // Return the head state root if all slots between the request and the head are skipped.
                Ok(Some(head.beacon_state_root()))
            } else if let Ok(root) = head.beacon_state.get_state_root(request_slot) {
                // Return the root if it's easily accessible from the head state.
                Ok(Some(*root))
            } else {
                // Fast lookup is not possible.
                Ok::<_, Error>(None)
            }
        })?;

        if let Some(root) = fast_lookup {
            return Ok(Some(root));
        }

        process_results(
            self.forwards_iter_state_roots_until(request_slot, request_slot)?,
            |mut iter| {
                if let Some((root, slot)) = iter.next() {
                    if slot == request_slot {
                        Ok(Some(root))
                    } else {
                        // Sanity check.
                        Err(Error::InconsistentForwardsIter { request_slot, slot })
                    }
                } else {
                    Ok(None)
                }
            },
        )?
    }

    /// Returns the block root at the given slot, if any. Only returns roots in the canonical chain.
    ///
    /// ## Notes
    ///
    /// - Use the `skips` parameter to define the behaviour when `request_slot` is a skipped slot.
    /// - Returns `Ok(None)` for any slot higher than the current wall-clock slot, or less than
    ///   the oldest known block slot.
    pub fn block_root_at_slot(
        &self,
        request_slot: Slot,
        skips: WhenSlotSkipped,
    ) -> Result<Option<Hash256>, Error> {
        match skips {
            WhenSlotSkipped::None => self.block_root_at_slot_skips_none(request_slot),
            WhenSlotSkipped::Prev => self.block_root_at_slot_skips_prev(request_slot),
        }
        .or_else(|e| match e {
            Error::HistoricalBlockError(_) => Ok(None),
            e => Err(e),
        })
    }

    /// Returns the block root at the given slot, if any. Only returns roots in the canonical chain.
    ///
    /// ## Notes
    ///
    /// - Returns `Ok(None)` if the given `Slot` was skipped.
    /// - Returns `Ok(None)` for any slot higher than the current wall-clock slot.
    ///
    /// ## Errors
    ///
    /// May return a database error.
    fn block_root_at_slot_skips_none(&self, request_slot: Slot) -> Result<Option<Hash256>, Error> {
        if request_slot > self.slot()? {
            return Ok(None);
        } else if request_slot == self.spec.genesis_slot {
            return Ok(Some(self.genesis_block_root));
        }

        let prev_slot = request_slot.saturating_sub(1_u64);

        // Try an optimized path of reading the root directly from the head state.
        let fast_lookup: Option<Option<Hash256>> = self.with_head(|head| {
            let state = &head.beacon_state;

            // Try find the root for the `request_slot`.
            let request_root_opt = match state.slot().cmp(&request_slot) {
                // It's always a skip slot if the head is less than the request slot, return early.
                Ordering::Less => return Ok(Some(None)),
                // The request slot is the head slot.
                Ordering::Equal => Some(head.beacon_block_root),
                // Try find the request slot in the state.
                Ordering::Greater => state.get_block_root(request_slot).ok().copied(),
            };

            if let Some(request_root) = request_root_opt {
                if let Ok(prev_root) = state.get_block_root(prev_slot) {
                    return Ok(Some((*prev_root != request_root).then_some(request_root)));
                }
            }

            // Fast lookup is not possible.
            Ok::<_, Error>(None)
        })?;
        if let Some(root_opt) = fast_lookup {
            return Ok(root_opt);
        }

        if let Some(((prev_root, _), (curr_root, curr_slot))) = process_results(
            self.forwards_iter_block_roots_until(prev_slot, request_slot)?,
            |iter| iter.tuple_windows().next(),
        )? {
            // Sanity check.
            if curr_slot != request_slot {
                return Err(Error::InconsistentForwardsIter {
                    request_slot,
                    slot: curr_slot,
                });
            }
            Ok((curr_root != prev_root).then_some(curr_root))
        } else {
            Ok(None)
        }
    }

    /// Returns the block root at the given slot, if any. Only returns roots in the canonical chain.
    ///
    /// ## Notes
    ///
    /// - Returns the root at the previous non-skipped slot if the given `Slot` was skipped.
    /// - Returns `Ok(None)` for any slot higher than the current wall-clock slot.
    ///
    /// ## Errors
    ///
    /// May return a database error.
    fn block_root_at_slot_skips_prev(&self, request_slot: Slot) -> Result<Option<Hash256>, Error> {
        if request_slot > self.slot()? {
            return Ok(None);
        } else if request_slot == self.spec.genesis_slot {
            return Ok(Some(self.genesis_block_root));
        }

        // Try an optimized path of reading the root directly from the head state.
        let fast_lookup: Option<Hash256> = self.with_head(|head| {
            if head.beacon_block.slot() <= request_slot {
                // Return the head root if all slots between the request and the head are skipped.
                Ok(Some(head.beacon_block_root))
            } else if let Ok(root) = head.beacon_state.get_block_root(request_slot) {
                // Return the root if it's easily accessible from the head state.
                Ok(Some(*root))
            } else {
                // Fast lookup is not possible.
                Ok::<_, Error>(None)
            }
        })?;
        if let Some(root) = fast_lookup {
            return Ok(Some(root));
        }

        process_results(
            self.forwards_iter_block_roots_until(request_slot, request_slot)?,
            |mut iter| {
                if let Some((root, slot)) = iter.next() {
                    if slot == request_slot {
                        Ok(Some(root))
                    } else {
                        // Sanity check.
                        Err(Error::InconsistentForwardsIter { request_slot, slot })
                    }
                } else {
                    Ok(None)
                }
            },
        )?
    }

    /// Returns the block at the given root, if any.
    ///
    /// Will also check the early attester cache for the block. Because of this, there's no
    /// guarantee that a block returned from this function has a `BeaconState` available in
    /// `self.store`. The expected use for this function is *only* for returning blocks requested
    /// from P2P peers.
    ///
    /// ## Errors
    ///
    /// May return a database error.
    pub fn get_blocks_checking_early_attester_cache(
        self: &Arc<Self>,
        block_roots: Vec<Hash256>,
        executor: &TaskExecutor,
    ) -> Result<
        impl Stream<
            Item = (
                Hash256,
                Arc<Result<Option<Arc<SignedBeaconBlock<T::EthSpec>>>, Error>>,
            ),
        >,
        Error,
    > {
        Ok(
            BeaconBlockStreamer::<T>::new(self, CheckEarlyAttesterCache::Yes)?
                .launch_stream(block_roots, executor),
        )
    }

    pub fn get_blocks(
        self: &Arc<Self>,
        block_roots: Vec<Hash256>,
        executor: &TaskExecutor,
    ) -> Result<
        impl Stream<
            Item = (
                Hash256,
                Arc<Result<Option<Arc<SignedBeaconBlock<T::EthSpec>>>, Error>>,
            ),
        >,
        Error,
    > {
        Ok(
            BeaconBlockStreamer::<T>::new(self, CheckEarlyAttesterCache::No)?
                .launch_stream(block_roots, executor),
        )
    }

    /// Returns the block at the given root, if any.
    ///
    /// ## Errors
    ///
    /// May return a database error.
    pub async fn get_block(
        &self,
        block_root: &Hash256,
    ) -> Result<Option<SignedBeaconBlock<T::EthSpec>>, Error> {
        // Load block from database, returning immediately if we have the full block w payload
        // stored.
        let blinded_block = match self.store.try_get_full_block(block_root)? {
            Some(DatabaseBlock::Full(block)) => return Ok(Some(block)),
            Some(DatabaseBlock::Blinded(block)) => block,
            None => return Ok(None),
        };
        let fork = blinded_block.fork_name(&self.spec)?;

        // If we only have a blinded block, load the execution payload from the EL.
        let block_message = blinded_block.message();
        let execution_payload_header = block_message
            .execution_payload()
            .map_err(|_| Error::BlockVariantLacksExecutionPayload(*block_root))?
            .to_execution_payload_header();

        let exec_block_hash = execution_payload_header.block_hash();

        let execution_payload = self
            .execution_layer
            .as_ref()
            .ok_or(Error::ExecutionLayerMissing)?
            .get_payload_for_header(&execution_payload_header, fork)
            .await
            .map_err(|e| {
                Error::ExecutionLayerErrorPayloadReconstruction(exec_block_hash, Box::new(e))
            })?
            .ok_or(Error::BlockHashMissingFromExecutionLayer(exec_block_hash))?;

        // Verify payload integrity.
        let header_from_payload = ExecutionPayloadHeader::from(execution_payload.to_ref());
        if header_from_payload != execution_payload_header {
            for txn in execution_payload.transactions() {
                debug!(
                    self.log,
                    "Reconstructed txn";
                    "bytes" => format!("0x{}", hex::encode(&**txn)),
                );
            }

            return Err(Error::InconsistentPayloadReconstructed {
                slot: blinded_block.slot(),
                exec_block_hash,
                canonical_transactions_root: execution_payload_header.transactions_root(),
                reconstructed_transactions_root: header_from_payload.transactions_root(),
            });
        }

        // Add the payload to the block to form a full block.
        blinded_block
            .try_into_full_block(Some(execution_payload))
            .ok_or(Error::AddPayloadLogicError)
            .map(Some)
    }

    pub fn get_blinded_block(
        &self,
        block_root: &Hash256,
    ) -> Result<Option<SignedBlindedBeaconBlock<T::EthSpec>>, Error> {
        Ok(self.store.get_blinded_block(block_root)?)
    }

    /// Returns the state at the given root, if any.
    ///
    /// ## Errors
    ///
    /// May return a database error.
    pub fn get_state(
        &self,
        state_root: &Hash256,
        slot: Option<Slot>,
    ) -> Result<Option<BeaconState<T::EthSpec>>, Error> {
        Ok(self.store.get_state(state_root, slot)?)
    }

    /// Return the sync committee at `slot + 1` from the canonical chain.
    ///
    /// This is useful when dealing with sync committee messages, because messages are signed
    /// and broadcast one slot prior to the slot of the sync committee (which is relevant at
    /// sync committee period boundaries).
    pub fn sync_committee_at_next_slot(
        &self,
        slot: Slot,
    ) -> Result<Arc<SyncCommittee<T::EthSpec>>, Error> {
        let epoch = slot.safe_add(1)?.epoch(T::EthSpec::slots_per_epoch());
        self.sync_committee_at_epoch(epoch)
    }

    /// Return the sync committee at `epoch` from the canonical chain.
    pub fn sync_committee_at_epoch(
        &self,
        epoch: Epoch,
    ) -> Result<Arc<SyncCommittee<T::EthSpec>>, Error> {
        // Try to read a committee from the head. This will work most of the time, but will fail
        // for faraway committees, or if there are skipped slots at the transition to Altair.
        let spec = &self.spec;
        let committee_from_head =
            self.with_head(
                |head| match head.beacon_state.get_built_sync_committee(epoch, spec) {
                    Ok(committee) => Ok(Some(committee.clone())),
                    Err(BeaconStateError::SyncCommitteeNotKnown { .. })
                    | Err(BeaconStateError::IncorrectStateVariant) => Ok(None),
                    Err(e) => Err(Error::from(e)),
                },
            )?;

        if let Some(committee) = committee_from_head {
            Ok(committee)
        } else {
            // Slow path: load a state (or advance the head).
            let sync_committee_period = epoch.sync_committee_period(spec)?;
            let committee = self
                .state_for_sync_committee_period(sync_committee_period)?
                .get_built_sync_committee(epoch, spec)?
                .clone();
            Ok(committee)
        }
    }

    /// Load a state suitable for determining the sync committee for the given period.
    ///
    /// Specifically, the state at the start of the *previous* sync committee period.
    ///
    /// This is sufficient for historical duties, and efficient in the case where the head
    /// is lagging the current period and we need duties for the next period (because we only
    /// have to transition the head to start of the current period).
    ///
    /// We also need to ensure that the load slot is after the Altair fork.
    ///
    /// **WARNING**: the state returned will have dummy state roots. It should only be used
    /// for its sync committees (determining duties, etc).
    pub fn state_for_sync_committee_period(
        &self,
        sync_committee_period: u64,
    ) -> Result<BeaconState<T::EthSpec>, Error> {
        let altair_fork_epoch = self
            .spec
            .altair_fork_epoch
            .ok_or(Error::AltairForkDisabled)?;

        let load_slot = std::cmp::max(
            self.spec.epochs_per_sync_committee_period * sync_committee_period.saturating_sub(1),
            altair_fork_epoch,
        )
        .start_slot(T::EthSpec::slots_per_epoch());

        self.state_at_slot(load_slot, StateSkipConfig::WithoutStateRoots)
    }

    /// Returns the current heads of the `BeaconChain`. For the canonical head, see `Self::head`.
    ///
    /// Returns `(block_root, block_slot)`.
    pub fn heads(&self) -> Vec<(Hash256, Slot)> {
        self.head_tracker.heads()
    }

    pub fn knows_head(&self, block_hash: &SignedBeaconBlockHash) -> bool {
        self.head_tracker.contains_head((*block_hash).into())
    }

    /// Returns the `BeaconState` at the given slot.
    ///
    /// Returns `None` when the state is not found in the database or there is an error skipping
    /// to a future state.
    pub fn state_at_slot(
        &self,
        slot: Slot,
        config: StateSkipConfig,
    ) -> Result<BeaconState<T::EthSpec>, Error> {
        let head_state = self.head_beacon_state_cloned();

        match slot.cmp(&head_state.slot()) {
            Ordering::Equal => Ok(head_state),
            Ordering::Greater => {
                if slot > head_state.slot() + T::EthSpec::slots_per_epoch() {
                    warn!(
                        self.log,
                        "Skipping more than an epoch";
                        "head_slot" => head_state.slot(),
                        "request_slot" => slot
                    )
                }

                let start_slot = head_state.slot();
                let task_start = Instant::now();
                let max_task_runtime = Duration::from_secs(self.spec.seconds_per_slot);

                let head_state_slot = head_state.slot();
                let mut state = head_state;

                let skip_state_root = match config {
                    StateSkipConfig::WithStateRoots => None,
                    StateSkipConfig::WithoutStateRoots => Some(Hash256::zero()),
                };

                while state.slot() < slot {
                    // Do not allow and forward state skip that takes longer than the maximum task duration.
                    //
                    // This is a protection against nodes doing too much work when they're not synced
                    // to a chain.
                    if task_start + max_task_runtime < Instant::now() {
                        return Err(Error::StateSkipTooLarge {
                            start_slot,
                            requested_slot: slot,
                            max_task_runtime,
                        });
                    }

                    // Note: supplying some `state_root` when it is known would be a cheap and easy
                    // optimization.
                    match per_slot_processing(&mut state, skip_state_root, &self.spec) {
                        Ok(_) => (),
                        Err(e) => {
                            warn!(
                                self.log,
                                "Unable to load state at slot";
                                "error" => ?e,
                                "head_slot" => head_state_slot,
                                "requested_slot" => slot
                            );
                            return Err(Error::NoStateForSlot(slot));
                        }
                    };
                }
                Ok(state)
            }
            Ordering::Less => {
                let state_root =
                    process_results(self.forwards_iter_state_roots_until(slot, slot)?, |iter| {
                        iter.take_while(|(_, current_slot)| *current_slot >= slot)
                            .find(|(_, current_slot)| *current_slot == slot)
                            .map(|(root, _slot)| root)
                    })?
                    .ok_or(Error::NoStateForSlot(slot))?;

                Ok(self
                    .get_state(&state_root, Some(slot))?
                    .ok_or(Error::NoStateForSlot(slot))?)
            }
        }
    }

    /// Returns the `BeaconState` the current slot (viz., `self.slot()`).
    ///
    ///  - A reference to the head state (note: this keeps a read lock on the head, try to use
    ///  sparingly).
    ///  - The head state, but with skipped slots (for states later than the head).
    ///
    ///  Returns `None` when there is an error skipping to a future state or the slot clock cannot
    ///  be read.
    pub fn wall_clock_state(&self) -> Result<BeaconState<T::EthSpec>, Error> {
        self.state_at_slot(self.slot()?, StateSkipConfig::WithStateRoots)
    }

    /// Returns the validator index (if any) for the given public key.
    ///
    /// ## Notes
    ///
    /// This query uses the `validator_pubkey_cache` which contains _all_ validators ever seen,
    /// even if those validators aren't included in the head state. It is important to remember
    /// that just because a validator exists here, it doesn't necessarily exist in all
    /// `BeaconStates`.
    ///
    /// ## Errors
    ///
    /// May return an error if acquiring a read-lock on the `validator_pubkey_cache` times out.
    pub fn validator_index(&self, pubkey: &PublicKeyBytes) -> Result<Option<usize>, Error> {
        let pubkey_cache = self
            .validator_pubkey_cache
            .try_read_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
            .ok_or(Error::ValidatorPubkeyCacheLockTimeout)?;

        Ok(pubkey_cache.get_index(pubkey))
    }

    /// Return the validator indices of all public keys fetched from an iterator.
    ///
    /// If any public key doesn't belong to a known validator then an error will be returned.
    /// We could consider relaxing this by returning `Vec<Option<usize>>` in future.
    pub fn validator_indices<'a>(
        &self,
        validator_pubkeys: impl Iterator<Item = &'a PublicKeyBytes>,
    ) -> Result<Vec<u64>, Error> {
        let pubkey_cache = self
            .validator_pubkey_cache
            .try_read_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
            .ok_or(Error::ValidatorPubkeyCacheLockTimeout)?;

        validator_pubkeys
            .map(|pubkey| {
                pubkey_cache
                    .get_index(pubkey)
                    .map(|id| id as u64)
                    .ok_or(Error::ValidatorPubkeyUnknown(*pubkey))
            })
            .collect()
    }

    /// Returns the validator pubkey (if any) for the given validator index.
    ///
    /// ## Notes
    ///
    /// This query uses the `validator_pubkey_cache` which contains _all_ validators ever seen,
    /// even if those validators aren't included in the head state. It is important to remember
    /// that just because a validator exists here, it doesn't necessarily exist in all
    /// `BeaconStates`.
    ///
    /// ## Errors
    ///
    /// May return an error if acquiring a read-lock on the `validator_pubkey_cache` times out.
    pub fn validator_pubkey(&self, validator_index: usize) -> Result<Option<PublicKey>, Error> {
        let pubkey_cache = self
            .validator_pubkey_cache
            .try_read_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
            .ok_or(Error::ValidatorPubkeyCacheLockTimeout)?;

        Ok(pubkey_cache.get(validator_index).cloned())
    }

    /// As per `Self::validator_pubkey`, but returns `PublicKeyBytes`.
    pub fn validator_pubkey_bytes(
        &self,
        validator_index: usize,
    ) -> Result<Option<PublicKeyBytes>, Error> {
        let pubkey_cache = self
            .validator_pubkey_cache
            .try_read_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
            .ok_or(Error::ValidatorPubkeyCacheLockTimeout)?;

        Ok(pubkey_cache.get_pubkey_bytes(validator_index).copied())
    }

    /// As per `Self::validator_pubkey_bytes` but will resolve multiple indices at once to avoid
    /// bouncing the read-lock on the pubkey cache.
    ///
    /// Returns a map that may have a length less than `validator_indices.len()` if some indices
    /// were unable to be resolved.
    pub fn validator_pubkey_bytes_many(
        &self,
        validator_indices: &[usize],
    ) -> Result<HashMap<usize, PublicKeyBytes>, Error> {
        let pubkey_cache = self
            .validator_pubkey_cache
            .try_read_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
            .ok_or(Error::ValidatorPubkeyCacheLockTimeout)?;

        let mut map = HashMap::with_capacity(validator_indices.len());
        for &validator_index in validator_indices {
            if let Some(pubkey) = pubkey_cache.get_pubkey_bytes(validator_index) {
                map.insert(validator_index, *pubkey);
            }
        }
        Ok(map)
    }

    /// Returns the block canonical root of the current canonical chain at a given slot, starting from the given state.
    ///
    /// Returns `None` if the given slot doesn't exist in the chain.
    pub fn root_at_slot_from_state(
        &self,
        target_slot: Slot,
        beacon_block_root: Hash256,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<Option<Hash256>, Error> {
        let iter = BlockRootsIterator::new(&self.store, state);
        let iter_with_head = std::iter::once(Ok((beacon_block_root, state.slot())))
            .chain(iter)
            .map(|result| result.map_err(|e| e.into()));

        process_results(iter_with_head, |mut iter| {
            iter.find(|(_, slot)| *slot == target_slot)
                .map(|(root, _)| root)
        })
    }

    /// Returns the attestation duties for the given validator indices using the shuffling cache.
    ///
    /// An error may be returned if `head_block_root` is a finalized block, this function is only
    /// designed for operations at the head of the chain.
    ///
    /// The returned `Vec` will have the same length as `validator_indices`, any
    /// non-existing/inactive validators will have `None` values.
    ///
    /// ## Notes
    ///
    /// This function will try to use the shuffling cache to return the value. If the value is not
    /// in the shuffling cache, it will be added. Care should be taken not to wash out the
    /// shuffling cache with historical/useless values.
    pub fn validator_attestation_duties(
        &self,
        validator_indices: &[u64],
        epoch: Epoch,
        head_block_root: Hash256,
    ) -> Result<(Vec<Option<AttestationDuty>>, Hash256, ExecutionStatus), Error> {
        let execution_status = self
            .canonical_head
            .fork_choice_read_lock()
            .get_block_execution_status(&head_block_root)
            .ok_or(Error::AttestationHeadNotInForkChoice(head_block_root))?;

        let (duties, dependent_root) = self.with_committee_cache(
            head_block_root,
            epoch,
            |committee_cache, dependent_root| {
                let duties = validator_indices
                    .iter()
                    .map(|validator_index| {
                        let validator_index = *validator_index as usize;
                        committee_cache.get_attestation_duties(validator_index)
                    })
                    .collect();

                Ok((duties, dependent_root))
            },
        )?;
        Ok((duties, dependent_root, execution_status))
    }

    /// Returns an aggregated `Attestation`, if any, that has a matching `attestation.data`.
    ///
    /// The attestation will be obtained from `self.naive_aggregation_pool`.
    pub fn get_aggregated_attestation(
        &self,
        data: &AttestationData,
    ) -> Result<Option<Attestation<T::EthSpec>>, Error> {
        if let Some(attestation) = self.naive_aggregation_pool.read().get(data) {
            self.filter_optimistic_attestation(attestation)
                .map(Option::Some)
        } else {
            Ok(None)
        }
    }

    /// Returns an aggregated `Attestation`, if any, that has a matching
    /// `attestation.data.tree_hash_root()`.
    ///
    /// The attestation will be obtained from `self.naive_aggregation_pool`.
    pub fn get_aggregated_attestation_by_slot_and_root(
        &self,
        slot: Slot,
        attestation_data_root: &Hash256,
    ) -> Result<Option<Attestation<T::EthSpec>>, Error> {
        if let Some(attestation) = self
            .naive_aggregation_pool
            .read()
            .get_by_slot_and_root(slot, attestation_data_root)
        {
            self.filter_optimistic_attestation(attestation)
                .map(Option::Some)
        } else {
            Ok(None)
        }
    }

    /// Returns `Ok(attestation)` if the supplied `attestation` references a valid
    /// `beacon_block_root`.
    fn filter_optimistic_attestation(
        &self,
        attestation: Attestation<T::EthSpec>,
    ) -> Result<Attestation<T::EthSpec>, Error> {
        let beacon_block_root = attestation.data.beacon_block_root;
        match self
            .canonical_head
            .fork_choice_read_lock()
            .get_block_execution_status(&beacon_block_root)
        {
            // The attestation references a block that is not in fork choice, it must be
            // pre-finalization.
            None => Err(Error::CannotAttestToFinalizedBlock { beacon_block_root }),
            // The attestation references a fully valid `beacon_block_root`.
            Some(execution_status) if execution_status.is_valid_or_irrelevant() => Ok(attestation),
            // The attestation references a block that has not been verified by an EL (i.e. it
            // is optimistic or invalid). Don't return the block, return an error instead.
            Some(execution_status) => Err(Error::HeadBlockNotFullyVerified {
                beacon_block_root,
                execution_status,
            }),
        }
    }

    /// Return an aggregated `SyncCommitteeContribution` matching the given `root`.
    pub fn get_aggregated_sync_committee_contribution(
        &self,
        sync_contribution_data: &SyncContributionData,
    ) -> Result<Option<SyncCommitteeContribution<T::EthSpec>>, Error> {
        if let Some(contribution) = self
            .naive_sync_aggregation_pool
            .read()
            .get(sync_contribution_data)
        {
            self.filter_optimistic_sync_committee_contribution(contribution)
                .map(Option::Some)
        } else {
            Ok(None)
        }
    }

    fn filter_optimistic_sync_committee_contribution(
        &self,
        contribution: SyncCommitteeContribution<T::EthSpec>,
    ) -> Result<SyncCommitteeContribution<T::EthSpec>, Error> {
        let beacon_block_root = contribution.beacon_block_root;
        match self
            .canonical_head
            .fork_choice_read_lock()
            .get_block_execution_status(&beacon_block_root)
        {
            // The contribution references a block that is not in fork choice, it must be
            // pre-finalization.
            None => Err(Error::SyncContributionDataReferencesFinalizedBlock { beacon_block_root }),
            // The contribution references a fully valid `beacon_block_root`.
            Some(execution_status) if execution_status.is_valid_or_irrelevant() => Ok(contribution),
            // The contribution references a block that has not been verified by an EL (i.e. it
            // is optimistic or invalid). Don't return the block, return an error instead.
            Some(execution_status) => Err(Error::HeadBlockNotFullyVerified {
                beacon_block_root,
                execution_status,
            }),
        }
    }

    /// Produce an unaggregated `Attestation` that is valid for the given `slot` and `index`.
    ///
    /// The produced `Attestation` will not be valid until it has been signed by exactly one
    /// validator that is in the committee for `slot` and `index` in the canonical chain.
    ///
    /// Always attests to the canonical chain.
    ///
    /// ## Errors
    ///
    /// May return an error if the `request_slot` is too far behind the head state.
    pub fn produce_unaggregated_attestation(
        &self,
        request_slot: Slot,
        request_index: CommitteeIndex,
    ) -> Result<Attestation<T::EthSpec>, Error> {
        let _total_timer = metrics::start_timer(&metrics::ATTESTATION_PRODUCTION_SECONDS);

        // The early attester cache will return `Some(attestation)` in the scenario where there is a
        // block being imported that will become the head block, but that block has not yet been
        // inserted into the database and set as `self.canonical_head`.
        //
        // In effect, the early attester cache prevents slow database IO from causing missed
        // head/target votes.
        //
        // The early attester cache should never contain an optimistically imported block.
        match self
            .early_attester_cache
            .try_attest(request_slot, request_index, &self.spec)
        {
            // The cache matched this request, return the value.
            Ok(Some(attestation)) => return Ok(attestation),
            // The cache did not match this request, proceed with the rest of this function.
            Ok(None) => (),
            // The cache returned an error. Log the error and proceed with the rest of this
            // function.
            Err(e) => warn!(
                self.log,
                "Early attester cache failed";
                "error" => ?e
            ),
        }

        let slots_per_epoch = T::EthSpec::slots_per_epoch();
        let request_epoch = request_slot.epoch(slots_per_epoch);

        /*
         * Phase 1/2:
         *
         * Take a short-lived read-lock on the head and copy the necessary information from it.
         *
         * It is important that this first phase is as quick as possible; creating contention for
         * the head-lock is not desirable.
         */

        let head_state_slot;
        let beacon_block_root;
        let beacon_state_root;
        let target;
        let current_epoch_attesting_info: Option<(Checkpoint, usize)>;
        let attester_cache_key;
        let head_timer = metrics::start_timer(&metrics::ATTESTATION_PRODUCTION_HEAD_SCRAPE_SECONDS);
        // The following braces are to prevent the `cached_head` Arc from being held for longer than
        // required. It also helps reduce the diff for a very large PR (#3244).
        {
            let head = self.head_snapshot();
            let head_state = &head.beacon_state;
            head_state_slot = head_state.slot();

            // There is no value in producing an attestation to a block that is pre-finalization and
            // it is likely to cause expensive and pointless reads to the freezer database. Exit
            // early if this is the case.
            let finalized_slot = head_state
                .finalized_checkpoint()
                .epoch
                .start_slot(slots_per_epoch);
            if request_slot < finalized_slot {
                return Err(Error::AttestingToFinalizedSlot {
                    finalized_slot,
                    request_slot,
                });
            }

            // This function will eventually fail when trying to access a slot which is
            // out-of-bounds of `state.block_roots`. This explicit error is intended to provide a
            // clearer message to the user than an ambiguous `SlotOutOfBounds` error.
            let slots_per_historical_root = T::EthSpec::slots_per_historical_root() as u64;
            let lowest_permissible_slot =
                head_state.slot().saturating_sub(slots_per_historical_root);
            if request_slot < lowest_permissible_slot {
                return Err(Error::AttestingToAncientSlot {
                    lowest_permissible_slot,
                    request_slot,
                });
            }

            if request_slot >= head_state.slot() {
                // When attesting to the head slot or later, always use the head of the chain.
                beacon_block_root = head.beacon_block_root;
                beacon_state_root = head.beacon_state_root();
            } else {
                // Permit attesting to slots *prior* to the current head. This is desirable when
                // the VC and BN are out-of-sync due to time issues or overloading.
                beacon_block_root = *head_state.get_block_root(request_slot)?;
                beacon_state_root = *head_state.get_state_root(request_slot)?;
            };

            let target_slot = request_epoch.start_slot(T::EthSpec::slots_per_epoch());
            let target_root = if head_state.slot() <= target_slot {
                // If the state is earlier than the target slot then the target *must* be the head
                // block root.
                beacon_block_root
            } else {
                *head_state.get_block_root(target_slot)?
            };
            target = Checkpoint {
                epoch: request_epoch,
                root: target_root,
            };

            current_epoch_attesting_info = if head_state.current_epoch() == request_epoch {
                // When the head state is in the same epoch as the request, all the information
                // required to attest is available on the head state.
                Some((
                    head_state.current_justified_checkpoint(),
                    head_state
                        .get_beacon_committee(request_slot, request_index)?
                        .committee
                        .len(),
                ))
            } else {
                // If the head state is in a *different* epoch to the request, more work is required
                // to determine the justified checkpoint and committee length.
                None
            };

            // Determine the key for `self.attester_cache`, in case it is required later in this
            // routine.
            attester_cache_key =
                AttesterCacheKey::new(request_epoch, head_state, beacon_block_root)?;
        }
        drop(head_timer);

        // Only attest to a block if it is fully verified (i.e. not optimistic or invalid).
        match self
            .canonical_head
            .fork_choice_read_lock()
            .get_block_execution_status(&beacon_block_root)
        {
            Some(execution_status) if execution_status.is_valid_or_irrelevant() => (),
            Some(execution_status) => {
                return Err(Error::HeadBlockNotFullyVerified {
                    beacon_block_root,
                    execution_status,
                })
            }
            None => return Err(Error::HeadMissingFromForkChoice(beacon_block_root)),
        };

        /*
         *  Phase 2/2:
         *
         *  If the justified checkpoint and committee length from the head are suitable for this
         *  attestation, use them. If not, try the attester cache. If the cache misses, load a state
         *  from disk and prime the cache with it.
         */

        let cache_timer =
            metrics::start_timer(&metrics::ATTESTATION_PRODUCTION_CACHE_INTERACTION_SECONDS);
        let (justified_checkpoint, committee_len) =
            if let Some((justified_checkpoint, committee_len)) = current_epoch_attesting_info {
                // The head state is in the same epoch as the attestation, so there is no more
                // required information.
                (justified_checkpoint, committee_len)
            } else if let Some(cached_values) = self.attester_cache.get::<T::EthSpec>(
                &attester_cache_key,
                request_slot,
                request_index,
                &self.spec,
            )? {
                // The suitable values were already cached. Return them.
                cached_values
            } else {
                debug!(
                    self.log,
                    "Attester cache miss";
                    "beacon_block_root" => ?beacon_block_root,
                    "head_state_slot" => %head_state_slot,
                    "request_slot" => %request_slot,
                );

                // Neither the head state, nor the attester cache was able to produce the required
                // information to attest in this epoch. So, load a `BeaconState` from disk and use
                // it to fulfil the request (and prime the cache to avoid this next time).
                let _cache_build_timer =
                    metrics::start_timer(&metrics::ATTESTATION_PRODUCTION_CACHE_PRIME_SECONDS);
                self.attester_cache.load_and_cache_state(
                    beacon_state_root,
                    attester_cache_key,
                    request_slot,
                    request_index,
                    self,
                )?
            };
        drop(cache_timer);

        Ok(Attestation {
            aggregation_bits: BitList::with_capacity(committee_len)?,
            data: AttestationData {
                slot: request_slot,
                index: request_index,
                beacon_block_root,
                source: justified_checkpoint,
                target,
            },
            signature: AggregateSignature::empty(),
        })
    }

    /// Performs the same validation as `Self::verify_unaggregated_attestation_for_gossip`, but for
    /// multiple attestations using batch BLS verification. Batch verification can provide
    /// significant CPU-time savings compared to individual verification.
    pub fn batch_verify_unaggregated_attestations_for_gossip<'a, I>(
        &self,
        attestations: I,
    ) -> Result<
        Vec<Result<VerifiedUnaggregatedAttestation<'a, T>, AttestationError>>,
        AttestationError,
    >
    where
        I: Iterator<Item = (&'a Attestation<T::EthSpec>, Option<SubnetId>)> + ExactSizeIterator,
    {
        batch_verify_unaggregated_attestations(attestations, self)
    }

    /// Accepts some `Attestation` from the network and attempts to verify it, returning `Ok(_)` if
    /// it is valid to be (re)broadcast on the gossip network.
    ///
    /// The attestation must be "unaggregated", that is it must have exactly one
    /// aggregation bit set.
    pub fn verify_unaggregated_attestation_for_gossip<'a>(
        &self,
        unaggregated_attestation: &'a Attestation<T::EthSpec>,
        subnet_id: Option<SubnetId>,
    ) -> Result<VerifiedUnaggregatedAttestation<'a, T>, AttestationError> {
        metrics::inc_counter(&metrics::UNAGGREGATED_ATTESTATION_PROCESSING_REQUESTS);
        let _timer =
            metrics::start_timer(&metrics::UNAGGREGATED_ATTESTATION_GOSSIP_VERIFICATION_TIMES);

        VerifiedUnaggregatedAttestation::verify(unaggregated_attestation, subnet_id, self).map(
            |v| {
                // This method is called for API and gossip attestations, so this covers all unaggregated attestation events
                if let Some(event_handler) = self.event_handler.as_ref() {
                    if event_handler.has_attestation_subscribers() {
                        event_handler
                            .register(EventKind::Attestation(Box::new(v.attestation().clone())));
                    }
                }
                metrics::inc_counter(&metrics::UNAGGREGATED_ATTESTATION_PROCESSING_SUCCESSES);
                v
            },
        )
    }

    /// Performs the same validation as `Self::verify_aggregated_attestation_for_gossip`, but for
    /// multiple attestations using batch BLS verification. Batch verification can provide
    /// significant CPU-time savings compared to individual verification.
    pub fn batch_verify_aggregated_attestations_for_gossip<'a, I>(
        &self,
        aggregates: I,
    ) -> Result<Vec<Result<VerifiedAggregatedAttestation<'a, T>, AttestationError>>, AttestationError>
    where
        I: Iterator<Item = &'a SignedAggregateAndProof<T::EthSpec>> + ExactSizeIterator,
    {
        batch_verify_aggregated_attestations(aggregates, self)
    }

    /// Accepts some `SignedAggregateAndProof` from the network and attempts to verify it,
    /// returning `Ok(_)` if it is valid to be (re)broadcast on the gossip network.
    pub fn verify_aggregated_attestation_for_gossip<'a>(
        &self,
        signed_aggregate: &'a SignedAggregateAndProof<T::EthSpec>,
    ) -> Result<VerifiedAggregatedAttestation<'a, T>, AttestationError> {
        metrics::inc_counter(&metrics::AGGREGATED_ATTESTATION_PROCESSING_REQUESTS);
        let _timer =
            metrics::start_timer(&metrics::AGGREGATED_ATTESTATION_GOSSIP_VERIFICATION_TIMES);

        VerifiedAggregatedAttestation::verify(signed_aggregate, self).map(|v| {
            // This method is called for API and gossip attestations, so this covers all aggregated attestation events
            if let Some(event_handler) = self.event_handler.as_ref() {
                if event_handler.has_attestation_subscribers() {
                    event_handler
                        .register(EventKind::Attestation(Box::new(v.attestation().clone())));
                }
            }
            metrics::inc_counter(&metrics::AGGREGATED_ATTESTATION_PROCESSING_SUCCESSES);
            v
        })
    }

    /// Accepts some `SyncCommitteeMessage` from the network and attempts to verify it, returning `Ok(_)` if
    /// it is valid to be (re)broadcast on the gossip network.
    pub fn verify_sync_committee_message_for_gossip(
        &self,
        sync_message: SyncCommitteeMessage,
        subnet_id: SyncSubnetId,
    ) -> Result<VerifiedSyncCommitteeMessage, SyncCommitteeError> {
        metrics::inc_counter(&metrics::SYNC_MESSAGE_PROCESSING_REQUESTS);
        let _timer = metrics::start_timer(&metrics::SYNC_MESSAGE_GOSSIP_VERIFICATION_TIMES);

        VerifiedSyncCommitteeMessage::verify(sync_message, subnet_id, self).map(|v| {
            metrics::inc_counter(&metrics::SYNC_MESSAGE_PROCESSING_SUCCESSES);
            v
        })
    }

    /// Accepts some `SignedContributionAndProof` from the network and attempts to verify it,
    /// returning `Ok(_)` if it is valid to be (re)broadcast on the gossip network.
    pub fn verify_sync_contribution_for_gossip(
        &self,
        sync_contribution: SignedContributionAndProof<T::EthSpec>,
    ) -> Result<VerifiedSyncContribution<T>, SyncCommitteeError> {
        metrics::inc_counter(&metrics::SYNC_CONTRIBUTION_PROCESSING_REQUESTS);
        let _timer = metrics::start_timer(&metrics::SYNC_CONTRIBUTION_GOSSIP_VERIFICATION_TIMES);
        VerifiedSyncContribution::verify(sync_contribution, self).map(|v| {
            if let Some(event_handler) = self.event_handler.as_ref() {
                if event_handler.has_contribution_subscribers() {
                    event_handler.register(EventKind::ContributionAndProof(Box::new(
                        v.aggregate().clone(),
                    )));
                }
            }
            metrics::inc_counter(&metrics::SYNC_CONTRIBUTION_PROCESSING_SUCCESSES);
            v
        })
    }

    /// Accepts some 'LightClientFinalityUpdate' from the network and attempts to verify it
    pub fn verify_finality_update_for_gossip(
        self: &Arc<Self>,
        light_client_finality_update: LightClientFinalityUpdate<T::EthSpec>,
        seen_timestamp: Duration,
    ) -> Result<VerifiedLightClientFinalityUpdate<T>, LightClientFinalityUpdateError> {
        VerifiedLightClientFinalityUpdate::verify(
            light_client_finality_update,
            self,
            seen_timestamp,
        )
        .map(|v| {
            metrics::inc_counter(&metrics::FINALITY_UPDATE_PROCESSING_SUCCESSES);
            v
        })
    }

    /// Accepts some 'LightClientOptimisticUpdate' from the network and attempts to verify it
    pub fn verify_optimistic_update_for_gossip(
        self: &Arc<Self>,
        light_client_optimistic_update: LightClientOptimisticUpdate<T::EthSpec>,
        seen_timestamp: Duration,
    ) -> Result<VerifiedLightClientOptimisticUpdate<T>, LightClientOptimisticUpdateError> {
        VerifiedLightClientOptimisticUpdate::verify(
            light_client_optimistic_update,
            self,
            seen_timestamp,
        )
        .map(|v| {
            metrics::inc_counter(&metrics::OPTIMISTIC_UPDATE_PROCESSING_SUCCESSES);
            v
        })
    }

    /// Accepts some attestation-type object and attempts to verify it in the context of fork
    /// choice. If it is valid it is applied to `self.fork_choice`.
    ///
    /// Common items that implement `VerifiedAttestation`:
    ///
    /// - `VerifiedUnaggregatedAttestation`
    /// - `VerifiedAggregatedAttestation`
    pub fn apply_attestation_to_fork_choice(
        &self,
        verified: &impl VerifiedAttestation<T>,
    ) -> Result<(), Error> {
        let _timer = metrics::start_timer(&metrics::FORK_CHOICE_PROCESS_ATTESTATION_TIMES);

        self.canonical_head
            .fork_choice_write_lock()
            .on_attestation(
                self.slot()?,
                verified.indexed_attestation(),
                AttestationFromBlock::False,
            )
            .map_err(Into::into)
    }

    /// Accepts an `VerifiedUnaggregatedAttestation` and attempts to apply it to the "naive
    /// aggregation pool".
    ///
    /// The naive aggregation pool is used by local validators to produce
    /// `SignedAggregateAndProof`.
    ///
    /// If the attestation is too old (low slot) to be included in the pool it is simply dropped
    /// and no error is returned.
    pub fn add_to_naive_aggregation_pool(
        &self,
        unaggregated_attestation: &impl VerifiedAttestation<T>,
    ) -> Result<(), AttestationError> {
        let _timer = metrics::start_timer(&metrics::ATTESTATION_PROCESSING_APPLY_TO_AGG_POOL);

        let attestation = unaggregated_attestation.attestation();

        match self.naive_aggregation_pool.write().insert(attestation) {
            Ok(outcome) => trace!(
                self.log,
                "Stored unaggregated attestation";
                "outcome" => ?outcome,
                "index" => attestation.data.index,
                "slot" => attestation.data.slot.as_u64(),
            ),
            Err(NaiveAggregationError::SlotTooLow {
                slot,
                lowest_permissible_slot,
            }) => {
                trace!(
                    self.log,
                    "Refused to store unaggregated attestation";
                    "lowest_permissible_slot" => lowest_permissible_slot.as_u64(),
                    "slot" => slot.as_u64(),
                );
            }
            Err(e) => {
                error!(
                        self.log,
                        "Failed to store unaggregated attestation";
                        "error" => ?e,
                        "index" => attestation.data.index,
                        "slot" => attestation.data.slot.as_u64(),
                );
                return Err(Error::from(e).into());
            }
        };

        Ok(())
    }

    /// Accepts a `VerifiedSyncCommitteeMessage` and attempts to apply it to the "naive
    /// aggregation pool".
    ///
    /// The naive aggregation pool is used by local validators to produce
    /// `SignedContributionAndProof`.
    ///
    /// If the sync message is too old (low slot) to be included in the pool it is simply dropped
    /// and no error is returned.
    pub fn add_to_naive_sync_aggregation_pool(
        &self,
        verified_sync_committee_message: VerifiedSyncCommitteeMessage,
    ) -> Result<VerifiedSyncCommitteeMessage, SyncCommitteeError> {
        let sync_message = verified_sync_committee_message.sync_message();
        let positions_by_subnet_id: &HashMap<SyncSubnetId, Vec<usize>> =
            verified_sync_committee_message.subnet_positions();
        for (subnet_id, positions) in positions_by_subnet_id.iter() {
            for position in positions {
                let _timer =
                    metrics::start_timer(&metrics::SYNC_CONTRIBUTION_PROCESSING_APPLY_TO_AGG_POOL);
                let contribution = SyncCommitteeContribution::from_message(
                    sync_message,
                    subnet_id.into(),
                    *position,
                )?;

                match self
                    .naive_sync_aggregation_pool
                    .write()
                    .insert(&contribution)
                {
                    Ok(outcome) => trace!(
                        self.log,
                        "Stored unaggregated sync committee message";
                        "outcome" => ?outcome,
                        "index" => sync_message.validator_index,
                        "slot" => sync_message.slot.as_u64(),
                    ),
                    Err(NaiveAggregationError::SlotTooLow {
                        slot,
                        lowest_permissible_slot,
                    }) => {
                        trace!(
                            self.log,
                            "Refused to store unaggregated sync committee message";
                            "lowest_permissible_slot" => lowest_permissible_slot.as_u64(),
                            "slot" => slot.as_u64(),
                        );
                    }
                    Err(e) => {
                        error!(
                                self.log,
                                "Failed to store unaggregated sync committee message";
                                "error" => ?e,
                                "index" => sync_message.validator_index,
                                "slot" => sync_message.slot.as_u64(),
                        );
                        return Err(Error::from(e).into());
                    }
                };
            }
        }
        Ok(verified_sync_committee_message)
    }

    /// Accepts a `VerifiedAttestation` and attempts to apply it to `self.op_pool`.
    ///
    /// The op pool is used by local block producers to pack blocks with operations.
    pub fn add_to_block_inclusion_pool<A>(
        &self,
        verified_attestation: A,
    ) -> Result<(), AttestationError>
    where
        A: VerifiedAttestation<T>,
    {
        let _timer = metrics::start_timer(&metrics::ATTESTATION_PROCESSING_APPLY_TO_OP_POOL);

        // If there's no eth1 chain then it's impossible to produce blocks and therefore
        // useless to put things in the op pool.
        if self.eth1_chain.is_some() {
            let (attestation, attesting_indices) =
                verified_attestation.into_attestation_and_indices();
            self.op_pool
                .insert_attestation(attestation, attesting_indices)
                .map_err(Error::from)?;
        }

        Ok(())
    }

    /// Accepts a `VerifiedSyncContribution` and attempts to apply it to `self.op_pool`.
    ///
    /// The op pool is used by local block producers to pack blocks with operations.
    pub fn add_contribution_to_block_inclusion_pool(
        &self,
        contribution: VerifiedSyncContribution<T>,
    ) -> Result<(), SyncCommitteeError> {
        let _timer = metrics::start_timer(&metrics::SYNC_CONTRIBUTION_PROCESSING_APPLY_TO_OP_POOL);

        // If there's no eth1 chain then it's impossible to produce blocks and therefore
        // useless to put things in the op pool.
        if self.eth1_chain.is_some() {
            self.op_pool
                .insert_sync_contribution(contribution.contribution())
                .map_err(Error::from)?;
        }

        Ok(())
    }

    /// Filter an attestation from the op pool for shuffling compatibility.
    ///
    /// Use the provided `filter_cache` map to memoize results.
    pub fn filter_op_pool_attestation(
        &self,
        filter_cache: &mut HashMap<(Hash256, Epoch), bool>,
        att: &AttestationRef<T::EthSpec>,
        state: &BeaconState<T::EthSpec>,
    ) -> bool {
        *filter_cache
            .entry((att.data.beacon_block_root, att.checkpoint.target_epoch))
            .or_insert_with(|| {
                self.shuffling_is_compatible(
                    &att.data.beacon_block_root,
                    att.checkpoint.target_epoch,
                    state,
                )
            })
    }

    /// Check that the shuffling at `block_root` is equal to one of the shufflings of `state`.
    ///
    /// The `target_epoch` argument determines which shuffling to check compatibility with, it
    /// should be equal to the current or previous epoch of `state`, or else `false` will be
    /// returned.
    ///
    /// The compatibility check is designed to be fast: we check that the block that
    /// determined the RANDAO mix for the `target_epoch` matches the ancestor of the block
    /// identified by `block_root` (at that slot).
    pub fn shuffling_is_compatible(
        &self,
        block_root: &Hash256,
        target_epoch: Epoch,
        state: &BeaconState<T::EthSpec>,
    ) -> bool {
        self.shuffling_is_compatible_result(block_root, target_epoch, state)
            .unwrap_or_else(|e| {
                debug!(
                    self.log,
                    "Skipping attestation with incompatible shuffling";
                    "block_root" => ?block_root,
                    "target_epoch" => target_epoch,
                    "reason" => ?e,
                );
                false
            })
    }

    fn shuffling_is_compatible_result(
        &self,
        block_root: &Hash256,
        target_epoch: Epoch,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<bool, Error> {
        // Compute the shuffling ID for the head state in the `target_epoch`.
        let relative_epoch = RelativeEpoch::from_epoch(state.current_epoch(), target_epoch)
            .map_err(|e| Error::BeaconStateError(e.into()))?;
        let head_shuffling_id =
            AttestationShufflingId::new(self.genesis_block_root, state, relative_epoch)?;

        // Load the block's shuffling ID from fork choice. We use the variant of `get_block` that
        // checks descent from the finalized block, so there's one case where we'll spuriously
        // return `false`: where an attestation for the previous epoch nominates the pivot block
        // which is the parent block of the finalized block. Such attestations are not useful, so
        // this doesn't matter.
        let fork_choice_lock = self.canonical_head.fork_choice_read_lock();
        let block = fork_choice_lock
            .get_block(block_root)
            .ok_or(Error::AttestationHeadNotInForkChoice(*block_root))?;
        drop(fork_choice_lock);

        let block_shuffling_id = if target_epoch == block.current_epoch_shuffling_id.shuffling_epoch
        {
            block.current_epoch_shuffling_id
        } else if target_epoch == block.next_epoch_shuffling_id.shuffling_epoch {
            block.next_epoch_shuffling_id
        } else if target_epoch > block.next_epoch_shuffling_id.shuffling_epoch {
            AttestationShufflingId {
                shuffling_epoch: target_epoch,
                shuffling_decision_block: *block_root,
            }
        } else {
            debug!(
                self.log,
                "Skipping attestation with incompatible shuffling";
                "block_root" => ?block_root,
                "target_epoch" => target_epoch,
                "reason" => "target epoch less than block epoch"
            );
            return Ok(false);
        };

        if head_shuffling_id == block_shuffling_id {
            Ok(true)
        } else {
            debug!(
                self.log,
                "Skipping attestation with incompatible shuffling";
                "block_root" => ?block_root,
                "target_epoch" => target_epoch,
                "head_shuffling_id" => ?head_shuffling_id,
                "block_shuffling_id" => ?block_shuffling_id,
            );
            Ok(false)
        }
    }

    /// Verify a voluntary exit before allowing it to propagate on the gossip network.
    pub fn verify_voluntary_exit_for_gossip(
        &self,
        exit: SignedVoluntaryExit,
    ) -> Result<ObservationOutcome<SignedVoluntaryExit, T::EthSpec>, Error> {
        let head_snapshot = self.head().snapshot;
        let head_state = &head_snapshot.beacon_state;
        let wall_clock_epoch = self.epoch()?;

        Ok(self
            .observed_voluntary_exits
            .lock()
            .verify_and_observe_at(exit, wall_clock_epoch, head_state, &self.spec)
            .map(|exit| {
                // this method is called for both API and gossip exits, so this covers all exit events
                if let Some(event_handler) = self.event_handler.as_ref() {
                    if event_handler.has_exit_subscribers() {
                        if let ObservationOutcome::New(exit) = exit.clone() {
                            event_handler.register(EventKind::VoluntaryExit(exit.into_inner()));
                        }
                    }
                }
                exit
            })?)
    }

    /// Accept a pre-verified exit and queue it for inclusion in an appropriate block.
    pub fn import_voluntary_exit(&self, exit: SigVerifiedOp<SignedVoluntaryExit, T::EthSpec>) {
        if self.eth1_chain.is_some() {
            self.op_pool.insert_voluntary_exit(exit)
        }
    }

    /// Verify a proposer slashing before allowing it to propagate on the gossip network.
    pub fn verify_proposer_slashing_for_gossip(
        &self,
        proposer_slashing: ProposerSlashing,
    ) -> Result<ObservationOutcome<ProposerSlashing, T::EthSpec>, Error> {
        let wall_clock_state = self.wall_clock_state()?;
        Ok(self.observed_proposer_slashings.lock().verify_and_observe(
            proposer_slashing,
            &wall_clock_state,
            &self.spec,
        )?)
    }

    /// Accept some proposer slashing and queue it for inclusion in an appropriate block.
    pub fn import_proposer_slashing(
        &self,
        proposer_slashing: SigVerifiedOp<ProposerSlashing, T::EthSpec>,
    ) {
        if self.eth1_chain.is_some() {
            self.op_pool.insert_proposer_slashing(proposer_slashing)
        }
    }

    /// Verify an attester slashing before allowing it to propagate on the gossip network.
    pub fn verify_attester_slashing_for_gossip(
        &self,
        attester_slashing: AttesterSlashing<T::EthSpec>,
    ) -> Result<ObservationOutcome<AttesterSlashing<T::EthSpec>, T::EthSpec>, Error> {
        let wall_clock_state = self.wall_clock_state()?;
        Ok(self.observed_attester_slashings.lock().verify_and_observe(
            attester_slashing,
            &wall_clock_state,
            &self.spec,
        )?)
    }

    /// Accept a verified attester slashing and:
    ///
    /// 1. Apply it to fork choice.
    /// 2. Add it to the op pool.
    pub fn import_attester_slashing(
        &self,
        attester_slashing: SigVerifiedOp<AttesterSlashing<T::EthSpec>, T::EthSpec>,
    ) {
        // Add to fork choice.
        self.canonical_head
            .fork_choice_write_lock()
            .on_attester_slashing(attester_slashing.as_inner());

        // Add to the op pool (if we have the ability to propose blocks).
        if self.eth1_chain.is_some() {
            self.op_pool.insert_attester_slashing(attester_slashing)
        }
    }

    /// Verify a signed BLS to execution change before allowing it to propagate on the gossip network.
    pub fn verify_bls_to_execution_change_for_http_api(
        &self,
        bls_to_execution_change: SignedBlsToExecutionChange,
    ) -> Result<ObservationOutcome<SignedBlsToExecutionChange, T::EthSpec>, Error> {
        // Before checking the gossip duplicate filter, check that no prior change is already
        // in our op pool. Ignore these messages: do not gossip, do not try to override the pool.
        match self
            .op_pool
            .bls_to_execution_change_in_pool_equals(&bls_to_execution_change)
        {
            Some(true) => return Ok(ObservationOutcome::AlreadyKnown),
            Some(false) => return Err(Error::BlsToExecutionConflictsWithPool),
            None => (),
        }

        // Use the head state to save advancing to the wall-clock slot unnecessarily. The message is
        // signed with respect to the genesis fork version, and the slot check for gossip is applied
        // separately. This `Arc` clone of the head is nice and cheap.
        let head_snapshot = self.head().snapshot;
        let head_state = &head_snapshot.beacon_state;

        Ok(self
            .observed_bls_to_execution_changes
            .lock()
            .verify_and_observe(bls_to_execution_change, head_state, &self.spec)?)
    }

    /// Verify a signed BLS to execution change before allowing it to propagate on the gossip network.
    pub fn verify_bls_to_execution_change_for_gossip(
        &self,
        bls_to_execution_change: SignedBlsToExecutionChange,
    ) -> Result<ObservationOutcome<SignedBlsToExecutionChange, T::EthSpec>, Error> {
        // Ignore BLS to execution changes on gossip prior to Capella.
        if !self.current_slot_is_post_capella()? {
            return Err(Error::BlsToExecutionPriorToCapella);
        }
        self.verify_bls_to_execution_change_for_http_api(bls_to_execution_change)
            .or_else(|e| {
                // On gossip treat conflicts the same as duplicates [IGNORE].
                match e {
                    Error::BlsToExecutionConflictsWithPool => Ok(ObservationOutcome::AlreadyKnown),
                    e => Err(e),
                }
            })
    }

    /// Check if the current slot is greater than or equal to the Capella fork epoch.
    pub fn current_slot_is_post_capella(&self) -> Result<bool, Error> {
        let current_fork = self.spec.fork_name_at_slot::<T::EthSpec>(self.slot()?);
        if let ForkName::Base | ForkName::Altair | ForkName::Merge = current_fork {
            Ok(false)
        } else {
            Ok(true)
        }
    }

    /// Import a BLS to execution change to the op pool.
    ///
    /// Return `true` if the change was added to the pool.
    pub fn import_bls_to_execution_change(
        &self,
        bls_to_execution_change: SigVerifiedOp<SignedBlsToExecutionChange, T::EthSpec>,
        received_pre_capella: ReceivedPreCapella,
    ) -> bool {
        if self.eth1_chain.is_some() {
            self.op_pool
                .insert_bls_to_execution_change(bls_to_execution_change, received_pre_capella)
        } else {
            false
        }
    }

    /// Attempt to obtain sync committee duties from the head.
    pub fn sync_committee_duties_from_head(
        &self,
        epoch: Epoch,
        validator_indices: &[u64],
    ) -> Result<Vec<Option<SyncDuty>>, Error> {
        self.with_head(move |head| {
            head.beacon_state
                .get_sync_committee_duties(epoch, validator_indices, &self.spec)
                .map_err(Error::SyncDutiesError)
        })
    }

    /// A convenience method for spawning a blocking task. It maps an `Option` and
    /// `tokio::JoinError` into a single `BeaconChainError`.
    pub(crate) async fn spawn_blocking_handle<F, R>(
        &self,
        task: F,
        name: &'static str,
    ) -> Result<R, Error>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let handle = self
            .task_executor
            .spawn_blocking_handle(task, name)
            .ok_or(Error::RuntimeShutdown)?;

        handle.await.map_err(Error::TokioJoin)
    }

    /// Accepts a `chain_segment` and filters out any uninteresting blocks (e.g., pre-finalization
    /// or already-known).
    ///
    /// This method is potentially long-running and should not run on the core executor.
    pub fn filter_chain_segment(
        self: &Arc<Self>,
        chain_segment: Vec<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> Result<Vec<HashBlockTuple<T::EthSpec>>, ChainSegmentResult<T::EthSpec>> {
        // This function will never import any blocks.
        let imported_blocks = 0;
        let mut filtered_chain_segment = Vec::with_capacity(chain_segment.len());

        // Produce a list of the parent root and slot of the child of each block.
        //
        // E.g., `children[0] == (chain_segment[1].parent_root(), chain_segment[1].slot())`
        let children = chain_segment
            .iter()
            .skip(1)
            .map(|block| (block.parent_root(), block.slot()))
            .collect::<Vec<_>>();

        for (i, block) in chain_segment.into_iter().enumerate() {
            // Ensure the block is the correct structure for the fork at `block.slot()`.
            if let Err(e) = block.fork_name(&self.spec) {
                return Err(ChainSegmentResult::Failed {
                    imported_blocks,
                    error: BlockError::InconsistentFork(e),
                });
            }

            let block_root = get_block_root(&block);

            if let Some((child_parent_root, child_slot)) = children.get(i) {
                // If this block has a child in this chain segment, ensure that its parent root matches
                // the root of this block.
                //
                // Without this check it would be possible to have a block verified using the
                // incorrect shuffling. That would be bad, mmkay.
                if block_root != *child_parent_root {
                    return Err(ChainSegmentResult::Failed {
                        imported_blocks,
                        error: BlockError::NonLinearParentRoots,
                    });
                }

                // Ensure that the slots are strictly increasing throughout the chain segment.
                if *child_slot <= block.slot() {
                    return Err(ChainSegmentResult::Failed {
                        imported_blocks,
                        error: BlockError::NonLinearSlots,
                    });
                }
            }

            match check_block_relevancy(&block, block_root, self) {
                // If the block is relevant, add it to the filtered chain segment.
                Ok(_) => filtered_chain_segment.push((block_root, block)),
                // If the block is already known, simply ignore this block.
                Err(BlockError::BlockIsAlreadyKnown) => continue,
                // If the block is the genesis block, simply ignore this block.
                Err(BlockError::GenesisBlock) => continue,
                // If the block is is for a finalized slot, simply ignore this block.
                //
                // The block is either:
                //
                // 1. In the canonical finalized chain.
                // 2. In some non-canonical chain at a slot that has been finalized already.
                //
                // In the case of (1), there's no need to re-import and later blocks in this
                // segement might be useful.
                //
                // In the case of (2), skipping the block is valid since we should never import it.
                // However, we will potentially get a `ParentUnknown` on a later block. The sync
                // protocol will need to ensure this is handled gracefully.
                Err(BlockError::WouldRevertFinalizedSlot { .. }) => continue,
                // The block has a known parent that does not descend from the finalized block.
                // There is no need to process this block or any children.
                Err(BlockError::NotFinalizedDescendant { block_parent_root }) => {
                    return Err(ChainSegmentResult::Failed {
                        imported_blocks,
                        error: BlockError::NotFinalizedDescendant { block_parent_root },
                    });
                }
                // If there was an error whilst determining if the block was invalid, return that
                // error.
                Err(BlockError::BeaconChainError(e)) => {
                    return Err(ChainSegmentResult::Failed {
                        imported_blocks,
                        error: BlockError::BeaconChainError(e),
                    });
                }
                // If the block was decided to be irrelevant for any other reason, don't include
                // this block or any of it's children in the filtered chain segment.
                _ => break,
            }
        }

        Ok(filtered_chain_segment)
    }

    /// Attempt to verify and import a chain of blocks to `self`.
    ///
    /// The provided blocks _must_ each reference the previous block via `block.parent_root` (i.e.,
    /// be a chain). An error will be returned if this is not the case.
    ///
    /// This operation is not atomic; if one of the blocks in the chain is invalid then some prior
    /// blocks might be imported.
    ///
    /// This method is generally much more efficient than importing each block using
    /// `Self::process_block`.
    pub async fn process_chain_segment(
        self: &Arc<Self>,
        chain_segment: Vec<Arc<SignedBeaconBlock<T::EthSpec>>>,
        notify_execution_layer: NotifyExecutionLayer,
    ) -> ChainSegmentResult<T::EthSpec> {
        let mut imported_blocks = 0;

        // Filter uninteresting blocks from the chain segment in a blocking task.
        let chain = self.clone();
        let filtered_chain_segment_future = self.spawn_blocking_handle(
            move || chain.filter_chain_segment(chain_segment),
            "filter_chain_segment",
        );
        let mut filtered_chain_segment = match filtered_chain_segment_future.await {
            Ok(Ok(filtered_segment)) => filtered_segment,
            Ok(Err(segment_result)) => return segment_result,
            Err(error) => {
                return ChainSegmentResult::Failed {
                    imported_blocks,
                    error: BlockError::BeaconChainError(error),
                }
            }
        };

        while let Some((_root, block)) = filtered_chain_segment.first() {
            // Determine the epoch of the first block in the remaining segment.
            let start_epoch = block.slot().epoch(T::EthSpec::slots_per_epoch());

            // The `last_index` indicates the position of the first block in an epoch greater
            // than the current epoch: partitioning the blocks into a run of blocks in the same
            // epoch and everything else. These same-epoch blocks can all be signature-verified with
            // the same `BeaconState`.
            let last_index = filtered_chain_segment
                .iter()
                .position(|(_root, block)| {
                    block.slot().epoch(T::EthSpec::slots_per_epoch()) > start_epoch
                })
                .unwrap_or(filtered_chain_segment.len());

            let mut blocks = filtered_chain_segment.split_off(last_index);
            std::mem::swap(&mut blocks, &mut filtered_chain_segment);

            let chain = self.clone();
            let signature_verification_future = self.spawn_blocking_handle(
                move || signature_verify_chain_segment(blocks, &chain),
                "signature_verify_chain_segment",
            );

            // Verify the signature of the blocks, returning early if the signature is invalid.
            let signature_verified_blocks = match signature_verification_future.await {
                Ok(Ok(blocks)) => blocks,
                Ok(Err(error)) => {
                    return ChainSegmentResult::Failed {
                        imported_blocks,
                        error,
                    };
                }
                Err(error) => {
                    return ChainSegmentResult::Failed {
                        imported_blocks,
                        error: BlockError::BeaconChainError(error),
                    };
                }
            };

            // Import the blocks into the chain.
            for signature_verified_block in signature_verified_blocks {
                match self
                    .process_block(
                        signature_verified_block.block_root(),
                        signature_verified_block,
                        notify_execution_layer,
                        || Ok(()),
                    )
                    .await
                {
                    Ok(_) => imported_blocks += 1,
                    Err(error) => {
                        return ChainSegmentResult::Failed {
                            imported_blocks,
                            error,
                        };
                    }
                }
            }
        }

        ChainSegmentResult::Successful { imported_blocks }
    }

    /// Returns `Ok(GossipVerifiedBlock)` if the supplied `block` should be forwarded onto the
    /// gossip network. The block is not imported into the chain, it is just partially verified.
    ///
    /// The returned `GossipVerifiedBlock` should be provided to `Self::process_block` immediately
    /// after it is returned, unless some other circumstance decides it should not be imported at
    /// all.
    ///
    /// ## Errors
    ///
    /// Returns an `Err` if the given block was invalid, or an error was encountered during
    pub async fn verify_block_for_gossip(
        self: &Arc<Self>,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
    ) -> Result<GossipVerifiedBlock<T>, BlockError<T::EthSpec>> {
        let chain = self.clone();
        self.task_executor
            .clone()
            .spawn_blocking_handle(
                move || {
                    let slot = block.slot();
                    let graffiti_string = block.message().body().graffiti().as_utf8_lossy();

                    match GossipVerifiedBlock::new(block, &chain) {
                        Ok(verified) => {
                            debug!(
                                chain.log,
                                "Successfully verified gossip block";
                                "graffiti" => graffiti_string,
                                "slot" => slot,
                                "root" => ?verified.block_root(),
                            );

                            Ok(verified)
                        }
                        Err(e) => {
                            debug!(
                                chain.log,
                                "Rejected gossip block";
                                "error" => e.to_string(),
                                "graffiti" => graffiti_string,
                                "slot" => slot,
                            );

                            Err(e)
                        }
                    }
                },
                "payload_verification_handle",
            )
            .ok_or(BeaconChainError::RuntimeShutdown)?
            .await
            .map_err(BeaconChainError::TokioJoin)?
    }

    /// Returns `Ok(block_root)` if the given `unverified_block` was successfully verified and
    /// imported into the chain.
    ///
    /// Items that implement `IntoExecutionPendingBlock` include:
    ///
    /// - `SignedBeaconBlock`
    /// - `GossipVerifiedBlock`
    ///
    /// ## Errors
    ///
    /// Returns an `Err` if the given block was invalid, or an error was encountered during
    /// verification.
    pub async fn process_block<B: IntoExecutionPendingBlock<T>>(
        self: &Arc<Self>,
        block_root: Hash256,
        unverified_block: B,
        notify_execution_layer: NotifyExecutionLayer,
        publish_fn: impl FnOnce() -> Result<(), BlockError<T::EthSpec>> + Send + 'static,
    ) -> Result<Hash256, BlockError<T::EthSpec>> {
        // Start the Prometheus timer.
        let _full_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_TIMES);

        // Increment the Prometheus counter for block processing requests.
        metrics::inc_counter(&metrics::BLOCK_PROCESSING_REQUESTS);

        // Clone the block so we can provide it to the event handler.
        let block = unverified_block.block().clone();

        // A small closure to group the verification and import errors.
        let chain = self.clone();
        let import_block = async move {
            let execution_pending = unverified_block.into_execution_pending_block(
                block_root,
                &chain,
                notify_execution_layer,
            )?;
            publish_fn()?;
            chain
                .import_execution_pending_block(execution_pending)
                .await
        };

        // Verify and import the block.
        match import_block.await {
            // The block was successfully verified and imported. Yay.
            Ok(block_root) => {
                trace!(
                    self.log,
                    "Beacon block imported";
                    "block_root" => ?block_root,
                    "block_slot" => %block.slot(),
                );

                // Increment the Prometheus counter for block processing successes.
                metrics::inc_counter(&metrics::BLOCK_PROCESSING_SUCCESSES);

                Ok(block_root)
            }
            Err(e @ BlockError::BeaconChainError(BeaconChainError::TokioJoin(_))) => {
                debug!(
                    self.log,
                    "Beacon block processing cancelled";
                    "error" => ?e,
                );
                Err(e)
            }
            // There was an error whilst attempting to verify and import the block. The block might
            // be partially verified or partially imported.
            Err(BlockError::BeaconChainError(e)) => {
                crit!(
                    self.log,
                    "Beacon block processing error";
                    "error" => ?e,
                );
                Err(BlockError::BeaconChainError(e))
            }
            // The block failed verification.
            Err(other) => {
                debug!(
                    self.log,
                    "Beacon block rejected";
                    "reason" => other.to_string(),
                );
                Err(other)
            }
        }
    }

    /// Accepts a fully-verified block and imports it into the chain without performing any
    /// additional verification.
    ///
    /// An error is returned if the block was unable to be imported. It may be partially imported
    /// (i.e., this function is not atomic).
    pub async fn import_execution_pending_block(
        self: Arc<Self>,
        execution_pending_block: ExecutionPendingBlock<T>,
    ) -> Result<Hash256, BlockError<T::EthSpec>> {
        let ExecutionPendingBlock {
            block,
            block_root,
            state,
            parent_block,
            confirmed_state_roots,
            payload_verification_handle,
            parent_eth1_finalization_data,
            consensus_context,
        } = execution_pending_block;

        let PayloadVerificationOutcome {
            payload_verification_status,
            is_valid_merge_transition_block,
        } = payload_verification_handle
            .await
            .map_err(BeaconChainError::TokioJoin)?
            .ok_or(BeaconChainError::RuntimeShutdown)??;

        // Log the PoS pandas if a merge transition just occurred.
        if is_valid_merge_transition_block {
            info!(self.log, "{}", POS_PANDA_BANNER);
            info!(
                self.log,
                "Proof of Stake Activated";
                "slot" => block.slot()
            );
            info!(
                self.log, "";
                "Terminal POW Block Hash" => ?block
                    .message()
                    .execution_payload()?
                    .parent_hash()
                    .into_root()
            );
            info!(
                self.log, "";
                "Merge Transition Block Root" => ?block.message().tree_hash_root()
            );
            info!(
                self.log, "";
                "Merge Transition Execution Hash" => ?block
                    .message()
                    .execution_payload()?
                    .block_hash()
                    .into_root()
            );
        }

        let chain = self.clone();
        let block_hash = self
            .spawn_blocking_handle(
                move || {
                    chain.import_block(
                        block,
                        block_root,
                        state,
                        confirmed_state_roots,
                        payload_verification_status,
                        parent_block,
                        parent_eth1_finalization_data,
                        consensus_context,
                    )
                },
                "payload_verification_handle",
            )
            .await??;

        Ok(block_hash)
    }

    /// Accepts a fully-verified block and imports it into the chain without performing any
    /// additional verification.
    ///
    /// An error is returned if the block was unable to be imported. It may be partially imported
    /// (i.e., this function is not atomic).
    #[allow(clippy::too_many_arguments)]
    fn import_block(
        &self,
        signed_block: Arc<SignedBeaconBlock<T::EthSpec>>,
        block_root: Hash256,
        mut state: BeaconState<T::EthSpec>,
        confirmed_state_roots: Vec<Hash256>,
        payload_verification_status: PayloadVerificationStatus,
        parent_block: SignedBlindedBeaconBlock<T::EthSpec>,
        parent_eth1_finalization_data: Eth1FinalizationData,
        mut consensus_context: ConsensusContext<T::EthSpec>,
    ) -> Result<Hash256, BlockError<T::EthSpec>> {
        // ----------------------------- BLOCK NOT YET ATTESTABLE ----------------------------------
        // Everything in this initial section is on the hot path between processing the block and
        // being able to attest to it. DO NOT add any extra processing in this initial section
        // unless it must run before fork choice.
        // -----------------------------------------------------------------------------------------
        let current_slot = self.slot()?;
        let current_epoch = current_slot.epoch(T::EthSpec::slots_per_epoch());
        let block = signed_block.message();
        let post_exec_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_POST_EXEC_PROCESSING);

        // Check against weak subjectivity checkpoint.
        self.check_block_against_weak_subjectivity_checkpoint(block, block_root, &state)?;

        // If there are new validators in this block, update our pubkey cache.
        //
        // The only keys imported here will be ones for validators deposited in this block, because
        // the cache *must* already have been updated for the parent block when it was imported.
        // Newly deposited validators are not active and their keys are not required by other parts
        // of block processing. The reason we do this here and not after making the block attestable
        // is so we don't have to think about lock ordering with respect to the fork choice lock.
        // There are a bunch of places where we lock both fork choice and the pubkey cache and it
        // would be difficult to check that they all lock fork choice first.
        let mut ops = self
            .validator_pubkey_cache
            .try_write_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
            .ok_or(Error::ValidatorPubkeyCacheLockTimeout)?
            .import_new_pubkeys(&state)?;

        // Apply the state to the attester cache, only if it is from the previous epoch or later.
        //
        // In a perfect scenario there should be no need to add previous-epoch states to the cache.
        // However, latency between the VC and the BN might cause the VC to produce attestations at
        // a previous slot.
        if state.current_epoch().saturating_add(1_u64) >= current_epoch {
            self.attester_cache
                .maybe_cache_state(&state, block_root, &self.spec)
                .map_err(BeaconChainError::from)?;
        }

        // Take an exclusive write-lock on fork choice. It's very important to prevent deadlocks by
        // avoiding taking other locks whilst holding this lock.
        let mut fork_choice = self.canonical_head.fork_choice_write_lock();

        // Do not import a block that doesn't descend from the finalized root.
        check_block_is_finalized_checkpoint_or_descendant(self, &fork_choice, &signed_block)?;

        // Register the new block with the fork choice service.
        {
            let _fork_choice_block_timer =
                metrics::start_timer(&metrics::FORK_CHOICE_PROCESS_BLOCK_TIMES);
            let block_delay = self
                .slot_clock
                .seconds_from_current_slot_start()
                .ok_or(Error::UnableToComputeTimeAtSlot)?;

            fork_choice
                .on_block(
                    current_slot,
                    block,
                    block_root,
                    block_delay,
                    &state,
                    payload_verification_status,
                    self.config.progressive_balances_mode,
                    &self.spec,
                    &self.log,
                )
                .map_err(|e| BlockError::BeaconChainError(e.into()))?;
        }

        // If the block is recent enough and it was not optimistically imported, check to see if it
        // becomes the head block. If so, apply it to the early attester cache. This will allow
        // attestations to the block without waiting for the block and state to be inserted to the
        // database.
        //
        // Only performing this check on recent blocks avoids slowing down sync with lots of calls
        // to fork choice `get_head`.
        //
        // Optimistically imported blocks are not added to the cache since the cache is only useful
        // for a small window of time and the complexity of keeping track of the optimistic status
        // is not worth it.
        if !payload_verification_status.is_optimistic()
            && block.slot() + EARLY_ATTESTER_CACHE_HISTORIC_SLOTS >= current_slot
        {
            let fork_choice_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_FORK_CHOICE);
            match fork_choice.get_head(current_slot, &self.spec) {
                // This block became the head, add it to the early attester cache.
                Ok(new_head_root) if new_head_root == block_root => {
                    if let Some(proto_block) = fork_choice.get_block(&block_root) {
                        if let Err(e) = self.early_attester_cache.add_head_block(
                            block_root,
                            signed_block.clone(),
                            proto_block,
                            &state,
                            &self.spec,
                        ) {
                            warn!(
                                self.log,
                                "Early attester cache insert failed";
                                "error" => ?e
                            );
                        }
                    } else {
                        warn!(
                            self.log,
                            "Early attester block missing";
                            "block_root" => ?block_root
                        );
                    }
                }
                // This block did not become the head, nothing to do.
                Ok(_) => (),
                Err(e) => error!(
                    self.log,
                    "Failed to compute head during block import";
                    "error" => ?e
                ),
            }
            drop(fork_choice_timer);
        }
        drop(post_exec_timer);

        // ---------------------------- BLOCK PROBABLY ATTESTABLE ----------------------------------
        // Most blocks are now capable of being attested to thanks to the `early_attester_cache`
        // cache above. Resume non-essential processing.
        //
        // It is important NOT to return errors here before the database commit, because the block
        // has already been added to fork choice and the database would be left in an inconsistent
        // state if we returned early without committing. In other words, an error here would
        // corrupt the node's database permanently.
        // -----------------------------------------------------------------------------------------

        self.import_block_update_shuffling_cache(block_root, &mut state);
        self.import_block_observe_attestations(
            block,
            &state,
            &mut consensus_context,
            current_epoch,
        );
        self.import_block_update_validator_monitor(
            block,
            &state,
            &mut consensus_context,
            current_slot,
            parent_block.slot(),
        );
        self.import_block_update_slasher(block, &state, &mut consensus_context);

        let db_write_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_DB_WRITE);

        // Store the block and its state, and execute the confirmation batch for the intermediate
        // states, which will delete their temporary flags.
        // If the write fails, revert fork choice to the version from disk, else we can
        // end up with blocks in fork choice that are missing from disk.
        // See https://github.com/sigp/lighthouse/issues/2028
        ops.extend(
            confirmed_state_roots
                .into_iter()
                .map(StoreOp::DeleteStateTemporaryFlag),
        );
        ops.push(StoreOp::PutBlock(block_root, signed_block.clone()));
        ops.push(StoreOp::PutState(block.state_root(), &state));
        let txn_lock = self.store.hot_db.begin_rw_transaction();

        if let Err(e) = self.store.do_atomically(ops) {
            error!(
                self.log,
                "Database write failed!";
                "msg" => "Restoring fork choice from disk",
                "error" => ?e,
            );

            // Clear the early attester cache to prevent attestations which we would later be unable
            // to verify due to the failure.
            self.early_attester_cache.clear();

            // Since the write failed, try to revert the canonical head back to what was stored
            // in the database. This attempts to prevent inconsistency between the database and
            // fork choice.
            if let Err(e) = self.canonical_head.restore_from_store(
                fork_choice,
                ResetPayloadStatuses::always_reset_conditionally(
                    self.config.always_reset_payload_statuses,
                ),
                &self.store,
                &self.spec,
                &self.log,
            ) {
                crit!(
                    self.log,
                    "No stored fork choice found to restore from";
                    "error" => ?e,
                    "warning" => "The database is likely corrupt now, consider --purge-db"
                );
                return Err(BlockError::BeaconChainError(e));
            }

            return Err(e.into());
        }
        drop(txn_lock);

        // The fork choice write-lock is dropped *after* the on-disk database has been updated.
        // This prevents inconsistency between the two at the expense of concurrency.
        drop(fork_choice);

        // We're declaring the block "imported" at this point, since fork choice and the DB know
        // about it.
        let block_time_imported = timestamp_now();

        let parent_root = block.parent_root();
        let slot = block.slot();

        let current_eth1_finalization_data = Eth1FinalizationData {
            eth1_data: state.eth1_data().clone(),
            eth1_deposit_index: state.eth1_deposit_index(),
        };
        let current_finalized_checkpoint = state.finalized_checkpoint();

        self.snapshot_cache
            .try_write_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
            .ok_or(Error::SnapshotCacheLockTimeout)
            .map(|mut snapshot_cache| {
                snapshot_cache.insert(
                    BeaconSnapshot {
                        beacon_state: state,
                        beacon_block: signed_block.clone(),
                        beacon_block_root: block_root,
                    },
                    None,
                    &self.spec,
                )
            })
            .unwrap_or_else(|e| {
                error!(
                    self.log,
                    "Failed to insert snapshot";
                    "error" => ?e,
                    "task" => "process block"
                );
            });

        self.head_tracker
            .register_block(block_root, parent_root, slot);

        metrics::stop_timer(db_write_timer);

        metrics::inc_counter(&metrics::BLOCK_PROCESSING_SUCCESSES);

        // Update the deposit contract cache.
        self.import_block_update_deposit_contract_finalization(
            block,
            block_root,
            current_epoch,
            current_finalized_checkpoint,
            current_eth1_finalization_data,
            parent_eth1_finalization_data,
            parent_block.slot(),
        );

        // Inform the unknown block cache, in case it was waiting on this block.
        self.pre_finalization_block_cache
            .block_processed(block_root);

        self.import_block_update_metrics_and_events(
            block,
            block_root,
            block_time_imported,
            payload_verification_status,
            current_slot,
        );

        Ok(block_root)
    }

    /// Check block's consistentency with any configured weak subjectivity checkpoint.
    fn check_block_against_weak_subjectivity_checkpoint(
        &self,
        block: BeaconBlockRef<T::EthSpec>,
        block_root: Hash256,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<(), BlockError<T::EthSpec>> {
        // Only perform the weak subjectivity check if it was configured.
        let wss_checkpoint = if let Some(checkpoint) = self.config.weak_subjectivity_checkpoint {
            checkpoint
        } else {
            return Ok(());
        };
        // Note: we're using the finalized checkpoint from the head state, rather than fork
        // choice.
        //
        // We are doing this to ensure that we detect changes in finalization. It's possible
        // that fork choice has already been updated to the finalized checkpoint in the block
        // we're importing.
        let current_head_finalized_checkpoint =
            self.canonical_head.cached_head().finalized_checkpoint();
        // Compare the existing finalized checkpoint with the incoming block's finalized checkpoint.
        let new_finalized_checkpoint = state.finalized_checkpoint();

        // This ensures we only perform the check once.
        if current_head_finalized_checkpoint.epoch < wss_checkpoint.epoch
            && wss_checkpoint.epoch <= new_finalized_checkpoint.epoch
        {
            if let Err(e) =
                self.verify_weak_subjectivity_checkpoint(wss_checkpoint, block_root, state)
            {
                let mut shutdown_sender = self.shutdown_sender();
                crit!(
                    self.log,
                    "Weak subjectivity checkpoint verification failed while importing block!";
                    "block_root" => ?block_root,
                    "parent_root" => ?block.parent_root(),
                    "old_finalized_epoch" => ?current_head_finalized_checkpoint.epoch,
                    "new_finalized_epoch" => ?new_finalized_checkpoint.epoch,
                    "weak_subjectivity_epoch" => ?wss_checkpoint.epoch,
                    "error" => ?e
                );
                crit!(
                    self.log,
                    "You must use the `--purge-db` flag to clear the database and restart sync. \
                         You may be on a hostile network."
                );
                shutdown_sender
                    .try_send(ShutdownReason::Failure(
                        "Weak subjectivity checkpoint verification failed. \
                             Provided block root is not a checkpoint.",
                    ))
                    .map_err(|err| {
                        BlockError::BeaconChainError(
                            BeaconChainError::WeakSubjectivtyShutdownError(err),
                        )
                    })?;
                return Err(BlockError::WeakSubjectivityConflict);
            }
        }
        Ok(())
    }

    /// Process a block for the validator monitor, including all its constituent messages.
    fn import_block_update_validator_monitor(
        &self,
        block: BeaconBlockRef<T::EthSpec>,
        state: &BeaconState<T::EthSpec>,
        ctxt: &mut ConsensusContext<T::EthSpec>,
        current_slot: Slot,
        parent_block_slot: Slot,
    ) {
        // Only register blocks with the validator monitor when the block is sufficiently close to
        // the current slot.
        if VALIDATOR_MONITOR_HISTORIC_EPOCHS as u64 * T::EthSpec::slots_per_epoch()
            + block.slot().as_u64()
            < current_slot.as_u64()
        {
            return;
        }

        // Allow the validator monitor to learn about a new valid state.
        self.validator_monitor
            .write()
            .process_valid_state(current_slot.epoch(T::EthSpec::slots_per_epoch()), state);

        let validator_monitor = self.validator_monitor.read();

        // Sync aggregate.
        if let Ok(sync_aggregate) = block.body().sync_aggregate() {
            // `SyncCommittee` for the sync_aggregate should correspond to the duty slot
            let duty_epoch = block.slot().epoch(T::EthSpec::slots_per_epoch());

            match self.sync_committee_at_epoch(duty_epoch) {
                Ok(sync_committee) => {
                    let participant_pubkeys = sync_committee
                        .pubkeys
                        .iter()
                        .zip(sync_aggregate.sync_committee_bits.iter())
                        .filter_map(|(pubkey, bit)| bit.then_some(pubkey))
                        .collect::<Vec<_>>();

                    validator_monitor.register_sync_aggregate_in_block(
                        block.slot(),
                        block.parent_root(),
                        participant_pubkeys,
                    );
                }
                Err(e) => {
                    warn!(
                        self.log,
                        "Unable to fetch sync committee";
                        "epoch" => duty_epoch,
                        "purpose" => "validator monitor",
                        "error" => ?e,
                    );
                }
            }
        }

        // Attestations.
        for attestation in block.body().attestations() {
            let indexed_attestation = match ctxt.get_indexed_attestation(state, attestation) {
                Ok(indexed) => indexed,
                Err(e) => {
                    debug!(
                        self.log,
                        "Failed to get indexed attestation";
                        "purpose" => "validator monitor",
                        "attestation_slot" => attestation.data.slot,
                        "error" => ?e,
                    );
                    continue;
                }
            };
            validator_monitor.register_attestation_in_block(
                indexed_attestation,
                parent_block_slot,
                &self.spec,
            );
        }

        for exit in block.body().voluntary_exits() {
            validator_monitor.register_block_voluntary_exit(&exit.message)
        }

        for slashing in block.body().attester_slashings() {
            validator_monitor.register_block_attester_slashing(slashing)
        }

        for slashing in block.body().proposer_slashings() {
            validator_monitor.register_block_proposer_slashing(slashing)
        }
    }

    /// Iterate through the attestations in the block and register them as "observed".
    ///
    /// This will stop us from propagating them on the gossip network.
    fn import_block_observe_attestations(
        &self,
        block: BeaconBlockRef<T::EthSpec>,
        state: &BeaconState<T::EthSpec>,
        ctxt: &mut ConsensusContext<T::EthSpec>,
        current_epoch: Epoch,
    ) {
        // To avoid slowing down sync, only observe attestations if the block is from the
        // previous epoch or later.
        if state.current_epoch() + 1 < current_epoch {
            return;
        }

        let _timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_ATTESTATION_OBSERVATION);

        for a in block.body().attestations() {
            match self.observed_attestations.write().observe_item(a, None) {
                // If the observation was successful or if the slot for the attestation was too
                // low, continue.
                //
                // We ignore `SlotTooLow` since this will be very common whilst syncing.
                Ok(_) | Err(AttestationObservationError::SlotTooLow { .. }) => {}
                Err(e) => {
                    debug!(
                        self.log,
                        "Failed to register observed attestation";
                        "error" => ?e,
                        "epoch" => a.data.target.epoch
                    );
                }
            }

            let indexed_attestation = match ctxt.get_indexed_attestation(state, a) {
                Ok(indexed) => indexed,
                Err(e) => {
                    debug!(
                        self.log,
                        "Failed to get indexed attestation";
                        "purpose" => "observation",
                        "attestation_slot" => a.data.slot,
                        "error" => ?e,
                    );
                    continue;
                }
            };

            let mut observed_block_attesters = self.observed_block_attesters.write();

            for &validator_index in &indexed_attestation.attesting_indices {
                if let Err(e) = observed_block_attesters
                    .observe_validator(a.data.target.epoch, validator_index as usize)
                {
                    debug!(
                        self.log,
                        "Failed to register observed block attester";
                        "error" => ?e,
                        "epoch" => a.data.target.epoch,
                        "validator_index" => validator_index,
                    )
                }
            }
        }
    }

    /// If a slasher is configured, provide the attestations from the block.
    fn import_block_update_slasher(
        &self,
        block: BeaconBlockRef<T::EthSpec>,
        state: &BeaconState<T::EthSpec>,
        ctxt: &mut ConsensusContext<T::EthSpec>,
    ) {
        if let Some(slasher) = self.slasher.as_ref() {
            for attestation in block.body().attestations() {
                let indexed_attestation = match ctxt.get_indexed_attestation(state, attestation) {
                    Ok(indexed) => indexed,
                    Err(e) => {
                        debug!(
                            self.log,
                            "Failed to get indexed attestation";
                            "purpose" => "slasher",
                            "attestation_slot" => attestation.data.slot,
                            "error" => ?e,
                        );
                        continue;
                    }
                };
                slasher.accept_attestation(indexed_attestation.clone());
            }
        }
    }

    fn import_block_update_metrics_and_events(
        &self,
        block: BeaconBlockRef<T::EthSpec>,
        block_root: Hash256,
        block_time_imported: Duration,
        payload_verification_status: PayloadVerificationStatus,
        current_slot: Slot,
    ) {
        // Only present some metrics for blocks from the previous epoch or later.
        //
        // This helps avoid noise in the metrics during sync.
        if block.slot() + 2 * T::EthSpec::slots_per_epoch() >= current_slot {
            metrics::observe(
                &metrics::OPERATIONS_PER_BLOCK_ATTESTATION,
                block.body().attestations().len() as f64,
            );

            if let Ok(sync_aggregate) = block.body().sync_aggregate() {
                metrics::set_gauge(
                    &metrics::BLOCK_SYNC_AGGREGATE_SET_BITS,
                    sync_aggregate.num_set_bits() as i64,
                );
            }
        }

        let block_delay_total =
            get_slot_delay_ms(block_time_imported, block.slot(), &self.slot_clock);

        // Do not write to the cache for blocks older than 2 epochs, this helps reduce writes to
        // the cache during sync.
        if block_delay_total < self.slot_clock.slot_duration() * 64 {
            // Store the timestamp of the block being imported into the cache.
            self.block_times_cache.write().set_time_imported(
                block_root,
                current_slot,
                block_time_imported,
            );
        }

        // Do not store metrics if the block was > 4 slots old, this helps prevent noise during
        // sync.
        if block_delay_total < self.slot_clock.slot_duration() * 4 {
            // Observe the delay between when we observed the block and when we imported it.
            let block_delays = self.block_times_cache.read().get_block_delays(
                block_root,
                self.slot_clock
                    .start_of(current_slot)
                    .unwrap_or_else(|| Duration::from_secs(0)),
            );

            metrics::observe_duration(
                &metrics::BEACON_BLOCK_IMPORTED_OBSERVED_DELAY_TIME,
                block_delays
                    .imported
                    .unwrap_or_else(|| Duration::from_secs(0)),
            );
        }

        if let Some(event_handler) = self.event_handler.as_ref() {
            if event_handler.has_block_subscribers() {
                event_handler.register(EventKind::Block(SseBlock {
                    slot: block.slot(),
                    block: block_root,
                    execution_optimistic: payload_verification_status.is_optimistic(),
                }));
            }
        }
    }

    // For the current and next epoch of this state, ensure we have the shuffling from this
    // block in our cache.
    fn import_block_update_shuffling_cache(
        &self,
        block_root: Hash256,
        state: &mut BeaconState<T::EthSpec>,
    ) {
        if let Err(e) = self.import_block_update_shuffling_cache_fallible(block_root, state) {
            warn!(
                self.log,
                "Failed to prime shuffling cache";
                "error" => ?e
            );
        }
    }

    fn import_block_update_shuffling_cache_fallible(
        &self,
        block_root: Hash256,
        state: &mut BeaconState<T::EthSpec>,
    ) -> Result<(), BlockError<T::EthSpec>> {
        for relative_epoch in [RelativeEpoch::Current, RelativeEpoch::Next] {
            let shuffling_id = AttestationShufflingId::new(block_root, state, relative_epoch)?;

            let shuffling_is_cached = self
                .shuffling_cache
                .try_read_for(ATTESTATION_CACHE_LOCK_TIMEOUT)
                .ok_or(Error::AttestationCacheLockTimeout)?
                .contains(&shuffling_id);

            if !shuffling_is_cached {
                state.build_committee_cache(relative_epoch, &self.spec)?;
                let committee_cache = state.committee_cache(relative_epoch)?;
                self.shuffling_cache
                    .try_write_for(ATTESTATION_CACHE_LOCK_TIMEOUT)
                    .ok_or(Error::AttestationCacheLockTimeout)?
                    .insert_committee_cache(shuffling_id, committee_cache);
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn import_block_update_deposit_contract_finalization(
        &self,
        block: BeaconBlockRef<T::EthSpec>,
        block_root: Hash256,
        current_epoch: Epoch,
        current_finalized_checkpoint: Checkpoint,
        current_eth1_finalization_data: Eth1FinalizationData,
        parent_eth1_finalization_data: Eth1FinalizationData,
        parent_block_slot: Slot,
    ) {
        // Do not write to eth1 finalization cache for blocks older than 5 epochs.
        if block.slot().epoch(T::EthSpec::slots_per_epoch()) + 5 < current_epoch {
            return;
        }

        let parent_block_epoch = parent_block_slot.epoch(T::EthSpec::slots_per_epoch());
        if parent_block_epoch < current_epoch {
            // we've crossed epoch boundary, store Eth1FinalizationData
            let (checkpoint, eth1_finalization_data) =
                if block.slot() % T::EthSpec::slots_per_epoch() == 0 {
                    // current block is the checkpoint
                    (
                        Checkpoint {
                            epoch: current_epoch,
                            root: block_root,
                        },
                        current_eth1_finalization_data,
                    )
                } else {
                    // parent block is the checkpoint
                    (
                        Checkpoint {
                            epoch: current_epoch,
                            root: block.parent_root(),
                        },
                        parent_eth1_finalization_data,
                    )
                };

            if let Some(finalized_eth1_data) = self
                .eth1_finalization_cache
                .try_write_for(ETH1_FINALIZATION_CACHE_LOCK_TIMEOUT)
                .and_then(|mut cache| {
                    cache.insert(checkpoint, eth1_finalization_data);
                    cache.finalize(&current_finalized_checkpoint)
                })
            {
                if let Some(eth1_chain) = self.eth1_chain.as_ref() {
                    let finalized_deposit_count = finalized_eth1_data.deposit_count;
                    eth1_chain.finalize_eth1_data(finalized_eth1_data);
                    debug!(
                        self.log,
                        "called eth1_chain.finalize_eth1_data()";
                        "epoch" => current_finalized_checkpoint.epoch,
                        "deposit count" => finalized_deposit_count,
                    );
                }
            }
        }
    }

    /// If configured, wait for the fork choice run at the start of the slot to complete.
    fn wait_for_fork_choice_before_block_production(
        self: &Arc<Self>,
        slot: Slot,
    ) -> Result<(), BlockProductionError> {
        if let Some(rx) = &self.fork_choice_signal_rx {
            let current_slot = self
                .slot()
                .map_err(|_| BlockProductionError::UnableToReadSlot)?;

            let timeout = Duration::from_millis(self.config.fork_choice_before_proposal_timeout_ms);

            if slot == current_slot || slot == current_slot + 1 {
                match rx.wait_for_fork_choice(slot, timeout) {
                    ForkChoiceWaitResult::Success(fc_slot) => {
                        debug!(
                            self.log,
                            "Fork choice successfully updated before block production";
                            "slot" => slot,
                            "fork_choice_slot" => fc_slot,
                        );
                    }
                    ForkChoiceWaitResult::Behind(fc_slot) => {
                        warn!(
                            self.log,
                            "Fork choice notifier out of sync with block production";
                            "fork_choice_slot" => fc_slot,
                            "slot" => slot,
                            "message" => "this block may be orphaned",
                        );
                    }
                    ForkChoiceWaitResult::TimeOut => {
                        warn!(
                            self.log,
                            "Timed out waiting for fork choice before proposal";
                            "message" => "this block may be orphaned",
                        );
                    }
                }
            } else {
                error!(
                    self.log,
                    "Producing block at incorrect slot";
                    "block_slot" => slot,
                    "current_slot" => current_slot,
                    "message" => "check clock sync, this block may be orphaned",
                );
            }
        }
        Ok(())
    }

    /// Produce a new block at the given `slot`.
    ///
    /// The produced block will not be inherently valid, it must be signed by a block producer.
    /// Block signing is out of the scope of this function and should be done by a separate program.
    pub async fn produce_block<Payload: AbstractExecPayload<T::EthSpec> + 'static>(
        self: &Arc<Self>,
        randao_reveal: Signature,
        slot: Slot,
        validator_graffiti: Option<Graffiti>,
    ) -> Result<BeaconBlockAndState<T::EthSpec, Payload>, BlockProductionError> {
        self.produce_block_with_verification(
            randao_reveal,
            slot,
            validator_graffiti,
            ProduceBlockVerification::VerifyRandao,
        )
        .await
    }

    /// Same as `produce_block` but allowing for configuration of RANDAO-verification.
    pub async fn produce_block_with_verification<
        Payload: AbstractExecPayload<T::EthSpec> + 'static,
    >(
        self: &Arc<Self>,
        randao_reveal: Signature,
        slot: Slot,
        validator_graffiti: Option<Graffiti>,
        verification: ProduceBlockVerification,
    ) -> Result<BeaconBlockAndState<T::EthSpec, Payload>, BlockProductionError> {
        // Part 1/2 (blocking)
        //
        // Load the parent state from disk.
        let chain = self.clone();
        let (state, state_root_opt) = self
            .task_executor
            .spawn_blocking_handle(
                move || chain.load_state_for_block_production(slot),
                "produce_partial_beacon_block",
            )
            .ok_or(BlockProductionError::ShuttingDown)?
            .await
            .map_err(BlockProductionError::TokioJoin)??;

        // Part 2/2 (async, with some blocking components)
        //
        // Produce the block upon the state
        self.produce_block_on_state::<Payload>(
            state,
            state_root_opt,
            slot,
            randao_reveal,
            validator_graffiti,
            verification,
        )
        .await
    }

    /// Load a beacon state from the database for block production. This is a long-running process
    /// that should not be performed in an `async` context.
    fn load_state_for_block_production(
        self: &Arc<Self>,
        slot: Slot,
    ) -> Result<(BeaconState<T::EthSpec>, Option<Hash256>), BlockProductionError> {
        metrics::inc_counter(&metrics::BLOCK_PRODUCTION_REQUESTS);
        let _complete_timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_TIMES);

        let fork_choice_timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_FORK_CHOICE_TIMES);
        self.wait_for_fork_choice_before_block_production(slot)?;
        drop(fork_choice_timer);

        // Producing a block requires the tree hash cache, so clone a full state corresponding to
        // the head from the snapshot cache. Unfortunately we can't move the snapshot out of the
        // cache (which would be fast), because we need to re-process the block after it has been
        // signed. If we miss the cache or we're producing a block that conflicts with the head,
        // fall back to getting the head from `slot - 1`.
        let state_load_timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_STATE_LOAD_TIMES);

        // Atomically read some values from the head whilst avoiding holding cached head `Arc` any
        // longer than necessary.
        let (head_slot, head_block_root) = {
            let head = self.canonical_head.cached_head();
            (head.head_slot(), head.head_block_root())
        };
        let (state, state_root_opt) = if head_slot < slot {
            // Attempt an aggressive re-org if configured and the conditions are right.
            if let Some(re_org_state) = self.get_state_for_re_org(slot, head_slot, head_block_root)
            {
                info!(
                    self.log,
                    "Proposing block to re-org current head";
                    "slot" => slot,
                    "head_to_reorg" => %head_block_root,
                );
                (re_org_state.pre_state, re_org_state.state_root)
            }
            // Normal case: proposing a block atop the current head. Use the snapshot cache.
            else if let Some(pre_state) = self
                .snapshot_cache
                .try_read_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
                .and_then(|snapshot_cache| {
                    snapshot_cache.get_state_for_block_production(head_block_root)
                })
            {
                (pre_state.pre_state, pre_state.state_root)
            } else {
                warn!(
                    self.log,
                    "Block production cache miss";
                    "message" => "this block is more likely to be orphaned",
                    "slot" => slot,
                );
                let state = self
                    .state_at_slot(slot - 1, StateSkipConfig::WithStateRoots)
                    .map_err(|_| BlockProductionError::UnableToProduceAtSlot(slot))?;

                (state, None)
            }
        } else {
            warn!(
                self.log,
                "Producing block that conflicts with head";
                "message" => "this block is more likely to be orphaned",
                "slot" => slot,
            );
            let state = self
                .state_at_slot(slot - 1, StateSkipConfig::WithStateRoots)
                .map_err(|_| BlockProductionError::UnableToProduceAtSlot(slot))?;

            (state, None)
        };

        drop(state_load_timer);

        Ok((state, state_root_opt))
    }

    /// Fetch the beacon state to use for producing a block if a 1-slot proposer re-org is viable.
    ///
    /// This function will return `None` if proposer re-orgs are disabled.
    fn get_state_for_re_org(
        &self,
        slot: Slot,
        head_slot: Slot,
        canonical_head: Hash256,
    ) -> Option<BlockProductionPreState<T::EthSpec>> {
        let re_org_threshold = self.config.re_org_threshold?;

        if self.spec.proposer_score_boost.is_none() {
            warn!(
                self.log,
                "Ignoring proposer re-org configuration";
                "reason" => "this network does not have proposer boost enabled"
            );
            return None;
        }

        let slot_delay = self
            .slot_clock
            .seconds_from_current_slot_start()
            .or_else(|| {
                warn!(
                    self.log,
                    "Not attempting re-org";
                    "error" => "unable to read slot clock"
                );
                None
            })?;

        // Attempt a proposer re-org if:
        //
        // 1. It seems we have time to propagate and still receive the proposer boost.
        // 2. The current head block was seen late.
        // 3. The `get_proposer_head` conditions from fork choice pass.
        let proposing_on_time = slot_delay < self.config.re_org_cutoff(self.spec.seconds_per_slot);
        if !proposing_on_time {
            debug!(
                self.log,
                "Not attempting re-org";
                "reason" => "not proposing on time",
            );
            return None;
        }

        let head_late = self.block_observed_after_attestation_deadline(canonical_head, head_slot);
        if !head_late {
            debug!(
                self.log,
                "Not attempting re-org";
                "reason" => "head not late"
            );
            return None;
        }

        // Is the current head weak and appropriate for re-orging?
        let proposer_head_timer =
            metrics::start_timer(&metrics::BLOCK_PRODUCTION_GET_PROPOSER_HEAD_TIMES);
        let proposer_head = self
            .canonical_head
            .fork_choice_read_lock()
            .get_proposer_head(
                slot,
                canonical_head,
                re_org_threshold,
                &self.config.re_org_disallowed_offsets,
                self.config.re_org_max_epochs_since_finalization,
            )
            .map_err(|e| match e {
                ProposerHeadError::DoNotReOrg(reason) => {
                    debug!(
                        self.log,
                        "Not attempting re-org";
                        "reason" => %reason,
                    );
                }
                ProposerHeadError::Error(e) => {
                    warn!(
                        self.log,
                        "Not attempting re-org";
                        "error" => ?e,
                    );
                }
            })
            .ok()?;
        drop(proposer_head_timer);
        let re_org_parent_block = proposer_head.parent_node.root;

        // Only attempt a re-org if we hit the snapshot cache.
        let pre_state = self
            .snapshot_cache
            .try_read_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
            .and_then(|snapshot_cache| {
                snapshot_cache.get_state_for_block_production(re_org_parent_block)
            })
            .or_else(|| {
                debug!(
                    self.log,
                    "Not attempting re-org";
                    "reason" => "missed snapshot cache",
                    "parent_block" => ?re_org_parent_block,
                );
                None
            })?;

        info!(
            self.log,
            "Attempting re-org due to weak head";
            "weak_head" => ?canonical_head,
            "parent" => ?re_org_parent_block,
            "head_weight" => proposer_head.head_node.weight,
            "threshold_weight" => proposer_head.re_org_weight_threshold
        );

        Some(pre_state)
    }

    /// Get the proposer index and `prev_randao` value for a proposal at slot `proposal_slot`.
    ///
    /// The `proposer_head` may be the head block of `cached_head` or its parent. An error will
    /// be returned for any other value.
    pub fn get_pre_payload_attributes(
        &self,
        proposal_slot: Slot,
        proposer_head: Hash256,
        cached_head: &CachedHead<T::EthSpec>,
    ) -> Result<Option<PrePayloadAttributes>, Error> {
        let proposal_epoch = proposal_slot.epoch(T::EthSpec::slots_per_epoch());

        let head_block_root = cached_head.head_block_root();
        let parent_block_root = cached_head.parent_block_root();

        // The proposer head must be equal to the canonical head or its parent.
        if proposer_head != head_block_root && proposer_head != parent_block_root {
            warn!(
                self.log,
                "Unable to compute payload attributes";
                "block_root" => ?proposer_head,
                "head_block_root" => ?head_block_root,
            );
            return Ok(None);
        }

        // Compute the proposer index.
        let head_epoch = cached_head.head_slot().epoch(T::EthSpec::slots_per_epoch());
        let shuffling_decision_root = if head_epoch == proposal_epoch {
            cached_head
                .snapshot
                .beacon_state
                .proposer_shuffling_decision_root(proposer_head)?
        } else {
            proposer_head
        };
        let cached_proposer = self
            .beacon_proposer_cache
            .lock()
            .get_slot::<T::EthSpec>(shuffling_decision_root, proposal_slot);
        let proposer_index = if let Some(proposer) = cached_proposer {
            proposer.index as u64
        } else {
            if head_epoch + 2 < proposal_epoch {
                warn!(
                    self.log,
                    "Skipping proposer preparation";
                    "msg" => "this is a non-critical issue that can happen on unhealthy nodes or \
                              networks.",
                    "proposal_epoch" => proposal_epoch,
                    "head_epoch" => head_epoch,
                );

                // Don't skip the head forward more than two epochs. This avoids burdening an
                // unhealthy node.
                //
                // Although this node might miss out on preparing for a proposal, they should still
                // be able to propose. This will prioritise beacon chain health over efficient
                // packing of execution blocks.
                return Ok(None);
            }

            let (proposers, decision_root, _, fork) =
                compute_proposer_duties_from_head(proposal_epoch, self)?;

            let proposer_offset = (proposal_slot % T::EthSpec::slots_per_epoch()).as_usize();
            let proposer = *proposers
                .get(proposer_offset)
                .ok_or(BeaconChainError::NoProposerForSlot(proposal_slot))?;

            self.beacon_proposer_cache.lock().insert(
                proposal_epoch,
                decision_root,
                proposers,
                fork,
            )?;

            // It's possible that the head changes whilst computing these duties. If so, abandon
            // this routine since the change of head would have also spawned another instance of
            // this routine.
            //
            // Exit now, after updating the cache.
            if decision_root != shuffling_decision_root {
                warn!(
                    self.log,
                    "Head changed during proposer preparation";
                );
                return Ok(None);
            }

            proposer as u64
        };

        // Get the `prev_randao` and parent block number.
        let head_block_number = cached_head.head_block_number()?;
        let (prev_randao, parent_block_number) = if proposer_head == parent_block_root {
            (
                cached_head.parent_random()?,
                head_block_number.saturating_sub(1),
            )
        } else {
            (cached_head.head_random()?, head_block_number)
        };

        Ok(Some(PrePayloadAttributes {
            proposer_index,
            prev_randao,
            parent_block_number,
        }))
    }

    pub fn get_expected_withdrawals(
        &self,
        forkchoice_update_params: &ForkchoiceUpdateParameters,
        proposal_slot: Slot,
    ) -> Result<Withdrawals<T::EthSpec>, Error> {
        let cached_head = self.canonical_head.cached_head();
        let head_state = &cached_head.snapshot.beacon_state;

        let parent_block_root = forkchoice_update_params.head_root;

        let (unadvanced_state, unadvanced_state_root) =
            if cached_head.head_block_root() == parent_block_root {
                (Cow::Borrowed(head_state), cached_head.head_state_root())
            } else if let Some(snapshot) = self
                .snapshot_cache
                .try_read_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
                .ok_or(Error::SnapshotCacheLockTimeout)?
                .get_cloned(parent_block_root, CloneConfig::none())
            {
                debug!(
                    self.log,
                    "Hit snapshot cache during withdrawals calculation";
                    "slot" => proposal_slot,
                    "parent_block_root" => ?parent_block_root,
                );
                let state_root = snapshot.beacon_state_root();
                (Cow::Owned(snapshot.beacon_state), state_root)
            } else {
                info!(
                    self.log,
                    "Missed snapshot cache during withdrawals calculation";
                    "slot" => proposal_slot,
                    "parent_block_root" => ?parent_block_root
                );
                let block = self
                    .get_blinded_block(&parent_block_root)?
                    .ok_or(Error::MissingBeaconBlock(parent_block_root))?;
                let state = self
                    .get_state(&block.state_root(), Some(block.slot()))?
                    .ok_or(Error::MissingBeaconState(block.state_root()))?;
                (Cow::Owned(state), block.state_root())
            };

        // Parent state epoch is the same as the proposal, we don't need to advance because the
        // list of expected withdrawals can only change after an epoch advance or a
        // block application.
        let proposal_epoch = proposal_slot.epoch(T::EthSpec::slots_per_epoch());
        if head_state.current_epoch() == proposal_epoch {
            return get_expected_withdrawals(&unadvanced_state, &self.spec)
                .map_err(Error::PrepareProposerFailed);
        }

        // Advance the state using the partial method.
        debug!(
            self.log,
            "Advancing state for withdrawals calculation";
            "proposal_slot" => proposal_slot,
            "parent_block_root" => ?parent_block_root,
        );
        let mut advanced_state = unadvanced_state.into_owned();
        partial_state_advance(
            &mut advanced_state,
            Some(unadvanced_state_root),
            proposal_epoch.start_slot(T::EthSpec::slots_per_epoch()),
            &self.spec,
        )?;
        get_expected_withdrawals(&advanced_state, &self.spec).map_err(Error::PrepareProposerFailed)
    }

    /// Determine whether a fork choice update to the execution layer should be overridden.
    ///
    /// This is *only* necessary when proposer re-orgs are enabled, because we have to prevent the
    /// execution layer from enshrining the block we want to re-org as the head.
    ///
    /// This function uses heuristics that align quite closely but not exactly with the re-org
    /// conditions set out in `get_state_for_re_org` and `get_proposer_head`. The differences are
    /// documented below.
    fn overridden_forkchoice_update_params(
        &self,
        canonical_forkchoice_params: ForkchoiceUpdateParameters,
    ) -> Result<ForkchoiceUpdateParameters, Error> {
        self.overridden_forkchoice_update_params_or_failure_reason(&canonical_forkchoice_params)
            .or_else(|e| match e {
                ProposerHeadError::DoNotReOrg(reason) => {
                    trace!(
                        self.log,
                        "Not suppressing fork choice update";
                        "reason" => %reason,
                    );
                    Ok(canonical_forkchoice_params)
                }
                ProposerHeadError::Error(e) => Err(e),
            })
    }

    fn overridden_forkchoice_update_params_or_failure_reason(
        &self,
        canonical_forkchoice_params: &ForkchoiceUpdateParameters,
    ) -> Result<ForkchoiceUpdateParameters, ProposerHeadError<Error>> {
        let _timer = metrics::start_timer(&metrics::FORK_CHOICE_OVERRIDE_FCU_TIMES);

        // Never override if proposer re-orgs are disabled.
        let re_org_threshold = self
            .config
            .re_org_threshold
            .ok_or(DoNotReOrg::ReOrgsDisabled)?;

        let head_block_root = canonical_forkchoice_params.head_root;

        // Perform initial checks and load the relevant info from fork choice.
        let info = self
            .canonical_head
            .fork_choice_read_lock()
            .get_preliminary_proposer_head(
                head_block_root,
                re_org_threshold,
                &self.config.re_org_disallowed_offsets,
                self.config.re_org_max_epochs_since_finalization,
            )
            .map_err(|e| e.map_inner_error(Error::ProposerHeadForkChoiceError))?;

        // The slot of our potential re-org block is always 1 greater than the head block because we
        // only attempt single-slot re-orgs.
        let head_slot = info.head_node.slot;
        let re_org_block_slot = head_slot + 1;
        let fork_choice_slot = info.current_slot;

        // If a re-orging proposal isn't made by the `re_org_cutoff` then we give up
        // and allow the fork choice update for the canonical head through so that we may attest
        // correctly.
        let current_slot_ok = if head_slot == fork_choice_slot {
            true
        } else if re_org_block_slot == fork_choice_slot {
            self.slot_clock
                .start_of(re_org_block_slot)
                .and_then(|slot_start| {
                    let now = self.slot_clock.now_duration()?;
                    let slot_delay = now.saturating_sub(slot_start);
                    Some(slot_delay <= self.config.re_org_cutoff(self.spec.seconds_per_slot))
                })
                .unwrap_or(false)
        } else {
            false
        };
        if !current_slot_ok {
            return Err(DoNotReOrg::HeadDistance.into());
        }

        // Only attempt a re-org if we have a proposer registered for the re-org slot.
        let proposing_at_re_org_slot = {
            // The proposer shuffling has the same decision root as the next epoch attestation
            // shuffling. We know our re-org block is not on the epoch boundary, so it has the
            // same proposer shuffling as the head (but not necessarily the parent which may lie
            // in the previous epoch).
            let shuffling_decision_root = info
                .head_node
                .next_epoch_shuffling_id
                .shuffling_decision_block;
            let proposer_index = self
                .beacon_proposer_cache
                .lock()
                .get_slot::<T::EthSpec>(shuffling_decision_root, re_org_block_slot)
                .ok_or_else(|| {
                    debug!(
                        self.log,
                        "Fork choice override proposer shuffling miss";
                        "slot" => re_org_block_slot,
                        "decision_root" => ?shuffling_decision_root,
                    );
                    DoNotReOrg::NotProposing
                })?
                .index as u64;

            self.execution_layer
                .as_ref()
                .ok_or(ProposerHeadError::Error(Error::ExecutionLayerMissing))?
                .has_proposer_preparation_data_blocking(proposer_index)
        };
        if !proposing_at_re_org_slot {
            return Err(DoNotReOrg::NotProposing.into());
        }

        // If the current slot is already equal to the proposal slot (or we are in the tail end of
        // the prior slot), then check the actual weight of the head against the re-org threshold.
        let head_weak = if fork_choice_slot == re_org_block_slot {
            info.head_node.weight < info.re_org_weight_threshold
        } else {
            true
        };
        if !head_weak {
            return Err(DoNotReOrg::HeadNotWeak {
                head_weight: info.head_node.weight,
                re_org_weight_threshold: info.re_org_weight_threshold,
            }
            .into());
        }

        // Check that the head block arrived late and is vulnerable to a re-org. This check is only
        // a heuristic compared to the proper weight check in `get_state_for_re_org`, the reason
        // being that we may have only *just* received the block and not yet processed any
        // attestations for it. We also can't dequeue attestations for the block during the
        // current slot, which would be necessary for determining its weight.
        let head_block_late =
            self.block_observed_after_attestation_deadline(head_block_root, head_slot);
        if !head_block_late {
            return Err(DoNotReOrg::HeadNotLate.into());
        }

        let parent_head_hash = info.parent_node.execution_status.block_hash();
        let forkchoice_update_params = ForkchoiceUpdateParameters {
            head_root: info.parent_node.root,
            head_hash: parent_head_hash,
            justified_hash: canonical_forkchoice_params.justified_hash,
            finalized_hash: canonical_forkchoice_params.finalized_hash,
        };

        debug!(
            self.log,
            "Fork choice update overridden";
            "canonical_head" => ?head_block_root,
            "override" => ?info.parent_node.root,
            "slot" => fork_choice_slot,
        );

        Ok(forkchoice_update_params)
    }

    /// Check if the block with `block_root` was observed after the attestation deadline of `slot`.
    fn block_observed_after_attestation_deadline(&self, block_root: Hash256, slot: Slot) -> bool {
        let block_delays = self.block_times_cache.read().get_block_delays(
            block_root,
            self.slot_clock
                .start_of(slot)
                .unwrap_or_else(|| Duration::from_secs(0)),
        );
        block_delays.observed.map_or(false, |delay| {
            delay > self.slot_clock.unagg_attestation_production_delay()
        })
    }

    /// Produce a block for some `slot` upon the given `state`.
    ///
    /// Typically the `self.produce_block()` function should be used, instead of calling this
    /// function directly. This function is useful for purposefully creating forks or blocks at
    /// non-current slots.
    ///
    /// If required, the given state will be advanced to the given `produce_at_slot`, then a block
    /// will be produced at that slot height.
    ///
    /// The provided `state_root_opt` should only ever be set to `Some` if the contained value is
    /// equal to the root of `state`. Providing this value will serve as an optimization to avoid
    /// performing a tree hash in some scenarios.
    pub async fn produce_block_on_state<Payload: AbstractExecPayload<T::EthSpec> + 'static>(
        self: &Arc<Self>,
        state: BeaconState<T::EthSpec>,
        state_root_opt: Option<Hash256>,
        produce_at_slot: Slot,
        randao_reveal: Signature,
        validator_graffiti: Option<Graffiti>,
        verification: ProduceBlockVerification,
    ) -> Result<BeaconBlockAndState<T::EthSpec, Payload>, BlockProductionError> {
        // Part 1/3 (blocking)
        //
        // Perform the state advance and block-packing functions.
        let chain = self.clone();
        let mut partial_beacon_block = self
            .task_executor
            .spawn_blocking_handle(
                move || {
                    chain.produce_partial_beacon_block(
                        state,
                        state_root_opt,
                        produce_at_slot,
                        randao_reveal,
                        validator_graffiti,
                    )
                },
                "produce_partial_beacon_block",
            )
            .ok_or(BlockProductionError::ShuttingDown)?
            .await
            .map_err(BlockProductionError::TokioJoin)??;

        // Part 2/3 (async)
        //
        // Wait for the execution layer to return an execution payload (if one is required).
        let prepare_payload_handle = partial_beacon_block.prepare_payload_handle.take();
        let block_contents = if let Some(prepare_payload_handle) = prepare_payload_handle {
            Some(
                prepare_payload_handle
                    .await
                    .map_err(BlockProductionError::TokioJoin)?
                    .ok_or(BlockProductionError::ShuttingDown)??,
            )
        } else {
            None
        };

        // Part 3/3 (blocking)
        //
        // Perform the final steps of combining all the parts and computing the state root.
        let chain = self.clone();
        self.task_executor
            .spawn_blocking_handle(
                move || {
                    chain.complete_partial_beacon_block(
                        partial_beacon_block,
                        block_contents,
                        verification,
                    )
                },
                "complete_partial_beacon_block",
            )
            .ok_or(BlockProductionError::ShuttingDown)?
            .await
            .map_err(BlockProductionError::TokioJoin)?
    }

    fn produce_partial_beacon_block<Payload: AbstractExecPayload<T::EthSpec> + 'static>(
        self: &Arc<Self>,
        mut state: BeaconState<T::EthSpec>,
        state_root_opt: Option<Hash256>,
        produce_at_slot: Slot,
        randao_reveal: Signature,
        validator_graffiti: Option<Graffiti>,
    ) -> Result<PartialBeaconBlock<T::EthSpec, Payload>, BlockProductionError> {
        let eth1_chain = self
            .eth1_chain
            .as_ref()
            .ok_or(BlockProductionError::NoEth1ChainConnection)?;

        // It is invalid to try to produce a block using a state from a future slot.
        if state.slot() > produce_at_slot {
            return Err(BlockProductionError::StateSlotTooHigh {
                produce_at_slot,
                state_slot: state.slot(),
            });
        }

        let slot_timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_SLOT_PROCESS_TIMES);

        // Ensure the state has performed a complete transition into the required slot.
        complete_state_advance(&mut state, state_root_opt, produce_at_slot, &self.spec)?;

        drop(slot_timer);

        state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;

        let parent_root = if state.slot() > 0 {
            *state
                .get_block_root(state.slot() - 1)
                .map_err(|_| BlockProductionError::UnableToGetBlockRootFromState)?
        } else {
            state.latest_block_header().canonical_root()
        };

        let proposer_index = state.get_beacon_proposer_index(state.slot(), &self.spec)? as u64;

        let pubkey = state
            .validators()
            .get(proposer_index as usize)
            .map(|v| v.pubkey)
            .ok_or(BlockProductionError::BeaconChain(
                BeaconChainError::ValidatorIndexUnknown(proposer_index as usize),
            ))?;

        let builder_params = BuilderParams {
            pubkey,
            slot: state.slot(),
            chain_health: self
                .is_healthy(&parent_root)
                .map_err(BlockProductionError::BeaconChain)?,
        };

        // If required, start the process of loading an execution payload from the EL early. This
        // allows it to run concurrently with things like attestation packing.
        let prepare_payload_handle = match &state {
            BeaconState::Base(_) | BeaconState::Altair(_) => None,
            BeaconState::Merge(_) | BeaconState::Capella(_) => {
                let prepare_payload_handle =
                    get_execution_payload(self.clone(), &state, proposer_index, builder_params)?;
                Some(prepare_payload_handle)
            }
        };

        let (mut proposer_slashings, mut attester_slashings, mut voluntary_exits) =
            self.op_pool.get_slashings_and_exits(&state, &self.spec);

        let eth1_data = eth1_chain.eth1_data_for_block_production(&state, &self.spec)?;
        let deposits = eth1_chain.deposits_for_block_inclusion(&state, &eth1_data, &self.spec)?;

        let bls_to_execution_changes = self
            .op_pool
            .get_bls_to_execution_changes(&state, &self.spec);

        // Iterate through the naive aggregation pool and ensure all the attestations from there
        // are included in the operation pool.
        let unagg_import_timer =
            metrics::start_timer(&metrics::BLOCK_PRODUCTION_UNAGGREGATED_TIMES);
        for attestation in self.naive_aggregation_pool.read().iter() {
            let import = |attestation: &Attestation<T::EthSpec>| {
                let attesting_indices = get_attesting_indices_from_state(&state, attestation)?;
                self.op_pool
                    .insert_attestation(attestation.clone(), attesting_indices)
            };
            if let Err(e) = import(attestation) {
                // Don't stop block production if there's an error, just create a log.
                error!(
                    self.log,
                    "Attestation did not transfer to op pool";
                    "reason" => ?e
                );
            }
        }
        drop(unagg_import_timer);

        // Override the beacon node's graffiti with graffiti from the validator, if present.
        let graffiti = match validator_graffiti {
            Some(graffiti) => graffiti,
            None => self.graffiti,
        };

        let attestation_packing_timer =
            metrics::start_timer(&metrics::BLOCK_PRODUCTION_ATTESTATION_TIMES);

        let mut prev_filter_cache = HashMap::new();
        let prev_attestation_filter = |att: &AttestationRef<T::EthSpec>| {
            self.filter_op_pool_attestation(&mut prev_filter_cache, att, &state)
        };
        let mut curr_filter_cache = HashMap::new();
        let curr_attestation_filter = |att: &AttestationRef<T::EthSpec>| {
            self.filter_op_pool_attestation(&mut curr_filter_cache, att, &state)
        };

        let mut attestations = self
            .op_pool
            .get_attestations(
                &state,
                prev_attestation_filter,
                curr_attestation_filter,
                &self.spec,
            )
            .map_err(BlockProductionError::OpPoolError)?;
        drop(attestation_packing_timer);

        // If paranoid mode is enabled re-check the signatures of every included message.
        // This will be a lot slower but guards against bugs in block production and can be
        // quickly rolled out without a release.
        if self.config.paranoid_block_proposal {
            let mut tmp_ctxt = ConsensusContext::new(state.slot());
            attestations.retain(|att| {
                verify_attestation_for_block_inclusion(
                    &state,
                    att,
                    &mut tmp_ctxt,
                    VerifySignatures::True,
                    &self.spec,
                )
                .map_err(|e| {
                    warn!(
                        self.log,
                        "Attempted to include an invalid attestation";
                        "err" => ?e,
                        "block_slot" => state.slot(),
                        "attestation" => ?att
                    );
                })
                .is_ok()
            });

            proposer_slashings.retain(|slashing| {
                slashing
                    .clone()
                    .validate(&state, &self.spec)
                    .map_err(|e| {
                        warn!(
                            self.log,
                            "Attempted to include an invalid proposer slashing";
                            "err" => ?e,
                            "block_slot" => state.slot(),
                            "slashing" => ?slashing
                        );
                    })
                    .is_ok()
            });

            attester_slashings.retain(|slashing| {
                slashing
                    .clone()
                    .validate(&state, &self.spec)
                    .map_err(|e| {
                        warn!(
                            self.log,
                            "Attempted to include an invalid attester slashing";
                            "err" => ?e,
                            "block_slot" => state.slot(),
                            "slashing" => ?slashing
                        );
                    })
                    .is_ok()
            });

            voluntary_exits.retain(|exit| {
                exit.clone()
                    .validate(&state, &self.spec)
                    .map_err(|e| {
                        warn!(
                            self.log,
                            "Attempted to include an invalid proposer slashing";
                            "err" => ?e,
                            "block_slot" => state.slot(),
                            "exit" => ?exit
                        );
                    })
                    .is_ok()
            });
        }

        let slot = state.slot();

        let sync_aggregate = if matches!(&state, BeaconState::Base(_)) {
            None
        } else {
            let sync_aggregate = self
                .op_pool
                .get_sync_aggregate(&state)
                .map_err(BlockProductionError::OpPoolError)?
                .unwrap_or_else(|| {
                    warn!(
                        self.log,
                        "Producing block with no sync contributions";
                        "slot" => state.slot(),
                    );
                    SyncAggregate::new()
                });
            Some(sync_aggregate)
        };

        Ok(PartialBeaconBlock {
            state,
            slot,
            proposer_index,
            parent_root,
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            prepare_payload_handle,
            bls_to_execution_changes,
        })
    }

    fn complete_partial_beacon_block<Payload: AbstractExecPayload<T::EthSpec>>(
        &self,
        partial_beacon_block: PartialBeaconBlock<T::EthSpec, Payload>,
        block_contents: Option<BlockProposalContents<T::EthSpec, Payload>>,
        verification: ProduceBlockVerification,
    ) -> Result<BeaconBlockAndState<T::EthSpec, Payload>, BlockProductionError> {
        let PartialBeaconBlock {
            mut state,
            slot,
            proposer_index,
            parent_root,
            randao_reveal,
            eth1_data,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_aggregate,
            // We don't need the prepare payload handle since the `execution_payload` is passed into
            // this function. We can assume that the handle has already been consumed in order to
            // produce said `execution_payload`.
            prepare_payload_handle: _,
            bls_to_execution_changes,
        } = partial_beacon_block;

        let inner_block = match &state {
            BeaconState::Base(_) => BeaconBlock::Base(BeaconBlockBase {
                slot,
                proposer_index,
                parent_root,
                state_root: Hash256::zero(),
                body: BeaconBlockBodyBase {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings: proposer_slashings.into(),
                    attester_slashings: attester_slashings.into(),
                    attestations: attestations.into(),
                    deposits: deposits.into(),
                    voluntary_exits: voluntary_exits.into(),
                    _phantom: PhantomData,
                },
            }),
            BeaconState::Altair(_) => BeaconBlock::Altair(BeaconBlockAltair {
                slot,
                proposer_index,
                parent_root,
                state_root: Hash256::zero(),
                body: BeaconBlockBodyAltair {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings: proposer_slashings.into(),
                    attester_slashings: attester_slashings.into(),
                    attestations: attestations.into(),
                    deposits: deposits.into(),
                    voluntary_exits: voluntary_exits.into(),
                    sync_aggregate: sync_aggregate
                        .ok_or(BlockProductionError::MissingSyncAggregate)?,
                    _phantom: PhantomData,
                },
            }),
            BeaconState::Merge(_) => BeaconBlock::Merge(BeaconBlockMerge {
                slot,
                proposer_index,
                parent_root,
                state_root: Hash256::zero(),
                body: BeaconBlockBodyMerge {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings: proposer_slashings.into(),
                    attester_slashings: attester_slashings.into(),
                    attestations: attestations.into(),
                    deposits: deposits.into(),
                    voluntary_exits: voluntary_exits.into(),
                    sync_aggregate: sync_aggregate
                        .ok_or(BlockProductionError::MissingSyncAggregate)?,
                    execution_payload: block_contents
                        .ok_or(BlockProductionError::MissingExecutionPayload)?
                        .to_payload()
                        .try_into()
                        .map_err(|_| BlockProductionError::InvalidPayloadFork)?,
                },
            }),
            BeaconState::Capella(_) => BeaconBlock::Capella(BeaconBlockCapella {
                slot,
                proposer_index,
                parent_root,
                state_root: Hash256::zero(),
                body: BeaconBlockBodyCapella {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings: proposer_slashings.into(),
                    attester_slashings: attester_slashings.into(),
                    attestations: attestations.into(),
                    deposits: deposits.into(),
                    voluntary_exits: voluntary_exits.into(),
                    sync_aggregate: sync_aggregate
                        .ok_or(BlockProductionError::MissingSyncAggregate)?,
                    execution_payload: block_contents
                        .ok_or(BlockProductionError::MissingExecutionPayload)?
                        .to_payload()
                        .try_into()
                        .map_err(|_| BlockProductionError::InvalidPayloadFork)?,
                    bls_to_execution_changes: bls_to_execution_changes.into(),
                },
            }),
        };

        let block = SignedBeaconBlock::from_block(
            inner_block,
            // The block is not signed here, that is the task of a validator client.
            Signature::empty(),
        );

        let block_size = block.ssz_bytes_len();
        debug!(
            self.log,
            "Produced block on state";
            "block_size" => block_size,
            "slot" => block.slot(),
        );

        metrics::observe(&metrics::BLOCK_SIZE, block_size as f64);

        if block_size > self.config.max_network_size {
            return Err(BlockProductionError::BlockTooLarge(block_size));
        }

        let process_timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_PROCESS_TIMES);
        let signature_strategy = match verification {
            ProduceBlockVerification::VerifyRandao => BlockSignatureStrategy::VerifyRandao,
            ProduceBlockVerification::NoVerification => BlockSignatureStrategy::NoVerification,
        };
        // Use a context without block root or proposer index so that both are checked.
        let mut ctxt = ConsensusContext::new(block.slot());
        per_block_processing(
            &mut state,
            &block,
            signature_strategy,
            StateProcessingStrategy::Accurate,
            VerifyBlockRoot::True,
            &mut ctxt,
            &self.spec,
        )?;
        drop(process_timer);

        let state_root_timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_STATE_ROOT_TIMES);
        let state_root = state.update_tree_hash_cache()?;
        drop(state_root_timer);

        let (mut block, _) = block.deconstruct();
        *block.state_root_mut() = state_root;

        metrics::inc_counter(&metrics::BLOCK_PRODUCTION_SUCCESSES);

        trace!(
            self.log,
            "Produced beacon block";
            "parent" => ?block.parent_root(),
            "attestations" => block.body().attestations().len(),
            "slot" => block.slot()
        );

        Ok((block, state))
    }

    /// This method must be called whenever an execution engine indicates that a payload is
    /// invalid.
    ///
    /// Fork choice will be run after the invalidation. The client may be shut down if the `op`
    /// results in the justified checkpoint being invalidated.
    ///
    /// See the documentation of `InvalidationOperation` for information about defining `op`.
    pub async fn process_invalid_execution_payload(
        self: &Arc<Self>,
        op: &InvalidationOperation,
    ) -> Result<(), Error> {
        debug!(
            self.log,
            "Processing payload invalidation";
            "op" => ?op,
        );

        // Update the execution status in fork choice.
        //
        // Use a blocking task since it interacts with the `canonical_head` lock. Lock contention
        // on the core executor is bad.
        let chain = self.clone();
        let inner_op = op.clone();
        let fork_choice_result = self
            .spawn_blocking_handle(
                move || {
                    chain
                        .canonical_head
                        .fork_choice_write_lock()
                        .on_invalid_execution_payload(&inner_op)
                },
                "invalid_payload_fork_choice_update",
            )
            .await?;

        // Update fork choice.
        if let Err(e) = fork_choice_result {
            crit!(
                self.log,
                "Failed to process invalid payload";
                "error" => ?e,
                "latest_valid_ancestor" => ?op.latest_valid_ancestor(),
                "block_root" => ?op.block_root(),
            );
        }

        // Run fork choice since it's possible that the payload invalidation might result in a new
        // head.
        self.recompute_head_at_current_slot().await;

        // Obtain the justified root from fork choice.
        //
        // Use a blocking task since it interacts with the `canonical_head` lock. Lock contention
        // on the core executor is bad.
        let chain = self.clone();
        let justified_block = self
            .spawn_blocking_handle(
                move || {
                    chain
                        .canonical_head
                        .fork_choice_read_lock()
                        .get_justified_block()
                },
                "invalid_payload_fork_choice_get_justified",
            )
            .await??;

        if justified_block.execution_status.is_invalid() {
            crit!(
                self.log,
                "The justified checkpoint is invalid";
                "msg" => "ensure you are not connected to a malicious network. This error is not \
                recoverable, please reach out to the lighthouse developers for assistance."
            );

            let mut shutdown_sender = self.shutdown_sender();
            if let Err(e) = shutdown_sender.try_send(ShutdownReason::Failure(
                INVALID_JUSTIFIED_PAYLOAD_SHUTDOWN_REASON,
            )) {
                crit!(
                    self.log,
                    "Unable to trigger client shut down";
                    "msg" => "shut down may already be under way",
                    "error" => ?e
                );
            }

            // Return an error here to try and prevent progression by upstream functions.
            return Err(Error::JustifiedPayloadInvalid {
                justified_root: justified_block.root,
                execution_block_hash: justified_block.execution_status.block_hash(),
            });
        }

        Ok(())
    }

    pub fn block_is_known_to_fork_choice(&self, root: &Hash256) -> bool {
        self.canonical_head
            .fork_choice_read_lock()
            .contains_block(root)
    }

    /// Determines the beacon proposer for the next slot. If that proposer is registered in the
    /// `execution_layer`, provide the `execution_layer` with the necessary information to produce
    /// `PayloadAttributes` for future calls to fork choice.
    ///
    /// The `PayloadAttributes` are used by the EL to give it a look-ahead for preparing an optimal
    /// set of transactions for a new `ExecutionPayload`.
    ///
    /// This function will result in a call to `forkchoiceUpdated` on the EL if we're in the
    /// tail-end of the slot (as defined by `self.config.prepare_payload_lookahead`).
    pub async fn prepare_beacon_proposer(
        self: &Arc<Self>,
        current_slot: Slot,
    ) -> Result<(), Error> {
        let prepare_slot = current_slot + 1;

        // There's no need to run the proposer preparation routine before the bellatrix fork.
        if self.slot_is_prior_to_bellatrix(prepare_slot) {
            return Ok(());
        }

        let execution_layer = self
            .execution_layer
            .clone()
            .ok_or(Error::ExecutionLayerMissing)?;

        // Nothing to do if there are no proposers registered with the EL, exit early to avoid
        // wasting cycles.
        if !self.config.always_prepare_payload
            && !execution_layer.has_any_proposer_preparation_data().await
        {
            return Ok(());
        }

        // Load the cached head and its forkchoice update parameters.
        //
        // Use a blocking task since blocking the core executor on the canonical head read lock can
        // block the core tokio executor.
        let chain = self.clone();
        let maybe_prep_data = self
            .spawn_blocking_handle(
                move || {
                    let cached_head = chain.canonical_head.cached_head();

                    // Don't bother with proposer prep if the head is more than
                    // `PREPARE_PROPOSER_HISTORIC_EPOCHS` prior to the current slot.
                    //
                    // This prevents the routine from running during sync.
                    let head_slot = cached_head.head_slot();
                    if head_slot + T::EthSpec::slots_per_epoch() * PREPARE_PROPOSER_HISTORIC_EPOCHS
                        < current_slot
                    {
                        debug!(
                            chain.log,
                            "Head too old for proposer prep";
                            "head_slot" => head_slot,
                            "current_slot" => current_slot,
                        );
                        return Ok(None);
                    }

                    let canonical_fcu_params = cached_head.forkchoice_update_parameters();
                    let fcu_params =
                        chain.overridden_forkchoice_update_params(canonical_fcu_params)?;
                    let pre_payload_attributes = chain.get_pre_payload_attributes(
                        prepare_slot,
                        fcu_params.head_root,
                        &cached_head,
                    )?;
                    Ok::<_, Error>(Some((fcu_params, pre_payload_attributes)))
                },
                "prepare_beacon_proposer_head_read",
            )
            .await??;

        let (forkchoice_update_params, pre_payload_attributes) =
            if let Some((fcu, Some(pre_payload))) = maybe_prep_data {
                (fcu, pre_payload)
            } else {
                // Appropriate log messages have already been logged above and in
                // `get_pre_payload_attributes`.
                return Ok(());
            };

        // If the execution layer doesn't have any proposer data for this validator then we assume
        // it's not connected to this BN and no action is required.
        let proposer = pre_payload_attributes.proposer_index;
        if !self.config.always_prepare_payload
            && !execution_layer
                .has_proposer_preparation_data(proposer)
                .await
        {
            return Ok(());
        }

        // Fetch payoad attributes from the execution layer's cache, or compute them from scratch
        // if no matching entry is found. This saves recomputing the withdrawals which can take
        // considerable time to compute if a state load is required.
        let head_root = forkchoice_update_params.head_root;
        let payload_attributes = if let Some(payload_attributes) = execution_layer
            .payload_attributes(prepare_slot, head_root)
            .await
        {
            payload_attributes
        } else {
            let withdrawals = match self.spec.fork_name_at_slot::<T::EthSpec>(prepare_slot) {
                ForkName::Base | ForkName::Altair | ForkName::Merge => None,
                ForkName::Capella => {
                    let chain = self.clone();
                    self.spawn_blocking_handle(
                        move || {
                            chain.get_expected_withdrawals(&forkchoice_update_params, prepare_slot)
                        },
                        "prepare_beacon_proposer_withdrawals",
                    )
                    .await?
                    .map(Some)?
                }
            };

            let payload_attributes = PayloadAttributes::new(
                self.slot_clock
                    .start_of(prepare_slot)
                    .ok_or(Error::InvalidSlot(prepare_slot))?
                    .as_secs(),
                pre_payload_attributes.prev_randao,
                execution_layer.get_suggested_fee_recipient(proposer).await,
                withdrawals.map(Into::into),
            );

            execution_layer
                .insert_proposer(
                    prepare_slot,
                    head_root,
                    proposer,
                    payload_attributes.clone(),
                )
                .await;

            // Only push a log to the user if this is the first time we've seen this proposer for
            // this slot.
            info!(
                self.log,
                "Prepared beacon proposer";
                "prepare_slot" => prepare_slot,
                "validator" => proposer,
                "parent_root" => ?head_root,
            );
            payload_attributes
        };

        // Push a server-sent event (probably to a block builder or relay).
        if let Some(event_handler) = &self.event_handler {
            if event_handler.has_payload_attributes_subscribers() {
                event_handler.register(EventKind::PayloadAttributes(ForkVersionedResponse {
                    data: SseExtendedPayloadAttributes {
                        proposal_slot: prepare_slot,
                        proposer_index: proposer,
                        parent_block_root: head_root,
                        parent_block_number: pre_payload_attributes.parent_block_number,
                        parent_block_hash: forkchoice_update_params.head_hash.unwrap_or_default(),
                        payload_attributes: payload_attributes.into(),
                    },
                    version: Some(self.spec.fork_name_at_slot::<T::EthSpec>(prepare_slot)),
                }));
            }
        }

        let till_prepare_slot =
            if let Some(duration) = self.slot_clock.duration_to_slot(prepare_slot) {
                duration
            } else {
                // `SlotClock::duration_to_slot` will return `None` when we are past the start
                // of `prepare_slot`. Don't bother sending a `forkchoiceUpdated` in that case,
                // it's too late.
                //
                // This scenario might occur on an overloaded/under-resourced node.
                warn!(
                    self.log,
                    "Delayed proposer preparation";
                    "prepare_slot" => prepare_slot,
                    "validator" => proposer,
                );
                return Ok(());
            };

        // If we are close enough to the proposal slot, send an fcU, which will have payload
        // attributes filled in by the execution layer cache we just primed.
        if self.config.always_prepare_payload
            || till_prepare_slot <= self.config.prepare_payload_lookahead
        {
            debug!(
                self.log,
                "Sending forkchoiceUpdate for proposer prep";
                "till_prepare_slot" => ?till_prepare_slot,
                "prepare_slot" => prepare_slot
            );

            self.update_execution_engine_forkchoice(
                current_slot,
                forkchoice_update_params,
                OverrideForkchoiceUpdate::AlreadyApplied,
            )
            .await?;
        }

        Ok(())
    }

    pub async fn update_execution_engine_forkchoice(
        self: &Arc<Self>,
        current_slot: Slot,
        input_params: ForkchoiceUpdateParameters,
        override_forkchoice_update: OverrideForkchoiceUpdate,
    ) -> Result<(), Error> {
        let next_slot = current_slot + 1;

        // There is no need to issue a `forkchoiceUpdated` (fcU) message unless the Bellatrix fork
        // has:
        //
        // 1. Already happened.
        // 2. Will happen in the next slot.
        //
        // The reason for a fcU message in the slot prior to the Bellatrix fork is in case the
        // terminal difficulty has already been reached and a payload preparation message needs to
        // be issued.
        if self.slot_is_prior_to_bellatrix(next_slot) {
            return Ok(());
        }

        let execution_layer = self
            .execution_layer
            .as_ref()
            .ok_or(Error::ExecutionLayerMissing)?;

        // Determine whether to override the forkchoiceUpdated message if we want to re-org
        // the current head at the next slot.
        let params = if override_forkchoice_update == OverrideForkchoiceUpdate::Yes {
            let chain = self.clone();
            self.spawn_blocking_handle(
                move || chain.overridden_forkchoice_update_params(input_params),
                "update_execution_engine_forkchoice_override",
            )
            .await??
        } else {
            input_params
        };

        // Take the global lock for updating the execution engine fork choice.
        //
        // Whilst holding this lock we must:
        //
        // 1. Read the canonical head.
        // 2. Issue a forkchoiceUpdated call to the execution engine.
        //
        // This will allow us to ensure that we provide the execution layer with an *ordered* view
        // of the head. I.e., we will never communicate a past head after communicating a later
        // one.
        //
        // There is a "deadlock warning" in this function. The downside of this nice ordering is the
        // potential for deadlock. I would advise against any other use of
        // `execution_engine_forkchoice_lock` apart from the one here.
        let forkchoice_lock = execution_layer.execution_engine_forkchoice_lock().await;

        let (head_block_root, head_hash, justified_hash, finalized_hash) = if let Some(head_hash) =
            params.head_hash
        {
            (
                params.head_root,
                head_hash,
                params
                    .justified_hash
                    .unwrap_or_else(ExecutionBlockHash::zero),
                params
                    .finalized_hash
                    .unwrap_or_else(ExecutionBlockHash::zero),
            )
        } else {
            // The head block does not have an execution block hash. We must check to see if we
            // happen to be the proposer of the transition block, in which case we still need to
            // send forkchoice_updated.
            match self.spec.fork_name_at_slot::<T::EthSpec>(next_slot) {
                // We are pre-bellatrix; no need to update the EL.
                ForkName::Base | ForkName::Altair => return Ok(()),
                _ => {
                    // We are post-bellatrix
                    if let Some(payload_attributes) = execution_layer
                        .payload_attributes(next_slot, params.head_root)
                        .await
                    {
                        // We are a proposer, check for terminal_pow_block_hash
                        if let Some(terminal_pow_block_hash) = execution_layer
                            .get_terminal_pow_block_hash(&self.spec, payload_attributes.timestamp())
                            .await
                            .map_err(Error::ForkchoiceUpdate)?
                        {
                            info!(
                                self.log,
                                "Prepared POS transition block proposer"; "slot" => next_slot
                            );
                            (
                                params.head_root,
                                terminal_pow_block_hash,
                                params
                                    .justified_hash
                                    .unwrap_or_else(ExecutionBlockHash::zero),
                                params
                                    .finalized_hash
                                    .unwrap_or_else(ExecutionBlockHash::zero),
                            )
                        } else {
                            // TTD hasn't been reached yet, no need to update the EL.
                            return Ok(());
                        }
                    } else {
                        // We are not a proposer, no need to update the EL.
                        return Ok(());
                    }
                }
            }
        };

        let forkchoice_updated_response = execution_layer
            .notify_forkchoice_updated(
                head_hash,
                justified_hash,
                finalized_hash,
                current_slot,
                head_block_root,
            )
            .await
            .map_err(Error::ExecutionForkChoiceUpdateFailed);

        // The head has been read and the execution layer has been updated. It is now valid to send
        // another fork choice update.
        drop(forkchoice_lock);

        match forkchoice_updated_response {
            Ok(status) => match status {
                PayloadStatus::Valid => {
                    // Ensure that fork choice knows that the block is no longer optimistic.
                    let chain = self.clone();
                    let fork_choice_update_result = self
                        .spawn_blocking_handle(
                            move || {
                                chain
                                    .canonical_head
                                    .fork_choice_write_lock()
                                    .on_valid_execution_payload(head_block_root)
                            },
                            "update_execution_engine_valid_payload",
                        )
                        .await?;
                    if let Err(e) = fork_choice_update_result {
                        error!(
                            self.log,
                            "Failed to validate payload";
                            "error" => ?e
                        )
                    };
                    Ok(())
                }
                // There's nothing to be done for a syncing response. If the block is already
                // `SYNCING` in fork choice, there's nothing to do. If already known to be `VALID`
                // or `INVALID` then we don't want to change it to syncing.
                PayloadStatus::Syncing => Ok(()),
                // The specification doesn't list `ACCEPTED` as a valid response to a fork choice
                // update. This response *seems* innocent enough, so we won't return early with an
                // error. However, we create a log to bring attention to the issue.
                PayloadStatus::Accepted => {
                    warn!(
                        self.log,
                        "Fork choice update received ACCEPTED";
                        "msg" => "execution engine provided an unexpected response to a fork \
                        choice update. although this is not a serious issue, please raise \
                        an issue."
                    );
                    Ok(())
                }
                PayloadStatus::Invalid {
                    latest_valid_hash,
                    ref validation_error,
                } => {
                    warn!(
                        self.log,
                        "Invalid execution payload";
                        "validation_error" => ?validation_error,
                        "latest_valid_hash" => ?latest_valid_hash,
                        "head_hash" => ?head_hash,
                        "head_block_root" => ?head_block_root,
                        "method" => "fcU",
                    );

                    match latest_valid_hash {
                        // The `latest_valid_hash` is set to `None` when the EE
                        // "cannot determine the ancestor of the invalid
                        // payload". In such a scenario we should only
                        // invalidate the head block and nothing else.
                        None => {
                            self.process_invalid_execution_payload(
                                &InvalidationOperation::InvalidateOne {
                                    block_root: head_block_root,
                                },
                            )
                            .await?;
                        }
                        // An all-zeros execution block hash implies that
                        // the terminal block was invalid. We are being
                        // explicit in invalidating only the head block in
                        // this case.
                        Some(hash) if hash == ExecutionBlockHash::zero() => {
                            self.process_invalid_execution_payload(
                                &InvalidationOperation::InvalidateOne {
                                    block_root: head_block_root,
                                },
                            )
                            .await?;
                        }
                        // The execution engine has stated that all blocks between the
                        // `head_execution_block_hash` and `latest_valid_hash` are invalid.
                        Some(latest_valid_hash) => {
                            self.process_invalid_execution_payload(
                                &InvalidationOperation::InvalidateMany {
                                    head_block_root,
                                    always_invalidate_head: true,
                                    latest_valid_ancestor: latest_valid_hash,
                                },
                            )
                            .await?;
                        }
                    }

                    Err(BeaconChainError::ExecutionForkChoiceUpdateInvalid { status })
                }
                PayloadStatus::InvalidBlockHash {
                    ref validation_error,
                } => {
                    warn!(
                        self.log,
                        "Invalid execution payload block hash";
                        "validation_error" => ?validation_error,
                        "head_hash" => ?head_hash,
                        "head_block_root" => ?head_block_root,
                        "method" => "fcU",
                    );
                    // The execution engine has stated that the head block is invalid, however it
                    // hasn't returned a latest valid ancestor.
                    //
                    // Using a `None` latest valid ancestor will result in only the head block
                    // being invalidated (no ancestors).
                    self.process_invalid_execution_payload(&InvalidationOperation::InvalidateOne {
                        block_root: head_block_root,
                    })
                    .await?;

                    Err(BeaconChainError::ExecutionForkChoiceUpdateInvalid { status })
                }
            },
            Err(e) => Err(e),
        }
    }

    /// Returns `true` if the given slot is prior to the `bellatrix_fork_epoch`.
    pub fn slot_is_prior_to_bellatrix(&self, slot: Slot) -> bool {
        self.spec.bellatrix_fork_epoch.map_or(true, |bellatrix| {
            slot.epoch(T::EthSpec::slots_per_epoch()) < bellatrix
        })
    }

    /// Returns the value of `execution_optimistic` for `block`.
    ///
    /// Returns `Ok(false)` if the block is pre-Bellatrix, or has `ExecutionStatus::Valid`.
    /// Returns `Ok(true)` if the block has `ExecutionStatus::Optimistic` or has
    /// `ExecutionStatus::Invalid`.
    pub fn is_optimistic_or_invalid_block<Payload: AbstractExecPayload<T::EthSpec>>(
        &self,
        block: &SignedBeaconBlock<T::EthSpec, Payload>,
    ) -> Result<bool, BeaconChainError> {
        // Check if the block is pre-Bellatrix.
        if self.slot_is_prior_to_bellatrix(block.slot()) {
            Ok(false)
        } else {
            self.canonical_head
                .fork_choice_read_lock()
                .is_optimistic_or_invalid_block(&block.canonical_root())
                .map_err(BeaconChainError::ForkChoiceError)
        }
    }

    /// Returns the value of `execution_optimistic` for `head_block`.
    ///
    /// Returns `Ok(false)` if the block is pre-Bellatrix, or has `ExecutionStatus::Valid`.
    /// Returns `Ok(true)` if the block has `ExecutionStatus::Optimistic` or `ExecutionStatus::Invalid`.
    ///
    /// This function will return an error if `head_block` is not present in the fork choice store
    /// and so should only be used on the head block or when the block *should* be present in the
    /// fork choice store.
    ///
    /// There is a potential race condition when syncing where the block_root of `head_block` could
    /// be pruned from the fork choice store before being read.
    pub fn is_optimistic_or_invalid_head_block<Payload: AbstractExecPayload<T::EthSpec>>(
        &self,
        head_block: &SignedBeaconBlock<T::EthSpec, Payload>,
    ) -> Result<bool, BeaconChainError> {
        // Check if the block is pre-Bellatrix.
        if self.slot_is_prior_to_bellatrix(head_block.slot()) {
            Ok(false)
        } else {
            self.canonical_head
                .fork_choice_read_lock()
                .is_optimistic_or_invalid_block_no_fallback(&head_block.canonical_root())
                .map_err(BeaconChainError::ForkChoiceError)
        }
    }

    /// Returns the value of `execution_optimistic` for the current head block.
    /// You can optionally provide `head_info` if it was computed previously.
    ///
    /// Returns `Ok(false)` if the head block is pre-Bellatrix, or has `ExecutionStatus::Valid`.
    /// Returns `Ok(true)` if the head block has `ExecutionStatus::Optimistic` or `ExecutionStatus::Invalid`.
    ///
    /// There is a potential race condition when syncing where the block root of `head_info` could
    /// be pruned from the fork choice store before being read.
    pub fn is_optimistic_or_invalid_head(&self) -> Result<bool, BeaconChainError> {
        self.canonical_head
            .head_execution_status()
            .map(|status| status.is_optimistic_or_invalid())
    }

    pub fn is_optimistic_or_invalid_block_root(
        &self,
        block_slot: Slot,
        block_root: &Hash256,
    ) -> Result<bool, BeaconChainError> {
        // Check if the block is pre-Bellatrix.
        if self.slot_is_prior_to_bellatrix(block_slot) {
            Ok(false)
        } else {
            self.canonical_head
                .fork_choice_read_lock()
                .is_optimistic_or_invalid_block_no_fallback(block_root)
                .map_err(BeaconChainError::ForkChoiceError)
        }
    }

    /// This function takes a configured weak subjectivity `Checkpoint` and the latest finalized `Checkpoint`.
    /// If the weak subjectivity checkpoint and finalized checkpoint share the same epoch, we compare
    /// roots. If we the weak subjectivity checkpoint is from an older epoch, we iterate back through
    /// roots in the canonical chain until we reach the finalized checkpoint from the correct epoch, and
    /// compare roots. This must called on startup and during verification of any block which causes a finality
    /// change affecting the weak subjectivity checkpoint.
    pub fn verify_weak_subjectivity_checkpoint(
        &self,
        wss_checkpoint: Checkpoint,
        beacon_block_root: Hash256,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<(), BeaconChainError> {
        let finalized_checkpoint = state.finalized_checkpoint();
        info!(self.log, "Verifying the configured weak subjectivity checkpoint"; "weak_subjectivity_epoch" => wss_checkpoint.epoch, "weak_subjectivity_root" => ?wss_checkpoint.root);
        // If epochs match, simply compare roots.
        if wss_checkpoint.epoch == finalized_checkpoint.epoch
            && wss_checkpoint.root != finalized_checkpoint.root
        {
            crit!(
                self.log,
                 "Root found at the specified checkpoint differs";
                  "weak_subjectivity_root" => ?wss_checkpoint.root,
                  "finalized_checkpoint_root" => ?finalized_checkpoint.root
            );
            return Err(BeaconChainError::WeakSubjectivtyVerificationFailure);
        } else if wss_checkpoint.epoch < finalized_checkpoint.epoch {
            let slot = wss_checkpoint
                .epoch
                .start_slot(T::EthSpec::slots_per_epoch());

            // Iterate backwards through block roots from the given state. If first slot of the epoch is a skip-slot,
            // this will return the root of the closest prior non-skipped slot.
            match self.root_at_slot_from_state(slot, beacon_block_root, state)? {
                Some(root) => {
                    if root != wss_checkpoint.root {
                        crit!(
                            self.log,
                             "Root found at the specified checkpoint differs";
                              "weak_subjectivity_root" => ?wss_checkpoint.root,
                              "finalized_checkpoint_root" => ?finalized_checkpoint.root
                        );
                        return Err(BeaconChainError::WeakSubjectivtyVerificationFailure);
                    }
                }
                None => {
                    crit!(self.log, "The root at the start slot of the given epoch could not be found";
                    "wss_checkpoint_slot" => ?slot);
                    return Err(BeaconChainError::WeakSubjectivtyVerificationFailure);
                }
            }
        }
        Ok(())
    }

    /// Called by the timer on every slot.
    ///
    /// Note: this function **MUST** be called from a non-async context since
    /// it contains a call to `fork_choice` which may eventually call
    /// `tokio::runtime::block_on` in certain cases.
    pub async fn per_slot_task(self: &Arc<Self>) {
        if let Some(slot) = self.slot_clock.now() {
            debug!(
                self.log,
                "Running beacon chain per slot tasks";
                "slot" => ?slot
            );

            // Always run the light-weight pruning tasks (these structures should be empty during
            // sync anyway).
            self.naive_aggregation_pool.write().prune(slot);
            self.block_times_cache.write().prune(slot);

            // Don't run heavy-weight tasks during sync.
            if self.best_slot() + MAX_PER_SLOT_FORK_CHOICE_DISTANCE < slot {
                return;
            }

            // Run fork choice and signal to any waiting task that it has completed.
            self.recompute_head_at_current_slot().await;

            // Send the notification regardless of fork choice success, this is a "best effort"
            // notification and we don't want block production to hit the timeout in case of error.
            // Use a blocking task to avoid blocking the core executor whilst waiting for locks
            // in `ForkChoiceSignalTx`.
            let chain = self.clone();
            self.task_executor.clone().spawn_blocking(
                move || {
                    // Signal block proposal for the next slot (if it happens to be waiting).
                    if let Some(tx) = &chain.fork_choice_signal_tx {
                        if let Err(e) = tx.notify_fork_choice_complete(slot) {
                            warn!(
                                chain.log,
                                "Error signalling fork choice waiter";
                                "error" => ?e,
                                "slot" => slot,
                            );
                        }
                    }
                },
                "per_slot_task_fc_signal_tx",
            );
        }
    }

    /// Runs the `map_fn` with the committee cache for `shuffling_epoch` from the chain with head
    /// `head_block_root`. The `map_fn` will be supplied two values:
    ///
    /// - `&CommitteeCache`: the committee cache that serves the given parameters.
    /// - `Hash256`: the "shuffling decision root" which uniquely identifies the `CommitteeCache`.
    ///
    /// It's not necessary that `head_block_root` matches our current view of the chain, it can be
    /// any block that is:
    ///
    /// - Known to us.
    /// - The finalized block or a descendant of the finalized block.
    ///
    /// It would be quite common for attestation verification operations to use a `head_block_root`
    /// that differs from our view of the head.
    ///
    /// ## Important
    ///
    /// This function is **not** suitable for determining proposer duties (only attester duties).
    ///
    /// ## Notes
    ///
    /// This function exists in this odd "map" pattern because efficiently obtaining a committee
    /// can be complex. It might involve reading straight from the `beacon_chain.shuffling_cache`
    /// or it might involve reading it from a state from the DB. Due to the complexities of
    /// `RwLock`s on the shuffling cache, a simple `Cow` isn't suitable here.
    ///
    /// If the committee for `(head_block_root, shuffling_epoch)` isn't found in the
    /// `shuffling_cache`, we will read a state from disk and then update the `shuffling_cache`.
    pub fn with_committee_cache<F, R>(
        &self,
        head_block_root: Hash256,
        shuffling_epoch: Epoch,
        map_fn: F,
    ) -> Result<R, Error>
    where
        F: Fn(&CommitteeCache, Hash256) -> Result<R, Error>,
    {
        let head_block = self
            .canonical_head
            .fork_choice_read_lock()
            .get_block(&head_block_root)
            .ok_or(Error::MissingBeaconBlock(head_block_root))?;

        let shuffling_id = BlockShufflingIds {
            current: head_block.current_epoch_shuffling_id.clone(),
            next: head_block.next_epoch_shuffling_id.clone(),
            previous: None,
            block_root: head_block.root,
        }
        .id_for_epoch(shuffling_epoch)
        .ok_or_else(|| Error::InvalidShufflingId {
            shuffling_epoch,
            head_block_epoch: head_block.slot.epoch(T::EthSpec::slots_per_epoch()),
        })?;

        // Obtain the shuffling cache, timing how long we wait.
        let cache_wait_timer =
            metrics::start_timer(&metrics::ATTESTATION_PROCESSING_SHUFFLING_CACHE_WAIT_TIMES);

        let mut shuffling_cache = self
            .shuffling_cache
            .try_write_for(ATTESTATION_CACHE_LOCK_TIMEOUT)
            .ok_or(Error::AttestationCacheLockTimeout)?;

        metrics::stop_timer(cache_wait_timer);

        if let Some(cache_item) = shuffling_cache.get(&shuffling_id) {
            // The shuffling cache is no longer required, drop the write-lock to allow concurrent
            // access.
            drop(shuffling_cache);

            let committee_cache = cache_item.wait()?;
            map_fn(&committee_cache, shuffling_id.shuffling_decision_block)
        } else {
            // Create an entry in the cache that "promises" this value will eventually be computed.
            // This avoids the case where multiple threads attempt to produce the same value at the
            // same time.
            //
            // Creating the promise whilst we hold the `shuffling_cache` lock will prevent the same
            // promise from being created twice.
            let sender = shuffling_cache.create_promise(shuffling_id.clone())?;

            // Drop the shuffling cache to avoid holding the lock for any longer than
            // required.
            drop(shuffling_cache);

            debug!(
                self.log,
                "Committee cache miss";
                "shuffling_id" => ?shuffling_epoch,
                "head_block_root" => head_block_root.to_string(),
            );

            let state_read_timer =
                metrics::start_timer(&metrics::ATTESTATION_PROCESSING_STATE_READ_TIMES);

            // If the head of the chain can serve this request, use it.
            //
            // This code is a little awkward because we need to ensure that the head we read and
            // the head we copy is identical. Taking one lock to read the head values and another
            // to copy the head is liable to race-conditions.
            let head_state_opt = self.with_head(|head| {
                if head.beacon_block_root == head_block_root {
                    Ok(Some((
                        head.beacon_state
                            .clone_with(CloneConfig::committee_caches_only()),
                        head.beacon_state_root(),
                    )))
                } else {
                    Ok::<_, Error>(None)
                }
            })?;

            // If the head state is useful for this request, use it. Otherwise, read a state from
            // disk.
            let (mut state, state_root) = if let Some((state, state_root)) = head_state_opt {
                (state, state_root)
            } else {
                let block_state_root = head_block.state_root;
                let max_slot = shuffling_epoch.start_slot(T::EthSpec::slots_per_epoch());
                let (state_root, state) = self
                    .store
                    .get_inconsistent_state_for_attestation_verification_only(
                        &head_block_root,
                        max_slot,
                        block_state_root,
                    )?
                    .ok_or(Error::MissingBeaconState(block_state_root))?;
                (state, state_root)
            };

            /*
             * IMPORTANT
             *
             * Since it's possible that
             * `Store::get_inconsistent_state_for_attestation_verification_only` was used to obtain
             * the state, we cannot rely upon the following fields:
             *
             * - `state.state_roots`
             * - `state.block_roots`
             *
             * These fields should not be used for the rest of this function.
             */

            metrics::stop_timer(state_read_timer);
            let state_skip_timer =
                metrics::start_timer(&metrics::ATTESTATION_PROCESSING_STATE_SKIP_TIMES);

            // If the state is in an earlier epoch, advance it. If it's from a later epoch, reject
            // it.
            if state.current_epoch() + 1 < shuffling_epoch {
                // Since there's a one-epoch look-ahead on the attester shuffling, it suffices to
                // only advance into the slot prior to the `shuffling_epoch`.
                let target_slot = shuffling_epoch
                    .saturating_sub(1_u64)
                    .start_slot(T::EthSpec::slots_per_epoch());

                // Advance the state into the required slot, using the "partial" method since the state
                // roots are not relevant for the shuffling.
                partial_state_advance(&mut state, Some(state_root), target_slot, &self.spec)?;
            } else if state.current_epoch() > shuffling_epoch {
                return Err(Error::InvalidStateForShuffling {
                    state_epoch: state.current_epoch(),
                    shuffling_epoch,
                });
            }

            metrics::stop_timer(state_skip_timer);
            let committee_building_timer =
                metrics::start_timer(&metrics::ATTESTATION_PROCESSING_COMMITTEE_BUILDING_TIMES);

            let relative_epoch = RelativeEpoch::from_epoch(state.current_epoch(), shuffling_epoch)
                .map_err(Error::IncorrectStateForAttestation)?;

            state.build_committee_cache(relative_epoch, &self.spec)?;

            let committee_cache = state.take_committee_cache(relative_epoch)?;
            let committee_cache = Arc::new(committee_cache);
            let shuffling_decision_block = shuffling_id.shuffling_decision_block;

            self.shuffling_cache
                .try_write_for(ATTESTATION_CACHE_LOCK_TIMEOUT)
                .ok_or(Error::AttestationCacheLockTimeout)?
                .insert_committee_cache(shuffling_id, &committee_cache);

            metrics::stop_timer(committee_building_timer);

            sender.send(committee_cache.clone());

            map_fn(&committee_cache, shuffling_decision_block)
        }
    }

    /// Dumps the entire canonical chain, from the head to genesis to a vector for analysis.
    ///
    /// This could be a very expensive operation and should only be done in testing/analysis
    /// activities.
    #[allow(clippy::type_complexity)]
    pub fn chain_dump(
        &self,
    ) -> Result<Vec<BeaconSnapshot<T::EthSpec, BlindedPayload<T::EthSpec>>>, Error> {
        let mut dump = vec![];

        let mut last_slot = {
            let head = self.canonical_head.cached_head();
            BeaconSnapshot {
                beacon_block: Arc::new(head.snapshot.beacon_block.clone_as_blinded()),
                beacon_block_root: head.snapshot.beacon_block_root,
                beacon_state: head.snapshot.beacon_state.clone(),
            }
        };

        dump.push(last_slot.clone());

        loop {
            let beacon_block_root = last_slot.beacon_block.parent_root();

            if beacon_block_root == Hash256::zero() {
                break; // Genesis has been reached.
            }

            let beacon_block = self
                .store
                .get_blinded_block(&beacon_block_root)?
                .ok_or_else(|| {
                    Error::DBInconsistent(format!("Missing block {}", beacon_block_root))
                })?;
            let beacon_state_root = beacon_block.state_root();
            let beacon_state = self
                .store
                .get_state(&beacon_state_root, Some(beacon_block.slot()))?
                .ok_or_else(|| {
                    Error::DBInconsistent(format!("Missing state {:?}", beacon_state_root))
                })?;

            let slot = BeaconSnapshot {
                beacon_block: Arc::new(beacon_block),
                beacon_block_root,
                beacon_state,
            };

            dump.push(slot.clone());
            last_slot = slot;
        }

        dump.reverse();

        Ok(dump)
    }

    /// Gets the current `EnrForkId`.
    pub fn enr_fork_id(&self) -> EnrForkId {
        // If we are unable to read the slot clock we assume that it is prior to genesis and
        // therefore use the genesis slot.
        let slot = self.slot().unwrap_or(self.spec.genesis_slot);

        self.spec
            .enr_fork_id::<T::EthSpec>(slot, self.genesis_validators_root)
    }

    /// Calculates the `Duration` to the next fork if it exists and returns it
    /// with it's corresponding `ForkName`.
    pub fn duration_to_next_fork(&self) -> Option<(ForkName, Duration)> {
        // If we are unable to read the slot clock we assume that it is prior to genesis and
        // therefore use the genesis slot.
        let slot = self.slot().unwrap_or(self.spec.genesis_slot);

        let (fork_name, epoch) = self.spec.next_fork_epoch::<T::EthSpec>(slot)?;
        self.slot_clock
            .duration_to_slot(epoch.start_slot(T::EthSpec::slots_per_epoch()))
            .map(|duration| (fork_name, duration))
    }

    /// This method serves to get a sense of the current chain health. It is used in block proposal
    /// to determine whether we should outsource payload production duties.
    ///
    /// Since we are likely calling this during the slot we are going to propose in, don't take into
    /// account the current slot when accounting for skips.
    pub fn is_healthy(&self, parent_root: &Hash256) -> Result<ChainHealth, Error> {
        let cached_head = self.canonical_head.cached_head();
        // Check if the merge has been finalized.
        if let Some(finalized_hash) = cached_head.forkchoice_update_parameters().finalized_hash {
            if ExecutionBlockHash::zero() == finalized_hash {
                return Ok(ChainHealth::PreMerge);
            }
        } else {
            return Ok(ChainHealth::PreMerge);
        };

        // Check that the parent is NOT optimistic.
        if let Some(execution_status) = self
            .canonical_head
            .fork_choice_read_lock()
            .get_block_execution_status(parent_root)
        {
            if execution_status.is_strictly_optimistic() {
                return Ok(ChainHealth::Optimistic);
            }
        }

        if self.config.builder_fallback_disable_checks {
            return Ok(ChainHealth::Healthy);
        }

        let current_slot = self.slot()?;

        // Check slots at the head of the chain.
        let prev_slot = current_slot.saturating_sub(Slot::new(1));
        let head_skips = prev_slot.saturating_sub(cached_head.head_slot());
        let head_skips_check = head_skips.as_usize() <= self.config.builder_fallback_skips;

        // Check if finalization is advancing.
        let current_epoch = current_slot.epoch(T::EthSpec::slots_per_epoch());
        let epochs_since_finalization =
            current_epoch.saturating_sub(cached_head.finalized_checkpoint().epoch);
        let finalization_check = epochs_since_finalization.as_usize()
            <= self.config.builder_fallback_epochs_since_finalization;

        // Check skip slots in the last `SLOTS_PER_EPOCH`.
        let start_slot = current_slot.saturating_sub(T::EthSpec::slots_per_epoch());
        let mut epoch_skips = 0;
        for slot in start_slot.as_u64()..current_slot.as_u64() {
            if self
                .block_root_at_slot_skips_none(Slot::new(slot))?
                .is_none()
            {
                epoch_skips += 1;
            }
        }
        let epoch_skips_check = epoch_skips <= self.config.builder_fallback_skips_per_epoch;

        if !head_skips_check {
            Ok(ChainHealth::Unhealthy(FailedCondition::Skips))
        } else if !finalization_check {
            Ok(ChainHealth::Unhealthy(
                FailedCondition::EpochsSinceFinalization,
            ))
        } else if !epoch_skips_check {
            Ok(ChainHealth::Unhealthy(FailedCondition::SkipsPerEpoch))
        } else {
            Ok(ChainHealth::Healthy)
        }
    }

    pub fn dump_as_dot<W: Write>(&self, output: &mut W) {
        let canonical_head_hash = self.canonical_head.cached_head().head_block_root();
        let mut visited: HashSet<Hash256> = HashSet::new();
        let mut finalized_blocks: HashSet<Hash256> = HashSet::new();
        let mut justified_blocks: HashSet<Hash256> = HashSet::new();

        let genesis_block_hash = Hash256::zero();
        writeln!(output, "digraph beacon {{").unwrap();
        writeln!(output, "\t_{:?}[label=\"zero\"];", genesis_block_hash).unwrap();

        // Canonical head needs to be processed first as otherwise finalized blocks aren't detected
        // properly.
        let heads = {
            let mut heads = self.heads();
            let canonical_head_index = heads
                .iter()
                .position(|(block_hash, _)| *block_hash == canonical_head_hash)
                .unwrap();
            let (canonical_head_hash, canonical_head_slot) =
                heads.swap_remove(canonical_head_index);
            heads.insert(0, (canonical_head_hash, canonical_head_slot));
            heads
        };

        for (head_hash, _head_slot) in heads {
            for maybe_pair in ParentRootBlockIterator::new(&*self.store, head_hash) {
                let (block_hash, signed_beacon_block) = maybe_pair.unwrap();
                if visited.contains(&block_hash) {
                    break;
                }
                visited.insert(block_hash);

                if signed_beacon_block.slot() % T::EthSpec::slots_per_epoch() == 0 {
                    let block = self.get_blinded_block(&block_hash).unwrap().unwrap();
                    let state = self
                        .get_state(&block.state_root(), Some(block.slot()))
                        .unwrap()
                        .unwrap();
                    finalized_blocks.insert(state.finalized_checkpoint().root);
                    justified_blocks.insert(state.current_justified_checkpoint().root);
                    justified_blocks.insert(state.previous_justified_checkpoint().root);
                }

                if block_hash == canonical_head_hash {
                    writeln!(
                        output,
                        "\t_{:?}[label=\"{} ({})\" shape=box3d];",
                        block_hash,
                        block_hash,
                        signed_beacon_block.slot()
                    )
                    .unwrap();
                } else if finalized_blocks.contains(&block_hash) {
                    writeln!(
                        output,
                        "\t_{:?}[label=\"{} ({})\" shape=Msquare];",
                        block_hash,
                        block_hash,
                        signed_beacon_block.slot()
                    )
                    .unwrap();
                } else if justified_blocks.contains(&block_hash) {
                    writeln!(
                        output,
                        "\t_{:?}[label=\"{} ({})\" shape=cds];",
                        block_hash,
                        block_hash,
                        signed_beacon_block.slot()
                    )
                    .unwrap();
                } else {
                    writeln!(
                        output,
                        "\t_{:?}[label=\"{} ({})\" shape=box];",
                        block_hash,
                        block_hash,
                        signed_beacon_block.slot()
                    )
                    .unwrap();
                }
                writeln!(
                    output,
                    "\t_{:?} -> _{:?};",
                    block_hash,
                    signed_beacon_block.parent_root()
                )
                .unwrap();
            }
        }

        writeln!(output, "}}").unwrap();
    }

    /// Get a channel to request shutting down.
    pub fn shutdown_sender(&self) -> Sender<ShutdownReason> {
        self.shutdown_sender.clone()
    }

    // Used for debugging
    #[allow(dead_code)]
    pub fn dump_dot_file(&self, file_name: &str) {
        let mut file = std::fs::File::create(file_name).unwrap();
        self.dump_as_dot(&mut file);
    }

    /// Checks if attestations have been seen from the given `validator_index` at the
    /// given `epoch`.
    pub fn validator_seen_at_epoch(&self, validator_index: usize, epoch: Epoch) -> bool {
        // It's necessary to assign these checks to intermediate variables to avoid a deadlock.
        //
        // See: https://github.com/sigp/lighthouse/pull/2230#discussion_r620013993
        let gossip_attested = self
            .observed_gossip_attesters
            .read()
            .index_seen_at_epoch(validator_index, epoch);
        let block_attested = self
            .observed_block_attesters
            .read()
            .index_seen_at_epoch(validator_index, epoch);
        let aggregated = self
            .observed_aggregators
            .read()
            .index_seen_at_epoch(validator_index, epoch);
        let produced_block = self
            .observed_block_producers
            .read()
            .index_seen_at_epoch(validator_index as u64, epoch);

        gossip_attested || block_attested || aggregated || produced_block
    }
}

impl<T: BeaconChainTypes> Drop for BeaconChain<T> {
    fn drop(&mut self) {
        let drop = || -> Result<(), Error> {
            self.persist_head_and_fork_choice()?;
            self.persist_op_pool()?;
            self.persist_eth1_cache()
        };

        if let Err(e) = drop() {
            error!(
                self.log,
                "Failed to persist on BeaconChain drop";
                "error" => ?e
            )
        } else {
            info!(
                self.log,
                "Saved beacon chain to disk";
            )
        }
    }
}

impl From<DBError> for Error {
    fn from(e: DBError) -> Error {
        Error::DBError(e)
    }
}

impl From<ForkChoiceError> for Error {
    fn from(e: ForkChoiceError) -> Error {
        Error::ForkChoiceError(e)
    }
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}

impl<T: EthSpec> ChainSegmentResult<T> {
    pub fn into_block_error(self) -> Result<(), BlockError<T>> {
        match self {
            ChainSegmentResult::Failed { error, .. } => Err(error),
            ChainSegmentResult::Successful { .. } => Ok(()),
        }
    }
}
