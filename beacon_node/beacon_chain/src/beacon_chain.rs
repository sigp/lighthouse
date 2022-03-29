use crate::attestation_verification::{
    batch_verify_aggregated_attestations, batch_verify_unaggregated_attestations,
    Error as AttestationError, VerifiedAggregatedAttestation, VerifiedAttestation,
    VerifiedUnaggregatedAttestation,
};
use crate::attester_cache::{AttesterCache, AttesterCacheKey};
use crate::beacon_proposer_cache::compute_proposer_duties_from_head;
use crate::beacon_proposer_cache::BeaconProposerCache;
use crate::block_times_cache::BlockTimesCache;
use crate::block_verification::{
    check_block_is_finalized_descendant, check_block_relevancy, get_block_root,
    signature_verify_chain_segment, BlockError, FullyVerifiedBlock, GossipVerifiedBlock,
    IntoFullyVerifiedBlock,
};
use crate::chain_config::ChainConfig;
use crate::early_attester_cache::EarlyAttesterCache;
use crate::errors::{BeaconChainError as Error, BlockProductionError};
use crate::eth1_chain::{Eth1Chain, Eth1ChainBackend};
use crate::events::ServerSentEventHandler;
use crate::execution_payload::get_execution_payload;
use crate::head_tracker::HeadTracker;
use crate::historical_blocks::HistoricalBlockError;
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
use crate::proposer_prep_service::PAYLOAD_PREPARATION_LOOKAHEAD_FACTOR;
use crate::shuffling_cache::{BlockShufflingIds, ShufflingCache};
use crate::snapshot_cache::SnapshotCache;
use crate::sync_committee_verification::{
    Error as SyncCommitteeError, VerifiedSyncCommitteeMessage, VerifiedSyncContribution,
};
use crate::timeout_rw_lock::TimeoutRwLock;
use crate::validator_monitor::{
    get_slot_delay_ms, timestamp_now, ValidatorMonitor,
    HISTORIC_EPOCHS as VALIDATOR_MONITOR_HISTORIC_EPOCHS,
};
use crate::validator_pubkey_cache::ValidatorPubkeyCache;
use crate::BeaconForkChoiceStore;
use crate::BeaconSnapshot;
use crate::{metrics, BeaconChainError};
use eth2::types::{
    EventKind, SseBlock, SseChainReorg, SseFinalizedCheckpoint, SseHead, SseLateHead, SyncDuty,
};
use execution_layer::{ExecutionLayer, PayloadAttributes, PayloadStatus};
use fork_choice::{AttestationFromBlock, ForkChoice, InvalidationOperation};
use futures::channel::mpsc::Sender;
use itertools::process_results;
use itertools::Itertools;
use operation_pool::{OperationPool, PersistedOperationPool};
use parking_lot::{Mutex, RwLock};
use proto_array::ExecutionStatus;
use safe_arith::SafeArith;
use slasher::Slasher;
use slog::{crit, debug, error, info, trace, warn, Logger};
use slot_clock::SlotClock;
use ssz::Encode;
use state_processing::{
    common::get_indexed_attestation,
    per_block_processing,
    per_block_processing::{errors::AttestationValidationError, is_merge_transition_complete},
    per_slot_processing,
    state_advance::{complete_state_advance, partial_state_advance},
    BlockSignatureStrategy, SigVerifiedOp, VerifyBlockRoot,
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
use store::{Error as DBError, HotColdDB, KeyValueStore, KeyValueStoreOp, StoreItem, StoreOp};
use task_executor::ShutdownReason;
use types::beacon_state::CloneConfig;
use types::*;

pub type ForkChoiceError = fork_choice::Error<crate::ForkChoiceStoreError>;

/// The time-out before failure during an operation to take a read/write RwLock on the canonical
/// head.
pub const HEAD_LOCK_TIMEOUT: Duration = Duration::from_secs(1);

/// The time-out before failure during an operation to take a read/write RwLock on the block
/// processing cache.
pub const BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(1);
/// The time-out before failure during an operation to take a read/write RwLock on the
/// attestation cache.
pub const ATTESTATION_CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(1);

/// The time-out before failure during an operation to take a read/write RwLock on the
/// validator pubkey cache.
pub const VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(1);

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

/// Reported to the user when the justified block has an invalid execution payload.
pub const INVALID_JUSTIFIED_PAYLOAD_SHUTDOWN_REASON: &str =
    "Justified block has an invalid execution payload.";

/// Defines the behaviour when a block/block-root for a skipped slot is requested.
pub enum WhenSlotSkipped {
    /// If the slot is a skip slot, return `None`.
    ///
    /// This is how the HTTP API behaves.
    None,
    /// If the slot it a skip slot, return the previous non-skipped block.
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

/// The accepted clock drift for nodes gossiping blocks and attestations. See:
///
/// https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/p2p-interface.md#configuration
pub const MAXIMUM_GOSSIP_CLOCK_DISPARITY: Duration = Duration::from_millis(500);

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

#[derive(Debug, PartialEq)]
pub struct HeadInfo {
    pub slot: Slot,
    pub block_root: Hash256,
    pub state_root: Hash256,
    pub current_justified_checkpoint: types::Checkpoint,
    pub finalized_checkpoint: types::Checkpoint,
    pub fork: Fork,
    pub genesis_time: u64,
    pub genesis_validators_root: Hash256,
    pub proposer_shuffling_decision_root: Hash256,
    pub is_merge_transition_complete: bool,
    pub execution_payload_block_hash: Option<ExecutionBlockHash>,
    pub random: Hash256,
}

pub trait BeaconChainTypes: Send + Sync + 'static {
    type HotStore: store::ItemStore<Self::EthSpec>;
    type ColdStore: store::ItemStore<Self::EthSpec>;
    type SlotClock: slot_clock::SlotClock;
    type Eth1Chain: Eth1ChainBackend<Self::EthSpec>;
    type EthSpec: types::EthSpec;
}

/// Indicates the EL payload verification status of the head beacon block.
#[derive(Debug, PartialEq)]
pub enum HeadSafetyStatus {
    /// The head block has either been verified by an EL or is does not require EL verification
    /// (e.g., it is pre-merge or pre-terminal-block).
    ///
    /// If the block is post-terminal-block, `Some(execution_payload.block_hash)` is included with
    /// the variant.
    Safe(Option<ExecutionBlockHash>),
    /// The head block execution payload has not yet been verified by an EL.
    ///
    /// The `execution_payload.block_hash` of the head block is returned.
    Unsafe(ExecutionBlockHash),
    /// The head block execution payload was deemed to be invalid by an EL.
    ///
    /// The `execution_payload.block_hash` of the head block is returned.
    Invalid(ExecutionBlockHash),
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
    pub(crate) observed_block_producers: RwLock<ObservedBlockProducers<T::EthSpec>>,
    /// Maintains a record of which validators have submitted voluntary exits.
    pub(crate) observed_voluntary_exits: Mutex<ObservedOperations<SignedVoluntaryExit, T::EthSpec>>,
    /// Maintains a record of which validators we've seen proposer slashings for.
    pub(crate) observed_proposer_slashings: Mutex<ObservedOperations<ProposerSlashing, T::EthSpec>>,
    /// Maintains a record of which validators we've seen attester slashings for.
    pub(crate) observed_attester_slashings:
        Mutex<ObservedOperations<AttesterSlashing<T::EthSpec>, T::EthSpec>>,
    /// Provides information from the Ethereum 1 (PoW) chain.
    pub eth1_chain: Option<Eth1Chain<T::Eth1Chain, T::EthSpec>>,
    /// Interfaces with the execution client.
    pub execution_layer: Option<ExecutionLayer>,
    /// Stores a "snapshot" of the chain at the time the head-of-the-chain block was received.
    pub(crate) canonical_head: TimeoutRwLock<BeaconSnapshot<T::EthSpec>>,
    /// The root of the genesis block.
    pub genesis_block_root: Hash256,
    /// The root of the genesis state.
    pub genesis_state_root: Hash256,
    /// The root of the list of genesis validators, used during syncing.
    pub genesis_validators_root: Hash256,
    /// A state-machine that is updated with information from the network and chooses a canonical
    /// head block.
    pub fork_choice: RwLock<BeaconForkChoice<T>>,
    /// A handler for events generated by the beacon chain. This is only initialized when the
    /// HTTP server is enabled.
    pub event_handler: Option<ServerSentEventHandler<T::EthSpec>>,
    /// Used to track the heads of the beacon chain.
    pub(crate) head_tracker: Arc<HeadTracker>,
    /// A cache dedicated to block processing.
    pub(crate) snapshot_cache: TimeoutRwLock<SnapshotCache<T::EthSpec>>,
    /// Caches the attester shuffling for a given epoch and shuffling key root.
    pub(crate) shuffling_cache: TimeoutRwLock<ShufflingCache>,
    /// Caches the beacon block proposer shuffling for a given epoch and shuffling key root.
    pub beacon_proposer_cache: Mutex<BeaconProposerCache>,
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
}

type BeaconBlockAndState<T, Payload> = (BeaconBlock<T, Payload>, BeaconState<T>);

impl<T: BeaconChainTypes> BeaconChain<T> {
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

    /// Return a database operation for writing fork choice to disk.
    pub fn persist_fork_choice_in_batch(&self) -> KeyValueStoreOp {
        let fork_choice = self.fork_choice.read();
        Self::persist_fork_choice_in_batch_standalone(&fork_choice)
    }

    /// Return a database operation for writing fork choice to disk.
    pub fn persist_fork_choice_in_batch_standalone(
        fork_choice: &BeaconForkChoice<T>,
    ) -> KeyValueStoreOp {
        let persisted_fork_choice = PersistedForkChoice {
            fork_choice: fork_choice.to_persisted(),
            fork_choice_store: fork_choice.fc_store().to_persisted(),
        };
        persisted_fork_choice.as_kv_store_op(FORK_CHOICE_DB_KEY)
    }

    /// Load fork choice from disk, returning `None` if it isn't found.
    pub fn load_fork_choice(store: BeaconStore<T>) -> Result<Option<BeaconForkChoice<T>>, Error> {
        let persisted_fork_choice =
            match store.get_item::<PersistedForkChoice>(&FORK_CHOICE_DB_KEY)? {
                Some(fc) => fc,
                None => return Ok(None),
            };

        let fc_store =
            BeaconForkChoiceStore::from_persisted(persisted_fork_choice.fork_choice_store, store)?;

        Ok(Some(ForkChoice::from_persisted(
            persisted_fork_choice.fork_choice,
            fc_store,
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
        let _timer = metrics::start_timer(&metrics::PERSIST_OP_POOL);

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

        let local_head = self.head()?;

        let iter = self.store.forwards_block_roots_iterator(
            start_slot,
            local_head.beacon_state,
            local_head.beacon_block_root,
            &self.spec,
        )?;

        Ok(iter.map(|result| result.map_err(Into::into)))
    }

    /// Even more efficient variant of `forwards_iter_block_roots` that will avoid cloning the head
    /// state if it isn't required for the requested range of blocks.
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
            .get_block(&block_root)?
            .ok_or(Error::MissingBeaconBlock(block_root))?;
        let state = self
            .get_state(&block.state_root(), Some(block.slot()))?
            .ok_or_else(|| Error::MissingBeaconState(block.state_root()))?;
        let iter = BlockRootsIterator::owned(&self.store, state);
        Ok(std::iter::once(Ok((block_root, block.slot())))
            .chain(iter)
            .map(|result| result.map_err(|e| e.into())))
    }

    /// Iterate through the current chain to find the slot intersecting with the given beacon state.
    /// The maximum depth this will search is `SLOTS_PER_HISTORICAL_ROOT`, and if that depth is reached
    /// and no intersection is found, the finalized slot will be returned.
    pub fn find_reorg_slot(
        &self,
        new_state: &BeaconState<T::EthSpec>,
        new_block_root: Hash256,
    ) -> Result<Slot, Error> {
        self.with_head(|snapshot| {
            let old_state = &snapshot.beacon_state;
            let old_block_root = snapshot.beacon_block_root;

            // The earliest slot for which the two chains may have a common history.
            let lowest_slot = std::cmp::min(new_state.slot(), old_state.slot());

            // Create an iterator across `$state`, assuming that the block at `$state.slot` has the
            // block root of `$block_root`.
            //
            // The iterator will be skipped until the next value returns `lowest_slot`.
            //
            // This is a macro instead of a function or closure due to the complex types invloved
            // in all the iterator wrapping.
            macro_rules! aligned_roots_iter {
                ($state: ident, $block_root: ident) => {
                    std::iter::once(Ok(($state.slot(), $block_root)))
                        .chain($state.rev_iter_block_roots(&self.spec))
                        .skip_while(|result| {
                            result
                                .as_ref()
                                .map_or(false, |(slot, _)| *slot > lowest_slot)
                        })
                };
            }

            // Create iterators across old/new roots where iterators both start at the same slot.
            let mut new_roots = aligned_roots_iter!(new_state, new_block_root);
            let mut old_roots = aligned_roots_iter!(old_state, old_block_root);

            // Whilst *both* of the iterators are still returning values, try and find a common
            // ancestor between them.
            while let (Some(old), Some(new)) = (old_roots.next(), new_roots.next()) {
                let (old_slot, old_root) = old?;
                let (new_slot, new_root) = new?;

                // Sanity check to detect programming errors.
                if old_slot != new_slot {
                    return Err(Error::InvalidReorgSlotIter { new_slot, old_slot });
                }

                if old_root == new_root {
                    // A common ancestor has been found.
                    return Ok(old_slot);
                }
            }

            // If no common ancestor is found, declare that the re-org happened at the previous
            // finalized slot.
            //
            // Sometimes this will result in the return slot being *lower* than the actual reorg
            // slot. However, assuming we don't re-org through a finalized slot, it will never be
            // *higher*.
            //
            // We provide this potentially-inaccurate-but-safe information to avoid onerous
            // database reads during times of deep reorgs.
            Ok(old_state
                .finalized_checkpoint()
                .epoch
                .start_slot(T::EthSpec::slots_per_epoch()))
        })
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
        let local_head = self.head()?;

        let iter = self.store.forwards_state_roots_iterator(
            start_slot,
            local_head.beacon_state_root(),
            local_head.beacon_state,
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
    ) -> Result<Option<SignedBeaconBlock<T::EthSpec>>, Error> {
        let root = self.block_root_at_slot(request_slot, skips)?;

        if let Some(block_root) = root {
            Ok(self.store.get_block(&block_root)?)
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
                    return Ok(Some((*prev_root != request_root).then(|| request_root)));
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
            Ok((curr_root != prev_root).then(|| curr_root))
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
    pub fn get_block_checking_early_attester_cache(
        &self,
        block_root: &Hash256,
    ) -> Result<Option<SignedBeaconBlock<T::EthSpec>>, Error> {
        let block_opt = self
            .store
            .get_block(block_root)?
            .or_else(|| self.early_attester_cache.get_block(*block_root));

        Ok(block_opt)
    }

    /// Returns the block at the given root, if any.
    ///
    /// ## Errors
    ///
    /// May return a database error.
    pub fn get_block(
        &self,
        block_root: &Hash256,
    ) -> Result<Option<SignedBeaconBlock<T::EthSpec>>, Error> {
        Ok(self.store.get_block(block_root)?)
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

    /// Returns a `Checkpoint` representing the head block and state. Contains the "best block";
    /// the head of the canonical `BeaconChain`.
    ///
    /// It is important to note that the `beacon_state` returned may not match the present slot. It
    /// is the state as it was when the head block was received, which could be some slots prior to
    /// now.
    pub fn head(&self) -> Result<BeaconSnapshot<T::EthSpec>, Error> {
        self.with_head(|head| Ok(head.clone_with(CloneConfig::committee_caches_only())))
    }

    /// Apply a function to the canonical head without cloning it.
    pub fn with_head<U, E>(
        &self,
        f: impl FnOnce(&BeaconSnapshot<T::EthSpec>) -> Result<U, E>,
    ) -> Result<U, E>
    where
        E: From<Error>,
    {
        let head_lock = self
            .canonical_head
            .try_read_for(HEAD_LOCK_TIMEOUT)
            .ok_or(Error::CanonicalHeadLockTimeout)?;
        f(&head_lock)
    }

    /// Returns the beacon block root at the head of the canonical chain.
    ///
    /// See `Self::head` for more information.
    pub fn head_beacon_block_root(&self) -> Result<Hash256, Error> {
        self.with_head(|s| Ok(s.beacon_block_root))
    }

    /// Returns the beacon block at the head of the canonical chain.
    ///
    /// See `Self::head` for more information.
    pub fn head_beacon_block(&self) -> Result<SignedBeaconBlock<T::EthSpec>, Error> {
        self.with_head(|s| Ok(s.beacon_block.clone()))
    }

    /// Returns the beacon state at the head of the canonical chain.
    ///
    /// See `Self::head` for more information.
    pub fn head_beacon_state(&self) -> Result<BeaconState<T::EthSpec>, Error> {
        self.with_head(|s| {
            Ok(s.beacon_state
                .clone_with(CloneConfig::committee_caches_only()))
        })
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

    /// Returns info representing the head block and state.
    ///
    /// A summarized version of `Self::head` that involves less cloning.
    pub fn head_info(&self) -> Result<HeadInfo, Error> {
        self.with_head(|head| {
            let proposer_shuffling_decision_root = head
                .beacon_state
                .proposer_shuffling_decision_root(head.beacon_block_root)?;

            // The `random` value is used whilst producing an `ExecutionPayload` atop the head.
            let current_epoch = head.beacon_state.current_epoch();
            let random = *head.beacon_state.get_randao_mix(current_epoch)?;

            Ok(HeadInfo {
                slot: head.beacon_block.slot(),
                block_root: head.beacon_block_root,
                state_root: head.beacon_state_root(),
                current_justified_checkpoint: head.beacon_state.current_justified_checkpoint(),
                finalized_checkpoint: head.beacon_state.finalized_checkpoint(),
                fork: head.beacon_state.fork(),
                genesis_time: head.beacon_state.genesis_time(),
                genesis_validators_root: head.beacon_state.genesis_validators_root(),
                proposer_shuffling_decision_root,
                is_merge_transition_complete: is_merge_transition_complete(&head.beacon_state),
                execution_payload_block_hash: head
                    .beacon_block
                    .message()
                    .body()
                    .execution_payload()
                    .ok()
                    .map(|ep| ep.block_hash()),
                random,
            })
        })
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
        let head_state = self.head()?.beacon_state;

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

    /// Returns the slot of the highest block in the canonical chain.
    pub fn best_slot(&self) -> Result<Slot, Error> {
        self.canonical_head
            .try_read_for(HEAD_LOCK_TIMEOUT)
            .map(|head| head.beacon_block.slot())
            .ok_or(Error::CanonicalHeadLockTimeout)
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
    ) -> Result<(Vec<Option<AttestationDuty>>, Hash256), Error> {
        self.with_committee_cache(head_block_root, epoch, |committee_cache, dependent_root| {
            let duties = validator_indices
                .iter()
                .map(|validator_index| {
                    let validator_index = *validator_index as usize;
                    committee_cache.get_attestation_duties(validator_index)
                })
                .collect();

            Ok((duties, dependent_root))
        })
    }

    /// Returns an aggregated `Attestation`, if any, that has a matching `attestation.data`.
    ///
    /// The attestation will be obtained from `self.naive_aggregation_pool`.
    pub fn get_aggregated_attestation(
        &self,
        data: &AttestationData,
    ) -> Option<Attestation<T::EthSpec>> {
        self.naive_aggregation_pool.read().get(data)
    }

    /// Returns an aggregated `Attestation`, if any, that has a matching
    /// `attestation.data.tree_hash_root()`.
    ///
    /// The attestation will be obtained from `self.naive_aggregation_pool`.
    pub fn get_aggregated_attestation_by_slot_and_root(
        &self,
        slot: Slot,
        attestation_data_root: &Hash256,
    ) -> Option<Attestation<T::EthSpec>> {
        self.naive_aggregation_pool
            .read()
            .get_by_slot_and_root(slot, attestation_data_root)
    }

    /// Return an aggregated `SyncCommitteeContribution` matching the given `root`.
    pub fn get_aggregated_sync_committee_contribution(
        &self,
        sync_contribution_data: &SyncContributionData,
    ) -> Option<SyncCommitteeContribution<T::EthSpec>> {
        self.naive_sync_aggregation_pool
            .read()
            .get(sync_contribution_data)
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
        if let Some(head) = self.canonical_head.try_read_for(HEAD_LOCK_TIMEOUT) {
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
        } else {
            return Err(Error::CanonicalHeadLockTimeout);
        }
        drop(head_timer);

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

    /// Produces an "unaggregated" attestation for the given `slot` and `index` that attests to
    /// `beacon_block_root`. The provided `state` should match the `block.state_root` for the
    /// `block` identified by `beacon_block_root`.
    ///
    /// The attestation doesn't _really_ have anything about it that makes it unaggregated per say,
    /// however this function is only required in the context of forming an unaggregated
    /// attestation. It would be an (undetectable) violation of the protocol to create a
    /// `SignedAggregateAndProof` based upon the output of this function.
    pub fn produce_unaggregated_attestation_for_block(
        &self,
        slot: Slot,
        index: CommitteeIndex,
        beacon_block_root: Hash256,
        mut state: Cow<BeaconState<T::EthSpec>>,
        state_root: Hash256,
    ) -> Result<Attestation<T::EthSpec>, Error> {
        let epoch = slot.epoch(T::EthSpec::slots_per_epoch());

        if state.slot() > slot {
            return Err(Error::CannotAttestToFutureState);
        } else if state.current_epoch() < epoch {
            let mut_state = state.to_mut();
            // Only perform a "partial" state advance since we do not require the state roots to be
            // accurate.
            partial_state_advance(
                mut_state,
                Some(state_root),
                epoch.start_slot(T::EthSpec::slots_per_epoch()),
                &self.spec,
            )?;
            mut_state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;
        }

        let committee_len = state.get_beacon_committee(slot, index)?.committee.len();

        let target_slot = epoch.start_slot(T::EthSpec::slots_per_epoch());
        let target_root = if state.slot() <= target_slot {
            beacon_block_root
        } else {
            *state.get_block_root(target_slot)?
        };

        Ok(Attestation {
            aggregation_bits: BitList::with_capacity(committee_len)?,
            data: AttestationData {
                slot,
                index,
                beacon_block_root,
                source: state.current_justified_checkpoint(),
                target: Checkpoint {
                    epoch,
                    root: target_root,
                },
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

        self.fork_choice
            .write()
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
    pub fn add_to_block_inclusion_pool(
        &self,
        verified_attestation: &impl VerifiedAttestation<T>,
    ) -> Result<(), AttestationError> {
        let _timer = metrics::start_timer(&metrics::ATTESTATION_PROCESSING_APPLY_TO_OP_POOL);

        // If there's no eth1 chain then it's impossible to produce blocks and therefore
        // useless to put things in the op pool.
        if self.eth1_chain.is_some() {
            let fork =
                self.with_head(|head| Ok::<_, AttestationError>(head.beacon_state.fork()))?;

            self.op_pool
                .insert_attestation(
                    // TODO: address this clone.
                    verified_attestation.attestation().clone(),
                    &fork,
                    self.genesis_validators_root,
                    &self.spec,
                )
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
        att: &Attestation<T::EthSpec>,
        state: &BeaconState<T::EthSpec>,
    ) -> bool {
        *filter_cache
            .entry((att.data.beacon_block_root, att.data.target.epoch))
            .or_insert_with(|| {
                self.shuffling_is_compatible(
                    &att.data.beacon_block_root,
                    att.data.target.epoch,
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
        let slots_per_epoch = T::EthSpec::slots_per_epoch();
        let shuffling_lookahead = 1 + self.spec.min_seed_lookahead.as_u64();

        // Shuffling can't have changed if we're in the first few epochs
        if state.current_epoch() < shuffling_lookahead {
            return true;
        }

        // Otherwise the shuffling is determined by the block at the end of the target epoch
        // minus the shuffling lookahead (usually 2). We call this the "pivot".
        let pivot_slot =
            if target_epoch == state.previous_epoch() || target_epoch == state.current_epoch() {
                (target_epoch - shuffling_lookahead).end_slot(slots_per_epoch)
            } else {
                return false;
            };

        let state_pivot_block_root = match state.get_block_root(pivot_slot) {
            Ok(root) => *root,
            Err(e) => {
                warn!(
                    &self.log,
                    "Missing pivot block root for attestation";
                    "slot" => pivot_slot,
                    "error" => ?e,
                );
                return false;
            }
        };

        // Use fork choice's view of the block DAG to quickly evaluate whether the attestation's
        // pivot block is the same as the current state's pivot block. If it is, then the
        // attestation's shuffling is the same as the current state's.
        // To account for skipped slots, find the first block at *or before* the pivot slot.
        let fork_choice_lock = self.fork_choice.read();
        let pivot_block_root = fork_choice_lock
            .proto_array()
            .core_proto_array()
            .iter_block_roots(block_root)
            .find(|(_, slot)| *slot <= pivot_slot)
            .map(|(block_root, _)| block_root);
        drop(fork_choice_lock);

        match pivot_block_root {
            Some(root) => root == state_pivot_block_root,
            None => {
                debug!(
                    &self.log,
                    "Discarding attestation because of missing ancestor";
                    "pivot_slot" => pivot_slot.as_u64(),
                    "block_root" => ?block_root,
                );
                false
            }
        }
    }

    /// Verify a voluntary exit before allowing it to propagate on the gossip network.
    pub fn verify_voluntary_exit_for_gossip(
        &self,
        exit: SignedVoluntaryExit,
    ) -> Result<ObservationOutcome<SignedVoluntaryExit>, Error> {
        // NOTE: this could be more efficient if it avoided cloning the head state
        let wall_clock_state = self.wall_clock_state()?;
        Ok(self
            .observed_voluntary_exits
            .lock()
            .verify_and_observe(exit, &wall_clock_state, &self.spec)
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
    pub fn import_voluntary_exit(&self, exit: SigVerifiedOp<SignedVoluntaryExit>) {
        if self.eth1_chain.is_some() {
            self.op_pool.insert_voluntary_exit(exit)
        }
    }

    /// Verify a proposer slashing before allowing it to propagate on the gossip network.
    pub fn verify_proposer_slashing_for_gossip(
        &self,
        proposer_slashing: ProposerSlashing,
    ) -> Result<ObservationOutcome<ProposerSlashing>, Error> {
        let wall_clock_state = self.wall_clock_state()?;
        Ok(self.observed_proposer_slashings.lock().verify_and_observe(
            proposer_slashing,
            &wall_clock_state,
            &self.spec,
        )?)
    }

    /// Accept some proposer slashing and queue it for inclusion in an appropriate block.
    pub fn import_proposer_slashing(&self, proposer_slashing: SigVerifiedOp<ProposerSlashing>) {
        if self.eth1_chain.is_some() {
            self.op_pool.insert_proposer_slashing(proposer_slashing)
        }
    }

    /// Verify an attester slashing before allowing it to propagate on the gossip network.
    pub fn verify_attester_slashing_for_gossip(
        &self,
        attester_slashing: AttesterSlashing<T::EthSpec>,
    ) -> Result<ObservationOutcome<AttesterSlashing<T::EthSpec>>, Error> {
        let wall_clock_state = self.wall_clock_state()?;
        Ok(self.observed_attester_slashings.lock().verify_and_observe(
            attester_slashing,
            &wall_clock_state,
            &self.spec,
        )?)
    }

    /// Accept some attester slashing and queue it for inclusion in an appropriate block.
    pub fn import_attester_slashing(
        &self,
        attester_slashing: SigVerifiedOp<AttesterSlashing<T::EthSpec>>,
    ) -> Result<(), Error> {
        if self.eth1_chain.is_some() {
            self.op_pool
                .insert_attester_slashing(attester_slashing, self.head_info()?.fork)
        }
        Ok(())
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
    pub fn process_chain_segment(
        &self,
        chain_segment: Vec<SignedBeaconBlock<T::EthSpec>>,
    ) -> ChainSegmentResult<T::EthSpec> {
        let mut filtered_chain_segment = Vec::with_capacity(chain_segment.len());
        let mut imported_blocks = 0;

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
                return ChainSegmentResult::Failed {
                    imported_blocks,
                    error: BlockError::InconsistentFork(e),
                };
            }

            let block_root = get_block_root(&block);

            if let Some((child_parent_root, child_slot)) = children.get(i) {
                // If this block has a child in this chain segment, ensure that its parent root matches
                // the root of this block.
                //
                // Without this check it would be possible to have a block verified using the
                // incorrect shuffling. That would be bad, mmkay.
                if block_root != *child_parent_root {
                    return ChainSegmentResult::Failed {
                        imported_blocks,
                        error: BlockError::NonLinearParentRoots,
                    };
                }

                // Ensure that the slots are strictly increasing throughout the chain segment.
                if *child_slot <= block.slot() {
                    return ChainSegmentResult::Failed {
                        imported_blocks,
                        error: BlockError::NonLinearSlots,
                    };
                }
            }

            match check_block_relevancy(&block, Some(block_root), self) {
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
                    return ChainSegmentResult::Failed {
                        imported_blocks,
                        error: BlockError::NotFinalizedDescendant { block_parent_root },
                    };
                }
                // If there was an error whilst determining if the block was invalid, return that
                // error.
                Err(BlockError::BeaconChainError(e)) => {
                    return ChainSegmentResult::Failed {
                        imported_blocks,
                        error: BlockError::BeaconChainError(e),
                    };
                }
                // If the block was decided to be irrelevant for any other reason, don't include
                // this block or any of it's children in the filtered chain segment.
                _ => break,
            }
        }

        while let Some((_root, block)) = filtered_chain_segment.first() {
            // Determine the epoch of the first block in the remaining segment.
            let start_epoch = block.slot().epoch(T::EthSpec::slots_per_epoch());

            // The `last_index` indicates the position of the last block that is in the current
            // epoch of `start_epoch`.
            let last_index = filtered_chain_segment
                .iter()
                .position(|(_root, block)| {
                    block.slot().epoch(T::EthSpec::slots_per_epoch()) > start_epoch
                })
                .unwrap_or(filtered_chain_segment.len());

            // Split off the first section blocks that are all either within the current epoch of
            // the first block. These blocks can all be signature-verified with the same
            // `BeaconState`.
            let mut blocks = filtered_chain_segment.split_off(last_index);
            std::mem::swap(&mut blocks, &mut filtered_chain_segment);

            // Verify the signature of the blocks, returning early if the signature is invalid.
            let signature_verified_blocks = match signature_verify_chain_segment(blocks, self) {
                Ok(blocks) => blocks,
                Err(error) => {
                    return ChainSegmentResult::Failed {
                        imported_blocks,
                        error,
                    };
                }
            };

            // Import the blocks into the chain.
            for signature_verified_block in signature_verified_blocks {
                match self.process_block(signature_verified_block) {
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
    pub fn verify_block_for_gossip(
        &self,
        block: SignedBeaconBlock<T::EthSpec>,
    ) -> Result<GossipVerifiedBlock<T>, BlockError<T::EthSpec>> {
        let slot = block.slot();
        let graffiti_string = block.message().body().graffiti().as_utf8_lossy();

        match GossipVerifiedBlock::new(block, self) {
            Ok(verified) => {
                debug!(
                    self.log,
                    "Successfully processed gossip block";
                    "graffiti" => graffiti_string,
                    "slot" => slot,
                    "root" => ?verified.block_root(),
                );

                Ok(verified)
            }
            Err(e) => {
                debug!(
                    self.log,
                    "Rejected gossip block";
                    "error" => e.to_string(),
                    "graffiti" => graffiti_string,
                    "slot" => slot,
                );

                Err(e)
            }
        }
    }

    /// Returns `Ok(block_root)` if the given `unverified_block` was successfully verified and
    /// imported into the chain.
    ///
    /// Items that implement `IntoFullyVerifiedBlock` include:
    ///
    /// - `SignedBeaconBlock`
    /// - `GossipVerifiedBlock`
    ///
    /// ## Errors
    ///
    /// Returns an `Err` if the given block was invalid, or an error was encountered during
    /// verification.
    pub fn process_block<B: IntoFullyVerifiedBlock<T>>(
        &self,
        unverified_block: B,
    ) -> Result<Hash256, BlockError<T::EthSpec>> {
        // Start the Prometheus timer.
        let _full_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_TIMES);

        // Increment the Prometheus counter for block processing requests.
        metrics::inc_counter(&metrics::BLOCK_PROCESSING_REQUESTS);

        // Clone the block so we can provide it to the event handler.
        let block = unverified_block.block().clone();

        // A small closure to group the verification and import errors.
        let import_block = |unverified_block: B| -> Result<Hash256, BlockError<T::EthSpec>> {
            let fully_verified = unverified_block.into_fully_verified_block(self)?;
            self.import_block(fully_verified)
        };

        // Verify and import the block.
        match import_block(unverified_block) {
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
                trace!(
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
    fn import_block(
        &self,
        fully_verified_block: FullyVerifiedBlock<T>,
    ) -> Result<Hash256, BlockError<T::EthSpec>> {
        let signed_block = fully_verified_block.block;
        let block_root = fully_verified_block.block_root;
        let mut state = fully_verified_block.state;
        let current_slot = self.slot()?;
        let current_epoch = current_slot.epoch(T::EthSpec::slots_per_epoch());
        let mut ops = fully_verified_block.confirmation_db_batch;
        let payload_verification_status = fully_verified_block.payload_verification_status;

        let attestation_observation_timer =
            metrics::start_timer(&metrics::BLOCK_PROCESSING_ATTESTATION_OBSERVATION);

        // Iterate through the attestations in the block and register them as an "observed
        // attestation". This will stop us from propagating them on the gossip network.
        for a in signed_block.message().body().attestations() {
            match self.observed_attestations.write().observe_item(a, None) {
                // If the observation was successful or if the slot for the attestation was too
                // low, continue.
                //
                // We ignore `SlotTooLow` since this will be very common whilst syncing.
                Ok(_) | Err(AttestationObservationError::SlotTooLow { .. }) => {}
                Err(e) => return Err(BlockError::BeaconChainError(e.into())),
            }
        }

        metrics::stop_timer(attestation_observation_timer);

        // If a slasher is configured, provide the attestations from the block.
        if let Some(slasher) = self.slasher.as_ref() {
            for attestation in signed_block.message().body().attestations() {
                let committee =
                    state.get_beacon_committee(attestation.data.slot, attestation.data.index)?;
                let indexed_attestation = get_indexed_attestation(committee.committee, attestation)
                    .map_err(|e| BlockError::BeaconChainError(e.into()))?;
                slasher.accept_attestation(indexed_attestation);
            }
        }

        // If there are new validators in this block, update our pubkey cache.
        //
        // We perform this _before_ adding the block to fork choice because the pubkey cache is
        // used by attestation processing which will only process an attestation if the block is
        // known to fork choice. This ordering ensure that the pubkey cache is always up-to-date.
        self.validator_pubkey_cache
            .try_write_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
            .ok_or(Error::ValidatorPubkeyCacheLockTimeout)?
            .import_new_pubkeys(&state)?;

        // For the current and next epoch of this state, ensure we have the shuffling from this
        // block in our cache.
        for relative_epoch in &[RelativeEpoch::Current, RelativeEpoch::Next] {
            let shuffling_id = AttestationShufflingId::new(block_root, &state, *relative_epoch)?;

            let shuffling_is_cached = self
                .shuffling_cache
                .try_read_for(ATTESTATION_CACHE_LOCK_TIMEOUT)
                .ok_or(Error::AttestationCacheLockTimeout)?
                .contains(&shuffling_id);

            if !shuffling_is_cached {
                state.build_committee_cache(*relative_epoch, &self.spec)?;
                let committee_cache = state.committee_cache(*relative_epoch)?;
                self.shuffling_cache
                    .try_write_for(ATTESTATION_CACHE_LOCK_TIMEOUT)
                    .ok_or(Error::AttestationCacheLockTimeout)?
                    .insert(shuffling_id, committee_cache);
            }
        }

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

        let mut fork_choice = self.fork_choice.write();

        // Do not import a block that doesn't descend from the finalized root.
        let signed_block =
            check_block_is_finalized_descendant::<T, _>(signed_block, &fork_choice, &self.store)?;
        let (block, block_signature) = signed_block.clone().deconstruct();

        // compare the existing finalized checkpoint with the incoming block's finalized checkpoint
        let old_finalized_checkpoint = fork_choice.finalized_checkpoint();
        let new_finalized_checkpoint = state.finalized_checkpoint();

        // Only perform the weak subjectivity check if it was configured.
        if let Some(wss_checkpoint) = self.config.weak_subjectivity_checkpoint {
            // This ensures we only perform the check once.
            if (old_finalized_checkpoint.epoch < wss_checkpoint.epoch)
                && (wss_checkpoint.epoch <= new_finalized_checkpoint.epoch)
            {
                if let Err(e) =
                    self.verify_weak_subjectivity_checkpoint(wss_checkpoint, block_root, &state)
                {
                    let mut shutdown_sender = self.shutdown_sender();
                    crit!(
                        self.log,
                        "Weak subjectivity checkpoint verification failed while importing block!";
                        "block_root" => ?block_root,
                        "parent_root" => ?block.parent_root(),
                        "old_finalized_epoch" => ?old_finalized_checkpoint.epoch,
                        "new_finalized_epoch" => ?new_finalized_checkpoint.epoch,
                        "weak_subjectivity_epoch" => ?wss_checkpoint.epoch,
                        "error" => ?e,
                    );
                    crit!(self.log, "You must use the `--purge-db` flag to clear the database and restart sync. You may be on a hostile network.");
                    shutdown_sender
                        .try_send(ShutdownReason::Failure(
                            "Weak subjectivity checkpoint verification failed. Provided block root is not a checkpoint."
                        ))
                        .map_err(|err| BlockError::BeaconChainError(BeaconChainError::WeakSubjectivtyShutdownError(err)))?;
                    return Err(BlockError::WeakSubjectivityConflict);
                }
            }
        }

        // Register the new block with the fork choice service.
        {
            let _fork_choice_block_timer =
                metrics::start_timer(&metrics::FORK_CHOICE_PROCESS_BLOCK_TIMES);
            let block_delay = self
                .slot_clock
                .seconds_from_current_slot_start(self.spec.seconds_per_slot)
                .ok_or(Error::UnableToComputeTimeAtSlot)?;

            fork_choice
                .on_block(
                    current_slot,
                    &block,
                    block_root,
                    block_delay,
                    &state,
                    payload_verification_status,
                    &self.spec,
                )
                .map_err(|e| BlockError::BeaconChainError(e.into()))?;
        }

        // Allow the validator monitor to learn about a new valid state.
        self.validator_monitor
            .write()
            .process_valid_state(current_slot.epoch(T::EthSpec::slots_per_epoch()), &state);
        let validator_monitor = self.validator_monitor.read();

        // Register each attestation in the block with the fork choice service.
        for attestation in block.body().attestations() {
            let _fork_choice_attestation_timer =
                metrics::start_timer(&metrics::FORK_CHOICE_PROCESS_ATTESTATION_TIMES);
            let attestation_target_epoch = attestation.data.target.epoch;

            let committee =
                state.get_beacon_committee(attestation.data.slot, attestation.data.index)?;
            let indexed_attestation = get_indexed_attestation(committee.committee, attestation)
                .map_err(|e| BlockError::BeaconChainError(e.into()))?;

            match fork_choice.on_attestation(
                current_slot,
                &indexed_attestation,
                AttestationFromBlock::True,
            ) {
                Ok(()) => Ok(()),
                // Ignore invalid attestations whilst importing attestations from a block. The
                // block might be very old and therefore the attestations useless to fork choice.
                Err(ForkChoiceError::InvalidAttestation(_)) => Ok(()),
                Err(e) => Err(BlockError::BeaconChainError(e.into())),
            }?;

            // To avoid slowing down sync, only register attestations for the
            // `observed_block_attesters` if they are from the previous epoch or later.
            if attestation_target_epoch + 1 >= current_epoch {
                let mut observed_block_attesters = self.observed_block_attesters.write();
                for &validator_index in &indexed_attestation.attesting_indices {
                    if let Err(e) = observed_block_attesters
                        .observe_validator(attestation_target_epoch, validator_index as usize)
                    {
                        debug!(
                            self.log,
                            "Failed to register observed block attester";
                            "error" => ?e,
                            "epoch" => attestation_target_epoch,
                            "validator_index" => validator_index,
                        )
                    }
                }
            }

            // Only register this with the validator monitor when the block is sufficiently close to
            // the current slot.
            if VALIDATOR_MONITOR_HISTORIC_EPOCHS as u64 * T::EthSpec::slots_per_epoch()
                + block.slot().as_u64()
                >= current_slot.as_u64()
            {
                match fork_choice.get_block(&block.parent_root()) {
                    Some(parent_block) => validator_monitor.register_attestation_in_block(
                        &indexed_attestation,
                        parent_block.slot,
                        &self.spec,
                    ),
                    None => warn!(self.log, "Failed to get parent block"; "slot" => %block.slot()),
                }
            }
        }

        // If the block is recent enough, check to see if it becomes the head block. If so, apply it
        // to the early attester cache. This will allow attestations to the block without waiting
        // for the block and state to be inserted to the database.
        //
        // Only performing this check on recent blocks avoids slowing down sync with lots of calls
        // to fork choice `get_head`.
        if block.slot() + EARLY_ATTESTER_CACHE_HISTORIC_SLOTS >= current_slot {
            let new_head_root = fork_choice
                .get_head(current_slot, &self.spec)
                .map_err(BeaconChainError::from)?;

            if new_head_root == block_root {
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
        }

        // Register sync aggregate with validator monitor
        if let Ok(sync_aggregate) = block.body().sync_aggregate() {
            // `SyncCommittee` for the sync_aggregate should correspond to the duty slot
            let duty_epoch = block.slot().epoch(T::EthSpec::slots_per_epoch());
            let sync_committee = self.sync_committee_at_epoch(duty_epoch)?;
            let participant_pubkeys = sync_committee
                .pubkeys
                .iter()
                .zip(sync_aggregate.sync_committee_bits.iter())
                .filter_map(|(pubkey, bit)| bit.then(|| pubkey))
                .collect::<Vec<_>>();

            validator_monitor.register_sync_aggregate_in_block(
                block.slot(),
                block.parent_root(),
                participant_pubkeys,
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

        drop(validator_monitor);

        // Only present some metrics for blocks from the previous epoch or later.
        //
        // This helps avoid noise in the metrics during sync.
        if block.slot().epoch(T::EthSpec::slots_per_epoch()) + 1 >= self.epoch()? {
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

        let db_write_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_DB_WRITE);

        // Store the block and its state, and execute the confirmation batch for the intermediate
        // states, which will delete their temporary flags.
        // If the write fails, revert fork choice to the version from disk, else we can
        // end up with blocks in fork choice that are missing from disk.
        // See https://github.com/sigp/lighthouse/issues/2028
        ops.push(StoreOp::PutBlock(block_root, Box::new(signed_block)));
        ops.push(StoreOp::PutState(block.state_root(), &state));
        let txn_lock = self.store.hot_db.begin_rw_transaction();

        if let Err(e) = self.store.do_atomically(ops) {
            error!(
                self.log,
                "Database write failed!";
                "msg" => "Restoring fork choice from disk",
                "error" => ?e,
            );
            match Self::load_fork_choice(self.store.clone())? {
                Some(persisted_fork_choice) => {
                    *fork_choice = persisted_fork_choice;
                }
                None => {
                    crit!(
                        self.log,
                        "No stored fork choice found to restore from";
                        "warning" => "The database is likely corrupt now, consider --purge-db"
                    );
                }
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
        let signed_block = SignedBeaconBlock::from_block(block, block_signature);

        self.snapshot_cache
            .try_write_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
            .ok_or(Error::SnapshotCacheLockTimeout)
            .map(|mut snapshot_cache| {
                snapshot_cache.insert(
                    BeaconSnapshot {
                        beacon_state: state,
                        beacon_block: signed_block,
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

        // Send an event to the `events` endpoint after fully processing the block.
        if let Some(event_handler) = self.event_handler.as_ref() {
            if event_handler.has_block_subscribers() {
                event_handler.register(EventKind::Block(SseBlock {
                    slot,
                    block: block_root,
                }));
            }
        }

        metrics::stop_timer(db_write_timer);

        metrics::inc_counter(&metrics::BLOCK_PROCESSING_SUCCESSES);

        let block_delay_total = get_slot_delay_ms(block_time_imported, slot, &self.slot_clock);

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

        // Inform the unknown block cache, in case it was waiting on this block.
        self.pre_finalization_block_cache
            .block_processed(block_root);

        Ok(block_root)
    }

    /// Produce a new block at the given `slot`.
    ///
    /// The produced block will not be inherently valid, it must be signed by a block producer.
    /// Block signing is out of the scope of this function and should be done by a separate program.
    pub fn produce_block<Payload: ExecPayload<T::EthSpec>>(
        &self,
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
    }

    /// Same as `produce_block` but allowing for configuration of RANDAO-verification.
    pub fn produce_block_with_verification<Payload: ExecPayload<T::EthSpec>>(
        &self,
        randao_reveal: Signature,
        slot: Slot,
        validator_graffiti: Option<Graffiti>,
        verification: ProduceBlockVerification,
    ) -> Result<BeaconBlockAndState<T::EthSpec, Payload>, BlockProductionError> {
        metrics::inc_counter(&metrics::BLOCK_PRODUCTION_REQUESTS);
        let _complete_timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_TIMES);

        // Producing a block requires the tree hash cache, so clone a full state corresponding to
        // the head from the snapshot cache. Unfortunately we can't move the snapshot out of the
        // cache (which would be fast), because we need to re-process the block after it has been
        // signed. If we miss the cache or we're producing a block that conflicts with the head,
        // fall back to getting the head from `slot - 1`.
        let state_load_timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_STATE_LOAD_TIMES);
        let head_info = self
            .head_info()
            .map_err(BlockProductionError::UnableToGetHeadInfo)?;
        let (state, state_root_opt) = if head_info.slot < slot {
            // Normal case: proposing a block atop the current head. Use the snapshot cache.
            if let Some(pre_state) = self
                .snapshot_cache
                .try_read_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
                .and_then(|snapshot_cache| {
                    snapshot_cache.get_state_for_block_production(head_info.block_root)
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

        self.produce_block_on_state::<Payload>(
            state,
            state_root_opt,
            slot,
            randao_reveal,
            validator_graffiti,
            verification,
        )
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
    pub fn produce_block_on_state<Payload: ExecPayload<T::EthSpec>>(
        &self,
        mut state: BeaconState<T::EthSpec>,
        state_root_opt: Option<Hash256>,
        produce_at_slot: Slot,
        randao_reveal: Signature,
        validator_graffiti: Option<Graffiti>,
        verification: ProduceBlockVerification,
    ) -> Result<BeaconBlockAndState<T::EthSpec, Payload>, BlockProductionError> {
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

        let (proposer_slashings, attester_slashings, voluntary_exits) =
            self.op_pool.get_slashings_and_exits(&state, &self.spec);

        let eth1_data = eth1_chain.eth1_data_for_block_production(&state, &self.spec)?;
        let deposits = eth1_chain
            .deposits_for_block_inclusion(&state, &eth1_data, &self.spec)?
            .into();

        // Iterate through the naive aggregation pool and ensure all the attestations from there
        // are included in the operation pool.
        let unagg_import_timer =
            metrics::start_timer(&metrics::BLOCK_PRODUCTION_UNAGGREGATED_TIMES);
        for attestation in self.naive_aggregation_pool.read().iter() {
            if let Err(e) = self.op_pool.insert_attestation(
                attestation.clone(),
                &state.fork(),
                state.genesis_validators_root(),
                &self.spec,
            ) {
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
        let prev_attestation_filter = |att: &&Attestation<T::EthSpec>| {
            self.filter_op_pool_attestation(&mut prev_filter_cache, *att, &state)
        };
        let mut curr_filter_cache = HashMap::new();
        let curr_attestation_filter = |att: &&Attestation<T::EthSpec>| {
            self.filter_op_pool_attestation(&mut curr_filter_cache, *att, &state)
        };

        let attestations = self
            .op_pool
            .get_attestations(
                &state,
                prev_attestation_filter,
                curr_attestation_filter,
                &self.spec,
            )
            .map_err(BlockProductionError::OpPoolError)?
            .into();
        drop(attestation_packing_timer);

        let slot = state.slot();
        let proposer_index = state.get_beacon_proposer_index(state.slot(), &self.spec)? as u64;

        // Closure to fetch a sync aggregate in cases where it is required.
        let get_sync_aggregate = || -> Result<SyncAggregate<_>, BlockProductionError> {
            Ok(self
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
                }))
        };

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
                    attestations,
                    deposits,
                    voluntary_exits: voluntary_exits.into(),
                    _phantom: PhantomData,
                },
            }),
            BeaconState::Altair(_) => {
                let sync_aggregate = get_sync_aggregate()?;
                BeaconBlock::Altair(BeaconBlockAltair {
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
                        attestations,
                        deposits,
                        voluntary_exits: voluntary_exits.into(),
                        sync_aggregate,
                        _phantom: PhantomData,
                    },
                })
            }
            BeaconState::Merge(_) => {
                let sync_aggregate = get_sync_aggregate()?;
                let execution_payload =
                    get_execution_payload::<T, Payload>(self, &state, proposer_index)?;
                BeaconBlock::Merge(BeaconBlockMerge {
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
                        attestations,
                        deposits,
                        voluntary_exits: voluntary_exits.into(),
                        sync_aggregate,
                        execution_payload,
                    },
                })
            }
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
        per_block_processing(
            &mut state,
            &block,
            None,
            signature_strategy,
            VerifyBlockRoot::True,
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
    pub fn process_invalid_execution_payload(
        &self,
        op: &InvalidationOperation,
    ) -> Result<(), Error> {
        debug!(
            self.log,
            "Invalid execution payload in block";
            "latest_valid_ancestor" => ?op.latest_valid_ancestor(),
            "block_root" => ?op.block_root(),
        );

        // Update fork choice.
        if let Err(e) = self.fork_choice.write().on_invalid_execution_payload(op) {
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
        //
        // Don't return early though, since invalidating the justified checkpoint might cause an
        // error here.
        if let Err(e) = self.fork_choice() {
            crit!(
                self.log,
                "Failed to run fork choice routine";
                "error" => ?e,
            );
        }

        // Atomically obtain the justified root from fork choice.
        let justified_block = self.fork_choice.read().get_justified_block()?;

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

    /// Execute the fork choice algorithm and enthrone the result as the canonical head.
    pub fn fork_choice(&self) -> Result<(), Error> {
        metrics::inc_counter(&metrics::FORK_CHOICE_REQUESTS);
        let _timer = metrics::start_timer(&metrics::FORK_CHOICE_TIMES);

        let result = self.fork_choice_internal();

        if result.is_err() {
            metrics::inc_counter(&metrics::FORK_CHOICE_ERRORS);
        }

        result
    }

    fn fork_choice_internal(&self) -> Result<(), Error> {
        // Atomically obtain the head block root and the finalized block.
        let (beacon_block_root, finalized_block) = {
            let mut fork_choice = self.fork_choice.write();

            // Determine the root of the block that is the head of the chain.
            let beacon_block_root = fork_choice.get_head(self.slot()?, &self.spec)?;

            (beacon_block_root, fork_choice.get_finalized_block()?)
        };

        let current_head = self.head_info()?;
        let old_finalized_checkpoint = current_head.finalized_checkpoint;

        // Exit early if the head hasn't changed.
        if beacon_block_root == current_head.block_root {
            return Ok(());
        }

        // Check to ensure that this finalized block hasn't been marked as invalid.
        if let ExecutionStatus::Invalid(block_hash) = finalized_block.execution_status {
            crit!(
                self.log,
                "Finalized block has an invalid payload";
                "msg" => "You must use the `--purge-db` flag to clear the database and restart sync. \
                You may be on a hostile network.",
                "block_hash" => ?block_hash
            );
            let mut shutdown_sender = self.shutdown_sender();
            shutdown_sender
                .try_send(ShutdownReason::Failure(
                    "Finalized block has an invalid execution payload.",
                ))
                .map_err(BeaconChainError::InvalidFinalizedPayloadShutdownError)?;

            // Exit now, the node is in an invalid state.
            return Err(Error::InvalidFinalizedPayload {
                finalized_root: finalized_block.root,
                execution_block_hash: block_hash,
            });
        }

        let lag_timer = metrics::start_timer(&metrics::FORK_CHOICE_SET_HEAD_LAG_TIMES);

        // At this point we know that the new head block is not the same as the previous one
        metrics::inc_counter(&metrics::FORK_CHOICE_CHANGED_HEAD);

        // Try and obtain the snapshot for `beacon_block_root` from the snapshot cache, falling
        // back to a database read if that fails.
        let new_head = self
            .snapshot_cache
            .try_read_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
            .and_then(|snapshot_cache| {
                snapshot_cache.get_cloned(beacon_block_root, CloneConfig::committee_caches_only())
            })
            .map::<Result<_, Error>, _>(Ok)
            .unwrap_or_else(|| {
                let beacon_block = self
                    .get_block(&beacon_block_root)?
                    .ok_or(Error::MissingBeaconBlock(beacon_block_root))?;

                let beacon_state_root = beacon_block.state_root();
                let beacon_state: BeaconState<T::EthSpec> = self
                    .get_state(&beacon_state_root, Some(beacon_block.slot()))?
                    .ok_or(Error::MissingBeaconState(beacon_state_root))?;

                Ok(BeaconSnapshot {
                    beacon_block,
                    beacon_block_root,
                    beacon_state,
                })
            })
            .and_then(|mut snapshot| {
                // Regardless of where we got the state from, attempt to build the committee
                // caches.
                snapshot
                    .beacon_state
                    .build_all_committee_caches(&self.spec)
                    .map_err(Into::into)
                    .map(|()| snapshot)
            })?;

        // Attempt to detect if the new head is not on the same chain as the previous block
        // (i.e., a re-org).
        //
        // Note: this will declare a re-org if we skip `SLOTS_PER_HISTORICAL_ROOT` blocks
        // between calls to fork choice without swapping between chains. This seems like an
        // extreme-enough scenario that a warning is fine.
        let is_reorg = new_head
            .beacon_state
            .get_block_root(current_head.slot)
            .map_or(true, |root| *root != current_head.block_root);

        let mut reorg_distance = Slot::new(0);

        if is_reorg {
            match self.find_reorg_slot(&new_head.beacon_state, new_head.beacon_block_root) {
                Ok(slot) => reorg_distance = current_head.slot.saturating_sub(slot),
                Err(e) => {
                    warn!(
                        self.log,
                        "Could not find re-org depth";
                        "error" => format!("{:?}", e),
                    );
                }
            }

            metrics::inc_counter(&metrics::FORK_CHOICE_REORG_COUNT);
            metrics::inc_counter(&metrics::FORK_CHOICE_REORG_COUNT_INTEROP);
            warn!(
                self.log,
                "Beacon chain re-org";
                "previous_head" => ?current_head.block_root,
                "previous_slot" => current_head.slot,
                "new_head_parent" => ?new_head.beacon_block.parent_root(),
                "new_head" => ?beacon_block_root,
                "new_slot" => new_head.beacon_block.slot(),
                "reorg_distance" => reorg_distance,
            );
        } else {
            debug!(
                self.log,
                "Head beacon block";
                "justified_root" => ?new_head.beacon_state.current_justified_checkpoint().root,
                "justified_epoch" => new_head.beacon_state.current_justified_checkpoint().epoch,
                "finalized_root" => ?new_head.beacon_state.finalized_checkpoint().root,
                "finalized_epoch" => new_head.beacon_state.finalized_checkpoint().epoch,
                "root" => ?beacon_block_root,
                "slot" => new_head.beacon_block.slot(),
            );
        };

        let new_finalized_checkpoint = new_head.beacon_state.finalized_checkpoint();

        // It is an error to try to update to a head with a lesser finalized epoch.
        if new_finalized_checkpoint.epoch < old_finalized_checkpoint.epoch {
            return Err(Error::RevertedFinalizedEpoch {
                previous_epoch: old_finalized_checkpoint.epoch,
                new_epoch: new_finalized_checkpoint.epoch,
            });
        }

        let is_epoch_transition = current_head.slot.epoch(T::EthSpec::slots_per_epoch())
            < new_head
                .beacon_state
                .slot()
                .epoch(T::EthSpec::slots_per_epoch());

        let update_head_timer = metrics::start_timer(&metrics::UPDATE_HEAD_TIMES);

        // These fields are used for server-sent events.
        let state_root = new_head.beacon_state_root();
        let head_slot = new_head.beacon_state.slot();
        let head_proposer_index = new_head.beacon_block.message().proposer_index();
        let proposer_graffiti = new_head
            .beacon_block
            .message()
            .body()
            .graffiti()
            .as_utf8_lossy();

        // Find the dependent roots associated with this head before updating the snapshot. This
        // is to ensure consistency when sending server sent events later in this method.
        let dependent_root = new_head
            .beacon_state
            .proposer_shuffling_decision_root(self.genesis_block_root);
        let prev_dependent_root = new_head
            .beacon_state
            .attester_shuffling_decision_root(self.genesis_block_root, RelativeEpoch::Current);

        // Used later for the execution engine.
        let is_merge_transition_complete = is_merge_transition_complete(&new_head.beacon_state);

        drop(lag_timer);

        // Clear the early attester cache in case it conflicts with `self.canonical_head`.
        self.early_attester_cache.clear();

        // Update the snapshot that stores the head of the chain at the time it received the
        // block.
        *self
            .canonical_head
            .try_write_for(HEAD_LOCK_TIMEOUT)
            .ok_or(Error::CanonicalHeadLockTimeout)? = new_head;

        // The block has now been set as head so we can record times and delays.
        metrics::stop_timer(update_head_timer);

        let block_time_set_as_head = timestamp_now();

        // Calculate the total delay between the start of the slot and when it was set as head.
        let block_delay_total =
            get_slot_delay_ms(block_time_set_as_head, head_slot, &self.slot_clock);

        // Do not write to the cache for blocks older than 2 epochs, this helps reduce writes to
        // the cache during sync.
        if block_delay_total < self.slot_clock.slot_duration() * 64 {
            self.block_times_cache.write().set_time_set_as_head(
                beacon_block_root,
                current_head.slot,
                block_time_set_as_head,
            );
        }

        // If a block comes in from over 4 slots ago, it is most likely a block from sync.
        let block_from_sync = block_delay_total > self.slot_clock.slot_duration() * 4;

        // Determine whether the block has been set as head too late for proper attestation
        // production.
        let late_head = block_delay_total >= self.slot_clock.unagg_attestation_production_delay();

        // Do not store metrics if the block was > 4 slots old, this helps prevent noise during
        // sync.
        if !block_from_sync {
            // Observe the total block delay. This is the delay between the time the slot started
            // and when the block was set as head.
            metrics::observe_duration(
                &metrics::BEACON_BLOCK_HEAD_SLOT_START_DELAY_TIME,
                block_delay_total,
            );

            // Observe the delay between when we imported the block and when we set the block as
            // head.
            let block_delays = self.block_times_cache.read().get_block_delays(
                beacon_block_root,
                self.slot_clock
                    .start_of(head_slot)
                    .unwrap_or_else(|| Duration::from_secs(0)),
            );

            metrics::observe_duration(
                &metrics::BEACON_BLOCK_OBSERVED_SLOT_START_DELAY_TIME,
                block_delays
                    .observed
                    .unwrap_or_else(|| Duration::from_secs(0)),
            );

            metrics::observe_duration(
                &metrics::BEACON_BLOCK_HEAD_IMPORTED_DELAY_TIME,
                block_delays
                    .set_as_head
                    .unwrap_or_else(|| Duration::from_secs(0)),
            );

            // If the block was enshrined as head too late for attestations to be created for it,
            // log a debug warning and increment a metric.
            if late_head {
                metrics::inc_counter(&metrics::BEACON_BLOCK_HEAD_SLOT_START_DELAY_EXCEEDED_TOTAL);
                debug!(
                    self.log,
                    "Delayed head block";
                    "block_root" => ?beacon_block_root,
                    "proposer_index" => head_proposer_index,
                    "slot" => head_slot,
                    "block_delay" => ?block_delay_total,
                    "observed_delay" => ?block_delays.observed,
                    "imported_delay" => ?block_delays.imported,
                    "set_as_head_delay" => ?block_delays.set_as_head,
                );
            }
        }

        self.snapshot_cache
            .try_write_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
            .map(|mut snapshot_cache| {
                snapshot_cache.update_head(beacon_block_root);
            })
            .unwrap_or_else(|| {
                error!(
                    self.log,
                    "Failed to obtain cache write lock";
                    "lock" => "snapshot_cache",
                    "task" => "update head"
                );
            });

        if is_epoch_transition || is_reorg {
            self.persist_head_and_fork_choice()?;
            self.op_pool.prune_attestations(self.epoch()?);
        }

        if new_finalized_checkpoint.epoch != old_finalized_checkpoint.epoch {
            // Due to race conditions, it's technically possible that the head we load here is
            // different to the one earlier in this function.
            //
            // Since the head can't move backwards in terms of finalized epoch, we can only load a
            // head with a *later* finalized state. There is no harm in this.
            let head = self
                .canonical_head
                .try_read_for(HEAD_LOCK_TIMEOUT)
                .ok_or(Error::CanonicalHeadLockTimeout)?;

            // State root of the finalized state on the epoch boundary, NOT the state
            // of the finalized block. We need to use an iterator in case the state is beyond
            // the reach of the new head's `state_roots` array.
            let new_finalized_slot = head
                .beacon_state
                .finalized_checkpoint()
                .epoch
                .start_slot(T::EthSpec::slots_per_epoch());
            let new_finalized_state_root = process_results(
                StateRootsIterator::new(&self.store, &head.beacon_state),
                |mut iter| {
                    iter.find_map(|(state_root, slot)| {
                        if slot == new_finalized_slot {
                            Some(state_root)
                        } else {
                            None
                        }
                    })
                },
            )?
            .ok_or(Error::MissingFinalizedStateRoot(new_finalized_slot))?;

            self.after_finalization(&head.beacon_state, new_finalized_state_root)?;
        }

        // Register a server-sent event if necessary
        if let Some(event_handler) = self.event_handler.as_ref() {
            if event_handler.has_head_subscribers() {
                match (dependent_root, prev_dependent_root) {
                    (Ok(current_duty_dependent_root), Ok(previous_duty_dependent_root)) => {
                        event_handler.register(EventKind::Head(SseHead {
                            slot: head_slot,
                            block: beacon_block_root,
                            state: state_root,
                            current_duty_dependent_root,
                            previous_duty_dependent_root,
                            epoch_transition: is_epoch_transition,
                        }));
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        warn!(
                            self.log,
                            "Unable to find dependent roots, cannot register head event";
                            "error" => ?e
                        );
                    }
                }
            }

            if is_reorg && event_handler.has_reorg_subscribers() {
                event_handler.register(EventKind::ChainReorg(SseChainReorg {
                    slot: head_slot,
                    depth: reorg_distance.as_u64(),
                    old_head_block: current_head.block_root,
                    old_head_state: current_head.state_root,
                    new_head_block: beacon_block_root,
                    new_head_state: state_root,
                    epoch: head_slot.epoch(T::EthSpec::slots_per_epoch()),
                }));
            }

            if !block_from_sync && late_head && event_handler.has_late_head_subscribers() {
                let peer_info = self
                    .block_times_cache
                    .read()
                    .get_peer_info(beacon_block_root);
                let block_delays = self.block_times_cache.read().get_block_delays(
                    beacon_block_root,
                    self.slot_clock
                        .start_of(head_slot)
                        .unwrap_or_else(|| Duration::from_secs(0)),
                );
                event_handler.register(EventKind::LateHead(SseLateHead {
                    slot: head_slot,
                    block: beacon_block_root,
                    peer_id: peer_info.id,
                    peer_client: peer_info.client,
                    proposer_index: head_proposer_index,
                    proposer_graffiti,
                    block_delay: block_delay_total,
                    observed_delay: block_delays.observed,
                    imported_delay: block_delays.imported,
                    set_as_head_delay: block_delays.set_as_head,
                }));
            }
        }

        // If this is a post-merge block, update the execution layer.
        if is_merge_transition_complete {
            let current_slot = self.slot()?;

            if let Err(e) = self.update_execution_engine_forkchoice_blocking(current_slot) {
                crit!(
                    self.log,
                    "Failed to update execution head";
                    "error" => ?e
                );
            }

            // Performing this call immediately after
            // `update_execution_engine_forkchoice_blocking` might result in two calls to fork
            // choice updated, one *without* payload attributes and then a second *with*
            // payload attributes.
            //
            // This seems OK. It's not a significant waste of EL<>CL bandwidth or resources, as
            // far as I know.
            if let Err(e) = self.prepare_beacon_proposer_blocking() {
                crit!(
                    self.log,
                    "Failed to prepare proposers after fork choice";
                    "error" => ?e
                );
            }
        }

        Ok(())
    }

    pub fn prepare_beacon_proposer_blocking(&self) -> Result<(), Error> {
        let execution_layer = self
            .execution_layer
            .as_ref()
            .ok_or(Error::ExecutionLayerMissing)?;

        execution_layer
            .block_on_generic(|_| self.prepare_beacon_proposer_async())
            .map_err(Error::PrepareProposerBlockingFailed)?
    }

    /// Determines the beacon proposer for the next slot. If that proposer is registered in the
    /// `execution_layer`, provide the `execution_layer` with the necessary information to produce
    /// `PayloadAttributes` for future calls to fork choice.
    ///
    /// The `PayloadAttributes` are used by the EL to give it a look-ahead for preparing an optimal
    /// set of transactions for a new `ExecutionPayload`.
    ///
    /// This function will result in a call to `forkchoiceUpdated` on the EL if:
    ///
    /// 1. We're in the tail-end of the slot (as defined by PAYLOAD_PREPARATION_LOOKAHEAD_FACTOR)
    /// 2. The head block is one slot (or less) behind the prepare slot (e.g., we're preparing for
    ///    the next slot and the block at the current slot is already known).
    pub async fn prepare_beacon_proposer_async(&self) -> Result<(), Error> {
        let execution_layer = self
            .execution_layer
            .clone()
            .ok_or(Error::ExecutionLayerMissing)?;

        // Nothing to do if there are no proposers registered with the EL, exit early to avoid
        // wasting cycles.
        if !execution_layer.has_any_proposer_preparation_data().await {
            return Ok(());
        }

        let head = self.head_info()?;
        let current_slot = self.slot()?;

        // Don't bother with proposer prep if the head is more than
        // `PREPARE_PROPOSER_HISTORIC_EPOCHS` prior to the current slot.
        //
        // This prevents the routine from running during sync.
        if head.slot + T::EthSpec::slots_per_epoch() * PREPARE_PROPOSER_HISTORIC_EPOCHS
            < current_slot
        {
            debug!(
                self.log,
                "Head too old for proposer prep";
                "head_slot" => head.slot,
                "current_slot" => current_slot,
            );
            return Ok(());
        }

        // We only start to push preparation data for some chain *after* the transition block
        // has been imported.
        //
        // There is no payload preparation for the transition block (i.e., the first block with
        // execution enabled in some chain).
        if head.execution_payload_block_hash.is_none() {
            return Ok(());
        };

        let head_epoch = head.slot.epoch(T::EthSpec::slots_per_epoch());
        let prepare_slot = current_slot + 1;
        let prepare_epoch = prepare_slot.epoch(T::EthSpec::slots_per_epoch());

        // Ensure that the shuffling decision root is correct relative to the epoch we wish to
        // query.
        let shuffling_decision_root = if head_epoch == prepare_epoch {
            head.proposer_shuffling_decision_root
        } else {
            head.block_root
        };

        // Read the proposer from the proposer cache.
        let cached_proposer = self
            .beacon_proposer_cache
            .lock()
            .get_slot::<T::EthSpec>(shuffling_decision_root, prepare_slot);
        let proposer = if let Some(proposer) = cached_proposer {
            proposer.index
        } else {
            if head_epoch + 2 < prepare_epoch {
                warn!(
                    self.log,
                    "Skipping proposer preparation";
                    "msg" => "this is a non-critical issue that can happen on unhealthy nodes or \
                              networks.",
                    "prepare_epoch" => prepare_epoch,
                    "head_epoch" => head_epoch,
                );

                // Don't skip the head forward more than two epochs. This avoids burdening an
                // unhealthy node.
                //
                // Although this node might miss out on preparing for a proposal, they should still
                // be able to propose. This will prioritise beacon chain health over efficient
                // packing of execution blocks.
                return Ok(());
            }

            let (proposers, decision_root, fork) =
                compute_proposer_duties_from_head(prepare_epoch, self)?;

            let proposer_index = prepare_slot.as_usize() % (T::EthSpec::slots_per_epoch() as usize);
            let proposer = *proposers
                .get(proposer_index)
                .ok_or(BeaconChainError::NoProposerForSlot(prepare_slot))?;

            self.beacon_proposer_cache.lock().insert(
                prepare_epoch,
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
                return Ok(());
            }

            proposer
        };

        // If the execution layer doesn't have any proposer data for this validator then we assume
        // it's not connected to this BN and no action is required.
        if !execution_layer
            .has_proposer_preparation_data(proposer as u64)
            .await
        {
            return Ok(());
        }

        let payload_attributes = PayloadAttributes {
            timestamp: self
                .slot_clock
                .start_of(prepare_slot)
                .ok_or(Error::InvalidSlot(prepare_slot))?
                .as_secs(),
            prev_randao: head.random,
            suggested_fee_recipient: execution_layer
                .get_suggested_fee_recipient(proposer as u64)
                .await,
        };

        debug!(
            self.log,
            "Preparing beacon proposer";
            "payload_attributes" => ?payload_attributes,
            "head_root" => ?head.block_root,
            "prepare_slot" => prepare_slot,
            "validator" => proposer,
        );

        let already_known = execution_layer
            .insert_proposer(
                prepare_slot,
                head.block_root,
                proposer as u64,
                payload_attributes,
            )
            .await;
        // Only push a log to the user if this is the first time we've seen this proposer for this
        // slot.
        if !already_known {
            info!(
                self.log,
                "Prepared beacon proposer";
                "already_known" => already_known,
                "prepare_slot" => prepare_slot,
                "validator" => proposer,
            );
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

        // If either of the following are true, send a fork-choice update message to the
        // EL:
        //
        // 1. We're in the tail-end of the slot (as defined by
        //    PAYLOAD_PREPARATION_LOOKAHEAD_FACTOR)
        // 2. The head block is one slot (or less) behind the prepare slot (e.g., we're
        //    preparing for the next slot and the block at the current slot is already
        //    known).
        if till_prepare_slot
            <= self.slot_clock.slot_duration() / PAYLOAD_PREPARATION_LOOKAHEAD_FACTOR
            || head.slot + 1 >= prepare_slot
        {
            debug!(
                self.log,
                "Pushing update to prepare proposer";
                "till_prepare_slot" => ?till_prepare_slot,
                "prepare_slot" => prepare_slot
            );

            // Use the blocking method here so that we don't form a queue of these functions when
            // routinely calling them.
            self.update_execution_engine_forkchoice_async(current_slot)
                .await?;
        }

        Ok(())
    }

    pub fn update_execution_engine_forkchoice_blocking(
        &self,
        current_slot: Slot,
    ) -> Result<(), Error> {
        let execution_layer = self
            .execution_layer
            .as_ref()
            .ok_or(Error::ExecutionLayerMissing)?;

        execution_layer
            .block_on_generic(|_| self.update_execution_engine_forkchoice_async(current_slot))
            .map_err(Error::ForkchoiceUpdate)?
    }

    pub async fn update_execution_engine_forkchoice_async(
        &self,
        current_slot: Slot,
    ) -> Result<(), Error> {
        let execution_layer = self
            .execution_layer
            .as_ref()
            .ok_or(Error::ExecutionLayerMissing)?;

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

        // Deadlock warning:
        //
        // We are taking the `self.fork_choice` lock whilst holding the `forkchoice_lock`. This
        // is intentional, since it allows us to ensure a consistent ordering of messages to the
        // execution layer.
        let (head_block_root, head_hash, finalized_hash) =
            if let Some(params) = self.fork_choice.read().get_forkchoice_update_parameters() {
                if let Some(head_hash) = params.head_hash {
                    (
                        params.head_root,
                        head_hash,
                        params
                            .finalized_hash
                            .unwrap_or_else(ExecutionBlockHash::zero),
                    )
                } else {
                    // The head block does not have an execution block hash, there is no need to
                    // send an update to the EL.
                    return Ok(());
                }
            } else {
                warn!(
                    self.log,
                    "Missing forkchoice params";
                    "msg" => "please report this non-critical bug"
                );
                return Ok(());
            };

        let forkchoice_updated_response = self
            .execution_layer
            .as_ref()
            .ok_or(Error::ExecutionLayerMissing)?
            .notify_forkchoice_updated(head_hash, finalized_hash, current_slot, head_block_root)
            .await
            .map_err(Error::ExecutionForkChoiceUpdateFailed);

        // The head has been read and the execution layer has been updated. It is now valid to send
        // another fork choice update.
        drop(forkchoice_lock);

        match forkchoice_updated_response {
            Ok(status) => match &status {
                PayloadStatus::Valid | PayloadStatus::Syncing => Ok(()),
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
                    latest_valid_hash, ..
                } => {
                    warn!(
                        self.log,
                        "Fork choice update invalidated payload";
                        "status" => ?status
                    );
                    // The execution engine has stated that all blocks between the
                    // `head_execution_block_hash` and `latest_valid_hash` are invalid.
                    self.process_invalid_execution_payload(
                        &InvalidationOperation::InvalidateMany {
                            head_block_root,
                            always_invalidate_head: true,
                            latest_valid_ancestor: *latest_valid_hash,
                        },
                    )?;

                    Err(BeaconChainError::ExecutionForkChoiceUpdateInvalid { status })
                }
                PayloadStatus::InvalidTerminalBlock { .. }
                | PayloadStatus::InvalidBlockHash { .. } => {
                    warn!(
                        self.log,
                        "Fork choice update invalidated payload";
                        "status" => ?status
                    );
                    // The execution engine has stated that the head block is invalid, however it
                    // hasn't returned a latest valid ancestor.
                    //
                    // Using a `None` latest valid ancestor will result in only the head block
                    // being invalidated (no ancestors).
                    self.process_invalid_execution_payload(
                        &InvalidationOperation::InvalidateOne {
                            block_root: head_block_root,
                        },
                    )?;

                    Err(BeaconChainError::ExecutionForkChoiceUpdateInvalid { status })
                }
            },
            Err(e) => Err(e),
        }
    }

    /// Returns the status of the current head block, regarding the validity of the execution
    /// payload.
    pub fn head_safety_status(&self) -> Result<HeadSafetyStatus, BeaconChainError> {
        let head = self.head_info()?;
        let head_block = self
            .fork_choice
            .read()
            .get_block(&head.block_root)
            .ok_or(BeaconChainError::HeadMissingFromForkChoice(head.block_root))?;

        let status = match head_block.execution_status {
            ExecutionStatus::Valid(block_hash) => HeadSafetyStatus::Safe(Some(block_hash)),
            ExecutionStatus::Invalid(block_hash) => HeadSafetyStatus::Invalid(block_hash),
            ExecutionStatus::Unknown(block_hash) => HeadSafetyStatus::Unsafe(block_hash),
            ExecutionStatus::Irrelevant(_) => HeadSafetyStatus::Safe(None),
        };

        Ok(status)
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
    /// Performs slot-based pruning.
    pub fn per_slot_task(&self) {
        trace!(self.log, "Running beacon chain per slot tasks");
        if let Some(slot) = self.slot_clock.now() {
            self.naive_aggregation_pool.write().prune(slot);
            self.block_times_cache.write().prune(slot);
        }
    }

    /// Called after `self` has had a new block finalized.
    ///
    /// Performs pruning and finality-based optimizations.
    fn after_finalization(
        &self,
        head_state: &BeaconState<T::EthSpec>,
        new_finalized_state_root: Hash256,
    ) -> Result<(), Error> {
        self.fork_choice.write().prune()?;
        let new_finalized_checkpoint = head_state.finalized_checkpoint();

        self.observed_block_producers.write().prune(
            new_finalized_checkpoint
                .epoch
                .start_slot(T::EthSpec::slots_per_epoch()),
        );

        self.snapshot_cache
            .try_write_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
            .map(|mut snapshot_cache| {
                snapshot_cache.prune(new_finalized_checkpoint.epoch);
                debug!(
                    self.log,
                    "Snapshot cache pruned";
                    "new_len" => snapshot_cache.len(),
                    "remaining_roots" => ?snapshot_cache.beacon_block_roots(),
                );
            })
            .unwrap_or_else(|| {
                error!(
                    self.log,
                    "Failed to obtain cache write lock";
                    "lock" => "snapshot_cache",
                    "task" => "prune"
                );
            });

        self.op_pool.prune_all(head_state, self.epoch()?);

        self.store_migrator.process_finalization(
            new_finalized_state_root.into(),
            new_finalized_checkpoint,
            self.head_tracker.clone(),
        )?;

        self.attester_cache
            .prune_below(new_finalized_checkpoint.epoch);

        if let Some(event_handler) = self.event_handler.as_ref() {
            if event_handler.has_finalized_subscribers() {
                event_handler.register(EventKind::FinalizedCheckpoint(SseFinalizedCheckpoint {
                    epoch: new_finalized_checkpoint.epoch,
                    block: new_finalized_checkpoint.root,
                    state: new_finalized_state_root,
                }));
            }
        }

        Ok(())
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
    pub(crate) fn with_committee_cache<F, R>(
        &self,
        head_block_root: Hash256,
        shuffling_epoch: Epoch,
        map_fn: F,
    ) -> Result<R, Error>
    where
        F: Fn(&CommitteeCache, Hash256) -> Result<R, Error>,
    {
        let head_block = self
            .fork_choice
            .read()
            .get_block(&head_block_root)
            .ok_or(Error::MissingBeaconBlock(head_block_root))?;

        let shuffling_id = BlockShufflingIds {
            current: head_block.current_epoch_shuffling_id.clone(),
            next: head_block.next_epoch_shuffling_id.clone(),
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

        if let Some(committee_cache) = shuffling_cache.get(&shuffling_id) {
            map_fn(committee_cache, shuffling_id.shuffling_decision_block)
        } else {
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
                let state_root = head_block.state_root;
                let state = self
                    .store
                    .get_inconsistent_state_for_attestation_verification_only(
                        &state_root,
                        Some(head_block.slot),
                    )?
                    .ok_or(Error::MissingBeaconState(head_block.state_root))?;
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

            let committee_cache = state.committee_cache(relative_epoch)?;
            let shuffling_decision_block = shuffling_id.shuffling_decision_block;

            self.shuffling_cache
                .try_write_for(ATTESTATION_CACHE_LOCK_TIMEOUT)
                .ok_or(Error::AttestationCacheLockTimeout)?
                .insert(shuffling_id, committee_cache);

            metrics::stop_timer(committee_building_timer);

            map_fn(committee_cache, shuffling_decision_block)
        }
    }

    /// Dumps the entire canonical chain, from the head to genesis to a vector for analysis.
    ///
    /// This could be a very expensive operation and should only be done in testing/analysis
    /// activities.
    pub fn chain_dump(&self) -> Result<Vec<BeaconSnapshot<T::EthSpec>>, Error> {
        let mut dump = vec![];

        let mut last_slot = BeaconSnapshot {
            beacon_block: self.head()?.beacon_block,
            beacon_block_root: self.head()?.beacon_block_root,
            beacon_state: self.head()?.beacon_state,
        };

        dump.push(last_slot.clone());

        loop {
            let beacon_block_root = last_slot.beacon_block.parent_root();

            if beacon_block_root == Hash256::zero() {
                break; // Genesis has been reached.
            }

            let beacon_block = self.store.get_block(&beacon_block_root)?.ok_or_else(|| {
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
                beacon_block,
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

    pub fn dump_as_dot<W: Write>(&self, output: &mut W) {
        let canonical_head_hash = self
            .canonical_head
            .try_read_for(HEAD_LOCK_TIMEOUT)
            .ok_or(Error::CanonicalHeadLockTimeout)
            .unwrap()
            .beacon_block_root;
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
                    let block = self.get_block(&block_hash).unwrap().unwrap();
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
