use crate::attestation_verification::{
    Error as AttestationError, SignatureVerifiedAttestation, VerifiedAggregatedAttestation,
    VerifiedUnaggregatedAttestation,
};
use crate::block_verification::{
    check_block_is_finalized_descendant, check_block_relevancy, get_block_root,
    signature_verify_chain_segment, BlockError, FullyVerifiedBlock, GossipVerifiedBlock,
    IntoFullyVerifiedBlock,
};
use crate::chain_config::ChainConfig;
use crate::errors::{BeaconChainError as Error, BlockProductionError};
use crate::eth1_chain::{Eth1Chain, Eth1ChainBackend};
use crate::events::{EventHandler, EventKind};
use crate::head_tracker::HeadTracker;
use crate::migrate::BackgroundMigrator;
use crate::naive_aggregation_pool::{Error as NaiveAggregationError, NaiveAggregationPool};
use crate::observed_attestations::{Error as AttestationObservationError, ObservedAttestations};
use crate::observed_attesters::{ObservedAggregators, ObservedAttesters};
use crate::observed_block_producers::ObservedBlockProducers;
use crate::observed_operations::{ObservationOutcome, ObservedOperations};
use crate::persisted_beacon_chain::{PersistedBeaconChain, DUMMY_CANONICAL_HEAD_BLOCK_ROOT};
use crate::persisted_fork_choice::PersistedForkChoice;
use crate::shuffling_cache::{BlockShufflingIds, ShufflingCache};
use crate::snapshot_cache::SnapshotCache;
use crate::timeout_rw_lock::TimeoutRwLock;
use crate::validator_pubkey_cache::ValidatorPubkeyCache;
use crate::BeaconForkChoiceStore;
use crate::BeaconSnapshot;
use crate::{metrics, BeaconChainError};
use fork_choice::ForkChoice;
use futures::channel::mpsc::Sender;
use itertools::process_results;
use operation_pool::{OperationPool, PersistedOperationPool};
use parking_lot::{Mutex, RwLock};
use slasher::Slasher;
use slog::{crit, debug, error, info, trace, warn, Logger};
use slot_clock::SlotClock;
use state_processing::{
    common::get_indexed_attestation, per_block_processing,
    per_block_processing::errors::AttestationValidationError, per_slot_processing,
    BlockSignatureStrategy, SigVerifiedOp, VerifyOperation,
};
use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::prelude::*;
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::iter::{BlockRootsIterator, ParentRootBlockIterator, StateRootsIterator};
use store::{Error as DBError, HotColdDB, KeyValueStore, KeyValueStoreOp, StoreItem, StoreOp};
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
}

pub trait BeaconChainTypes: Send + Sync + 'static {
    type HotStore: store::ItemStore<Self::EthSpec>;
    type ColdStore: store::ItemStore<Self::EthSpec>;
    type SlotClock: slot_clock::SlotClock;
    type Eth1Chain: Eth1ChainBackend<Self::EthSpec>;
    type EthSpec: types::EthSpec;
    type EventHandler: EventHandler<Self::EthSpec>;
}

/// Represents the "Beacon Chain" component of Ethereum 2.0. Allows import of blocks and block
/// operations and chooses a canonical head.
pub struct BeaconChain<T: BeaconChainTypes> {
    pub spec: ChainSpec,
    /// Configuration for `BeaconChain` runtime behaviour.
    pub config: ChainConfig,
    /// Persistent storage for blocks, states, etc. Typically an on-disk store, such as LevelDB.
    pub store: Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>,
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
    pub naive_aggregation_pool: RwLock<NaiveAggregationPool<T::EthSpec>>,
    /// Contains a store of attestations which have been observed by the beacon chain.
    pub(crate) observed_attestations: RwLock<ObservedAttestations<T::EthSpec>>,
    /// Maintains a record of which validators have been seen to attest in recent epochs.
    pub(crate) observed_attesters: RwLock<ObservedAttesters<T::EthSpec>>,
    /// Maintains a record of which validators have been seen to create `SignedAggregateAndProofs`
    /// in recent epochs.
    pub(crate) observed_aggregators: RwLock<ObservedAggregators<T::EthSpec>>,
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
    /// Stores a "snapshot" of the chain at the time the head-of-the-chain block was received.
    pub(crate) canonical_head: TimeoutRwLock<BeaconSnapshot<T::EthSpec>>,
    /// The root of the genesis block.
    pub genesis_block_root: Hash256,
    /// The root of the genesis state.
    pub genesis_state_root: Hash256,
    /// The root of the list of genesis validators, used during syncing.
    pub genesis_validators_root: Hash256,

    #[allow(clippy::type_complexity)]
    /// A state-machine that is updated with information from the network and chooses a canonical
    /// head block.
    pub fork_choice: RwLock<
        ForkChoice<BeaconForkChoiceStore<T::EthSpec, T::HotStore, T::ColdStore>, T::EthSpec>,
    >,
    /// A handler for events generated by the beacon chain.
    pub event_handler: T::EventHandler,
    /// Used to track the heads of the beacon chain.
    pub(crate) head_tracker: Arc<HeadTracker>,
    /// A cache dedicated to block processing.
    pub(crate) snapshot_cache: TimeoutRwLock<SnapshotCache<T::EthSpec>>,
    /// Caches the shuffling for a given epoch and state root.
    pub(crate) shuffling_cache: TimeoutRwLock<ShufflingCache>,
    /// Caches a map of `validator_index -> validator_pubkey`.
    pub(crate) validator_pubkey_cache: TimeoutRwLock<ValidatorPubkeyCache>,
    /// A list of any hard-coded forks that have been disabled.
    pub disabled_forks: Vec<String>,
    /// Sender given to tasks, so that if they encounter a state in which execution cannot
    /// continue they can request that everything shuts down.
    pub shutdown_sender: Sender<&'static str>,
    /// Logging to CLI, etc.
    pub(crate) log: Logger,
    /// Arbitrary bytes included in the blocks.
    pub(crate) graffiti: Graffiti,
    /// Optional slasher.
    pub(crate) slasher: Option<Arc<Slasher<T::EthSpec>>>,
}

type BeaconBlockAndState<T> = (BeaconBlock<T>, BeaconState<T>);

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

    /// Return a `PersistedBeaconChain` representing the current head.
    pub fn make_persisted_head(&self) -> PersistedBeaconChain {
        PersistedBeaconChain {
            _canonical_head_block_root: DUMMY_CANONICAL_HEAD_BLOCK_ROOT,
            genesis_block_root: self.genesis_block_root,
            ssz_head_tracker: self.head_tracker.to_ssz_container(),
        }
    }

    /// Return a database operation for writing the beacon chain head to disk.
    pub fn persist_head_in_batch(&self) -> KeyValueStoreOp {
        self.make_persisted_head()
            .as_kv_store_op(BEACON_CHAIN_DB_KEY)
    }

    /// Return a database operation for writing fork choice to disk.
    pub fn persist_fork_choice_in_batch(&self) -> KeyValueStoreOp {
        let fork_choice = self.fork_choice.read();
        let persisted_fork_choice = PersistedForkChoice {
            fork_choice: fork_choice.to_persisted(),
            fork_choice_store: fork_choice.fc_store().to_persisted(),
        };
        persisted_fork_choice.as_kv_store_op(FORK_CHOICE_DB_KEY)
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

    /// Iterates across all `(block_root, slot)` pairs from the head of the chain (inclusive) to
    /// the earliest reachable ancestor (may or may not be genesis).
    ///
    /// ## Notes
    ///
    /// `slot` always decreases by `1`.
    /// - Skipped slots contain the root of the closest prior
    ///     non-skipped slot (identical to the way they are stored in `state.block_roots`) .
    /// - Iterator returns `(Hash256, Slot)`.
    /// - As this iterator starts at the `head` of the chain (viz., the best block), the first slot
    ///     returned may be earlier than the wall-clock slot.
    pub fn rev_iter_block_roots(
        &self,
    ) -> Result<impl Iterator<Item = Result<(Hash256, Slot), Error>>, Error> {
        let head = self.head()?;
        let iter = BlockRootsIterator::owned(self.store.clone(), head.beacon_state);
        Ok(
            std::iter::once(Ok((head.beacon_block_root, head.beacon_block.slot())))
                .chain(iter)
                .map(|result| result.map_err(|e| e.into())),
        )
    }

    pub fn forwards_iter_block_roots(
        &self,
        start_slot: Slot,
    ) -> Result<impl Iterator<Item = Result<(Hash256, Slot), Error>>, Error> {
        let local_head = self.head()?;

        let iter = HotColdDB::forwards_block_roots_iterator(
            self.store.clone(),
            start_slot,
            local_head.beacon_state,
            local_head.beacon_block_root,
            &self.spec,
        )?;

        Ok(iter.map(|result| result.map_err(Into::into)))
    }

    /// Traverse backwards from `block_root` to find the block roots of its ancestors.
    ///
    /// ## Notes
    ///
    /// `slot` always decreases by `1`.
    /// - Skipped slots contain the root of the closest prior
    ///     non-skipped slot (identical to the way they are stored in `state.block_roots`) .
    /// - Iterator returns `(Hash256, Slot)`.
    /// - The provided `block_root` is included as the first item in the iterator.
    pub fn rev_iter_block_roots_from(
        &self,
        block_root: Hash256,
    ) -> Result<impl Iterator<Item = Result<(Hash256, Slot), Error>>, Error> {
        let block = self
            .get_block(&block_root)?
            .ok_or(Error::MissingBeaconBlock(block_root))?;
        let state = self
            .get_state(&block.state_root(), Some(block.slot()))?
            .ok_or_else(|| Error::MissingBeaconState(block.state_root()))?;
        let iter = BlockRootsIterator::owned(self.store.clone(), state);
        Ok(std::iter::once(Ok((block_root, block.slot())))
            .chain(iter)
            .map(|result| result.map_err(|e| e.into())))
    }

    /// Traverse backwards from `block_root` to find the root of the ancestor block at `slot`.
    pub fn get_ancestor_block_root(
        &self,
        block_root: Hash256,
        slot: Slot,
    ) -> Result<Option<Hash256>, Error> {
        process_results(self.rev_iter_block_roots_from(block_root)?, |mut iter| {
            iter.find(|(_, ancestor_slot)| *ancestor_slot == slot)
                .map(|(ancestor_block_root, _)| ancestor_block_root)
        })
    }

    /// Iterates across all `(state_root, slot)` pairs from the head of the chain (inclusive) to
    /// the earliest reachable ancestor (may or may not be genesis).
    ///
    /// ## Notes
    ///
    /// `slot` always decreases by `1`.
    /// - Iterator returns `(Hash256, Slot)`.
    /// - As this iterator starts at the `head` of the chain (viz., the best block), the first slot
    ///     returned may be earlier than the wall-clock slot.
    pub fn rev_iter_state_roots(
        &self,
    ) -> Result<impl Iterator<Item = Result<(Hash256, Slot), Error>>, Error> {
        let head = self.head()?;
        let slot = head.beacon_state.slot;
        let iter = StateRootsIterator::owned(self.store.clone(), head.beacon_state);
        let iter = std::iter::once(Ok((head.beacon_state_root, slot)))
            .chain(iter)
            .map(|result| result.map_err(Into::into));
        Ok(iter)
    }

    /// As for `rev_iter_state_roots` but starting from an arbitrary `BeaconState`.
    pub fn rev_iter_state_roots_from<'a>(
        &self,
        state_root: Hash256,
        state: &'a BeaconState<T::EthSpec>,
    ) -> impl Iterator<Item = Result<(Hash256, Slot), Error>> + 'a {
        std::iter::once(Ok((state_root, state.slot)))
            .chain(StateRootsIterator::new(self.store.clone(), state))
            .map(|result| result.map_err(Into::into))
    }

    /// Returns the block at the given slot, if any. Only returns blocks in the canonical chain.
    ///
    /// ## Errors
    ///
    /// May return a database error.
    pub fn block_at_slot(
        &self,
        slot: Slot,
    ) -> Result<Option<SignedBeaconBlock<T::EthSpec>>, Error> {
        let root = process_results(self.rev_iter_block_roots()?, |mut iter| {
            iter.find(|(_, this_slot)| *this_slot == slot)
                .map(|(root, _)| root)
        })?;

        if let Some(block_root) = root {
            Ok(self.store.get_item(&block_root)?)
        } else {
            Ok(None)
        }
    }

    /// Returns the block at the given slot, if any. Only returns blocks in the canonical chain.
    ///
    /// ## Errors
    ///
    /// May return a database error.
    pub fn state_root_at_slot(&self, slot: Slot) -> Result<Option<Hash256>, Error> {
        process_results(self.rev_iter_state_roots()?, |mut iter| {
            iter.find(|(_, this_slot)| *this_slot == slot)
                .map(|(root, _)| root)
        })
    }

    /// Returns the block root at the given slot, if any. Only returns roots in the canonical chain.
    ///
    /// ## Errors
    ///
    /// May return a database error.
    pub fn block_root_at_slot(&self, slot: Slot) -> Result<Option<Hash256>, Error> {
        process_results(self.rev_iter_block_roots()?, |mut iter| {
            iter.find(|(_, this_slot)| *this_slot == slot)
                .map(|(root, _)| root)
        })
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
        self.with_head(|head| Ok(head.clone_with_only_committee_caches()))
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

    /// Returns info representing the head block and state.
    ///
    /// A summarized version of `Self::head` that involves less cloning.
    pub fn head_info(&self) -> Result<HeadInfo, Error> {
        self.with_head(|head| {
            Ok(HeadInfo {
                slot: head.beacon_block.slot(),
                block_root: head.beacon_block_root,
                state_root: head.beacon_state_root,
                current_justified_checkpoint: head.beacon_state.current_justified_checkpoint,
                finalized_checkpoint: head.beacon_state.finalized_checkpoint,
                fork: head.beacon_state.fork,
                genesis_time: head.beacon_state.genesis_time,
                genesis_validators_root: head.beacon_state.genesis_validators_root,
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

        match slot.cmp(&head_state.slot) {
            Ordering::Equal => Ok(head_state),
            Ordering::Greater => {
                if slot > head_state.slot + T::EthSpec::slots_per_epoch() {
                    warn!(
                        self.log,
                        "Skipping more than an epoch";
                        "head_slot" => head_state.slot,
                        "request_slot" => slot
                    )
                }

                let start_slot = head_state.slot;
                let task_start = Instant::now();
                let max_task_runtime = Duration::from_millis(self.spec.milliseconds_per_slot);

                let head_state_slot = head_state.slot;
                let mut state = head_state;

                let skip_state_root = match config {
                    StateSkipConfig::WithStateRoots => None,
                    StateSkipConfig::WithoutStateRoots => Some(Hash256::zero()),
                };

                while state.slot < slot {
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
                                "error" => format!("{:?}", e),
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
                let state_root = process_results(self.rev_iter_state_roots()?, |iter| {
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

    /// Returns the block canonical root of the current canonical chain at a given slot.
    ///
    /// Returns `None` if the given slot doesn't exist in the chain.
    pub fn root_at_slot(&self, target_slot: Slot) -> Result<Option<Hash256>, Error> {
        process_results(self.rev_iter_block_roots()?, |mut iter| {
            iter.find(|(_, slot)| *slot == target_slot)
                .map(|(root, _)| root)
        })
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
        let iter = BlockRootsIterator::new(self.store.clone(), state);
        let iter_with_head = std::iter::once(Ok((beacon_block_root, state.slot)))
            .chain(iter)
            .map(|result| result.map_err(|e| e.into()));

        process_results(iter_with_head, |mut iter| {
            iter.find(|(_, slot)| *slot == target_slot)
                .map(|(root, _)| root)
        })
    }

    /// Returns the block proposer for a given slot.
    ///
    /// Information is read from the present `beacon_state` shuffling, only information from the
    /// present epoch is available.
    pub fn block_proposer(&self, slot: Slot) -> Result<usize, Error> {
        let epoch = |slot: Slot| slot.epoch(T::EthSpec::slots_per_epoch());
        let head_state = &self.head()?.beacon_state;

        let mut state = if epoch(slot) == epoch(head_state.slot) {
            self.head()?.beacon_state
        } else {
            // The block proposer shuffling is not affected by the state roots, so we don't need to
            // calculate them.
            self.state_at_slot(slot, StateSkipConfig::WithoutStateRoots)?
        };

        state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;

        if epoch(state.slot) != epoch(slot) {
            return Err(Error::InvariantViolated(format!(
                "Epochs in consistent in proposer lookup: state: {}, requested: {}",
                epoch(state.slot),
                epoch(slot)
            )));
        }

        state
            .get_beacon_proposer_index(slot, &self.spec)
            .map_err(Into::into)
    }

    /// Returns the attestation duties for a given validator index.
    ///
    /// Information is read from the current state, so only information from the present and prior
    /// epoch is available.
    pub fn validator_attestation_duty(
        &self,
        validator_index: usize,
        epoch: Epoch,
    ) -> Result<Option<AttestationDuty>, Error> {
        let head_block_root = self.head_beacon_block_root()?;

        self.with_committee_cache(head_block_root, epoch, |committee_cache| {
            Ok(committee_cache.get_attestation_duties(validator_index))
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

    /// Produce an unaggregated `Attestation` that is valid for the given `slot` and `index`.
    ///
    /// The produced `Attestation` will not be valid until it has been signed by exactly one
    /// validator that is in the committee for `slot` and `index` in the canonical chain.
    ///
    /// Always attests to the canonical chain.
    pub fn produce_unaggregated_attestation(
        &self,
        slot: Slot,
        index: CommitteeIndex,
    ) -> Result<Attestation<T::EthSpec>, Error> {
        // Note: we're taking a lock on the head. The work involved here should be trivial enough
        // that the lock should not be held for long.
        let head = self
            .canonical_head
            .try_read_for(HEAD_LOCK_TIMEOUT)
            .ok_or(Error::CanonicalHeadLockTimeout)?;

        if slot >= head.beacon_block.slot() {
            self.produce_unaggregated_attestation_for_block(
                slot,
                index,
                head.beacon_block_root,
                Cow::Borrowed(&head.beacon_state),
            )
        } else {
            // Note: this method will fail if `slot` is more than `state.block_roots.len()` slots
            // prior to the head.
            //
            // This seems reasonable, producing an attestation at a slot so far
            // in the past seems useless, definitely in mainnet spec. In minimal spec, when the
            // block roots only contain two epochs of history, it's possible that you will fail to
            // produce an attestation that would be valid to be included in a block. Given that
            // minimal is only for testing, I think this is fine.
            //
            // It is important to note that what's _not_ allowed here is attesting to a slot in the
            // past. You can still attest to a block an arbitrary distance in the past, just not as
            // if you are in a slot in the past.
            let beacon_block_root = *head.beacon_state.get_block_root(slot)?;
            let state_root = *head.beacon_state.get_state_root(slot)?;

            // Avoid holding a lock on the head whilst doing database reads. Good boi functions
            // don't hog locks.
            drop(head);

            let mut state = self
                .get_state(&state_root, Some(slot))?
                .ok_or(Error::MissingBeaconState(state_root))?;

            state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;

            self.produce_unaggregated_attestation_for_block(
                slot,
                index,
                beacon_block_root,
                Cow::Owned(state),
            )
        }
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
    ) -> Result<Attestation<T::EthSpec>, Error> {
        let epoch = slot.epoch(T::EthSpec::slots_per_epoch());

        if state.slot > slot {
            return Err(Error::CannotAttestToFutureState);
        } else if state.current_epoch() < epoch {
            let mut_state = state.to_mut();
            while mut_state.current_epoch() < epoch {
                // Note: here we provide `Hash256::zero()` as the root of the current state. This
                // has the effect of setting the values of all historic state roots to the zero
                // hash. This is an optimization, we don't need the state roots so why calculate
                // them?
                per_slot_processing(mut_state, Some(Hash256::zero()), &self.spec)?;
            }
            mut_state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;
        }

        let committee_len = state.get_beacon_committee(slot, index)?.committee.len();

        let target_slot = epoch.start_slot(T::EthSpec::slots_per_epoch());
        let target_root = if state.slot <= target_slot {
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
                source: state.current_justified_checkpoint,
                target: Checkpoint {
                    epoch,
                    root: target_root,
                },
            },
            signature: AggregateSignature::empty(),
        })
    }

    /// Accepts some `Attestation` from the network and attempts to verify it, returning `Ok(_)` if
    /// it is valid to be (re)broadcast on the gossip network.
    ///
    /// The attestation must be "unaggregated", that is it must have exactly one
    /// aggregation bit set.
    pub fn verify_unaggregated_attestation_for_gossip(
        &self,
        attestation: Attestation<T::EthSpec>,
        subnet_id: Option<SubnetId>,
    ) -> Result<VerifiedUnaggregatedAttestation<T>, AttestationError> {
        metrics::inc_counter(&metrics::UNAGGREGATED_ATTESTATION_PROCESSING_REQUESTS);
        let _timer =
            metrics::start_timer(&metrics::UNAGGREGATED_ATTESTATION_GOSSIP_VERIFICATION_TIMES);

        VerifiedUnaggregatedAttestation::verify(attestation, subnet_id, self).map(|v| {
            metrics::inc_counter(&metrics::UNAGGREGATED_ATTESTATION_PROCESSING_SUCCESSES);
            v
        })
    }

    /// Accepts some `SignedAggregateAndProof` from the network and attempts to verify it,
    /// returning `Ok(_)` if it is valid to be (re)broadcast on the gossip network.
    pub fn verify_aggregated_attestation_for_gossip(
        &self,
        signed_aggregate: SignedAggregateAndProof<T::EthSpec>,
    ) -> Result<VerifiedAggregatedAttestation<T>, AttestationError> {
        metrics::inc_counter(&metrics::AGGREGATED_ATTESTATION_PROCESSING_REQUESTS);
        let _timer =
            metrics::start_timer(&metrics::AGGREGATED_ATTESTATION_GOSSIP_VERIFICATION_TIMES);

        VerifiedAggregatedAttestation::verify(signed_aggregate, self).map(|v| {
            metrics::inc_counter(&metrics::AGGREGATED_ATTESTATION_PROCESSING_SUCCESSES);
            v
        })
    }

    /// Accepts some attestation-type object and attempts to verify it in the context of fork
    /// choice. If it is valid it is applied to `self.fork_choice`.
    ///
    /// Common items that implement `SignatureVerifiedAttestation`:
    ///
    /// - `VerifiedUnaggregatedAttestation`
    /// - `VerifiedAggregatedAttestation`
    pub fn apply_attestation_to_fork_choice(
        &self,
        verified: &impl SignatureVerifiedAttestation<T>,
    ) -> Result<(), Error> {
        let _timer = metrics::start_timer(&metrics::FORK_CHOICE_PROCESS_ATTESTATION_TIMES);

        self.fork_choice
            .write()
            .on_attestation(self.slot()?, verified.indexed_attestation())
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
        unaggregated_attestation: VerifiedUnaggregatedAttestation<T>,
    ) -> Result<VerifiedUnaggregatedAttestation<T>, AttestationError> {
        let _timer = metrics::start_timer(&metrics::ATTESTATION_PROCESSING_APPLY_TO_AGG_POOL);

        let attestation = unaggregated_attestation.attestation();

        match self.naive_aggregation_pool.write().insert(attestation) {
            Ok(outcome) => trace!(
                self.log,
                "Stored unaggregated attestation";
                "outcome" => format!("{:?}", outcome),
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
                        "error" => format!("{:?}", e),
                        "index" => attestation.data.index,
                        "slot" => attestation.data.slot.as_u64(),
                );
                return Err(Error::from(e).into());
            }
        };

        Ok(unaggregated_attestation)
    }

    /// Accepts a `VerifiedAggregatedAttestation` and attempts to apply it to `self.op_pool`.
    ///
    /// The op pool is used by local block producers to pack blocks with operations.
    pub fn add_to_block_inclusion_pool(
        &self,
        signed_aggregate: VerifiedAggregatedAttestation<T>,
    ) -> Result<VerifiedAggregatedAttestation<T>, AttestationError> {
        let _timer = metrics::start_timer(&metrics::ATTESTATION_PROCESSING_APPLY_TO_OP_POOL);

        // If there's no eth1 chain then it's impossible to produce blocks and therefore
        // useless to put things in the op pool.
        if self.eth1_chain.is_some() {
            let fork = self
                .canonical_head
                .try_read_for(HEAD_LOCK_TIMEOUT)
                .ok_or(Error::CanonicalHeadLockTimeout)?
                .beacon_state
                .fork;

            self.op_pool
                .insert_attestation(
                    // TODO: address this clone.
                    signed_aggregate.attestation().clone(),
                    &fork,
                    self.genesis_validators_root,
                    &self.spec,
                )
                .map_err(Error::from)?;
        }

        Ok(signed_aggregate)
    }

    /// Move slashings collected by the slasher into the op pool for block inclusion.
    fn ingest_slashings_to_op_pool(&self, state: &BeaconState<T::EthSpec>) {
        if let Some(slasher) = self.slasher.as_ref() {
            let attester_slashings = slasher.get_attester_slashings();
            let proposer_slashings = slasher.get_proposer_slashings();

            if !attester_slashings.is_empty() || !proposer_slashings.is_empty() {
                debug!(
                    self.log,
                    "Ingesting slashings";
                    "num_attester_slashings" => attester_slashings.len(),
                    "num_proposer_slashings" => proposer_slashings.len(),
                );
            }

            for slashing in attester_slashings {
                let verified_slashing = match slashing.clone().validate(state, &self.spec) {
                    Ok(verified) => verified,
                    Err(e) => {
                        error!(
                            self.log,
                            "Attester slashing from slasher failed verification";
                            "error" => format!("{:?}", e),
                            "slashing" => format!("{:?}", slashing),
                        );
                        continue;
                    }
                };

                if let Err(e) = self.import_attester_slashing(verified_slashing) {
                    error!(
                        self.log,
                        "Attester slashing from slasher is invalid";
                        "error" => format!("{:?}", e),
                        "slashing" => format!("{:?}", slashing),
                    );
                }
            }

            for slashing in proposer_slashings {
                let verified_slashing = match slashing.clone().validate(state, &self.spec) {
                    Ok(verified) => verified,
                    Err(e) => {
                        error!(
                            self.log,
                            "Proposer slashing from slasher failed verification";
                            "error" => format!("{:?}", e),
                            "slashing" => format!("{:?}", slashing),
                        );
                        continue;
                    }
                };
                self.import_proposer_slashing(verified_slashing);
            }
        }
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
                    "error" => format!("{:?}", e),
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
                    "block_root" => format!("{:?}", block_root),
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
        Ok(self.observed_voluntary_exits.lock().verify_and_observe(
            exit,
            &wall_clock_state,
            &self.spec,
        )?)
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
                .unwrap_or_else(|| filtered_chain_segment.len());

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
        let slot = block.message.slot;
        let graffiti_string = block.message.body.graffiti.as_utf8_lossy();

        match GossipVerifiedBlock::new(block, self) {
            Ok(verified) => {
                debug!(
                    self.log,
                    "Successfully processed gossip block";
                    "graffiti" => graffiti_string,
                    "slot" => slot,
                    "root" => format!("{:?}", verified.block_root()),
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
                    "block_root" => format!("{:?}", block_root),
                    "block_slot" => format!("{:?}", block.slot().as_u64()),
                );

                // Increment the Prometheus counter for block processing successes.
                metrics::inc_counter(&metrics::BLOCK_PROCESSING_SUCCESSES);

                let _ = self.event_handler.register(EventKind::BeaconBlockImported {
                    block_root,
                    block: Box::new(block),
                });

                Ok(block_root)
            }
            // There was an error whilst attempting to verify and import the block. The block might
            // be partially verified or partially imported.
            Err(BlockError::BeaconChainError(e)) => {
                crit!(
                    self.log,
                    "Beacon block processing error";
                    "error" => format!("{:?}", e),
                );

                let _ = self.event_handler.register(EventKind::BeaconBlockRejected {
                    reason: format!("Internal error: {:?}", e),
                    block: Box::new(block),
                });

                Err(BlockError::BeaconChainError(e))
            }
            // The block failed verification.
            Err(other) => {
                trace!(
                    self.log,
                    "Beacon block rejected";
                    "reason" => other.to_string(),
                );

                let _ = self.event_handler.register(EventKind::BeaconBlockRejected {
                    reason: format!("Invalid block: {}", other),
                    block: Box::new(block),
                });

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
        let mut ops = fully_verified_block.confirmation_db_batch;

        let attestation_observation_timer =
            metrics::start_timer(&metrics::BLOCK_PROCESSING_ATTESTATION_OBSERVATION);

        // Iterate through the attestations in the block and register them as an "observed
        // attestation". This will stop us from propagating them on the gossip network.
        for a in &signed_block.message.body.attestations {
            match self
                .observed_attestations
                .write()
                .observe_attestation(a, None)
            {
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
            for attestation in &signed_block.message.body.attestations {
                let committee =
                    state.get_beacon_committee(attestation.data.slot, attestation.data.index)?;
                let indexed_attestation =
                    get_indexed_attestation(&committee.committee, attestation)
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
            let shuffling_id = ShufflingId::new(block_root, &state, *relative_epoch)?;

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

        let mut fork_choice = self.fork_choice.write();

        // Do not import a block that doesn't descend from the finalized root.
        let signed_block =
            check_block_is_finalized_descendant::<T, _>(signed_block, &fork_choice, &self.store)?;
        let block = &signed_block.message;

        // compare the existing finalized checkpoint with the incoming block's finalized checkpoint
        let old_finalized_checkpoint = fork_choice.finalized_checkpoint();
        let new_finalized_checkpoint = state.finalized_checkpoint;

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
                        "block_root" => format!("{:?}", block_root),
                        "parent_root" => format!("{:?}", block.parent_root),
                        "old_finalized_epoch" => format!("{:?}", old_finalized_checkpoint.epoch),
                        "new_finalized_epoch" => format!("{:?}", new_finalized_checkpoint.epoch),
                        "weak_subjectivity_epoch" => format!("{:?}", wss_checkpoint.epoch),
                        "error" => format!("{:?}", e),
                    );
                    crit!(self.log, "You must use the `--purge-db` flag to clear the database and restart sync. You may be on a hostile network.");
                    shutdown_sender.try_send("Weak subjectivity checkpoint verification failed. Provided block root is not a checkpoint.")
                        .map_err(|err|BlockError::BeaconChainError(BeaconChainError::WeakSubjectivtyShutdownError(err)))?;
                    return Err(BlockError::WeakSubjectivityConflict);
                }
            }
        }

        // Register the new block with the fork choice service.
        {
            let _fork_choice_block_timer =
                metrics::start_timer(&metrics::FORK_CHOICE_PROCESS_BLOCK_TIMES);
            fork_choice
                .on_block(current_slot, block, block_root, &state)
                .map_err(|e| BlockError::BeaconChainError(e.into()))?;
        }

        // Register each attestation in the block with the fork choice service.
        for attestation in &block.body.attestations[..] {
            let _fork_choice_attestation_timer =
                metrics::start_timer(&metrics::FORK_CHOICE_PROCESS_ATTESTATION_TIMES);

            let committee =
                state.get_beacon_committee(attestation.data.slot, attestation.data.index)?;
            let indexed_attestation = get_indexed_attestation(committee.committee, attestation)
                .map_err(|e| BlockError::BeaconChainError(e.into()))?;

            match fork_choice.on_attestation(current_slot, &indexed_attestation) {
                Ok(()) => Ok(()),
                // Ignore invalid attestations whilst importing attestations from a block. The
                // block might be very old and therefore the attestations useless to fork choice.
                Err(ForkChoiceError::InvalidAttestation(_)) => Ok(()),
                Err(e) => Err(BlockError::BeaconChainError(e.into())),
            }?;
        }

        metrics::observe(
            &metrics::OPERATIONS_PER_BLOCK_ATTESTATION,
            block.body.attestations.len() as f64,
        );

        let db_write_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_DB_WRITE);

        // Store the block and its state, and execute the confirmation batch for the intermediate
        // states, which will delete their temporary flags.
        ops.push(StoreOp::PutBlock(
            block_root,
            Box::new(signed_block.clone()),
        ));
        ops.push(StoreOp::PutState(block.state_root, &state));
        let txn_lock = self.store.hot_db.begin_rw_transaction();
        self.store.do_atomically(ops)?;
        drop(txn_lock);

        // The fork choice write-lock is dropped *after* the on-disk database has been updated.
        // This prevents inconsistency between the two at the expense of concurrency.
        drop(fork_choice);

        let parent_root = block.parent_root;
        let slot = block.slot;

        self.snapshot_cache
            .try_write_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
            .map(|mut snapshot_cache| {
                snapshot_cache.insert(BeaconSnapshot {
                    beacon_state: state,
                    beacon_state_root: signed_block.state_root(),
                    beacon_block: signed_block,
                    beacon_block_root: block_root,
                });
            })
            .unwrap_or_else(|| {
                error!(
                    self.log,
                    "Failed to obtain cache write lock";
                    "lock" => "snapshot_cache",
                    "task" => "process block"
                );
            });

        self.head_tracker
            .register_block(block_root, parent_root, slot);

        metrics::stop_timer(db_write_timer);

        metrics::inc_counter(&metrics::BLOCK_PROCESSING_SUCCESSES);

        Ok(block_root)
    }

    /// Produce a new block at the given `slot`.
    ///
    /// The produced block will not be inherently valid, it must be signed by a block producer.
    /// Block signing is out of the scope of this function and should be done by a separate program.
    pub fn produce_block(
        &self,
        randao_reveal: Signature,
        slot: Slot,
        validator_graffiti: Option<Graffiti>,
    ) -> Result<BeaconBlockAndState<T::EthSpec>, BlockProductionError> {
        let state = self
            .state_at_slot(slot - 1, StateSkipConfig::WithStateRoots)
            .map_err(|_| BlockProductionError::UnableToProduceAtSlot(slot))?;

        self.produce_block_on_state(state, slot, randao_reveal, validator_graffiti)
    }

    /// Produce a block for some `slot` upon the given `state`.
    ///
    /// Typically the `self.produce_block()` function should be used, instead of calling this
    /// function directly. This function is useful for purposefully creating forks or blocks at
    /// non-current slots.
    ///
    /// The given state will be advanced to the given `produce_at_slot`, then a block will be
    /// produced at that slot height.
    pub fn produce_block_on_state(
        &self,
        mut state: BeaconState<T::EthSpec>,
        produce_at_slot: Slot,
        randao_reveal: Signature,
        validator_graffiti: Option<Graffiti>,
    ) -> Result<BeaconBlockAndState<T::EthSpec>, BlockProductionError> {
        metrics::inc_counter(&metrics::BLOCK_PRODUCTION_REQUESTS);
        let timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_TIMES);

        let eth1_chain = self
            .eth1_chain
            .as_ref()
            .ok_or(BlockProductionError::NoEth1ChainConnection)?;

        // If required, transition the new state to the present slot.
        //
        // Note: supplying some `state_root` when it it is known would be a cheap and easy
        // optimization.
        while state.slot < produce_at_slot {
            per_slot_processing(&mut state, None, &self.spec)?;
        }

        state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;

        let parent_root = if state.slot > 0 {
            *state
                .get_block_root(state.slot - 1)
                .map_err(|_| BlockProductionError::UnableToGetBlockRootFromState)?
        } else {
            state.latest_block_header.canonical_root()
        };

        self.ingest_slashings_to_op_pool(&state);
        let (proposer_slashings, attester_slashings) =
            self.op_pool.get_slashings(&state, &self.spec);

        let eth1_data = eth1_chain.eth1_data_for_block_production(&state, &self.spec)?;
        let deposits = eth1_chain
            .deposits_for_block_inclusion(&state, &eth1_data, &self.spec)?
            .into();

        // Map from attestation head block root to shuffling compatibility.
        // Used to memoize the `attestation_shuffling_is_compatible` function.
        let mut shuffling_filter_cache = HashMap::new();
        let attestation_filter = |att: &&Attestation<T::EthSpec>| -> bool {
            *shuffling_filter_cache
                .entry((att.data.beacon_block_root, att.data.target.epoch))
                .or_insert_with(|| {
                    self.shuffling_is_compatible(
                        &att.data.beacon_block_root,
                        att.data.target.epoch,
                        &state,
                    )
                })
        };

        // Iterate through the naive aggregation pool and ensure all the attestations from there
        // are included in the operation pool.
        for attestation in self.naive_aggregation_pool.read().iter() {
            if let Err(e) = self.op_pool.insert_attestation(
                attestation.clone(),
                &state.fork,
                state.genesis_validators_root,
                &self.spec,
            ) {
                // Don't stop block production if there's an error, just create a log.
                error!(
                    self.log,
                    "Attestation did not transfer to op pool";
                    "reason" => format!("{:?}", e)
                );
            }
        }

        // Override the beacon node's graffiti with graffiti from the validator, if present.
        let graffiti = match validator_graffiti {
            Some(graffiti) => graffiti,
            None => self.graffiti,
        };

        let mut block = SignedBeaconBlock {
            message: BeaconBlock {
                slot: state.slot,
                proposer_index: state.get_beacon_proposer_index(state.slot, &self.spec)? as u64,
                parent_root,
                state_root: Hash256::zero(),
                body: BeaconBlockBody {
                    randao_reveal,
                    eth1_data,
                    graffiti,
                    proposer_slashings: proposer_slashings.into(),
                    attester_slashings: attester_slashings.into(),
                    attestations: self
                        .op_pool
                        .get_attestations(&state, attestation_filter, &self.spec)
                        .map_err(BlockProductionError::OpPoolError)?
                        .into(),
                    deposits,
                    voluntary_exits: self.op_pool.get_voluntary_exits(&state, &self.spec).into(),
                },
            },
            // The block is not signed here, that is the task of a validator client.
            signature: Signature::empty(),
        };

        per_block_processing(
            &mut state,
            &block,
            None,
            BlockSignatureStrategy::NoVerification,
            &self.spec,
        )?;

        let state_root = state.update_tree_hash_cache()?;

        block.message.state_root = state_root;

        metrics::inc_counter(&metrics::BLOCK_PRODUCTION_SUCCESSES);
        metrics::stop_timer(timer);

        trace!(
            self.log,
            "Produced beacon block";
            "parent" => format!("{}", block.message.parent_root),
            "attestations" => block.message.body.attestations.len(),
            "slot" => block.message.slot
        );

        Ok((block.message, state))
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
        // Determine the root of the block that is the head of the chain.
        let beacon_block_root = self.fork_choice.write().get_head(self.slot()?)?;

        let current_head = self.head_info()?;
        let old_finalized_checkpoint = current_head.finalized_checkpoint;

        if beacon_block_root == current_head.block_root {
            return Ok(());
        }

        // At this point we know that the new head block is not the same as the previous one
        metrics::inc_counter(&metrics::FORK_CHOICE_CHANGED_HEAD);

        // Try and obtain the snapshot for `beacon_block_root` from the snapshot cache, falling
        // back to a database read if that fails.
        let new_head = self
            .snapshot_cache
            .try_read_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
            .and_then(|snapshot_cache| snapshot_cache.get_cloned(beacon_block_root))
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
                    beacon_state_root,
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
        let is_reorg = current_head.block_root
            != new_head
                .beacon_state
                .get_block_root(current_head.slot)
                .map(|root| *root)
                .unwrap_or_else(|_| Hash256::random());

        if is_reorg {
            metrics::inc_counter(&metrics::FORK_CHOICE_REORG_COUNT);
            warn!(
                self.log,
                "Beacon chain re-org";
                "previous_head" => format!("{}", current_head.block_root),
                "previous_slot" => current_head.slot,
                "new_head_parent" => format!("{}", new_head.beacon_block.parent_root()),
                "new_head" => format!("{}", beacon_block_root),
                "new_slot" => new_head.beacon_block.slot()
            );
        } else {
            debug!(
                self.log,
                "Head beacon block";
                "justified_root" => format!("{}", new_head.beacon_state.current_justified_checkpoint.root),
                "justified_epoch" => new_head.beacon_state.current_justified_checkpoint.epoch,
                "finalized_root" => format!("{}", new_head.beacon_state.finalized_checkpoint.root),
                "finalized_epoch" => new_head.beacon_state.finalized_checkpoint.epoch,
                "root" => format!("{}", beacon_block_root),
                "slot" => new_head.beacon_block.slot(),
            );
        };

        let new_finalized_checkpoint = new_head.beacon_state.finalized_checkpoint;

        // It is an error to try to update to a head with a lesser finalized epoch.
        if new_finalized_checkpoint.epoch < old_finalized_checkpoint.epoch {
            return Err(Error::RevertedFinalizedEpoch {
                previous_epoch: old_finalized_checkpoint.epoch,
                new_epoch: new_finalized_checkpoint.epoch,
            });
        }

        if current_head.slot.epoch(T::EthSpec::slots_per_epoch())
            < new_head
                .beacon_state
                .slot
                .epoch(T::EthSpec::slots_per_epoch())
            || is_reorg
        {
            self.persist_head_and_fork_choice()?;
            self.op_pool.prune_attestations(self.epoch()?);
            self.ingest_slashings_to_op_pool(&new_head.beacon_state);
            self.persist_op_pool()?;
        }

        let update_head_timer = metrics::start_timer(&metrics::UPDATE_HEAD_TIMES);

        // Update the snapshot that stores the head of the chain at the time it received the
        // block.
        *self
            .canonical_head
            .try_write_for(HEAD_LOCK_TIMEOUT)
            .ok_or(Error::CanonicalHeadLockTimeout)? = new_head;

        metrics::stop_timer(update_head_timer);

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
                .finalized_checkpoint
                .epoch
                .start_slot(T::EthSpec::slots_per_epoch());
            let new_finalized_state_root = process_results(
                StateRootsIterator::new(self.store.clone(), &head.beacon_state),
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

        let _ = self.event_handler.register(EventKind::BeaconHeadChanged {
            reorg: is_reorg,
            previous_head_beacon_block_root: current_head.block_root,
            current_head_beacon_block_root: beacon_block_root,
        });

        Ok(())
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
        let finalized_checkpoint = state.finalized_checkpoint;
        info!(self.log, "Verifying the configured weak subjectivity checkpoint"; "weak_subjectivity_epoch" => wss_checkpoint.epoch, "weak_subjectivity_root" => format!("{:?}", wss_checkpoint.root));
        // If epochs match, simply compare roots.
        if wss_checkpoint.epoch == finalized_checkpoint.epoch
            && wss_checkpoint.root != finalized_checkpoint.root
        {
            crit!(
                self.log,
                 "Root found at the specified checkpoint differs";
                  "weak_subjectivity_root" => format!("{:?}", wss_checkpoint.root),
                  "finalized_checkpoint_root" => format!("{:?}", finalized_checkpoint.root)
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
                              "weak_subjectivity_root" => format!("{:?}", wss_checkpoint.root),
                              "finalized_checkpoint_root" => format!("{:?}", finalized_checkpoint.root)
                        );
                        return Err(BeaconChainError::WeakSubjectivtyVerificationFailure);
                    }
                }
                None => {
                    crit!(self.log, "The root at the start slot of the given epoch could not be found";
                    "wss_checkpoint_slot" => format!("{:?}", slot));
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
        let new_finalized_checkpoint = head_state.finalized_checkpoint;

        self.observed_block_producers.write().prune(
            new_finalized_checkpoint
                .epoch
                .start_slot(T::EthSpec::slots_per_epoch()),
        );

        self.snapshot_cache
            .try_write_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
            .map(|mut snapshot_cache| {
                snapshot_cache.prune(new_finalized_checkpoint.epoch);
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

        let _ = self.event_handler.register(EventKind::BeaconFinalization {
            epoch: new_finalized_checkpoint.epoch,
            root: new_finalized_checkpoint.root,
        });

        Ok(())
    }

    /// Runs the `map_fn` with the committee cache for `shuffling_epoch` from the chain with head
    /// `head_block_root`.
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
    /// This function is **not** suitable for determining proposer duties.
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
        F: Fn(&CommitteeCache) -> Result<R, Error>,
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
            map_fn(committee_cache)
        } else {
            // Drop the shuffling cache to avoid holding the lock for any longer than
            // required.
            drop(shuffling_cache);

            debug!(
                self.log,
                "Committee cache miss";
                "shuffling_epoch" => shuffling_epoch.as_u64(),
                "head_block_root" => head_block_root.to_string(),
            );

            let state_read_timer =
                metrics::start_timer(&metrics::ATTESTATION_PROCESSING_STATE_READ_TIMES);

            let mut state = self
                .store
                .get_inconsistent_state_for_attestation_verification_only(
                    &head_block.state_root,
                    Some(head_block.slot),
                )?
                .ok_or(Error::MissingBeaconState(head_block.state_root))?;

            metrics::stop_timer(state_read_timer);
            let state_skip_timer =
                metrics::start_timer(&metrics::ATTESTATION_PROCESSING_STATE_SKIP_TIMES);

            while state.current_epoch() + 1 < shuffling_epoch {
                // Here we tell `per_slot_processing` to skip hashing the state and just
                // use the zero hash instead.
                //
                // The state roots are not useful for the shuffling, so there's no need to
                // compute them.
                per_slot_processing(&mut state, Some(Hash256::zero()), &self.spec)
                    .map_err(Error::from)?;
            }

            metrics::stop_timer(state_skip_timer);
            let committee_building_timer =
                metrics::start_timer(&metrics::ATTESTATION_PROCESSING_COMMITTEE_BUILDING_TIMES);

            let relative_epoch = RelativeEpoch::from_epoch(state.current_epoch(), shuffling_epoch)
                .map_err(Error::IncorrectStateForAttestation)?;

            state.build_committee_cache(relative_epoch, &self.spec)?;

            let committee_cache = state.committee_cache(relative_epoch)?;

            self.shuffling_cache
                .try_write_for(ATTESTATION_CACHE_LOCK_TIMEOUT)
                .ok_or(Error::AttestationCacheLockTimeout)?
                .insert(shuffling_id, committee_cache);

            metrics::stop_timer(committee_building_timer);

            map_fn(&committee_cache)
        }
    }

    /// Returns `true` if the given block root has not been processed.
    pub fn is_new_block_root(&self, beacon_block_root: &Hash256) -> Result<bool, Error> {
        Ok(!self
            .store
            .item_exists::<SignedBeaconBlock<T::EthSpec>>(beacon_block_root)?)
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
            beacon_state_root: self.head()?.beacon_state_root,
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
                beacon_state_root,
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

        self.spec.enr_fork_id(slot, self.genesis_validators_root)
    }

    /// Calculates the `Duration` to the next fork, if one exists.
    pub fn duration_to_next_fork(&self) -> Option<Duration> {
        let epoch = self.spec.next_fork_epoch()?;
        self.slot_clock
            .duration_to_slot(epoch.start_slot(T::EthSpec::slots_per_epoch()))
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
                    finalized_blocks.insert(state.finalized_checkpoint.root);
                    justified_blocks.insert(state.current_justified_checkpoint.root);
                    justified_blocks.insert(state.previous_justified_checkpoint.root);
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
    pub fn shutdown_sender(&self) -> Sender<&'static str> {
        self.shutdown_sender.clone()
    }

    // Used for debugging
    #[allow(dead_code)]
    pub fn dump_dot_file(&self, file_name: &str) {
        let mut file = std::fs::File::create(file_name).unwrap();
        self.dump_as_dot(&mut file);
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
                "error" => format!("{:?}", e)
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
