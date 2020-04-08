use crate::block_verification::{
    check_block_relevancy, get_block_root, signature_verify_chain_segment, BlockError,
    FullyVerifiedBlock, GossipVerifiedBlock, IntoFullyVerifiedBlock,
};
use crate::errors::{BeaconChainError as Error, BlockProductionError};
use crate::eth1_chain::{Eth1Chain, Eth1ChainBackend};
use crate::events::{EventHandler, EventKind};
use crate::fork_choice::{Error as ForkChoiceError, ForkChoice};
use crate::head_tracker::HeadTracker;
use crate::metrics;
use crate::naive_aggregation_pool::{Error as NaiveAggregationError, NaiveAggregationPool};
use crate::persisted_beacon_chain::PersistedBeaconChain;
use crate::shuffling_cache::ShufflingCache;
use crate::snapshot_cache::SnapshotCache;
use crate::timeout_rw_lock::TimeoutRwLock;
use crate::validator_pubkey_cache::ValidatorPubkeyCache;
use crate::BeaconSnapshot;
use operation_pool::{OperationPool, PersistedOperationPool};
use slog::{crit, debug, error, info, trace, warn, Logger};
use slot_clock::SlotClock;
use state_processing::per_block_processing::errors::{
    AttestationValidationError, AttesterSlashingValidationError, ExitValidationError,
    ProposerSlashingValidationError,
};
use state_processing::{
    common::get_indexed_attestation, per_block_processing, per_slot_processing,
    signature_sets::indexed_attestation_signature_set_from_pubkeys, BlockSignatureStrategy,
};
use std::borrow::Cow;
use std::cmp::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::iter::{
    BlockRootsIterator, ReverseBlockRootIterator, ReverseStateRootIterator, StateRootsIterator,
};
use store::{Error as DBError, Migrate, Store};
use types::*;

// Text included in blocks.
// Must be 32-bytes or panic.
//
//                          |-------must be this long------|
pub const GRAFFITI: &str = "sigp/lighthouse-0.1.1-prerelease";

/// The time-out before failure during an operation to take a read/write RwLock on the canonical
/// head.
const HEAD_LOCK_TIMEOUT: Duration = Duration::from_secs(1);

/// The time-out before failure during an operation to take a read/write RwLock on the block
/// processing cache.
pub const BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(1);
/// The time-out before failure during an operation to take a read/write RwLock on the
/// attestation cache.
const ATTESTATION_CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(1);

/// The time-out before failure during an operation to take a read/write RwLock on the
/// validator pubkey cache.
pub const VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(1);

pub const BEACON_CHAIN_DB_KEY: [u8; 32] = [0; 32];
pub const OP_POOL_DB_KEY: [u8; 32] = [0; 32];
pub const ETH1_CACHE_DB_KEY: [u8; 32] = [0; 32];
pub const FORK_CHOICE_DB_KEY: [u8; 32] = [0; 32];

#[derive(Debug, PartialEq)]
pub enum AttestationType {
    /// An attestation with a single-signature that has been published in accordance with the naive
    /// aggregation strategy.
    ///
    /// These attestations may have come from a `committee_index{subnet_id}_beacon_attestation`
    /// gossip subnet or they have have come directly from a validator attached to our API.
    ///
    /// If `should_store == true`, the attestation will be added to the `NaiveAggregationPool`.
    Unaggregated { should_store: bool },
    /// An attestation with one more more signatures that has passed through the aggregation phase
    /// of the naive aggregation scheme.
    ///
    /// These attestations must have come from the `beacon_aggregate_and_proof` gossip subnet.
    Aggregated,
}

/// The accepted clock drift for nodes gossiping blocks and attestations (spec v0.11.0). See:
///
/// https://github.com/ethereum/eth2.0-specs/blob/v0.11.0/specs/phase0/p2p-interface.md#configuration
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
    type Store: store::Store<Self::EthSpec>;
    type StoreMigrator: store::Migrate<Self::Store, Self::EthSpec>;
    type SlotClock: slot_clock::SlotClock;
    type Eth1Chain: Eth1ChainBackend<Self::EthSpec, Self::Store>;
    type EthSpec: types::EthSpec;
    type EventHandler: EventHandler<Self::EthSpec>;
}

/// Represents the "Beacon Chain" component of Ethereum 2.0. Allows import of blocks and block
/// operations and chooses a canonical head.
pub struct BeaconChain<T: BeaconChainTypes> {
    pub spec: ChainSpec,
    /// Persistent storage for blocks, states, etc. Typically an on-disk store, such as LevelDB.
    pub store: Arc<T::Store>,
    /// Database migrator for running background maintenance on the store.
    pub store_migrator: T::StoreMigrator,
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
    pub naive_aggregation_pool: NaiveAggregationPool<T::EthSpec>,
    /// Provides information from the Ethereum 1 (PoW) chain.
    pub eth1_chain: Option<Eth1Chain<T::Eth1Chain, T::EthSpec, T::Store>>,
    /// Stores a "snapshot" of the chain at the time the head-of-the-chain block was received.
    pub(crate) canonical_head: TimeoutRwLock<BeaconSnapshot<T::EthSpec>>,
    /// The root of the genesis block.
    pub genesis_block_root: Hash256,
    /// The root of the list of genesis validators, used during syncing.
    pub genesis_validators_root: Hash256,
    /// A state-machine that is updated with information from the network and chooses a canonical
    /// head block.
    pub fork_choice: ForkChoice<T>,
    /// A handler for events generated by the beacon chain.
    pub event_handler: T::EventHandler,
    /// Used to track the heads of the beacon chain.
    pub(crate) head_tracker: HeadTracker,
    /// A cache dedicated to block processing.
    pub(crate) snapshot_cache: TimeoutRwLock<SnapshotCache<T::EthSpec>>,
    /// Caches the shuffling for a given epoch and state root.
    pub(crate) shuffling_cache: TimeoutRwLock<ShufflingCache>,
    /// Caches a map of `validator_index -> validator_pubkey`.
    pub(crate) validator_pubkey_cache: TimeoutRwLock<ValidatorPubkeyCache>,
    /// A list of any hard-coded forks that have been disabled.
    pub disabled_forks: Vec<String>,
    /// Logging to CLI, etc.
    pub(crate) log: Logger,
}

type BeaconBlockAndState<T> = (BeaconBlock<T>, BeaconState<T>);

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Persists the core `BeaconChain` components (including the head block) and the fork choice.
    ///
    /// ## Notes:
    ///
    /// In this function we first obtain the head, persist fork choice, then persist the head. We
    /// do it in this order to ensure that the persisted head is always from a time prior to fork
    /// choice.
    ///
    /// We want to ensure that the head never out dates the fork choice to avoid having references
    /// to blocks that do not exist in fork choice.
    pub fn persist_head_and_fork_choice(&self) -> Result<(), Error> {
        let canonical_head_block_root = self
            .canonical_head
            .try_read_for(HEAD_LOCK_TIMEOUT)
            .ok_or_else(|| Error::CanonicalHeadLockTimeout)?
            .beacon_block_root;

        let persisted_head = PersistedBeaconChain {
            canonical_head_block_root,
            genesis_block_root: self.genesis_block_root,
            ssz_head_tracker: self.head_tracker.to_ssz_container(),
        };

        let fork_choice_timer = metrics::start_timer(&metrics::PERSIST_FORK_CHOICE);

        self.store.put(
            &Hash256::from_slice(&FORK_CHOICE_DB_KEY),
            &self.fork_choice.as_ssz_container(),
        )?;

        metrics::stop_timer(fork_choice_timer);
        let head_timer = metrics::start_timer(&metrics::PERSIST_HEAD);

        self.store
            .put(&Hash256::from_slice(&BEACON_CHAIN_DB_KEY), &persisted_head)?;

        metrics::stop_timer(head_timer);

        Ok(())
    }

    /// Persists `self.op_pool` to disk.
    ///
    /// ## Notes
    ///
    /// This operation is typically slow and causes a lot of allocations. It should be used
    /// sparingly.
    pub fn persist_op_pool(&self) -> Result<(), Error> {
        let timer = metrics::start_timer(&metrics::PERSIST_OP_POOL);

        self.store.put(
            &Hash256::from_slice(&OP_POOL_DB_KEY),
            &PersistedOperationPool::from_operation_pool(&self.op_pool),
        )?;

        metrics::stop_timer(timer);

        Ok(())
    }

    /// Persists `self.eth1_chain` and its caches to disk.
    pub fn persist_eth1_cache(&self) -> Result<(), Error> {
        let timer = metrics::start_timer(&metrics::PERSIST_OP_POOL);

        if let Some(eth1_chain) = self.eth1_chain.as_ref() {
            self.store.put(
                &Hash256::from_slice(&ETH1_CACHE_DB_KEY),
                &eth1_chain.as_ssz_container(),
            )?;
        }

        metrics::stop_timer(timer);

        Ok(())
    }

    /// Returns the slot _right now_ according to `self.slot_clock`. Returns `Err` if the slot is
    /// unavailable.
    ///
    /// The slot might be unavailable due to an error with the system clock, or if the present time
    /// is before genesis (i.e., a negative slot).
    pub fn slot(&self) -> Result<Slot, Error> {
        self.slot_clock.now().ok_or_else(|| Error::UnableToReadSlot)
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
    ) -> Result<ReverseBlockRootIterator<T::EthSpec, T::Store>, Error> {
        let head = self.head()?;

        let iter = BlockRootsIterator::owned(self.store.clone(), head.beacon_state);

        Ok(ReverseBlockRootIterator::new(
            (head.beacon_block_root, head.beacon_block.slot()),
            iter,
        ))
    }

    pub fn forwards_iter_block_roots(
        &self,
        start_slot: Slot,
    ) -> Result<<T::Store as Store<T::EthSpec>>::ForwardsBlockRootsIterator, Error> {
        let local_head = self.head()?;

        Ok(T::Store::forwards_block_roots_iterator(
            self.store.clone(),
            start_slot,
            local_head.beacon_state,
            local_head.beacon_block_root,
            &self.spec,
        ))
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
    ) -> Result<ReverseBlockRootIterator<T::EthSpec, T::Store>, Error> {
        let block = self
            .get_block(&block_root)?
            .ok_or_else(|| Error::MissingBeaconBlock(block_root))?;
        let state = self
            .get_state(&block.state_root(), Some(block.slot()))?
            .ok_or_else(|| Error::MissingBeaconState(block.state_root()))?;
        let iter = BlockRootsIterator::owned(self.store.clone(), state);
        Ok(ReverseBlockRootIterator::new(
            (block_root, block.slot()),
            iter,
        ))
    }

    /// Traverse backwards from `block_root` to find the root of the ancestor block at `slot`.
    pub fn get_ancestor_block_root(
        &self,
        block_root: Hash256,
        slot: Slot,
    ) -> Result<Option<Hash256>, Error> {
        Ok(self
            .rev_iter_block_roots_from(block_root)?
            .find(|(_, ancestor_slot)| *ancestor_slot == slot)
            .map(|(ancestor_block_root, _)| ancestor_block_root))
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
    ) -> Result<ReverseStateRootIterator<T::EthSpec, T::Store>, Error> {
        let head = self.head()?;
        let slot = head.beacon_state.slot;

        let iter = StateRootsIterator::owned(self.store.clone(), head.beacon_state);

        Ok(ReverseStateRootIterator::new(
            (head.beacon_state_root, slot),
            iter,
        ))
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
        let root = self
            .rev_iter_block_roots()?
            .find(|(_, this_slot)| *this_slot == slot)
            .map(|(root, _)| root);

        if let Some(block_root) = root {
            Ok(self.store.get(&block_root)?)
        } else {
            Ok(None)
        }
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
        self.canonical_head
            .try_read_for(HEAD_LOCK_TIMEOUT)
            .ok_or_else(|| Error::CanonicalHeadLockTimeout)
            .map(|v| v.clone_with_only_committee_caches())
    }

    /// Returns info representing the head block and state.
    ///
    /// A summarized version of `Self::head` that involves less cloning.
    pub fn head_info(&self) -> Result<HeadInfo, Error> {
        let head = self
            .canonical_head
            .try_read_for(HEAD_LOCK_TIMEOUT)
            .ok_or_else(|| Error::CanonicalHeadLockTimeout)?;

        Ok(HeadInfo {
            slot: head.beacon_block.slot(),
            block_root: head.beacon_block_root,
            state_root: head.beacon_state_root,
            current_justified_checkpoint: head.beacon_state.current_justified_checkpoint.clone(),
            finalized_checkpoint: head.beacon_state.finalized_checkpoint.clone(),
            fork: head.beacon_state.fork.clone(),
            genesis_time: head.beacon_state.genesis_time,
            genesis_validators_root: head.beacon_state.genesis_validators_root,
        })
    }

    /// Returns the current heads of the `BeaconChain`. For the canonical head, see `Self::head`.
    ///
    /// Returns `(block_root, block_slot)`.
    pub fn heads(&self) -> Vec<(Hash256, Slot)> {
        self.head_tracker.heads()
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
                        Ok(()) => (),
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
                let state_root = self
                    .rev_iter_state_roots()?
                    .take_while(|(_root, current_slot)| *current_slot >= slot)
                    .find(|(_root, current_slot)| *current_slot == slot)
                    .map(|(root, _slot)| root)
                    .ok_or_else(|| Error::NoStateForSlot(slot))?;

                Ok(self
                    .get_state(&state_root, Some(slot))?
                    .ok_or_else(|| Error::NoStateForSlot(slot))?)
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
            .ok_or_else(|| Error::CanonicalHeadLockTimeout)
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
            .ok_or_else(|| Error::ValidatorPubkeyCacheLockTimeout)?;

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
            .ok_or_else(|| Error::ValidatorPubkeyCacheLockTimeout)?;

        Ok(pubkey_cache.get(validator_index).cloned())
    }

    /// Returns the block canonical root of the current canonical chain at a given slot.
    ///
    /// Returns None if a block doesn't exist at the slot.
    pub fn root_at_slot(&self, target_slot: Slot) -> Result<Option<Hash256>, Error> {
        Ok(self
            .rev_iter_block_roots()?
            .find(|(_root, slot)| *slot == target_slot)
            .map(|(root, _slot)| root))
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

    /// Returns the attestation slot and committee index for a given validator index.
    ///
    /// Information is read from the current state, so only information from the present and prior
    /// epoch is available.
    pub fn validator_attestation_slot_and_index(
        &self,
        validator_index: usize,
        epoch: Epoch,
    ) -> Result<Option<(Slot, u64)>, Error> {
        let as_epoch = |slot: Slot| slot.epoch(T::EthSpec::slots_per_epoch());
        let head_state = &self.head()?.beacon_state;

        let mut state = if epoch == as_epoch(head_state.slot) {
            self.head()?.beacon_state
        } else {
            // The block proposer shuffling is not affected by the state roots, so we don't need to
            // calculate them.
            self.state_at_slot(
                epoch.start_slot(T::EthSpec::slots_per_epoch()),
                StateSkipConfig::WithoutStateRoots,
            )?
        };

        state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;

        if as_epoch(state.slot) != epoch {
            return Err(Error::InvariantViolated(format!(
                "Epochs in consistent in attestation duties lookup: state: {}, requested: {}",
                as_epoch(state.slot),
                epoch
            )));
        }

        if let Some(attestation_duty) =
            state.get_attestation_duties(validator_index, RelativeEpoch::Current)?
        {
            Ok(Some((attestation_duty.slot, attestation_duty.index)))
        } else {
            Ok(None)
        }
    }

    /// Returns an aggregated `Attestation`, if any, that has a matching `attestation.data`.
    ///
    /// The attestation will be obtained from `self.naive_aggregation_pool`.
    pub fn get_aggregated_attestation(
        &self,
        data: &AttestationData,
    ) -> Result<Option<Attestation<T::EthSpec>>, Error> {
        self.naive_aggregation_pool.get(data).map_err(Into::into)
    }

    /// Produce a raw unsigned `Attestation` that is valid for the given `slot` and `index`.
    ///
    /// Always attests to the canonical chain.
    pub fn produce_attestation(
        &self,
        slot: Slot,
        index: CommitteeIndex,
    ) -> Result<Attestation<T::EthSpec>, Error> {
        // Note: we're taking a lock on the head. The work involved here should be trivial enough
        // that the lock should not be held for long.
        let head = self
            .canonical_head
            .try_read_for(HEAD_LOCK_TIMEOUT)
            .ok_or_else(|| Error::CanonicalHeadLockTimeout)?;

        if slot >= head.beacon_block.slot() {
            self.produce_attestation_for_block(
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
                .ok_or_else(|| Error::MissingBeaconState(state_root))?;

            state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;

            self.produce_attestation_for_block(slot, index, beacon_block_root, Cow::Owned(state))
        }
    }

    /// Produce an `AttestationData` that attests to the chain denoted by `block_root` and `state`.
    ///
    /// Permits attesting to any arbitrary chain. Generally, the `produce_attestation_data`
    /// function should be used as it attests to the canonical chain.
    pub fn produce_attestation_for_block(
        &self,
        slot: Slot,
        index: CommitteeIndex,
        beacon_block_root: Hash256,
        mut state: Cow<BeaconState<T::EthSpec>>,
    ) -> Result<Attestation<T::EthSpec>, Error> {
        let epoch = slot.epoch(T::EthSpec::slots_per_epoch());

        if state.slot > slot {
            return Err(Error::CannotAttestToFutureState);
        } else if state.current_epoch() + 1 < epoch {
            let mut_state = state.to_mut();
            while mut_state.current_epoch() + 1 < epoch {
                // Note: here we provide `Hash256::zero()` as the root of the current state. This
                // has the effect of setting the values of all historic state roots to the zero
                // hash. This is an optimization, we don't need the state roots so why calculate
                // them?
                per_slot_processing(mut_state, Some(Hash256::zero()), &self.spec)?;
            }
            mut_state.build_committee_cache(RelativeEpoch::Next, &self.spec)?;
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
                beacon_block_root: beacon_block_root,
                source: state.current_justified_checkpoint.clone(),
                target: Checkpoint {
                    epoch,
                    root: target_root,
                },
            },
            signature: AggregateSignature::empty_signature(),
        })
    }

    /// Accept a new, potentially invalid attestation from the network.
    ///
    /// If valid, the attestation is added to `self.op_pool` and `self.fork_choice`.
    ///
    /// Returns an `Ok(AttestationProcessingOutcome)` if the chain was able to make a determination
    /// about the `attestation` (whether it was invalid or not). Returns an `Err` if there was an
    /// error during this process and no determination was able to be made.
    ///
    /// ## Notes
    ///
    /// - Whilst the `attestation` is added to fork choice, the head is not updated. That must be
    /// done separately.
    ///
    /// The `store_raw` parameter determines if this attestation is to be stored in the operation
    /// pool. `None` indicates the attestation is not stored in the operation pool (we don't have a
    /// validator required to aggregate these attestations). `Some(true)` indicates we are storing a
    /// raw un-aggregated attestation from a subnet into the `op_pool` which is short-lived and `Some(false)`
    /// indicates that we are storing an aggregate attestation in the `op_pool`.
    pub fn process_attestation(
        &self,
        attestation: Attestation<T::EthSpec>,
        attestation_type: AttestationType,
    ) -> Result<AttestationProcessingOutcome, Error> {
        metrics::inc_counter(&metrics::ATTESTATION_PROCESSING_REQUESTS);
        let timer = metrics::start_timer(&metrics::ATTESTATION_PROCESSING_TIMES);

        let outcome = self.process_attestation_internal(attestation.clone(), attestation_type);

        match &outcome {
            Ok(outcome) => match outcome {
                AttestationProcessingOutcome::Processed => {
                    metrics::inc_counter(&metrics::ATTESTATION_PROCESSING_SUCCESSES);
                    trace!(
                        self.log,
                        "Beacon attestation imported";
                        "target_epoch" => attestation.data.target.epoch,
                        "index" => attestation.data.index,
                    );
                    let _ = self
                        .event_handler
                        .register(EventKind::BeaconAttestationImported {
                            attestation: Box::new(attestation),
                        });
                }
                other => {
                    trace!(
                        self.log,
                        "Beacon attestation rejected";
                        "reason" => format!("{:?}", other),
                    );
                    let _ = self
                        .event_handler
                        .register(EventKind::BeaconAttestationRejected {
                            reason: format!("Invalid attestation: {:?}", other),
                            attestation: Box::new(attestation),
                        });
                }
            },
            Err(e) => {
                error!(
                    self.log,
                    "Beacon attestation processing error";
                    "error" => format!("{:?}", e),
                );
                let _ = self
                    .event_handler
                    .register(EventKind::BeaconAttestationRejected {
                        reason: format!("Internal error: {:?}", e),
                        attestation: Box::new(attestation),
                    });
            }
        }

        metrics::stop_timer(timer);
        outcome
    }

    pub fn process_attestation_internal(
        &self,
        attestation: Attestation<T::EthSpec>,
        attestation_type: AttestationType,
    ) -> Result<AttestationProcessingOutcome, Error> {
        let initial_validation_timer =
            metrics::start_timer(&metrics::ATTESTATION_PROCESSING_INITIAL_VALIDATION_TIMES);

        // There is no point in processing an attestation with an empty bitfield. Reject
        // it immediately.
        if attestation.aggregation_bits.num_set_bits() == 0 {
            return Ok(AttestationProcessingOutcome::EmptyAggregationBitfield);
        }

        let attestation_epoch = attestation.data.slot.epoch(T::EthSpec::slots_per_epoch());
        let epoch_now = self.epoch()?;
        let target = attestation.data.target.clone();

        // Attestation must be from the current or previous epoch.
        if attestation_epoch > epoch_now {
            return Ok(AttestationProcessingOutcome::FutureEpoch {
                attestation_epoch,
                current_epoch: epoch_now,
            });
        } else if attestation_epoch + 1 < epoch_now {
            return Ok(AttestationProcessingOutcome::PastEpoch {
                attestation_epoch,
                current_epoch: epoch_now,
            });
        }

        if target.epoch != attestation.data.slot.epoch(T::EthSpec::slots_per_epoch()) {
            return Ok(AttestationProcessingOutcome::BadTargetEpoch);
        }

        // Attestation target must be for a known block.
        //
        // We use fork choice to find the target root, which means that we reject any attestation
        // that has a `target.root` earlier than our latest finalized root. There's no point in
        // processing an attestation that does not include our latest finalized block in its chain.
        //
        // We do not delay consideration for later, we simply drop the attestation.
        let (target_block_slot, target_block_state_root) = if let Some((slot, state_root)) =
            self.fork_choice.block_slot_and_state_root(&target.root)
        {
            (slot, state_root)
        } else {
            return Ok(AttestationProcessingOutcome::UnknownTargetRoot(target.root));
        };

        // Load the slot and state root for `attestation.data.beacon_block_root`.
        //
        // This indirectly checks to see if the `attestation.data.beacon_block_root` is in our fork
        // choice. Any known, non-finalized block should be in fork choice, so this check
        // immediately filters out attestations that attest to a block that has not been processed.
        //
        // Attestations must be for a known block. If the block is unknown, we simply drop the
        // attestation and do not delay consideration for later.
        let block_slot = if let Some((slot, _state_root)) = self
            .fork_choice
            .block_slot_and_state_root(&attestation.data.beacon_block_root)
        {
            slot
        } else {
            return Ok(AttestationProcessingOutcome::UnknownHeadBlock {
                beacon_block_root: attestation.data.beacon_block_root,
            });
        };

        // TODO: currently we do not check the FFG source/target. This is what the spec dictates
        // but it seems wrong.
        //
        // I have opened an issue on the specs repo for this:
        //
        // https://github.com/ethereum/eth2.0-specs/issues/1636
        //
        // We should revisit this code once that issue has been resolved.

        // Attestations must not be for blocks in the future. If this is the case, the attestation
        // should not be considered.
        if block_slot > attestation.data.slot {
            return Ok(AttestationProcessingOutcome::AttestsToFutureBlock {
                block: block_slot,
                attestation: attestation.data.slot,
            });
        }

        metrics::stop_timer(initial_validation_timer);

        let cache_wait_timer =
            metrics::start_timer(&metrics::ATTESTATION_PROCESSING_SHUFFLING_CACHE_WAIT_TIMES);

        let mut shuffling_cache = self
            .shuffling_cache
            .try_write_for(ATTESTATION_CACHE_LOCK_TIMEOUT)
            .ok_or_else(|| Error::AttestationCacheLockTimeout)?;

        metrics::stop_timer(cache_wait_timer);

        let indexed_attestation =
            if let Some(committee_cache) = shuffling_cache.get(attestation_epoch, target.root) {
                if let Some(committee) = committee_cache
                    .get_beacon_committee(attestation.data.slot, attestation.data.index)
                {
                    let indexed_attestation =
                        get_indexed_attestation(committee.committee, &attestation)?;

                    // Drop the shuffling cache to avoid holding the lock for any longer than
                    // required.
                    drop(shuffling_cache);

                    indexed_attestation
                } else {
                    return Ok(AttestationProcessingOutcome::NoCommitteeForSlotAndIndex {
                        slot: attestation.data.slot,
                        index: attestation.data.index,
                    });
                }
            } else {
                // Drop the shuffling cache to avoid holding the lock for any longer than
                // required.
                drop(shuffling_cache);

                debug!(
                    self.log,
                    "Attestation processing cache miss";
                    "attn_epoch" => attestation_epoch.as_u64(),
                    "head_block_epoch" => block_slot.epoch(T::EthSpec::slots_per_epoch()).as_u64(),
                );

                let state_read_timer =
                    metrics::start_timer(&metrics::ATTESTATION_PROCESSING_STATE_READ_TIMES);

                let mut state = self
                    .get_state(&target_block_state_root, Some(target_block_slot))?
                    .ok_or_else(|| Error::MissingBeaconState(target_block_state_root))?;

                metrics::stop_timer(state_read_timer);
                let state_skip_timer =
                    metrics::start_timer(&metrics::ATTESTATION_PROCESSING_STATE_SKIP_TIMES);

                while state.current_epoch() + 1 < attestation_epoch {
                    // Here we tell `per_slot_processing` to skip hashing the state and just
                    // use the zero hash instead.
                    //
                    // The state roots are not useful for the shuffling, so there's no need to
                    // compute them.
                    per_slot_processing(&mut state, Some(Hash256::zero()), &self.spec)?
                }

                metrics::stop_timer(state_skip_timer);
                let committee_building_timer =
                    metrics::start_timer(&metrics::ATTESTATION_PROCESSING_COMMITTEE_BUILDING_TIMES);

                let relative_epoch =
                    RelativeEpoch::from_epoch(state.current_epoch(), attestation_epoch)
                        .map_err(Error::IncorrectStateForAttestation)?;

                state.build_committee_cache(relative_epoch, &self.spec)?;

                let committee_cache = state.committee_cache(relative_epoch)?;

                self.shuffling_cache
                    .try_write_for(ATTESTATION_CACHE_LOCK_TIMEOUT)
                    .ok_or_else(|| Error::AttestationCacheLockTimeout)?
                    .insert(attestation_epoch, target.root, committee_cache);

                metrics::stop_timer(committee_building_timer);

                if let Some(committee) = committee_cache
                    .get_beacon_committee(attestation.data.slot, attestation.data.index)
                {
                    get_indexed_attestation(committee.committee, &attestation)?
                } else {
                    return Ok(AttestationProcessingOutcome::NoCommitteeForSlotAndIndex {
                        slot: attestation.data.slot,
                        index: attestation.data.index,
                    });
                }
            };

        let signature_setup_timer =
            metrics::start_timer(&metrics::ATTESTATION_PROCESSING_SIGNATURE_SETUP_TIMES);

        let pubkey_cache = self
            .validator_pubkey_cache
            .try_read_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
            .ok_or_else(|| Error::ValidatorPubkeyCacheLockTimeout)?;

        let (fork, genesis_validators_root) = self
            .canonical_head
            .try_read_for(HEAD_LOCK_TIMEOUT)
            .ok_or_else(|| Error::CanonicalHeadLockTimeout)
            .map(|head| {
                (
                    head.beacon_state.fork.clone(),
                    head.beacon_state.genesis_validators_root,
                )
            })?;

        let signature_set = indexed_attestation_signature_set_from_pubkeys(
            |validator_index| {
                pubkey_cache
                    .get(validator_index)
                    .map(|pk| Cow::Borrowed(pk.as_point()))
            },
            &attestation.signature,
            &indexed_attestation,
            &fork,
            genesis_validators_root,
            &self.spec,
        )
        .map_err(Error::SignatureSetError)?;

        metrics::stop_timer(signature_setup_timer);

        let signature_verification_timer =
            metrics::start_timer(&metrics::ATTESTATION_PROCESSING_SIGNATURE_TIMES);

        let signature_is_valid = signature_set.is_valid();

        metrics::stop_timer(signature_verification_timer);

        drop(pubkey_cache);

        if signature_is_valid {
            // Provide the attestation to fork choice, updating the validator latest messages but
            // _without_ finding and updating the head.
            if let Err(e) = self
                .fork_choice
                .process_indexed_attestation(&indexed_attestation)
            {
                error!(
                    self.log,
                    "Add attestation to fork choice failed";
                    "beacon_block_root" =>  format!("{}", attestation.data.beacon_block_root),
                    "error" => format!("{:?}", e)
                );
                return Err(e.into());
            }

            // Provide the valid attestation to op pool, which may choose to retain the
            // attestation for inclusion in a future block. If we receive an attestation from a
            // subnet without a validator responsible for aggregating it, we don't store it in the
            // op pool.
            if self.eth1_chain.is_some() {
                match attestation_type {
                    AttestationType::Unaggregated { should_store } if should_store => {
                        match self.naive_aggregation_pool.insert(&attestation) {
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
                            Err(e) => error!(
                                    self.log,
                                    "Failed to store unaggregated attestation";
                                    "error" => format!("{:?}", e),
                                    "index" => attestation.data.index,
                                    "slot" => attestation.data.slot.as_u64(),
                            ),
                        }
                    }
                    AttestationType::Unaggregated { .. } => trace!(
                        self.log,
                        "Did not store unaggregated attestation";
                        "index" => attestation.data.index,
                        "slot" => attestation.data.slot.as_u64(),
                    ),
                    AttestationType::Aggregated => {
                        let index = attestation.data.index;
                        let slot = attestation.data.slot;

                        match self.op_pool.insert_attestation(
                            attestation,
                            &fork,
                            genesis_validators_root,
                            &self.spec,
                        ) {
                            Ok(_) => {}
                            Err(e) => {
                                error!(
                                    self.log,
                                    "Failed to add attestation to op pool";
                                    "error" => format!("{:?}", e),
                                    "index" => index,
                                    "slot" => slot.as_u64(),
                                );
                            }
                        }
                    }
                }
            }

            // Update the metrics.
            metrics::inc_counter(&metrics::ATTESTATION_PROCESSING_SUCCESSES);

            Ok(AttestationProcessingOutcome::Processed)
        } else {
            Ok(AttestationProcessingOutcome::InvalidSignature)
        }
    }

    /// Accept some exit and queue it for inclusion in an appropriate block.
    pub fn process_voluntary_exit(
        &self,
        exit: SignedVoluntaryExit,
    ) -> Result<(), ExitValidationError> {
        match self.wall_clock_state() {
            Ok(state) => {
                if self.eth1_chain.is_some() {
                    self.op_pool.insert_voluntary_exit(exit, &state, &self.spec)
                } else {
                    Ok(())
                }
            }
            Err(e) => {
                error!(
                    &self.log,
                    "Unable to process voluntary exit";
                    "error" => format!("{:?}", e),
                    "reason" => "no state"
                );
                Ok(())
            }
        }
    }

    /// Accept some proposer slashing and queue it for inclusion in an appropriate block.
    pub fn process_proposer_slashing(
        &self,
        proposer_slashing: ProposerSlashing,
    ) -> Result<(), ProposerSlashingValidationError> {
        match self.wall_clock_state() {
            Ok(state) => {
                if self.eth1_chain.is_some() {
                    self.op_pool
                        .insert_proposer_slashing(proposer_slashing, &state, &self.spec)
                } else {
                    Ok(())
                }
            }
            Err(e) => {
                error!(
                    &self.log,
                    "Unable to process proposer slashing";
                    "error" => format!("{:?}", e),
                    "reason" => "no state"
                );
                Ok(())
            }
        }
    }

    /// Accept some attester slashing and queue it for inclusion in an appropriate block.
    pub fn process_attester_slashing(
        &self,
        attester_slashing: AttesterSlashing<T::EthSpec>,
    ) -> Result<(), AttesterSlashingValidationError> {
        match self.wall_clock_state() {
            Ok(state) => {
                if self.eth1_chain.is_some() {
                    self.op_pool
                        .insert_attester_slashing(attester_slashing, &state, &self.spec)
                } else {
                    Ok(())
                }
            }
            Err(e) => {
                error!(
                    &self.log,
                    "Unable to process attester slashing";
                    "error" => format!("{:?}", e),
                    "reason" => "no state"
                );
                Ok(())
            }
        }
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
    ) -> Result<Vec<Hash256>, BlockError> {
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
            let block_root = get_block_root(&block);

            if let Some((child_parent_root, child_slot)) = children.get(i) {
                // If this block has a child in this chain segment, ensure that its parent root matches
                // the root of this block.
                //
                // Without this check it would be possible to have a block verified using the
                // incorrect shuffling. That would be bad, mmkay.
                if block_root != *child_parent_root {
                    return Err(BlockError::NonLinearParentRoots);
                }

                // Ensure that the slots are strictly increasing throughout the chain segement.
                if *child_slot <= block.slot() {
                    return Err(BlockError::NonLinearSlots);
                }
            }

            match check_block_relevancy(&block, Some(block_root), self) {
                // If the block is relevant, add it to the filtered chain segment.
                Ok(_) => filtered_chain_segment.push((block_root, block)),
                // If the block is already known, simply ignore this block.
                Err(BlockError::BlockIsAlreadyKnown) => continue,
                // If the block is the genesis block, simply ignore this block.
                Err(BlockError::GenesisBlock) => continue,
                // If there was an error whilst determining if the block was invalid, return that
                // error.
                Err(BlockError::BeaconChainError(e)) => {
                    return Err(BlockError::BeaconChainError(e))
                }
                // If the block was decided to be irrelevant for any other reason, don't include
                // this block or any of it's children in the filtered chain segment.
                _ => break,
            }
        }

        let mut roots = Vec::with_capacity(filtered_chain_segment.len());

        while !filtered_chain_segment.is_empty() {
            // Determine the epoch of the first block in the remaining segment.
            let start_epoch = filtered_chain_segment
                .first()
                .map(|(_root, block)| block)
                .expect("chain_segment cannot be empty")
                .slot()
                .epoch(T::EthSpec::slots_per_epoch());

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
            let signature_verified_blocks = signature_verify_chain_segment(blocks, self)?;

            // Import the blocks into the chain.
            for signature_verified_block in signature_verified_blocks {
                roots.push(self.process_block(signature_verified_block)?);
            }
        }

        Ok(roots)
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
    ) -> Result<GossipVerifiedBlock<T>, BlockError> {
        GossipVerifiedBlock::new(block, self)
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
    ) -> Result<Hash256, BlockError> {
        // Start the Prometheus timer.
        let full_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_TIMES);

        // Increment the Prometheus counter for block processing requests.
        metrics::inc_counter(&metrics::BLOCK_PROCESSING_REQUESTS);

        // Clone the block so we can provide it to the event handler.
        let block = unverified_block.block().clone();

        // A small closure to group the verification and import errors.
        let import_block = |unverified_block: B| -> Result<Hash256, BlockError> {
            let fully_verified = unverified_block.into_fully_verified_block(self)?;
            self.import_block(fully_verified)
        };

        // Verify and import the block.
        let result = match import_block(unverified_block) {
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
                    block_root: block_root,
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
                    "reason" => format!("{:?}", other),
                );

                let _ = self.event_handler.register(EventKind::BeaconBlockRejected {
                    reason: format!("Invalid block: {:?}", other),
                    block: Box::new(block),
                });

                Err(other)
            }
        };

        // Stop the Prometheus timer.
        metrics::stop_timer(full_timer);

        result
    }

    /// Accepts a fully-verified block and imports it into the chain without performing any
    /// additional verification.
    ///
    /// An error is returned if the block was unable to be imported. It may be partially imported
    /// (i.e., this function is not atomic).
    fn import_block(
        &self,
        fully_verified_block: FullyVerifiedBlock<T>,
    ) -> Result<Hash256, BlockError> {
        let signed_block = fully_verified_block.block;
        let block = &signed_block.message;
        let block_root = fully_verified_block.block_root;
        let state = fully_verified_block.state;
        let parent_block = fully_verified_block.parent_block;
        let intermediate_states = fully_verified_block.intermediate_states;

        let fork_choice_register_timer =
            metrics::start_timer(&metrics::BLOCK_PROCESSING_FORK_CHOICE_REGISTER);

        // If there are new validators in this block, update our pubkey cache.
        //
        // We perform this _before_ adding the block to fork choice because the pubkey cache is
        // used by attestation processing which will only process an attestation if the block is
        // known to fork choice. This ordering ensure that the pubkey cache is always up-to-date.
        self.validator_pubkey_cache
            .try_write_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
            .ok_or_else(|| Error::ValidatorPubkeyCacheLockTimeout)?
            .import_new_pubkeys(&state)?;

        // If the imported block is in the previous or current epochs (according to the
        // wall-clock), check to see if this is the first block of the epoch. If so, add the
        // committee to the shuffling cache.
        if state.current_epoch() + 1 >= self.epoch()?
            && parent_block.slot().epoch(T::EthSpec::slots_per_epoch()) != state.current_epoch()
        {
            let mut shuffling_cache = self
                .shuffling_cache
                .try_write_for(ATTESTATION_CACHE_LOCK_TIMEOUT)
                .ok_or_else(|| Error::AttestationCacheLockTimeout)?;

            let committee_cache = state.committee_cache(RelativeEpoch::Current)?;

            let epoch_start_slot = state
                .current_epoch()
                .start_slot(T::EthSpec::slots_per_epoch());
            let target_root = if state.slot == epoch_start_slot {
                block_root
            } else {
                *state.get_block_root(epoch_start_slot)?
            };

            shuffling_cache.insert(state.current_epoch(), target_root, committee_cache);
        }

        // Register the new block with the fork choice service.
        if let Err(e) = self
            .fork_choice
            .process_block(self, &state, block, block_root)
        {
            error!(
                self.log,
                "Add block to fork choice failed";
                "block_root" =>  format!("{}", block_root),
                "error" => format!("{:?}", e),
            )
        }

        metrics::stop_timer(fork_choice_register_timer);

        self.head_tracker.register_block(block_root, &block);
        metrics::observe(
            &metrics::OPERATIONS_PER_BLOCK_ATTESTATION,
            block.body.attestations.len() as f64,
        );

        let db_write_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_DB_WRITE);

        // Store all the states between the parent block state and this block's slot before storing
        // the final state.
        intermediate_states.commit(&*self.store)?;

        // Store the block and state.
        // NOTE: we store the block *after* the state to guard against inconsistency in the event of
        // a crash, as states are usually looked up from blocks, not the other way around. A better
        // solution would be to use a database transaction (once our choice of database and API
        // settles down).
        // See: https://github.com/sigp/lighthouse/issues/692
        self.store.put_state(&block.state_root, &state)?;
        self.store.put_block(&block_root, signed_block.clone())?;

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
    ) -> Result<BeaconBlockAndState<T::EthSpec>, BlockProductionError> {
        let state = self
            .state_at_slot(slot - 1, StateSkipConfig::WithStateRoots)
            .map_err(|_| BlockProductionError::UnableToProduceAtSlot(slot))?;

        self.produce_block_on_state(state, slot, randao_reveal)
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
    ) -> Result<BeaconBlockAndState<T::EthSpec>, BlockProductionError> {
        metrics::inc_counter(&metrics::BLOCK_PRODUCTION_REQUESTS);
        let timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_TIMES);

        let eth1_chain = self
            .eth1_chain
            .as_ref()
            .ok_or_else(|| BlockProductionError::NoEth1ChainConnection)?;

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

        let mut graffiti: [u8; 32] = [0; 32];
        graffiti.copy_from_slice(GRAFFITI.as_bytes());

        let (proposer_slashings, attester_slashings) =
            self.op_pool.get_slashings(&state, &self.spec);

        let eth1_data = eth1_chain.eth1_data_for_block_production(&state, &self.spec)?;
        let deposits = eth1_chain
            .deposits_for_block_inclusion(&state, &eth1_data, &self.spec)?
            .into();

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
                        .get_attestations(&state, &self.spec)
                        .map_err(BlockProductionError::OpPoolError)?
                        .into(),
                    deposits,
                    voluntary_exits: self.op_pool.get_voluntary_exits(&state, &self.spec).into(),
                },
            },
            // The block is not signed here, that is the task of a validator client.
            signature: Signature::empty_signature(),
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
        let overall_timer = metrics::start_timer(&metrics::FORK_CHOICE_TIMES);

        let result = self.fork_choice_internal();

        if result.is_err() {
            metrics::inc_counter(&metrics::FORK_CHOICE_ERRORS);
        }

        metrics::stop_timer(overall_timer);

        result
    }

    fn fork_choice_internal(&self) -> Result<(), Error> {
        // Determine the root of the block that is the head of the chain.
        let beacon_block_root = self.fork_choice.find_head(&self)?;

        let current_head = self.head_info()?;

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
            .map::<Result<_, Error>, _>(|snapshot| Ok(snapshot))
            .unwrap_or_else(|| {
                let beacon_block = self
                    .get_block(&beacon_block_root)?
                    .ok_or_else(|| Error::MissingBeaconBlock(beacon_block_root))?;

                let beacon_state_root = beacon_block.state_root();
                let beacon_state: BeaconState<T::EthSpec> = self
                    .get_state(&beacon_state_root, Some(beacon_block.slot()))?
                    .ok_or_else(|| Error::MissingBeaconState(beacon_state_root))?;

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

        let old_finalized_epoch = current_head.finalized_checkpoint.epoch;
        let new_finalized_epoch = new_head.beacon_state.finalized_checkpoint.epoch;
        let finalized_root = new_head.beacon_state.finalized_checkpoint.root;

        // It is an error to try to update to a head with a lesser finalized epoch.
        if new_finalized_epoch < old_finalized_epoch {
            return Err(Error::RevertedFinalizedEpoch {
                previous_epoch: old_finalized_epoch,
                new_epoch: new_finalized_epoch,
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
        }

        let update_head_timer = metrics::start_timer(&metrics::UPDATE_HEAD_TIMES);

        // Update the snapshot that stores the head of the chain at the time it received the
        // block.
        *self
            .canonical_head
            .try_write_for(HEAD_LOCK_TIMEOUT)
            .ok_or_else(|| Error::CanonicalHeadLockTimeout)? = new_head;

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

        if new_finalized_epoch != old_finalized_epoch {
            self.after_finalization(old_finalized_epoch, finalized_root)?;
        }

        let _ = self.event_handler.register(EventKind::BeaconHeadChanged {
            reorg: is_reorg,
            previous_head_beacon_block_root: current_head.block_root,
            current_head_beacon_block_root: beacon_block_root,
        });

        Ok(())
    }

    /// Called by the timer on every slot.
    ///
    /// Performs slot-based pruning.
    pub fn per_slot_task(&self) {
        trace!(self.log, "Running beacon chain per slot tasks");
        if let Some(slot) = self.slot_clock.now() {
            self.naive_aggregation_pool.prune(slot);
        }
    }

    /// Called after `self` has had a new block finalized.
    ///
    /// Performs pruning and finality-based optimizations.
    fn after_finalization(
        &self,
        old_finalized_epoch: Epoch,
        finalized_block_root: Hash256,
    ) -> Result<(), Error> {
        let finalized_block = self
            .store
            .get_block(&finalized_block_root)?
            .ok_or_else(|| Error::MissingBeaconBlock(finalized_block_root))?
            .message;

        let new_finalized_epoch = finalized_block.slot.epoch(T::EthSpec::slots_per_epoch());

        if new_finalized_epoch < old_finalized_epoch {
            Err(Error::RevertedFinalizedEpoch {
                previous_epoch: old_finalized_epoch,
                new_epoch: new_finalized_epoch,
            })
        } else {
            self.fork_choice.prune()?;

            self.snapshot_cache
                .try_write_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
                .map(|mut snapshot_cache| {
                    snapshot_cache.prune(new_finalized_epoch);
                })
                .unwrap_or_else(|| {
                    error!(
                        self.log,
                        "Failed to obtain cache write lock";
                        "lock" => "snapshot_cache",
                        "task" => "prune"
                    );
                });

            let finalized_state = self
                .get_state(&finalized_block.state_root, Some(finalized_block.slot))?
                .ok_or_else(|| Error::MissingBeaconState(finalized_block.state_root))?;

            self.op_pool.prune_all(&finalized_state, &self.spec);

            // TODO: configurable max finality distance
            let max_finality_distance = 0;
            self.store_migrator.freeze_to_state(
                finalized_block.state_root,
                finalized_state,
                max_finality_distance,
            );

            let _ = self.event_handler.register(EventKind::BeaconFinalization {
                epoch: new_finalized_epoch,
                root: finalized_block_root,
            });

            Ok(())
        }
    }

    /// Returns `true` if the given block root has not been processed.
    pub fn is_new_block_root(&self, beacon_block_root: &Hash256) -> Result<bool, Error> {
        Ok(!self
            .store
            .exists::<SignedBeaconBlock<T::EthSpec>>(beacon_block_root)?)
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

    /// Gets the current EnrForkId.
    pub fn enr_fork_id(&self) -> EnrForkId {
        // If we are unable to read the slot clock we assume that it is prior to genesis and
        // therefore use the genesis slot.
        let slot = self.slot().unwrap_or_else(|_| self.spec.genesis_slot);

        self.spec.enr_fork_id(slot, self.genesis_validators_root)
    }

    /// Calculates the `Duration` to the next fork, if one exists.
    pub fn duration_to_next_fork(&self) -> Option<Duration> {
        let epoch = self.spec.next_fork_epoch()?;
        self.slot_clock
            .duration_to_slot(epoch.start_slot(T::EthSpec::slots_per_epoch()))
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
