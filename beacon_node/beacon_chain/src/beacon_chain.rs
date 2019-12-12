use crate::checkpoint::CheckPoint;
use crate::checkpoint_cache::CheckPointCache;
use crate::errors::{BeaconChainError as Error, BlockProductionError};
use crate::eth1_chain::{Eth1Chain, Eth1ChainBackend};
use crate::events::{EventHandler, EventKind};
use crate::fork_choice::{Error as ForkChoiceError, ForkChoice};
use crate::head_tracker::HeadTracker;
use crate::metrics;
use crate::persisted_beacon_chain::{PersistedBeaconChain, BEACON_CHAIN_DB_KEY};
use lmd_ghost::LmdGhost;
use operation_pool::DepositInsertStatus;
use operation_pool::{OperationPool, PersistedOperationPool};
use parking_lot::RwLock;
use slog::{debug, error, info, trace, warn, Logger};
use slot_clock::SlotClock;
use ssz::Encode;
use state_processing::per_block_processing::{
    errors::{
        AttestationValidationError, AttesterSlashingValidationError, DepositValidationError,
        ExitValidationError, ProposerSlashingValidationError,
    },
    verify_attestation_for_state, VerifySignatures,
};
use state_processing::{
    per_block_processing, per_slot_processing, BlockProcessingError, BlockSignatureStrategy,
};
use std::fs;
use std::io::prelude::*;
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::iter::{
    BlockRootsIterator, ReverseBlockRootIterator, ReverseStateRootIterator, StateRootsIterator,
};
use store::{Error as DBError, Migrate, Store};
use tree_hash::TreeHash;
use types::*;

// Text included in blocks.
// Must be 32-bytes or panic.
//
//                          |-------must be this long------|
pub const GRAFFITI: &str = "sigp/lighthouse-0.0.0-prerelease";

/// If true, everytime a block is processed the pre-state, post-state and block are written to SSZ
/// files in the temp directory.
///
/// Only useful for testing.
const WRITE_BLOCK_PROCESSING_SSZ: bool = cfg!(feature = "write_ssz_files");

#[derive(Debug, PartialEq)]
pub enum BlockProcessingOutcome {
    /// Block was valid and imported into the block graph.
    Processed { block_root: Hash256 },
    /// The blocks parent_root is unknown.
    ParentUnknown { parent: Hash256 },
    /// The block slot is greater than the present slot.
    FutureSlot {
        present_slot: Slot,
        block_slot: Slot,
    },
    /// The block state_root does not match the generated state.
    StateRootMismatch { block: Hash256, local: Hash256 },
    /// The block was a genesis block, these blocks cannot be re-imported.
    GenesisBlock,
    /// The slot is finalized, no need to import.
    WouldRevertFinalizedSlot {
        block_slot: Slot,
        finalized_slot: Slot,
    },
    /// Block is already known, no need to re-import.
    BlockIsAlreadyKnown,
    /// The block could not be applied to the state, it is invalid.
    PerBlockProcessingError(BlockProcessingError),
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
    AttestsToFutureState {
        state: Slot,
        attestation: Slot,
    },
    /// The slot is finalized, no need to import.
    FinalizedSlot {
        attestation: Epoch,
        finalized: Epoch,
    },
    Invalid(AttestationValidationError),
}

pub struct HeadInfo {
    pub slot: Slot,
    pub block_root: Hash256,
    pub state_root: Hash256,
    pub finalized_checkpoint: types::Checkpoint,
}

pub trait BeaconChainTypes: Send + Sync + 'static {
    type Store: store::Store<Self::EthSpec>;
    type StoreMigrator: store::Migrate<Self::Store, Self::EthSpec>;
    type SlotClock: slot_clock::SlotClock;
    type LmdGhost: LmdGhost<Self::Store, Self::EthSpec>;
    type Eth1Chain: Eth1ChainBackend<Self::EthSpec>;
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
    /// Provides information from the Ethereum 1 (PoW) chain.
    pub eth1_chain: Option<Eth1Chain<T::Eth1Chain, T::EthSpec>>,
    /// Stores a "snapshot" of the chain at the time the head-of-the-chain block was received.
    pub(crate) canonical_head: RwLock<CheckPoint<T::EthSpec>>,
    /// The root of the genesis block.
    pub genesis_block_root: Hash256,
    /// A state-machine that is updated with information from the network and chooses a canonical
    /// head block.
    pub fork_choice: ForkChoice<T>,
    /// A handler for events generated by the beacon chain.
    pub event_handler: T::EventHandler,
    /// Used to track the heads of the beacon chain.
    pub(crate) head_tracker: HeadTracker,
    /// Provides a small cache of `BeaconState` and `BeaconBlock`.
    pub(crate) checkpoint_cache: CheckPointCache<T::EthSpec>,
    /// Logging to CLI, etc.
    pub(crate) log: Logger,
}

type BeaconBlockAndState<T> = (BeaconBlock<T>, BeaconState<T>);

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Attempt to save this instance to `self.store`.
    pub fn persist(&self) -> Result<(), Error> {
        let timer = metrics::start_timer(&metrics::PERSIST_CHAIN);

        let canonical_head = self.head();

        let finalized_checkpoint = {
            let beacon_block_root = canonical_head.beacon_state.finalized_checkpoint.root;
            let beacon_block = self
                .store
                .get::<BeaconBlock<_>>(&beacon_block_root)?
                .ok_or_else(|| Error::MissingBeaconBlock(beacon_block_root))?;
            let beacon_state_root = beacon_block.state_root;
            let beacon_state = self
                .store
                .get_state(&beacon_state_root, Some(beacon_block.slot))?
                .ok_or_else(|| Error::MissingBeaconState(beacon_state_root))?;

            CheckPoint {
                beacon_block_root,
                beacon_block,
                beacon_state_root,
                beacon_state,
            }
        };

        let p: PersistedBeaconChain<T> = PersistedBeaconChain {
            canonical_head,
            finalized_checkpoint,
            op_pool: PersistedOperationPool::from_operation_pool(&self.op_pool),
            genesis_block_root: self.genesis_block_root,
            ssz_head_tracker: self.head_tracker.to_ssz_container(),
            fork_choice: self.fork_choice.as_ssz_container(),
        };

        let key = Hash256::from_slice(&BEACON_CHAIN_DB_KEY.as_bytes());
        self.store.put(&key, &p)?;

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

    /// Returns the beacon block body for each beacon block root in `roots`.
    ///
    /// Fails if any root in `roots` does not have a corresponding block.
    pub fn get_block_bodies(
        &self,
        roots: &[Hash256],
    ) -> Result<Vec<BeaconBlockBody<T::EthSpec>>, Error> {
        let bodies: Result<Vec<_>, _> = roots
            .iter()
            .map(|root| match self.block_at_root(*root)? {
                Some(block) => Ok(block.body),
                None => Err(Error::DBInconsistent(format!("Missing block: {}", root))),
            })
            .collect();

        Ok(bodies?)
    }

    /// Returns the beacon block header for each beacon block root in `roots`.
    ///
    /// Fails if any root in `roots` does not have a corresponding block.
    pub fn get_block_headers(&self, roots: &[Hash256]) -> Result<Vec<BeaconBlockHeader>, Error> {
        let headers: Result<Vec<BeaconBlockHeader>, _> = roots
            .iter()
            .map(|root| match self.block_at_root(*root)? {
                Some(block) => Ok(block.block_header()),
                None => Err(Error::DBInconsistent("Missing block".into())),
            })
            .collect();

        Ok(headers?)
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
    pub fn rev_iter_block_roots(&self) -> ReverseBlockRootIterator<T::EthSpec, T::Store> {
        let head = self.head();

        let iter = BlockRootsIterator::owned(self.store.clone(), head.beacon_state);

        ReverseBlockRootIterator::new((head.beacon_block_root, head.beacon_block.slot), iter)
    }

    pub fn forwards_iter_block_roots(
        &self,
        start_slot: Slot,
    ) -> <T::Store as Store<T::EthSpec>>::ForwardsBlockRootsIterator {
        let local_head = self.head();
        T::Store::forwards_block_roots_iterator(
            self.store.clone(),
            start_slot,
            local_head.beacon_state,
            local_head.beacon_block_root,
            &self.spec,
        )
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
            .get_block_caching(&block_root)?
            .ok_or_else(|| Error::MissingBeaconBlock(block_root))?;
        let state = self
            .get_state_caching(&block.state_root, Some(block.slot))?
            .ok_or_else(|| Error::MissingBeaconState(block.state_root))?;
        let iter = BlockRootsIterator::owned(self.store.clone(), state);
        Ok(ReverseBlockRootIterator::new(
            (block_root, block.slot),
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
    pub fn rev_iter_state_roots(&self) -> ReverseStateRootIterator<T::EthSpec, T::Store> {
        let head = self.head();
        let slot = head.beacon_state.slot;

        let iter = StateRootsIterator::owned(self.store.clone(), head.beacon_state);

        ReverseStateRootIterator::new((head.beacon_state_root, slot), iter)
    }

    /// Returns the block at the given root, if any.
    ///
    /// ## Errors
    ///
    /// May return a database error.
    pub fn block_at_root(
        &self,
        block_root: Hash256,
    ) -> Result<Option<BeaconBlock<T::EthSpec>>, Error> {
        Ok(self.store.get(&block_root)?)
    }

    /// Returns the block at the given slot, if any. Only returns blocks in the canonical chain.
    ///
    /// ## Errors
    ///
    /// May return a database error.
    pub fn block_at_slot(&self, slot: Slot) -> Result<Option<BeaconBlock<T::EthSpec>>, Error> {
        let root = self
            .rev_iter_block_roots()
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
    ) -> Result<Option<BeaconBlock<T::EthSpec>>, Error> {
        Ok(self.store.get(block_root)?)
    }

    /// Returns the block at the given root, if any.
    ///
    /// ## Errors
    ///
    /// May return a database error.
    fn get_block_caching(
        &self,
        block_root: &Hash256,
    ) -> Result<Option<BeaconBlock<T::EthSpec>>, Error> {
        if let Some(block) = self.checkpoint_cache.get_block(block_root) {
            Ok(Some(block))
        } else {
            Ok(self.store.get(block_root)?)
        }
    }

    /// Returns the state at the given root, if any.
    ///
    /// ## Errors
    ///
    /// May return a database error.
    fn get_state_caching(
        &self,
        state_root: &Hash256,
        slot: Option<Slot>,
    ) -> Result<Option<BeaconState<T::EthSpec>>, Error> {
        if let Some(state) = self.checkpoint_cache.get_state(state_root) {
            Ok(Some(state))
        } else {
            Ok(self.store.get_state(state_root, slot)?)
        }
    }

    /// Returns the state at the given root, if any.
    ///
    /// The return state does not contain any caches other than the committee caches. This method
    /// is much faster than `Self::get_state_caching` because it does not clone the tree hash cache
    /// when the state is found in the checkpoint cache.
    ///
    /// ## Errors
    ///
    /// May return a database error.
    fn get_state_caching_only_with_committee_caches(
        &self,
        state_root: &Hash256,
        slot: Option<Slot>,
    ) -> Result<Option<BeaconState<T::EthSpec>>, Error> {
        if let Some(state) = self
            .checkpoint_cache
            .get_state_only_with_committee_cache(state_root)
        {
            Ok(Some(state))
        } else {
            Ok(self.store.get_state(state_root, slot)?)
        }
    }

    /// Returns a `Checkpoint` representing the head block and state. Contains the "best block";
    /// the head of the canonical `BeaconChain`.
    ///
    /// It is important to note that the `beacon_state` returned may not match the present slot. It
    /// is the state as it was when the head block was received, which could be some slots prior to
    /// now.
    pub fn head(&self) -> CheckPoint<T::EthSpec> {
        self.canonical_head.read().clone()
    }

    /// Returns info representing the head block and state.
    ///
    /// A summarized version of `Self::head` that involves less cloning.
    pub fn head_info(&self) -> HeadInfo {
        let head = self.canonical_head.read();

        HeadInfo {
            slot: head.beacon_block.slot,
            block_root: head.beacon_block_root,
            state_root: head.beacon_state_root,
            finalized_checkpoint: head.beacon_state.finalized_checkpoint.clone(),
        }
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
    pub fn state_at_slot(&self, slot: Slot) -> Result<BeaconState<T::EthSpec>, Error> {
        let head_state = self.head().beacon_state;

        if slot == head_state.slot {
            Ok(head_state)
        } else if slot > head_state.slot {
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

                match per_slot_processing(&mut state, &self.spec) {
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
        } else {
            let state_root = self
                .rev_iter_state_roots()
                .take_while(|(_root, current_slot)| *current_slot >= slot)
                .find(|(_root, current_slot)| *current_slot == slot)
                .map(|(root, _slot)| root)
                .ok_or_else(|| Error::NoStateForSlot(slot))?;

            Ok(self
                .get_state_caching(&state_root, Some(slot))?
                .ok_or_else(|| Error::NoStateForSlot(slot))?)
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
        self.state_at_slot(self.slot()?)
    }

    /// Returns the slot of the highest block in the canonical chain.
    pub fn best_slot(&self) -> Slot {
        self.canonical_head.read().beacon_block.slot
    }

    /// Returns the validator index (if any) for the given public key.
    ///
    /// Information is retrieved from the present `beacon_state.validators`.
    pub fn validator_index(&self, pubkey: &PublicKeyBytes) -> Option<usize> {
        for (i, validator) in self.head().beacon_state.validators.iter().enumerate() {
            if validator.pubkey == *pubkey {
                return Some(i);
            }
        }
        None
    }

    /// Returns the block canonical root of the current canonical chain at a given slot.
    ///
    /// Returns None if a block doesn't exist at the slot.
    pub fn root_at_slot(&self, target_slot: Slot) -> Option<Hash256> {
        self.rev_iter_block_roots()
            .find(|(_root, slot)| *slot == target_slot)
            .map(|(root, _slot)| root)
    }

    /// Reads the slot clock (see `self.read_slot_clock()` and returns the number of slots since
    /// genesis.
    pub fn slots_since_genesis(&self) -> Option<SlotHeight> {
        let now = self.slot().ok()?;
        let genesis_slot = self.spec.genesis_slot;

        if now < genesis_slot {
            None
        } else {
            Some(SlotHeight::from(now.as_u64() - genesis_slot.as_u64()))
        }
    }

    /// Returns the block proposer for a given slot.
    ///
    /// Information is read from the present `beacon_state` shuffling, only information from the
    /// present epoch is available.
    pub fn block_proposer(&self, slot: Slot) -> Result<usize, Error> {
        let epoch = |slot: Slot| slot.epoch(T::EthSpec::slots_per_epoch());
        let head_state = &self.head().beacon_state;

        let mut state = if epoch(slot) == epoch(head_state.slot) {
            self.head().beacon_state.clone()
        } else {
            self.state_at_slot(slot)?
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
        let head_state = &self.head().beacon_state;

        let mut state = if epoch == as_epoch(head_state.slot) {
            self.head().beacon_state.clone()
        } else {
            self.state_at_slot(epoch.start_slot(T::EthSpec::slots_per_epoch()))?
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

    /// Produce an `Attestation` that is valid for the given `slot` and `index`.
    ///
    /// Always attests to the canonical chain.
    pub fn produce_attestation(
        &self,
        slot: Slot,
        index: CommitteeIndex,
    ) -> Result<Attestation<T::EthSpec>, Error> {
        let state = self.state_at_slot(slot)?;
        let head = self.head();

        let data = self.produce_attestation_data_for_block(
            index,
            head.beacon_block_root,
            head.beacon_block.slot,
            &state,
        )?;

        let committee_len = state.get_beacon_committee(slot, index)?.committee.len();

        Ok(Attestation {
            aggregation_bits: BitList::with_capacity(committee_len)?,
            data,
            signature: AggregateSignature::new(),
        })
    }

    /// Produce an `AttestationData` that is valid for the given `slot`, `index`.
    ///
    /// Always attests to the canonical chain.
    pub fn produce_attestation_data(
        &self,
        slot: Slot,
        index: CommitteeIndex,
    ) -> Result<AttestationData, Error> {
        let state = self.state_at_slot(slot)?;
        let head = self.head();

        self.produce_attestation_data_for_block(
            index,
            head.beacon_block_root,
            head.beacon_block.slot,
            &state,
        )
    }

    /// Produce an `AttestationData` that attests to the chain denoted by `block_root` and `state`.
    ///
    /// Permits attesting to any arbitrary chain. Generally, the `produce_attestation_data`
    /// function should be used as it attests to the canonical chain.
    pub fn produce_attestation_data_for_block(
        &self,
        index: CommitteeIndex,
        head_block_root: Hash256,
        head_block_slot: Slot,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<AttestationData, Error> {
        // Collect some metrics.
        metrics::inc_counter(&metrics::ATTESTATION_PRODUCTION_REQUESTS);
        let timer = metrics::start_timer(&metrics::ATTESTATION_PRODUCTION_TIMES);

        let slots_per_epoch = T::EthSpec::slots_per_epoch();
        let current_epoch_start_slot = state.current_epoch().start_slot(slots_per_epoch);

        // The `target_root` is the root of the first block of the current epoch.
        //
        // The `state` does not know the root of the block for it's current slot (it only knows
        // about blocks from prior slots). This creates an edge-case when the state is on the first
        // slot of the epoch -- we're unable to obtain the `target_root` because it is not a prior
        // root.
        //
        // This edge case is handled in two ways:
        //
        // - If the head block is on the same slot as the state, we use it's root.
        // - Otherwise, assume the current slot has been skipped and use the block root from the
        // prior slot.
        //
        // For all other cases, we simply read the `target_root` from `state.latest_block_roots`.
        let target_root = if state.slot == current_epoch_start_slot {
            if head_block_slot == current_epoch_start_slot {
                head_block_root
            } else {
                *state.get_block_root(current_epoch_start_slot - 1)?
            }
        } else {
            *state.get_block_root(current_epoch_start_slot)?
        };

        let target = Checkpoint {
            epoch: state.current_epoch(),
            root: target_root,
        };

        // Collect some metrics.
        metrics::inc_counter(&metrics::ATTESTATION_PRODUCTION_SUCCESSES);
        metrics::stop_timer(timer);

        trace!(
            self.log,
            "Produced beacon attestation data";
            "beacon_block_root" => format!("{}", head_block_root),
            "slot" => state.slot,
            "index" => index
        );

        Ok(AttestationData {
            slot: state.slot,
            index,
            beacon_block_root: head_block_root,
            source: state.current_justified_checkpoint.clone(),
            target,
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
    pub fn process_attestation(
        &self,
        attestation: Attestation<T::EthSpec>,
    ) -> Result<AttestationProcessingOutcome, Error> {
        let outcome = self.process_attestation_internal(attestation.clone());

        match &outcome {
            Ok(outcome) => match outcome {
                AttestationProcessingOutcome::Processed => {
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

        outcome
    }

    pub fn process_attestation_internal(
        &self,
        attestation: Attestation<T::EthSpec>,
    ) -> Result<AttestationProcessingOutcome, Error> {
        metrics::inc_counter(&metrics::ATTESTATION_PROCESSING_REQUESTS);
        let timer = metrics::start_timer(&metrics::ATTESTATION_PROCESSING_TIMES);

        if attestation.aggregation_bits.num_set_bits() == 0 {
            return Ok(AttestationProcessingOutcome::EmptyAggregationBitfield);
        }

        // From the store, load the attestation's "head block".
        //
        // An honest validator would have set this block to be the head of the chain (i.e., the
        // result of running fork choice).
        let result = if let Some(attestation_head_block) =
            self.get_block_caching(&attestation.data.beacon_block_root)?
        {
            // Use the `data.beacon_block_root` to load the state from the latest non-skipped
            // slot preceding the attestation's creation.
            //
            // This state is guaranteed to be in the same chain as the attestation, but it's
            // not guaranteed to be from the same slot or epoch as the attestation.
            let mut state: BeaconState<T::EthSpec> = self
                .get_state_caching_only_with_committee_caches(
                    &attestation_head_block.state_root,
                    Some(attestation_head_block.slot),
                )?
                .ok_or_else(|| Error::MissingBeaconState(attestation_head_block.state_root))?;

            // Ensure the state loaded from the database matches the state of the attestation
            // head block.
            //
            // The state needs to be advanced from the current slot through to the epoch in
            // which the attestation was created in. It would be an error to try and use
            // `state.get_attestation_data_slot(..)` because the state matching the
            // `data.beacon_block_root` isn't necessarily in a nearby epoch to the attestation
            // (e.g., if there were lots of skip slots since the head of the chain and the
            // epoch creation epoch).
            for _ in state.slot.as_u64()
                ..attestation
                    .data
                    .target
                    .epoch
                    .start_slot(T::EthSpec::slots_per_epoch())
                    .as_u64()
            {
                per_slot_processing(&mut state, &self.spec)?;
            }

            state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;

            // Reject any attestation where the `state` loaded from `data.beacon_block_root`
            // has a higher slot than the attestation.
            //
            // Permitting this would allow for attesters to vote on _future_ slots.
            if state.slot > attestation.data.slot {
                Ok(AttestationProcessingOutcome::AttestsToFutureState {
                    state: state.slot,
                    attestation: attestation.data.slot,
                })
            } else {
                self.process_attestation_for_state_and_block(
                    attestation,
                    &state,
                    &attestation_head_block,
                )
            }
        } else {
            // Drop any attestation where we have not processed `attestation.data.beacon_block_root`.
            //
            // This is likely overly restrictive, we could store the attestation for later
            // processing.
            let head_epoch = self.head_info().slot.epoch(T::EthSpec::slots_per_epoch());
            let attestation_epoch = attestation.data.slot.epoch(T::EthSpec::slots_per_epoch());

            // Only log a warning if our head is in a reasonable place to verify this attestation.
            // This avoids excess logging during syncing.
            if head_epoch + 1 >= attestation_epoch {
                debug!(
                    self.log,
                    "Dropped attestation for unknown block";
                    "block" => format!("{}", attestation.data.beacon_block_root)
                );
            } else {
                debug!(
                    self.log,
                    "Dropped attestation for unknown block";
                    "block" => format!("{}", attestation.data.beacon_block_root)
                );
            }

            Ok(AttestationProcessingOutcome::UnknownHeadBlock {
                beacon_block_root: attestation.data.beacon_block_root,
            })
        };

        metrics::stop_timer(timer);

        if let Ok(AttestationProcessingOutcome::Processed) = &result {
            metrics::inc_counter(&metrics::ATTESTATION_PROCESSING_SUCCESSES);
        }

        result
    }

    /// Verifies the `attestation` against the `state` to which it is attesting.
    ///
    /// Updates fork choice with any new latest messages, but _does not_ find or update the head.
    ///
    /// ## Notes
    ///
    /// The given `state` must fulfil one of the following conditions:
    ///
    /// - `state` corresponds to the `block.state_root` identified by
    /// `attestation.data.beacon_block_root`. (Viz., `attestation` was created using `state`).
    /// - `state.slot` is in the same epoch as `data.target.epoch` and
    /// `attestation.data.beacon_block_root` is in the history of `state`.
    ///
    /// Additionally, `attestation.data.beacon_block_root` **must** be available to read in
    /// `self.store` _and_ be the root of the given `block`.
    ///
    /// If the given conditions are not fulfilled, the function may error or provide a false
    /// negative (indicating that a given `attestation` is invalid when it is was validly formed).
    fn process_attestation_for_state_and_block(
        &self,
        attestation: Attestation<T::EthSpec>,
        state: &BeaconState<T::EthSpec>,
        block: &BeaconBlock<T::EthSpec>,
    ) -> Result<AttestationProcessingOutcome, Error> {
        // Find the highest between:
        //
        // - The highest valid finalized epoch we've ever seen (i.e., the head).
        // - The finalized epoch that this attestation was created against.
        let finalized_epoch = std::cmp::max(
            self.head_info().finalized_checkpoint.epoch,
            state.finalized_checkpoint.epoch,
        );

        // A helper function to allow attestation processing to be metered.
        let verify_attestation_for_state = |state, attestation, spec, verify_signatures| {
            let timer = metrics::start_timer(&metrics::ATTESTATION_PROCESSING_CORE);

            let result = verify_attestation_for_state(state, attestation, spec, verify_signatures);

            metrics::stop_timer(timer);
            result
        };

        if block.slot > 0 && block.slot <= finalized_epoch.start_slot(T::EthSpec::slots_per_epoch())
        {
            // Ignore any attestation where the slot of `data.beacon_block_root` is equal to or
            // prior to the finalized epoch.
            //
            // For any valid attestation if the `beacon_block_root` is prior to finalization, then
            // all other parameters (source, target, etc) must all be prior to finalization and
            // therefore no longer interesting.
            //
            // We allow the case where the block is the genesis block. Without this, all
            // attestations prior to the first block being produced would be invalid.
            Ok(AttestationProcessingOutcome::FinalizedSlot {
                attestation: block.slot.epoch(T::EthSpec::slots_per_epoch()),
                finalized: finalized_epoch,
            })
        } else if let Err(e) =
            verify_attestation_for_state(state, &attestation, VerifySignatures::True, &self.spec)
        {
            warn!(
                self.log,
                "Invalid attestation";
                "state_epoch" => state.current_epoch(),
                "error" => format!("{:?}", e),
            );

            Ok(AttestationProcessingOutcome::Invalid(e))
        } else {
            // If the attestation is from the current or previous epoch, supply it to the fork
            // choice. This is FMD GHOST.
            let current_epoch = self.epoch()?;
            if attestation.data.target.epoch == current_epoch
                || attestation.data.target.epoch == current_epoch - 1
            {
                // Provide the attestation to fork choice, updating the validator latest messages but
                // _without_ finding and updating the head.
                if let Err(e) = self
                    .fork_choice
                    .process_attestation(&state, &attestation, block)
                {
                    error!(
                        self.log,
                        "Add attestation to fork choice failed";
                        "fork_choice_integrity" => format!("{:?}", self.fork_choice.verify_integrity()),
                        "beacon_block_root" =>  format!("{}", attestation.data.beacon_block_root),
                        "error" => format!("{:?}", e)
                    );
                    return Err(e.into());
                }
            }

            // Provide the valid attestation to op pool, which may choose to retain the
            // attestation for inclusion in a future block.
            self.op_pool
                .insert_attestation(attestation, state, &self.spec)?;

            // Update the metrics.
            metrics::inc_counter(&metrics::ATTESTATION_PROCESSING_SUCCESSES);

            Ok(AttestationProcessingOutcome::Processed)
        }
    }

    /// Accept some deposit and queue it for inclusion in an appropriate block.
    pub fn process_deposit(
        &self,
        index: u64,
        deposit: Deposit,
    ) -> Result<DepositInsertStatus, DepositValidationError> {
        self.op_pool.insert_deposit(index, deposit)
    }

    /// Accept some exit and queue it for inclusion in an appropriate block.
    pub fn process_voluntary_exit(&self, exit: VoluntaryExit) -> Result<(), ExitValidationError> {
        match self.wall_clock_state() {
            Ok(state) => self.op_pool.insert_voluntary_exit(exit, &state, &self.spec),
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
                self.op_pool
                    .insert_proposer_slashing(proposer_slashing, &state, &self.spec)
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
                self.op_pool
                    .insert_attester_slashing(attester_slashing, &state, &self.spec)
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

    /// Accept some block and attempt to add it to block DAG.
    ///
    /// Will accept blocks from prior slots, however it will reject any block from a future slot.
    pub fn process_block(
        &self,
        block: BeaconBlock<T::EthSpec>,
    ) -> Result<BlockProcessingOutcome, Error> {
        let outcome = self.process_block_internal(block.clone());

        match &outcome {
            Ok(outcome) => match outcome {
                BlockProcessingOutcome::Processed { block_root } => {
                    trace!(
                        self.log,
                        "Beacon block imported";
                        "block_root" => format!("{:?}", block_root),
                        "block_slot" => format!("{:?}", block.slot.as_u64()),
                    );
                    let _ = self.event_handler.register(EventKind::BeaconBlockImported {
                        block_root: *block_root,
                        block: Box::new(block),
                    });
                }
                other => {
                    trace!(
                        self.log,
                        "Beacon block rejected";
                        "reason" => format!("{:?}", other),
                    );
                    let _ = self.event_handler.register(EventKind::BeaconBlockRejected {
                        reason: format!("Invalid block: {:?}", other),
                        block: Box::new(block),
                    });
                }
            },
            Err(e) => {
                error!(
                    self.log,
                    "Beacon block processing error";
                    "error" => format!("{:?}", e),
                );
                let _ = self.event_handler.register(EventKind::BeaconBlockRejected {
                    reason: format!("Internal error: {:?}", e),
                    block: Box::new(block),
                });
            }
        }

        outcome
    }

    /// Accept some block and attempt to add it to block DAG.
    ///
    /// Will accept blocks from prior slots, however it will reject any block from a future slot.
    fn process_block_internal(
        &self,
        block: BeaconBlock<T::EthSpec>,
    ) -> Result<BlockProcessingOutcome, Error> {
        metrics::inc_counter(&metrics::BLOCK_PROCESSING_REQUESTS);
        let full_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_TIMES);

        let finalized_slot = self
            .head_info()
            .finalized_checkpoint
            .epoch
            .start_slot(T::EthSpec::slots_per_epoch());

        if block.slot == 0 {
            return Ok(BlockProcessingOutcome::GenesisBlock);
        }

        if block.slot <= finalized_slot {
            return Ok(BlockProcessingOutcome::WouldRevertFinalizedSlot {
                block_slot: block.slot,
                finalized_slot,
            });
        }

        let block_root_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_BLOCK_ROOT);

        let block_root = block.canonical_root();

        metrics::stop_timer(block_root_timer);

        if block_root == self.genesis_block_root {
            return Ok(BlockProcessingOutcome::GenesisBlock);
        }

        let present_slot = self.slot()?;

        if block.slot > present_slot {
            return Ok(BlockProcessingOutcome::FutureSlot {
                present_slot,
                block_slot: block.slot,
            });
        }

        if self.store.exists::<BeaconBlock<T::EthSpec>>(&block_root)? {
            return Ok(BlockProcessingOutcome::BlockIsAlreadyKnown);
        }

        // Records the time taken to load the block and state from the database during block
        // processing.
        let db_read_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_DB_READ);

        // Load the blocks parent block from the database, returning invalid if that block is not
        // found.
        let parent_block: BeaconBlock<T::EthSpec> =
            match self.get_block_caching(&block.parent_root)? {
                Some(block) => block,
                None => {
                    return Ok(BlockProcessingOutcome::ParentUnknown {
                        parent: block.parent_root,
                    });
                }
            };

        // Load the parent blocks state from the database, returning an error if it is not found.
        // It is an error because if we know the parent block we should also know the parent state.
        let parent_state_root = parent_block.state_root;
        let parent_state = self
            .get_state_caching(&parent_state_root, Some(parent_block.slot))?
            .ok_or_else(|| {
                Error::DBInconsistent(format!("Missing state {:?}", parent_state_root))
            })?;

        metrics::stop_timer(db_read_timer);

        write_block(&block, block_root, &self.log);

        let catchup_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_CATCHUP_STATE);

        // Keep a list of any states that were "skipped" (block-less) in between the parent state
        // slot and the block slot. These will need to be stored in the database.
        let mut intermediate_states = vec![];

        // Transition the parent state to the block slot.
        let mut state: BeaconState<T::EthSpec> = parent_state;
        let distance = block.slot.as_u64().saturating_sub(state.slot.as_u64());
        for i in 0..distance {
            if i > 0 {
                intermediate_states.push(state.clone());
            }
            per_slot_processing(&mut state, &self.spec)?;
        }

        metrics::stop_timer(catchup_timer);

        let committee_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_COMMITTEE);

        state.build_committee_cache(RelativeEpoch::Previous, &self.spec)?;
        state.build_committee_cache(RelativeEpoch::Current, &self.spec)?;

        metrics::stop_timer(committee_timer);

        write_state(
            &format!("state_pre_block_{}", block_root),
            &state,
            &self.log,
        );

        let core_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_CORE);

        // Apply the received block to its parent state (which has been transitioned into this
        // slot).
        match per_block_processing(
            &mut state,
            &block,
            Some(block_root),
            BlockSignatureStrategy::VerifyIndividual,
            &self.spec,
        ) {
            Err(BlockProcessingError::BeaconStateError(e)) => {
                return Err(Error::BeaconStateError(e))
            }
            Err(e) => return Ok(BlockProcessingOutcome::PerBlockProcessingError(e)),
            _ => {}
        }

        metrics::stop_timer(core_timer);

        let state_root_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_STATE_ROOT);

        let state_root = state.update_tree_hash_cache()?;

        metrics::stop_timer(state_root_timer);

        write_state(
            &format!("state_post_block_{}", block_root),
            &state,
            &self.log,
        );

        if block.state_root != state_root {
            return Ok(BlockProcessingOutcome::StateRootMismatch {
                block: block.state_root,
                local: state_root,
            });
        }

        let db_write_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_DB_WRITE);

        // Store all the states between the parent block state and this blocks slot before storing
        // the final state.
        for (i, intermediate_state) in intermediate_states.iter().enumerate() {
            // To avoid doing an unnecessary tree hash, use the following (slot + 1) state's
            // state_roots field to find the root.
            let following_state = match intermediate_states.get(i + 1) {
                Some(following_state) => following_state,
                None => &state,
            };
            let intermediate_state_root =
                following_state.get_state_root(intermediate_state.slot)?;

            self.store
                .put_state(&intermediate_state_root, intermediate_state)?;
        }

        // Store the block and state.
        // NOTE: we store the block *after* the state to guard against inconsistency in the event of
        // a crash, as states are usually looked up from blocks, not the other way around. A better
        // solution would be to use a database transaction (once our choice of database and API
        // settles down).
        // See: https://github.com/sigp/lighthouse/issues/692
        self.store.put_state(&state_root, &state)?;
        self.store.put(&block_root, &block)?;

        metrics::stop_timer(db_write_timer);

        self.head_tracker.register_block(block_root, &block);

        let fork_choice_register_timer =
            metrics::start_timer(&metrics::BLOCK_PROCESSING_FORK_CHOICE_REGISTER);

        // Register the new block with the fork choice service.
        if let Err(e) = self
            .fork_choice
            .process_block(self, &state, &block, block_root)
        {
            error!(
                self.log,
                "Add block to fork choice failed";
                "fork_choice_integrity" => format!("{:?}", self.fork_choice.verify_integrity()),
                "block_root" =>  format!("{}", block_root),
                "error" => format!("{:?}", e),
            )
        }

        metrics::stop_timer(fork_choice_register_timer);

        metrics::inc_counter(&metrics::BLOCK_PROCESSING_SUCCESSES);
        metrics::observe(
            &metrics::OPERATIONS_PER_BLOCK_ATTESTATION,
            block.body.attestations.len() as f64,
        );

        // Store the block in the checkpoint cache.
        //
        // A block that was just imported is likely to be referenced by the next block that we
        // import.
        self.checkpoint_cache.insert(&CheckPoint {
            beacon_block_root: block_root,
            beacon_block: block,
            beacon_state_root: state_root,
            beacon_state: state,
        });

        metrics::stop_timer(full_timer);

        Ok(BlockProcessingOutcome::Processed { block_root })
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
            .state_at_slot(slot - 1)
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
        while state.slot < produce_at_slot {
            per_slot_processing(&mut state, &self.spec)?;
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

        let mut block = BeaconBlock {
            slot: state.slot,
            parent_root,
            state_root: Hash256::zero(),
            // The block is not signed here, that is the task of a validator client.
            signature: Signature::empty_signature(),
            body: BeaconBlockBody {
                randao_reveal,
                eth1_data,
                graffiti,
                proposer_slashings: proposer_slashings.into(),
                attester_slashings: attester_slashings.into(),
                attestations: self.op_pool.get_attestations(&state, &self.spec).into(),
                deposits,
                voluntary_exits: self.op_pool.get_voluntary_exits(&state, &self.spec).into(),
            },
        };

        per_block_processing(
            &mut state,
            &block,
            None,
            BlockSignatureStrategy::NoVerification,
            &self.spec,
        )?;

        let state_root = state.update_tree_hash_cache()?;

        block.state_root = state_root;

        metrics::inc_counter(&metrics::BLOCK_PRODUCTION_SUCCESSES);
        metrics::stop_timer(timer);

        trace!(
            self.log,
            "Produced beacon block";
            "parent" => format!("{}", block.parent_root),
            "attestations" => block.body.attestations.len(),
            "slot" => block.slot
        );

        Ok((block, state))
    }

    /// Execute the fork choice algorithm and enthrone the result as the canonical head.
    pub fn fork_choice(&self) -> Result<(), Error> {
        metrics::inc_counter(&metrics::FORK_CHOICE_REQUESTS);

        // Start fork choice metrics timer.
        let timer = metrics::start_timer(&metrics::FORK_CHOICE_TIMES);

        // Determine the root of the block that is the head of the chain.
        let beacon_block_root = self.fork_choice.find_head(&self)?;

        // If a new head was chosen.
        let result = if beacon_block_root != self.head_info().block_root {
            metrics::inc_counter(&metrics::FORK_CHOICE_CHANGED_HEAD);

            let beacon_block: BeaconBlock<T::EthSpec> = self
                .get_block_caching(&beacon_block_root)?
                .ok_or_else(|| Error::MissingBeaconBlock(beacon_block_root))?;

            let beacon_state_root = beacon_block.state_root;
            let beacon_state: BeaconState<T::EthSpec> = self
                .get_state_caching(&beacon_state_root, Some(beacon_block.slot))?
                .ok_or_else(|| Error::MissingBeaconState(beacon_state_root))?;

            let previous_slot = self.head_info().slot;
            let new_slot = beacon_block.slot;

            // Note: this will declare a re-org if we skip `SLOTS_PER_HISTORICAL_ROOT` blocks
            // between calls to fork choice without swapping between chains. This seems like an
            // extreme-enough scenario that a warning is fine.
            let is_reorg = self.head_info().block_root
                != beacon_state
                    .get_block_root(self.head_info().slot)
                    .map(|root| *root)
                    .unwrap_or_else(|_| Hash256::random());

            // If we switched to a new chain (instead of building atop the present chain).
            if is_reorg {
                metrics::inc_counter(&metrics::FORK_CHOICE_REORG_COUNT);
                warn!(
                    self.log,
                    "Beacon chain re-org";
                    "previous_head" => format!("{}", self.head_info().block_root),
                    "previous_slot" => previous_slot,
                    "new_head_parent" => format!("{}", beacon_block.parent_root),
                    "new_head" => format!("{}", beacon_block_root),
                    "new_slot" => new_slot
                );
            } else {
                debug!(
                    self.log,
                    "Head beacon block";
                    "justified_root" => format!("{}", beacon_state.current_justified_checkpoint.root),
                    "justified_epoch" => beacon_state.current_justified_checkpoint.epoch,
                    "finalized_root" => format!("{}", beacon_state.finalized_checkpoint.root),
                    "finalized_epoch" => beacon_state.finalized_checkpoint.epoch,
                    "root" => format!("{}", beacon_block_root),
                    "slot" => new_slot,
                );
            };

            let old_finalized_epoch = self.head_info().finalized_checkpoint.epoch;
            let new_finalized_epoch = beacon_state.finalized_checkpoint.epoch;
            let finalized_root = beacon_state.finalized_checkpoint.root;

            // Never revert back past a finalized epoch.
            if new_finalized_epoch < old_finalized_epoch {
                Err(Error::RevertedFinalizedEpoch {
                    previous_epoch: old_finalized_epoch,
                    new_epoch: new_finalized_epoch,
                })
            } else {
                let previous_head_beacon_block_root = self.canonical_head.read().beacon_block_root;
                let current_head_beacon_block_root = beacon_block_root;

                let mut new_head = CheckPoint {
                    beacon_block,
                    beacon_block_root,
                    beacon_state,
                    beacon_state_root,
                };

                new_head.beacon_state.build_all_caches(&self.spec)?;

                let timer = metrics::start_timer(&metrics::UPDATE_HEAD_TIMES);

                // Store the head in the checkpoint cache.
                //
                // The head block is likely to be referenced by the next imported block.
                self.checkpoint_cache.insert(&new_head);

                // Update the checkpoint that stores the head of the chain at the time it received the
                // block.
                *self.canonical_head.write() = new_head;

                metrics::stop_timer(timer);

                // Save `self` to `self.store`.
                self.persist()?;

                let _ = self.event_handler.register(EventKind::BeaconHeadChanged {
                    reorg: is_reorg,
                    previous_head_beacon_block_root,
                    current_head_beacon_block_root,
                });

                if new_finalized_epoch != old_finalized_epoch {
                    self.after_finalization(old_finalized_epoch, finalized_root)?;
                }

                Ok(())
            }
        } else {
            Ok(())
        };

        // End fork choice metrics timer.
        metrics::stop_timer(timer);

        if result.is_err() {
            metrics::inc_counter(&metrics::FORK_CHOICE_ERRORS);
        }

        result
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
            .get::<BeaconBlock<T::EthSpec>>(&finalized_block_root)?
            .ok_or_else(|| Error::MissingBeaconBlock(finalized_block_root))?;

        let new_finalized_epoch = finalized_block.slot.epoch(T::EthSpec::slots_per_epoch());

        if new_finalized_epoch < old_finalized_epoch {
            Err(Error::RevertedFinalizedEpoch {
                previous_epoch: old_finalized_epoch,
                new_epoch: new_finalized_epoch,
            })
        } else {
            self.fork_choice
                .process_finalization(&finalized_block, finalized_block_root)?;

            let finalized_state = self
                .store
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
            .exists::<BeaconBlock<T::EthSpec>>(beacon_block_root)?)
    }

    /// Dumps the entire canonical chain, from the head to genesis to a vector for analysis.
    ///
    /// This could be a very expensive operation and should only be done in testing/analysis
    /// activities.
    pub fn chain_dump(&self) -> Result<Vec<CheckPoint<T::EthSpec>>, Error> {
        let mut dump = vec![];

        let mut last_slot = CheckPoint {
            beacon_block: self.head().beacon_block.clone(),
            beacon_block_root: self.head().beacon_block_root,
            beacon_state: self.head().beacon_state.clone(),
            beacon_state_root: self.head().beacon_state_root,
        };

        dump.push(last_slot.clone());

        loop {
            let beacon_block_root = last_slot.beacon_block.parent_root;

            if beacon_block_root == Hash256::zero() {
                break; // Genesis has been reached.
            }

            let beacon_block: BeaconBlock<T::EthSpec> =
                self.store.get(&beacon_block_root)?.ok_or_else(|| {
                    Error::DBInconsistent(format!("Missing block {}", beacon_block_root))
                })?;
            let beacon_state_root = beacon_block.state_root;
            let beacon_state = self
                .store
                .get_state(&beacon_state_root, Some(beacon_block.slot))?
                .ok_or_else(|| {
                    Error::DBInconsistent(format!("Missing state {:?}", beacon_state_root))
                })?;

            let slot = CheckPoint {
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
}

impl<T: BeaconChainTypes> Drop for BeaconChain<T> {
    fn drop(&mut self) {
        if let Err(e) = self.persist() {
            error!(
                self.log,
                "Failed to persist BeaconChain on drop";
                "error" => format!("{:?}", e)
            )
        } else {
            info!(
                self.log,
                "Saved beacon chain state";
            )
        }
    }
}

fn write_state<T: EthSpec>(prefix: &str, state: &BeaconState<T>, log: &Logger) {
    if WRITE_BLOCK_PROCESSING_SSZ {
        let root = Hash256::from_slice(&state.tree_hash_root());
        let filename = format!("{}_slot_{}_root_{}.ssz", prefix, state.slot, root);
        let mut path = std::env::temp_dir().join("lighthouse");
        let _ = fs::create_dir_all(path.clone());
        path = path.join(filename);

        match fs::File::create(path.clone()) {
            Ok(mut file) => {
                let _ = file.write_all(&state.as_ssz_bytes());
            }
            Err(e) => error!(
                log,
                "Failed to log state";
                "path" => format!("{:?}", path),
                "error" => format!("{:?}", e)
            ),
        }
    }
}

fn write_block<T: EthSpec>(block: &BeaconBlock<T>, root: Hash256, log: &Logger) {
    if WRITE_BLOCK_PROCESSING_SSZ {
        let filename = format!("block_slot_{}_root{}.ssz", block.slot, root);
        let mut path = std::env::temp_dir().join("lighthouse");
        let _ = fs::create_dir_all(path.clone());
        path = path.join(filename);

        match fs::File::create(path.clone()) {
            Ok(mut file) => {
                let _ = file.write_all(&block.as_ssz_bytes());
            }
            Err(e) => error!(
                log,
                "Failed to log block";
                "path" => format!("{:?}", path),
                "error" => format!("{:?}", e)
            ),
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
