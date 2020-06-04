use crate::ForkChoiceStore;
use proto_array_fork_choice::{Block as ProtoBlock, ProtoArrayForkChoice};
use ssz_derive::{Decode, Encode};
use std::marker::PhantomData;
use types::{
    BeaconBlock, BeaconState, BeaconStateError, Epoch, EthSpec, Hash256, IndexedAttestation, Slot,
};

/// Defined here:
///
/// https://github.com/ethereum/eth2.0-specs/blob/v0.12.0/specs/phase0/fork-choice.md#configuration
const SAFE_SLOTS_TO_UPDATE_JUSTIFIED: u64 = 8;

#[derive(Debug)]
pub enum Error<T> {
    InvalidAttestation(InvalidAttestation),
    // TODO: make this an actual error enum.
    ProtoArrayError(String),
    MissingProtoArrayBlock(Hash256),
    BeaconStateError(BeaconStateError),
    ForkChoiceStoreError(T),
}

impl<T> From<InvalidAttestation> for Error<T> {
    fn from(e: InvalidAttestation) -> Self {
        Error::InvalidAttestation(e)
    }
}

#[derive(Debug)]
pub enum InvalidAttestation {
    /// The attestations aggregation bits were empty when they shouldn't be.
    EmptyAggregationBitfield,
    /// The `attestation.data.beacon_block_root` block is unknown.
    UnknownHeadBlock { beacon_block_root: Hash256 },
    /// The `attestation.data.slot` is not from the same epoch as `data.target.epoch` and therefore
    /// the attestation is invalid.
    BadTargetEpoch,
    /// The target root of the attestation points to a block that we have not verified.
    UnknownTargetRoot(Hash256),
    /// The attestation is for an epoch in the future (with respect to the gossip clock disparity).
    FutureEpoch {
        attestation_epoch: Epoch,
        current_epoch: Epoch,
    },
    /// The attestation is for an epoch in the past (with respect to the gossip clock disparity).
    PastEpoch {
        attestation_epoch: Epoch,
        current_epoch: Epoch,
    },
    /// The attestation references a target root that does not match what is stored in our
    /// database.
    InvalidTarget {
        attestation: Hash256,
        block: Hash256,
    },
    /// The attestation is attesting to a state that is later than itself. (Viz., attesting to the
    /// future).
    AttestsToFutureBlock { block: Slot, attestation: Slot },
}

impl<T> From<String> for Error<T> {
    fn from(e: String) -> Self {
        Error::ProtoArrayError(e)
    }
}

/// Calculate how far `slot` lies from the start of its epoch.
///
/// ## Specification
///
/// Equivalent to:
///
/// https://github.com/ethereum/eth2.0-specs/blob/v0.12.0/specs/phase0/fork-choice.md#compute_slots_since_epoch_start
pub fn compute_slots_since_epoch_start<E: EthSpec>(slot: Slot) -> Slot {
    slot - slot
        .epoch(E::slots_per_epoch())
        .start_slot(E::slots_per_epoch())
}

/// Calculate the first slot in `epoch`.
///
/// ## Specification
///
/// Equivalent to:
///
/// https://github.com/ethereum/eth2.0-specs/blob/v0.12.0/specs/phase0/beacon-chain.md#compute_start_slot_at_epoch
fn compute_start_slot_at_epoch<E: EthSpec>(epoch: Epoch) -> Slot {
    epoch.start_slot(E::slots_per_epoch())
}

/// Used for queuing attestations from the current slot. Only contains the minimum necessary
/// information about the attestation (i.e., it is simplified).
#[derive(Clone, Encode, Decode)]
pub struct QueuedAttestation {
    slot: Slot,
    attesting_indices: Vec<u64>,
    block_root: Hash256,
    target_epoch: Epoch,
}

impl<E: EthSpec> From<&IndexedAttestation<E>> for QueuedAttestation {
    fn from(a: &IndexedAttestation<E>) -> Self {
        Self {
            slot: a.data.slot,
            attesting_indices: a.attesting_indices[..].to_vec(),
            block_root: a.data.beacon_block_root,
            target_epoch: a.data.target.epoch,
        }
    }
}

/// Returns all values in `self.queued_attestations` that have a slot that is earlier than the
/// current slot. Also removes those values from `self.queued_attestations`.
fn dequeue_attestations<T, E>(
    fc_store: &T,
    queued_attestations: &mut Vec<QueuedAttestation>,
) -> Vec<QueuedAttestation>
where
    T: ForkChoiceStore<E>,
    E: EthSpec,
{
    let slot = fc_store.get_current_slot();

    let remaining = queued_attestations.split_off(
        queued_attestations
            .iter()
            .position(|a| a.slot >= slot)
            .unwrap_or(queued_attestations.len()),
    );

    std::mem::replace(queued_attestations, remaining)
}

/// Provides an implementation of "Ethereum 2.0 Phase 0 -- Beacon Chain Fork Choice":
///
/// https://github.com/ethereum/eth2.0-specs/blob/v0.12.0/specs/phase0/fork-choice.md#ethereum-20-phase-0----beacon-chain-fork-choice
///
/// ## Detail
///
/// This struct wraps `ProtoArrayForkChoice` and provides:
///
/// - Management of the justified state and caching of balances.
/// - Queuing of attestations from the current slot.
pub struct ForkChoice<T, E> {
    /// Storage for `ForkChoice`, modelled off the spec `Store` object.
    fc_store: T,
    /// The underlying representation of the block DAG.
    proto_array: ProtoArrayForkChoice,
    /// Used for resolving the `0x00..00` alias back to genesis.
    ///
    /// Does not necessarily need to be the _actual_ genesis, it suffices to be the finalized root
    /// whenever the struct was instantiated.
    genesis_block_root: Hash256,
    /// Stores queued attestations that can be applied once we have advanced a slot.
    queued_attestations: Vec<QueuedAttestation>,
    _phantom: PhantomData<E>,
}

impl<T, E> PartialEq for ForkChoice<T, E>
where
    T: ForkChoiceStore<E> + PartialEq,
    E: EthSpec,
{
    fn eq(&self, other: &Self) -> bool {
        self.fc_store == other.fc_store
            && self.proto_array == other.proto_array
            && self.genesis_block_root == other.genesis_block_root
    }
}

impl<T, E> ForkChoice<T, E>
where
    T: ForkChoiceStore<E>,
    E: EthSpec,
{
    /// Instantiates `Self` from the genesis parameters.
    pub fn from_genesis(
        fc_store: T,
        genesis_block_root: Hash256,
        genesis_block: &BeaconBlock<E>,
        genesis_state: &BeaconState<E>,
    ) -> Result<Self, Error<T::Error>> {
        let finalized_block_slot = genesis_block.slot;
        let finalized_block_state_root = genesis_block.state_root;
        let justified_epoch = genesis_state.current_epoch();
        let finalized_epoch = genesis_state.current_epoch();
        let finalized_root = genesis_block_root;

        let proto_array = ProtoArrayForkChoice::new(
            finalized_block_slot,
            finalized_block_state_root,
            justified_epoch,
            finalized_epoch,
            finalized_root,
        )?;

        Ok(Self {
            fc_store,
            proto_array,
            genesis_block_root,
            queued_attestations: vec![],
            _phantom: PhantomData,
        })
    }

    /// Instantiates `Self` from some existing components.
    ///
    /// This is useful if the existing components have been loaded from disk after a process
    /// restart.
    pub fn from_components(
        fc_store: T,
        proto_array: ProtoArrayForkChoice,
        genesis_block_root: Hash256,
        queued_attestations: Vec<QueuedAttestation>,
    ) -> Self {
        Self {
            fc_store,
            proto_array,
            genesis_block_root,
            queued_attestations,
            _phantom: PhantomData,
        }
    }

    /// Returns the block root of an ancestor of `block_root` at the given `slot`. (Note: `slot` refers
    /// to the block is *returned*, not the one that is supplied.)
    ///
    /// The root of `state` must match the `block.state_root` of the block identified by `block_root`.
    ///
    /// ## Specification
    ///
    /// Equivalent to:
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.12.0/specs/phase0/fork-choice.md#get_ancestor
    fn get_ancestor(
        &self,
        state: &BeaconState<E>,
        block_root: Hash256,
        ancestor_slot: Slot,
    ) -> Result<Hash256, Error<T::Error>>
    where
        T: ForkChoiceStore<E>,
        E: EthSpec,
    {
        let block = self
            .proto_array
            .get_block(&block_root)
            .ok_or_else(|| Error::MissingProtoArrayBlock(block_root))?;

        if block.slot > ancestor_slot {
            self.fc_store
                .ancestor_at_slot(state, block_root, ancestor_slot)
                .map_err(Error::ForkChoiceStoreError)
        } else if block.slot == ancestor_slot {
            Ok(block_root)
        } else {
            // root is older than queried slot, thus a skip slot. Return most recent root prior to
            // slot
            Ok(block_root)
        }
    }

    /// Run the fork choice rule to determine the head.
    ///
    /// ## Specification
    ///
    /// Is equivalent to:
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.12.0/specs/phase0/fork-choice.md#get_head
    pub fn get_head(&mut self) -> Result<Hash256, Error<T::Error>> {
        self.fc_store
            .update_time()
            .map_err(Error::ForkChoiceStoreError)?;

        // Process any attestations that were delayed for consideration.
        self.process_attestation_queue()?;

        let store = &mut self.fc_store;
        let genesis_block_root = self.genesis_block_root;

        let remove_alias = |root| {
            if root == Hash256::zero() {
                genesis_block_root
            } else {
                root
            }
        };

        let result = self
            .proto_array
            .find_head(
                store.justified_checkpoint().epoch,
                remove_alias(store.justified_checkpoint().root),
                store.finalized_checkpoint().epoch,
                store.justified_balances(),
            )
            .map_err(Into::into);

        result
    }

    /// Returns `true` if the given `store` should be updated to set
    /// `state.current_justified_checkpoint` its `justified_checkpoint`.
    ///
    /// ## Specification
    ///
    /// Is equivalent to:
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.12.0/specs/phase0/fork-choice.md#should_update_justified_checkpoint
    fn should_update_justified_checkpoint(
        &mut self,
        state: &BeaconState<E>,
    ) -> Result<bool, Error<T::Error>> {
        self.fc_store
            .update_time()
            .map_err(Error::ForkChoiceStoreError)?;

        let new_justified_checkpoint = &state.current_justified_checkpoint;

        if compute_slots_since_epoch_start::<E>(self.fc_store.get_current_slot())
            < SAFE_SLOTS_TO_UPDATE_JUSTIFIED
        {
            return Ok(true);
        }

        let justified_slot =
            compute_start_slot_at_epoch::<E>(self.fc_store.justified_checkpoint().epoch);
        if self.get_ancestor(state, new_justified_checkpoint.root, justified_slot)?
            != self.fc_store.justified_checkpoint().root
        {
            return Ok(false);
        }

        Ok(true)
    }

    /// Add `block` to the fork choice DAG.
    ///
    /// - `block_root_root` is the root of `block.
    /// - The root of `state` matches `block.state_root`.
    ///
    /// ## Specification
    ///
    /// Approximates:
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.12.0/specs/phase0/fork-choice.md#on_block
    ///
    /// It only approximates the specification since it does not perform verification on the
    /// `block`. It is assumed that this verification has already been completed by the caller.
    pub fn on_block(
        &mut self,
        block: &BeaconBlock<E>,
        block_root: Hash256,
        state: &BeaconState<E>,
    ) -> Result<(), Error<T::Error>> {
        self.fc_store
            .update_time()
            .map_err(Error::ForkChoiceStoreError)?;

        // Process any attestations that were delayed for consideration.
        //
        // It's not strictly necessary to run this here, however it is a nice way to keep the
        // attestation queue small without adding a heartbeat timer.
        self.process_attestation_queue()?;

        // TODO: stuff here
        if state.current_justified_checkpoint.epoch > self.fc_store.justified_checkpoint().epoch {
            if state.current_justified_checkpoint.epoch
                > self.fc_store.best_justified_checkpoint().epoch
            {
                self.fc_store.set_best_justified_checkpoint(state);
            }
            if self.should_update_justified_checkpoint(state)? {
                self.fc_store.set_justified_checkpoint(state);
            }
        }

        if state.finalized_checkpoint.epoch > self.fc_store.finalized_checkpoint().epoch {
            self.fc_store
                .set_finalized_checkpoint(state.finalized_checkpoint);
            let finalized_slot =
                compute_start_slot_at_epoch::<E>(self.fc_store.finalized_checkpoint().epoch);

            if state.current_justified_checkpoint.epoch > self.fc_store.justified_checkpoint().epoch
                || self.get_ancestor(
                    state,
                    self.fc_store.justified_checkpoint().root,
                    finalized_slot,
                )? != self.fc_store.finalized_checkpoint().root
            {
                self.fc_store.set_justified_checkpoint(state);
            }
        }

        let target_slot = block
            .slot
            .epoch(E::slots_per_epoch())
            .start_slot(E::slots_per_epoch());
        let target_root = if block.slot == target_slot {
            block_root
        } else {
            *state
                .get_block_root(target_slot)
                .map_err(Error::BeaconStateError)?
        };

        // This does not apply a vote to the block, it just makes fork choice aware of the block so
        // it can still be identified as the head even if it doesn't have any votes.
        self.proto_array.process_block(ProtoBlock {
            slot: block.slot,
            root: block_root,
            parent_root: Some(block.parent_root),
            target_root,
            state_root: block.state_root,
            justified_epoch: state.current_justified_checkpoint.epoch,
            finalized_epoch: state.finalized_checkpoint.epoch,
        })?;

        Ok(())
    }

    fn validate_on_attestation(
        &self,
        indexed_attestation: &IndexedAttestation<E>,
    ) -> Result<(), InvalidAttestation> {
        // There is no point in processing an attestation with an empty bitfield. Reject
        // it immediately.
        //
        // This is not in the specification, however it should be transparent to other nodes. We
        // return early here to avoid wasting precious resources verifying the rest of it.
        if indexed_attestation.attesting_indices.len() == 0 {
            return Err(InvalidAttestation::EmptyAggregationBitfield);
        }

        let slot_now = self.fc_store.get_current_slot();
        let epoch_now = slot_now.epoch(E::slots_per_epoch());
        let target = indexed_attestation.data.target.clone();

        // Attestation must be from the current or previous epoch.
        if target.epoch > epoch_now {
            return Err(InvalidAttestation::FutureEpoch {
                attestation_epoch: target.epoch,
                current_epoch: epoch_now,
            });
        } else if target.epoch + 1 < epoch_now {
            return Err(InvalidAttestation::PastEpoch {
                attestation_epoch: target.epoch,
                current_epoch: epoch_now,
            });
        }

        if target.epoch != indexed_attestation.data.slot.epoch(E::slots_per_epoch()) {
            return Err(InvalidAttestation::BadTargetEpoch);
        }

        // Attestation target must be for a known block.
        if !self.proto_array.contains_block(&target.root) {
            return Err(InvalidAttestation::UnknownTargetRoot(target.root));
        }

        // Load the block for `attestation.data.beacon_block_root`.
        //
        // This indirectly checks to see if the `attestation.data.beacon_block_root` is in our fork
        // choice. Any known, non-finalized block should be in fork choice, so this check
        // immediately filters out attestations that attest to a block that has not been processed.
        //
        // Attestations must be for a known block. If the block is unknown, we simply drop the
        // attestation and do not delay consideration for later.
        let block = self
            .proto_array
            .get_block(&indexed_attestation.data.beacon_block_root)
            .ok_or_else(|| InvalidAttestation::UnknownHeadBlock {
                beacon_block_root: indexed_attestation.data.beacon_block_root,
            })?;

        if block.target_root != target.root {
            return Err(InvalidAttestation::InvalidTarget {
                attestation: target.root,
                block: block.target_root,
            });
        }

        // Attestations must not be for blocks in the future. If this is the case, the attestation
        // should not be considered.
        if block.slot > indexed_attestation.data.slot {
            return Err(InvalidAttestation::AttestsToFutureBlock {
                block: block.slot,
                attestation: indexed_attestation.data.slot,
            });
        }

        Ok(())
    }

    /// Register `attestation` with the fork choice DAG so that it may influence future calls to
    /// `Self::get_head`.
    ///
    /// ## Specification
    ///
    /// Approximates:
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.12.0/specs/phase0/fork-choice.md#on_attestation
    ///
    /// It only approximates the specification since it does not perform verification on the
    /// `attestation`. It is assumed that this verification has already been completed by the
    /// caller.
    pub fn on_attestation(
        &mut self,
        attestation: &IndexedAttestation<E>,
    ) -> Result<(), Error<T::Error>> {
        // Ensure the store is up-to-date.
        self.fc_store
            .update_time()
            .map_err(Error::ForkChoiceStoreError)?;

        // Ignore any attestations to the zero hash.
        //
        // This is an edge case that results from the spec aliasing the zero hash to the genesis
        // block. Attesters may attest to the zero hash if they have never seen a block.
        //
        // We have two options here:
        //
        //  1. Apply all zero-hash attestations to the zero hash.
        //  2. Ignore all attestations to the zero hash.
        //
        // (1) becomes weird once we hit finality and fork choice drops the genesis block. (2) is
        // fine because votes to the genesis block are not useful; all validators implicitly attest
        // to genesis just by being present in the chain.
        //
        // Additionally, don't add any block hash to fork choice unless we have imported the block.
        if attestation.data.beacon_block_root != Hash256::zero() {
            return Ok(());
        }

        self.validate_on_attestation(attestation)?;

        if attestation.data.slot < self.fc_store.get_current_slot() {
            for validator_index in attestation.attesting_indices.iter() {
                self.proto_array.process_attestation(
                    *validator_index as usize,
                    attestation.data.beacon_block_root,
                    attestation.data.target.epoch,
                )?;
            }
        } else {
            // The spec declares:
            //
            // ```
            // Attestations can only affect the fork choice of subsequent slots.
            // Delay consideration in the fork choice until their slot is in the past.
            // ```
            self.queued_attestations
                .push(QueuedAttestation::from(attestation));
        }

        Ok(())
    }

    /// Processes and removes from the queue any queued attestations which are now able to be
    /// processed due to the slot clock incrementing.
    fn process_attestation_queue(&mut self) -> Result<(), Error<T::Error>> {
        for attestation in dequeue_attestations(&self.fc_store, &mut self.queued_attestations) {
            for validator_index in attestation.attesting_indices.iter() {
                self.proto_array.process_attestation(
                    *validator_index as usize,
                    attestation.block_root,
                    attestation.target_epoch,
                )?;
            }
        }

        Ok(())
    }

    /// Returns a reference to the underlying fork choice DAG.
    pub fn proto_array(&self) -> &ProtoArrayForkChoice {
        &self.proto_array
    }

    /// Returns a reference to the underlying `fc_store`.
    pub fn fc_store(&self) -> &T {
        &self.fc_store
    }

    /// Returns a reference to the genesis block root.
    pub fn genesis_block_root(&self) -> &Hash256 {
        &self.genesis_block_root
    }

    /// Returns a reference to the currently queued attestations.
    pub fn queued_attestations(&self) -> &[QueuedAttestation] {
        &self.queued_attestations
    }

    /// Prunes the underlying fork choice DAG.
    pub fn prune(&mut self) -> Result<(), Error<T::Error>> {
        let finalized_root = self.fc_store.finalized_checkpoint().root;

        self.proto_array
            .maybe_prune(finalized_root)
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing_utils::{StateBuilder, TestingStore};
    use types::{EthSpec, MainnetEthSpec};

    type E = MainnetEthSpec;

    #[test]
    fn slots_since_epoch_start() {
        for epoch in 0..3 {
            for slot in 0..E::slots_per_epoch() {
                let input = epoch * E::slots_per_epoch() + slot;
                assert_eq!(compute_slots_since_epoch_start::<E>(Slot::new(input)), slot)
            }
        }
    }

    #[test]
    fn start_slot_at_epoch() {
        for epoch in 0..3 {
            assert_eq!(
                compute_start_slot_at_epoch::<E>(Epoch::new(epoch)),
                epoch * E::slots_per_epoch()
            )
        }
    }

    fn get_queued_attestations() -> Vec<QueuedAttestation> {
        (1..4)
            .into_iter()
            .map(|i| QueuedAttestation {
                slot: Slot::new(i),
                attesting_indices: vec![],
                block_root: Hash256::zero(),
                target_epoch: Epoch::new(0),
            })
            .collect()
    }

    fn get_slots(queued_attestations: &[QueuedAttestation]) -> Vec<u64> {
        queued_attestations.iter().map(|a| a.slot.into()).collect()
    }

    fn test_queued_attestations(current_time: Slot) -> (Vec<u64>, Vec<u64>) {
        let mut store = TestingStore::from_state(StateBuilder::genesis().build());
        store.current_time = current_time;
        store.update_time().unwrap();

        let mut queued = get_queued_attestations();
        let dequeued = dequeue_attestations::<_, E>(&store, &mut queued);

        (get_slots(&queued), get_slots(&dequeued))
    }

    #[test]
    fn dequeing_attestations() {
        let (queued, dequeued) = test_queued_attestations(Slot::new(0));
        assert_eq!(queued, vec![1, 2, 3]);
        assert!(dequeued.is_empty());

        let (queued, dequeued) = test_queued_attestations(Slot::new(1));
        assert_eq!(queued, vec![1, 2, 3]);
        assert!(dequeued.is_empty());

        let (queued, dequeued) = test_queued_attestations(Slot::new(2));
        assert_eq!(queued, vec![2, 3]);
        assert_eq!(dequeued, vec![1]);

        let (queued, dequeued) = test_queued_attestations(Slot::new(3));
        assert_eq!(queued, vec![3]);
        assert_eq!(dequeued, vec![1, 2]);

        let (queued, dequeued) = test_queued_attestations(Slot::new(4));
        dbg!(&queued);
        assert!(queued.is_empty());
        assert_eq!(dequeued, vec![1, 2, 3]);
    }

    // TODO: test updating justified checkpoint via on_tick.

    /*
    #[test]
    fn update_justified_checkpoint_non_ancestor() {
        let mut store = TestingStore::from_state(
            StateBuilder::genesis()
                .at_slot(Slot::new(E::slots_per_epoch() * 5))
                .justified_at(Epoch::new(1))
                .build(),
        );
        let state = StateBuilder::genesis()
            .at_slot(Slot::new(E::slots_per_epoch() * 6))
            .justified_at(Epoch::new(2))
            .ancestor_root_at_epoch(Epoch::new(1), Hash256::zero())
            .build();

        assert_ne!(
            store
                .get_ancestor(
                    &state,
                    state.current_justified_checkpoint.root,
                    compute_start_slot_at_epoch::<E>(store.justified_checkpoint().epoch),
                )
                .unwrap(),
            store.justified_checkpoint().root,
            "precondition: state must not be a descendant of current justified state"
        );

        assert_eq!(
            should_update_justified_checkpoint::<TestingStore<E>, E>(&mut store, &state),
            Ok(true),
            "inside safe-to-update slots"
        );

        store.current_time = store.current_time + SAFE_SLOTS_TO_UPDATE_JUSTIFIED;

        assert_eq!(
            should_update_justified_checkpoint::<TestingStore<E>, E>(&mut store, &state),
            Ok(false),
            "outside safe-to-update slots"
        );
    }

    #[test]
    fn update_justified_checkpoint_ancestor() {
        let mut store = TestingStore::from_state(
            StateBuilder::genesis()
                .at_slot(Slot::new(E::slots_per_epoch() * 5))
                .justified_at(Epoch::new(1))
                .build(),
        );
        let state = StateBuilder::genesis()
            .at_slot(Slot::new(E::slots_per_epoch() * 6))
            .justified_at(Epoch::new(2))
            .build();

        assert_eq!(
            store
                .get_ancestor(
                    &state,
                    state.current_justified_checkpoint.root,
                    compute_start_slot_at_epoch::<E>(store.justified_checkpoint().epoch),
                )
                .unwrap(),
            store.justified_checkpoint().root,
            "precondition: state must be a descendant of current justified state"
        );

        assert_eq!(
            should_update_justified_checkpoint::<TestingStore<E>, E>(&mut store, &state),
            Ok(true),
            "inside safe-to-update slots"
        );

        store.current_time = store.current_time + SAFE_SLOTS_TO_UPDATE_JUSTIFIED;

        assert_eq!(
            should_update_justified_checkpoint::<TestingStore<E>, E>(&mut store, &state),
            Ok(true),
            "outside safe-to-update slots"
        );
    }
    */
}
