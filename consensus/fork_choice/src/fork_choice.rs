use crate::{ForkChoiceStore, InvalidationOperation};
use proto_array::{Block as ProtoBlock, ExecutionStatus, ProtoArrayForkChoice};
use ssz_derive::{Decode, Encode};
use std::cmp::Ordering;
use std::marker::PhantomData;
use std::time::Duration;
use types::{
    consts::merge::INTERVALS_PER_SLOT, AttestationShufflingId, BeaconBlock, BeaconState,
    BeaconStateError, ChainSpec, Checkpoint, Epoch, EthSpec, ExecPayload, ExecutionBlockHash,
    Hash256, IndexedAttestation, RelativeEpoch, SignedBeaconBlock, Slot,
};

#[derive(Debug)]
pub enum Error<T> {
    InvalidAttestation(InvalidAttestation),
    InvalidBlock(InvalidBlock),
    ProtoArrayError(String),
    InvalidProtoArrayBytes(String),
    InvalidLegacyProtoArrayBytes(String),
    FailedToProcessInvalidExecutionPayload(String),
    FailedToProcessValidExecutionPayload(String),
    MissingProtoArrayBlock(Hash256),
    UnknownAncestor {
        ancestor_slot: Slot,
        descendant_root: Hash256,
    },
    InconsistentOnTick {
        previous_slot: Slot,
        time: Slot,
    },
    BeaconStateError(BeaconStateError),
    AttemptToRevertJustification {
        store: Slot,
        state: Slot,
    },
    ForkChoiceStoreError(T),
    UnableToSetJustifiedCheckpoint(T),
    AfterBlockFailed(T),
    InvalidAnchor {
        block_slot: Slot,
        state_slot: Slot,
    },
    InvalidPayloadStatus {
        block_slot: Slot,
        block_root: Hash256,
        payload_verification_status: PayloadVerificationStatus,
    },
    MissingJustifiedBlock {
        justified_checkpoint: Checkpoint,
    },
    MissingFinalizedBlock {
        finalized_checkpoint: Checkpoint,
    },
    UnrealizedVoteProcessing(state_processing::EpochProcessingError),
}

impl<T> From<InvalidAttestation> for Error<T> {
    fn from(e: InvalidAttestation) -> Self {
        Error::InvalidAttestation(e)
    }
}

impl<T> From<state_processing::EpochProcessingError> for Error<T> {
    fn from(e: state_processing::EpochProcessingError) -> Self {
        Error::UnrealizedVoteProcessing(e)
    }
}

#[derive(Debug)]
pub enum InvalidBlock {
    UnknownParent(Hash256),
    FutureSlot {
        current_slot: Slot,
        block_slot: Slot,
    },
    FinalizedSlot {
        finalized_slot: Slot,
        block_slot: Slot,
    },
    NotFinalizedDescendant {
        finalized_root: Hash256,
        block_ancestor: Option<Hash256>,
    },
}

#[derive(Debug)]
pub enum InvalidAttestation {
    /// The attestations aggregation bits were empty when they shouldn't be.
    EmptyAggregationBitfield,
    /// The `attestation.data.beacon_block_root` block is unknown.
    UnknownHeadBlock { beacon_block_root: Hash256 },
    /// The `attestation.data.slot` is not from the same epoch as `data.target.epoch` and therefore
    /// the attestation is invalid.
    BadTargetEpoch { target: Epoch, slot: Slot },
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
        local: Hash256,
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

/// Indicates if a block has been verified by an execution payload.
///
/// There is no variant for "invalid", since such a block should never be added to fork choice.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PayloadVerificationStatus {
    /// An EL has declared the execution payload to be valid.
    Verified,
    /// An EL has not yet made a determination about the execution payload.
    Optimistic,
    /// The block is either pre-merge-fork, or prior to the terminal PoW block.
    Irrelevant,
}

impl PayloadVerificationStatus {
    /// Returns `true` if the payload was optimistically imported.
    pub fn is_optimistic(&self) -> bool {
        match self {
            PayloadVerificationStatus::Verified => false,
            PayloadVerificationStatus::Optimistic => true,
            PayloadVerificationStatus::Irrelevant => false,
        }
    }
}

/// Calculate how far `slot` lies from the start of its epoch.
///
/// ## Specification
///
/// Equivalent to:
///
/// https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/fork-choice.md#compute_slots_since_epoch_start
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
/// https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/beacon-chain.md#compute_start_slot_at_epoch
fn compute_start_slot_at_epoch<E: EthSpec>(epoch: Epoch) -> Slot {
    epoch.start_slot(E::slots_per_epoch())
}

/// Used for queuing attestations from the current slot. Only contains the minimum necessary
/// information about the attestation.
#[derive(Clone, PartialEq, Encode, Decode)]
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
fn dequeue_attestations(
    current_slot: Slot,
    queued_attestations: &mut Vec<QueuedAttestation>,
) -> Vec<QueuedAttestation> {
    let remaining = queued_attestations.split_off(
        queued_attestations
            .iter()
            .position(|a| a.slot >= current_slot)
            .unwrap_or(queued_attestations.len()),
    );

    std::mem::replace(queued_attestations, remaining)
}

/// Denotes whether an attestation we are processing was received from a block or from gossip.
/// Equivalent to the `is_from_block` `bool` in:
///
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/fork-choice.md#validate_on_attestation
pub enum AttestationFromBlock {
    True,
    False,
}

/// Parameters which are cached between calls to `Self::get_head`.
#[derive(Clone, Copy)]
pub struct ForkchoiceUpdateParameters {
    pub head_root: Hash256,
    pub head_hash: Option<ExecutionBlockHash>,
    pub finalized_hash: Option<ExecutionBlockHash>,
}

/// Provides an implementation of "Ethereum 2.0 Phase 0 -- Beacon Chain Fork Choice":
///
/// https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/fork-choice.md#ethereum-20-phase-0----beacon-chain-fork-choice
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
    /// Attestations that arrived at the current slot and must be queued for later processing.
    queued_attestations: Vec<QueuedAttestation>,
    /// Stores a cache of the values required to be sent to the execution layer.
    forkchoice_update_parameters: Option<ForkchoiceUpdateParameters>,
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
            && self.queued_attestations == other.queued_attestations
    }
}

impl<T, E> ForkChoice<T, E>
where
    T: ForkChoiceStore<E>,
    E: EthSpec,
{
    /// Instantiates `Self` from an anchor (genesis or another finalized checkpoint).
    pub fn from_anchor(
        fc_store: T,
        anchor_block_root: Hash256,
        anchor_block: &SignedBeaconBlock<E>,
        anchor_state: &BeaconState<E>,
    ) -> Result<Self, Error<T::Error>> {
        // Sanity check: the anchor must lie on an epoch boundary.
        if anchor_block.slot() % E::slots_per_epoch() != 0 {
            return Err(Error::InvalidAnchor {
                block_slot: anchor_block.slot(),
                state_slot: anchor_state.slot(),
            });
        }

        let finalized_block_slot = anchor_block.slot();
        let finalized_block_state_root = anchor_block.state_root();
        let current_epoch_shuffling_id =
            AttestationShufflingId::new(anchor_block_root, anchor_state, RelativeEpoch::Current)
                .map_err(Error::BeaconStateError)?;
        let next_epoch_shuffling_id =
            AttestationShufflingId::new(anchor_block_root, anchor_state, RelativeEpoch::Next)
                .map_err(Error::BeaconStateError)?;

        // Default any non-merge execution block hashes to 0x000..000.
        let execution_status = anchor_block.message_merge().map_or_else(
            |()| ExecutionStatus::irrelevant(),
            |message| {
                let execution_payload = &message.body.execution_payload;
                if execution_payload == &<_>::default() {
                    // A default payload does not have execution enabled.
                    ExecutionStatus::irrelevant()
                } else {
                    // Assume that this payload is valid, since the anchor should be a trusted block and
                    // state.
                    ExecutionStatus::Valid(message.body.execution_payload.block_hash())
                }
            },
        );

        let proto_array = ProtoArrayForkChoice::new(
            finalized_block_slot,
            finalized_block_state_root,
            *fc_store.justified_checkpoint(),
            *fc_store.finalized_checkpoint(),
            current_epoch_shuffling_id,
            next_epoch_shuffling_id,
            execution_status,
        )?;

        Ok(Self {
            fc_store,
            proto_array,
            queued_attestations: vec![],
            forkchoice_update_parameters: None,
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
        queued_attestations: Vec<QueuedAttestation>,
    ) -> Self {
        Self {
            fc_store,
            proto_array,
            queued_attestations,
            forkchoice_update_parameters: None,
            _phantom: PhantomData,
        }
    }

    /// Returns cached information that can be used to issue a `forkchoiceUpdated` message to an
    /// execution engine.
    ///
    /// These values are updated each time `Self::get_head` is called. May return `None` if
    /// `Self::get_head` has not yet been called.
    pub fn get_forkchoice_update_parameters(&self) -> Option<ForkchoiceUpdateParameters> {
        self.forkchoice_update_parameters
    }

    /// Returns the block root of an ancestor of `block_root` at the given `slot`. (Note: `slot` refers
    /// to the block that is *returned*, not the one that is supplied.)
    ///
    /// The result may be `Ok(None)` if the block does not descend from the finalized block. This
    /// is an artifact of proto-array, sometimes it contains descendants of blocks that have been
    /// pruned.
    ///
    /// ## Specification
    ///
    /// Equivalent to:
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/fork-choice.md#get_ancestor
    fn get_ancestor(
        &self,
        block_root: Hash256,
        ancestor_slot: Slot,
    ) -> Result<Option<Hash256>, Error<T::Error>>
    where
        T: ForkChoiceStore<E>,
        E: EthSpec,
    {
        let block = self
            .proto_array
            .get_block(&block_root)
            .ok_or(Error::MissingProtoArrayBlock(block_root))?;

        match block.slot.cmp(&ancestor_slot) {
            Ordering::Greater => Ok(self
                .proto_array
                .core_proto_array()
                .iter_block_roots(&block_root)
                // Search for a slot that is **less than or equal to** the target slot. We check
                // for lower slots to account for skip slots.
                .find(|(_, slot)| *slot <= ancestor_slot)
                .map(|(root, _)| root)),
            Ordering::Less => Ok(Some(block_root)),
            Ordering::Equal =>
            // Root is older than queried slot, thus a skip slot. Return most recent root prior
            // to slot.
            {
                Ok(Some(block_root))
            }
        }
    }

    /// Run the fork choice rule to determine the head.
    ///
    /// ## Specification
    ///
    /// Is equivalent to:
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/fork-choice.md#get_head
    pub fn get_head(
        &mut self,
        current_slot: Slot,
        spec: &ChainSpec,
    ) -> Result<Hash256, Error<T::Error>> {
        self.update_time(current_slot)?;

        let store = &mut self.fc_store;

        let head_root = self.proto_array.find_head::<E>(
            *store.justified_checkpoint(),
            *store.finalized_checkpoint(),
            store.justified_balances(),
            store.proposer_boost_root(),
            current_slot,
            spec,
        )?;

        // Cache some values for the next forkchoiceUpdate call to the execution layer.
        let head_hash = self
            .get_block(&head_root)
            .and_then(|b| b.execution_status.block_hash());
        let finalized_root = self.finalized_checkpoint().root;
        let finalized_hash = self
            .get_block(&finalized_root)
            .and_then(|b| b.execution_status.block_hash());
        self.forkchoice_update_parameters = Some(ForkchoiceUpdateParameters {
            head_root,
            head_hash,
            finalized_hash,
        });

        Ok(head_root)
    }

    /// Returns `true` if the given `store` should be updated to set
    /// `state.current_justified_checkpoint` its `justified_checkpoint`.
    ///
    /// ## Specification
    ///
    /// Is equivalent to:
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/fork-choice.md#should_update_justified_checkpoint
    fn should_update_justified_checkpoint(
        &mut self,
        new_justified_checkpoint: Checkpoint,
        state_slot: Slot,
        current_slot: Slot,
        spec: &ChainSpec,
    ) -> Result<bool, Error<T::Error>> {
        //TODO(sean) update_time -> on_tick -> update_checkpoints -> should_update_justified_checkpoint -> update_time
        self.update_time(current_slot)?;

        if compute_slots_since_epoch_start::<E>(self.fc_store.get_current_slot())
            < spec.safe_slots_to_update_justified
        {
            return Ok(true);
        }

        let justified_slot =
            compute_start_slot_at_epoch::<E>(self.fc_store.justified_checkpoint().epoch);

        // This sanity check is not in the spec, but the invariant is implied.
        if justified_slot >= state_slot {
            return Err(Error::AttemptToRevertJustification {
                store: justified_slot,
                state: state_slot,
            });
        }

        // We know that the slot for `new_justified_checkpoint.root` is not greater than
        // `state.slot`, since a state cannot justify its own slot.
        //
        // We know that `new_justified_checkpoint.root` is an ancestor of `state`, since a `state`
        // only ever justifies ancestors.
        //
        // A prior `if` statement protects against a justified_slot that is greater than
        // `state.slot`
        let justified_ancestor =
            self.get_ancestor(new_justified_checkpoint.root, justified_slot)?;
        if justified_ancestor != Some(self.fc_store.justified_checkpoint().root) {
            return Ok(false);
        }

        Ok(true)
    }

    /// See `ProtoArrayForkChoice::process_execution_payload_validation` for documentation.
    pub fn on_valid_execution_payload(
        &mut self,
        block_root: Hash256,
    ) -> Result<(), Error<T::Error>> {
        self.proto_array
            .process_execution_payload_validation(block_root)
            .map_err(Error::FailedToProcessValidExecutionPayload)
    }

    /// See `ProtoArrayForkChoice::process_execution_payload_invalidation` for documentation.
    pub fn on_invalid_execution_payload(
        &mut self,
        op: &InvalidationOperation,
    ) -> Result<(), Error<T::Error>> {
        self.proto_array
            .process_execution_payload_invalidation(op)
            .map_err(Error::FailedToProcessInvalidExecutionPayload)
    }

    /// Add `block` to the fork choice DAG.
    ///
    /// - `block_root` is the root of `block.
    /// - The root of `state` matches `block.state_root`.
    ///
    /// ## Specification
    ///
    /// Approximates:
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/fork-choice.md#on_block
    ///
    /// It only approximates the specification since it does not run the `state_transition` check.
    /// That should have already been called upstream and it's too expensive to call again.
    ///
    /// ## Notes:
    ///
    /// The supplied block **must** pass the `state_transition` function as it will not be run
    /// here.
    #[allow(clippy::too_many_arguments)]
    pub fn on_block<Payload: ExecPayload<E>>(
        &mut self,
        current_slot: Slot,
        block: &BeaconBlock<E, Payload>,
        block_root: Hash256,
        block_delay: Duration,
        state: &mut BeaconState<E>,
        payload_verification_status: PayloadVerificationStatus,
        spec: &ChainSpec,
    ) -> Result<(), Error<T::Error>> {
        let current_slot = self.update_time(current_slot)?;

        // Parent block must be known.
        if !self.proto_array.contains_block(&block.parent_root()) {
            return Err(Error::InvalidBlock(InvalidBlock::UnknownParent(
                block.parent_root(),
            )));
        }

        // Blocks cannot be in the future. If they are, their consideration must be delayed until
        // the are in the past.
        //
        // Note: presently, we do not delay consideration. We just drop the block.
        if block.slot() > current_slot {
            return Err(Error::InvalidBlock(InvalidBlock::FutureSlot {
                current_slot,
                block_slot: block.slot(),
            }));
        }

        // Check that block is later than the finalized epoch slot (optimization to reduce calls to
        // get_ancestor).
        let finalized_slot =
            compute_start_slot_at_epoch::<E>(self.fc_store.finalized_checkpoint().epoch);
        if block.slot() <= finalized_slot {
            return Err(Error::InvalidBlock(InvalidBlock::FinalizedSlot {
                finalized_slot,
                block_slot: block.slot(),
            }));
        }

        // Check block is a descendant of the finalized block at the checkpoint finalized slot.
        //
        // Note: the specification uses `hash_tree_root(block)` instead of `block.parent_root` for
        // the start of this search. I claim that since `block.slot > finalized_slot` it is
        // equivalent to use the parent root for this search. Doing so reduces a single lookup
        // (trivial), but more importantly, it means we don't need to have added `block` to
        // `self.proto_array` to do this search. See:
        //
        // https://github.com/ethereum/eth2.0-specs/pull/1884
        let block_ancestor = self.get_ancestor(block.parent_root(), finalized_slot)?;
        let finalized_root = self.fc_store.finalized_checkpoint().root;
        if block_ancestor != Some(finalized_root) {
            return Err(Error::InvalidBlock(InvalidBlock::NotFinalizedDescendant {
                finalized_root,
                block_ancestor,
            }));
        }

        // Add proposer score boost if the block is timely.
        let is_before_attesting_interval =
            block_delay < Duration::from_secs(spec.seconds_per_slot / INTERVALS_PER_SLOT);
        if current_slot == block.slot() && is_before_attesting_interval {
            self.fc_store.set_proposer_boost_root(block_root);
        }

        // Update store with checkpoints if necessary
        self.update_checkpoints(
            state.current_justified_checkpoint(),
            state.finalized_checkpoint(),
            state.slot(),
            current_slot,
            spec,
        )?;

        // Update unrealized justified/finalized checkpoints.
        let (unrealized_justified_checkpoint, unrealized_finalized_checkpoint) = {
            if !matches!(block, BeaconBlock::Merge(_)) {
                let (justifiable_beacon_state, _) =
                    state_processing::per_epoch_processing::altair::process_justifiable(
                        state, spec,
                    )?;
                let unrealized_justified_checkpoint =
                    justifiable_beacon_state.current_justified_checkpoint;
                let unrealized_finalized_checkpoint = justifiable_beacon_state.finalized_checkpoint;

                // Update best known unrealized justified & finalized checkpoints
                if unrealized_justified_checkpoint.epoch
                    > self.fc_store.unrealized_justified_checkpoint().epoch
                {
                    self.fc_store
                        .set_unrealized_justified_checkpoint(unrealized_justified_checkpoint);
                }
                if unrealized_finalized_checkpoint.epoch
                    > self.fc_store.unrealized_finalized_checkpoint().epoch
                {
                    self.fc_store
                        .set_unrealized_finalized_checkpoint(unrealized_finalized_checkpoint);
                }

                // If block is from past epochs, try to update store's justified & finalized checkpoints right away
                if block.slot().epoch(E::slots_per_epoch())
                    < current_slot.epoch(E::slots_per_epoch())
                {
                    self.update_checkpoints(
                        unrealized_justified_checkpoint,
                        unrealized_finalized_checkpoint,
                        state.slot(),
                        current_slot,
                        spec,
                    )?;
                }

                (
                    Some(unrealized_justified_checkpoint),
                    Some(unrealized_finalized_checkpoint),
                )
            } else {
                (None, None)
            }
        };

        let target_slot = block
            .slot()
            .epoch(E::slots_per_epoch())
            .start_slot(E::slots_per_epoch());
        let target_root = if block.slot() == target_slot {
            block_root
        } else {
            *state
                .get_block_root(target_slot)
                .map_err(Error::BeaconStateError)?
        };

        self.fc_store
            .on_verified_block(block, block_root, state)
            .map_err(Error::AfterBlockFailed)?;

        let execution_status = if let Ok(execution_payload) = block.body().execution_payload() {
            let block_hash = execution_payload.block_hash();

            if block_hash == ExecutionBlockHash::zero() {
                // The block is post-merge-fork, but pre-terminal-PoW block. We don't need to verify
                // the payload.
                ExecutionStatus::irrelevant()
            } else {
                match payload_verification_status {
                    PayloadVerificationStatus::Verified => ExecutionStatus::Valid(block_hash),
                    PayloadVerificationStatus::Optimistic => {
                        ExecutionStatus::Optimistic(block_hash)
                    }
                    // It would be a logic error to declare a block irrelevant if it has an
                    // execution payload with a non-zero block hash.
                    PayloadVerificationStatus::Irrelevant => {
                        return Err(Error::InvalidPayloadStatus {
                            block_slot: block.slot(),
                            block_root,
                            payload_verification_status,
                        })
                    }
                }
            }
        } else {
            // There is no payload to verify.
            ExecutionStatus::irrelevant()
        };

        // This does not apply a vote to the block, it just makes fork choice aware of the block so
        // it can still be identified as the head even if it doesn't have any votes.
        self.proto_array.process_block(ProtoBlock {
            slot: block.slot(),
            root: block_root,
            parent_root: Some(block.parent_root()),
            target_root,
            current_epoch_shuffling_id: AttestationShufflingId::new(
                block_root,
                state,
                RelativeEpoch::Current,
            )
            .map_err(Error::BeaconStateError)?,
            next_epoch_shuffling_id: AttestationShufflingId::new(
                block_root,
                state,
                RelativeEpoch::Next,
            )
            .map_err(Error::BeaconStateError)?,
            state_root: block.state_root(),
            justified_checkpoint: state.current_justified_checkpoint(),
            finalized_checkpoint: state.finalized_checkpoint(),
            execution_status,
            unrealized_justified_checkpoint,
            unrealized_finalized_checkpoint,
        }, current_slot)?;

        Ok(())
    }

    /// Update checkpoints in store if necessary
    fn update_checkpoints(
        &mut self,
        justified_checkpoint: Checkpoint,
        finalized_checkpoint: Checkpoint,
        state_slot: Slot,
        current_slot: Slot,
        spec: &ChainSpec,
    ) -> Result<(), Error<T::Error>> {
        // Update justified checkpoint.
        if justified_checkpoint.epoch > self.fc_store.justified_checkpoint().epoch {
            if justified_checkpoint.epoch > self.fc_store.best_justified_checkpoint().epoch {
                self.fc_store
                    .set_best_justified_checkpoint(justified_checkpoint);
            }
            if self.should_update_justified_checkpoint(
                justified_checkpoint,
                state_slot,
                current_slot,
                spec,
            )? {
                self.fc_store
                    .set_justified_checkpoint(justified_checkpoint)
                    .map_err(Error::UnableToSetJustifiedCheckpoint)?;
            }
        }

        // Update finalized checkpoint.
        if finalized_checkpoint.epoch > self.fc_store.finalized_checkpoint().epoch {
            self.fc_store.set_finalized_checkpoint(finalized_checkpoint);
            self.fc_store
                .set_justified_checkpoint(justified_checkpoint)
                .map_err(Error::UnableToSetJustifiedCheckpoint)?;
        }
        Ok(())
    }

    /// Validates the `epoch` against the current time according to the fork choice store.
    ///
    /// ## Specification
    ///
    /// Equivalent to:
    ///
    /// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/fork-choice.md#validate_target_epoch_against_current_time
    fn validate_target_epoch_against_current_time(
        &self,
        target_epoch: Epoch,
    ) -> Result<(), InvalidAttestation> {
        let slot_now = self.fc_store.get_current_slot();
        let epoch_now = slot_now.epoch(E::slots_per_epoch());

        // Attestation must be from the current or previous epoch.
        if target_epoch > epoch_now {
            return Err(InvalidAttestation::FutureEpoch {
                attestation_epoch: target_epoch,
                current_epoch: epoch_now,
            });
        } else if target_epoch + 1 < epoch_now {
            return Err(InvalidAttestation::PastEpoch {
                attestation_epoch: target_epoch,
                current_epoch: epoch_now,
            });
        }
        Ok(())
    }

    /// Validates the `indexed_attestation` for application to fork choice.
    ///
    /// ## Specification
    ///
    /// Equivalent to:
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/fork-choice.md#validate_on_attestation
    fn validate_on_attestation(
        &self,
        indexed_attestation: &IndexedAttestation<E>,
        is_from_block: AttestationFromBlock,
    ) -> Result<(), InvalidAttestation> {
        // There is no point in processing an attestation with an empty bitfield. Reject
        // it immediately.
        //
        // This is not in the specification, however it should be transparent to other nodes. We
        // return early here to avoid wasting precious resources verifying the rest of it.
        if indexed_attestation.attesting_indices.is_empty() {
            return Err(InvalidAttestation::EmptyAggregationBitfield);
        }

        let target = indexed_attestation.data.target;

        if matches!(is_from_block, AttestationFromBlock::False) {
            self.validate_target_epoch_against_current_time(target.epoch)?;
        }

        if target.epoch != indexed_attestation.data.slot.epoch(E::slots_per_epoch()) {
            return Err(InvalidAttestation::BadTargetEpoch {
                target: target.epoch,
                slot: indexed_attestation.data.slot,
            });
        }

        // Attestation target must be for a known block.
        //
        // We do not delay the block for later processing to reduce complexity and DoS attack
        // surface.
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
            .ok_or(InvalidAttestation::UnknownHeadBlock {
                beacon_block_root: indexed_attestation.data.beacon_block_root,
            })?;

        // If an attestation points to a block that is from an earlier slot than the attestation,
        // then all slots between the block and attestation must be skipped. Therefore if the block
        // is from a prior epoch to the attestation, then the target root must be equal to the root
        // of the block that is being attested to.
        let expected_target = if target.epoch > block.slot.epoch(E::slots_per_epoch()) {
            indexed_attestation.data.beacon_block_root
        } else {
            block.target_root
        };

        if expected_target != target.root {
            return Err(InvalidAttestation::InvalidTarget {
                attestation: target.root,
                local: expected_target,
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
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/fork-choice.md#on_attestation
    ///
    /// It only approximates the specification since it does not perform
    /// `is_valid_indexed_attestation` since that should already have been called upstream and it's
    /// too expensive to call again.
    ///
    /// ## Notes:
    ///
    /// The supplied `attestation` **must** pass the `in_valid_indexed_attestation` function as it
    /// will not be run here.
    pub fn on_attestation(
        &mut self,
        current_slot: Slot,
        attestation: &IndexedAttestation<E>,
        is_from_block: AttestationFromBlock,
    ) -> Result<(), Error<T::Error>> {
        // Ensure the store is up-to-date.
        self.update_time(current_slot)?;

        // Ignore any attestations to the zero hash.
        //
        // This is an edge case that results from the spec aliasing the zero hash to the genesis
        // block. Attesters may attest to the zero hash if they have never seen a block.
        //
        // We have two options here:
        //
        //  1. Apply all zero-hash attestations to the genesis block.
        //  2. Ignore all attestations to the zero hash.
        //
        // (1) becomes weird once we hit finality and fork choice drops the genesis block. (2) is
        // fine because votes to the genesis block are not useful; all validators implicitly attest
        // to genesis just by being present in the chain.
        if attestation.data.beacon_block_root == Hash256::zero() {
            return Ok(());
        }

        self.validate_on_attestation(attestation, is_from_block)?;

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

    /// Call `on_tick` for all slots between `fc_store.get_current_slot()` and the provided
    /// `current_slot`. Returns the value of `self.fc_store.get_current_slot`.
    pub fn update_time(&mut self, current_slot: Slot) -> Result<Slot, Error<T::Error>> {
        while self.fc_store.get_current_slot() < current_slot {
            let previous_slot = self.fc_store.get_current_slot();
            // Note: we are relying upon `on_tick` to update `fc_store.time` to ensure we don't
            // get stuck in a loop.
            //TODO(sean) fix chain spec
            self.on_tick(previous_slot + 1, &ChainSpec::mainnet())?
        }

        // Process any attestations that might now be eligible.
        self.process_attestation_queue()?;

        Ok(self.fc_store.get_current_slot())
    }

    /// Called whenever the current time increases.
    ///
    /// ## Specification
    ///
    /// Equivalent to:
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/fork-choice.md#on_tick
    fn on_tick(&mut self, time: Slot, spec: &ChainSpec) -> Result<(), Error<T::Error>> {
        let store = &mut self.fc_store;
        let previous_slot = store.get_current_slot();

        if time > previous_slot + 1 {
            return Err(Error::InconsistentOnTick {
                previous_slot,
                time,
            });
        }

        // Update store time.
        store.set_current_slot(time);

        let current_slot = store.get_current_slot();

        // Reset proposer boost if this is a new slot.
        if current_slot > previous_slot {
            store.set_proposer_boost_root(Hash256::zero());
        }

        // Not a new epoch, return.
        if !(current_slot > previous_slot
            && compute_slots_since_epoch_start::<E>(current_slot) == 0)
        {
            return Ok(());
        }

        if store.best_justified_checkpoint().epoch > store.justified_checkpoint().epoch {
            store
                .set_justified_checkpoint(*store.best_justified_checkpoint())
                .map_err(Error::ForkChoiceStoreError)?;
        }

        // Update store.justified_checkpoint if a better unrealized justified checkpoint is known
        let unrealized_justified_checkpoint = *store.unrealized_justified_checkpoint();
        let unrealized_finalized_checkpoint = *store.unrealized_finalized_checkpoint();
        self.update_checkpoints(
            unrealized_justified_checkpoint,
            unrealized_finalized_checkpoint,
            current_slot,
            current_slot,
            spec,
        )?;
        Ok(())
    }

    /// Processes and removes from the queue any queued attestations which may now be eligible for
    /// processing due to the slot clock incrementing.
    fn process_attestation_queue(&mut self) -> Result<(), Error<T::Error>> {
        for attestation in dequeue_attestations(
            self.fc_store.get_current_slot(),
            &mut self.queued_attestations,
        ) {
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

    /// Returns `true` if the block is known **and** a descendant of the finalized root.
    pub fn contains_block(&self, block_root: &Hash256) -> bool {
        self.proto_array.contains_block(block_root) && self.is_descendant_of_finalized(*block_root)
    }

    /// Returns a `ProtoBlock` if the block is known **and** a descendant of the finalized root.
    pub fn get_block(&self, block_root: &Hash256) -> Option<ProtoBlock> {
        if self.is_descendant_of_finalized(*block_root) {
            self.proto_array.get_block(block_root)
        } else {
            None
        }
    }

    /// Returns an `ExecutionStatus` if the block is known **and** a descendant of the finalized root.
    pub fn get_block_execution_status(&self, block_root: &Hash256) -> Option<ExecutionStatus> {
        if self.is_descendant_of_finalized(*block_root) {
            self.proto_array.get_block_execution_status(block_root)
        } else {
            None
        }
    }

    /// Returns the `ProtoBlock` for the justified checkpoint.
    ///
    /// ## Notes
    ///
    /// This does *not* return the "best justified checkpoint". It returns the justified checkpoint
    /// that is used for computing balances.
    pub fn get_justified_block(&self) -> Result<ProtoBlock, Error<T::Error>> {
        let justified_checkpoint = self.justified_checkpoint();
        self.get_block(&justified_checkpoint.root)
            .ok_or(Error::MissingJustifiedBlock {
                justified_checkpoint,
            })
    }

    /// Returns the `ProtoBlock` for the finalized checkpoint.
    pub fn get_finalized_block(&self) -> Result<ProtoBlock, Error<T::Error>> {
        let finalized_checkpoint = self.finalized_checkpoint();
        self.get_block(&finalized_checkpoint.root)
            .ok_or(Error::MissingFinalizedBlock {
                finalized_checkpoint,
            })
    }

    /// Return `true` if `block_root` is equal to the finalized root, or a known descendant of it.
    pub fn is_descendant_of_finalized(&self, block_root: Hash256) -> bool {
        self.proto_array
            .is_descendant(self.fc_store.finalized_checkpoint().root, block_root)
    }

    /// Returns `Ok(false)` if a block is not viable to be imported optimistically.
    ///
    /// ## Notes
    ///
    /// Equivalent to the function with the same name in the optimistic sync specs:
    ///
    /// https://github.com/ethereum/consensus-specs/blob/dev/sync/optimistic.md#helpers
    pub fn is_optimistic_candidate_block(
        &self,
        current_slot: Slot,
        block_slot: Slot,
        block_parent_root: &Hash256,
        spec: &ChainSpec,
    ) -> Result<bool, Error<T::Error>> {
        // If the block is sufficiently old, import it.
        if block_slot + spec.safe_slots_to_import_optimistically <= current_slot {
            return Ok(true);
        }

        // If the justified block has execution enabled, then optimistically import any block.
        if self
            .get_justified_block()?
            .execution_status
            .is_execution_enabled()
        {
            return Ok(true);
        }

        // If the parent block has execution enabled, always import the block.
        //
        // TODO(bellatrix): this condition has not yet been merged into the spec.
        //
        // See:
        //
        // https://github.com/ethereum/consensus-specs/pull/2844
        if self
            .proto_array
            .get_block(block_parent_root)
            .map_or(false, |parent| {
                parent.execution_status.is_execution_enabled()
            })
        {
            return Ok(true);
        }

        Ok(false)
    }

    /// Return the current finalized checkpoint.
    pub fn finalized_checkpoint(&self) -> Checkpoint {
        *self.fc_store.finalized_checkpoint()
    }

    /// Return the justified checkpoint.
    pub fn justified_checkpoint(&self) -> Checkpoint {
        *self.fc_store.justified_checkpoint()
    }

    /// Return the best justified checkpoint.
    ///
    /// ## Warning
    ///
    /// This is distinct to the "justified checkpoint" or the "current justified checkpoint". This
    /// "best justified checkpoint" value should only be used internally or for testing.
    pub fn best_justified_checkpoint(&self) -> Checkpoint {
        *self.fc_store.best_justified_checkpoint()
    }

    /// Returns the latest message for a given validator, if any.
    ///
    /// Returns `(block_root, block_slot)`.
    ///
    /// ## Notes
    ///
    /// It may be prudent to call `Self::update_time` before calling this function,
    /// since some attestations might be queued and awaiting processing.
    pub fn latest_message(&self, validator_index: usize) -> Option<(Hash256, Epoch)> {
        self.proto_array.latest_message(validator_index)
    }

    /// Returns a reference to the underlying fork choice DAG.
    pub fn proto_array(&self) -> &ProtoArrayForkChoice {
        &self.proto_array
    }

    /// Returns a reference to the underlying `fc_store`.
    pub fn fc_store(&self) -> &T {
        &self.fc_store
    }

    /// Returns a reference to the currently queued attestations.
    pub fn queued_attestations(&self) -> &[QueuedAttestation] {
        &self.queued_attestations
    }

    /// Returns the store's `proposer_boost_root`.
    pub fn proposer_boost_root(&self) -> Hash256 {
        self.fc_store.proposer_boost_root()
    }

    /// Prunes the underlying fork choice DAG.
    pub fn prune(&mut self) -> Result<(), Error<T::Error>> {
        let finalized_root = self.fc_store.finalized_checkpoint().root;

        self.proto_array
            .maybe_prune(finalized_root)
            .map_err(Into::into)
    }

    /// Instantiate `Self` from some `PersistedForkChoice` generated by a earlier call to
    /// `Self::to_persisted`.
    pub fn from_persisted(
        persisted: PersistedForkChoice,
        fc_store: T,
    ) -> Result<Self, Error<T::Error>> {
        let proto_array = ProtoArrayForkChoice::from_bytes(&persisted.proto_array_bytes)
            .map_err(Error::InvalidProtoArrayBytes)?;

        Ok(Self {
            fc_store,
            proto_array,
            queued_attestations: persisted.queued_attestations,
            forkchoice_update_parameters: None,
            _phantom: PhantomData,
        })
    }

    /// Takes a snapshot of `Self` and stores it in `PersistedForkChoice`, allowing this struct to
    /// be instantiated again later.
    pub fn to_persisted(&self) -> PersistedForkChoice {
        PersistedForkChoice {
            proto_array_bytes: self.proto_array().as_bytes(),
            queued_attestations: self.queued_attestations().to_vec(),
        }
    }
}

/// Helper struct that is used to encode/decode the state of the `ForkChoice` as SSZ bytes.
///
/// This is used when persisting the state of the fork choice to disk.
#[derive(Encode, Decode, Clone)]
pub struct PersistedForkChoice {
    pub proto_array_bytes: Vec<u8>,
    queued_attestations: Vec<QueuedAttestation>,
}

#[cfg(test)]
mod tests {
    use types::{EthSpec, MainnetEthSpec};

    use super::*;

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
        let mut queued = get_queued_attestations();
        let dequeued = dequeue_attestations(current_time, &mut queued);

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
        assert!(queued.is_empty());
        assert_eq!(dequeued, vec![1, 2, 3]);
    }
}
