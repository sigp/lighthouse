use crate::{ForkChoiceStore, InvalidationOperation};
use proto_array::{
    Block as ProtoBlock, CountUnrealizedFull, ExecutionStatus, ProposerHeadError, ProposerHeadInfo,
    ProtoArrayForkChoice, ReOrgThreshold,
};
use slog::{crit, debug, warn, Logger};
use ssz_derive::{Decode, Encode};
use state_processing::{
    per_block_processing::errors::AttesterSlashingValidationError, per_epoch_processing,
};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::time::Duration;
use types::{
    consts::merge::INTERVALS_PER_SLOT, AbstractExecPayload, AttestationShufflingId,
    AttesterSlashing, BeaconBlockRef, BeaconState, BeaconStateError, ChainSpec, Checkpoint, Epoch,
    EthSpec, ExecPayload, ExecutionBlockHash, Hash256, IndexedAttestation, RelativeEpoch,
    SignedBeaconBlock, Slot,
};

#[derive(Debug)]
pub enum Error<T> {
    InvalidAttestation(InvalidAttestation),
    InvalidAttesterSlashing(AttesterSlashingValidationError),
    InvalidBlock(InvalidBlock),
    ProtoArrayStringError(String),
    ProtoArrayError(proto_array::Error),
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
    ProposerHeadError(T),
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
    WrongSlotForGetProposerHead {
        current_slot: Slot,
        fc_store_slot: Slot,
    },
    ProposerBoostNotExpiredForGetProposerHead {
        proposer_boost_root: Hash256,
    },
    UnrealizedVoteProcessing(state_processing::EpochProcessingError),
    ParticipationCacheBuild(BeaconStateError),
    ValidatorStatuses(BeaconStateError),
}

impl<T> From<InvalidAttestation> for Error<T> {
    fn from(e: InvalidAttestation) -> Self {
        Error::InvalidAttestation(e)
    }
}

impl<T> From<AttesterSlashingValidationError> for Error<T> {
    fn from(e: AttesterSlashingValidationError) -> Self {
        Error::InvalidAttesterSlashing(e)
    }
}

impl<T> From<state_processing::EpochProcessingError> for Error<T> {
    fn from(e: state_processing::EpochProcessingError) -> Self {
        Error::UnrealizedVoteProcessing(e)
    }
}

#[derive(Debug, Clone, Copy)]
/// Controls how fork choice should behave when restoring from a persisted fork choice.
pub enum ResetPayloadStatuses {
    /// Reset all payload statuses back to "optimistic".
    Always,
    /// Only reset all payload statuses back to "optimistic" when an "invalid" block is present.
    OnlyWithInvalidPayload,
}

impl ResetPayloadStatuses {
    /// When `should_always_reset == True`, return `ResetPayloadStatuses::Always`.
    pub fn always_reset_conditionally(should_always_reset: bool) -> Self {
        if should_always_reset {
            ResetPayloadStatuses::Always
        } else {
            ResetPayloadStatuses::OnlyWithInvalidPayload
        }
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
        Error::ProtoArrayStringError(e)
    }
}

impl<T> From<proto_array::Error> for Error<T> {
    fn from(e: proto_array::Error) -> Self {
        Error::ProtoArrayError(e)
    }
}

/// Indicates whether the unrealized justification of a block should be calculated and tracked.
/// If a block has been finalized, this can be set to false. This is useful when syncing finalized
/// portions of the chain. Otherwise this should always be set to true.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CountUnrealized {
    True,
    False,
}

impl CountUnrealized {
    pub fn is_true(&self) -> bool {
        matches!(self, CountUnrealized::True)
    }

    pub fn and(&self, other: CountUnrealized) -> CountUnrealized {
        if self.is_true() && other.is_true() {
            CountUnrealized::True
        } else {
            CountUnrealized::False
        }
    }
}

impl From<bool> for CountUnrealized {
    fn from(count_unrealized: bool) -> Self {
        if count_unrealized {
            CountUnrealized::True
        } else {
            CountUnrealized::False
        }
    }
}

#[derive(Copy, Clone)]
enum UpdateJustifiedCheckpointSlots {
    OnTick {
        current_slot: Slot,
    },
    OnBlock {
        state_slot: Slot,
        current_slot: Slot,
    },
}

impl UpdateJustifiedCheckpointSlots {
    fn current_slot(&self) -> Slot {
        match self {
            UpdateJustifiedCheckpointSlots::OnTick { current_slot } => *current_slot,
            UpdateJustifiedCheckpointSlots::OnBlock { current_slot, .. } => *current_slot,
        }
    }

    fn state_slot(&self) -> Option<Slot> {
        match self {
            UpdateJustifiedCheckpointSlots::OnTick { .. } => None,
            UpdateJustifiedCheckpointSlots::OnBlock { state_slot, .. } => Some(*state_slot),
        }
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
#[derive(Clone, Copy)]
pub enum AttestationFromBlock {
    True,
    False,
}

/// Parameters which are cached between calls to `Self::get_head`.
#[derive(Clone, Copy)]
pub struct ForkchoiceUpdateParameters {
    pub head_root: Hash256,
    pub head_hash: Option<ExecutionBlockHash>,
    pub justified_hash: Option<ExecutionBlockHash>,
    pub finalized_hash: Option<ExecutionBlockHash>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ForkChoiceView {
    pub head_block_root: Hash256,
    pub justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
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
    forkchoice_update_parameters: ForkchoiceUpdateParameters,
    /// The most recent result of running `Self::get_head`.
    head_block_root: Hash256,
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
        current_slot: Option<Slot>,
        count_unrealized_full_config: CountUnrealizedFull,
        spec: &ChainSpec,
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

        let execution_status = anchor_block.message().execution_payload().map_or_else(
            // If the block doesn't have an execution payload then it can't have
            // execution enabled.
            |_| ExecutionStatus::irrelevant(),
            |execution_payload| {
                if execution_payload.is_default_with_empty_roots() {
                    // A default payload does not have execution enabled.
                    ExecutionStatus::irrelevant()
                } else {
                    // Assume that this payload is valid, since the anchor should be a trusted block and
                    // state.
                    ExecutionStatus::Valid(execution_payload.block_hash())
                }
            },
        );

        // If the current slot is not provided, use the value that was last provided to the store.
        let current_slot = current_slot.unwrap_or_else(|| fc_store.get_current_slot());

        let proto_array = ProtoArrayForkChoice::new::<E>(
            finalized_block_slot,
            finalized_block_state_root,
            *fc_store.justified_checkpoint(),
            *fc_store.finalized_checkpoint(),
            current_epoch_shuffling_id,
            next_epoch_shuffling_id,
            execution_status,
            count_unrealized_full_config,
        )?;

        let mut fork_choice = Self {
            fc_store,
            proto_array,
            queued_attestations: vec![],
            // This will be updated during the next call to `Self::get_head`.
            forkchoice_update_parameters: ForkchoiceUpdateParameters {
                head_hash: None,
                justified_hash: None,
                finalized_hash: None,
                head_root: Hash256::zero(),
            },
            // This will be updated during the next call to `Self::get_head`.
            head_block_root: Hash256::zero(),
            _phantom: PhantomData,
        };

        // Ensure that `fork_choice.head_block_root` is updated.
        fork_choice.get_head(current_slot, spec)?;

        Ok(fork_choice)
    }

    /// Returns cached information that can be used to issue a `forkchoiceUpdated` message to an
    /// execution engine.
    ///
    /// These values are updated each time `Self::get_head` is called.
    pub fn get_forkchoice_update_parameters(&self) -> ForkchoiceUpdateParameters {
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
        system_time_current_slot: Slot,
        spec: &ChainSpec,
    ) -> Result<Hash256, Error<T::Error>> {
        // Provide the slot (as per the system clock) to the `fc_store` and then return its view of
        // the current slot. The `fc_store` will ensure that the `current_slot` is never
        // decreasing, a property which we must maintain.
        let current_slot = self.update_time(system_time_current_slot, spec)?;

        let store = &mut self.fc_store;

        let head_root = self.proto_array.find_head::<E>(
            *store.justified_checkpoint(),
            *store.finalized_checkpoint(),
            store.justified_balances(),
            store.proposer_boost_root(),
            store.equivocating_indices(),
            current_slot,
            spec,
        )?;

        self.head_block_root = head_root;

        // Cache some values for the next forkchoiceUpdate call to the execution layer.
        let head_hash = self
            .get_block(&head_root)
            .and_then(|b| b.execution_status.block_hash());
        let justified_root = self.justified_checkpoint().root;
        let finalized_root = self.finalized_checkpoint().root;
        let justified_hash = self
            .get_block(&justified_root)
            .and_then(|b| b.execution_status.block_hash());
        let finalized_hash = self
            .get_block(&finalized_root)
            .and_then(|b| b.execution_status.block_hash());
        self.forkchoice_update_parameters = ForkchoiceUpdateParameters {
            head_root,
            head_hash,
            justified_hash,
            finalized_hash,
        };

        Ok(head_root)
    }

    /// Get the block to build on as proposer, taking into account proposer re-orgs.
    ///
    /// You *must* call `get_head` for the proposal slot prior to calling this function and pass
    /// in the result of `get_head` as `canonical_head`.
    pub fn get_proposer_head(
        &self,
        current_slot: Slot,
        canonical_head: Hash256,
        re_org_threshold: ReOrgThreshold,
        max_epochs_since_finalization: Epoch,
    ) -> Result<ProposerHeadInfo, ProposerHeadError<Error<proto_array::Error>>> {
        // Ensure that fork choice has already been updated for the current slot. This prevents
        // us from having to take a write lock or do any dequeueing of attestations in this
        // function.
        let fc_store_slot = self.fc_store.get_current_slot();
        if current_slot != fc_store_slot {
            return Err(ProposerHeadError::Error(
                Error::WrongSlotForGetProposerHead {
                    current_slot,
                    fc_store_slot,
                },
            ));
        }

        // Similarly, the proposer boost for the previous head should already have expired.
        let proposer_boost_root = self.fc_store.proposer_boost_root();
        if !proposer_boost_root.is_zero() {
            return Err(ProposerHeadError::Error(
                Error::ProposerBoostNotExpiredForGetProposerHead {
                    proposer_boost_root,
                },
            ));
        }

        self.proto_array
            .get_proposer_head::<E>(
                current_slot,
                canonical_head,
                self.fc_store.justified_balances(),
                re_org_threshold,
                max_epochs_since_finalization,
            )
            .map_err(ProposerHeadError::convert_inner_error)
    }

    pub fn get_preliminary_proposer_head(
        &self,
        canonical_head: Hash256,
        re_org_threshold: ReOrgThreshold,
        max_epochs_since_finalization: Epoch,
    ) -> Result<ProposerHeadInfo, ProposerHeadError<Error<proto_array::Error>>> {
        let current_slot = self.fc_store.get_current_slot();
        self.proto_array
            .get_proposer_head_info::<E>(
                current_slot,
                canonical_head,
                self.fc_store.justified_balances(),
                re_org_threshold,
                max_epochs_since_finalization,
            )
            .map_err(ProposerHeadError::convert_inner_error)
    }

    /// Return information about:
    ///
    /// - The LMD head of the chain.
    /// - The FFG checkpoints.
    ///
    /// The information is "cached" since the last call to `Self::get_head`.
    ///
    /// ## Notes
    ///
    /// The finalized/justified checkpoints are determined from the fork choice store. Therefore,
    /// it's possible that the state corresponding to `get_state(get_block(head_block_root))` will
    /// have *differing* finalized and justified information.
    pub fn cached_fork_choice_view(&self) -> ForkChoiceView {
        ForkChoiceView {
            head_block_root: self.head_block_root,
            justified_checkpoint: self.justified_checkpoint(),
            finalized_checkpoint: self.finalized_checkpoint(),
        }
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
        slots: UpdateJustifiedCheckpointSlots,
        spec: &ChainSpec,
    ) -> Result<bool, Error<T::Error>> {
        self.update_time(slots.current_slot(), spec)?;

        if compute_slots_since_epoch_start::<E>(self.fc_store.get_current_slot())
            < spec.safe_slots_to_update_justified
        {
            return Ok(true);
        }

        let justified_slot =
            compute_start_slot_at_epoch::<E>(self.fc_store.justified_checkpoint().epoch);

        // This sanity check is not in the spec, but the invariant is implied.
        if let Some(state_slot) = slots.state_slot() {
            if justified_slot >= state_slot {
                return Err(Error::AttemptToRevertJustification {
                    store: justified_slot,
                    state: state_slot,
                });
            }
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
            .process_execution_payload_invalidation::<E>(op)
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
    pub fn on_block<Payload: AbstractExecPayload<E>>(
        &mut self,
        system_time_current_slot: Slot,
        block: BeaconBlockRef<E, Payload>,
        block_root: Hash256,
        block_delay: Duration,
        state: &BeaconState<E>,
        payload_verification_status: PayloadVerificationStatus,
        spec: &ChainSpec,
        count_unrealized: CountUnrealized,
    ) -> Result<(), Error<T::Error>> {
        // Provide the slot (as per the system clock) to the `fc_store` and then return its view of
        // the current slot. The `fc_store` will ensure that the `current_slot` is never
        // decreasing, a property which we must maintain.
        let current_slot = self.update_time(system_time_current_slot, spec)?;

        // Parent block must be known.
        let parent_block = self
            .proto_array
            .get_block(&block.parent_root())
            .ok_or_else(|| Error::InvalidBlock(InvalidBlock::UnknownParent(block.parent_root())))?;

        // Blocks cannot be in the future. If they are, their consideration must be delayed until
        // they are in the past.
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

        let update_justified_checkpoint_slots = UpdateJustifiedCheckpointSlots::OnBlock {
            state_slot: state.slot(),
            current_slot,
        };

        // Update store with checkpoints if necessary
        self.update_checkpoints(
            state.current_justified_checkpoint(),
            state.finalized_checkpoint(),
            update_justified_checkpoint_slots,
            spec,
        )?;

        // Update unrealized justified/finalized checkpoints.
        let (unrealized_justified_checkpoint, unrealized_finalized_checkpoint) = if count_unrealized
            .is_true()
        {
            let block_epoch = block.slot().epoch(E::slots_per_epoch());

            // If the parent checkpoints are already at the same epoch as the block being imported,
            // it's impossible for the unrealized checkpoints to differ from the parent's. This
            // holds true because:
            //
            // 1. A child block cannot have lower FFG checkpoints than its parent.
            // 2. A block in epoch `N` cannot contain attestations which would justify an epoch higher than `N`.
            // 3. A block in epoch `N` cannot contain attestations which would finalize an epoch higher than `N - 1`.
            //
            // This is an optimization. It should reduce the amount of times we run
            // `process_justification_and_finalization` by approximately 1/3rd when the chain is
            // performing optimally.
            let parent_checkpoints = parent_block
                .unrealized_justified_checkpoint
                .zip(parent_block.unrealized_finalized_checkpoint)
                .filter(|(parent_justified, parent_finalized)| {
                    parent_justified.epoch == block_epoch
                        && parent_finalized.epoch + 1 >= block_epoch
                });

            let (unrealized_justified_checkpoint, unrealized_finalized_checkpoint) =
                if let Some((parent_justified, parent_finalized)) = parent_checkpoints {
                    (parent_justified, parent_finalized)
                } else {
                    let justification_and_finalization_state = match block {
                        // TODO(eip4844): Ensure that the final specification
                        // does not substantially modify per epoch processing.
                        BeaconBlockRef::Eip4844(_)
                        | BeaconBlockRef::Capella(_)
                        | BeaconBlockRef::Merge(_)
                        | BeaconBlockRef::Altair(_) => {
                            let participation_cache =
                                per_epoch_processing::altair::ParticipationCache::new(state, spec)
                                    .map_err(Error::ParticipationCacheBuild)?;
                            per_epoch_processing::altair::process_justification_and_finalization(
                                state,
                                &participation_cache,
                            )?
                        }
                        BeaconBlockRef::Base(_) => {
                            let mut validator_statuses =
                                per_epoch_processing::base::ValidatorStatuses::new(state, spec)
                                    .map_err(Error::ValidatorStatuses)?;
                            validator_statuses
                                .process_attestations(state)
                                .map_err(Error::ValidatorStatuses)?;
                            per_epoch_processing::base::process_justification_and_finalization(
                                state,
                                &validator_statuses.total_balances,
                                spec,
                            )?
                        }
                    };

                    (
                        justification_and_finalization_state.current_justified_checkpoint(),
                        justification_and_finalization_state.finalized_checkpoint(),
                    )
                };

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
            if block.slot().epoch(E::slots_per_epoch()) < current_slot.epoch(E::slots_per_epoch()) {
                self.update_checkpoints(
                    unrealized_justified_checkpoint,
                    unrealized_finalized_checkpoint,
                    update_justified_checkpoint_slots,
                    spec,
                )?;
            }

            (
                Some(unrealized_justified_checkpoint),
                Some(unrealized_finalized_checkpoint),
            )
        } else {
            (None, None)
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
        self.proto_array.process_block::<E>(
            ProtoBlock {
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
            },
            current_slot,
        )?;

        Ok(())
    }

    /// Update checkpoints in store if necessary
    fn update_checkpoints(
        &mut self,
        justified_checkpoint: Checkpoint,
        finalized_checkpoint: Checkpoint,
        slots: UpdateJustifiedCheckpointSlots,
        spec: &ChainSpec,
    ) -> Result<(), Error<T::Error>> {
        // Update justified checkpoint.
        if justified_checkpoint.epoch > self.fc_store.justified_checkpoint().epoch {
            if justified_checkpoint.epoch > self.fc_store.best_justified_checkpoint().epoch {
                self.fc_store
                    .set_best_justified_checkpoint(justified_checkpoint);
            }
            if self.should_update_justified_checkpoint(justified_checkpoint, slots, spec)? {
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
        system_time_current_slot: Slot,
        attestation: &IndexedAttestation<E>,
        is_from_block: AttestationFromBlock,
        spec: &ChainSpec,
    ) -> Result<(), Error<T::Error>> {
        self.update_time(system_time_current_slot, spec)?;

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

    /// Apply an attester slashing to fork choice.
    ///
    /// We assume that the attester slashing provided to this function has already been verified.
    pub fn on_attester_slashing(&mut self, slashing: &AttesterSlashing<E>) {
        let attesting_indices_set = |att: &IndexedAttestation<E>| {
            att.attesting_indices
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
        };
        let att1_indices = attesting_indices_set(&slashing.attestation_1);
        let att2_indices = attesting_indices_set(&slashing.attestation_2);
        self.fc_store
            .extend_equivocating_indices(att1_indices.intersection(&att2_indices).copied());
    }

    /// Call `on_tick` for all slots between `fc_store.get_current_slot()` and the provided
    /// `current_slot`. Returns the value of `self.fc_store.get_current_slot`.
    pub fn update_time(
        &mut self,
        current_slot: Slot,
        spec: &ChainSpec,
    ) -> Result<Slot, Error<T::Error>> {
        while self.fc_store.get_current_slot() < current_slot {
            let previous_slot = self.fc_store.get_current_slot();
            // Note: we are relying upon `on_tick` to update `fc_store.time` to ensure we don't
            // get stuck in a loop.
            self.on_tick(previous_slot + 1, spec)?
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
            let store = &self.fc_store;
            if self.is_finalized_checkpoint_or_descendant(store.best_justified_checkpoint().root) {
                let store = &mut self.fc_store;
                store
                    .set_justified_checkpoint(*store.best_justified_checkpoint())
                    .map_err(Error::ForkChoiceStoreError)?;
            }
        }

        // Update store.justified_checkpoint if a better unrealized justified checkpoint is known
        let unrealized_justified_checkpoint = *self.fc_store.unrealized_justified_checkpoint();
        let unrealized_finalized_checkpoint = *self.fc_store.unrealized_finalized_checkpoint();
        self.update_checkpoints(
            unrealized_justified_checkpoint,
            unrealized_finalized_checkpoint,
            UpdateJustifiedCheckpointSlots::OnTick { current_slot },
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
        self.proto_array.contains_block(block_root)
            && self.is_finalized_checkpoint_or_descendant(*block_root)
    }

    /// Returns a `ProtoBlock` if the block is known **and** a descendant of the finalized root.
    pub fn get_block(&self, block_root: &Hash256) -> Option<ProtoBlock> {
        if self.is_finalized_checkpoint_or_descendant(*block_root) {
            self.proto_array.get_block(block_root)
        } else {
            None
        }
    }

    /// Returns an `ExecutionStatus` if the block is known **and** a descendant of the finalized root.
    pub fn get_block_execution_status(&self, block_root: &Hash256) -> Option<ExecutionStatus> {
        if self.is_finalized_checkpoint_or_descendant(*block_root) {
            self.proto_array.get_block_execution_status(block_root)
        } else {
            None
        }
    }

    /// Returns the weight for the given block root.
    pub fn get_block_weight(&self, block_root: &Hash256) -> Option<u64> {
        self.proto_array.get_weight(block_root)
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

    /// Return `true` if `block_root` is equal to the finalized checkpoint, or a known descendant of it.
    pub fn is_finalized_checkpoint_or_descendant(&self, block_root: Hash256) -> bool {
        self.proto_array
            .is_finalized_checkpoint_or_descendant::<E>(block_root)
    }

    /// Returns `Ok(true)` if `block_root` has been imported optimistically or deemed invalid.
    ///
    /// Returns `Ok(false)` if `block_root`'s execution payload has been elected as fully VALID, if
    /// it is a pre-Bellatrix block or if it is before the PoW terminal block.
    ///
    /// In the case where the block could not be found in fork-choice, it returns the
    /// `execution_status` of the current finalized block.
    ///
    /// This function assumes the `block_root` exists.
    pub fn is_optimistic_or_invalid_block(
        &self,
        block_root: &Hash256,
    ) -> Result<bool, Error<T::Error>> {
        if let Some(status) = self.get_block_execution_status(block_root) {
            Ok(status.is_optimistic_or_invalid())
        } else {
            Ok(self
                .get_finalized_block()?
                .execution_status
                .is_optimistic_or_invalid())
        }
    }

    /// The same as `is_optimistic_block` but does not fallback to `self.get_finalized_block`
    /// when the block cannot be found.
    ///
    /// Intended to be used when checking if the head has been imported optimistically or is
    /// invalid.
    pub fn is_optimistic_or_invalid_block_no_fallback(
        &self,
        block_root: &Hash256,
    ) -> Result<bool, Error<T::Error>> {
        if let Some(status) = self.get_block_execution_status(block_root) {
            Ok(status.is_optimistic_or_invalid())
        } else {
            Err(Error::MissingProtoArrayBlock(*block_root))
        }
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

        // If the parent block has execution enabled, always import the block.
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

    pub fn unrealized_justified_checkpoint(&self) -> Checkpoint {
        *self.fc_store.unrealized_justified_checkpoint()
    }

    pub fn unrealized_finalized_checkpoint(&self) -> Checkpoint {
        *self.fc_store.unrealized_finalized_checkpoint()
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

    /// Returns a mutable reference to `proto_array`.
    /// Should only be used in testing.
    pub fn proto_array_mut(&mut self) -> &mut ProtoArrayForkChoice {
        &mut self.proto_array
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
    pub fn proto_array_from_persisted(
        persisted: &PersistedForkChoice,
        reset_payload_statuses: ResetPayloadStatuses,
        count_unrealized_full: CountUnrealizedFull,
        spec: &ChainSpec,
        log: &Logger,
    ) -> Result<ProtoArrayForkChoice, Error<T::Error>> {
        let mut proto_array =
            ProtoArrayForkChoice::from_bytes(&persisted.proto_array_bytes, count_unrealized_full)
                .map_err(Error::InvalidProtoArrayBytes)?;
        let contains_invalid_payloads = proto_array.contains_invalid_payloads();

        debug!(
            log,
            "Restoring fork choice from persisted";
            "reset_payload_statuses" => ?reset_payload_statuses,
            "contains_invalid_payloads" => contains_invalid_payloads,
        );

        // Exit early if there are no "invalid" payloads, if requested.
        if matches!(
            reset_payload_statuses,
            ResetPayloadStatuses::OnlyWithInvalidPayload
        ) && !contains_invalid_payloads
        {
            return Ok(proto_array);
        }

        // Reset all blocks back to being "optimistic". This helps recover from an EL consensus
        // fault where an invalid payload becomes valid.
        if let Err(e) = proto_array.set_all_blocks_to_optimistic::<E>(spec) {
            // If there is an error resetting the optimistic status then log loudly and revert
            // back to a proto-array which does not have the reset applied. This indicates a
            // significant error in Lighthouse and warrants detailed investigation.
            crit!(
                log,
                "Failed to reset payload statuses";
                "error" => e,
                "info" => "please report this error",
            );
            ProtoArrayForkChoice::from_bytes(&persisted.proto_array_bytes, count_unrealized_full)
                .map_err(Error::InvalidProtoArrayBytes)
        } else {
            debug!(
                log,
                "Successfully reset all payload statuses";
            );
            Ok(proto_array)
        }
    }

    /// Instantiate `Self` from some `PersistedForkChoice` generated by a earlier call to
    /// `Self::to_persisted`.
    pub fn from_persisted(
        persisted: PersistedForkChoice,
        reset_payload_statuses: ResetPayloadStatuses,
        fc_store: T,
        count_unrealized_full: CountUnrealizedFull,
        spec: &ChainSpec,
        log: &Logger,
    ) -> Result<Self, Error<T::Error>> {
        let proto_array = Self::proto_array_from_persisted(
            &persisted,
            reset_payload_statuses,
            count_unrealized_full,
            spec,
            log,
        )?;

        let current_slot = fc_store.get_current_slot();

        let mut fork_choice = Self {
            fc_store,
            proto_array,
            queued_attestations: persisted.queued_attestations,
            // Will be updated in the following call to `Self::get_head`.
            forkchoice_update_parameters: ForkchoiceUpdateParameters {
                head_hash: None,
                justified_hash: None,
                finalized_hash: None,
                head_root: Hash256::zero(),
            },
            // Will be updated in the following call to `Self::get_head`.
            head_block_root: Hash256::zero(),
            _phantom: PhantomData,
        };

        // If a call to `get_head` fails, the only known cause is because the only head with viable
        // FFG properties is has an invalid payload. In this scenario, set all the payloads back to
        // an optimistic status so that we can have a head to start from.
        if let Err(e) = fork_choice.get_head(current_slot, spec) {
            warn!(
                log,
                "Could not find head on persisted FC";
                "info" => "resetting all payload statuses and retrying",
                "error" => ?e
            );
            // Although we may have already made this call whilst loading `proto_array`, try it
            // again since we may have mutated the `proto_array` during `get_head` and therefore may
            // get a different result.
            fork_choice
                .proto_array
                .set_all_blocks_to_optimistic::<E>(spec)?;
            // If the second attempt at finding a head fails, return an error since we do not
            // expect this scenario.
            fork_choice.get_head(current_slot, spec)?;
        }

        Ok(fork_choice)
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
