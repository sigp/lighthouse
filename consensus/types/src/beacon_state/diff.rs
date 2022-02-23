use crate::{
    BeaconBlockHeader, BeaconState, BeaconStateError as Error, BitVector, Checkpoint, Eth1Data,
    EthSpec, ExecutionPayloadHeader, Fork, Hash256, ParticipationFlags, PendingAttestation, Slot,
    SyncCommittee, Validator,
};
use milhouse::{CloneDiff, Diff, ListDiff, ResetListDiff, VectorDiff};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;

/// `Option`-like type implementing SSZ encode/decode.
///
/// Uses a succinct 1 byte union selector.
#[derive(Debug, PartialEq, Encode, Decode)]
#[ssz(enum_behaviour = "union")]
pub enum Maybe<T: Encode + Decode> {
    Nothing(u8),
    Just(T),
}

impl<T: Encode + Decode> Maybe<T> {
    fn nothing() -> Self {
        Self::Nothing(0)
    }
}

#[derive(Debug, PartialEq, Encode, Decode)]
pub struct BeaconStateDiff<T: EthSpec> {
    // Versioning
    genesis_time: CloneDiff<u64>,
    genesis_validators_root: CloneDiff<Hash256>,
    slot: CloneDiff<Slot>,
    fork: CloneDiff<Fork>,

    // History
    latest_block_header: CloneDiff<BeaconBlockHeader>,
    block_roots: VectorDiff<Hash256, T::SlotsPerHistoricalRoot>,
    state_roots: VectorDiff<Hash256, T::SlotsPerHistoricalRoot>,
    historical_roots: ListDiff<Hash256, T::HistoricalRootsLimit>,

    // Ethereum 1.0 chain data
    eth1_data: CloneDiff<Eth1Data>,
    eth1_data_votes: ResetListDiff<Eth1Data, T::SlotsPerEth1VotingPeriod>,
    eth1_deposit_index: CloneDiff<u64>,

    // Registry
    validators: ListDiff<Validator, T::ValidatorRegistryLimit>,
    balances: ListDiff<u64, T::ValidatorRegistryLimit>,

    // Randomness
    randao_mixes: VectorDiff<Hash256, T::EpochsPerHistoricalVector>,

    // Slashings
    slashings: VectorDiff<u64, T::EpochsPerSlashingsVector>,

    // Attestations (genesis fork only)
    // FIXME(sproul): do some clever diffing of prev against former current
    previous_epoch_attestations:
        Maybe<ResetListDiff<PendingAttestation<T>, T::MaxPendingAttestations>>,
    current_epoch_attestations:
        Maybe<ResetListDiff<PendingAttestation<T>, T::MaxPendingAttestations>>,

    // Participation (Altair and later)
    previous_epoch_participation: Maybe<ListDiff<ParticipationFlags, T::ValidatorRegistryLimit>>,
    current_epoch_participation: Maybe<ListDiff<ParticipationFlags, T::ValidatorRegistryLimit>>,

    // Finality
    justification_bits: CloneDiff<BitVector<T::JustificationBitsLength>>,
    previous_justified_checkpoint: CloneDiff<Checkpoint>,
    current_justified_checkpoint: CloneDiff<Checkpoint>,
    finalized_checkpoint: CloneDiff<Checkpoint>,

    // Inactivity
    inactivity_scores: Maybe<ListDiff<u64, T::ValidatorRegistryLimit>>,

    // Light-client sync committees
    current_sync_committee: Maybe<CloneDiff<Arc<SyncCommittee<T>>>>,
    next_sync_committee: Maybe<CloneDiff<Arc<SyncCommittee<T>>>>,

    // Execution
    latest_execution_payload_header: Maybe<CloneDiff<ExecutionPayloadHeader<T>>>,
}

fn optional_field_diff<
    T: EthSpec,
    X,
    D: Diff<Target = X, Error = milhouse::Error> + Encode + Decode,
>(
    old: &BeaconState<T>,
    new: &BeaconState<T>,
    field: impl Fn(&BeaconState<T>) -> Result<&X, Error>,
) -> Result<Maybe<D>, Error> {
    if let Ok(new_value) = field(new) {
        let old_value = field(old)?;
        Ok(Maybe::Just(D::compute_diff(old_value, new_value)?))
    } else {
        Ok(Maybe::nothing())
    }
}

fn apply_optional_diff<X, D: Diff<Target = X, Error = milhouse::Error> + Encode + Decode>(
    diff: Maybe<D>,
    field: Result<&mut X, Error>,
) -> Result<(), Error> {
    if let Maybe::Just(diff) = diff {
        diff.apply_diff(field?)?;
    }
    Ok(())
}

impl<T: EthSpec> Diff for BeaconStateDiff<T> {
    type Target = BeaconState<T>;
    type Error = Error;

    // FIXME(sproul): proc macro
    fn compute_diff(orig: &Self::Target, other: &Self::Target) -> Result<Self, Error> {
        // FIXME(sproul): consider cross-variant diffs
        Ok(BeaconStateDiff {
            genesis_time: <_>::compute_diff(&orig.genesis_time(), &other.genesis_time())?,
            genesis_validators_root: <_>::compute_diff(
                &orig.genesis_validators_root(),
                &other.genesis_validators_root(),
            )?,
            slot: <_>::compute_diff(&orig.slot(), &other.slot())?,
            fork: <_>::compute_diff(&orig.fork(), &other.fork())?,
            latest_block_header: <_>::compute_diff(
                orig.latest_block_header(),
                other.latest_block_header(),
            )?,
            block_roots: <_>::compute_diff(orig.block_roots(), other.block_roots())?,
            state_roots: <_>::compute_diff(orig.state_roots(), other.state_roots())?,
            historical_roots: <_>::compute_diff(orig.historical_roots(), other.historical_roots())?,
            eth1_data: <_>::compute_diff(orig.eth1_data(), other.eth1_data())?,
            eth1_data_votes: <_>::compute_diff(orig.eth1_data_votes(), other.eth1_data_votes())?,
            eth1_deposit_index: <_>::compute_diff(
                &orig.eth1_deposit_index(),
                &other.eth1_deposit_index(),
            )?,
            validators: <_>::compute_diff(orig.validators(), other.validators())?,
            balances: <_>::compute_diff(orig.balances(), other.balances())?,
            randao_mixes: <_>::compute_diff(orig.randao_mixes(), other.randao_mixes())?,
            slashings: <_>::compute_diff(orig.slashings(), other.slashings())?,
            previous_epoch_attestations: optional_field_diff(
                orig,
                other,
                BeaconState::previous_epoch_attestations,
            )?,
            current_epoch_attestations: optional_field_diff(
                orig,
                other,
                BeaconState::current_epoch_attestations,
            )?,
            previous_epoch_participation: optional_field_diff(
                orig,
                other,
                BeaconState::previous_epoch_participation,
            )?,
            current_epoch_participation: optional_field_diff(
                orig,
                other,
                BeaconState::current_epoch_participation,
            )?,
            justification_bits: <_>::compute_diff(
                orig.justification_bits(),
                other.justification_bits(),
            )?,
            previous_justified_checkpoint: <_>::compute_diff(
                &orig.previous_justified_checkpoint(),
                &other.previous_justified_checkpoint(),
            )?,
            current_justified_checkpoint: <_>::compute_diff(
                &orig.current_justified_checkpoint(),
                &other.current_justified_checkpoint(),
            )?,
            finalized_checkpoint: <_>::compute_diff(
                &orig.finalized_checkpoint(),
                &other.finalized_checkpoint(),
            )?,
            inactivity_scores: optional_field_diff(orig, other, BeaconState::inactivity_scores)?,
            current_sync_committee: optional_field_diff(
                orig,
                other,
                BeaconState::current_sync_committee,
            )?,
            next_sync_committee: optional_field_diff(
                orig,
                other,
                BeaconState::next_sync_committee,
            )?,
            latest_execution_payload_header: optional_field_diff(
                orig,
                other,
                BeaconState::latest_execution_payload_header,
            )?,
        })
    }

    fn apply_diff(self, target: &mut BeaconState<T>) -> Result<(), Error> {
        self.genesis_time.apply_diff(target.genesis_time_mut())?;
        self.genesis_validators_root
            .apply_diff(target.genesis_validators_root_mut())?;
        self.slot.apply_diff(target.slot_mut())?;
        self.fork.apply_diff(target.fork_mut())?;
        self.latest_block_header
            .apply_diff(target.latest_block_header_mut())?;
        self.block_roots.apply_diff(target.block_roots_mut())?;
        self.state_roots.apply_diff(target.state_roots_mut())?;
        self.historical_roots
            .apply_diff(target.historical_roots_mut())?;
        self.eth1_data.apply_diff(target.eth1_data_mut())?;
        self.eth1_data_votes
            .apply_diff(target.eth1_data_votes_mut())?;
        self.eth1_deposit_index
            .apply_diff(target.eth1_deposit_index_mut())?;
        self.validators.apply_diff(target.validators_mut())?;
        self.balances.apply_diff(target.balances_mut())?;
        self.randao_mixes.apply_diff(target.randao_mixes_mut())?;
        self.slashings.apply_diff(target.slashings_mut())?;
        apply_optional_diff(
            self.previous_epoch_attestations,
            target.previous_epoch_attestations_mut(),
        )?;
        apply_optional_diff(
            self.current_epoch_attestations,
            target.current_epoch_attestations_mut(),
        )?;
        apply_optional_diff(
            self.previous_epoch_participation,
            target.previous_epoch_participation_mut(),
        )?;
        apply_optional_diff(
            self.current_epoch_participation,
            target.current_epoch_participation_mut(),
        )?;
        self.justification_bits
            .apply_diff(target.justification_bits_mut())?;
        self.previous_justified_checkpoint
            .apply_diff(target.previous_justified_checkpoint_mut())?;
        self.current_justified_checkpoint
            .apply_diff(target.current_justified_checkpoint_mut())?;
        self.finalized_checkpoint
            .apply_diff(target.finalized_checkpoint_mut())?;
        apply_optional_diff(self.inactivity_scores, target.inactivity_scores_mut())?;
        apply_optional_diff(
            self.current_sync_committee,
            target.current_sync_committee_mut(),
        )?;
        apply_optional_diff(self.next_sync_committee, target.next_sync_committee_mut())?;
        apply_optional_diff(
            self.latest_execution_payload_header,
            target.latest_execution_payload_header_mut(),
        )?;
        Ok(())
    }
}
