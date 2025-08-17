use integer_sqrt::IntegerSquareRoot;
use safe_arith::SafeArith;
use smallvec::SmallVec;
use types::{AttestationData, BeaconState, ChainSpec, EthSpec};
use types::{
    BeaconStateError as Error,
    consts::altair::{
        NUM_FLAG_INDICES, TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX,
        TIMELY_TARGET_FLAG_INDEX,
    },
};

/// Get the participation flags for a valid attestation.
///
/// You should have called `verify_attestation_for_block_inclusion` or similar before
/// calling this function, in order to ensure that the attestation's source is correct.
///
/// This function will return an error if the source of the attestation doesn't match the
/// state's relevant justified checkpoint.
pub fn get_attestation_participation_flag_indices<E: EthSpec>(
    state: &BeaconState<E>,
    data: &AttestationData,
    inclusion_delay: u64,
    spec: &ChainSpec,
) -> Result<SmallVec<[usize; NUM_FLAG_INDICES]>, Error> {
    // Matching source
    let justified_checkpoint = if data.target.epoch == state.current_epoch() {
        state.current_justified_checkpoint()
    } else {
        state.previous_justified_checkpoint()
    };
    let is_matching_source = data.source == justified_checkpoint;

    // Matching target
    let target_root = *state.get_block_root_at_epoch(data.target.epoch)?;
    let target_root_matches = data.target.root == target_root;
    let is_matching_target = is_matching_source && target_root_matches;

    // Matching head
    let head_root = *state.get_block_root(data.slot)?;
    let head_root_matches = data.beacon_block_root == head_root;

    let is_matching_head = if state.fork_name_unchecked().gloas_enabled() {
        let payload_matches = if state.is_attestation_same_slot(data)? {
            // For same-slot attestations, data.index must be 0
            if data.index != 0 {
                return Err(Error::BadOverloadedDataIndex(data.index));
            }
            true
        } else {
            // For non same-slot attestations, check execution payload availability
            // TODO(EIP7732) Discuss if we want to return new error BeaconStateError::InvalidExecutionPayloadAvailabilityIndex here for bit out of bounds or use something like BeaconStateError::InvalidBitfield
            let slot_index = data
                .slot
                .as_usize()
                .safe_rem(E::slots_per_historical_root())?;
            state
                .execution_payload_availability()?
                .get(slot_index)
                .map_err(|_| Error::InvalidExecutionPayloadAvailabilityIndex(slot_index))?
        };
        is_matching_target && head_root_matches && payload_matches
    } else {
        is_matching_target && head_root_matches
    };

    if !is_matching_source {
        return Err(Error::IncorrectAttestationSource);
    }

    // Participation flag indices
    let mut participation_flag_indices = SmallVec::new();
    if is_matching_source && inclusion_delay <= E::slots_per_epoch().integer_sqrt() {
        participation_flag_indices.push(TIMELY_SOURCE_FLAG_INDEX);
    }
    if state.fork_name_unchecked().deneb_enabled() {
        if is_matching_target {
            // [Modified in Deneb:EIP7045]
            participation_flag_indices.push(TIMELY_TARGET_FLAG_INDEX);
        }
    } else if is_matching_target && inclusion_delay <= E::slots_per_epoch() {
        participation_flag_indices.push(TIMELY_TARGET_FLAG_INDEX);
    }

    if is_matching_head && inclusion_delay == spec.min_attestation_inclusion_delay {
        participation_flag_indices.push(TIMELY_HEAD_FLAG_INDEX);
    }
    Ok(participation_flag_indices)
}
