use crate::per_block_processing::errors::BlockProcessingError as Error;
use integer_sqrt::IntegerSquareRoot;
use safe_arith::SafeArith;
use smallvec::SmallVec;
use types::consts::altair::{
    TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX,
};
use types::{AttestationData, BeaconState, ChainSpec, EthSpec};

/// Get the participation flags for a **valid** attestation.
///
/// You must have called `verify_attestation_for_block_inclusion` or similar before
/// calling this function, in order to ensure that the attestation's source is correct.
///
/// This function is extracted from `process_attestation`
pub fn get_attestation_participation<T: EthSpec>(
    data: &AttestationData,
    state: &BeaconState<T>,
    spec: &ChainSpec,
) -> Result<SmallVec<[u64; 3]>, Error> {
    // Matching roots.
    // Source match is checked by `verify_attestation_for_block_inclusion`.
    let is_matching_head = data.beacon_block_root == *state.get_block_root(data.slot)?;
    let is_matching_source = true;
    let is_matching_target =
        data.target.root == *state.get_block_root_at_epoch(data.target.epoch)?;

    // Participation flag indices
    let mut participation_flag_indices = SmallVec::new();
    if is_matching_head
        && is_matching_target
        && state.slot() <= data.slot.safe_add(spec.min_attestation_inclusion_delay)?
    {
        participation_flag_indices.push(TIMELY_HEAD_FLAG_INDEX);
    }
    if is_matching_source
        && state.slot() <= data.slot.safe_add(T::slots_per_epoch().integer_sqrt())?
    {
        participation_flag_indices.push(TIMELY_SOURCE_FLAG_INDEX);
    }
    if is_matching_target && state.slot() <= data.slot.safe_add(T::slots_per_epoch())? {
        participation_flag_indices.push(TIMELY_TARGET_FLAG_INDEX);
    }

    Ok(participation_flag_indices)
}
