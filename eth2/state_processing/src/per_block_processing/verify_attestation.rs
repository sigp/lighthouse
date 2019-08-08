use super::errors::{AttestationInvalid as Invalid, AttestationValidationError as Error};
use super::VerifySignatures;
use crate::common::get_indexed_attestation;
use crate::per_block_processing::{
    is_valid_indexed_attestation, is_valid_indexed_attestation_without_signature,
};
use tree_hash::TreeHash;
use types::*;

/// Indicates if an `Attestation` is valid to be included in a block in the current epoch of the
/// given state, optionally validating the aggregate signature.
///
/// Spec v0.8.0
pub fn verify_attestation_for_block<T: EthSpec>(
    state: &BeaconState<T>,
    attestation: &Attestation<T>,
    spec: &ChainSpec,
    verify_signatures: VerifySignatures,
) -> Result<(), Error> {
    let data = &attestation.data;

    // Check attestation slot.
    let attestation_slot = state.get_attestation_data_slot(&data)?;

    verify!(
        attestation_slot + spec.min_attestation_inclusion_delay <= state.slot,
        Invalid::IncludedTooEarly {
            state: state.slot,
            delay: spec.min_attestation_inclusion_delay,
            attestation: attestation_slot
        }
    );
    verify!(
        state.slot <= attestation_slot + T::slots_per_epoch(),
        Invalid::IncludedTooLate {
            state: state.slot,
            attestation: attestation_slot
        }
    );

    verify_attestation_for_state(state, attestation, spec, verify_signatures)
}

/// Returns `Ok(())` if `attestation` is a valid attestation to the chain that preceeds the given
/// `state`.
///
/// Returns a descriptive `Err` if the attestation is malformed or does not accurately reflect the
/// prior blocks in `state`.
///
/// Spec v0.8.0
pub fn verify_attestation_for_state<T: EthSpec>(
    state: &BeaconState<T>,
    attestation: &Attestation<T>,
    spec: &ChainSpec,
    verify_signature: VerifySignatures,
) -> Result<(), Error> {
    let data = &attestation.data;
    verify!(
        data.crosslink.shard < T::ShardCount::to_u64(),
        Invalid::BadShard
    );

    // Verify the Casper FFG vote and crosslink data.
    let parent_crosslink = verify_casper_ffg_vote(attestation, state)?;

    verify!(
        data.crosslink.parent_root == Hash256::from_slice(&parent_crosslink.tree_hash_root()),
        Invalid::BadParentCrosslinkHash
    );
    verify!(
        data.crosslink.start_epoch == parent_crosslink.end_epoch,
        Invalid::BadParentCrosslinkStartEpoch
    );
    verify!(
        data.crosslink.end_epoch
            == std::cmp::min(
                data.target.epoch,
                parent_crosslink.end_epoch + spec.max_epochs_per_crosslink
            ),
        Invalid::BadParentCrosslinkEndEpoch
    );

    // Crosslink data root is zero (to be removed in phase 1).
    verify!(
        attestation.data.crosslink.data_root == Hash256::zero(),
        Invalid::ShardBlockRootNotZero
    );

    // Check signature and bitfields
    let indexed_attestation = get_indexed_attestation(state, attestation)?;
    if verify_signature == VerifySignatures::True {
        is_valid_indexed_attestation(state, &indexed_attestation, spec)?;
    } else {
        is_valid_indexed_attestation_without_signature(state, &indexed_attestation, spec)?;
    }

    Ok(())
}

/// Check target epoch and source checkpoint.
///
/// Return the parent crosslink for further checks.
///
/// Spec v0.8.0
fn verify_casper_ffg_vote<'a, T: EthSpec>(
    attestation: &Attestation<T>,
    state: &'a BeaconState<T>,
) -> Result<&'a Crosslink, Error> {
    let data = &attestation.data;
    if data.target.epoch == state.current_epoch() {
        verify!(
            data.source == state.current_justified_checkpoint,
            Invalid::WrongJustifiedCheckpoint {
                state: state.current_justified_checkpoint.clone(),
                attestation: data.source.clone(),
                is_current: true,
            }
        );
        Ok(state.get_current_crosslink(data.crosslink.shard)?)
    } else if data.target.epoch == state.previous_epoch() {
        verify!(
            data.source == state.previous_justified_checkpoint,
            Invalid::WrongJustifiedCheckpoint {
                state: state.previous_justified_checkpoint.clone(),
                attestation: data.source.clone(),
                is_current: false,
            }
        );
        Ok(state.get_previous_crosslink(data.crosslink.shard)?)
    } else {
        invalid!(Invalid::BadTargetEpoch)
    }
}
