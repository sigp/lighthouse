use super::errors::{AttestationInvalid as Invalid, AttestationValidationError as Error};
use crate::common::convert_to_indexed;
use crate::per_block_processing::{
    verify_indexed_attestation, verify_indexed_attestation_without_signature,
};
use tree_hash::TreeHash;
use types::*;

/// Indicates if an `Attestation` is valid to be included in a block in the current epoch of the
/// given state.
///
/// Returns `Ok(())` if the `Attestation` is valid, otherwise indicates the reason for invalidity.
///
/// Spec v0.6.3
pub fn validate_attestation<T: EthSpec>(
    state: &BeaconState<T>,
    attestation: &Attestation,
    spec: &ChainSpec,
) -> Result<(), Error> {
    validate_attestation_parametric(state, attestation, spec, true, false)
}

/// Like `validate_attestation` but doesn't run checks which may become true in future states.
pub fn validate_attestation_time_independent_only<T: EthSpec>(
    state: &BeaconState<T>,
    attestation: &Attestation,
    spec: &ChainSpec,
) -> Result<(), Error> {
    validate_attestation_parametric(state, attestation, spec, true, true)
}

/// Indicates if an `Attestation` is valid to be included in a block in the current epoch of the
/// given state, without validating the aggregate signature.
///
/// Returns `Ok(())` if the `Attestation` is valid, otherwise indicates the reason for invalidity.
///
/// Spec v0.6.3
pub fn validate_attestation_without_signature<T: EthSpec>(
    state: &BeaconState<T>,
    attestation: &Attestation,
    spec: &ChainSpec,
) -> Result<(), Error> {
    validate_attestation_parametric(state, attestation, spec, false, false)
}

/// Indicates if an `Attestation` is valid to be included in a block in the current epoch of the
/// given state, optionally validating the aggregate signature.
///
///
/// Spec v0.6.3
fn validate_attestation_parametric<T: EthSpec>(
    state: &BeaconState<T>,
    attestation: &Attestation,
    spec: &ChainSpec,
    verify_signature: bool,
    time_independent_only: bool,
) -> Result<(), Error> {
    let attestation_slot = state.get_attestation_slot(&attestation.data)?;

    // Check attestation slot.
    verify!(
        time_independent_only
            || attestation_slot + spec.min_attestation_inclusion_delay <= state.slot,
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

    // Verify the Casper FFG vote.
    if !time_independent_only {
        verify_casper_ffg_vote(attestation, state)?;
    }

    // Crosslink data root is zero (to be removed in phase 1).
    verify!(
        attestation.data.crosslink_data_root == spec.zero_hash,
        Invalid::ShardBlockRootNotZero
    );

    // Check signature and bitfields
    let indexed_attestation = convert_to_indexed(state, attestation)?;
    if verify_signature {
        verify_indexed_attestation(state, &indexed_attestation, spec)?;
    } else {
        verify_indexed_attestation_without_signature(state, &indexed_attestation, spec)?;
    }

    Ok(())
}

/// Check target epoch, source epoch, source root, and source crosslink.
///
/// Spec v0.6.3
fn verify_casper_ffg_vote<T: EthSpec>(
    attestation: &Attestation,
    state: &BeaconState<T>,
) -> Result<(), Error> {
    let data = &attestation.data;
    if data.target_epoch == state.current_epoch() {
        verify!(
            data.source_epoch == state.current_justified_epoch,
            Invalid::WrongJustifiedEpoch {
                state: state.current_justified_epoch,
                attestation: data.source_epoch,
                is_current: true,
            }
        );
        verify!(
            data.source_root == state.current_justified_root,
            Invalid::WrongJustifiedRoot {
                state: state.current_justified_root,
                attestation: data.source_root,
                is_current: true,
            }
        );
        verify!(
            data.previous_crosslink_root
                == Hash256::from_slice(&state.get_current_crosslink(data.shard)?.tree_hash_root()),
            Invalid::BadPreviousCrosslink
        );
    } else if data.target_epoch == state.previous_epoch() {
        verify!(
            data.source_epoch == state.previous_justified_epoch,
            Invalid::WrongJustifiedEpoch {
                state: state.previous_justified_epoch,
                attestation: data.source_epoch,
                is_current: false,
            }
        );
        verify!(
            data.source_root == state.previous_justified_root,
            Invalid::WrongJustifiedRoot {
                state: state.previous_justified_root,
                attestation: data.source_root,
                is_current: false,
            }
        );
        verify!(
            data.previous_crosslink_root
                == Hash256::from_slice(&state.get_previous_crosslink(data.shard)?.tree_hash_root()),
            Invalid::BadPreviousCrosslink
        );
    } else {
        invalid!(Invalid::BadTargetEpoch)
    }
    Ok(())
}
