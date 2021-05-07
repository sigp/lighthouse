use super::errors::{AttestationInvalid as Invalid, BlockOperationError};
use super::VerifySignatures;
use crate::common::get_indexed_attestation;
use crate::per_block_processing::is_valid_indexed_attestation;
use safe_arith::SafeArith;
use types::*;

type Result<T> = std::result::Result<T, BlockOperationError<Invalid>>;

fn error(reason: Invalid) -> BlockOperationError<Invalid> {
    BlockOperationError::invalid(reason)
}

/// Returns `Ok(())` if the given `attestation` is valid to be included in a block that is applied
/// to `state`. Otherwise, returns a descriptive `Err`.
///
/// Optionally verifies the aggregate signature, depending on `verify_signatures`.
pub fn verify_attestation_for_block_inclusion<T: EthSpec>(
    state: &BeaconState<T>,
    attestation: &Attestation<T>,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<IndexedAttestation<T>> {
    let data = &attestation.data;

    verify!(
        data.slot.safe_add(spec.min_attestation_inclusion_delay)? <= state.slot(),
        Invalid::IncludedTooEarly {
            state: state.slot(),
            delay: spec.min_attestation_inclusion_delay,
            attestation: data.slot,
        }
    );
    verify!(
        state.slot() <= data.slot.safe_add(T::slots_per_epoch())?,
        Invalid::IncludedTooLate {
            state: state.slot(),
            attestation: data.slot,
        }
    );

    verify_attestation_for_state(state, attestation, verify_signatures, spec)
}

/// Returns `Ok(())` if `attestation` is a valid attestation to the chain that precedes the given
/// `state`.
///
/// Returns a descriptive `Err` if the attestation is malformed or does not accurately reflect the
/// prior blocks in `state`.
///
/// Spec v0.12.1
pub fn verify_attestation_for_state<T: EthSpec>(
    state: &BeaconState<T>,
    attestation: &Attestation<T>,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<IndexedAttestation<T>> {
    let data = &attestation.data;

    verify!(
        data.index < state.get_committee_count_at_slot(data.slot)?,
        Invalid::BadCommitteeIndex
    );

    // Verify the Casper FFG vote.
    verify_casper_ffg_vote(attestation, state)?;

    // Check signature and bitfields
    let committee = state.get_beacon_committee(attestation.data.slot, attestation.data.index)?;
    let indexed_attestation = get_indexed_attestation(committee.committee, attestation)?;
    is_valid_indexed_attestation(state, &indexed_attestation, verify_signatures, spec)?;

    Ok(indexed_attestation)
}

/// Check target epoch and source checkpoint.
///
/// Spec v0.12.1
fn verify_casper_ffg_vote<T: EthSpec>(
    attestation: &Attestation<T>,
    state: &BeaconState<T>,
) -> Result<()> {
    let data = &attestation.data;
    verify!(
        data.target.epoch == data.slot.epoch(T::slots_per_epoch()),
        Invalid::TargetEpochSlotMismatch {
            target_epoch: data.target.epoch,
            slot_epoch: data.slot.epoch(T::slots_per_epoch()),
        }
    );
    if data.target.epoch == state.current_epoch() {
        verify!(
            data.source == state.current_justified_checkpoint(),
            Invalid::WrongJustifiedCheckpoint {
                state: state.current_justified_checkpoint(),
                attestation: data.source,
                is_current: true,
            }
        );
        Ok(())
    } else if data.target.epoch == state.previous_epoch() {
        verify!(
            data.source == state.previous_justified_checkpoint(),
            Invalid::WrongJustifiedCheckpoint {
                state: state.previous_justified_checkpoint(),
                attestation: data.source,
                is_current: false,
            }
        );
        Ok(())
    } else {
        Err(error(Invalid::BadTargetEpoch))
    }
}
