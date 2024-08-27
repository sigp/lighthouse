use super::errors::{AttestationInvalid as Invalid, BlockOperationError};
use super::VerifySignatures;
use crate::per_block_processing::is_valid_indexed_attestation;
use crate::ConsensusContext;
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
pub fn verify_attestation_for_block_inclusion<'ctxt, E: EthSpec>(
    state: &BeaconState<E>,
    attestation: AttestationRef<'ctxt, E>,
    ctxt: &'ctxt mut ConsensusContext<E>,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<IndexedAttestationRef<'ctxt, E>> {
    let data = attestation.data();

    verify!(
        data.slot.safe_add(spec.min_attestation_inclusion_delay)? <= state.slot(),
        Invalid::IncludedTooEarly {
            state: state.slot(),
            delay: spec.min_attestation_inclusion_delay,
            attestation: data.slot,
        }
    );
    match state {
        BeaconState::Base(_)
        | BeaconState::Altair(_)
        | BeaconState::Bellatrix(_)
        | BeaconState::Capella(_) => {
            verify!(
                state.slot() <= data.slot.safe_add(E::slots_per_epoch())?,
                Invalid::IncludedTooLate {
                    state: state.slot(),
                    attestation: data.slot,
                }
            );
        }
        // [Modified in Deneb:EIP7045]
        BeaconState::Deneb(_) | BeaconState::Electra(_) | BeaconState::EIP7732(_) => {}
    }

    verify_attestation_for_state(state, attestation, ctxt, verify_signatures, spec)
}

/// Returns `Ok(())` if `attestation` is a valid attestation to the chain that precedes the given
/// `state`.
///
/// Returns a descriptive `Err` if the attestation is malformed or does not accurately reflect the
/// prior blocks in `state`.
///
/// Spec v0.12.1
pub fn verify_attestation_for_state<'ctxt, E: EthSpec>(
    state: &BeaconState<E>,
    attestation: AttestationRef<'ctxt, E>,
    ctxt: &'ctxt mut ConsensusContext<E>,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<IndexedAttestationRef<'ctxt, E>> {
    let data = attestation.data();

    // TODO(electra) choosing a validation based on the attestation's fork
    // rather than the state's fork makes this simple, but technically the spec
    // defines this verification based on the state's fork.
    match attestation {
        AttestationRef::Base(_) => {
            verify!(
                data.index < state.get_committee_count_at_slot(data.slot)?,
                Invalid::BadCommitteeIndex
            );
        }
        AttestationRef::Electra(_) => {
            verify!(data.index == 0, Invalid::BadCommitteeIndex);
        }
    }

    // Verify the Casper FFG vote.
    verify_casper_ffg_vote(attestation, state)?;

    // Check signature and bitfields
    let indexed_attestation = ctxt.get_indexed_attestation(state, attestation)?;
    is_valid_indexed_attestation(state, indexed_attestation, verify_signatures, spec)?;

    Ok(indexed_attestation)
}

/// Check target epoch and source checkpoint.
///
/// Spec v0.12.1
fn verify_casper_ffg_vote<E: EthSpec>(
    attestation: AttestationRef<E>,
    state: &BeaconState<E>,
) -> Result<()> {
    let data = attestation.data();
    verify!(
        data.target.epoch == data.slot.epoch(E::slots_per_epoch()),
        Invalid::TargetEpochSlotMismatch {
            target_epoch: data.target.epoch,
            slot_epoch: data.slot.epoch(E::slots_per_epoch()),
        }
    );
    if data.target.epoch == state.current_epoch() {
        verify!(
            data.source == state.current_justified_checkpoint(),
            Invalid::WrongJustifiedCheckpoint {
                state: Box::new(state.current_justified_checkpoint()),
                attestation: Box::new(data.source),
                is_current: true,
            }
        );
        Ok(())
    } else if data.target.epoch == state.previous_epoch() {
        verify!(
            data.source == state.previous_justified_checkpoint(),
            Invalid::WrongJustifiedCheckpoint {
                state: Box::new(state.previous_justified_checkpoint()),
                attestation: Box::new(data.source),
                is_current: false,
            }
        );
        Ok(())
    } else {
        Err(error(Invalid::BadTargetEpoch))
    }
}
