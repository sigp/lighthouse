use crate::errors::{ExitInvalid as Invalid, ExitValidationError as Error};
use ssz::SignedRoot;
use types::*;

/// Verify validity of ``slashable_attestation`` fields.
///
/// Returns `Ok(())` if all fields are valid.
///
/// Spec v0.4.0
pub fn verify_exit(
    state: &BeaconState,
    exit: &VoluntaryExit,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let validator = state
        .validator_registry
        .get(exit.validator_index as usize)
        .ok_or(Error::Invalid(Invalid::ValidatorUnknown))?;

    verify!(
        validator.exit_epoch
            > state.get_delayed_activation_exit_epoch(state.current_epoch(spec), spec),
        Invalid::AlreadyExited
    );

    verify!(
        state.current_epoch(spec) >= exit.epoch,
        Invalid::FutureEpoch
    );

    let message = exit.signed_root();
    let domain = spec.get_domain(exit.epoch, Domain::Exit, &state.fork);

    verify!(
        exit.signature
            .verify(&message[..], domain, &validator.pubkey),
        Invalid::BadSignature
    );

    Ok(())
}
