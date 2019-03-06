use crate::errors::{ExitInvalid as Invalid, ExitValidationError as Error};
use ssz::SignedRoot;
use types::*;

/// Indicates if an `Exit` is valid to be included in a block in the current epoch of the given
/// state.
///
/// Returns `Ok(())` if the `Exit` is valid, otherwise indicates the reason for invalidity.
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
        .ok_or(Error::Invalid(Invalid::ValidatorUnknown(
            exit.validator_index,
        )))?;

    verify!(
        validator.exit_epoch
            > state.get_delayed_activation_exit_epoch(state.current_epoch(spec), spec),
        Invalid::AlreadyExited
    );

    verify!(
        state.current_epoch(spec) >= exit.epoch,
        Invalid::FutureEpoch(state.current_epoch(spec), exit.epoch)
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
