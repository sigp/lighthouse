use super::Error;
use types::*;

macro_rules! ensure {
    ($condition: expr, $result: expr) => {
        if !$condition {
            return Err($result);
        }
    };
}

/// Returns `Ok(())` if some `AttesterSlashing` is valid to be included in some `BeaconState`,
/// otherwise returns an `Err`.
pub fn verify_slashable_attestation(
    state: &mut BeaconState,
    attester_slashing: &AttesterSlashing,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let slashable_attestation_1 = &attester_slashing.slashable_attestation_1;
    let slashable_attestation_2 = &attester_slashing.slashable_attestation_2;

    ensure!(
        slashable_attestation_1.data != slashable_attestation_2.data,
        Error::BadAttesterSlashing
    );
    ensure!(
        slashable_attestation_1.is_double_vote(slashable_attestation_2, spec)
            | slashable_attestation_1.is_surround_vote(slashable_attestation_2, spec),
        Error::BadAttesterSlashing
    );
    ensure!(
        state.verify_slashable_attestation(&slashable_attestation_1, spec),
        Error::BadAttesterSlashing
    );
    ensure!(
        state.verify_slashable_attestation(&slashable_attestation_2, spec),
        Error::BadAttesterSlashing
    );

    let mut slashable_indices = vec![];
    for i in &slashable_attestation_1.validator_indices {
        let validator = state
            .validator_registry
            .get(*i as usize)
            .ok_or_else(|| Error::BadAttesterSlashing)?;

        if slashable_attestation_1.validator_indices.contains(&i)
            & !validator.is_penalized_at(state.current_epoch(spec))
        {
            slashable_indices.push(i);
        }
    }

    ensure!(!slashable_indices.is_empty(), Error::BadAttesterSlashing);

    for i in slashable_indices {
        state.penalize_validator(*i as usize, spec)?;
    }

    Ok(())
}
