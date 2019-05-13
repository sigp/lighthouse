// use crate::common::exit_validator;
use types::{BeaconStateError as Error, *};

/// Iterate through the validator registry and eject active validators with balance below
/// ``EJECTION_BALANCE``.
///
/// Spec v0.5.1
pub fn process_ejections(state: &mut BeaconState, spec: &ChainSpec) -> Result<(), Error> {
    // There is an awkward double (triple?) loop here because we can't loop across the borrowed
    // active validator indices and mutate state in the one loop.
    let exitable: Vec<usize> = state
        .get_cached_active_validator_indices(RelativeEpoch::Current, spec)?
        .iter()
        .filter_map(|&i| {
            if state.balances[i as usize] < spec.ejection_balance {
                Some(i)
            } else {
                None
            }
        })
        .collect();

    for validator_index in exitable {
        // FIXME(sproul)
        // exit_validator(state, validator_index, spec)?
    }

    Ok(())
}
