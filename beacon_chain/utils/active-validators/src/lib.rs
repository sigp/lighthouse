extern crate types;

use types::{
    ValidatorRecord,
    ValidatorStatus,
};

pub fn validator_is_active(v: &ValidatorRecord) -> bool {
    v.status == ValidatorStatus::Active as u8
}

/// Returns the indicies of each active validator in a given vec of validators.
pub fn active_validator_indices(validators: &[ValidatorRecord])
    -> Vec<usize>
{
    validators.iter()
        .enumerate()
        .filter_map(|(i, validator)| {
            if validator_is_active(&validator) {
                Some(i)
            } else {
                None
            }
        })
        .collect()
}
