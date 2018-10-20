use types::{
    ValidatorRecord,
    ValidatorStatus,
};

/// Returns the indicies of each active validator in a given vec of validators.
pub fn active_validator_indices(validators: &[ValidatorRecord])
    -> Vec<usize>
{
    validators.iter()
        .enumerate()
        .filter_map(|(i, validator)| {
            match validator.status {
                x if x == ValidatorStatus::Active as u8 => Some(i),
                _ => None
            }
        })
        .collect()
}
