mod block_hash;
mod validator;

use super::utils;

/// Produce a vector of validators indicies where those
/// validators start and end dynasties are within the supplied
/// `dynasty`.
pub fn active_validator_indicies(
    dynasty: &u64,
    validators: &Vec<ValidatorRecord>)
    -> Vec<usize>
{
    validators.iter()
        .enumerate()
        .filter_map(|(i, validator)| {
            if (validator.start_dynasty >= *dynasty) &
                (validator.end_dynasty < *dynasty)
            {
                Some(i)
            } else {
                None
            }
        })
        .collect()
}


