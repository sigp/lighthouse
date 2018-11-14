extern crate types;

use types::{ValidatorRecord, ValidatorStatus};

pub fn validator_is_active(v: &ValidatorRecord) -> bool {
    v.status == ValidatorStatus::Active as u8
}

/// Returns the indicies of each active validator in a given vec of validators.
pub fn active_validator_indices(validators: &[ValidatorRecord]) -> Vec<usize> {
    validators
        .iter()
        .enumerate()
        .filter_map(|(i, validator)| {
            if validator_is_active(&validator) {
                Some(i)
            } else {
                None
            }
        }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_active_validator() {
        let mut validators = vec![];

        let (mut v, _) = ValidatorRecord::zero_with_thread_rand_keypair();
        v.status = ValidatorStatus::Active as u8;
        assert!(validator_is_active(&v));
        validators.push(v);

        let (mut v, _) = ValidatorRecord::zero_with_thread_rand_keypair();
        v.status = ValidatorStatus::PendingActivation as u8;
        assert!(!validator_is_active(&v));
        validators.push(v);

        let (mut v, _) = ValidatorRecord::zero_with_thread_rand_keypair();
        v.status = ValidatorStatus::PendingExit as u8;
        assert!(!validator_is_active(&v));
        validators.push(v);

        let (mut v, _) = ValidatorRecord::zero_with_thread_rand_keypair();
        v.status = ValidatorStatus::PendingWithdraw as u8;
        assert!(!validator_is_active(&v));
        validators.push(v);

        let (mut v, _) = ValidatorRecord::zero_with_thread_rand_keypair();
        v.status = ValidatorStatus::Withdrawn as u8;
        assert!(!validator_is_active(&v));
        validators.push(v);

        let (mut v, _) = ValidatorRecord::zero_with_thread_rand_keypair();
        v.status = ValidatorStatus::Penalized as u8;
        assert!(!validator_is_active(&v));
        validators.push(v);

        assert_eq!(active_validator_indices(&validators), vec![0]);
    }
}
