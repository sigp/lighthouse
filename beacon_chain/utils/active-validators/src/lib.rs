extern crate types;

use types::{ValidatorRecord, ValidatorStatus};

/// Returns the indicies of each active validator in a given vec of validators.
pub fn active_validator_indices(validators: &[ValidatorRecord]) -> Vec<usize> {
    validators
        .iter()
        .enumerate()
        .filter_map(|(i, validator)| {
            if validator.status_is(ValidatorStatus::Active) {
                Some(i)
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn validator_is_active(v: &ValidatorRecord) -> bool {
        v.status_is(ValidatorStatus::Active)
    }

    #[test]
    fn test_active_validator() {
        let mut validators = vec![];

        let (mut v, _) = ValidatorRecord::zero_with_thread_rand_keypair();
        v.status = ValidatorStatus::Active;
        assert!(validator_is_active(&v));
        validators.push(v);

        let (mut v, _) = ValidatorRecord::zero_with_thread_rand_keypair();
        v.status = ValidatorStatus::PendingActivation;
        assert!(!validator_is_active(&v));
        validators.push(v);

        let (mut v, _) = ValidatorRecord::zero_with_thread_rand_keypair();
        v.status = ValidatorStatus::PendingExit;
        assert!(!validator_is_active(&v));
        validators.push(v);

        let (mut v, _) = ValidatorRecord::zero_with_thread_rand_keypair();
        v.status = ValidatorStatus::PendingWithdraw;
        assert!(!validator_is_active(&v));
        validators.push(v);

        let (mut v, _) = ValidatorRecord::zero_with_thread_rand_keypair();
        v.status = ValidatorStatus::Withdrawn;
        assert!(!validator_is_active(&v));
        validators.push(v);

        let (mut v, _) = ValidatorRecord::zero_with_thread_rand_keypair();
        v.status = ValidatorStatus::Penalized;
        assert!(!validator_is_active(&v));
        validators.push(v);

        assert_eq!(active_validator_indices(&validators), vec![0]);
    }
}
