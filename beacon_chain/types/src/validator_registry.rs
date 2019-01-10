/// Contains logic to manipulate a `&[ValidatorRecord]`.
/// For now, we avoid defining a newtype and just have flat functions here.
use super::validator_record::*;

pub fn get_active_validator_indices(validators: &[ValidatorRecord], slot: u64) -> Vec<usize> {
    validators
        .iter()
        .enumerate()
        .filter_map(|(index, validator)| {
            if validator.is_active_at(slot) {
                Some(index)
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};

    #[test]
    fn can_get_empty_active_validator_indices() {
        let mut rng = XorShiftRng::from_seed([42; 16]);

        let validators = vec![];
        let some_slot = u64::random_for_test(&mut rng);
        let indices = get_active_validator_indices(&validators, some_slot);
        assert_eq!(indices, vec![]);
    }

    #[test]
    fn can_get_no_active_validator_indices() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let mut validators = vec![];
        let count_validators = 10;
        for _ in 0..count_validators {
            validators.push(ValidatorRecord::default())
        }

        let some_slot = u64::random_for_test(&mut rng);
        let indices = get_active_validator_indices(&validators, some_slot);
        assert_eq!(indices, vec![]);
    }

    #[test]
    fn can_get_all_active_validator_indices() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let count_validators = 10;
        let some_slot = u64::random_for_test(&mut rng);

        let mut validators = (0..count_validators)
            .into_iter()
            .map(|_| {
                let mut validator = ValidatorRecord::default();

                let activation_offset = u64::random_for_test(&mut rng);
                let exit_offset = u64::random_for_test(&mut rng);

                validator.activation_slot = some_slot.checked_sub(activation_offset).unwrap_or(0);
                validator.exit_slot = some_slot.checked_add(exit_offset).unwrap_or(std::u64::MAX);

                validator
            })
            .collect::<Vec<_>>();

        // test boundary condition by ensuring that at least one validator in the list just activated
        if let Some(validator) = validators.get_mut(0) {
            validator.activation_slot = some_slot;
        }

        let indices = get_active_validator_indices(&validators, some_slot);
        assert_eq!(
            indices,
            (0..count_validators).into_iter().collect::<Vec<_>>()
        );
    }

    fn set_validators_to_default_entry_exit(validators: &mut [ValidatorRecord]) {
        for validator in validators.iter_mut() {
            validator.activation_slot = std::u64::MAX;
            validator.exit_slot = std::u64::MAX;
        }
    }

    // sets all `validators` to be active as of some slot prior to `slot`. returns the activation slot.
    fn set_validators_to_activated(validators: &mut [ValidatorRecord], slot: u64) -> u64 {
        let activation_slot = slot - 10;
        for validator in validators.iter_mut() {
            validator.activation_slot = activation_slot;
        }
        activation_slot
    }

    // sets all `validators` to be exited as of some slot before `slot`.
    fn set_validators_to_exited(
        validators: &mut [ValidatorRecord],
        slot: u64,
        activation_slot: u64,
    ) {
        assert!(activation_slot < slot);
        let mut exit_slot = activation_slot + 10;
        while exit_slot >= slot {
            exit_slot -= 1;
        }
        assert!(activation_slot < exit_slot && exit_slot < slot);

        for validator in validators.iter_mut() {
            validator.exit_slot = exit_slot;
        }
    }

    #[test]
    fn can_get_some_active_validator_indices() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        const COUNT_PARTITIONS: usize = 3;
        const COUNT_VALIDATORS: usize = 3 * COUNT_PARTITIONS;
        let some_slot: u64 = u64::random_for_test(&mut rng);

        let mut validators = (0..COUNT_VALIDATORS)
            .into_iter()
            .map(|_| {
                let mut validator = ValidatorRecord::default();

                let activation_offset = u64::random_for_test(&mut rng);
                let exit_offset = u64::random_for_test(&mut rng);

                validator.activation_slot = some_slot.checked_sub(activation_offset).unwrap_or(0);
                validator.exit_slot = some_slot.checked_add(exit_offset).unwrap_or(std::u64::MAX);

                validator
            })
            .collect::<Vec<_>>();

        // we partition the set into partitions based on lifecycle:
        for (i, chunk) in validators.chunks_exact_mut(COUNT_PARTITIONS).enumerate() {
            match i {
                0 => {
                    // 1. not activated (Default::default())
                    set_validators_to_default_entry_exit(chunk);
                }
                1 => {
                    // 2. activated, but not exited
                    set_validators_to_activated(chunk, some_slot);
                    // test boundary condition by ensuring that at least one validator in the list just activated
                    if let Some(validator) = chunk.get_mut(0) {
                        validator.activation_slot = some_slot;
                    }
                }
                2 => {
                    // 3. exited
                    let activation_slot = set_validators_to_activated(chunk, some_slot);
                    set_validators_to_exited(chunk, some_slot, activation_slot);
                    // test boundary condition by ensuring that at least one validator in the list just exited
                    if let Some(validator) = chunk.get_mut(0) {
                        validator.exit_slot = some_slot;
                    }
                }
                _ => unreachable!(
                    "constants local to this test not in sync with generation of test case"
                ),
            }
        }

        let indices = get_active_validator_indices(&validators, some_slot);
        assert_eq!(indices, vec![3, 4, 5]);
    }
}
