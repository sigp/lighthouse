/// Contains logic to manipulate a `&[Validator]`.
/// For now, we avoid defining a newtype and just have flat functions here.
use super::validator::*;
use crate::Epoch;

/// Given an indexed sequence of `validators`, return the indices corresponding to validators that are active at `epoch`.
///
/// Spec v0.4.0
pub fn get_active_validator_indices(validators: &[Validator], epoch: Epoch) -> Vec<usize> {
    validators
        .iter()
        .enumerate()
        .filter_map(|(index, validator)| {
            if validator.is_active_at(epoch) {
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
        let some_epoch = Epoch::random_for_test(&mut rng);
        let indices = get_active_validator_indices(&validators, some_epoch);
        assert_eq!(indices, vec![]);
    }

    #[test]
    fn can_get_no_active_validator_indices() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let mut validators = vec![];
        let count_validators = 10;
        for _ in 0..count_validators {
            validators.push(Validator::default())
        }

        let some_epoch = Epoch::random_for_test(&mut rng);
        let indices = get_active_validator_indices(&validators, some_epoch);
        assert_eq!(indices, vec![]);
    }

    #[test]
    fn can_get_all_active_validator_indices() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let count_validators = 10;
        let some_epoch = Epoch::random_for_test(&mut rng);

        let mut validators = (0..count_validators)
            .into_iter()
            .map(|_| {
                let mut validator = Validator::default();

                let activation_offset = u64::random_for_test(&mut rng);
                let exit_offset = u64::random_for_test(&mut rng);

                validator.activation_epoch = some_epoch - activation_offset;
                validator.exit_epoch = some_epoch + exit_offset;

                validator
            })
            .collect::<Vec<_>>();

        // test boundary condition by ensuring that at least one validator in the list just activated
        if let Some(validator) = validators.get_mut(0) {
            validator.activation_epoch = some_epoch;
        }

        let indices = get_active_validator_indices(&validators, some_epoch);
        assert_eq!(
            indices,
            (0..count_validators).into_iter().collect::<Vec<_>>()
        );
    }

    fn set_validators_to_default_entry_exit(validators: &mut [Validator]) {
        for validator in validators.iter_mut() {
            validator.activation_epoch = Epoch::max_value();
            validator.exit_epoch = Epoch::max_value();
        }
    }

    // sets all `validators` to be active as of some epoch prior to `epoch`. returns the activation epoch.
    fn set_validators_to_activated(validators: &mut [Validator], epoch: Epoch) -> Epoch {
        let activation_epoch = epoch - 10;
        for validator in validators.iter_mut() {
            validator.activation_epoch = activation_epoch;
        }
        activation_epoch
    }

    // sets all `validators` to be exited as of some epoch before `epoch`.
    fn set_validators_to_exited(
        validators: &mut [Validator],
        epoch: Epoch,
        activation_epoch: Epoch,
    ) {
        assert!(activation_epoch < epoch);
        let mut exit_epoch = activation_epoch + 10;
        while exit_epoch >= epoch {
            exit_epoch -= 1;
        }
        assert!(activation_epoch < exit_epoch && exit_epoch < epoch);

        for validator in validators.iter_mut() {
            validator.exit_epoch = exit_epoch;
        }
    }

    #[test]
    fn can_get_some_active_validator_indices() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        const COUNT_PARTITIONS: usize = 3;
        const COUNT_VALIDATORS: usize = 3 * COUNT_PARTITIONS;
        let some_epoch: Epoch = Epoch::random_for_test(&mut rng);

        let mut validators = (0..COUNT_VALIDATORS)
            .into_iter()
            .map(|_| {
                let mut validator = Validator::default();

                let activation_offset = Epoch::random_for_test(&mut rng);
                let exit_offset = Epoch::random_for_test(&mut rng);

                validator.activation_epoch = some_epoch - activation_offset;
                validator.exit_epoch = some_epoch + exit_offset;

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
                    set_validators_to_activated(chunk, some_epoch);
                    // test boundary condition by ensuring that at least one validator in the list just activated
                    if let Some(validator) = chunk.get_mut(0) {
                        validator.activation_epoch = some_epoch;
                    }
                }
                2 => {
                    // 3. exited
                    let activation_epoch = set_validators_to_activated(chunk, some_epoch);
                    set_validators_to_exited(chunk, some_epoch, activation_epoch);
                    // test boundary condition by ensuring that at least one validator in the list just exited
                    if let Some(validator) = chunk.get_mut(0) {
                        validator.exit_epoch = some_epoch;
                    }
                }
                _ => unreachable!(
                    "constants local to this test not in sync with generation of test case"
                ),
            }
        }

        let indices = get_active_validator_indices(&validators, some_epoch);
        assert_eq!(indices, vec![3, 4, 5]);
    }
}
