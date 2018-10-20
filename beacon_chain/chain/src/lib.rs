extern crate types;
extern crate validator_induction;
extern crate validator_shuffling;

use types::{
    ActiveState,
    ChainConfig,
    CrystallizedState,
    ValidatorRecord,
};
use validator_induction::{
    ValidatorInductor,
    ValidatorRegistration,
};
use validator_shuffling::shard_and_committees_for_cycle;

pub struct ChainHead<'a> {
    act_state: ActiveState,
    cry_state: &'a CrystallizedState,
    config: ChainConfig,
}

impl<'a> ChainHead<'a> {
    pub fn genesis(
        initial_validator_entries: &[ValidatorRegistration],
        config: ChainConfig)
        -> Self
    {
        /*
         * Parse the ValidatorRegistrations into ValidatorRecords and induct them.
         *
         * Ignore any records which fail proof-of-possession or are invalid.
         */
        let validators = {
            let mut validators = vec![];
            let inductor = ValidatorInductor {
                current_slot: 0,
                shard_count: config.shard_count,
                validators: &mut validators,
                empty_validator_start: 0,
            };
            for registration in initial_validator_entries {
                let _ = inductor.induct(&registration);
            };
            validators
        };

        /*
         * Delegate the validators to shards.
         */
        let shard_and_committees = shard_and_committees_for_cycle(
            &vec![0; 32],
            &validators,
            0,
            &config);

        //TODO: complete this
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
