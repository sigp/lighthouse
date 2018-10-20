extern crate types;
extern crate validator_induction;
extern crate validator_shuffling;

use types::{
    ActiveState,
    ChainConfig,
    CrosslinkRecord,
    CrystallizedState,
    Hash256,
    ValidatorRecord,
};
use validator_induction::{
    ValidatorInductor,
    ValidatorRegistration,
};
use validator_shuffling::{
    shard_and_committees_for_cycle,
    ValidatorAssignmentError,
};

pub const INITIAL_FORK_VERSION: u32 = 0;

pub struct ChainHead {
    active_state: ActiveState,
    crystallized_state: CrystallizedState,
    config: ChainConfig,
}

impl ChainHead {
    pub fn genesis(
        initial_validator_entries: &[ValidatorRegistration],
        config: ChainConfig)
        -> Result<Self, ValidatorAssignmentError>
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
         * Assign the validators to shards, using all zeros as the seed.
         *
         * Crystallizedstate stores two cycles, so we simply repeat the same assignment twice.
         */
        let shard_and_committee_for_slots = {
            let x = shard_and_committees_for_cycle(&vec![0; 32], &validators, 0, &config)?;
            x.append(&mut x.clone());
            x
        };

        /*
         * Set all the crosslink records to reference zero hashes.
         */
        let crosslinks = {
            let mut c = vec![];
            for _ in 0..config.shard_count {
                c.push(CrosslinkRecord {
                    recently_changed: false,
                    slot: 0,
                    hash: Hash256::zero(),
                });
            }
            c
        };

        /*
         * Initialize a genesis `Crystallizedstate`
         */
        let crystallized_state = CrystallizedState {
            validator_set_change_slot: 0,
            validators,
            crosslinks,
            last_state_recalculation_slot: 0,
            last_finalized_slot: 0,
            last_justified_slot: 0,
            justified_streak: 0,
            shard_and_committee_for_slots,
            deposits_penalized_in_period: vec![],
            validator_set_delta_hash_chain: Hash256::zero(),
            pre_fork_version: INITIAL_FORK_VERSION,
            post_fork_version: INITIAL_FORK_VERSION,
            fork_slot_number: 0,
        };

        let recent_block_hashes = {
            let mut x = vec![];
            for _ in 0..config.cycle_length {
                x.push(Hash256::zero());
            }
            x
        };

        let active_state = ActiveState {
            pending_attestations: vec![],
            pending_specials: vec![],
            recent_block_hashes,
            randao_mix: Hash256::zero(),
        };


        Ok(Self {
            active_state,
            crystallized_state,
            config,
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
