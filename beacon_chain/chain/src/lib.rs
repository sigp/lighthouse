extern crate types;
extern crate validator_induction;
extern crate validator_shuffling;

use types::{
    ActiveState,
    ChainConfig,
    CrosslinkRecord,
    CrystallizedState,
    Hash256,
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

/// A ChainHead structure represents the "head" or "tip" of a beacon chain blockchain.
///
/// Initially, a "gensis" chainhead will be created and then new blocks will be built upon it.
pub struct ChainHead {
    /// The hash of the block that is the head of the chain.
    pub head_hash: Hash256,
    /// The active state at this head block.
    pub active_state: ActiveState,
    /// The crystallized state at this head block.
    pub crystallized_state: CrystallizedState,
    /// The configuration of the underlying chain.
    pub config: ChainConfig,
}

impl ChainHead {
    /// Initialize a new ChainHead with genesis parameters.
    ///
    /// Used when syncing a chain from scratch.
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
            let mut inductor = ValidatorInductor::new(0, config.shard_count, vec![]);
            for registration in initial_validator_entries {
                let _ = inductor.induct(&registration);
            };
            inductor.to_vec()
        };

        /*
         * Assign the validators to shards, using all zeros as the seed.
         *
         * Crystallizedstate stores two cycles, so we simply repeat the same assignment twice.
         */
        let shard_and_committee_for_slots = {
            let mut a = shard_and_committees_for_cycle(&vec![0; 32], &validators, 0, &config)?;
            let mut b = a.clone();
            a.append(&mut b);
            a
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
            validators: validators.to_vec(),
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

        /*
         * Set all recent block hashes to zero.
         */
        let recent_block_hashes = {
            let mut x = vec![];
            for _ in 0..config.cycle_length {
                x.push(Hash256::zero());
            }
            x
        };

        /*
         * Create an active state.
         */
        let active_state = ActiveState {
            pending_attestations: vec![],
            pending_specials: vec![],
            recent_block_hashes,
            randao_mix: Hash256::zero(),
        };


        Ok(Self {
            head_hash: Hash256::zero(),
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
