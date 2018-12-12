use spec::ChainSpec;
use types::{
    BeaconState, CrosslinkRecord, ForkData, Hash256, ValidatorRegistration, ValidatorStatus,
};
use validator_induction::ValidatorInductor;
use validator_shuffling::{shard_and_committees_for_cycle, ValidatorAssignmentError};

#[derive(Debug, PartialEq)]
pub enum Error {
    ValidationAssignmentError(ValidatorAssignmentError),
    NotImplemented,
}

impl From<ValidatorAssignmentError> for Error {
    fn from(e: ValidatorAssignmentError) -> Error {
        Error::ValidationAssignmentError(e)
    }
}

/// Initialize a new ChainHead with genesis parameters.
///
/// Used when syncing a chain from scratch.
pub fn genesis_states(
    spec: &ChainSpec,
    initial_validators: Vec<ValidatorRegistration>,
    genesis_time: u64,
    processed_pow_receipt_root: Hash256,
) -> Result<BeaconState, Error> {
    /*
     * Parse the ValidatorRegistrations into ValidatorRecords and induct them.
     *
     * Ignore any records which fail proof-of-possession or are invalid.
     */
    let validators = {
        let mut inductor = ValidatorInductor::new(0, spec.shard_count, vec![]);
        for registration in &initial_validators {
            let _ = inductor.induct(&registration, ValidatorStatus::Active);
        }
        inductor.to_vec()
    };

    /*
     * Assign the validators to shards, using all zeros as the seed.
     *
     * Crystallizedstate stores two cycles, so we simply repeat the same assignment twice.
     */
    let _shard_and_committee_for_slots = {
        let mut a = shard_and_committees_for_cycle(&vec![0; 32], &validators, 0, &spec)?;
        let mut b = a.clone();
        a.append(&mut b);
        a
    };

    let initial_crosslink = CrosslinkRecord {
        slot: spec.initial_slot_number,
        shard_block_root: spec.zero_hash,
    };

    Ok(BeaconState {
        /*
         * Misc
         */
        slot: spec.initial_slot_number,
        genesis_time,
        fork_data: ForkData {
            pre_fork_version: spec.initial_fork_version,
            post_fork_version: spec.initial_fork_version,
            fork_slot: spec.initial_slot_number,
        },
        /*
         * Validator registry
         */
        validator_registry: validators,
        validator_registry_latest_change_slot: spec.initial_slot_number,
        validator_registry_exit_count: 0,
        validator_registry_delta_chain_tip: spec.zero_hash,
        /*
         * Randomness and committees
         */
        randao_mix: spec.zero_hash,
        next_seed: spec.zero_hash,
        shard_committees_at_slot: vec![],
        persistent_committees: vec![],
        persisten_committee_reassignments: vec![],
        /*
         * Finality
         */
        previous_justified_slot: spec.initial_slot_number,
        justified_slot: spec.initial_slot_number,
        justified_bitfield: 0,
        finalized_slot: spec.initial_slot_number,
        /*
         * Recent state
         */
        latest_crosslinks: vec![initial_crosslink; spec.shard_count as usize],
        latest_block_roots: vec![spec.zero_hash; spec.epoch_length as usize],
        latest_penalized_exit_balances: vec![],
        latest_attestations: vec![],
        /*
         * PoW receipt root
         */
        processed_pow_receipt_root,
        candidate_pow_receipt_roots: vec![],
    })
}

#[cfg(test)]
mod tests {
    extern crate bls;
    extern crate validator_induction;

    // TODO: implement genesis for `BeaconState`
    // https://github.com/sigp/lighthouse/issues/99
    //
    /*
    use self::bls::{create_proof_of_possession, Keypair};
    use super::*;
    use types::{Address, Hash256, ValidatorRegistration};

    #[test]
    fn test_genesis_no_validators() {
        let config = ChainConfig::standard();
        let (act, cry) = genesis_states(&config).unwrap();

        assert_eq!(cry.validator_set_change_slot, 0);
        assert_eq!(cry.validators.len(), 0);
        assert_eq!(cry.crosslinks.len(), config.shard_count as usize);
        for cl in cry.crosslinks {
            assert_eq!(cl.recently_changed, false);
            assert_eq!(cl.slot, 0);
            assert_eq!(cl.hash, Hash256::zero());
        }
        assert_eq!(cry.last_state_recalculation_slot, 0);
        assert_eq!(cry.last_finalized_slot, 0);
        assert_eq!(cry.last_justified_slot, 0);
        assert_eq!(cry.justified_streak, 0);
        assert_eq!(
            cry.shard_and_committee_for_slots.len(),
            (config.cycle_length as usize) * 2
        );
        assert_eq!(cry.deposits_penalized_in_period.len(), 0);
        assert_eq!(cry.validator_set_delta_hash_chain, Hash256::zero());
        assert_eq!(cry.pre_fork_version, INITIAL_FORK_VERSION);
        assert_eq!(cry.post_fork_version, INITIAL_FORK_VERSION);
        assert_eq!(cry.fork_slot_number, 0);

        assert_eq!(act.pending_attestations.len(), 0);
        assert_eq!(act.pending_specials.len(), 0);
        assert_eq!(
            act.recent_block_hashes,
            vec![Hash256::zero(); config.cycle_length as usize]
        );
        assert_eq!(act.randao_mix, Hash256::zero());
    }

    fn random_registration() -> ValidatorRegistration {
        let keypair = Keypair::random();
        ValidatorRegistration {
            pubkey: keypair.pk.clone(),
            withdrawal_shard: 0,
            withdrawal_address: Address::random(),
            randao_commitment: Hash256::random(),
            proof_of_possession: create_proof_of_possession(&keypair),
        }
    }

    #[test]
    fn test_genesis_valid_validators() {
        let mut config = ChainConfig::standard();
        let validator_count = 5;

        for _ in 0..validator_count {
            config.initial_validators.push(random_registration());
        }

        let (_, cry) = genesis_states(&config).unwrap();

        assert_eq!(cry.validators.len(), validator_count);
    }

    #[test]
    fn test_genesis_invalid_validators() {
        let mut config = ChainConfig::standard();
        let good_validator_count = 5;

        for _ in 0..good_validator_count {
            config.initial_validators.push(random_registration());
        }

        let mut bad_v = random_registration();
        let bad_kp = Keypair::random();
        bad_v.proof_of_possession = create_proof_of_possession(&bad_kp);
        config.initial_validators.push(bad_v);

        let mut bad_v = random_registration();
        bad_v.withdrawal_shard = config.shard_count + 1;
        config.initial_validators.push(bad_v);

        let (_, cry) = genesis_states(&config).unwrap();

        assert!(
            config.initial_validators.len() != good_validator_count,
            "test is invalid"
        );
        assert_eq!(cry.validators.len(), good_validator_count);
    }
    */
}
