use super::{ActiveState, ChainConfig, CrystallizedState};
use types::ValidatorStatus;
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
pub fn genesis_states(config: &ChainConfig) -> Result<(ActiveState, CrystallizedState), Error> {
    /*
     * Parse the ValidatorRegistrations into ValidatorRecords and induct them.
     *
     * Ignore any records which fail proof-of-possession or are invalid.
     */
    /*
    TODO: refactor this
    let validators = {
        let mut inductor = ValidatorInductor::new(0, config.shard_count, vec![]);
        for registration in &config.initial_validators {
            let _ = inductor.induct(&registration, ValidatorStatus::Active);
        }
        inductor.to_vec()
    };
    */
    let validators = vec![];

    /*
     * Assign the validators to shards, using all zeros as the seed.
     *
     * Crystallizedstate stores two cycles, so we simply repeat the same assignment twice.
     */
    let _shard_and_committee_for_slots = {
        let mut a = shard_and_committees_for_cycle(&vec![0; 32], &validators, 0, &config)?;
        let mut b = a.clone();
        a.append(&mut b);
        a
    };

    // TODO: implement genesis for `BeaconState`
    // https://github.com/sigp/lighthouse/issues/99

    Err(Error::NotImplemented)
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
