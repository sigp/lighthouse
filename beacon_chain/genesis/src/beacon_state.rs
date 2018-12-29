use spec::ChainSpec;
use types::{BeaconState, CrosslinkRecord, ForkData};
use validator_shuffling::{shard_and_committees_for_cycle, ValidatorAssignmentError};

#[derive(Debug, PartialEq)]
pub enum Error {
    NoValidators,
    ValidationAssignmentError(ValidatorAssignmentError),
    NotImplemented,
}

pub fn genesis_beacon_state(spec: &ChainSpec) -> Result<BeaconState, Error> {
    /*
     * Assign the validators to shards, using all zeros as the seed.
     *
     * Crystallizedstate stores two cycles, so we simply repeat the same assignment twice.
     */
    let _shard_and_committee_for_slots = {
        let mut a = shard_and_committees_for_cycle(&[0; 32], &spec.initial_validators, 0, &spec)?;
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
        genesis_time: spec.genesis_time,
        fork_data: ForkData {
            pre_fork_version: spec.initial_fork_version,
            post_fork_version: spec.initial_fork_version,
            fork_slot: spec.initial_slot_number,
        },
        /*
         * Validator registry
         */
        validator_registry: spec.initial_validators.clone(),
        validator_balances: spec.initial_balances.clone(),
        validator_registry_latest_change_slot: spec.initial_slot_number,
        validator_registry_exit_count: 0,
        validator_registry_delta_chain_tip: spec.zero_hash,
        /*
         * Randomness and committees
         */
        randao_mix: spec.zero_hash,
        next_seed: spec.zero_hash,
        shard_committees_at_slots: vec![],
        persistent_committees: vec![],
        persistent_committee_reassignments: vec![],
        /*
         * Finality
         */
        previous_justified_slot: spec.initial_slot_number,
        justified_slot: spec.initial_slot_number,
        justification_bitfield: 0,
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
        processed_pow_receipt_root: spec.processed_pow_receipt_root,
        candidate_pow_receipt_roots: vec![],
    })
}

impl From<ValidatorAssignmentError> for Error {
    fn from(e: ValidatorAssignmentError) -> Error {
        Error::ValidationAssignmentError(e)
    }
}

#[cfg(test)]
mod tests {
    extern crate bls;
    extern crate validator_induction;

    use super::*;

    // TODO: enhance these tests.
    // https://github.com/sigp/lighthouse/issues/117

    #[test]
    fn test_genesis() {
        let spec = ChainSpec::foundation();

        let state = genesis_beacon_state(&spec).unwrap();

        assert_eq!(
            state.validator_registry.len(),
            spec.initial_validators.len()
        );
    }

    /*
    #[test]
    fn test_genesis_bad_validator() {
        let mut spec = ChainSpec::foundation();

        let random_kp = Keypair::random();
        spec.initial_validators[4].proof_of_possession = create_proof_of_possession(&random_kp);

        let state = genesis_beacon_state(&spec).unwrap();

        assert_eq!(
            state.validator_registry.len(),
            spec.initial_validators.len() - 1
        );
    }
    */
}
