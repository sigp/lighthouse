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
    use types::Hash256;

    // TODO: enhance these tests.
    // https://github.com/sigp/lighthouse/issues/117

    #[test]
    fn test_gen_state() {
        let spec = ChainSpec::foundation();

        let state = genesis_beacon_state(&spec).unwrap();

        assert_eq!(
            state.validator_registry.len(),
            spec.initial_validators.len()
        );
    }

    #[test]
    fn test_gen_state_misc() {
        let spec = ChainSpec::foundation();

        let state = genesis_beacon_state(&spec).unwrap();

        assert_eq!(state.slot, 0);
        assert_eq!(state.genesis_time, spec.genesis_time); 
        assert_eq!(state.fork_data.pre_fork_version, 0);
        assert_eq!(state.fork_data.post_fork_version, 0);
        assert_eq!(state.fork_data.fork_slot, 0);
    }

    #[test]
    fn test_gen_state_validators() {
        let spec = ChainSpec::foundation();

        let state = genesis_beacon_state(&spec).unwrap();

        assert_eq!(state.validator_registry, spec.initial_validators);
        assert_eq!(state.validator_balances, spec.initial_balances);
        assert!(state.validator_registry_latest_change_slot == 0);
        assert!(state.validator_registry_exit_count == 0);
        assert_eq!(state.validator_registry_delta_chain_tip, Hash256::zero());
    }

    #[test]
    fn test_gen_state_randomness_committees() {
        let spec = ChainSpec::foundation();

        let state = genesis_beacon_state(&spec).unwrap();

        // Note: specs now have randao_mixes containing 8,192 zero hashes
        assert_eq!(state.randao_mix, Hash256::zero());

        // Note: next_seed has changed to latest_vdf_outputs[8,192]8,192]
        assert_eq!(state.next_seed, Hash256::zero());

        // TODO: Check shard and committee shuffling requires solving issue:
        // https://github.com/sigp/lighthouse/issues/151

        // initial_shuffling = get_shuffling(Hash256::zero(), &state.validator_registry, 0, 0)
        // initial_shuffling = initial_shuffling.append(initial_shuffling.clone());
    }

    #[test]
    fn test_gen_state_custody_finanilty() {
        let spec = ChainSpec::foundation();

        let state = genesis_beacon_state(&spec).unwrap();

        // Note: custody_challenges are not included yet but are in Eth2.0 specs

        assert_eq!(state.previous_justified_slot, 0);
        assert_eq!(state.justified_slot, 0);
        assert_eq!(state.justification_bitfield, 0);
        assert_eq!(state.finalized_slot, 0);
    }

    #[test]
    fn test_gen_state_recent_state() {
        let spec = ChainSpec::foundation();

        let state = genesis_beacon_state(&spec).unwrap();


        // Test latest_crosslinks
        assert_eq!(state.latest_crosslinks.len(), 1024);
        for link in state.latest_crosslinks.iter() {
            assert_eq!(link.slot, 0);
            assert_eq!(link.shard_block_root, Hash256::zero());
        }

        // Test latest_block_roots
        assert_eq!(state.latest_block_roots.len(), 64);
        for block in state.latest_block_roots.iter() {
            assert_eq!(*block, Hash256::zero());
        }

        // Test latest_penalized_exit_balances
        // Note: Eth2.0 specs says this should be an array of length LATEST_PENALIZE_EXIT_LENGTH
        // = (8,192)
        assert!(state.latest_penalized_exit_balances.is_empty());

        // Test latest_attestations
        assert!(state.latest_attestations.is_empty());

        // Note: missing batched_block_roots in new spec

    }

    // Note: here we refer to it as pow_reciept in the Eth2.0 specs it is called deposit
    #[test]
    fn test_gen_state_deposit_root() {
        let spec = ChainSpec::foundation();

        let state = genesis_beacon_state(&spec).unwrap();

        assert_eq!(state.processed_pow_receipt_root, spec.processed_pow_receipt_root);
        assert!(state.candidate_pow_receipt_roots.is_empty());
    }
}
