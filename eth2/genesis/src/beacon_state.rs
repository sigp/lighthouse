use types::{BeaconState, ChainSpec, Crosslink, Fork};
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

    let initial_crosslink = Crosslink {
        slot: spec.genesis_slot,
        shard_block_root: spec.zero_hash,
    };

    Ok(BeaconState {
        /*
         * Misc
         */
        slot: spec.genesis_slot,
        genesis_time: spec.genesis_time,
        fork_data: Fork {
            pre_fork_version: spec.genesis_fork_version,
            post_fork_version: spec.genesis_fork_version,
            fork_slot: spec.genesis_slot,
        },
        /*
         * Validator registry
         */
        validator_registry: spec.initial_validators.clone(),
        validator_balances: spec.initial_balances.clone(),
        validator_registry_update_slot: spec.genesis_slot,
        validator_registry_exit_count: 0,
        validator_registry_delta_chain_tip: spec.zero_hash,
        /*
         * Randomness and committees
         */
        latest_randao_mixes: vec![spec.zero_hash; spec.latest_randao_mixes_length as usize],
        latest_vdf_outputs: vec![
            spec.zero_hash;
            (spec.latest_randao_mixes_length / spec.epoch_length) as usize
        ],
        previous_epoch_start_shard: spec.genesis_start_shard,
        current_epoch_start_shard: spec.genesis_start_shard,
        previous_epoch_calculation_slot: spec.genesis_slot,
        current_epoch_calculation_slot: spec.genesis_slot,
        previous_epoch_randao_mix: spec.zero_hash,
        current_epoch_randao_mix: spec.zero_hash,
        /*
         * Custody challenges
         */
        custody_challenges: vec![],
        /*
         * Finality
         */
        previous_justified_slot: spec.genesis_slot,
        justified_slot: spec.genesis_slot,
        justification_bitfield: 0,
        finalized_slot: spec.genesis_slot,
        /*
         * Recent state
         */
        latest_crosslinks: vec![initial_crosslink; spec.shard_count as usize],
        latest_block_roots: vec![spec.zero_hash; spec.latest_block_roots_length as usize],
        latest_penalized_balances: vec![0; spec.latest_penalized_exit_length as usize],
        latest_attestations: vec![],
        batched_block_roots: vec![],
        /*
         * PoW receipt root
         */
        latest_eth1_data: spec.intial_eth1_data.clone(),
        eth1_data_votes: vec![],
    })
}

impl From<ValidatorAssignmentError> for Error {
    fn from(e: ValidatorAssignmentError) -> Error {
        Error::ValidationAssignmentError(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::Hash256;

    #[test]
    fn test_genesis_state() {
        let spec = ChainSpec::foundation();

        let state = genesis_beacon_state(&spec).unwrap();

        assert_eq!(
            state.validator_registry.len(),
            spec.initial_validators.len()
        );
    }

    #[test]
    fn test_genesis_state_misc() {
        let spec = ChainSpec::foundation();

        let state = genesis_beacon_state(&spec).unwrap();

        assert_eq!(state.slot, 0);
        assert_eq!(state.genesis_time, spec.genesis_time);
        assert_eq!(state.fork_data.pre_fork_version, 0);
        assert_eq!(state.fork_data.post_fork_version, 0);
        assert_eq!(state.fork_data.fork_slot, 0);
    }

    #[test]
    fn test_genesis_state_validators() {
        let spec = ChainSpec::foundation();

        let state = genesis_beacon_state(&spec).unwrap();

        assert_eq!(state.validator_registry, spec.initial_validators);
        assert_eq!(state.validator_balances, spec.initial_balances);
        assert!(state.validator_registry_update_slot == 0);
        assert!(state.validator_registry_exit_count == 0);
        assert_eq!(state.validator_registry_delta_chain_tip, Hash256::zero());
    }

    #[test]
    fn test_genesis_state_randomness_committees() {
        let spec = ChainSpec::foundation();

        let state = genesis_beacon_state(&spec).unwrap();

        // Array of size 8,192 each being zero_hash
        assert_eq!(state.latest_randao_mixes.len(), 8_192);
        for item in state.latest_randao_mixes.iter() {
            assert_eq!(*item, Hash256::zero());
        }

        // Array of size 8,192 each being a zero hash
        assert_eq!(state.latest_vdf_outputs.len(), (8_192 / 64));
        for item in state.latest_vdf_outputs.iter() {
            assert_eq!(*item, Hash256::zero());
        }

        // TODO: Check shard and committee shuffling requires solving issue:
        // https://github.com/sigp/lighthouse/issues/151

        // initial_shuffling = get_shuffling(Hash256::zero(), &state.validator_registry, 0, 0)
        // initial_shuffling = initial_shuffling.append(initial_shuffling.clone());
    }

    // Custody not implemented until Phase 1
    #[test]
    fn test_genesis_state_custody() {}

    #[test]
    fn test_genesis_state_finanilty() {
        let spec = ChainSpec::foundation();

        let state = genesis_beacon_state(&spec).unwrap();

        assert_eq!(state.previous_justified_slot, 0);
        assert_eq!(state.justified_slot, 0);
        assert_eq!(state.justification_bitfield, 0);
        assert_eq!(state.finalized_slot, 0);
    }

    #[test]
    fn test_genesis_state_recent_state() {
        let spec = ChainSpec::foundation();

        let state = genesis_beacon_state(&spec).unwrap();

        // Test latest_crosslinks
        assert_eq!(state.latest_crosslinks.len(), 1_024);
        for link in state.latest_crosslinks.iter() {
            assert_eq!(link.slot, 0);
            assert_eq!(link.shard_block_root, Hash256::zero());
        }

        // Test latest_block_roots
        assert_eq!(state.latest_block_roots.len(), 8_192);
        for block in state.latest_block_roots.iter() {
            assert_eq!(*block, Hash256::zero());
        }

        // Test latest_penalized_balances
        assert_eq!(state.latest_penalized_balances.len(), 8_192);
        for item in state.latest_penalized_balances.iter() {
            assert!(*item == 0);
        }

        // Test latest_attestations
        assert!(state.latest_attestations.is_empty());

        // batched_block_roots
        assert!(state.batched_block_roots.is_empty());
    }

    #[test]
    fn test_genesis_state_deposit_root() {
        let spec = ChainSpec::foundation();

        let state = genesis_beacon_state(&spec).unwrap();

        assert_eq!(&state.latest_eth1_data, &spec.intial_eth1_data);
        assert!(state.eth1_data_votes.is_empty());
    }
}
