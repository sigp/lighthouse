use super::per_block_processing::{errors::BlockProcessingError, process_deposits};
use tree_hash::TreeHash;
use types::*;

pub enum GenesisError {
    BlockProcessingError(BlockProcessingError),
    BeaconStateError(BeaconStateError),
}

/// Returns the genesis `BeaconState`
///
/// Spec v0.6.1
pub fn get_genesis_beacon_state<T: EthSpec>(
    genesis_validator_deposits: &[Deposit],
    genesis_time: u64,
    genesis_eth1_data: Eth1Data,
    spec: &ChainSpec,
) -> Result<BeaconState<T>, BlockProcessingError> {
    // Get the genesis `BeaconState`
    let mut state = BeaconState::genesis(genesis_time, genesis_eth1_data, spec);

    // Process genesis deposits.
    process_deposits(&mut state, genesis_validator_deposits, spec)?;

    // Process genesis activations.
    for (i, validator) in state.validator_registry.iter_mut().enumerate() {
        if validator.effective_balance >= spec.max_effective_balance {
            validator.activation_eligibility_epoch = spec.genesis_epoch;
            validator.activation_epoch = spec.genesis_epoch;
        }
    }

    // Ensure the current epoch cache is built.
    state.build_committee_cache(RelativeEpoch::Current, spec)?;

    // Set all the active index roots to be the genesis active index root.
    let active_validator_indices = state
        .get_cached_active_validator_indices(RelativeEpoch::Current)?
        .to_vec();
    let genesis_active_index_root = Hash256::from_slice(&active_validator_indices.tree_hash_root());
    state.fill_active_index_roots_with(genesis_active_index_root);

    Ok(state)
}

impl From<BlockProcessingError> for GenesisError {
    fn from(e: BlockProcessingError) -> GenesisError {
        GenesisError::BlockProcessingError(e)
    }
}

impl From<BeaconStateError> for GenesisError {
    fn from(e: BeaconStateError) -> GenesisError {
        GenesisError::BeaconStateError(e)
    }
}
