use super::per_block_processing::{errors::BlockProcessingError, process_deposits};
use tree_hash::TreeHash;
use types::*;

pub enum GenesisError {
    BlockProcessingError(BlockProcessingError),
    BeaconStateError(BeaconStateError),
}

/// Returns the genesis `BeaconState`
///
/// Spec v0.5.1
pub fn get_genesis_state<T: EthSpec>(
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
    for i in 0..state.validator_registry.len() {
        if state.get_effective_balance(i, spec)? >= spec.max_deposit_amount {
            state.validator_registry[i].activation_epoch = spec.genesis_epoch;
        }
    }

    // Ensure the current epoch cache is built.
    state.build_epoch_cache(RelativeEpoch::Current, spec)?;

    // Set all the active index roots to be the genesis active index root.
    let active_validator_indices = state
        .get_cached_active_validator_indices(RelativeEpoch::Current, spec)?
        .to_vec();
    let genesis_active_index_root = Hash256::from_slice(&active_validator_indices.tree_hash_root());
    state.fill_active_index_roots_with(genesis_active_index_root);

    // Generate the current shuffling seed.
    state.current_shuffling_seed = state.generate_seed(spec.genesis_epoch, spec)?;

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
