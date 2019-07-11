use super::per_block_processing::{errors::BlockProcessingError, process_deposits};
use tree_hash::TreeHash;
use types::*;

pub enum GenesisError {
    BlockProcessingError(BlockProcessingError),
    BeaconStateError(BeaconStateError),
}

/// New genesis state
pub fn initialize_beacon_state_from_eth1<T: EthSpec>(
    eth1_block_hash: Hash256,
    eth1_timestamp: u64,
    deposits: Vec<Deposit>,
    spec: &ChainSpec,
) -> Result<BeaconState<T>, BlockProcessingError> {
    let genesis_time =
        eth1_timestamp - eth1_timestamp % spec.seconds_per_day + 2 * spec.seconds_per_day;
    let eth1_data = Eth1Data {
        // Temporary deposit root
        deposit_root: Hash256::zero(),
        deposit_count: deposits.len() as u64,
        block_hash: eth1_block_hash,
    };
    let mut state = BeaconState::new(genesis_time, eth1_data, spec);

    // Process deposits
    // TODO: merkle tree construction (needs tree hash impl for Lists)
    for (i, deposit) in deposits.iter().enumerate() {}

    Ok(state)
}

/* FIXME(freeze): fix this
/// Returns the genesis `BeaconState`
///
/// Spec v0.6.3
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
    for validator in &mut state.validators {
        if validator.effective_balance >= spec.max_effective_balance {
            validator.activation_eligibility_epoch = T::genesis_epoch();
            validator.activation_epoch = T::genesis_epoch();
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
*/

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
