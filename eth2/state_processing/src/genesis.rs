use super::per_block_processing::{errors::BlockProcessingError, process_deposit};
use crate::common::DepositDataTree;
use tree_hash::TreeHash;
use types::DEPOSIT_TREE_DEPTH;
use types::*;

/// Initialize a `BeaconState` from genesis data.
///
/// Spec v0.11.1
// TODO: this is quite inefficient and we probably want to rethink how we do this
pub fn initialize_beacon_state_from_eth1<T: EthSpec>(
    eth1_block_hash: Hash256,
    eth1_timestamp: u64,
    deposits: Vec<Deposit>,
    spec: &ChainSpec,
) -> Result<BeaconState<T>, BlockProcessingError> {
    let genesis_time =
        eth1_timestamp - eth1_timestamp % spec.min_genesis_delay + 2 * spec.min_genesis_delay;
    let eth1_data = Eth1Data {
        // Temporary deposit root
        deposit_root: Hash256::zero(),
        deposit_count: deposits.len() as u64,
        block_hash: eth1_block_hash,
    };
    let mut state = BeaconState::new(genesis_time, eth1_data, spec);

    // Seed RANDAO with Eth1 entropy
    state.fill_randao_mixes_with(eth1_block_hash);

    let mut deposit_tree = DepositDataTree::create(&[], 0, DEPOSIT_TREE_DEPTH);

    for deposit in deposits.iter() {
        deposit_tree
            .push_leaf(deposit.data.tree_hash_root())
            .map_err(BlockProcessingError::MerkleTreeError)?;
        state.eth1_data.deposit_root = deposit_tree.root();
        process_deposit(&mut state, &deposit, spec, true)?;
    }

    process_activations(&mut state, spec);

    // Now that we have our validators, initialize the caches (including the committees)
    state.build_all_caches(spec)?;

    // Set genesis validators root for domain separation and chain versioning
    state.genesis_validators_root = state.update_validators_tree_hash_cache()?;

    Ok(state)
}

/// Determine whether a candidate genesis state is suitable for starting the chain.
///
/// Spec v0.11.1
pub fn is_valid_genesis_state<T: EthSpec>(state: &BeaconState<T>, spec: &ChainSpec) -> bool {
    state.genesis_time >= spec.min_genesis_time
        && state.get_active_validator_indices(T::genesis_epoch()).len() as u64
            >= spec.min_genesis_active_validator_count
}

/// Activate genesis validators, if their balance is acceptable.
///
/// Spec v0.11.1
pub fn process_activations<T: EthSpec>(state: &mut BeaconState<T>, spec: &ChainSpec) {
    for (index, validator) in state.validators.iter_mut().enumerate() {
        let balance = state.balances[index];
        validator.effective_balance = std::cmp::min(
            balance - balance % spec.effective_balance_increment,
            spec.max_effective_balance,
        );
        if validator.effective_balance == spec.max_effective_balance {
            validator.activation_eligibility_epoch = T::genesis_epoch();
            validator.activation_epoch = T::genesis_epoch();
        }
    }
}
