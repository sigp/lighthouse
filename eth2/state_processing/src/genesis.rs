use super::per_block_processing::{errors::BlockProcessingError, process_deposit};
use crate::common::get_compact_committees_root;
use tree_hash::TreeHash;
use types::typenum::U4294967296;
use types::*;

/// Initialize a `BeaconState` from genesis data.
///
/// Spec v0.8.0
// TODO: this is quite inefficient and we probably want to rethink how we do this
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
    let leaves: Vec<_> = deposits
        .iter()
        .map(|deposit| deposit.data.clone())
        .collect();
    for (index, deposit) in deposits.into_iter().enumerate() {
        let deposit_data_list = VariableList::<_, U4294967296>::from(leaves[..=index].to_vec());
        state.eth1_data.deposit_root = Hash256::from_slice(&deposit_data_list.tree_hash_root());
        process_deposit(&mut state, &deposit, spec, true)?;
    }

    // Process activations
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

    // Now that we have our validators, initialize the caches (including the committees)
    state.build_all_caches(spec)?;

    // Populate active_index_roots and compact_committees_roots
    let indices_list = VariableList::<usize, T::ValidatorRegistryLimit>::from(
        state.get_active_validator_indices(T::genesis_epoch()),
    );
    let active_index_root = Hash256::from_slice(&indices_list.tree_hash_root());
    let committee_root = get_compact_committees_root(&state, RelativeEpoch::Current, spec)?;
    state.fill_active_index_roots_with(active_index_root);
    state.fill_compact_committees_roots_with(committee_root);

    Ok(state)
}

/// Determine whether a candidate genesis state is suitable for starting the chain.
///
/// Spec v0.8.1
pub fn is_valid_genesis_state<T: EthSpec>(state: &BeaconState<T>, spec: &ChainSpec) -> bool {
    state.genesis_time >= spec.min_genesis_time
        && state.get_active_validator_indices(T::genesis_epoch()).len() as u64
            >= spec.min_genesis_active_validator_count
}
