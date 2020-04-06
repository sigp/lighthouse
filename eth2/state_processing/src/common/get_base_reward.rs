use integer_sqrt::IntegerSquareRoot;
use types::*;

/// Returns the base reward for some validator.
///
/// Spec v0.11.1
pub fn get_base_reward<T: EthSpec>(
    state: &BeaconState<T>,
    index: usize,
    // Should be == get_total_active_balance(state, spec)
    total_active_balance: u64,
    spec: &ChainSpec,
) -> Result<u64, BeaconStateError> {
    if total_active_balance == 0 {
        Ok(0)
    } else {
        Ok(
            state.get_effective_balance(index, spec)? * spec.base_reward_factor
                / total_active_balance.integer_sqrt()
                / spec.base_rewards_per_epoch,
        )
    }
}
