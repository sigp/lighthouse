use integer_sqrt::IntegerSquareRoot;
use safe_arith::SafeArith;
use types::*;

/// Returns the base reward for some validator.
pub fn get_base_reward<T: EthSpec>(
    state: &BeaconState<T>,
    index: usize,
    // Should be == get_total_active_balance(state, spec)
    total_active_balance: u64,
    spec: &ChainSpec,
) -> Result<u64, BeaconStateError> {
    state
        .get_effective_balance(index)?
        .safe_mul(spec.base_reward_factor)?
        .safe_div(total_active_balance.integer_sqrt())?
        .safe_div(spec.base_rewards_per_epoch)
        .map_err(Into::into)
}
