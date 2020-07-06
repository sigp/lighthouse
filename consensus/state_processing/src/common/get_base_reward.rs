use integer_sqrt::IntegerSquareRoot;
use safe_arith::SafeArith;
use types::*;

/// Returns the base reward for some validator.
///
/// Spec v0.12.1
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
        Ok(state
            .get_effective_balance(index, spec)?
            .safe_mul(spec.base_reward_factor)?
            .safe_div(total_active_balance.integer_sqrt())?
            .safe_div(spec.base_rewards_per_epoch)?)
    }
}
