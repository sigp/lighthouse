use integer_sqrt::IntegerSquareRoot;
use safe_arith::{ArithError, SafeArith};
use types::*;

/// Returns the base reward for some validator.
///
/// Spec v1.1.0
pub fn get_base_reward<T: EthSpec>(
    state: &BeaconState<T>,
    index: usize,
    // Should be == get_total_active_balance(state, spec)
    total_active_balance: u64,
    spec: &ChainSpec,
) -> Result<u64, Error> {
    state
        .get_effective_balance(index)?
        .safe_div(spec.effective_balance_increment)?
        .safe_mul(get_base_reward_per_increment(total_active_balance, spec)?)
        .map_err(Into::into)
}

/// Returns the base reward for some validator.
///
/// Spec v1.1.0
pub fn get_base_reward_per_increment(
    total_active_balance: u64,
    spec: &ChainSpec,
) -> Result<u64, ArithError> {
    spec.effective_balance_increment
        .safe_mul(spec.base_reward_factor)?
        .safe_div(total_active_balance.integer_sqrt())
}
