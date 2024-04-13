use integer_sqrt::IntegerSquareRoot;
use safe_arith::{ArithError, SafeArith};
use types::*;

/// This type exists to avoid confusing `total_active_balance` with `sqrt_total_active_balance`,
/// since they are used in close proximity and have the same type (`u64`).
#[derive(Copy, Clone)]
pub struct SqrtTotalActiveBalance(u64);

impl SqrtTotalActiveBalance {
    pub fn new(total_active_balance: u64) -> Self {
        Self(total_active_balance.integer_sqrt())
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Returns the base reward for some validator.
pub fn get_base_reward(
    validator_effective_balance: u64,
    sqrt_total_active_balance: SqrtTotalActiveBalance,
    spec: &ChainSpec,
) -> Result<u64, ArithError> {
    validator_effective_balance
        .safe_mul(spec.base_reward_factor)?
        .safe_div(sqrt_total_active_balance.as_u64())?
        .safe_div(spec.base_rewards_per_epoch)
}
