use integer_sqrt::IntegerSquareRoot;
use safe_arith::{ArithError, SafeArith};
use types::*;

/// This type exists to avoid confusing `total_active_balance` with `base_reward_per_increment`,
/// since they are used in close proximity and the same type (`u64`).
#[derive(Copy, Clone)]
pub struct BaseRewardPerIncrement(u64);

impl BaseRewardPerIncrement {
    pub fn new(total_active_balance: u64, spec: &ChainSpec) -> Result<Self, ArithError> {
        get_base_reward_per_increment(total_active_balance, spec).map(Self)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Returns the base reward for some validator.
///
/// The function has a different interface to the spec since it accepts the
/// `base_reward_per_increment` without computing it each time. Avoiding the re computation has
/// shown to be a significant optimisation.
///
/// Spec v1.1.0
pub fn get_base_reward(
    validator_effective_balance: u64,
    base_reward_per_increment: BaseRewardPerIncrement,
    spec: &ChainSpec,
) -> Result<u64, Error> {
    validator_effective_balance
        .safe_div(spec.effective_balance_increment)?
        .safe_mul(base_reward_per_increment.as_u64())
        .map_err(Into::into)
}

/// Returns the base reward for some validator.
///
/// Spec v1.1.0
fn get_base_reward_per_increment(
    total_active_balance: u64,
    spec: &ChainSpec,
) -> Result<u64, ArithError> {
    spec.effective_balance_increment
        .safe_mul(spec.base_reward_factor)?
        .safe_div(total_active_balance.integer_sqrt())
}
