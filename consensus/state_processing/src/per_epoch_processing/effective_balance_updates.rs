use super::errors::EpochProcessingError;
use crate::per_epoch_processing::altair::ParticipationCache;
use safe_arith::SafeArith;
use types::beacon_state::BeaconState;
use types::chain_spec::ChainSpec;
use types::{BeaconStateError, EthSpec, ProgressiveBalancesCache};

pub fn process_effective_balance_updates<T: EthSpec>(
    state: &mut BeaconState<T>,
    maybe_participation_cache: Option<&ParticipationCache>,
    spec: &ChainSpec,
) -> Result<(), EpochProcessingError> {
    let hysteresis_increment = spec
        .effective_balance_increment
        .safe_div(spec.hysteresis_quotient)?;
    let downward_threshold = hysteresis_increment.safe_mul(spec.hysteresis_downward_multiplier)?;
    let upward_threshold = hysteresis_increment.safe_mul(spec.hysteresis_upward_multiplier)?;
    let (validators, balances, progressive_balances_cache) =
        state.validators_and_balances_and_progressive_balances_mut();
    for (index, validator) in validators.iter_mut().enumerate() {
        let balance = balances
            .get(index)
            .copied()
            .ok_or(BeaconStateError::BalancesOutOfBounds(index))?;

        if balance.safe_add(downward_threshold)? < validator.effective_balance
            || validator.effective_balance.safe_add(upward_threshold)? < balance
        {
            let old_effective_balance = validator.effective_balance;
            let new_effective_balance = std::cmp::min(
                balance.safe_sub(balance.safe_rem(spec.effective_balance_increment)?)?,
                spec.max_effective_balance,
            );

            if let Some(participation_cache) = maybe_participation_cache {
                update_progressive_balances(
                    participation_cache,
                    progressive_balances_cache,
                    index,
                    old_effective_balance,
                    new_effective_balance,
                )?;
            }

            validator.effective_balance = new_effective_balance;
        }
    }
    Ok(())
}

fn update_progressive_balances(
    participation_cache: &ParticipationCache,
    progressive_balances_cache: &mut ProgressiveBalancesCache,
    index: usize,
    old_effective_balance: u64,
    new_effective_balance: u64,
) -> Result<(), EpochProcessingError> {
    if old_effective_balance != new_effective_balance {
        let is_current_epoch_target_attester =
            participation_cache.is_current_epoch_timely_target_attester(index)?;
        progressive_balances_cache.on_effective_balance_change(
            is_current_epoch_target_attester,
            old_effective_balance,
            new_effective_balance,
        )?;
    }
    Ok(())
}
