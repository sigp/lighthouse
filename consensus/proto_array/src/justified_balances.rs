use std::collections::BTreeMap;

use safe_arith::{ArithError, SafeArith};
use types::{BeaconState, EthSpec};

#[derive(Debug, PartialEq, Clone, Default)]
pub struct JustifiedBalances {
    /// The effective balances for every validator in a given justified state.
    ///
    /// Any validator who is not active in the epoch of the justified state is assigned a balance of
    /// zero.
    pub effective_balances: Vec<u64>,
    /// The sum of `self.effective_balances`.
    pub total_effective_balance: u64,
    /// The number of active validators included in `self.effective_balances`.
    pub num_active_validators: u64,
    /// A mapping from a slashed validator index to its effective balance active at the current
    /// epoch.
    pub slashed_balances: BTreeMap<u64, u64>,
}

impl JustifiedBalances {
    pub fn from_justified_state<E: EthSpec>(state: &BeaconState<E>) -> Result<Self, ArithError> {
        let current_epoch = state.current_epoch();
        let mut total_effective_balance = 0u64;
        let mut num_active_validators = 0u64;
        let mut slashed_balances = BTreeMap::new();

        let effective_balances = state
            .validators()
            .iter()
            .enumerate()
            .map(|(i, validator)| {
                if !validator.slashed && validator.is_active_at(current_epoch) {
                    total_effective_balance.safe_add_assign(validator.effective_balance)?;
                    num_active_validators.safe_add_assign(1)?;

                    Ok(validator.effective_balance)
                } else {
                    if validator.slashed && validator.is_active_at(current_epoch) {
                        slashed_balances.insert(i as u64, validator.effective_balance);
                    }
                    Ok(0)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            effective_balances,
            total_effective_balance,
            num_active_validators,
            slashed_balances,
        })
    }

    pub fn from_effective_balances(effective_balances: Vec<u64>) -> Result<Self, ArithError> {
        let mut total_effective_balance = 0;
        let mut num_active_validators = 0;

        for &balance in &effective_balances {
            if balance != 0 {
                total_effective_balance.safe_add_assign(balance)?;
                num_active_validators.safe_add_assign(1)?;
            }
        }

        Ok(Self {
            effective_balances,
            total_effective_balance,
            num_active_validators,
            slashed_balances: BTreeMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{ChainSpec, Epoch, MinimalEthSpec, Validator};

    type E = MinimalEthSpec;

    fn push_validator(
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
        effective_balance: u64,
        slashed: bool,
        activation_epoch: Epoch,
    ) {
        state
            .validators_mut()
            .push(Validator {
                effective_balance,
                slashed,
                activation_epoch,
                exit_epoch: spec.far_future_epoch,
                withdrawable_epoch: spec.far_future_epoch,
                ..Default::default()
            })
            .unwrap();
    }

    #[test]
    fn from_justified_state_handles_slashed_and_inactive_validators() {
        let spec = E::default_spec();
        let mut state: BeaconState<E> = BeaconState::new(0, <_>::default(), &spec);
        let epoch = state.current_epoch();

        push_validator(&mut state, &spec, 32_000_000_000, false, epoch);
        push_validator(&mut state, &spec, 31_000_000_000, true, epoch);
        push_validator(
            &mut state,
            &spec,
            30_000_000_000,
            false,
            spec.far_future_epoch,
        );
        push_validator(
            &mut state,
            &spec,
            29_000_000_000,
            true,
            spec.far_future_epoch,
        );

        let justified_balances = JustifiedBalances::from_justified_state(&state).unwrap();

        assert_eq!(
            justified_balances.effective_balances,
            vec![32_000_000_000, 0, 0, 0]
        );
        assert_eq!(justified_balances.total_effective_balance, 32_000_000_000);
        assert_eq!(justified_balances.num_active_validators, 1);
        assert_eq!(
            justified_balances.slashed_balances,
            BTreeMap::from([(1, 31_000_000_000)])
        );
    }

    #[test]
    fn from_effective_balances_has_empty_slashed_balances() {
        let justified_balances =
            JustifiedBalances::from_effective_balances(vec![32_000_000_000, 0, 31_000_000_000])
                .unwrap();

        assert_eq!(justified_balances.total_effective_balance, 63_000_000_000);
        assert_eq!(justified_balances.num_active_validators, 2);
        assert!(justified_balances.slashed_balances.is_empty());
    }
}
