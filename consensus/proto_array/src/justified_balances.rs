use safe_arith::{ArithError, SafeArith};
use types::{BeaconState, Epoch, EthSpec, Validator};

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
}

impl JustifiedBalances {
    pub fn from_justified_state<T: EthSpec>(state: &BeaconState<T>) -> Result<Self, ArithError> {
        Self::from_justified_components(state.current_epoch(), &mut state.validators().iter())
    }

    /// Instantiates `Self` and returns a list of all slashed validator indices
    /// in `state`, without performing any additional iterations over the
    /// validator set.
    pub fn from_justified_state_with_equivocating_indices<T: EthSpec>(
        state: &BeaconState<T>,
    ) -> Result<(Self, Vec<u64>), ArithError> {
        let mut equivocating_indices = vec![];

        let mut iter = state.validators().iter().enumerate().map(|(i, validator)| {
            if validator.slashed {
                equivocating_indices.push(i as u64);
            }
            validator
        });

        let justified_balances = Self::from_justified_components(state.current_epoch(), &mut iter)?;

        // Ensure that the entirety of the iterator has been consumed. This is a
        // paranoid check to defend against modifications to
        // `Self::from_justified_changes` that might result in the `validators`
        // iterator not visiting all validators.
        iter.all(|_| true);

        Ok((justified_balances, equivocating_indices))
    }

    /// A generic method for generating `Self` from an iterator over the
    /// validator set.
    fn from_justified_components<'a, I>(
        current_epoch: Epoch,
        validators: &mut I,
    ) -> Result<Self, ArithError>
    where
        I: Iterator<Item = &'a Validator>,
    {
        let mut total_effective_balance = 0u64;
        let mut num_active_validators = 0u64;

        let effective_balances = validators
            .map(|validator| {
                if validator.is_active_at(current_epoch) {
                    total_effective_balance.safe_add_assign(validator.effective_balance)?;
                    num_active_validators.safe_add_assign(1)?;

                    Ok(validator.effective_balance)
                } else {
                    Ok(0)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            effective_balances,
            total_effective_balance,
            num_active_validators,
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
        })
    }
}
