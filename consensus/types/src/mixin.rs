use crate::beacon_state::{BalancesMut, Error, ValidatorsMut};
use crate::{Unsigned, Validator};

pub trait GetValidatorMut {
    fn get_validator(&self, index: usize) -> Result<&Validator, Error>;

    fn get_validator_mut(&mut self, index: usize) -> Result<&mut Validator, Error>;
}

impl<'a, N: Unsigned> GetValidatorMut for ValidatorsMut<'a, N> {
    fn get_validator(&self, index: usize) -> Result<&Validator, Error> {
        self.get(index).ok_or(Error::UnknownValidator(index))
    }

    fn get_validator_mut(&mut self, index: usize) -> Result<&mut Validator, Error> {
        self.get_mut(index).ok_or(Error::UnknownValidator(index))
    }
}

pub trait GetBalanceMut {
    fn get_balance(&self, index: usize) -> Result<u64, Error>;

    fn get_balance_mut(&mut self, index: usize) -> Result<&mut u64, Error>;
}

impl<'a, N: Unsigned> GetBalanceMut for BalancesMut<'a, N> {
    fn get_balance(&self, index: usize) -> Result<u64, Error> {
        self.get(index)
            .copied()
            .ok_or(Error::BalancesOutOfBounds(index))
    }

    fn get_balance_mut(&mut self, index: usize) -> Result<&mut u64, Error> {
        self.get_mut(index).ok_or(Error::BalancesOutOfBounds(index))
    }
}
