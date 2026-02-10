use crate::{EthSpec, Withdrawals};
use superstruct::superstruct;

#[superstruct(
    variants(Capella, Electra, Gloas),
    variant_attributes(derive(Debug, PartialEq, Clone))
)]
#[derive(Debug, PartialEq, Clone)]
pub struct ExpectedWithdrawals<E: EthSpec> {
    pub withdrawals: Withdrawals<E>,
    #[superstruct(only(Gloas), partial_getter(copy))]
    pub processed_builder_withdrawals_count: u64,
    #[superstruct(only(Electra, Gloas), partial_getter(copy))]
    pub processed_partial_withdrawals_count: u64,
    #[superstruct(only(Gloas), partial_getter(copy))]
    pub processed_builders_sweep_count: u64,
    #[superstruct(getter(copy))]
    pub processed_sweep_withdrawals_count: u64,
}

impl<E: EthSpec> From<ExpectedWithdrawals<E>> for Withdrawals<E> {
    fn from(expected_withdrawals: ExpectedWithdrawals<E>) -> Withdrawals<E> {
        match expected_withdrawals {
            ExpectedWithdrawals::Capella(ew) => ew.withdrawals,
            ExpectedWithdrawals::Electra(ew) => ew.withdrawals,
            ExpectedWithdrawals::Gloas(ew) => ew.withdrawals,
        }
    }
}
