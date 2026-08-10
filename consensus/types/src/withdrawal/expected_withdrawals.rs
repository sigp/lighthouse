use crate::Withdrawals;
use superstruct::superstruct;

#[superstruct(
    variants(Capella, Electra, Gloas, Heze),
    variant_attributes(derive(Debug, PartialEq, Clone))
)]
#[derive(Debug, PartialEq, Clone)]
pub struct ExpectedWithdrawals {
    pub withdrawals: Withdrawals,
    #[superstruct(only(Gloas, Heze), partial_getter(copy))]
    pub processed_builder_withdrawals_count: u64,
    #[superstruct(only(Electra, Gloas, Heze), partial_getter(copy))]
    pub processed_partial_withdrawals_count: u64,
    #[superstruct(only(Gloas, Heze), partial_getter(copy))]
    pub processed_builders_sweep_count: u64,
    #[superstruct(getter(copy))]
    pub processed_sweep_withdrawals_count: u64,
}

impl From<ExpectedWithdrawals> for Withdrawals {
    fn from(expected_withdrawals: ExpectedWithdrawals) -> Withdrawals {
        match expected_withdrawals {
            ExpectedWithdrawals::Capella(ew) => ew.withdrawals,
            ExpectedWithdrawals::Electra(ew) => ew.withdrawals,
            ExpectedWithdrawals::Gloas(ew) => ew.withdrawals,
            ExpectedWithdrawals::Heze(ew) => ew.withdrawals,
        }
    }
}
