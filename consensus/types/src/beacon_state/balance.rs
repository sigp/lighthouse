use arbitrary::Arbitrary;
use safe_arith::{ArithError, SafeArith};

/// A balance which will never be below the specified `minimum`.
///
/// This is an effort to ensure the `EFFECTIVE_BALANCE_INCREMENT` minimum is always respected.
#[derive(PartialEq, Debug, Clone, Copy, Arbitrary)]
pub struct Balance {
    raw: u64,
    minimum: u64,
}

impl Balance {
    /// Initialize the balance to `0`, or the given `minimum`.
    pub fn zero(minimum: u64) -> Self {
        Self { raw: 0, minimum }
    }

    /// Returns the balance with respect to the initialization `minimum`.
    pub fn get(&self) -> u64 {
        std::cmp::max(self.raw, self.minimum)
    }

    /// Add-assign to the balance.
    pub fn safe_add_assign(&mut self, other: u64) -> Result<(), ArithError> {
        self.raw.safe_add_assign(other)
    }

    /// Sub-assign to the balance.
    pub fn safe_sub_assign(&mut self, other: u64) -> Result<(), ArithError> {
        self.raw.safe_sub_assign(other)
    }
}
