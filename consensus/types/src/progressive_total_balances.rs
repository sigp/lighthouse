use crate::{BeaconStateError, Epoch};
use arbitrary::Arbitrary;
use safe_arith::SafeArith;

#[derive(Default, Debug, PartialEq, Arbitrary, Clone)]
pub struct ProgressiveTotalBalances {
    inner: Option<Inner>,
}

#[derive(Debug, PartialEq, Arbitrary, Clone)]
struct Inner {
    pub current_epoch: Epoch,
    pub previous_epoch_target_attesting_balance: u64,
    pub current_epoch_target_attesting_balance: u64,
}

impl ProgressiveTotalBalances {
    pub fn initialize(
        &mut self,
        current_epoch: Epoch,
        previous_epoch_target_attesting_balance: u64,
        current_epoch_target_attesting_balance: u64,
    ) {
        self.inner = Some(Inner {
            current_epoch,
            previous_epoch_target_attesting_balance,
            current_epoch_target_attesting_balance,
        });
    }

    pub fn is_initialized(&self) -> bool {
        self.inner.is_some()
    }

    /// When a new target attestation has been processed, we update the cached
    /// `current_epoch_target_attesting_balance` to include the validator effective balance.
    /// If the epoch is neither the current epoch nor the previous epoch, an error is returned.
    pub fn on_new_target_attestation(
        &mut self,
        epoch: Epoch,
        validator_effective_balance: u64,
    ) -> Result<(), BeaconStateError> {
        let cache = self.get_inner_mut()?;

        if epoch == cache.current_epoch {
            cache
                .current_epoch_target_attesting_balance
                .safe_add_assign(validator_effective_balance)?;
        } else if epoch.safe_add(1)? == cache.current_epoch {
            cache
                .previous_epoch_target_attesting_balance
                .safe_add_assign(validator_effective_balance)?;
        } else {
            return Err(BeaconStateError::ProgressiveBalancesCacheInconsistent);
        }

        Ok(())
    }

    /// When a validator is slashed, we reduce the `current_epoch_target_attesting_balance` by the
    /// validator's effective balance to exclude the validator weight.
    pub fn on_slashing(
        &mut self,
        is_current_epoch_target_attester: bool,
        effective_balance: u64,
    ) -> Result<(), BeaconStateError> {
        let cache = self.get_inner_mut()?;
        if is_current_epoch_target_attester {
            cache
                .current_epoch_target_attesting_balance
                .safe_sub_assign(effective_balance)?;
        }
        Ok(())
    }

    pub fn on_effective_balance_change(
        &mut self,
        is_current_epoch_target_attester: bool,
        old_effective_balance: u64,
        new_effective_balance: u64,
    ) -> Result<(), BeaconStateError> {
        let cache = self.get_inner_mut()?;
        if is_current_epoch_target_attester {
            if new_effective_balance > old_effective_balance {
                cache
                    .current_epoch_target_attesting_balance
                    .safe_add_assign(new_effective_balance.safe_sub(old_effective_balance)?)?;
            } else {
                cache
                    .current_epoch_target_attesting_balance
                    .safe_sub_assign(old_effective_balance.safe_sub(new_effective_balance)?)?;
            }
        }
        Ok(())
    }

    pub fn on_epoch_transition(&mut self) -> Result<(), BeaconStateError> {
        let cache = self.get_inner_mut()?;
        cache.current_epoch.safe_add_assign(1)?;
        cache.previous_epoch_target_attesting_balance =
            cache.current_epoch_target_attesting_balance;
        cache.current_epoch_target_attesting_balance = 0;
        Ok(())
    }

    pub fn previous_epoch_target_attesting_balance(&self) -> Result<u64, BeaconStateError> {
        Ok(self.get_inner()?.previous_epoch_target_attesting_balance)
    }

    pub fn current_epoch_target_attesting_balance(&self) -> Result<u64, BeaconStateError> {
        Ok(self.get_inner()?.current_epoch_target_attesting_balance)
    }

    fn get_inner_mut(&mut self) -> Result<&mut Inner, BeaconStateError> {
        self.inner
            .as_mut()
            .ok_or(BeaconStateError::ProgressiveBalancesCacheNotInitialized)
    }

    fn get_inner(&self) -> Result<&Inner, BeaconStateError> {
        self.inner
            .as_ref()
            .ok_or(BeaconStateError::ProgressiveBalancesCacheNotInitialized)
    }
}
