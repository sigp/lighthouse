use crate::beacon_state::balance::Balance;
use crate::{BeaconState, BeaconStateError, ChainSpec, Epoch, EthSpec};
use arbitrary::Arbitrary;
use safe_arith::SafeArith;
use serde_derive::{Deserialize, Serialize};
use strum::{Display, EnumString, EnumVariantNames};

/// This cache keeps track of the accumulated target attestation balance for the current & previous
/// epochs. The cached values can be utilised by fork choice to calculate unrealized justification
/// and finalization instead of converting epoch participation arrays to balances for each block we
/// process.
#[derive(Default, Debug, PartialEq, Arbitrary, Clone)]
pub struct ProgressiveBalancesCache {
    inner: Option<Inner>,
}

#[derive(Debug, PartialEq, Arbitrary, Clone)]
struct Inner {
    pub current_epoch: Epoch,
    pub previous_epoch_target_attesting_balance: Balance,
    pub current_epoch_target_attesting_balance: Balance,
}

impl ProgressiveBalancesCache {
    pub fn initialize(
        &mut self,
        current_epoch: Epoch,
        previous_epoch_target_attesting_balance: Balance,
        current_epoch_target_attesting_balance: Balance,
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
        is_previous_epoch_target_attester: bool,
        is_current_epoch_target_attester: bool,
        effective_balance: u64,
    ) -> Result<(), BeaconStateError> {
        let cache = self.get_inner_mut()?;
        if is_previous_epoch_target_attester {
            cache
                .previous_epoch_target_attesting_balance
                .safe_sub_assign(effective_balance)?;
        }
        if is_current_epoch_target_attester {
            cache
                .current_epoch_target_attesting_balance
                .safe_sub_assign(effective_balance)?;
        }
        Ok(())
    }

    /// When a current epoch target attester has its effective balance changed, we adjust the
    /// its share of the target attesting balance in the cache.
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

    /// On epoch transition, the balance from current epoch is shifted to previous epoch, and the
    /// current epoch balance is reset to 0.
    pub fn on_epoch_transition(&mut self, spec: &ChainSpec) -> Result<(), BeaconStateError> {
        let cache = self.get_inner_mut()?;
        cache.current_epoch.safe_add_assign(1)?;
        cache.previous_epoch_target_attesting_balance =
            cache.current_epoch_target_attesting_balance;
        cache.current_epoch_target_attesting_balance =
            Balance::zero(spec.effective_balance_increment);
        Ok(())
    }

    pub fn previous_epoch_target_attesting_balance(&self) -> Result<u64, BeaconStateError> {
        Ok(self
            .get_inner()?
            .previous_epoch_target_attesting_balance
            .get())
    }

    pub fn current_epoch_target_attesting_balance(&self) -> Result<u64, BeaconStateError> {
        Ok(self
            .get_inner()?
            .current_epoch_target_attesting_balance
            .get())
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

#[derive(
    Debug, PartialEq, Eq, Clone, Copy, Deserialize, Serialize, Display, EnumString, EnumVariantNames,
)]
#[strum(serialize_all = "lowercase")]
pub enum ProgressiveBalancesMode {
    /// Disable the usage of progressive cache, and use the existing `ParticipationCache` calculation.
    Disabled,
    /// Enable the usage of progressive cache, with checks against the `ParticipationCache` and falls
    /// back to the existing calculation if there is a balance mismatch.
    Checked,
    /// Enable the usage of progressive cache, with checks against the `ParticipationCache`. Errors
    /// if there is a balance mismatch. Used in testing only.
    Strict,
    /// Enable the usage of progressive cache, with no comparative checks against the
    /// `ParticipationCache`. This is fast but an experimental mode, use with caution.
    Fast,
}

impl ProgressiveBalancesMode {
    pub fn perform_comparative_checks(&self) -> bool {
        match self {
            Self::Disabled | Self::Fast => false,
            Self::Checked | Self::Strict => true,
        }
    }
}

/// `ProgressiveBalancesCache` is only enabled from `Altair` as it requires `ParticipationCache`.
pub fn is_progressive_balances_enabled<E: EthSpec>(state: &BeaconState<E>) -> bool {
    match state {
        BeaconState::Base(_) => false,
        BeaconState::Altair(_) | BeaconState::Merge(_) | BeaconState::Capella(_) => true,
    }
}
