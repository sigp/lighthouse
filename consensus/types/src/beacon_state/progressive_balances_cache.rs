use crate::beacon_state::balance::Balance;
use crate::{
    consts::altair::{
        NUM_FLAG_INDICES, TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX,
        TIMELY_TARGET_FLAG_INDEX,
    },
    BeaconState, BeaconStateError, ChainSpec, Epoch, EthSpec, ParticipationFlags,
};
use arbitrary::Arbitrary;
use safe_arith::SafeArith;

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
    pub previous_epoch_cache: EpochTotalBalances,
    pub current_epoch_cache: EpochTotalBalances,
}

/// Caches the participation values for one epoch (either the previous or current).
#[derive(PartialEq, Debug, Clone, Arbitrary)]
pub struct EpochTotalBalances {
    /// Stores the sum of the balances for all validators in `self.unslashed_participating_indices`
    /// for all flags in `NUM_FLAG_INDICES`.
    ///
    /// A flag balance is only incremented if a validator is in that flag set.
    pub total_flag_balances: [Balance; NUM_FLAG_INDICES],
}

impl EpochTotalBalances {
    pub fn new(spec: &ChainSpec) -> Self {
        let zero_balance = Balance::zero(spec.effective_balance_increment);

        Self {
            total_flag_balances: [zero_balance; NUM_FLAG_INDICES],
        }
    }

    /// Returns the total balance of attesters who have `flag_index` set.
    pub fn total_flag_balance(&self, flag_index: usize) -> Result<u64, BeaconStateError> {
        self.total_flag_balances
            .get(flag_index)
            .map(Balance::get)
            .ok_or(BeaconStateError::InvalidFlagIndex(flag_index))
    }

    /// Returns the raw total balance of attesters who have `flag_index` set.
    pub fn total_flag_balance_raw(&self, flag_index: usize) -> Result<Balance, BeaconStateError> {
        self.total_flag_balances
            .get(flag_index)
            .copied()
            .ok_or(BeaconStateError::InvalidFlagIndex(flag_index))
    }

    pub fn on_new_attestation(
        &mut self,
        is_slashed: bool,
        flag_index: usize,
        validator_effective_balance: u64,
    ) -> Result<(), BeaconStateError> {
        if is_slashed {
            return Ok(());
        }
        let balance = self
            .total_flag_balances
            .get_mut(flag_index)
            .ok_or(BeaconStateError::InvalidFlagIndex(flag_index))?;
        balance.safe_add_assign(validator_effective_balance)?;
        Ok(())
    }

    pub fn on_slashing(
        &mut self,
        participation_flags: ParticipationFlags,
        validator_effective_balance: u64,
    ) -> Result<(), BeaconStateError> {
        for flag_index in 0..NUM_FLAG_INDICES {
            if participation_flags.has_flag(flag_index)? {
                self.total_flag_balances
                    .get_mut(flag_index)
                    .ok_or(BeaconStateError::InvalidFlagIndex(flag_index))?
                    .safe_sub_assign(validator_effective_balance)?;
            }
        }
        Ok(())
    }

    pub fn on_effective_balance_change(
        &mut self,
        is_slashed: bool,
        current_epoch_participation_flags: ParticipationFlags,
        old_effective_balance: u64,
        new_effective_balance: u64,
    ) -> Result<(), BeaconStateError> {
        // If the validator is slashed then we should not update the effective balance, because this
        // validator's effective balance has already been removed from the totals.
        if is_slashed {
            return Ok(());
        }
        for flag_index in 0..NUM_FLAG_INDICES {
            if current_epoch_participation_flags.has_flag(flag_index)? {
                let total = self
                    .total_flag_balances
                    .get_mut(flag_index)
                    .ok_or(BeaconStateError::InvalidFlagIndex(flag_index))?;
                if new_effective_balance > old_effective_balance {
                    total
                        .safe_add_assign(new_effective_balance.safe_sub(old_effective_balance)?)?;
                } else {
                    total
                        .safe_sub_assign(old_effective_balance.safe_sub(new_effective_balance)?)?;
                }
            }
        }
        Ok(())
    }
}

impl ProgressiveBalancesCache {
    pub fn initialize(
        &mut self,
        current_epoch: Epoch,
        previous_epoch_cache: EpochTotalBalances,
        current_epoch_cache: EpochTotalBalances,
    ) {
        self.inner = Some(Inner {
            current_epoch,
            previous_epoch_cache,
            current_epoch_cache,
        });
    }

    pub fn is_initialized(&self) -> bool {
        self.inner.is_some()
    }

    pub fn is_initialized_at(&self, epoch: Epoch) -> bool {
        self.inner
            .as_ref()
            .map_or(false, |inner| inner.current_epoch == epoch)
    }

    /// When a new target attestation has been processed, we update the cached
    /// `current_epoch_target_attesting_balance` to include the validator effective balance.
    /// If the epoch is neither the current epoch nor the previous epoch, an error is returned.
    pub fn on_new_attestation(
        &mut self,
        epoch: Epoch,
        is_slashed: bool,
        flag_index: usize,
        validator_effective_balance: u64,
    ) -> Result<(), BeaconStateError> {
        let cache = self.get_inner_mut()?;

        if epoch == cache.current_epoch {
            cache.current_epoch_cache.on_new_attestation(
                is_slashed,
                flag_index,
                validator_effective_balance,
            )?;
        } else if epoch.safe_add(1)? == cache.current_epoch {
            cache.previous_epoch_cache.on_new_attestation(
                is_slashed,
                flag_index,
                validator_effective_balance,
            )?;
        } else {
            return Err(BeaconStateError::ProgressiveBalancesCacheInconsistent);
        }

        Ok(())
    }

    /// When a validator is slashed, we reduce the `current_epoch_target_attesting_balance` by the
    /// validator's effective balance to exclude the validator weight.
    pub fn on_slashing(
        &mut self,
        previous_epoch_participation: ParticipationFlags,
        current_epoch_participation: ParticipationFlags,
        effective_balance: u64,
    ) -> Result<(), BeaconStateError> {
        let cache = self.get_inner_mut()?;
        cache
            .previous_epoch_cache
            .on_slashing(previous_epoch_participation, effective_balance)?;
        cache
            .current_epoch_cache
            .on_slashing(current_epoch_participation, effective_balance)?;
        Ok(())
    }

    /// When a current epoch target attester has its effective balance changed, we adjust the
    /// its share of the target attesting balance in the cache.
    pub fn on_effective_balance_change(
        &mut self,
        is_slashed: bool,
        current_epoch_participation: ParticipationFlags,
        old_effective_balance: u64,
        new_effective_balance: u64,
    ) -> Result<(), BeaconStateError> {
        let cache = self.get_inner_mut()?;
        cache.current_epoch_cache.on_effective_balance_change(
            is_slashed,
            current_epoch_participation,
            old_effective_balance,
            new_effective_balance,
        )?;
        Ok(())
    }

    /// On epoch transition, the balance from current epoch is shifted to previous epoch, and the
    /// current epoch balance is reset to 0.
    pub fn on_epoch_transition(&mut self, spec: &ChainSpec) -> Result<(), BeaconStateError> {
        let cache = self.get_inner_mut()?;
        cache.current_epoch.safe_add_assign(1)?;
        cache.previous_epoch_cache = std::mem::replace(
            &mut cache.current_epoch_cache,
            EpochTotalBalances::new(spec),
        );
        Ok(())
    }

    pub fn previous_epoch_flag_attesting_balance(
        &self,
        flag_index: usize,
    ) -> Result<u64, BeaconStateError> {
        self.get_inner()?
            .previous_epoch_cache
            .total_flag_balance(flag_index)
    }

    pub fn current_epoch_flag_attesting_balance(
        &self,
        flag_index: usize,
    ) -> Result<u64, BeaconStateError> {
        self.get_inner()?
            .current_epoch_cache
            .total_flag_balance(flag_index)
    }

    pub fn previous_epoch_source_attesting_balance(&self) -> Result<u64, BeaconStateError> {
        self.previous_epoch_flag_attesting_balance(TIMELY_SOURCE_FLAG_INDEX)
    }

    pub fn previous_epoch_target_attesting_balance(&self) -> Result<u64, BeaconStateError> {
        self.previous_epoch_flag_attesting_balance(TIMELY_TARGET_FLAG_INDEX)
    }

    pub fn previous_epoch_head_attesting_balance(&self) -> Result<u64, BeaconStateError> {
        self.previous_epoch_flag_attesting_balance(TIMELY_HEAD_FLAG_INDEX)
    }

    pub fn current_epoch_source_attesting_balance(&self) -> Result<u64, BeaconStateError> {
        self.current_epoch_flag_attesting_balance(TIMELY_SOURCE_FLAG_INDEX)
    }

    pub fn current_epoch_target_attesting_balance(&self) -> Result<u64, BeaconStateError> {
        self.current_epoch_flag_attesting_balance(TIMELY_TARGET_FLAG_INDEX)
    }

    pub fn current_epoch_head_attesting_balance(&self) -> Result<u64, BeaconStateError> {
        self.current_epoch_flag_attesting_balance(TIMELY_HEAD_FLAG_INDEX)
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

/// `ProgressiveBalancesCache` is only enabled from `Altair` as it uses Altair-specific logic.
pub fn is_progressive_balances_enabled<E: EthSpec>(state: &BeaconState<E>) -> bool {
    match state {
        BeaconState::Base(_) => false,
        BeaconState::Altair(_)
        | BeaconState::Bellatrix(_)
        | BeaconState::Capella(_)
        | BeaconState::Deneb(_)
        | BeaconState::Electra(_)
        | BeaconState::EIP7732(_) => true,
    }
}
