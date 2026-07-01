//! Validator-balance snapshot used by the Fast Confirmation Rule.

use crate::Error;
use types::{BeaconState, Epoch, EthSpec, Hash256};

/// Snapshot of a validator set's effective balances for one epoch.
///
/// `dependent_root` (the block at the last slot of the previous epoch) is the chain-identity that
/// fixes this snapshot — two chains sharing it have the same view — and is used as the cache key.
#[derive(Clone, Debug)]
pub struct BalanceSourceData {
    pub dependent_root: Hash256,
    pub total_active_balance: u64,
    /// Effective balance per validator index. 0 for inactive.
    pub effective_balances: Vec<u64>,
    /// Used to filter support votes
    /// (spec: `get_block_support_between_slots` excludes slashed validators).
    pub slashed: Vec<bool>,
}

impl BalanceSourceData {
    /// Build a balance source for a single `epoch` in one pass over the validator set, tagged with
    /// the epoch's dependent root. Effective balance is counted for active validators regardless of
    /// slashed status (matching the spec's `get_total_active_balance`); `slashed` is recorded
    /// separately for the slashed-filtering used by `get_block_support_between_slots`. The total
    /// uses a saturating add — it is a sum of effective balances and cannot realistically overflow.
    pub(crate) fn for_epoch<E: EthSpec>(
        state: &BeaconState<E>,
        epoch: Epoch,
    ) -> Result<Self, Error> {
        let dependent_root = crate::dependent_root::<E>(state, epoch)?;
        let validators = state.validators();
        let mut effective_balances = Vec::with_capacity(validators.len());
        let mut slashed = Vec::with_capacity(validators.len());
        let mut total_active_balance = 0u64;

        for validator in validators.iter() {
            slashed.push(validator.slashed);
            if validator.is_active_at(epoch) {
                effective_balances.push(validator.effective_balance);
                total_active_balance =
                    total_active_balance.saturating_add(validator.effective_balance);
            } else {
                effective_balances.push(0);
            }
        }

        Ok(Self {
            dependent_root,
            total_active_balance,
            effective_balances,
            slashed,
        })
    }

    pub(crate) fn balance(&self, val_idx: usize) -> u64 {
        self.effective_balances.get(val_idx).copied().unwrap_or(0)
    }

    pub(crate) fn unslashed_and_active_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.effective_balances
            .iter()
            .enumerate()
            .filter_map(|(i, balance)| {
                (*balance > 0 && !self.slashed.get(i).copied().unwrap_or(false)).then_some(i)
            })
    }

    /// Return balance only if the validator is not slashed.
    /// Spec: `get_block_support_between_slots` excludes slashed validators.
    pub(crate) fn unslashed_balance(&self, val_idx: usize) -> u64 {
        if self.slashed.get(val_idx).copied().unwrap_or(false) {
            0
        } else {
            self.balance(val_idx)
        }
    }
}
