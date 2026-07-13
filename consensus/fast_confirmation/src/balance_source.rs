//! Validator-balance snapshot used by the Fast Confirmation Rule.

use crate::Error;
use safe_arith::SafeArith;
use types::{BeaconState, Epoch, EthSpec, Hash256};

/// Cache key identifying the validator-set view a `BalanceSourceData` was built from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BalanceSourceKey {
    /// No slashings have been processed in the `epoch` (`state.slashings[epoch % E] == 0`): the
    /// epoch's boundary root (block at the last slot of the previous epoch) pins the effective
    /// balances, activation set and slashed flags for the whole epoch.
    NoSlashings {
        epoch_boundary_root: Hash256,
        epoch: Epoch,
    },
    /// At least one slashing has been processed in the epoch. Slashings flip `Validator.slashed`
    /// mid-epoch without moving the epoch boundary root, so the snapshot is keyed on its own block
    /// root instead and every head change rebuilds it for the rest of the epoch.
    SlashingsPresent { head_block_root: Hash256 },
}

impl BalanceSourceKey {
    /// Create a key for a specific `block_root` and its state.
    pub(crate) fn compute<E: EthSpec>(
        state: &BeaconState<E>,
        block_root: Hash256,
    ) -> Result<Self, Error> {
        let epoch = state.current_epoch();
        let epoch_slashings = state
            .get_slashings(epoch)
            .map_err(|e| Error::SlashingsOutOfBounds(format!("slashings lookup: {e:?}")))?;
        if epoch_slashings > 0 {
            Ok(Self::SlashingsPresent {
                head_block_root: block_root,
            })
        } else {
            Ok(Self::NoSlashings {
                epoch_boundary_root: get_epoch_boundary_root::<E>(state)?,
                epoch,
            })
        }
    }
}

/// Snapshot of a validator set's effective balances for one epoch.
///
/// The [`BalanceSourceKey`] fixes this snapshot — two chains sharing it have the same view — and
/// is used as the cache key.
#[derive(Clone, Debug)]
pub struct BalanceSourceData {
    pub key: BalanceSourceKey,
    pub total_active_balance: u64,
    /// Effective balance per validator index. 0 for inactive.
    pub effective_balances: Vec<u64>,
    /// Used to filter support votes
    /// (spec: `get_block_support_between_slots` excludes slashed validators).
    pub slashed: Vec<bool>,
}

impl BalanceSourceData {
    /// Create a balance source for `state` at its current epoch.
    ///
    /// The state must be pulled up to the desired epoch prior to calling this function.
    pub(crate) fn new<E: EthSpec>(
        state: &BeaconState<E>,
        block_root: Hash256,
    ) -> Result<Self, Error> {
        let current_epoch = state.current_epoch();
        let key = BalanceSourceKey::compute(state, block_root)?;
        let validators = state.validators();
        let mut effective_balances = Vec::with_capacity(validators.len());
        let mut slashed = Vec::with_capacity(validators.len());
        let mut total_active_balance = 0u64;

        for validator in validators.iter() {
            slashed.push(validator.slashed);
            if validator.is_active_at(current_epoch) {
                effective_balances.push(validator.effective_balance);
                total_active_balance =
                    total_active_balance.saturating_add(validator.effective_balance);
            } else {
                effective_balances.push(0);
            }
        }

        Ok(Self {
            key,
            total_active_balance,
            effective_balances,
            slashed,
        })
    }

    pub(crate) fn balance(&self, val_idx: usize) -> u64 {
        self.effective_balances.get(val_idx).copied().unwrap_or(0)
    }

    pub(crate) fn unslashed_and_active_indices(&self) -> impl Iterator<Item = (usize, u64)> + '_ {
        self.effective_balances
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(i, balance)| {
                (balance > 0 && !self.slashed.get(i).copied().unwrap_or(false))
                    .then_some((i, balance))
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

/// Block root at the last slot of the previous epoch.
///
/// Used to identify the balance source fields of the `validator` registry in the absence of
/// slashings.
fn get_epoch_boundary_root<E: EthSpec>(state: &BeaconState<E>) -> Result<Hash256, Error> {
    if state.current_epoch() == 0 {
        return Ok(Hash256::ZERO);
    }
    let slot = state
        .current_epoch()
        .start_slot(E::slots_per_epoch())
        .safe_sub(1)?;
    Ok(*state
        .get_block_root(slot)
        .map_err(|e| Error::BlockRootsOutOfBounds(format!("{e:?}")))?)
}
