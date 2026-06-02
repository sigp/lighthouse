//! Per-checkpoint snapshot of validator balances used by the Fast Confirmation Rule.

use crate::Error;
use tracing::{debug, debug_span};
use types::{BeaconState, Checkpoint, Epoch, EthSpec, RelativeEpoch};

/// Snapshot of a checkpoint state's balances and committee assignments.
///
/// FCR needs two of these simultaneously: one for new confirmations (current epoch
/// observed justified) and one for reconfirmation at epoch boundaries (previous).
#[derive(Clone, Debug, Default)]
pub struct BalanceSourceData {
    pub checkpoint: Checkpoint,
    pub total_active_balance: u64,
    /// Effective balance per validator index. 0 for inactive.
    pub effective_balances: Vec<u64>,
    /// True if the validator has been slashed. Used to filter support votes
    /// (spec: `get_block_support_between_slots` excludes slashed validators).
    pub slashed: Vec<bool>,
}

/// Active-validator balances for a single epoch, produced by
/// [`BalanceSourceData::build_for_epochs`].
#[derive(Default)]
pub struct EpochBalances {
    /// Per-validator effective balance; `0` for validators not active at the epoch.
    pub effective_balances: Vec<u64>,
    /// Sum of `effective_balances` over validators active at the epoch.
    pub total_active_balance: u64,
}

impl BalanceSourceData {
    /// Build a `BalanceSourceData` from a beacon state.
    ///
    /// Extracts effective balances and committee slot assignments for the given epoch.
    /// The committee cache for `relative_epoch` must already be built on `state`.
    pub fn from_state<E: EthSpec>(
        state: &BeaconState<E>,
        checkpoint: Checkpoint,
        relative_epoch: RelativeEpoch,
    ) -> Result<Self, Error> {
        let epoch = relative_epoch.into_epoch(state.current_epoch());
        let (slashed, mut per_epoch) = Self::build_for_epochs(state, &[epoch]);
        let eb = per_epoch.pop().unwrap_or_default();
        Ok(Self::from_parts(
            checkpoint,
            eb.effective_balances,
            eb.total_active_balance,
            slashed,
        ))
    }

    /// Assemble a `BalanceSourceData` from already-computed parts (see `build_for_epochs`).
    pub fn from_parts(
        checkpoint: Checkpoint,
        effective_balances: Vec<u64>,
        total_active_balance: u64,
        slashed: Vec<bool>,
    ) -> Self {
        debug!(
            validators = effective_balances.len(),
            active_balance = total_active_balance,
            epoch = %checkpoint.epoch,
            "FCR balance source built"
        );
        Self {
            checkpoint,
            total_active_balance,
            effective_balances,
            slashed,
        }
    }

    /// Build the shared (epoch-independent) `slashed` bitvec and, for each requested epoch, the
    /// active-validator `effective_balances` vector and `total_active_balance`, in a **single**
    /// pass over the validator set.
    ///
    /// At an epoch boundary FCR rebuilds three balance sources (head, current, previous); they
    /// share the same state and differ only by epoch, so batching them here turns three full
    /// validator-set iterations into one. The per-validator computation is identical to building
    /// each source separately: effective balance is counted for active validators regardless of
    /// slashed status (matching the spec's `get_total_active_balance`), and `slashed` is recorded
    /// for the separate slashed-filtering used by `get_block_support_between_slots`.
    pub fn build_for_epochs<E: EthSpec>(
        state: &BeaconState<E>,
        epochs: &[Epoch],
    ) -> (Vec<bool>, Vec<EpochBalances>) {
        let _span = debug_span!("fcr_build_balance_source", epochs = epochs.len()).entered();

        let validator_count = state.validators().len();
        let mut slashed = Vec::with_capacity(validator_count);
        let mut per_epoch: Vec<EpochBalances> = epochs
            .iter()
            .map(|_| EpochBalances {
                effective_balances: Vec::with_capacity(validator_count),
                total_active_balance: 0,
            })
            .collect();

        for validator in state.validators().iter() {
            slashed.push(validator.slashed);
            let effective_balance = validator.effective_balance;
            for (i, &epoch) in epochs.iter().enumerate() {
                if validator.is_active_at(epoch) {
                    per_epoch[i].effective_balances.push(effective_balance);
                    per_epoch[i].total_active_balance = per_epoch[i]
                        .total_active_balance
                        .saturating_add(effective_balance);
                } else {
                    per_epoch[i].effective_balances.push(0);
                }
            }
        }

        (slashed, per_epoch)
    }

    pub(crate) fn balance(&self, val_idx: usize) -> u64 {
        self.effective_balances.get(val_idx).copied().unwrap_or(0)
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
