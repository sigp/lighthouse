//! Per-checkpoint snapshot of validator balances used by the Fast Confirmation Rule.

use crate::Error;
use tracing::{debug, debug_span};
use types::{BeaconState, Checkpoint, EthSpec, RelativeEpoch};

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
        let _span = debug_span!("fcr_build_balance_source", epoch = %checkpoint.epoch).entered();

        let validator_count = state.validators().len();
        let mut effective_balances = Vec::with_capacity(validator_count);
        let mut slashed = Vec::with_capacity(validator_count);
        let mut total_active_balance = 0u64;

        let epoch = match relative_epoch {
            RelativeEpoch::Current => state.current_epoch(),
            RelativeEpoch::Previous => state.previous_epoch(),
            RelativeEpoch::Next => state
                .next_epoch()
                .map_err(|e| Error::CommitteeCache(format!("{e:?}")))?,
        };

        // Build effective balances for all active validators regardless of slashed status.
        // The spec's get_total_active_balance uses is_active_at without checking slashed.
        // Slashed filtering is applied separately where needed (e.g. get_block_support_between_slots).
        for validator in state.validators().iter() {
            slashed.push(validator.slashed);
            if validator.is_active_at(epoch) {
                effective_balances.push(validator.effective_balance);
                total_active_balance =
                    total_active_balance.saturating_add(validator.effective_balance);
            } else {
                effective_balances.push(0);
            }
        }

        debug!(
            validators = validator_count,
            active_balance = total_active_balance,
            epoch = %checkpoint.epoch,
            "FCR balance source built"
        );

        Ok(Self {
            checkpoint,
            total_active_balance,
            effective_balances,
            slashed,
        })
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
