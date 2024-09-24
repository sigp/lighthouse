use super::errors::BlockProcessingError;
use super::get_expected_withdrawals;
use crate::common::decrease_balance;
use safe_arith::SafeArith;
use tree_hash::TreeHash;
use types::{AbstractExecPayload, BeaconState, ChainSpec, EthSpec, ExecPayload, List, Withdrawals};

fn process_withdrawals_common<E: EthSpec>(
    state: &mut BeaconState<E>,
    expected_withdrawals: Withdrawals<E>,
    partial_withdrawals_count: Option<usize>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    match state {
        BeaconState::Capella(_)
        | BeaconState::Deneb(_)
        | BeaconState::Electra(_)
        | BeaconState::EIP7732(_) => {
            for withdrawal in expected_withdrawals.iter() {
                decrease_balance(
                    state,
                    withdrawal.validator_index as usize,
                    withdrawal.amount,
                )?;
            }

            // Update pending partial withdrawals [New in Electra:EIP7251]
            if let Some(partial_withdrawals_count) = partial_withdrawals_count {
                // TODO(electra): Use efficient pop_front after milhouse release https://github.com/sigp/milhouse/pull/38
                let new_partial_withdrawals = state
                    .pending_partial_withdrawals()?
                    .iter_from(partial_withdrawals_count)?
                    .cloned()
                    .collect::<Vec<_>>();
                *state.pending_partial_withdrawals_mut()? = List::new(new_partial_withdrawals)?;
            }

            // Update the next withdrawal index if this block contained withdrawals
            if let Some(latest_withdrawal) = expected_withdrawals.last() {
                *state.next_withdrawal_index_mut()? = latest_withdrawal.index.safe_add(1)?;

                // Update the next validator index to start the next withdrawal sweep
                if expected_withdrawals.len() == E::max_withdrawals_per_payload() {
                    // Next sweep starts after the latest withdrawal's validator index
                    let next_validator_index = latest_withdrawal
                        .validator_index
                        .safe_add(1)?
                        .safe_rem(state.validators().len() as u64)?;
                    *state.next_withdrawal_validator_index_mut()? = next_validator_index;
                }
            }

            // Advance sweep by the max length of the sweep if there was not a full set of withdrawals
            if expected_withdrawals.len() != E::max_withdrawals_per_payload() {
                let next_validator_index = state
                    .next_withdrawal_validator_index()?
                    .safe_add(spec.max_validators_per_withdrawals_sweep)?
                    .safe_rem(state.validators().len() as u64)?;
                *state.next_withdrawal_validator_index_mut()? = next_validator_index;
            }

            Ok(())
        }
        // these shouldn't even be encountered but they're here for completeness
        BeaconState::Base(_) | BeaconState::Altair(_) | BeaconState::Bellatrix(_) => Ok(()),
    }
}

pub mod capella {
    use super::*;
    /// Apply withdrawals to the state.
    pub fn process_withdrawals<E: EthSpec, Payload: AbstractExecPayload<E>>(
        state: &mut BeaconState<E>,
        payload: Payload::Ref<'_>,
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        let (expected_withdrawals, partial_withdrawals_count) =
            get_expected_withdrawals(state, spec)?;

        let expected_root = expected_withdrawals.tree_hash_root();
        let withdrawals_root = payload.withdrawals_root()?;
        if expected_root != withdrawals_root {
            return Err(BlockProcessingError::WithdrawalsRootMismatch {
                expected: expected_root,
                found: withdrawals_root,
            });
        }

        process_withdrawals_common(state, expected_withdrawals, partial_withdrawals_count, spec)
    }
}

pub mod eip7732 {
    use super::*;
    /// Apply withdrawals to the state.
    pub fn process_withdrawals<E: EthSpec>(
        state: &mut BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<(), BlockProcessingError> {
        let (expected_withdrawals, partial_withdrawals_count) =
            get_expected_withdrawals(state, spec)?;
        process_withdrawals_common(state, expected_withdrawals, partial_withdrawals_count, spec)
    }
}
