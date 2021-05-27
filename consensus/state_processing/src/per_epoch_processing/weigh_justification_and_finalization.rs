use crate::per_epoch_processing::Error;
use safe_arith::SafeArith;
use std::ops::Range;
use types::{BeaconState, Checkpoint, EthSpec};

/// Update the justified and finalized checkpoints for matching target attestations.
#[allow(clippy::if_same_then_else)] // For readability and consistency with spec.
pub fn weigh_justification_and_finalization<T: EthSpec>(
    state: &mut BeaconState<T>,
    total_active_balance: u64,
    previous_target_balance: u64,
    current_target_balance: u64,
) -> Result<(), Error> {
    let previous_epoch = state.previous_epoch();
    let current_epoch = state.current_epoch();

    let old_previous_justified_checkpoint = state.previous_justified_checkpoint();
    let old_current_justified_checkpoint = state.current_justified_checkpoint();

    // Process justifications
    *state.previous_justified_checkpoint_mut() = state.current_justified_checkpoint();
    state.justification_bits_mut().shift_up(1)?;

    if previous_target_balance.safe_mul(3)? >= total_active_balance.safe_mul(2)? {
        *state.current_justified_checkpoint_mut() = Checkpoint {
            epoch: previous_epoch,
            root: *state.get_block_root_at_epoch(previous_epoch)?,
        };
        state.justification_bits_mut().set(1, true)?;
    }
    // If the current epoch gets justified, fill the last bit.
    if current_target_balance.safe_mul(3)? >= total_active_balance.safe_mul(2)? {
        *state.current_justified_checkpoint_mut() = Checkpoint {
            epoch: current_epoch,
            root: *state.get_block_root_at_epoch(current_epoch)?,
        };
        state.justification_bits_mut().set(0, true)?;
    }

    let bits = state.justification_bits().clone();
    let all_bits_set = |range: Range<usize>| -> Result<bool, Error> {
        for i in range {
            if !bits.get(i).map_err(Error::InvalidJustificationBit)? {
                return Ok(false);
            }
        }
        Ok(true)
    };

    // The 2nd/3rd/4th most recent epochs are all justified, the 2nd using the 4th as source.
    if all_bits_set(1..4)? && old_previous_justified_checkpoint.epoch.safe_add(3)? == current_epoch
    {
        *state.finalized_checkpoint_mut() = old_previous_justified_checkpoint;
    }
    // The 2nd/3rd most recent epochs are both justified, the 2nd using the 3rd as source.
    if all_bits_set(1..3)? && old_previous_justified_checkpoint.epoch.safe_add(2)? == current_epoch
    {
        *state.finalized_checkpoint_mut() = old_previous_justified_checkpoint;
    }
    // The 1st/2nd/3rd most recent epochs are all justified, the 1st using the 3nd as source.
    if all_bits_set(0..3)? && old_current_justified_checkpoint.epoch.safe_add(2)? == current_epoch {
        *state.finalized_checkpoint_mut() = old_current_justified_checkpoint;
    }
    // The 1st/2nd most recent epochs are both justified, the 1st using the 2nd as source.
    if all_bits_set(0..2)? && old_current_justified_checkpoint.epoch.safe_add(1)? == current_epoch {
        *state.finalized_checkpoint_mut() = old_current_justified_checkpoint;
    }

    Ok(())
}
