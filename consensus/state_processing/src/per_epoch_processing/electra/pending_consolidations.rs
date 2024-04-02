use crate::common::{decrease_balance, increase_balance};
use crate::EpochProcessingError;
use types::{BeaconState, ChainSpec, EthSpec};

pub fn process_pending_consolidations<T: EthSpec>(
    state: &mut BeaconState<T>,
    spec: &ChainSpec,
) -> Result<(), EpochProcessingError> {
    let mut next_pending_consolidation = 0;
    // move pending consolidations to a mutable vector
    let mut pending_consolidations = Vec::from(std::mem::replace(
        state.pending_consolidations_mut()?,
        Vec::new().into(),
    ));

    let current_epoch = state.current_epoch();
    for pending_consolidation in pending_consolidations.iter() {
        let source_validator = state.get_validator(pending_consolidation.source_index as usize)?;
        if source_validator.slashed {
            next_pending_consolidation += 1;
            continue;
        }
        if source_validator.withdrawable_epoch > current_epoch {
            break;
        }
        // Churn any target excess active balance of target and raise its max
        state.switch_to_compounding_validator(pending_consolidation.target_index as usize, spec)?;
        // Move active balance to target. Excess balance is withdrawable.
        let active_balance = state.get_active_balance(pending_consolidation.source_index, spec)?;
        decrease_balance(
            state,
            pending_consolidation.source_index as usize,
            active_balance,
        )?;
        increase_balance(
            state,
            pending_consolidation.target_index as usize,
            active_balance,
        )?;
        next_pending_consolidation += 1;
    }
    pending_consolidations.drain(0..next_pending_consolidation);
    *state.pending_consolidations_mut()? = pending_consolidations.into();

    Ok(())
}
