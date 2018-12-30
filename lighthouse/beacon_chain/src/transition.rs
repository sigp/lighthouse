use super::BeaconChain;
use db::ClientDB;
use state_transition::{extend_active_state, StateTransitionError};
use types::{ActiveState, BeaconBlock, CrystallizedState, Hash256};

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB + Sized,
{
    pub(crate) fn transition_states(
        &self,
        act_state: &ActiveState,
        cry_state: &CrystallizedState,
        block: &BeaconBlock,
        block_hash: &Hash256,
    ) -> Result<(ActiveState, Option<CrystallizedState>), StateTransitionError> {
        let state_recalc_distance = block
            .slot
            .checked_sub(cry_state.last_state_recalculation_slot)
            .ok_or(StateTransitionError::BlockSlotBeforeRecalcSlot)?;

        if state_recalc_distance >= u64::from(self.spec.epoch_length) {
            panic!("Not implemented!")
        } else {
            let new_act_state = extend_active_state(act_state, block, block_hash)?;
            Ok((new_act_state, None))
        }
    }
}
