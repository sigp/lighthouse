use super::BeaconChain;
use db::ClientDB;
use state_transition::extend_active_state;
use types::{ActiveState, BeaconBlock, CrystallizedState};

pub use state_transition::StateTransitionError;

impl<T> BeaconChain<T>
where
    T: ClientDB + Sized,
{
    pub(crate) fn transition_states(
        &self,
        act_state: &ActiveState,
        cry_state: &CrystallizedState,
        block: &BeaconBlock,
    ) -> Result<(ActiveState, Option<CrystallizedState>), StateTransitionError> {
        let state_recalc_distance = block
            .slot
            .checked_sub(cry_state.last_state_recalculation_slot)
            .ok_or(StateTransitionError::BlockSlotBeforeRecalcSlot)?;

        if state_recalc_distance >= u64::from(self.config.cycle_length) {
            panic!("Crystallized state transitions are not implemented!")
        } else {
            let parent_hash = block
                .parent_hash()
                .ok_or(StateTransitionError::InvalidParentHashes)?;

            let new_act_state = extend_active_state(
                act_state,
                &block.attestations,
                &block.specials,
                &parent_hash,
                &block.randao_reveal,
            )?;
            Ok((new_act_state, None))
        }
    }
}
