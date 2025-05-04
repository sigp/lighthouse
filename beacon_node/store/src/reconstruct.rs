//! Implementation of historic state reconstruction (given complete block history).
use crate::StoreError as Error;
use crate::{HotColdDB, ItemStore};
use types::{BeaconState, EthSpec, Hash256, Slot};
use parking_lot::RwLock;
use std::sync::Arc;

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> HotColdDB<E, Hot, Cold> {
    pub fn reconstruct_historic_states(&self) -> Result<(), Error> {
        let anchor_info = self.get_anchor_info()?;
        if anchor_info.state_lower_limit >= anchor_info.state_upper_limit {
            return Ok(());
        }

        let mut state = self.get_state(&anchor_info.state_upper_limit, None)?
            .ok_or(Error::MissingStateToReconstruct(anchor_info.state_upper_limit))?;

        let mut state_root = self.get_state_root(&anchor_info.state_upper_limit)?
            .ok_or(Error::MissingStateRootToReconstruct(anchor_info.state_upper_limit))?;

        for slot in (anchor_info.state_lower_limit..anchor_info.state_upper_limit).rev() {
            let block_root = self.get_block_root(slot)?
                .ok_or(Error::MissingBlockToReconstruct(slot))?;

            let block = self.get_block(&block_root)?
                .ok_or(Error::MissingBlockToReconstruct(slot))?;

            state = state.clone_with(slot, &block, state_root)?;
            state_root = block.state_root();

            self.store_historic_state(&state, state_root)?;
        }

        Ok(())
    }

    fn store_historic_state(&self, state: &BeaconState<E>, state_root: Hash256) -> Result<(), Error> {
        let mut ops = vec![];
        self.store_state(state_root, state, None, &mut ops)?;
        self.do_atomically(ops)
    }
}
