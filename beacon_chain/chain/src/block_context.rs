use db::{
    ClientDB,
};
use db::stores::{
    BeaconBlockAtSlotError,
};
use validation::block_validation::{
    BeaconBlockValidationContext,
};
use super::{
    BeaconChain,
};
use ssz_helpers::ssz_beacon_block::{
    SszBeaconBlock,
};
use std::sync::Arc;
use types::{
    Hash256,
};

pub enum BlockValidationContextError {
    UnknownCrystallizedState,
    UnknownActiveState,
    UnknownAttesterProposerMaps,
    NoParentHash,
    UnknownJustifiedBlock,
    BlockAlreadyKnown,
    BlockSlotLookupError(BeaconBlockAtSlotError),
}

impl From<BeaconBlockAtSlotError> for BlockValidationContextError {
    fn from(e: BeaconBlockAtSlotError) -> BlockValidationContextError {
        BlockValidationContextError::BlockSlotLookupError(e)
    }
}

impl<T> BeaconChain<T>
    where T: ClientDB + Sized
{
    pub(crate) fn block_validation_context(&self, block: &SszBeaconBlock, present_slot: u64)
        -> Result<BeaconBlockValidationContext<T>, BlockValidationContextError>
    {
        /*
         * Load the crystallized state for this block from our caches.
         *
         * Fail if the crystallized state is unknown.
         */
        let cry_state_root = Hash256::from(block.cry_state_root());
        let cry_state = self.crystallized_states.get(&cry_state_root)
            .ok_or(BlockValidationContextError::UnknownCrystallizedState)?;

        /*
         * Load the active state for this block from our caches.
         *
         * Fail if the active state is unknown.
         */
        let act_state_root = Hash256::from(block.act_state_root());
        let act_state = self.active_states.get(&act_state_root)
            .ok_or(BlockValidationContextError::UnknownActiveState)?;

        /*
         * Learn the last justified slot from the crystallized state and load
         * the hash of this block from the database
         */
        let last_justified_slot = cry_state.last_justified_slot;
        let parent_block_hash = block.parent_hash()
            .ok_or(BlockValidationContextError::NoParentHash)?;
        let (last_justified_block_hash, _) = self.store.block.block_at_slot(
            &parent_block_hash, last_justified_slot)?
            .ok_or(BlockValidationContextError::UnknownJustifiedBlock)?;

        /*
         * Load the attester and proposer maps for the crystallized state.
         */
        let (attester_map, proposer_map) = self.attester_proposer_maps.get(&cry_state_root)
            .ok_or(BlockValidationContextError::UnknownAttesterProposerMaps)?;

        Ok(BeaconBlockValidationContext {
            present_slot,
            cycle_length: self.config.cycle_length,
            last_justified_slot: cry_state.last_justified_slot,
            last_justified_block_hash: Hash256::from(&last_justified_block_hash[..]),
            last_finalized_slot: self.last_finalized_slot,
            recent_block_hashes: Arc::new(act_state.recent_block_hashes.clone()),
            proposer_map: proposer_map.clone(),
            attester_map: attester_map.clone(),
            block_store: self.store.block.clone(),
            validator_store: self.store.validator.clone(),
            pow_store: self.store.pow_chain.clone(),
        })
    }
}
