extern crate ssz_helpers;
extern crate validation;

use db::{
    ClientDB,
};
use db::stores::{
    BeaconBlockAtSlotError,
};
use self::validation::block_validation::{
    BeaconBlockValidationContext,
    SszBeaconBlockValidationError,
};
use super::{
    BeaconChain,
    BeaconChainError,
};
use self::ssz_helpers::ssz_beacon_block::{
    SszBeaconBlock,
    SszBeaconBlockError,
};
use std::sync::Arc;
use types::{
    BeaconBlock,
    Hash256,
};

pub use self::validation::block_validation::BeaconBlockStatus;

pub enum BeaconChainBlockError {
    UnknownCrystallizedState,
    UnknownActiveState,
    UnknownAttesterProposerMaps,
    NoParentHash,
    UnknownJustifiedBlock,
    BlockAlreadyKnown,
    BlockSlotLookupError(BeaconBlockAtSlotError),
    BadSsz(SszBeaconBlockError),
    BlockValidationError(SszBeaconBlockValidationError),
    DBError(String),
}

impl From<BeaconBlockAtSlotError> for BeaconChainBlockError {
    fn from(e: BeaconBlockAtSlotError) -> BeaconChainBlockError {
        BeaconChainBlockError::BlockSlotLookupError(e)
    }
}

impl From<SszBeaconBlockValidationError> for BeaconChainBlockError {
    fn from(e: SszBeaconBlockValidationError) -> BeaconChainBlockError {
        BeaconChainBlockError::BlockValidationError(e)
    }
}

pub type BlockStatusTriple = (BeaconBlockStatus, Hash256, BeaconBlock);


impl<T> BeaconChain<T>
    where T: ClientDB + Sized
{
    pub fn process_incoming_block(&self, ssz: &[u8], rx_time: u64)
        -> Result<BlockStatusTriple, BeaconChainBlockError>
    {
        /*
         * Generate a SszBlock to read directly from the serialized SSZ.
         */
        let block = SszBeaconBlock::from_slice(ssz)?;
        let block_hash = Hash256::from(&block.block_hash()[..]);

        /*
         * Load the crystallized state for this block from our caches.
         *
         * Fail if the crystallized state is unknown.
         */
        let cry_state_root = Hash256::from(block.cry_state_root());
        let cry_state = self.crystallized_states.get(&cry_state_root)
            .ok_or(BeaconChainBlockError::UnknownCrystallizedState)?;

        /*
         * Load the active state for this block from our caches.
         *
         * Fail if the active state is unknown.
         */
        let act_state_root = Hash256::from(block.act_state_root());
        let act_state = self.active_states.get(&act_state_root)
            .ok_or(BeaconChainBlockError::UnknownActiveState)?;

        /*
         * Learn the last justified slot from the crystallized state and load
         * the hash of this block from the database
         */
        let last_justified_slot = cry_state.last_justified_slot;
        let parent_block_hash = block.parent_hash()
            .ok_or(BeaconChainBlockError::NoParentHash)?;
        let (last_justified_block_hash, _) = self.store.block.block_at_slot(
            &parent_block_hash, last_justified_slot)?
            .ok_or(BeaconChainBlockError::UnknownJustifiedBlock)?;

        /*
         * Load the attester and proposer maps for the crystallized state.
         */
        let (attester_map, proposer_map) = self.attester_proposer_maps.get(&cry_state_root)
            .ok_or(BeaconChainBlockError::UnknownAttesterProposerMaps)?;

        let present_slot =  100;    // TODO: fix this

        /*
         * Build a block validation context to test the block against.
         */
        let validation_context = BeaconBlockValidationContext {
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
        };
        let (block_status, deserialized_block) = validation_context.validate_ssz_block(&block_hash, &block)?;
        match deserialized_block {
            Some(b) => Ok((block_status, block_hash, b)),
            None => Err(BeaconChainBlockError::BlockAlreadyKnown)
        }
    }
}

impl From<SszBeaconBlockError> for BeaconChainBlockError {
    fn from(e: SszBeaconBlockError) -> BeaconChainBlockError {
        BeaconChainBlockError::BadSsz(e)
    }
}
