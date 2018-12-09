use super::block_context::BlockValidationContextError;
use super::state_transition::StateTransitionError;
use super::BeaconChain;
use db::{ClientDB, DBError};
use naive_fork_choice::{naive_fork_choice, ForkChoiceError};
use ssz_helpers::ssz_beacon_block::{SszBeaconBlock, SszBeaconBlockError};
use types::Hash256;

pub enum BlockProcessingOutcome {
    BlockAlreadyKnown,
    NewCanonicalBlock,
    NewReorgBlock,
    NewForkBlock,
}

pub enum BlockProcessingError {
    ParentBlockNotFound,
    ActiveStateRootInvalid,
    CrystallizedStateRootInvalid,
    NoHeadHashes,
    UnknownParentHash,
    ForkChoiceFailed(ForkChoiceError),
    ContextGenerationFailed(BlockValidationContextError),
    DeserializationFailed(SszBeaconBlockError),
    ValidationFailed,
    StateTransitionFailed(StateTransitionError),
    DBError(String),
}

impl<T> BeaconChain<T>
where
    T: ClientDB + Sized,
{
    pub fn process_block(
        &mut self,
        ssz: &[u8],
        present_slot: u64,
    ) -> Result<(BlockProcessingOutcome, Hash256), BlockProcessingError> {
        /*
         * Generate a SszBlock to read directly from the serialized SSZ.
         */
        let ssz_block = SszBeaconBlock::from_slice(ssz)?;
        let block_hash = Hash256::from(&ssz_block.block_hash()[..]);

        /*
         * If this block is already known, return immediately and indicate the the block is
         * known. Don't attempt to deserialize the block.
         */
        if self.store.block.block_exists(&block_hash)? {
            return Ok((BlockProcessingOutcome::BlockAlreadyKnown, block_hash));
        }

        /*
         * Determine the hash of the blocks parent
         */
        let parent_hash = ssz_block
            .parent_hash()
            .ok_or(BlockProcessingError::UnknownParentHash)?;

        /*
         * Load the parent block from the database and create an SszBeaconBlock for reading it.
         */
        let parent_block_ssz_bytes = self
            .store
            .block
            .get_serialized_block(&parent_hash[..])?
            .ok_or(BlockProcessingError::ParentBlockNotFound)?;
        let parent_ssz_block = SszBeaconBlock::from_slice(&parent_block_ssz_bytes)?;

        /*
         * Generate the context in which to validate this block.
         */
        let validation_context =
            self.block_validation_context(&ssz_block, &parent_ssz_block, present_slot)?;

        /*
         * Validate the block against the context, checking signatures, parent_hashes, etc.
         */
        let block = validation_context.validate_ssz_block(&ssz_block)?;

        let (new_act_state, new_cry_state_option) = {
            /*
             * Load the states from memory.
             *
             * Note: this is the second time we load these, the first was in
             * `block_validation_context`. Theres an opportunity for some opimisation here.
             * It was left out because it made the code more cumbersome.
             */
            let act_state = self
                .active_states
                .get(&block.active_state_root)
                .ok_or(BlockValidationContextError::UnknownActiveState)?;
            let cry_state = self
                .crystallized_states
                .get(&block.crystallized_state_root)
                .ok_or(BlockValidationContextError::UnknownCrystallizedState)?;

            self.transition_states(act_state, cry_state, &block, &block_hash)?
        };

        /*
         * Calculate the new active state root and ensure the block state root matches.
         */
        let new_act_state_root = new_act_state.canonical_root();
        if new_act_state_root != block.active_state_root {
            return Err(BlockProcessingError::ActiveStateRootInvalid);
        }

        /*
         * Determine the crystallized state root and ensure the block state root matches.
         *
         * If a new crystallized state was created, store it in memory.
         */
        let (new_cry_state_root, cry_state_transitioned) = match new_cry_state_option {
            None => {
                /*
                 * A new crystallized state was not created, therefore the
                 * `crystallized_state_root` of this block must match its parent.
                 */
                if Hash256::from(parent_ssz_block.cry_state_root()) != block.crystallized_state_root
                {
                    return Err(BlockProcessingError::ActiveStateRootInvalid);
                }
                // Return the old root
                (block.crystallized_state_root, false)
            }
            Some(new_cry_state) => {
                /*
                 * A new crystallized state was created. Check to ensure the crystallized
                 * state root in the block is the same as the calculated on this node.
                 */
                let cry_state_root = new_cry_state.canonical_root();
                if cry_state_root != block.crystallized_state_root {
                    return Err(BlockProcessingError::ActiveStateRootInvalid);
                }
                /*
                 * Store the new crystallized state in memory.
                 */
                self.crystallized_states
                    .insert(cry_state_root, new_cry_state);
                // Return the new root
                (cry_state_root, true)
            }
        };

        /*
         * Store the new block as a leaf in the block tree.
         */
        let mut new_head_block_hashes = self.head_block_hashes.clone();
        let new_parent_head_hash_index = match new_head_block_hashes
            .iter()
            .position(|x| *x == Hash256::from(parent_hash))
        {
            Some(i) => {
                new_head_block_hashes[i] = block_hash.clone();
                i
            }
            None => {
                new_head_block_hashes.push(block_hash.clone());
                new_head_block_hashes.len() - 1
            }
        };

        /*
         * Store the new block in the database.
         */
        self.store
            .block
            .put_serialized_block(&block_hash[..], ssz_block.block_ssz())?;

        /*
         * Store the active state in memory.
         */
        self.active_states.insert(new_act_state_root, new_act_state);

        let new_canonical_head_block_hash_index =
            match naive_fork_choice(&self.head_block_hashes, self.store.block.clone())? {
                None => {
                    /*
                     * Fork choice failed, therefore the block, active state and crystallized state
                     * can be removed from storage (i.e., forgotten).
                     */
                    if cry_state_transitioned {
                        // A new crystallized state was generated, so it should be deleted.
                        self.crystallized_states.remove(&new_cry_state_root);
                    }
                    self.active_states.remove(&new_act_state_root);
                    self.store.block.delete_block(&block_hash[..])?;
                    return Err(BlockProcessingError::NoHeadHashes);
                }
                Some(i) => i,
            };

        if new_canonical_head_block_hash_index != self.canonical_head_block_hash {
            /*
             * The block caused a re-org (switch of chains).
             */
            Ok((BlockProcessingOutcome::NewReorgBlock, block_hash))
        } else {
            /*
             * The block did not cause a re-org.
             */
            if new_parent_head_hash_index == self.canonical_head_block_hash {
                Ok((BlockProcessingOutcome::NewCanonicalBlock, block_hash))
            } else {
                Ok((BlockProcessingOutcome::NewForkBlock, block_hash))
            }
        }
    }
}

impl From<BlockValidationContextError> for BlockProcessingError {
    fn from(e: BlockValidationContextError) -> Self {
        BlockProcessingError::ContextGenerationFailed(e)
    }
}

impl From<SszBeaconBlockError> for BlockProcessingError {
    fn from(e: SszBeaconBlockError) -> Self {
        BlockProcessingError::DeserializationFailed(e)
    }
}

impl From<DBError> for BlockProcessingError {
    fn from(e: DBError) -> Self {
        BlockProcessingError::DBError(e.message)
    }
}

impl From<ForkChoiceError> for BlockProcessingError {
    fn from(e: ForkChoiceError) -> Self {
        BlockProcessingError::ForkChoiceFailed(e)
    }
}

impl From<StateTransitionError> for BlockProcessingError {
    fn from(e: StateTransitionError) -> Self {
        BlockProcessingError::StateTransitionFailed(e)
    }
}
