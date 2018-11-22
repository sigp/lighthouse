use super::transition::StateTransitionError;
use super::BeaconChain;
use db::{ClientDB, DBError};
use ssz_helpers::ssz_beacon_block::{SszBeaconBlock, SszBeaconBlockError};
use types::{
    ActiveState, AttestationRecord, BeaconBlock, CrystallizedState, Hash256, SpecialRecord,
};

#[derive(Debug, PartialEq)]
pub enum BlockProductionError {
    InvalidHeadBlockIndex,
    UnableToLoadAncestor,
    UnableToLoadCrystallizedState,
    UnableToLoadActiveState,
    DeserializationFailed(SszBeaconBlockError),
    StateTransitionError(StateTransitionError),
    DBError(String),
}

impl<T> BeaconChain<T>
where
    T: ClientDB + Sized,
{
    pub fn produce_canonical_block(
        &self,
        slot: u64,
        randao_reveal: Hash256,
        pow_chain_reference: Hash256,
        attestations: Vec<AttestationRecord>,
        specials: Vec<SpecialRecord>,
    ) -> Result<BeaconBlock, BlockProductionError> {
        /*
         * If there exists some known canonical block, use that block and its state roots to
         * produce the new block.
         *
         * If no canonical block exists (e.g., because its the first time this client has been
         * turned on, or genesis just happened), use `0x0` for both state roots and the parent
         * hash.
         */
        let (parent_hash, active_state_root, crystallized_state_root) =
            match self.canonical_head_block_hash {
                None => (Hash256::zero(), Hash256::zero(), Hash256::zero()),
                Some(i) => {
                    let parent_hash = self
                        .head_block_hashes
                        .get(i)
                        .ok_or(BlockProductionError::InvalidHeadBlockIndex)?;
                    let (active_state_root, crystallized_state_root) = {
                        let ssz = self
                            .store
                            .block
                            .get_serialized_block(&parent_hash[..])?
                            .ok_or(BlockProductionError::UnableToLoadAncestor)?;
                        let block = SszBeaconBlock::from_slice(&ssz)?;
                        (block.act_state_root(), block.cry_state_root())
                    };
                    (
                        parent_hash,
                        Hash256::from(active_state_root),
                        Hash256::from(crystallized_state_root),
                    )
                }
            };
        self.produce_block(
            slot,
            parent_hash,
            active_state_root,
            crystallized_state_root,
            randao_reveal,
            pow_chain_reference,
            attestations,
            specials,
        )
    }

    /// Produce a new block "on top of" some existing active and crystallied states.
    ///
    /// This method can be used for genesis (i.e., the first block once the genesis states are
    /// known).
    pub fn produce_block(
        &self,
        slot: u64,
        parent_hash: &Hash256,
        parent_active_state_root: &Hash256,
        parent_crystallized_state_root: &Hash256,
        randao_reveal: Hash256,
        pow_chain_reference: Hash256,
        attestations: Vec<AttestationRecord>,
        specials: Vec<SpecialRecord>,
    ) -> Result<BeaconBlock, BlockProductionError> {
        /*
         * Generate a new block with the state roots set to zero.
         */
        let mut new_block = BeaconBlock {
            slot,
            randao_reveal,
            pow_chain_reference,
            ancestor_hashes: self.build_skip_list()?,
            active_state_root: Hash256::zero(), // Defaulted for now.
            crystallized_state_root: Hash256::zero(), // Defaulted for now.
            attestations: attestations,
            specials: specials,
        };

        /*
         * Generate the states for this new block.
         */
        let (active_state_root, crystallized_state_root) = {
            /*
             * Load the active and crystallized states for the parent block.
             */
            let parent_active_state = self
                .active_state_from_root(&parent_active_state_root)
                .ok_or(BlockProductionError::UnableToLoadActiveState)?;
            let parent_crystallized_state = self
                .crystallized_state_from_root(&parent_crystallized_state_root)
                .ok_or(BlockProductionError::UnableToLoadCrystallizedState)?;

            /*
             * Perform a state transition based upon this block and the parent's states.
             */
            let (active_state, crystallized_state_option) =
                self.transition_states(parent_active_state, parent_crystallized_state, &new_block)?;
            /*
             * Derive the crystallized state root hash from either the newly produced state or the
             * previous one.
             */
            let crystallized_state_hash = match crystallized_state_option {
                Some(new_crystallized_state) => new_crystallized_state.canonical_root(),
                None => parent_crystallized_state.canonical_root(),
            };

            (active_state.canonical_root(), crystallized_state_hash)
        };

        /*
         * Set the root hashes from the new states.
         */
        new_block.active_state_root = active_state_root;
        new_block.crystallized_state_root = crystallized_state_root;

        Ok(new_block)
    }

    pub fn build_skip_list(
        &self,
        parent_hash: &Hash256,
    ) -> Result<Vec<Hash256>, BlockProductionError> {
        // TODO: fix this; it is a stub.
        Ok(vec![Hash256::zero(); 32])
    }
}

impl From<StateTransitionError> for BlockProductionError {
    fn from(e: StateTransitionError) -> Self {
        BlockProductionError::StateTransitionError(e)
    }
}

impl From<DBError> for BlockProductionError {
    fn from(e: DBError) -> Self {
        BlockProductionError::DBError(e.message)
    }
}

impl From<SszBeaconBlockError> for BlockProductionError {
    fn from(e: SszBeaconBlockError) -> Self {
        BlockProductionError::DeserializationFailed(e)
    }
}
