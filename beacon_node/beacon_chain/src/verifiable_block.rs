use crate::{
    beacon_chain::BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT, BeaconChain, BeaconChainError,
    BeaconChainTypes, BeaconSnapshot,
};
use types::{Hash256, SignedBeaconBlock};

pub struct VerifiableBlock<T: BeaconChainTypes> {
    pub(crate) block: SignedBeaconBlock<T::EthSpec>,
    pub(crate) block_root: Option<Hash256>,
    /// The outer Option indicates whether not there has been an attempt to load the parent. The
    /// inner option indicates if the parent exists.
    pub(crate) parent: Option<Option<BeaconSnapshot<T::EthSpec>>>,
    pub(crate) proposal_signature_is_valid: Option<bool>,
    /// Note: this field does not indicate the validity of `block.body.deposits` signatures, they
    /// must be verified during `per_block_processing`.
    pub(crate) all_signatures_valid: Option<bool>,
}

impl<T: BeaconChainTypes> Into<VerifiableBlock<T>> for SignedBeaconBlock<T::EthSpec> {
    fn into(self) -> VerifiableBlock<T> {
        VerifiableBlock {
            block: self,
            block_root: None,
            parent: None,
            proposal_signature_is_valid: None,
            all_signatures_valid: None,
        }
    }
}

impl<T: BeaconChainTypes> VerifiableBlock<T> {
    pub fn block_root(&mut self) -> Hash256 {
        if let Some(known_root) = self.block_root {
            known_root
        } else {
            let computed_root = self.block.canonical_root();
            self.block_root = Some(computed_root);
            computed_root
        }
    }

    pub fn load_parent(
        &self,
        chain: &BeaconChain<T>,
    ) -> Result<Option<BeaconSnapshot<T::EthSpec>>, BeaconChainError> {
        let block = &self.block.message;

        // Reject any block if its parent is not known to fork choice.
        //
        // A block that is not in fork choice is either:
        //
        //  - Not yet imported: we should reject this block because we should only import a child
        //  after its parent has been fully imported.
        //  - Pre-finalized: if the parent block is _prior_ to finalization, we should ignore it
        //  because it will revert finalization. Note that the finalized block is stored in fork
        //  choice, so we will not reject any child of the finalized block (this is relevant during
        //  genesis).
        if !chain.fork_choice.contains_block(&block.parent_root) {
            return Ok(None);
        }

        // Load the parent block and state from disk, returning early if it's not available.
        chain
            .block_processing_cache
            .try_write_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
            .and_then(|mut block_processing_cache| {
                block_processing_cache.try_remove(block.parent_root)
            })
            .map(|snapshot| Ok(Some(snapshot)))
            .unwrap_or_else(|| {
                // Load the blocks parent block from the database, returning invalid if that block is not
                // found.
                //
                // We don't return a DBInconsistent error here since it's possible for a block to
                // exist in fork choice but not in the database yet. In such a case we simply
                // indicate that we don't yet know the parent.
                let parent_block = if let Some(block) = chain.get_block(&block.parent_root)? {
                    block
                } else {
                    return Ok(None);
                };

                // Load the parent blocks state from the database, returning an error if it is not found.
                // It is an error because if we know the parent block we should also know the parent state.
                let parent_state_root = parent_block.state_root();
                let parent_state = chain
                    .get_state(&parent_state_root, Some(parent_block.slot()))?
                    .ok_or_else(|| {
                        BeaconChainError::DBInconsistent(format!(
                            "Missing state {:?}",
                            parent_state_root
                        ))
                    })?;

                Ok(Some(BeaconSnapshot {
                    beacon_block: parent_block,
                    beacon_block_root: block.parent_root,
                    beacon_state: parent_state,
                    beacon_state_root: parent_state_root,
                }))
            })
    }
}
