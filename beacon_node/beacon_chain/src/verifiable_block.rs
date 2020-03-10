use crate::{
    beacon_chain::BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT, metrics, BeaconChain, BeaconChainError,
    BeaconChainTypes, BeaconSnapshot,
};
use state_processing::block_signature_verifier::{BlockSignatureVerifier, G1Point};
use std::borrow::Cow;
use types::{BeaconBlock, Hash256, SignedBeaconBlock};

pub struct VerifiableBlock<T: BeaconChainTypes> {
    pub(crate) block_root: Option<Hash256>,
    /// The outer Option indicates whether not there has been an attempt to load the parent. The
    /// inner option indicates if the parent exists.
    pub(crate) parent: Option<Option<BeaconSnapshot<T::EthSpec>>>,
    pub(crate) proposal_signature_is_valid: Option<bool>,
    /// Note: this field does not indicate the validity of `block.body.deposits` signatures, they
    /// must be verified during `per_block_processing`.
    pub(crate) all_signatures_valid: Option<bool>,
}

impl<T: BeaconChainTypes> VerifiableBlock<T> {
    pub fn empty() -> Self {
        Self {
            block_root: None,
            parent: None,
            proposal_signature_is_valid: None,
            all_signatures_valid: None,
        }
    }

    pub fn block_root(&mut self, block: &SignedBeaconBlock<T::EthSpec>) -> Hash256 {
        if let Some(known_root) = self.block_root {
            known_root
        } else {
            let computed_root = block.canonical_root();
            self.block_root = Some(computed_root);
            computed_root
        }
    }

    pub fn take_parent(
        &mut self,
        chain: &BeaconChain<T>,
        block: &BeaconBlock<T::EthSpec>,
    ) -> Result<Option<BeaconSnapshot<T::EthSpec>>, BeaconChainError> {
        // Return early if the value has been already computed.
        if let Some(parent_opt) = &mut self.parent {
            return Ok(std::mem::replace(parent_opt, None));
        }

        self.load_parent(chain, block)
    }

    fn load_parent(
        &self,
        chain: &BeaconChain<T>,
        block: &BeaconBlock<T::EthSpec>,
    ) -> Result<Option<BeaconSnapshot<T::EthSpec>>, BeaconChainError> {
        let db_read_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_DB_READ);

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
        let result = chain
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
            });

        metrics::stop_timer(db_read_timer);

        result
    }

    pub fn apply_to_signature_verifier<'a, F>(
        &'a self,
        verifier: &mut BlockSignatureVerifier<'a, T::EthSpec, F>,
        block: &'a SignedBeaconBlock<T::EthSpec>,
    ) -> Result<(), BeaconChainError>
    where
        F: Fn(usize) -> Option<Cow<'a, G1Point>> + Clone,
    {
        // TODO: build the committee caches somewhere..

        // Only include the block proposal signature if we have not already calculated it or if it
        // was previously flagged as invalid.
        if self
            .proposal_signature_is_valid
            .map_or(true, |is_valid| !is_valid)
        {
            verifier.include_block_proposal(&block, self.block_root)?;
        }

        // Only include the other signatures if they are not calculated or if they were previously
        // flagged as invalid.
        if self.all_signatures_valid.map_or(true, |is_valid| !is_valid) {
            verifier.include_randao_reveal(&block)?;
            verifier.include_proposer_slashings(&block)?;
            verifier.include_attester_slashings(&block)?;
            verifier.include_attestations(&block)?;
            //Deposits are not included because they can legally have invalid signatures.
            verifier.include_exits(&block)?;
        }

        Ok(())
    }

    pub fn set_signatures_to_valid(&mut self) {
        self.proposal_signature_is_valid = Some(true);
        self.all_signatures_valid = Some(true);
    }
}
