use crate::{
    beacon_chain::{
        BlockProcessingOutcome, BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT,
        VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT,
    },
    metrics, BeaconChain, BeaconChainError, BeaconChainTypes, BeaconSnapshot,
};
use slog::{debug, error, info, trace, warn, Logger};
use ssz::Encode;
use state_processing::{
    block_signature_verifier::{
        BlockSignatureVerifier, Error as BlockSignatureVerifierError, G1Point,
    },
    signature_sets::{block_proposal_signature_set, Error as SignatureSetError},
};
use std::borrow::Cow;
use std::fs;
use std::io::prelude::*;
use std::sync::Arc;
use store::Store;
use tree_hash::TreeHash;
use types::{BeaconBlock, BeaconState, EthSpec, Hash256, RelativeEpoch, SignedBeaconBlock};

/// If true, everytime a block is processed the pre-state, post-state and block are written to SSZ
/// files in the temp directory.
///
/// Only useful for testing.
const WRITE_BLOCK_PROCESSING_SSZ: bool = cfg!(feature = "write_ssz_files");

/// Maximum block slot number. Block with slots bigger than this constant will NOT be processed.
const MAXIMUM_BLOCK_SLOT_NUMBER: u64 = 4_294_967_296; // 2^32

pub enum Error {
    ParentUnknown(Hash256),
    DBInconsistent(String),
    BeaconChainError(BeaconChainError),
    SignatureSetError(SignatureSetError),
    BlockSignatureVerifierError(BlockSignatureVerifierError),
    NoParentLoaded,
    NoBlockRoot,
}

impl From<BeaconChainError> for Error {
    fn from(e: BeaconChainError) -> Error {
        Error::BeaconChainError(e)
    }
}

impl From<BlockSignatureVerifierError> for Error {
    fn from(e: BlockSignatureVerifierError) -> Error {
        Error::BlockSignatureVerifierError(e)
    }
}

pub struct BlockImporter<T: BeaconChainTypes> {
    chain: Arc<BeaconChain<T>>,
    block: SignedBeaconBlock<T::EthSpec>,
    block_root: Option<Hash256>,
    parent: Option<BeaconSnapshot<T::EthSpec>>,
    proposal_signature_is_valid: Option<bool>,
    all_signatures_valid: Option<bool>,
}

impl<T: BeaconChainTypes> BlockImporter<T> {
    pub fn new(chain: Arc<BeaconChain<T>>, block: SignedBeaconBlock<T::EthSpec>) -> Self {
        Self {
            chain,
            block,
            block_root: None,
            parent: None,
            proposal_signature_is_valid: None,
            all_signatures_valid: None,
        }
    }

    pub fn block(&self) -> &SignedBeaconBlock<T::EthSpec> {
        &self.block
    }

    pub fn should_gossip(&mut self) -> Result<bool, Error> {
        // TODO: allow for `MAXIMUM_GOSSIP_CLOCK_DISPARITY` when checking the slot.
        //
        // https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/p2p-interface.md#configuration
        Ok(self.block.slot() <= self.chain.slot()? && self.maybe_verify_proposal_signature()?)
    }

    pub fn import(mut self) -> Result<BlockProcessingOutcome, BeaconChainError> {
        metrics::inc_counter(&metrics::BLOCK_PROCESSING_REQUESTS);
        let full_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_TIMES);

        self.maybe_load_parent()?;
        let parent = self.parent.as_ref().ok_or_else(|| Error::NoParentLoaded)?;

        let chain = &self.chain;
        let signed_block = &self.block;
        let block = &signed_block.message;

        let finalized_slot = chain
            .head_info()?
            .finalized_checkpoint
            .epoch
            .start_slot(T::EthSpec::slots_per_epoch());

        if block.slot == 0 {
            return Ok(BlockProcessingOutcome::GenesisBlock);
        }

        if block.slot >= MAXIMUM_BLOCK_SLOT_NUMBER {
            return Ok(BlockProcessingOutcome::BlockSlotLimitReached);
        }

        if block.slot <= finalized_slot {
            return Ok(BlockProcessingOutcome::WouldRevertFinalizedSlot {
                block_slot: block.slot,
                finalized_slot,
            });
        }

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
            return Ok(BlockProcessingOutcome::ParentUnknown {
                parent: block.parent_root,
                reference_location: "fork_choice",
            });
        }

        let block_root_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_BLOCK_ROOT);

        let block_root = block.canonical_root();

        metrics::stop_timer(block_root_timer);

        if block_root == chain.genesis_block_root {
            return Ok(BlockProcessingOutcome::GenesisBlock);
        }

        let present_slot = chain.slot()?;

        if block.slot > present_slot {
            return Ok(BlockProcessingOutcome::FutureSlot {
                present_slot,
                block_slot: block.slot,
            });
        }

        // Check if the block is already known. We know it is post-finalization, so it is
        // sufficient to check the fork choice.
        if chain.fork_choice.contains_block(&block_root) {
            return Ok(BlockProcessingOutcome::BlockIsAlreadyKnown);
        }

        // Records the time taken to load the block and state from the database during block
        // processing.
        let db_read_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_DB_READ);

        let cached_snapshot = chain
            .block_processing_cache
            .try_write_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
            .and_then(|mut block_processing_cache| {
                block_processing_cache.try_remove(block.parent_root)
            });

        let (parent_block, parent_state) = if let Some(snapshot) = cached_snapshot {
            (snapshot.beacon_block, snapshot.beacon_state)
        } else {
            // Load the blocks parent block from the database, returning invalid if that block is not
            // found.
            let parent_block = match chain.get_block(&block.parent_root)? {
                Some(block) => block,
                None => {
                    return Ok(BlockProcessingOutcome::ParentUnknown {
                        parent: block.parent_root,
                        reference_location: "database",
                    });
                }
            };

            // Load the parent blocks state from the database, returning an error if it is not found.
            // It is an error because if we know the parent block we should also know the parent state.
            let parent_state_root = parent_block.state_root();
            let parent_state = chain
                .get_state(&parent_state_root, Some(parent_block.slot()))?
                .ok_or_else(|| {
                    Error::DBInconsistent(format!("Missing state {:?}", parent_state_root))
                })?;

            (parent_block, parent_state)
        };

        metrics::stop_timer(db_read_timer);

        write_block(&block, block_root, &chain.log);

        let catchup_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_CATCHUP_STATE);

        // Keep a batch of any states that were "skipped" (block-less) in between the parent state
        // slot and the block slot. These will be stored in the database.
        let mut intermediate_states = StateBatch::new();

        // Transition the parent state to the block slot.
        let mut state: BeaconState<T::EthSpec> = parent_state;
        let distance = block.slot.as_u64().saturating_sub(state.slot.as_u64());
        for i in 0..distance {
            let state_root = if i == 0 {
                parent_block.state_root()
            } else {
                // This is a new state we've reached, so stage it for storage in the DB.
                // Computing the state root here is time-equivalent to computing it during slot
                // processing, but we get early access to it.
                let state_root = state.update_tree_hash_cache()?;
                intermediate_states.add_state(state_root, &state)?;
                state_root
            };

            per_slot_processing(&mut state, Some(state_root), &chain.spec)?;
        }

        metrics::stop_timer(catchup_timer);

        let committee_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_COMMITTEE);

        state.build_committee_cache(RelativeEpoch::Previous, &chain.spec)?;
        state.build_committee_cache(RelativeEpoch::Current, &chain.spec)?;

        metrics::stop_timer(committee_timer);

        write_state(
            &format!("state_pre_block_{}", block_root),
            &state,
            &chain.log,
        );

        let signature_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_SIGNATURE);

        if !block_importer.verify_all_signatures()? {
            return Ok(BlockProcessingOutcome::InvalidSignature);
        }

        metrics::stop_timer(signature_timer);

        let core_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_CORE);

        // Apply the received block to its parent state (which has been transitioned into this
        // slot).
        match per_block_processing(
            &mut state,
            &signed_block,
            Some(block_root),
            // Signatures were verified earlier in this function.
            BlockSignatureStrategy::NoVerification,
            &chain.spec,
        ) {
            Err(BlockProcessingError::BeaconStateError(e)) => {
                return Err(Error::BeaconStateError(e))
            }
            Err(e) => return Ok(BlockProcessingOutcome::PerBlockProcessingError(e)),
            _ => {}
        }

        metrics::stop_timer(core_timer);

        let state_root_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_STATE_ROOT);

        let state_root = state.update_tree_hash_cache()?;

        metrics::stop_timer(state_root_timer);

        write_state(
            &format!("state_post_block_{}", block_root),
            &state,
            &chain.log,
        );

        if block.state_root != state_root {
            return Ok(BlockProcessingOutcome::StateRootMismatch {
                block: block.state_root,
                local: state_root,
            });
        }

        let fork_choice_register_timer =
            metrics::start_timer(&metrics::BLOCK_PROCESSING_FORK_CHOICE_REGISTER);

        // If there are new validators in this block, update our pubkey cache.
        //
        // We perform this _before_ adding the block to fork choice because the pubkey cache is
        // used by attestation processing which will only process an attestation if the block is
        // known to fork choice. This ordering ensure that the pubkey cache is always up-to-date.
        chain
            .validator_pubkey_cache
            .try_write_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
            .ok_or_else(|| Error::ValidatorPubkeyCacheLockTimeout)?
            .import_new_pubkeys(&state)?;

        // If the imported block is in the previous or current epochs (according to the
        // wall-clock), check to see if this is the first block of the epoch. If so, add the
        // committee to the shuffling cache.
        if state.current_epoch() + 1 >= chain.epoch()?
            && parent_block.slot().epoch(T::EthSpec::slots_per_epoch()) != state.current_epoch()
        {
            let mut shuffling_cache = chain
                .shuffling_cache
                .try_write_for(ATTESTATION_CACHE_LOCK_TIMEOUT)
                .ok_or_else(|| Error::AttestationCacheLockTimeout)?;

            let committee_cache = state.committee_cache(RelativeEpoch::Current)?;

            let epoch_start_slot = state
                .current_epoch()
                .start_slot(T::EthSpec::slots_per_epoch());
            let target_root = if state.slot == epoch_start_slot {
                block_root
            } else {
                *state.get_block_root(epoch_start_slot)?
            };

            shuffling_cache.insert(state.current_epoch(), target_root, committee_cache);
        }

        // Register the new block with the fork choice service.
        if let Err(e) = chain
            .fork_choice
            .process_block(chain, &state, &block, block_root)
        {
            error!(
                chain.log,
                "Add block to fork choice failed";
                "block_root" =>  format!("{}", block_root),
                "error" => format!("{:?}", e),
            )
        }

        metrics::stop_timer(fork_choice_register_timer);

        chain.head_tracker.register_block(block_root, &block);
        metrics::observe(
            &metrics::OPERATIONS_PER_BLOCK_ATTESTATION,
            block.body.attestations.len() as f64,
        );

        let db_write_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_DB_WRITE);

        // Store all the states between the parent block state and this block's slot before storing
        // the final state.
        intermediate_states.commit(&*chain.store)?;

        // Store the block and state.
        // NOTE: we store the block *after* the state to guard against inconsistency in the event of
        // a crash, as states are usually looked up from blocks, not the other way around. A better
        // solution would be to use a database transaction (once our choice of database and API
        // settles down).
        // See: https://github.com/sigp/lighthouse/issues/692
        chain.store.put_state(&state_root, &state)?;
        chain.store.put_block(&block_root, signed_block.clone())?;

        chain
            .block_processing_cache
            .try_write_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
            .map(|mut block_processing_cache| {
                block_processing_cache.insert(BeaconSnapshot {
                    beacon_block: block_importer.into_block(),
                    beacon_block_root: block_root,
                    beacon_state: state,
                    beacon_state_root: state_root,
                });
            })
            .unwrap_or_else(|| {
                error!(
                    chain.log,
                    "Failed to obtain cache write lock";
                    "lock" => "block_processing_cache",
                    "task" => "process block"
                );
            });

        metrics::stop_timer(db_write_timer);

        metrics::inc_counter(&metrics::BLOCK_PROCESSING_SUCCESSES);

        metrics::stop_timer(full_timer);

        Ok(BlockProcessingOutcome::Processed { block_root })
    }

    pub fn verify_all_signatures(&mut self) -> Result<bool, Error> {
        // Return early if the result is already known.
        if let Some(is_valid) = self.all_signatures_valid {
            return Ok(is_valid);
        }

        self.maybe_load_parent()?;
        self.maybe_calculate_block_root();

        let parent = self.parent.as_ref().ok_or_else(|| Error::NoParentLoaded)?;
        let state = &parent.beacon_state;

        let validator_pubkey_cache = self
            .chain
            .validator_pubkey_cache
            .try_read_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
            .ok_or_else(|| BeaconChainError::ValidatorPubkeyCacheLockTimeout)?;

        let mut verifier = self.produce_signature_verifier(|validator_index| {
            // Disallow access to any validator pubkeys that are not in the current beacon
            // state.
            if validator_index < state.validators.len() {
                validator_pubkey_cache
                    .get(validator_index)
                    .map(|pk| Cow::Borrowed(pk.as_point()))
            } else {
                None
            }
        })?;

        if verifier.verify().is_ok() {
            self.set_signatures_to_valid();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Produces an _empty_ `BlockSignatureVerifier`.
    ///
    /// The signature verifier is empty because it does not yet have any of this block's signatures
    /// added to it. Use `Self::apply_to_signature_verifier` to apply the signatures.
    pub fn produce_signature_verifier<'a, F>(
        &'a mut self,
        get_pubkey: F,
    ) -> Result<BlockSignatureVerifier<'a, T::EthSpec, F>, Error>
    where
        F: Fn(usize) -> Option<Cow<'a, G1Point>> + Clone,
    {
        self.maybe_load_parent()?;
        self.maybe_calculate_block_root();

        let parent = self.parent.as_ref().ok_or_else(|| Error::NoParentLoaded)?;

        let state = &parent.beacon_state;

        Ok(BlockSignatureVerifier::new(
            state,
            get_pubkey,
            &self.chain.spec,
        ))
    }

    pub fn apply_to_signature_verifier<'a, F>(
        &'a self,
        verifier: &mut BlockSignatureVerifier<'a, T::EthSpec, F>,
    ) -> Result<(), Error>
    where
        F: Fn(usize) -> Option<Cow<'a, G1Point>> + Clone,
    {
        // TODO: build the committee caches somewhere..

        // Only include the block proposal signature if we have not already calculated it.
        if self
            .proposal_signature_is_valid
            .map_or(false, |is_valid| is_valid)
        {
            verifier.include_block_proposal(&self.block, self.block_root)?;
        }
        verifier.include_randao_reveal(&self.block)?;
        verifier.include_proposer_slashings(&self.block)?;
        verifier.include_attester_slashings(&self.block)?;
        verifier.include_attestations(&self.block)?;
        //Deposits are not included because they can legally have invalid signatures.
        verifier.include_exits(&self.block)?;

        Ok(())
    }

    pub fn set_signatures_to_valid(&mut self) {
        self.proposal_signature_is_valid = Some(true);
        self.all_signatures_valid = Some(true);
    }

    fn maybe_load_parent(&mut self) -> Result<(), Error> {
        // Return early if the parent has already been loaded.
        if self.parent.is_some() {
            return Ok(());
        }

        let block = &self.block.message;
        let chain = &self.chain;

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
            return Err(Error::ParentUnknown(block.parent_root));
        }

        // Load the parent block and state from disk, returning early if it's not available.
        self.parent = chain
            .block_processing_cache
            .try_write_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
            .and_then(|mut block_processing_cache| {
                block_processing_cache.try_remove(block.parent_root)
            })
            .map::<Result<_, Error>, _>(Result::Ok)
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
                        Error::DBInconsistent(format!("Missing state {:?}", parent_state_root))
                    })?;

                Ok(Some(BeaconSnapshot {
                    beacon_block: parent_block,
                    beacon_block_root: block.parent_root,
                    beacon_state: parent_state,
                    beacon_state_root: parent_state_root,
                }))
            })?;

        Ok(())
    }

    fn maybe_calculate_block_root(&mut self) {
        if self.block_root.is_none() {
            self.block_root = Some(self.block.canonical_root())
        }
    }

    fn maybe_verify_proposal_signature(&mut self) -> Result<bool, Error> {
        // Return early if this result is already known.
        if let Some(is_valid) = self.proposal_signature_is_valid {
            return Ok(is_valid);
        }

        // TODO: bring the parent state into the current epoch (or close enough so it can be
        // verified).

        // The parent is required for this operation.
        self.maybe_load_parent()?;

        // It is not strictly necessary to calculate the block root here, but we might as well to
        // avoid double-hashing it later.
        self.maybe_calculate_block_root();

        let parent = self.parent.as_ref().ok_or_else(|| Error::NoParentLoaded)?;
        let state = &parent.beacon_state;

        let validator_pubkey_cache = self
            .chain
            .validator_pubkey_cache
            .try_read_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
            .ok_or_else(|| BeaconChainError::ValidatorPubkeyCacheLockTimeout)?;

        let is_valid = block_proposal_signature_set(
            state,
            |validator_index| {
                // Disallow access to any validator pubkeys that are not in the current beacon
                // state.
                if validator_index < state.validators.len() {
                    validator_pubkey_cache
                        .get(validator_index)
                        .map(|pk| Cow::Borrowed(pk.as_point()))
                } else {
                    None
                }
            },
            &self.block,
            self.block_root,
            &self.chain.spec,
        )
        .map_err(Error::SignatureSetError)?
        .is_valid();

        self.proposal_signature_is_valid = Some(is_valid);

        Ok(is_valid)
    }
}

fn write_state<T: EthSpec>(prefix: &str, state: &BeaconState<T>, log: &Logger) {
    if WRITE_BLOCK_PROCESSING_SSZ {
        let root = state.tree_hash_root();
        let filename = format!("{}_slot_{}_root_{}.ssz", prefix, state.slot, root);
        let mut path = std::env::temp_dir().join("lighthouse");
        let _ = fs::create_dir_all(path.clone());
        path = path.join(filename);

        match fs::File::create(path.clone()) {
            Ok(mut file) => {
                let _ = file.write_all(&state.as_ssz_bytes());
            }
            Err(e) => error!(
                log,
                "Failed to log state";
                "path" => format!("{:?}", path),
                "error" => format!("{:?}", e)
            ),
        }
    }
}

fn write_block<T: EthSpec>(block: &BeaconBlock<T>, root: Hash256, log: &Logger) {
    if WRITE_BLOCK_PROCESSING_SSZ {
        let filename = format!("block_slot_{}_root{}.ssz", block.slot, root);
        let mut path = std::env::temp_dir().join("lighthouse");
        let _ = fs::create_dir_all(path.clone());
        path = path.join(filename);

        match fs::File::create(path.clone()) {
            Ok(mut file) => {
                let _ = file.write_all(&block.as_ssz_bytes());
            }
            Err(e) => error!(
                log,
                "Failed to log block";
                "path" => format!("{:?}", path),
                "error" => format!("{:?}", e)
            ),
        }
    }
}
