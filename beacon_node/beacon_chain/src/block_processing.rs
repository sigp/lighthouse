use crate::validator_pubkey_cache::ValidatorPubkeyCache;
use crate::{
    beacon_chain::{BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT, VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT},
    metrics, BeaconChain, BeaconChainError, BeaconChainTypes, BeaconSnapshot,
};
use parking_lot::RwLockReadGuard;
use state_processing::{
    block_signature_verifier::{
        BlockSignatureVerifier, Error as BlockSignatureVerifierError, G1Point,
    },
    per_block_processing, per_slot_processing, BlockProcessingError, BlockSignatureStrategy,
    SlotProcessingError,
};
use std::borrow::Cow;
use store::{Error as DBError, StateBatch};
use types::{
    BeaconBlock, BeaconState, BeaconStateError, ChainSpec, CloneConfig, EthSpec, Hash256,
    RelativeEpoch, RelativeEpochError, SignedBeaconBlock, Slot,
};

/// Maximum block slot number. Block with slots bigger than this constant will NOT be processed.
const MAXIMUM_BLOCK_SLOT_NUMBER: u64 = 4_294_967_296; // 2^32

pub enum BlockError {
    /// The parent block was unknown.
    ParentUnknown(Hash256),
    /// The block slot is greater than the present slot.
    FutureSlot {
        present_slot: Slot,
        block_slot: Slot,
    },
    /// The block state_root does not match the generated state.
    StateRootMismatch { block: Hash256, local: Hash256 },
    /// The block was a genesis block, these blocks cannot be re-imported.
    GenesisBlock,
    /// The slot is finalized, no need to import.
    WouldRevertFinalizedSlot {
        block_slot: Slot,
        finalized_slot: Slot,
    },
    /// Block is already known, no need to re-import.
    BlockIsAlreadyKnown,
    /// The block slot exceeds the MAXIMUM_BLOCK_SLOT_NUMBER.
    BlockSlotLimitReached,
    /// The proposal signature in invalid.
    ProposalSignatureInvalid,
    /// A signature in the block is invalid (exactly which is unknown).
    InvalidSignature,
    /// The provided block is from an earlier slot than its parent.
    BlockIsEarlierThanParent,
    /// The block failed the specification's `per_block_processing` function, it is invalid.
    PerBlockProcessingError(BlockProcessingError),
    /// There was an error whilst processing the block. It is not necessarily invalid.
    BeaconChainError(BeaconChainError),
}

impl From<BlockSignatureVerifierError> for BlockError {
    fn from(e: BlockSignatureVerifierError) -> Self {
        BlockError::BeaconChainError(BeaconChainError::BlockSignatureVerifierError(e))
    }
}

impl From<BeaconChainError> for BlockError {
    fn from(e: BeaconChainError) -> Self {
        BlockError::BeaconChainError(e)
    }
}

impl From<BeaconStateError> for BlockError {
    fn from(e: BeaconStateError) -> Self {
        BlockError::BeaconChainError(BeaconChainError::BeaconStateError(e))
    }
}

impl From<SlotProcessingError> for BlockError {
    fn from(e: SlotProcessingError) -> Self {
        BlockError::BeaconChainError(BeaconChainError::SlotProcessingError(e))
    }
}

impl From<DBError> for BlockError {
    fn from(e: DBError) -> Self {
        BlockError::BeaconChainError(BeaconChainError::DBError(e))
    }
}

pub struct GossipVerifiedBlock<T: BeaconChainTypes> {
    block: SignedBeaconBlock<T::EthSpec>,
    block_root: Hash256,
    parent: BeaconSnapshot<T::EthSpec>,
}

pub struct SignatureVerifiedBlock<T: BeaconChainTypes> {
    block: SignedBeaconBlock<T::EthSpec>,
    block_root: Hash256,
    parent: Option<BeaconSnapshot<T::EthSpec>>,
}

pub struct ReadyToProcessBlock<T: BeaconChainTypes> {
    block: SignedBeaconBlock<T::EthSpec>,
    block_root: Hash256,
    parent: BeaconSnapshot<T::EthSpec>,
}

pub trait IntoReadyToProcessBlock<T: BeaconChainTypes> {
    fn into_ready_to_process_block(
        self,
        chain: &BeaconChain<T>,
    ) -> Result<ReadyToProcessBlock<T>, BlockError>;
}

impl<T: BeaconChainTypes> GossipVerifiedBlock<T> {
    pub fn new(
        block: SignedBeaconBlock<T::EthSpec>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, BlockError> {
        // Do not gossip or process blocks from future slots.
        //
        // TODO: adjust this to allow for clock disparity tolerance.
        let present_slot = chain.slot()?;
        if block.slot() > present_slot {
            return Err(BlockError::FutureSlot {
                present_slot,
                block_slot: block.slot(),
            });
        }

        let mut parent = load_parent(&block.message, chain)?;
        let block_root = get_block_root(&block);

        let state = cheap_state_advance_to_obtain_committees(
            &mut parent.beacon_state,
            block.slot(),
            &chain.spec,
        )?;

        let pubkey_cache = get_validator_pubkey_cache(chain)?;

        let mut signature_verifier = get_signature_verifier(&state, &pubkey_cache, &chain.spec);
        signature_verifier.include_block_proposal(&block, Some(block_root))?;

        if signature_verifier.verify().is_ok() {
            Ok(Self {
                block,
                block_root,
                parent,
            })
        } else {
            Err(BlockError::ProposalSignatureInvalid)
        }
    }
}

impl<T: BeaconChainTypes> IntoReadyToProcessBlock<T> for GossipVerifiedBlock<T> {
    fn into_ready_to_process_block(
        self,
        chain: &BeaconChain<T>,
    ) -> Result<ReadyToProcessBlock<T>, BlockError> {
        let fully_verified = SignatureVerifiedBlock::from_gossip_verified_block(self, chain)?;
        fully_verified.into_ready_to_process_block(chain)
    }
}

impl<T: BeaconChainTypes> SignatureVerifiedBlock<T> {
    pub fn new(
        block: SignedBeaconBlock<T::EthSpec>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, BlockError> {
        let mut parent = load_parent(&block.message, chain)?;
        let block_root = get_block_root(&block);

        let state = cheap_state_advance_to_obtain_committees(
            &mut parent.beacon_state,
            block.slot(),
            &chain.spec,
        )?;

        let pubkey_cache = get_validator_pubkey_cache(chain)?;

        let mut signature_verifier = get_signature_verifier(&state, &pubkey_cache, &chain.spec);

        signature_verifier.include_all_signatures(&block, Some(block_root))?;

        if signature_verifier.verify().is_ok() {
            Ok(Self {
                block,
                block_root,
                parent: Some(parent),
            })
        } else {
            Err(BlockError::ProposalSignatureInvalid)
        }
    }

    pub fn from_gossip_verified_block(
        from: GossipVerifiedBlock<T>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, BlockError> {
        let mut parent = from.parent;
        let block = from.block;

        let state = cheap_state_advance_to_obtain_committees(
            &mut parent.beacon_state,
            block.slot(),
            &chain.spec,
        )?;

        let pubkey_cache = get_validator_pubkey_cache(chain)?;

        let mut signature_verifier = get_signature_verifier(&state, &pubkey_cache, &chain.spec);

        signature_verifier.include_all_signatures_except_proposal(&block)?;

        if signature_verifier.verify().is_ok() {
            Ok(Self {
                block,
                block_root: from.block_root,
                parent: Some(parent),
            })
        } else {
            Err(BlockError::ProposalSignatureInvalid)
        }
    }
}

impl<T: BeaconChainTypes> IntoReadyToProcessBlock<T> for SignatureVerifiedBlock<T> {
    fn into_ready_to_process_block(
        self,
        chain: &BeaconChain<T>,
    ) -> Result<ReadyToProcessBlock<T>, BlockError> {
        let block = self.block;
        let parent = self
            .parent
            .map(Result::Ok)
            .unwrap_or_else(|| load_parent(&block.message, chain))?;

        ReadyToProcessBlock::from_signature_verified_components(
            block,
            self.block_root,
            parent,
            chain,
        )
    }
}

impl<T: BeaconChainTypes> ReadyToProcessBlock<T> {
    pub fn from_signature_verified_components(
        block: SignedBeaconBlock<T::EthSpec>,
        block_root: Hash256,
        mut parent: BeaconSnapshot<T::EthSpec>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, BlockError> {
        /*
         *  Perform cursory checks to see if the block is even worth processing.
         */

        check_block_relevancy(&block, Some(block_root), chain)?;

        /*
         * Advance the given `parent.beacon_state` to the slot of the given `block`.
         */

        let catchup_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_CATCHUP_STATE);

        // Keep a batch of any states that were "skipped" (block-less) in between the parent state
        // slot and the block slot. These will be stored in the database.
        let mut intermediate_states = StateBatch::new();

        // Transition the parent state to the block slot.
        let state = &mut parent.beacon_state;
        let distance = block.slot().as_u64().saturating_sub(state.slot.as_u64());
        for i in 0..distance {
            let state_root = if i == 0 {
                parent.beacon_block.state_root()
            } else {
                // This is a new state we've reached, so stage it for storage in the DB.
                // Computing the state root here is time-equivalent to computing it during slot
                // processing, but we get early access to it.
                let state_root = state.update_tree_hash_cache()?;
                intermediate_states.add_state(state_root, &state)?;
                state_root
            };

            per_slot_processing(state, Some(state_root), &chain.spec)?;
        }

        metrics::stop_timer(catchup_timer);

        /*
         * Build the committee caches on the state.
         */

        let committee_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_COMMITTEE);

        state.build_committee_cache(RelativeEpoch::Previous, &chain.spec)?;
        state.build_committee_cache(RelativeEpoch::Current, &chain.spec)?;

        metrics::stop_timer(committee_timer);

        /*
         * Perform `per_block_processing` on the block and state, returning early if the block is
         * invalid.
         */

        let core_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_CORE);

        if let Err(err) = per_block_processing(
            state,
            &block,
            Some(block_root),
            // Signatures were verified earlier in this function.
            BlockSignatureStrategy::NoVerification,
            &chain.spec,
        ) {
            match err {
                // Capture `BeaconStateError` so that we can easily distinguish between a block
                // that's invalid and one that caused an internal error.
                BlockProcessingError::BeaconStateError(e) => return Err(e.into()),
                other => return Err(BlockError::PerBlockProcessingError(other)),
            }
        };

        metrics::stop_timer(core_timer);

        /*
         * Calculate the state root of the newly modified state
         */

        let state_root_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_STATE_ROOT);

        let state_root = state.update_tree_hash_cache()?;

        metrics::stop_timer(state_root_timer);

        /*
         * Check to ensure the state root on the block matches the one we have calculated.
         */

        if block.state_root() != state_root {
            return Err(BlockError::StateRootMismatch {
                block: block.state_root(),
                local: state_root,
            });
        }

        Ok(Self {
            block,
            block_root,
            parent,
        })
    }
}

fn check_block_relevancy<T: BeaconChainTypes>(
    signed_block: &SignedBeaconBlock<T::EthSpec>,
    block_root: Option<Hash256>,
    chain: &BeaconChain<T>,
) -> Result<Hash256, BlockError> {
    let block = &signed_block.message;

    // Do not process blocks from the future.
    if block.slot > chain.slot()? {
        return Err(BlockError::FutureSlot {
            present_slot: chain.slot()?,
            block_slot: block.slot,
        });
    }

    // Do not re-process the genesis block.
    if block.slot == 0 {
        return Err(BlockError::GenesisBlock);
    }

    // This is an artificial (non-spec) restriction that provides some protection from overflow
    // abuses.
    if block.slot >= MAXIMUM_BLOCK_SLOT_NUMBER {
        return Err(BlockError::BlockSlotLimitReached);
    }

    // Do not process a block from a finalized slot.
    let finalized_slot = chain
        .head_info()?
        .finalized_checkpoint
        .epoch
        .start_slot(T::EthSpec::slots_per_epoch());
    if block.slot <= finalized_slot {
        return Err(BlockError::WouldRevertFinalizedSlot {
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
        return Err(BlockError::ParentUnknown(block.parent_root));
    }

    let block_root = block_root.unwrap_or_else(|| get_block_root(&signed_block));

    // Check if the block is already known. We know it is post-finalization, so it is
    // sufficient to check the fork choice.
    if chain.fork_choice.contains_block(&block_root) {
        return Err(BlockError::BlockIsAlreadyKnown);
    }

    Ok(block_root)
}

fn get_block_root<E: EthSpec>(block: &SignedBeaconBlock<E>) -> Hash256 {
    let block_root_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_BLOCK_ROOT);

    let block_root = block.canonical_root();

    metrics::stop_timer(block_root_timer);

    block_root
}

fn load_parent<T: BeaconChainTypes>(
    block: &BeaconBlock<T::EthSpec>,
    chain: &BeaconChain<T>,
) -> Result<BeaconSnapshot<T::EthSpec>, BlockError> {
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
        return Err(BlockError::ParentUnknown(block.parent_root));
    }

    // Load the parent block and state from disk, returning early if it's not available.
    let result = chain
        .snapshot_cache
        .try_write_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
        .and_then(|mut snapshot_cache| snapshot_cache.try_remove(block.parent_root))
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
        .map_err(BlockError::BeaconChainError)?
        .ok_or_else(|| BlockError::ParentUnknown(block.parent_root));

    metrics::stop_timer(db_read_timer);

    result
}

fn cheap_state_advance_to_obtain_committees<'a, E: EthSpec>(
    state: &'a mut BeaconState<E>,
    block_slot: Slot,
    spec: &ChainSpec,
) -> Result<Cow<'a, BeaconState<E>>, BlockError> {
    let block_epoch = block_slot.epoch(E::slots_per_epoch());
    let state_epoch = state.current_epoch();

    if let Ok(relative_epoch) = RelativeEpoch::from_epoch(state_epoch, block_epoch) {
        state
            .build_committee_cache(relative_epoch, spec)
            .map_err(|e| BlockError::BeaconChainError(BeaconChainError::BeaconStateError(e)))?;

        state.build_committee_cache(relative_epoch, spec)?;

        Ok(Cow::Borrowed(state))
    } else {
        let mut state = state.clone_with(CloneConfig::none());

        let relative_epoch = loop {
            match RelativeEpoch::from_epoch(state.current_epoch(), block_epoch) {
                Ok(relative_epoch) => break relative_epoch,
                Err(RelativeEpochError::EpochTooLow { .. }) => {
                    // Don't calculate state roots since they aren't required for calculating
                    // shuffling (achieved by providing Hash256::zero()).
                    per_slot_processing(&mut state, Some(Hash256::zero()), spec).map_err(|e| {
                        BlockError::BeaconChainError(BeaconChainError::SlotProcessingError(e))
                    })?;
                }
                Err(RelativeEpochError::EpochTooHigh { .. }) => {
                    return Err(BlockError::BlockIsEarlierThanParent);
                }
            }
        };

        state.build_committee_cache(relative_epoch, spec)?;

        Ok(Cow::Owned(state))
    }
}

fn get_validator_pubkey_cache<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
) -> Result<RwLockReadGuard<ValidatorPubkeyCache>, BlockError> {
    chain
        .validator_pubkey_cache
        .try_read_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
        .ok_or_else(|| BeaconChainError::ValidatorPubkeyCacheLockTimeout)
        .map_err(BlockError::BeaconChainError)
}

/// Produces an _empty_ `BlockSignatureVerifier`.
///
/// The signature verifier is empty because it does not yet have any of this block's signatures
/// added to it. Use `Self::apply_to_signature_verifier` to apply the signatures.
fn get_signature_verifier<'a, E: EthSpec>(
    state: &'a BeaconState<E>,
    validator_pubkey_cache: &'a ValidatorPubkeyCache,
    spec: &'a ChainSpec,
) -> BlockSignatureVerifier<'a, E, impl Fn(usize) -> Option<Cow<'a, G1Point>> + Clone> {
    BlockSignatureVerifier::new(
        state,
        move |validator_index| {
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
        spec,
    )
}
