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
    per_slot_processing,
};
use std::borrow::Cow;
use types::{
    BeaconBlock, BeaconState, ChainSpec, CloneConfig, EthSpec, Hash256, RelativeEpoch,
    RelativeEpochError, SignedBeaconBlock, Slot,
};

pub enum BlockProcessingError {
    ProposalSignatureInvalid,
    UnknownParent(Hash256),
    BlockIsEarlierThanParent,
    BeaconChainError(BeaconChainError),
    SignatureVerificationError(BlockSignatureVerifierError),
}

impl From<BlockSignatureVerifierError> for BlockProcessingError {
    fn from(e: BlockSignatureVerifierError) -> Self {
        BlockProcessingError::SignatureVerificationError(e)
    }
}

pub struct ProposalSignatureVerifiedBlock<T: BeaconChainTypes> {
    block: SignedBeaconBlock<T::EthSpec>,
    block_root: Hash256,
    parent: BeaconSnapshot<T::EthSpec>,
}

pub struct FullySignatureVerifiedBlock<T: BeaconChainTypes> {
    block: SignedBeaconBlock<T::EthSpec>,
    block_root: Hash256,
    parent: Option<BeaconSnapshot<T::EthSpec>>,
}

pub struct ReadyToProcessBlock<E: EthSpec> {
    block: SignedBeaconBlock<E>,
    block_root: Hash256,
    parent: BeaconSnapshot<E>,
}

trait IntoReadyToProcessBlock<T: BeaconChainTypes> {
    fn into_ready_to_process_block(
        self,
        chain: &BeaconChain<T>,
    ) -> Result<ReadyToProcessBlock<T::EthSpec>, BlockProcessingError>;
}

impl<T: BeaconChainTypes> ProposalSignatureVerifiedBlock<T> {
    pub fn new(
        block: SignedBeaconBlock<T::EthSpec>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, BlockProcessingError> {
        let mut parent = load_parent(&block.message, chain)?;
        let block_root = block.canonical_root();

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
            Err(BlockProcessingError::ProposalSignatureInvalid)
        }
    }
}

impl<T: BeaconChainTypes> IntoReadyToProcessBlock<T> for ProposalSignatureVerifiedBlock<T> {
    fn into_ready_to_process_block(
        self,
        chain: &BeaconChain<T>,
    ) -> Result<ReadyToProcessBlock<T::EthSpec>, BlockProcessingError> {
        let fully_verified =
            FullySignatureVerifiedBlock::from_proposal_signature_verified_block(self, chain)?;
        fully_verified.into_ready_to_process_block(chain)
    }
}

impl<T: BeaconChainTypes> FullySignatureVerifiedBlock<T> {
    pub fn new(
        block: SignedBeaconBlock<T::EthSpec>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, BlockProcessingError> {
        let mut parent = load_parent(&block.message, chain)?;
        let block_root = block.canonical_root();

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
            Err(BlockProcessingError::ProposalSignatureInvalid)
        }
    }

    pub fn from_proposal_signature_verified_block(
        from: ProposalSignatureVerifiedBlock<T>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, BlockProcessingError> {
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
            Err(BlockProcessingError::ProposalSignatureInvalid)
        }
    }
}

impl<T: BeaconChainTypes> IntoReadyToProcessBlock<T> for FullySignatureVerifiedBlock<T> {
    fn into_ready_to_process_block(
        self,
        chain: &BeaconChain<T>,
    ) -> Result<ReadyToProcessBlock<T::EthSpec>, BlockProcessingError> {
        let block = self.block;
        let parent = self
            .parent
            .map(Result::Ok)
            .unwrap_or_else(|| load_parent(&block.message, chain))?;

        Ok(ReadyToProcessBlock {
            block,
            block_root: self.block_root,
            parent,
        })
    }
}

fn load_parent<T: BeaconChainTypes>(
    block: &BeaconBlock<T::EthSpec>,
    chain: &BeaconChain<T>,
) -> Result<BeaconSnapshot<T::EthSpec>, BlockProcessingError> {
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
        return Err(BlockProcessingError::UnknownParent(block.parent_root));
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
        .map_err(BlockProcessingError::BeaconChainError)?
        .ok_or_else(|| BlockProcessingError::UnknownParent(block.parent_root));

    metrics::stop_timer(db_read_timer);

    result
}

pub fn cheap_state_advance_to_obtain_committees<'a, E: EthSpec>(
    state: &'a mut BeaconState<E>,
    block_slot: Slot,
    spec: &ChainSpec,
) -> Result<Cow<'a, BeaconState<E>>, BlockProcessingError> {
    let block_epoch = block_slot.epoch(E::slots_per_epoch());
    let state_epoch = state.current_epoch();

    macro_rules! build_committee_cache {
        ($state: ident, $relative_epoch: ident) => {
            $state
                .build_committee_cache($relative_epoch, spec)
                .map_err(|e| {
                    BlockProcessingError::BeaconChainError(BeaconChainError::BeaconStateError(e))
                })?;
        };
    };

    if let Ok(relative_epoch) = RelativeEpoch::from_epoch(state_epoch, block_epoch) {
        state
            .build_committee_cache(relative_epoch, spec)
            .map_err(|e| {
                BlockProcessingError::BeaconChainError(BeaconChainError::BeaconStateError(e))
            })?;

        build_committee_cache!(state, relative_epoch);

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
                        BlockProcessingError::BeaconChainError(
                            BeaconChainError::SlotProcessingError(e),
                        )
                    })?;
                }
                Err(RelativeEpochError::EpochTooHigh { .. }) => {
                    return Err(BlockProcessingError::BlockIsEarlierThanParent);
                }
            }
        };

        build_committee_cache!(state, relative_epoch);

        Ok(Cow::Owned(state))
    }
}

pub fn get_validator_pubkey_cache<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
) -> Result<RwLockReadGuard<ValidatorPubkeyCache>, BlockProcessingError> {
    chain
        .validator_pubkey_cache
        .try_read_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
        .ok_or_else(|| BeaconChainError::ValidatorPubkeyCacheLockTimeout)
        .map_err(BlockProcessingError::BeaconChainError)
}

/// Produces an _empty_ `BlockSignatureVerifier`.
///
/// The signature verifier is empty because it does not yet have any of this block's signatures
/// added to it. Use `Self::apply_to_signature_verifier` to apply the signatures.
pub fn get_signature_verifier<'a, E: EthSpec>(
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
