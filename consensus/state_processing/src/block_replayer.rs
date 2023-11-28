use crate::{
    per_block_processing, per_epoch_processing::EpochProcessingSummary, per_slot_processing,
    BlockProcessingError, BlockSignatureStrategy, ConsensusContext, SlotProcessingError,
    VerifyBlockRoot,
};
use itertools::Itertools;
use std::iter::Peekable;
use std::marker::PhantomData;
use types::{BeaconState, BlindedPayload, ChainSpec, EthSpec, Hash256, SignedBeaconBlock, Slot};

type PreBlockHook<'a, E, Error> = Box<
    dyn FnMut(&mut BeaconState<E>, &SignedBeaconBlock<E, BlindedPayload<E>>) -> Result<(), Error>
        + 'a,
>;
type PostBlockHook<'a, E, Error> = PreBlockHook<'a, E, Error>;
type PreSlotHook<'a, E, Error> = Box<dyn FnMut(&mut BeaconState<E>) -> Result<(), Error> + 'a>;
type PostSlotHook<'a, E, Error> = Box<
    dyn FnMut(&mut BeaconState<E>, Option<EpochProcessingSummary<E>>, bool) -> Result<(), Error>
        + 'a,
>;
type StateRootIterDefault<Error> = std::iter::Empty<Result<(Hash256, Slot), Error>>;

/// Efficiently apply blocks to a state while configuring various parameters.
///
/// Usage follows a builder pattern.
pub struct BlockReplayer<
    'a,
    Spec: EthSpec,
    Error = BlockReplayError,
    StateRootIter: Iterator<Item = Result<(Hash256, Slot), Error>> = StateRootIterDefault<Error>,
> {
    state: BeaconState<Spec>,
    spec: &'a ChainSpec,
    state_processing_strategy: StateProcessingStrategy,
    block_sig_strategy: BlockSignatureStrategy,
    verify_block_root: Option<VerifyBlockRoot>,
    pre_block_hook: Option<PreBlockHook<'a, Spec, Error>>,
    post_block_hook: Option<PostBlockHook<'a, Spec, Error>>,
    pre_slot_hook: Option<PreSlotHook<'a, Spec, Error>>,
    post_slot_hook: Option<PostSlotHook<'a, Spec, Error>>,
    pub(crate) state_root_iter: Option<Peekable<StateRootIter>>,
    state_root_miss: bool,
    _phantom: PhantomData<Error>,
}

#[derive(Debug)]
pub enum BlockReplayError {
    NoBlocks,
    SlotProcessing(SlotProcessingError),
    BlockProcessing(BlockProcessingError),
}

impl From<SlotProcessingError> for BlockReplayError {
    fn from(e: SlotProcessingError) -> Self {
        Self::SlotProcessing(e)
    }
}

impl From<BlockProcessingError> for BlockReplayError {
    fn from(e: BlockProcessingError) -> Self {
        Self::BlockProcessing(e)
    }
}

/// Defines how state roots should be computed and whether to perform all state transitions during block replay.
#[derive(PartialEq, Clone, Copy)]
pub enum StateProcessingStrategy {
    /// Perform all transitions faithfully to the specification.
    Accurate,
    /// Don't compute state roots and process withdrawals, eventually computing an invalid beacon
    /// state that can only be used for obtaining shuffling.
    Inconsistent,
}

impl<'a, E, Error, StateRootIter> BlockReplayer<'a, E, Error, StateRootIter>
where
    E: EthSpec,
    StateRootIter: Iterator<Item = Result<(Hash256, Slot), Error>>,
    Error: From<BlockReplayError>,
{
    /// Create a new replayer that will apply blocks upon `state`.
    ///
    /// Defaults:
    ///
    /// - Full (bulk) signature verification
    /// - Accurate state roots
    /// - Full block root verification
    pub fn new(state: BeaconState<E>, spec: &'a ChainSpec) -> Self {
        Self {
            state,
            spec,
            state_processing_strategy: StateProcessingStrategy::Accurate,
            block_sig_strategy: BlockSignatureStrategy::VerifyBulk,
            verify_block_root: Some(VerifyBlockRoot::True),
            pre_block_hook: None,
            post_block_hook: None,
            pre_slot_hook: None,
            post_slot_hook: None,
            state_root_iter: None,
            state_root_miss: false,
            _phantom: PhantomData,
        }
    }

    /// Set the replayer's state processing strategy different from the default.
    pub fn state_processing_strategy(
        mut self,
        state_processing_strategy: StateProcessingStrategy,
    ) -> Self {
        if state_processing_strategy == StateProcessingStrategy::Inconsistent {
            self.verify_block_root = None;
        }
        self.state_processing_strategy = state_processing_strategy;
        self
    }

    /// Set the replayer's block signature verification strategy.
    pub fn block_signature_strategy(mut self, block_sig_strategy: BlockSignatureStrategy) -> Self {
        self.block_sig_strategy = block_sig_strategy;
        self
    }

    /// Disable signature verification during replay.
    ///
    /// If you are truly _replaying_ blocks then you will almost certainly want to disable
    /// signature checks for performance.
    pub fn no_signature_verification(self) -> Self {
        self.block_signature_strategy(BlockSignatureStrategy::NoVerification)
    }

    /// Verify only the block roots of the initial few blocks, and trust the rest.
    pub fn minimal_block_root_verification(mut self) -> Self {
        self.verify_block_root = None;
        self
    }

    /// Supply a state root iterator to accelerate slot processing.
    ///
    /// If possible the state root iterator should return a state root for every slot from
    /// `self.state.slot` to the `target_slot` supplied to `apply_blocks` (inclusive of both
    /// endpoints).
    pub fn state_root_iter(mut self, iter: StateRootIter) -> Self {
        self.state_root_iter = Some(iter.peekable());
        self
    }

    /// Run a function immediately before each block that is applied during `apply_blocks`.
    ///
    /// This can be used to inspect the state as blocks are applied.
    pub fn pre_block_hook(mut self, hook: PreBlockHook<'a, E, Error>) -> Self {
        self.pre_block_hook = Some(hook);
        self
    }

    /// Run a function immediately after each block that is applied during `apply_blocks`.
    ///
    /// This can be used to inspect the state as blocks are applied.
    pub fn post_block_hook(mut self, hook: PostBlockHook<'a, E, Error>) -> Self {
        self.post_block_hook = Some(hook);
        self
    }

    /// Run a function immediately before slot processing advances the state to the next slot.
    pub fn pre_slot_hook(mut self, hook: PreSlotHook<'a, E, Error>) -> Self {
        self.pre_slot_hook = Some(hook);
        self
    }

    /// Run a function immediately after slot processing has advanced the state to the next slot.
    ///
    /// The hook receives the state and a bool indicating if this state corresponds to a skipped
    /// slot (i.e. it will not have a block applied).
    pub fn post_slot_hook(mut self, hook: PostSlotHook<'a, E, Error>) -> Self {
        self.post_slot_hook = Some(hook);
        self
    }

    /// Compute the state root for `slot` as efficiently as possible.
    ///
    /// The `blocks` should be the full list of blocks being applied and `i` should be the index of
    /// the next block that will be applied, or `blocks.len()` if all blocks have already been
    /// applied.
    fn get_state_root(
        &mut self,
        slot: Slot,
        blocks: &[SignedBeaconBlock<E, BlindedPayload<E>>],
        i: usize,
    ) -> Result<Option<Hash256>, Error> {
        // If we don't care about state roots then return immediately.
        if self.state_processing_strategy == StateProcessingStrategy::Inconsistent {
            return Ok(Some(Hash256::zero()));
        }

        // If a state root iterator is configured, use it to find the root.
        if let Some(ref mut state_root_iter) = self.state_root_iter {
            let opt_root = state_root_iter
                .peeking_take_while(|res| res.as_ref().map_or(true, |(_, s)| *s <= slot))
                .find(|res| res.as_ref().map_or(true, |(_, s)| *s == slot))
                .transpose()?;

            if let Some((root, _)) = opt_root {
                return Ok(Some(root));
            }
        }

        // Otherwise try to source a root from the previous block.
        if let Some(prev_i) = i.checked_sub(1) {
            if let Some(prev_block) = blocks.get(prev_i) {
                if prev_block.slot() == slot {
                    return Ok(Some(prev_block.state_root()));
                }
            }
        }

        self.state_root_miss = true;
        Ok(None)
    }

    /// Apply `blocks` atop `self.state`, taking care of slot processing.
    ///
    /// If `target_slot` is provided then the state will be advanced through to `target_slot`
    /// after the blocks have been applied.
    pub fn apply_blocks(
        mut self,
        blocks: Vec<SignedBeaconBlock<E, BlindedPayload<E>>>,
        target_slot: Option<Slot>,
    ) -> Result<Self, Error> {
        for (i, block) in blocks.iter().enumerate() {
            // Allow one additional block at the start which is only used for its state root.
            if i == 0 && block.slot() <= self.state.slot() {
                continue;
            }

            while self.state.slot() < block.slot() {
                if let Some(ref mut pre_slot_hook) = self.pre_slot_hook {
                    pre_slot_hook(&mut self.state)?;
                }

                let state_root = self.get_state_root(self.state.slot(), &blocks, i)?;
                let summary = per_slot_processing(&mut self.state, state_root, self.spec)
                    .map_err(BlockReplayError::from)?;

                if let Some(ref mut post_slot_hook) = self.post_slot_hook {
                    let is_skipped_slot = self.state.slot() < block.slot();
                    post_slot_hook(&mut self.state, summary, is_skipped_slot)?;
                }
            }

            if let Some(ref mut pre_block_hook) = self.pre_block_hook {
                pre_block_hook(&mut self.state, block)?;
            }

            let verify_block_root = self.verify_block_root.unwrap_or_else(|| {
                // If no explicit policy is set, verify only the first 1 or 2 block roots if using
                // accurate state roots. Inaccurate state roots require block root verification to
                // be off.
                if i <= 1 && self.state_processing_strategy == StateProcessingStrategy::Accurate {
                    VerifyBlockRoot::True
                } else {
                    VerifyBlockRoot::False
                }
            });
            // Proposer index was already checked when this block was originally processed, we
            // can omit recomputing it during replay.
            let mut ctxt = ConsensusContext::new(block.slot())
                .set_proposer_index(block.message().proposer_index());
            per_block_processing(
                &mut self.state,
                block,
                self.block_sig_strategy,
                self.state_processing_strategy,
                verify_block_root,
                &mut ctxt,
                self.spec,
            )
            .map_err(BlockReplayError::from)?;

            if let Some(ref mut post_block_hook) = self.post_block_hook {
                post_block_hook(&mut self.state, block)?;
            }
        }

        if let Some(target_slot) = target_slot {
            while self.state.slot() < target_slot {
                if let Some(ref mut pre_slot_hook) = self.pre_slot_hook {
                    pre_slot_hook(&mut self.state)?;
                }

                let state_root = self.get_state_root(self.state.slot(), &blocks, blocks.len())?;
                let summary = per_slot_processing(&mut self.state, state_root, self.spec)
                    .map_err(BlockReplayError::from)?;

                if let Some(ref mut post_slot_hook) = self.post_slot_hook {
                    // No more blocks to apply (from our perspective) so we consider these slots
                    // skipped.
                    let is_skipped_slot = true;
                    post_slot_hook(&mut self.state, summary, is_skipped_slot)?;
                }
            }
        }

        Ok(self)
    }

    /// After block application, check if a state root miss occurred.
    pub fn state_root_miss(&self) -> bool {
        self.state_root_miss
    }

    /// Convert the replayer into the state that was built.
    pub fn into_state(self) -> BeaconState<E> {
        self.state
    }
}

impl<'a, E, Error> BlockReplayer<'a, E, Error, StateRootIterDefault<Error>>
where
    E: EthSpec,
    Error: From<BlockReplayError>,
{
    /// If type inference fails to infer the state root iterator type you can use this method
    /// to hint that no state root iterator is desired.
    pub fn no_state_root_iter(self) -> Self {
        self
    }
}
