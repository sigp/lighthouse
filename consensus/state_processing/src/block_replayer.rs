use crate::{
    BlockProcessingError, BlockSignatureStrategy, ConsensusContext, SlotProcessingError,
    VerifyBlockRoot, per_block_processing, per_epoch_processing::EpochProcessingSummary,
    per_slot_processing, process_execution_payload_envelope,
};
use itertools::Itertools;
use std::collections::HashMap;
use std::iter::Peekable;
use std::marker::PhantomData;
use types::{
    BeaconState, BeaconStateError, BlindedPayload, ChainSpec, EthSpec, ExecutionBlockHash,
    ExecutionPayloadEnvelope, Hash256, SignedBeaconBlock, Slot,
};

pub type PreBlockHook<'a, E, Error> = Box<
    dyn FnMut(&mut BeaconState<E>, &SignedBeaconBlock<E, BlindedPayload<E>>) -> Result<(), Error>
        + 'a,
>;
pub type PostBlockHook<'a, E, Error> = PreBlockHook<'a, E, Error>;
pub type PreSlotHook<'a, E, Error> =
    Box<dyn FnMut(Hash256, &mut BeaconState<E>) -> Result<(), Error> + 'a>;
pub type PostSlotHook<'a, E, Error> = Box<
    dyn FnMut(&mut BeaconState<E>, Option<EpochProcessingSummary<E>>, bool) -> Result<(), Error>
        + 'a,
>;
pub type StateRootIterDefault<Error> = std::iter::Empty<Result<(Hash256, Slot), Error>>;

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
    block_sig_strategy: BlockSignatureStrategy,
    verify_block_root: Option<VerifyBlockRoot>,
    pre_block_hook: Option<PreBlockHook<'a, Spec, Error>>,
    post_block_hook: Option<PostBlockHook<'a, Spec, Error>>,
    pre_slot_hook: Option<PreSlotHook<'a, Spec, Error>>,
    post_slot_hook: Option<PostSlotHook<'a, Spec, Error>>,
    pub(crate) state_root_iter: Option<Peekable<StateRootIter>>,
    state_root_miss: bool,
    /// Execution payload envelopes keyed by execution `block_hash` (the hash committed to in the
    /// builder's bid for that slot).  When the look-ahead determines that block N's payload was
    /// committed, the corresponding envelope is applied between block N and block N+1.
    payload_envelopes: HashMap<ExecutionBlockHash, ExecutionPayloadEnvelope<Spec>>,
    /// The first block *after* the replay range, used as the look-ahead for the last block in
    /// `apply_blocks` so that its envelope can also be applied when appropriate.
    lookahead_block: Option<SignedBeaconBlock<Spec, BlindedPayload<Spec>>>,
    _phantom: PhantomData<Error>,
}

#[derive(Debug)]
pub enum BlockReplayError {
    SlotProcessing(SlotProcessingError),
    BlockProcessing(BlockProcessingError),
    BeaconState(BeaconStateError),
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

impl From<BeaconStateError> for BlockReplayError {
    fn from(e: BeaconStateError) -> Self {
        Self::BeaconState(e)
    }
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
            block_sig_strategy: BlockSignatureStrategy::VerifyBulk,
            verify_block_root: Some(VerifyBlockRoot::True),
            pre_block_hook: None,
            post_block_hook: None,
            pre_slot_hook: None,
            post_slot_hook: None,
            state_root_iter: None,
            state_root_miss: false,
            payload_envelopes: HashMap::new(),
            lookahead_block: None,
            _phantom: PhantomData,
        }
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

    /// Supply a map of execution payload envelopes (EIP-7732 / Gloas) to be applied during replay.
    ///
    /// Envelopes are keyed by the execution `block_hash` that the builder committed to in the
    /// corresponding slot's `signed_execution_payload_bid`.  When the look-ahead logic determines
    /// that block N's payload was included, the matching envelope is applied between block N and
    /// block N+1 via `process_execution_payload_envelope`.
    pub fn payload_envelopes(
        mut self,
        envelopes: HashMap<ExecutionBlockHash, ExecutionPayloadEnvelope<E>>,
    ) -> Self {
        self.payload_envelopes = envelopes;
        self
    }

    /// Supply the first block *after* the replay range as a look-ahead sentinel.
    ///
    /// This allows the last block in `apply_blocks` to also have its execution payload envelope
    /// applied when the next proposer built on it.
    pub fn lookahead_block(mut self, block: SignedBeaconBlock<E, BlindedPayload<E>>) -> Self {
        self.lookahead_block = Some(block);
        self
    }

    /// Compute the state root for `self.state` as efficiently as possible.
    ///
    /// This function MUST only be called when `self.state` is a post-state, i.e. it MUST not be
    /// called between advancing a state with `per_slot_processing` and applying the block for that
    /// slot.
    ///
    /// The `blocks` should be the full list of blocks being applied and `i` should be the index of
    /// the next block that will be applied, or `blocks.len()` if all blocks have already been
    /// applied.
    ///
    /// If the state root is not available from the state root iterator or the blocks then it will
    /// be computed from `self.state` and a state root iterator miss will be recorded.
    fn get_state_root(
        &mut self,
        blocks: &[SignedBeaconBlock<E, BlindedPayload<E>>],
        i: usize,
    ) -> Result<Hash256, Error> {
        let slot = self.state.slot();

        // If a state root iterator is configured, use it to find the root.
        if let Some(ref mut state_root_iter) = self.state_root_iter {
            let opt_root = state_root_iter
                .peeking_take_while(|res| res.as_ref().map_or(true, |(_, s)| *s <= slot))
                .find(|res| res.as_ref().map_or(true, |(_, s)| *s == slot))
                .transpose()?;

            if let Some((root, _)) = opt_root {
                return Ok(root);
            }
        }

        // Otherwise try to source a root from the previous block.
        if let Some(prev_i) = i.checked_sub(1)
            && let Some(prev_block) = blocks.get(prev_i)
            && prev_block.slot() == slot
        {
            return Ok(prev_block.state_root());
        }

        self.state_root_miss = true;
        let state_root = self
            .state
            .update_tree_hash_cache()
            .map_err(BlockReplayError::from)?;
        Ok(state_root)
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
                let state_root = self.get_state_root(&blocks, i)?;

                if let Some(ref mut pre_slot_hook) = self.pre_slot_hook {
                    pre_slot_hook(state_root, &mut self.state)?;
                }

                let summary = per_slot_processing(&mut self.state, Some(state_root), self.spec)
                    .map_err(BlockReplayError::from)?;

                if let Some(ref mut post_slot_hook) = self.post_slot_hook {
                    let is_skipped_slot = self.state.slot() < block.slot();
                    post_slot_hook(&mut self.state, summary, is_skipped_slot)?;
                }
            }

            if let Some(ref mut pre_block_hook) = self.pre_block_hook {
                pre_block_hook(&mut self.state, block)?;
            }

            // If no explicit policy is set, verify only the first 1 or 2 block roots.
            let verify_block_root = self.verify_block_root.unwrap_or(if i <= 1 {
                VerifyBlockRoot::True
            } else {
                VerifyBlockRoot::False
            });
            // Proposer index was already checked when this block was originally processed, we
            // can omit recomputing it during replay.
            let mut ctxt = ConsensusContext::new(block.slot())
                .set_proposer_index(block.message().proposer_index());
            per_block_processing(
                &mut self.state,
                block,
                self.block_sig_strategy,
                verify_block_root,
                &mut ctxt,
                self.spec,
            )
            .map_err(BlockReplayError::from)?;

            if let Some(ref mut post_block_hook) = self.post_block_hook {
                post_block_hook(&mut self.state, block)?;
            }

            // EIP-7732 (Gloas) look-ahead: determine whether block N's execution payload
            // envelope should be applied before we process block N+1.
            //
            // The decision rule: if the next block's builder bid says its *parent* execution
            // hash is equal to the hash that the *current* block's builder promised to deliver,
            // then the current block's payload was committed and we must apply the envelope now.
            //
            // We look at `blocks[i+1]` first; if this is the last block we fall back to
            // `self.lookahead_block` (the first block after the replay range).
            if self.state.fork_name_unchecked().gloas_enabled()
                && !self.payload_envelopes.is_empty()
            {
                let next_idx = i.saturating_add(1);
                let next_block = blocks.get(next_idx).or(self.lookahead_block.as_ref());

                // Extract the next block's bid parent_block_hash, if it is a Gloas block.
                let next_parent_block_hash = next_block.and_then(|nb| match nb.message().body() {
                    types::BeaconBlockBodyRef::Gloas(body) => {
                        Some(body.signed_execution_payload_bid.message.parent_block_hash)
                    }
                    _ => None,
                });

                // The hash that the current block's builder promised to deliver.
                let current_bid_block_hash = if let types::BeaconState::Gloas(gs) = &self.state {
                    Some(gs.latest_execution_payload_bid.block_hash)
                } else {
                    None
                };

                // If the next block builds on this slot's promised payload, apply the envelope.
                if let (Some(next_parent), Some(bid_hash)) =
                    (next_parent_block_hash, current_bid_block_hash)
                    && next_parent == bid_hash
                    && let Some(envelope) = self.payload_envelopes.get(&bid_hash)
                {
                    let envelope = envelope.clone();
                    process_execution_payload_envelope(&mut self.state, &envelope, self.spec)
                        .map_err(BlockReplayError::from)?;
                }
            }
        }

        if let Some(target_slot) = target_slot {
            while self.state.slot() < target_slot {
                let state_root = self.get_state_root(&blocks, blocks.len())?;

                if let Some(ref mut pre_slot_hook) = self.pre_slot_hook {
                    pre_slot_hook(state_root, &mut self.state)?;
                }

                let summary = per_slot_processing(&mut self.state, Some(state_root), self.spec)
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

impl<E, Error> BlockReplayer<'_, E, Error, StateRootIterDefault<Error>>
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
