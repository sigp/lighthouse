//! Provides `SignedBeaconBlock` verification logic.
//!
//! Specifically, it provides the following:
//!
//! - Verification for gossip blocks (i.e., should we gossip some block from the network).
//! - Verification for normal blocks (e.g., some block received on the RPC during a parent lookup).
//! - Verification for chain segments (e.g., some chain of blocks received on the RPC during a
//!    sync).
//!
//! The primary source of complexity here is that we wish to avoid doing duplicate work as a block
//! moves through the verification process. For example, if some block is verified for gossip, we
//! do not wish to re-verify the block proposal signature or re-hash the block. Or, if we've
//! verified the signatures of a block during a chain segment import, we do not wish to verify each
//! signature individually again.
//!
//! The incremental processing steps (e.g., signatures verified but not the state transition) is
//! represented as a sequence of wrapper-types around the block. There is a linear progression of
//! types, starting at a `SignedBeaconBlock` and finishing with a `Fully VerifiedBlock` (see
//! diagram below).
//!
//! ```ignore
//!           START
//!             |
//!             ▼
//!     SignedBeaconBlock
//!             |---------------
//!             |              |
//!             |              ▼
//!             |      GossipVerifiedBlock
//!             |              |
//!             |---------------
//!             |
//!             ▼
//!     SignatureVerifiedBlock
//!             |
//!             ▼
//!      FullyVerifiedBlock
//!             |
//!             ▼
//!            END
//!
//! ```
use crate::snapshot_cache::PreProcessingSnapshot;
use crate::validator_monitor::HISTORIC_EPOCHS as VALIDATOR_MONITOR_HISTORIC_EPOCHS;
use crate::validator_pubkey_cache::ValidatorPubkeyCache;
use crate::{
    beacon_chain::{
        BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT, MAXIMUM_GOSSIP_CLOCK_DISPARITY,
        VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT,
    },
    metrics, BeaconChain, BeaconChainError, BeaconChainTypes,
};
use fork_choice::{ForkChoice, ForkChoiceStore};
use parking_lot::RwLockReadGuard;
use proto_array::Block as ProtoBlock;
use slog::{debug, error, Logger};
use slot_clock::SlotClock;
use ssz::Encode;
use state_processing::{
    block_signature_verifier::{BlockSignatureVerifier, Error as BlockSignatureVerifierError},
    per_block_processing, per_slot_processing,
    state_advance::partial_state_advance,
    BlockProcessingError, BlockSignatureStrategy, SlotProcessingError,
};
use std::borrow::Cow;
use std::fs;
use std::io::Write;
use store::{Error as DBError, HotColdDB, HotStateSummary, KeyValueStore, StoreOp};
use tree_hash::TreeHash;
use types::{
    BeaconBlockRef, BeaconState, BeaconStateError, ChainSpec, CloneConfig, Epoch, EthSpec, Hash256,
    InconsistentFork, PublicKey, PublicKeyBytes, RelativeEpoch, SignedBeaconBlock,
    SignedBeaconBlockHeader, Slot,
};

/// Maximum block slot number. Block with slots bigger than this constant will NOT be processed.
const MAXIMUM_BLOCK_SLOT_NUMBER: u64 = 4_294_967_296; // 2^32

/// If true, everytime a block is processed the pre-state, post-state and block are written to SSZ
/// files in the temp directory.
///
/// Only useful for testing.
const WRITE_BLOCK_PROCESSING_SSZ: bool = cfg!(feature = "write_ssz_files");

/// Returned when a block was not verified. A block is not verified for two reasons:
///
/// - The block is malformed/invalid (indicated by all results other than `BeaconChainError`.
/// - We encountered an error whilst trying to verify the block (a `BeaconChainError`).
#[derive(Debug)]
pub enum BlockError<T: EthSpec> {
    /// The parent block was unknown.
    ///
    /// ## Peer scoring
    ///
    /// It's unclear if this block is valid, but it cannot be processed without already knowing
    /// its parent.
    ParentUnknown(Box<SignedBeaconBlock<T>>),
    /// The block skips too many slots and is a DoS risk.
    TooManySkippedSlots { parent_slot: Slot, block_slot: Slot },
    /// The block slot is greater than the present slot.
    ///
    /// ## Peer scoring
    ///
    /// Assuming the local clock is correct, the peer has sent an invalid message.
    FutureSlot {
        present_slot: Slot,
        block_slot: Slot,
    },
    /// The block state_root does not match the generated state.
    ///
    /// ## Peer scoring
    ///
    /// The peer has incompatible state transition logic and is faulty.
    StateRootMismatch { block: Hash256, local: Hash256 },
    /// The block was a genesis block, these blocks cannot be re-imported.
    GenesisBlock,
    /// The slot is finalized, no need to import.
    ///
    /// ## Peer scoring
    ///
    /// It's unclear if this block is valid, but this block is for a finalized slot and is
    /// therefore useless to us.
    WouldRevertFinalizedSlot {
        block_slot: Slot,
        finalized_slot: Slot,
    },
    /// The block conflicts with finalization, no need to propagate.
    ///
    /// ## Peer scoring
    ///
    /// It's unclear if this block is valid, but it conflicts with finality and shouldn't be
    /// imported.
    NotFinalizedDescendant { block_parent_root: Hash256 },
    /// Block is already known, no need to re-import.
    ///
    /// ## Peer scoring
    ///
    /// The block is valid and we have already imported a block with this hash.
    BlockIsAlreadyKnown,
    /// A block for this proposer and slot has already been observed.
    ///
    /// ## Peer scoring
    ///
    /// The `proposer` has already proposed a block at this slot. The existing block may or may not
    /// be equal to the given block.
    RepeatProposal { proposer: u64, slot: Slot },
    /// The block slot exceeds the MAXIMUM_BLOCK_SLOT_NUMBER.
    ///
    /// ## Peer scoring
    ///
    /// We set a very, very high maximum slot number and this block exceeds it. There's no good
    /// reason to be sending these blocks, they're from future slots.
    ///
    /// The block is invalid and the peer is faulty.
    BlockSlotLimitReached,
    /// The `BeaconBlock` has a `proposer_index` that does not match the index we computed locally.
    ///
    /// ## Peer scoring
    ///
    /// The block is invalid and the peer is faulty.
    IncorrectBlockProposer { block: u64, local_shuffling: u64 },
    /// The proposal signature in invalid.
    ///
    /// ## Peer scoring
    ///
    /// The block is invalid and the peer is faulty.
    ProposalSignatureInvalid,
    /// The `block.proposal_index` is not known.
    ///
    /// ## Peer scoring
    ///
    /// The block is invalid and the peer is faulty.
    UnknownValidator(u64),
    /// A signature in the block is invalid (exactly which is unknown).
    ///
    /// ## Peer scoring
    ///
    /// The block is invalid and the peer is faulty.
    InvalidSignature,
    /// The provided block is from an later slot than its parent.
    ///
    /// ## Peer scoring
    ///
    /// The block is invalid and the peer is faulty.
    BlockIsNotLaterThanParent { block_slot: Slot, parent_slot: Slot },
    /// At least one block in the chain segment did not have it's parent root set to the root of
    /// the prior block.
    ///
    /// ## Peer scoring
    ///
    /// The chain of blocks is invalid and the peer is faulty.
    NonLinearParentRoots,
    /// The slots of the blocks in the chain segment were not strictly increasing. I.e., a child
    /// had lower slot than a parent.
    ///
    /// ## Peer scoring
    ///
    /// The chain of blocks is invalid and the peer is faulty.
    NonLinearSlots,
    /// The block failed the specification's `per_block_processing` function, it is invalid.
    ///
    /// ## Peer scoring
    ///
    /// The block is invalid and the peer is faulty.
    PerBlockProcessingError(BlockProcessingError),
    /// There was an error whilst processing the block. It is not necessarily invalid.
    ///
    /// ## Peer scoring
    ///
    /// We were unable to process this block due to an internal error. It's unclear if the block is
    /// valid.
    BeaconChainError(BeaconChainError),
    /// There was an error whilst verifying weak subjectivity. This block conflicts with the
    /// configured weak subjectivity checkpoint and was not imported.
    ///
    /// ## Peer scoring
    ///
    /// The block is invalid and the peer is faulty.
    WeakSubjectivityConflict,
    /// The block has the wrong structure for the fork at `block.slot`.
    ///
    /// ## Peer scoring
    ///
    /// The block is invalid and the peer is faulty.
    InconsistentFork(InconsistentFork),
}

impl<T: EthSpec> std::fmt::Display for BlockError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockError::ParentUnknown(block) => {
                write!(f, "ParentUnknown(parent_root:{})", block.parent_root())
            }
            other => write!(f, "{:?}", other),
        }
    }
}

impl<T: EthSpec> From<BlockSignatureVerifierError> for BlockError<T> {
    fn from(e: BlockSignatureVerifierError) -> Self {
        match e {
            // Make a special distinction for `IncorrectBlockProposer` since it indicates an
            // invalid block, not an internal error.
            BlockSignatureVerifierError::IncorrectBlockProposer {
                block,
                local_shuffling,
            } => BlockError::IncorrectBlockProposer {
                block,
                local_shuffling,
            },
            e => BlockError::BeaconChainError(BeaconChainError::BlockSignatureVerifierError(e)),
        }
    }
}

impl<T: EthSpec> From<BeaconChainError> for BlockError<T> {
    fn from(e: BeaconChainError) -> Self {
        BlockError::BeaconChainError(e)
    }
}

impl<T: EthSpec> From<BeaconStateError> for BlockError<T> {
    fn from(e: BeaconStateError) -> Self {
        BlockError::BeaconChainError(BeaconChainError::BeaconStateError(e))
    }
}

impl<T: EthSpec> From<SlotProcessingError> for BlockError<T> {
    fn from(e: SlotProcessingError) -> Self {
        BlockError::BeaconChainError(BeaconChainError::SlotProcessingError(e))
    }
}

impl<T: EthSpec> From<DBError> for BlockError<T> {
    fn from(e: DBError) -> Self {
        BlockError::BeaconChainError(BeaconChainError::DBError(e))
    }
}

/// Information about invalid blocks which might still be slashable despite being invalid.
#[allow(clippy::enum_variant_names)]
pub enum BlockSlashInfo<TErr> {
    /// The block is invalid, but its proposer signature wasn't checked.
    SignatureNotChecked(SignedBeaconBlockHeader, TErr),
    /// The block's proposer signature is invalid, so it will never be slashable.
    SignatureInvalid(TErr),
    /// The signature is valid but the attestation is invalid in some other way.
    SignatureValid(SignedBeaconBlockHeader, TErr),
}

impl<E: EthSpec> BlockSlashInfo<BlockError<E>> {
    pub fn from_early_error(header: SignedBeaconBlockHeader, e: BlockError<E>) -> Self {
        match e {
            BlockError::ProposalSignatureInvalid => BlockSlashInfo::SignatureInvalid(e),
            // `InvalidSignature` could indicate any signature in the block, so we want
            // to recheck the proposer signature alone.
            _ => BlockSlashInfo::SignatureNotChecked(header, e),
        }
    }
}

/// Process invalid blocks to see if they are suitable for the slasher.
///
/// If no slasher is configured, this is a no-op.
fn process_block_slash_info<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    slash_info: BlockSlashInfo<BlockError<T::EthSpec>>,
) -> BlockError<T::EthSpec> {
    if let Some(slasher) = chain.slasher.as_ref() {
        let (verified_header, error) = match slash_info {
            BlockSlashInfo::SignatureNotChecked(header, e) => {
                if verify_header_signature(chain, &header).is_ok() {
                    (header, e)
                } else {
                    return e;
                }
            }
            BlockSlashInfo::SignatureInvalid(e) => return e,
            BlockSlashInfo::SignatureValid(header, e) => (header, e),
        };

        slasher.accept_block_header(verified_header);
        error
    } else {
        match slash_info {
            BlockSlashInfo::SignatureNotChecked(_, e)
            | BlockSlashInfo::SignatureInvalid(e)
            | BlockSlashInfo::SignatureValid(_, e) => e,
        }
    }
}

/// Verify all signatures (except deposit signatures) on all blocks in the `chain_segment`. If all
/// signatures are valid, the `chain_segment` is mapped to a `Vec<SignatureVerifiedBlock>` that can
/// later be transformed into a `FullyVerifiedBlock` without re-checking the signatures. If any
/// signature in the block is invalid, an `Err` is returned (it is not possible to known _which_
/// signature was invalid).
///
/// ## Errors
///
/// The given `chain_segment` must span no more than two epochs, otherwise an error will be
/// returned.
pub fn signature_verify_chain_segment<T: BeaconChainTypes>(
    mut chain_segment: Vec<(Hash256, SignedBeaconBlock<T::EthSpec>)>,
    chain: &BeaconChain<T>,
) -> Result<Vec<SignatureVerifiedBlock<T>>, BlockError<T::EthSpec>> {
    if chain_segment.is_empty() {
        return Ok(vec![]);
    }

    let (first_root, first_block) = chain_segment.remove(0);
    let (mut parent, first_block) = load_parent(first_block, chain)?;
    let slot = first_block.slot();
    chain_segment.insert(0, (first_root, first_block));

    let highest_slot = chain_segment
        .last()
        .map(|(_, block)| block.slot())
        .unwrap_or_else(|| slot);

    let state = cheap_state_advance_to_obtain_committees(
        &mut parent.pre_state,
        parent.beacon_state_root,
        highest_slot,
        &chain.spec,
    )?;

    let pubkey_cache = get_validator_pubkey_cache(chain)?;
    let mut signature_verifier = get_signature_verifier(&state, &pubkey_cache, &chain.spec);

    for (block_root, block) in &chain_segment {
        signature_verifier.include_all_signatures(block, Some(*block_root))?;
    }

    if signature_verifier.verify().is_err() {
        return Err(BlockError::InvalidSignature);
    }

    drop(pubkey_cache);

    let mut signature_verified_blocks = chain_segment
        .into_iter()
        .map(|(block_root, block)| SignatureVerifiedBlock {
            block,
            block_root,
            parent: None,
        })
        .collect::<Vec<_>>();

    if let Some(signature_verified_block) = signature_verified_blocks.first_mut() {
        signature_verified_block.parent = Some(parent);
    }

    Ok(signature_verified_blocks)
}

/// A wrapper around a `SignedBeaconBlock` that indicates it has been approved for re-gossiping on
/// the p2p network.
#[derive(Debug)]
pub struct GossipVerifiedBlock<T: BeaconChainTypes> {
    pub block: SignedBeaconBlock<T::EthSpec>,
    pub block_root: Hash256,
    parent: Option<PreProcessingSnapshot<T::EthSpec>>,
}

/// A wrapper around a `SignedBeaconBlock` that indicates that all signatures (except the deposit
/// signatures) have been verified.
pub struct SignatureVerifiedBlock<T: BeaconChainTypes> {
    block: SignedBeaconBlock<T::EthSpec>,
    block_root: Hash256,
    parent: Option<PreProcessingSnapshot<T::EthSpec>>,
}

/// A wrapper around a `SignedBeaconBlock` that indicates that this block is fully verified and
/// ready to import into the `BeaconChain`. The validation includes:
///
/// - Parent is known
/// - Signatures
/// - State root check
/// - Per block processing
///
/// Note: a `FullyVerifiedBlock` is not _forever_ valid to be imported, it may later become invalid
/// due to finality or some other event. A `FullyVerifiedBlock` should be imported into the
/// `BeaconChain` immediately after it is instantiated.
pub struct FullyVerifiedBlock<'a, T: BeaconChainTypes> {
    pub block: SignedBeaconBlock<T::EthSpec>,
    pub block_root: Hash256,
    pub state: BeaconState<T::EthSpec>,
    pub parent_block: SignedBeaconBlock<T::EthSpec>,
    pub confirmation_db_batch: Vec<StoreOp<'a, T::EthSpec>>,
}

/// Implemented on types that can be converted into a `FullyVerifiedBlock`.
///
/// Used to allow functions to accept blocks at various stages of verification.
pub trait IntoFullyVerifiedBlock<T: BeaconChainTypes>: Sized {
    fn into_fully_verified_block(
        self,
        chain: &BeaconChain<T>,
    ) -> Result<FullyVerifiedBlock<T>, BlockError<T::EthSpec>> {
        self.into_fully_verified_block_slashable(chain)
            .map(|fully_verified| {
                // Supply valid block to slasher.
                if let Some(slasher) = chain.slasher.as_ref() {
                    slasher.accept_block_header(fully_verified.block.signed_block_header());
                }
                fully_verified
            })
            .map_err(|slash_info| process_block_slash_info(chain, slash_info))
    }

    /// Convert the block to fully-verified form while producing data to aid checking slashability.
    fn into_fully_verified_block_slashable(
        self,
        chain: &BeaconChain<T>,
    ) -> Result<FullyVerifiedBlock<T>, BlockSlashInfo<BlockError<T::EthSpec>>>;

    fn block(&self) -> &SignedBeaconBlock<T::EthSpec>;
}

impl<T: BeaconChainTypes> GossipVerifiedBlock<T> {
    /// Instantiates `Self`, a wrapper that indicates the given `block` is safe to be re-gossiped
    /// on the p2p network.
    ///
    /// Returns an error if the block is invalid, or if the block was unable to be verified.
    pub fn new(
        block: SignedBeaconBlock<T::EthSpec>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, BlockError<T::EthSpec>> {
        // If the block is valid for gossip we don't supply it to the slasher here because
        // we assume it will be transformed into a fully verified block. We *do* need to supply
        // it to the slasher if an error occurs, because that's the end of this block's journey,
        // and it could be a repeat proposal (a likely cause for slashing!).
        let header = block.signed_block_header();
        Self::new_without_slasher_checks(block, chain).map_err(|e| {
            process_block_slash_info(chain, BlockSlashInfo::from_early_error(header, e))
        })
    }

    /// As for new, but doesn't pass the block to the slasher.
    fn new_without_slasher_checks(
        block: SignedBeaconBlock<T::EthSpec>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, BlockError<T::EthSpec>> {
        // Ensure the block is the correct structure for the fork at `block.slot()`.
        block
            .fork_name(&chain.spec)
            .map_err(BlockError::InconsistentFork)?;

        // Do not gossip or process blocks from future slots.
        let present_slot_with_tolerance = chain
            .slot_clock
            .now_with_future_tolerance(MAXIMUM_GOSSIP_CLOCK_DISPARITY)
            .ok_or(BeaconChainError::UnableToReadSlot)?;
        if block.slot() > present_slot_with_tolerance {
            return Err(BlockError::FutureSlot {
                present_slot: present_slot_with_tolerance,
                block_slot: block.slot(),
            });
        }

        let block_root = get_block_root(&block);

        // Disallow blocks that conflict with the anchor (weak subjectivity checkpoint), if any.
        check_block_against_anchor_slot(block.message(), chain)?;

        // Do not gossip a block from a finalized slot.
        check_block_against_finalized_slot(block.message(), chain)?;

        // Check if the block is already known. We know it is post-finalization, so it is
        // sufficient to check the fork choice.
        //
        // In normal operation this isn't necessary, however it is useful immediately after a
        // reboot if the `observed_block_producers` cache is empty. In that case, without this
        // check, we will load the parent and state from disk only to find out later that we
        // already know this block.
        if chain.fork_choice.read().contains_block(&block_root) {
            return Err(BlockError::BlockIsAlreadyKnown);
        }

        // Check that we have not already received a block with a valid signature for this slot.
        if chain
            .observed_block_producers
            .read()
            .proposer_has_been_observed(block.message())
            .map_err(|e| BlockError::BeaconChainError(e.into()))?
        {
            return Err(BlockError::RepeatProposal {
                proposer: block.message().proposer_index(),
                slot: block.slot(),
            });
        }

        // Do not process a block that doesn't descend from the finalized root.
        //
        // We check this *before* we load the parent so that we can return a more detailed error.
        let block = check_block_is_finalized_descendant::<T, _>(
            block,
            &chain.fork_choice.read(),
            &chain.store,
        )?;

        let block_epoch = block.slot().epoch(T::EthSpec::slots_per_epoch());
        let (parent_block, block) = verify_parent_block_is_known(chain, block)?;

        // Track the number of skip slots between the block and its parent.
        metrics::set_gauge(
            &metrics::GOSSIP_BEACON_BLOCK_SKIPPED_SLOTS,
            block
                .slot()
                .as_u64()
                .saturating_sub(1)
                .saturating_sub(parent_block.slot.into()) as i64,
        );

        // Paranoid check to prevent propagation of blocks that don't form a legitimate chain.
        //
        // This is not in the spec, but @protolambda tells me that the majority of other clients are
        // already doing it. For reference:
        //
        // https://github.com/ethereum/eth2.0-specs/pull/2196
        if parent_block.slot >= block.slot() {
            return Err(BlockError::BlockIsNotLaterThanParent {
                block_slot: block.slot(),
                parent_slot: parent_block.slot,
            });
        }

        let proposer_shuffling_decision_block =
            if parent_block.slot.epoch(T::EthSpec::slots_per_epoch()) == block_epoch {
                parent_block
                    .next_epoch_shuffling_id
                    .shuffling_decision_block
            } else {
                parent_block.root
            };

        // Reject any block that exceeds our limit on skipped slots.
        check_block_skip_slots(chain, parent_block.slot, block.message())?;

        // We assign to a variable instead of using `if let Some` directly to ensure we drop the
        // write lock before trying to acquire it again in the `else` clause.
        let proposer_opt = chain
            .beacon_proposer_cache
            .lock()
            .get_slot::<T::EthSpec>(proposer_shuffling_decision_block, block.slot());
        let (expected_proposer, fork, parent, block) = if let Some(proposer) = proposer_opt {
            // The proposer index was cached and we can return it without needing to load the
            // parent.
            (proposer.index, proposer.fork, None, block)
        } else {
            // The proposer index was *not* cached and we must load the parent in order to determine
            // the proposer index.
            let (mut parent, block) = load_parent(block, chain)?;

            debug!(
                chain.log,
                "Proposer shuffling cache miss";
                "parent_root" => ?parent.beacon_block_root,
                "parent_slot" => parent.beacon_block.slot(),
                "block_root" => ?block_root,
                "block_slot" => block.slot(),
            );

            // The state produced is only valid for determining proposer/attester shuffling indices.
            let state = cheap_state_advance_to_obtain_committees(
                &mut parent.pre_state,
                parent.beacon_state_root,
                block.slot(),
                &chain.spec,
            )?;

            let proposers = state.get_beacon_proposer_indices(&chain.spec)?;
            let proposer_index = *proposers
                .get(block.slot().as_usize() % T::EthSpec::slots_per_epoch() as usize)
                .ok_or_else(|| BeaconChainError::NoProposerForSlot(block.slot()))?;

            // Prime the proposer shuffling cache with the newly-learned value.
            chain.beacon_proposer_cache.lock().insert(
                block_epoch,
                proposer_shuffling_decision_block,
                proposers,
                state.fork(),
            )?;

            (proposer_index, state.fork(), Some(parent), block)
        };

        let signature_is_valid = {
            let pubkey_cache = get_validator_pubkey_cache(chain)?;
            let pubkey = pubkey_cache
                .get(block.message().proposer_index() as usize)
                .ok_or_else(|| BlockError::UnknownValidator(block.message().proposer_index()))?;
            block.verify_signature(
                Some(block_root),
                pubkey,
                &fork,
                chain.genesis_validators_root,
                &chain.spec,
            )
        };

        if !signature_is_valid {
            return Err(BlockError::ProposalSignatureInvalid);
        }

        // Now the signature is valid, store the proposal so we don't accept another from this
        // validator and slot.
        //
        // It's important to double-check that the proposer still hasn't been observed so we don't
        // have a race-condition when verifying two blocks simultaneously.
        if chain
            .observed_block_producers
            .write()
            .observe_proposer(block.message())
            .map_err(|e| BlockError::BeaconChainError(e.into()))?
        {
            return Err(BlockError::RepeatProposal {
                proposer: block.message().proposer_index(),
                slot: block.slot(),
            });
        }

        if block.message().proposer_index() != expected_proposer as u64 {
            return Err(BlockError::IncorrectBlockProposer {
                block: block.message().proposer_index(),
                local_shuffling: expected_proposer as u64,
            });
        }

        Ok(Self {
            block,
            block_root,
            parent,
        })
    }

    pub fn block_root(&self) -> Hash256 {
        self.block_root
    }
}

impl<T: BeaconChainTypes> IntoFullyVerifiedBlock<T> for GossipVerifiedBlock<T> {
    /// Completes verification of the wrapped `block`.
    fn into_fully_verified_block_slashable(
        self,
        chain: &BeaconChain<T>,
    ) -> Result<FullyVerifiedBlock<T>, BlockSlashInfo<BlockError<T::EthSpec>>> {
        let fully_verified =
            SignatureVerifiedBlock::from_gossip_verified_block_check_slashable(self, chain)?;
        fully_verified.into_fully_verified_block_slashable(chain)
    }

    fn block(&self) -> &SignedBeaconBlock<T::EthSpec> {
        &self.block
    }
}

impl<T: BeaconChainTypes> SignatureVerifiedBlock<T> {
    /// Instantiates `Self`, a wrapper that indicates that all signatures (except the deposit
    /// signatures) are valid  (i.e., signed by the correct public keys).
    ///
    /// Returns an error if the block is invalid, or if the block was unable to be verified.
    pub fn new(
        block: SignedBeaconBlock<T::EthSpec>,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> Result<Self, BlockError<T::EthSpec>> {
        // Ensure the block is the correct structure for the fork at `block.slot()`.
        block
            .fork_name(&chain.spec)
            .map_err(BlockError::InconsistentFork)?;

        // Check the anchor slot before loading the parent, to avoid spurious lookups.
        check_block_against_anchor_slot(block.message(), chain)?;

        let (mut parent, block) = load_parent(block, chain)?;

        // Reject any block that exceeds our limit on skipped slots.
        check_block_skip_slots(chain, parent.beacon_block.slot(), block.message())?;

        let state = cheap_state_advance_to_obtain_committees(
            &mut parent.pre_state,
            parent.beacon_state_root,
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
            Err(BlockError::InvalidSignature)
        }
    }

    /// As for `new` above but producing `BlockSlashInfo`.
    pub fn check_slashable(
        block: SignedBeaconBlock<T::EthSpec>,
        block_root: Hash256,
        chain: &BeaconChain<T>,
    ) -> Result<Self, BlockSlashInfo<BlockError<T::EthSpec>>> {
        let header = block.signed_block_header();
        Self::new(block, block_root, chain).map_err(|e| BlockSlashInfo::from_early_error(header, e))
    }

    /// Finishes signature verification on the provided `GossipVerifedBlock`. Does not re-verify
    /// the proposer signature.
    pub fn from_gossip_verified_block(
        from: GossipVerifiedBlock<T>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, BlockError<T::EthSpec>> {
        let (mut parent, block) = if let Some(parent) = from.parent {
            (parent, from.block)
        } else {
            load_parent(from.block, chain)?
        };

        let state = cheap_state_advance_to_obtain_committees(
            &mut parent.pre_state,
            parent.beacon_state_root,
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
            Err(BlockError::InvalidSignature)
        }
    }

    /// Same as `from_gossip_verified_block` but producing slashing-relevant data as well.
    pub fn from_gossip_verified_block_check_slashable(
        from: GossipVerifiedBlock<T>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, BlockSlashInfo<BlockError<T::EthSpec>>> {
        let header = from.block.signed_block_header();
        Self::from_gossip_verified_block(from, chain)
            .map_err(|e| BlockSlashInfo::from_early_error(header, e))
    }
}

impl<T: BeaconChainTypes> IntoFullyVerifiedBlock<T> for SignatureVerifiedBlock<T> {
    /// Completes verification of the wrapped `block`.
    fn into_fully_verified_block_slashable(
        self,
        chain: &BeaconChain<T>,
    ) -> Result<FullyVerifiedBlock<T>, BlockSlashInfo<BlockError<T::EthSpec>>> {
        let header = self.block.signed_block_header();
        let (parent, block) = if let Some(parent) = self.parent {
            (parent, self.block)
        } else {
            load_parent(self.block, chain)
                .map_err(|e| BlockSlashInfo::SignatureValid(header.clone(), e))?
        };

        FullyVerifiedBlock::from_signature_verified_components(
            block,
            self.block_root,
            parent,
            chain,
        )
        .map_err(|e| BlockSlashInfo::SignatureValid(header, e))
    }

    fn block(&self) -> &SignedBeaconBlock<T::EthSpec> {
        &self.block
    }
}

impl<T: BeaconChainTypes> IntoFullyVerifiedBlock<T> for SignedBeaconBlock<T::EthSpec> {
    /// Verifies the `SignedBeaconBlock` by first transforming it into a `SignatureVerifiedBlock`
    /// and then using that implementation of `IntoFullyVerifiedBlock` to complete verification.
    fn into_fully_verified_block_slashable(
        self,
        chain: &BeaconChain<T>,
    ) -> Result<FullyVerifiedBlock<T>, BlockSlashInfo<BlockError<T::EthSpec>>> {
        // Perform an early check to prevent wasting time on irrelevant blocks.
        let block_root = check_block_relevancy(&self, None, chain)
            .map_err(|e| BlockSlashInfo::SignatureNotChecked(self.signed_block_header(), e))?;

        SignatureVerifiedBlock::check_slashable(self, block_root, chain)?
            .into_fully_verified_block_slashable(chain)
    }

    fn block(&self) -> &SignedBeaconBlock<T::EthSpec> {
        self
    }
}

impl<'a, T: BeaconChainTypes> FullyVerifiedBlock<'a, T> {
    /// Instantiates `Self`, a wrapper that indicates that the given `block` is fully valid. See
    /// the struct-level documentation for more information.
    ///
    /// Note: this function does not verify block signatures, it assumes they are valid. Signature
    /// verification must be done upstream (e.g., via a `SignatureVerifiedBlock`
    ///
    /// Returns an error if the block is invalid, or if the block was unable to be verified.
    pub fn from_signature_verified_components(
        block: SignedBeaconBlock<T::EthSpec>,
        block_root: Hash256,
        parent: PreProcessingSnapshot<T::EthSpec>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, BlockError<T::EthSpec>> {
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
        if !chain
            .fork_choice
            .read()
            .contains_block(&block.parent_root())
        {
            return Err(BlockError::ParentUnknown(Box::new(block)));
        }

        // Reject any block that exceeds our limit on skipped slots.
        check_block_skip_slots(chain, parent.beacon_block.slot(), block.message())?;

        /*
         *  Perform cursory checks to see if the block is even worth processing.
         */

        check_block_relevancy(&block, Some(block_root), chain)?;

        /*
         * Advance the given `parent.beacon_state` to the slot of the given `block`.
         */

        let catchup_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_CATCHUP_STATE);

        // Stage a batch of operations to be completed atomically if this block is imported
        // successfully.
        let mut confirmation_db_batch = vec![];

        // The block must have a higher slot than its parent.
        if block.slot() <= parent.beacon_block.slot() {
            return Err(BlockError::BlockIsNotLaterThanParent {
                block_slot: block.slot(),
                parent_slot: parent.beacon_block.slot(),
            });
        }

        let mut summaries = vec![];

        // Transition the parent state to the block slot.
        //
        // It is important to note that we're using a "pre-state" here, one that has potentially
        // been advanced one slot forward from `parent.beacon_block.slot`.
        let mut state = parent.pre_state;

        // Perform a sanity check on the pre-state.
        let parent_slot = parent.beacon_block.slot();
        if state.slot() < parent_slot || state.slot() > parent_slot + 1 {
            return Err(BeaconChainError::BadPreState {
                parent_root: parent.beacon_block_root,
                parent_slot,
                block_root,
                block_slot: block.slot(),
                state_slot: state.slot(),
            }
            .into());
        }

        let distance = block.slot().as_u64().saturating_sub(state.slot().as_u64());
        for _ in 0..distance {
            let state_root = if parent.beacon_block.slot() == state.slot() {
                // If it happens that `pre_state` has *not* already been advanced forward a single
                // slot, then there is no need to compute the state root for this
                // `per_slot_processing` call since that state root is already stored in the parent
                // block.
                parent.beacon_block.state_root()
            } else {
                // This is a new state we've reached, so stage it for storage in the DB.
                // Computing the state root here is time-equivalent to computing it during slot
                // processing, but we get early access to it.
                let state_root = state.update_tree_hash_cache()?;

                // Store the state immediately, marking it as temporary, and staging the deletion
                // of its temporary status as part of the larger atomic operation.
                let txn_lock = chain.store.hot_db.begin_rw_transaction();
                let state_already_exists =
                    chain.store.load_hot_state_summary(&state_root)?.is_some();

                let state_batch = if state_already_exists {
                    // If the state exists, it could be temporary or permanent, but in neither case
                    // should we rewrite it or store a new temporary flag for it. We *will* stage
                    // the temporary flag for deletion because it's OK to double-delete the flag,
                    // and we don't mind if another thread gets there first.
                    vec![]
                } else {
                    vec![
                        if state.slot() % T::EthSpec::slots_per_epoch() == 0 {
                            StoreOp::PutState(state_root, &state)
                        } else {
                            StoreOp::PutStateSummary(
                                state_root,
                                HotStateSummary::new(&state_root, &state)?,
                            )
                        },
                        StoreOp::PutStateTemporaryFlag(state_root),
                    ]
                };
                chain.store.do_atomically(state_batch)?;
                drop(txn_lock);

                confirmation_db_batch.push(StoreOp::DeleteStateTemporaryFlag(state_root));

                state_root
            };

            if let Some(summary) = per_slot_processing(&mut state, Some(state_root), &chain.spec)? {
                // Expose Prometheus metrics.
                if let Err(e) = summary.observe_metrics() {
                    error!(
                        chain.log,
                        "Failed to observe epoch summary metrics";
                        "src" => "block_verification",
                        "error" => ?e
                    );
                }
                summaries.push(summary);
            }
        }

        // If the block is sufficiently recent, notify the validator monitor.
        if let Some(slot) = chain.slot_clock.now() {
            let epoch = slot.epoch(T::EthSpec::slots_per_epoch());
            if block.slot().epoch(T::EthSpec::slots_per_epoch())
                + VALIDATOR_MONITOR_HISTORIC_EPOCHS as u64
                >= epoch
            {
                let validator_monitor = chain.validator_monitor.read();
                // Update the summaries in a separate loop to `per_slot_processing`. This protects
                // the `validator_monitor` lock from being bounced or held for a long time whilst
                // performing `per_slot_processing`.
                for (i, summary) in summaries.iter().enumerate() {
                    let epoch = state.current_epoch() - Epoch::from(summaries.len() - i);
                    if let Err(e) =
                        validator_monitor.process_validator_statuses(epoch, summary, &chain.spec)
                    {
                        error!(
                            chain.log,
                            "Failed to process validator statuses";
                            "error" => ?e
                        );
                    }
                }
            }
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

        write_state(
            &format!("state_pre_block_{}", block_root),
            &state,
            &chain.log,
        );
        write_block(&block, block_root, &chain.log);

        let core_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_CORE);

        if let Err(err) = per_block_processing(
            &mut state,
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

        write_state(
            &format!("state_post_block_{}", block_root),
            &state,
            &chain.log,
        );

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
            state,
            parent_block: parent.beacon_block,
            confirmation_db_batch,
        })
    }
}

/// Check that the count of skip slots between the block and its parent does not exceed our maximum
/// value.
///
/// Whilst this is not part of the specification, we include this to help prevent us from DoS
/// attacks. In times of dire network circumstance, the user can configure the
/// `import_max_skip_slots` value.
fn check_block_skip_slots<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    parent_slot: Slot,
    block: BeaconBlockRef<'_, T::EthSpec>,
) -> Result<(), BlockError<T::EthSpec>> {
    // Reject any block that exceeds our limit on skipped slots.
    if let Some(max_skip_slots) = chain.config.import_max_skip_slots {
        if block.slot() > parent_slot + max_skip_slots {
            return Err(BlockError::TooManySkippedSlots {
                parent_slot,
                block_slot: block.slot(),
            });
        }
    }

    Ok(())
}

/// Returns `Ok(())` if the block's slot is greater than the anchor block's slot (if any).
fn check_block_against_anchor_slot<T: BeaconChainTypes>(
    block: BeaconBlockRef<'_, T::EthSpec>,
    chain: &BeaconChain<T>,
) -> Result<(), BlockError<T::EthSpec>> {
    if let Some(anchor_slot) = chain.store.get_anchor_slot() {
        if block.slot() <= anchor_slot {
            return Err(BlockError::WeakSubjectivityConflict);
        }
    }
    Ok(())
}

/// Returns `Ok(())` if the block is later than the finalized slot on `chain`.
///
/// Returns an error if the block is earlier or equal to the finalized slot, or there was an error
/// verifying that condition.
fn check_block_against_finalized_slot<T: BeaconChainTypes>(
    block: BeaconBlockRef<'_, T::EthSpec>,
    chain: &BeaconChain<T>,
) -> Result<(), BlockError<T::EthSpec>> {
    let finalized_slot = chain
        .head_info()?
        .finalized_checkpoint
        .epoch
        .start_slot(T::EthSpec::slots_per_epoch());

    if block.slot() <= finalized_slot {
        Err(BlockError::WouldRevertFinalizedSlot {
            block_slot: block.slot(),
            finalized_slot,
        })
    } else {
        Ok(())
    }
}

/// Returns `Ok(block)` if the block descends from the finalized root.
pub fn check_block_is_finalized_descendant<T: BeaconChainTypes, F: ForkChoiceStore<T::EthSpec>>(
    block: SignedBeaconBlock<T::EthSpec>,
    fork_choice: &ForkChoice<F, T::EthSpec>,
    store: &HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>,
) -> Result<SignedBeaconBlock<T::EthSpec>, BlockError<T::EthSpec>> {
    if fork_choice.is_descendant_of_finalized(block.parent_root()) {
        Ok(block)
    } else {
        // If fork choice does *not* consider the parent to be a descendant of the finalized block,
        // then there are two more cases:
        //
        // 1. We have the parent stored in our database. Because fork-choice has confirmed the
        //    parent is *not* in our post-finalization DAG, all other blocks must be either
        //    pre-finalization or conflicting with finalization.
        // 2. The parent is unknown to us, we probably want to download it since it might actually
        //    descend from the finalized root.
        if store
            .block_exists(&block.parent_root())
            .map_err(|e| BlockError::BeaconChainError(e.into()))?
        {
            Err(BlockError::NotFinalizedDescendant {
                block_parent_root: block.parent_root(),
            })
        } else {
            Err(BlockError::ParentUnknown(Box::new(block)))
        }
    }
}

/// Performs simple, cheap checks to ensure that the block is relevant to be imported.
///
/// `Ok(block_root)` is returned if the block passes these checks and should progress with
/// verification (viz., it is relevant).
///
/// Returns an error if the block fails one of these checks (viz., is not relevant) or an error is
/// experienced whilst attempting to verify.
pub fn check_block_relevancy<T: BeaconChainTypes>(
    signed_block: &SignedBeaconBlock<T::EthSpec>,
    block_root: Option<Hash256>,
    chain: &BeaconChain<T>,
) -> Result<Hash256, BlockError<T::EthSpec>> {
    let block = signed_block.message();

    // Do not process blocks from the future.
    if block.slot() > chain.slot()? {
        return Err(BlockError::FutureSlot {
            present_slot: chain.slot()?,
            block_slot: block.slot(),
        });
    }

    // Do not re-process the genesis block.
    if block.slot() == 0 {
        return Err(BlockError::GenesisBlock);
    }

    // This is an artificial (non-spec) restriction that provides some protection from overflow
    // abuses.
    if block.slot() >= MAXIMUM_BLOCK_SLOT_NUMBER {
        return Err(BlockError::BlockSlotLimitReached);
    }

    // Do not process a block from a finalized slot.
    check_block_against_finalized_slot(block, chain)?;

    let block_root = block_root.unwrap_or_else(|| get_block_root(signed_block));

    // Check if the block is already known. We know it is post-finalization, so it is
    // sufficient to check the fork choice.
    if chain.fork_choice.read().contains_block(&block_root) {
        return Err(BlockError::BlockIsAlreadyKnown);
    }

    Ok(block_root)
}

/// Returns the canonical root of the given `block`.
///
/// Use this function to ensure that we report the block hashing time Prometheus metric.
pub fn get_block_root<E: EthSpec>(block: &SignedBeaconBlock<E>) -> Hash256 {
    let block_root_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_BLOCK_ROOT);

    let block_root = block.canonical_root();

    metrics::stop_timer(block_root_timer);

    block_root
}

/// Verify the parent of `block` is known, returning some information about the parent block from
/// fork choice.
#[allow(clippy::type_complexity)]
fn verify_parent_block_is_known<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    block: SignedBeaconBlock<T::EthSpec>,
) -> Result<(ProtoBlock, SignedBeaconBlock<T::EthSpec>), BlockError<T::EthSpec>> {
    if let Some(proto_block) = chain
        .fork_choice
        .read()
        .get_block(&block.message().parent_root())
    {
        Ok((proto_block, block))
    } else {
        Err(BlockError::ParentUnknown(Box::new(block)))
    }
}

/// Load the parent snapshot (block and state) of the given `block`.
///
/// Returns `Err(BlockError::ParentUnknown)` if the parent is not found, or if an error occurs
/// whilst attempting the operation.
#[allow(clippy::type_complexity)]
fn load_parent<T: BeaconChainTypes>(
    block: SignedBeaconBlock<T::EthSpec>,
    chain: &BeaconChain<T>,
) -> Result<
    (
        PreProcessingSnapshot<T::EthSpec>,
        SignedBeaconBlock<T::EthSpec>,
    ),
    BlockError<T::EthSpec>,
> {
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
    if !chain
        .fork_choice
        .read()
        .contains_block(&block.parent_root())
    {
        return Err(BlockError::ParentUnknown(Box::new(block)));
    }

    let db_read_timer = metrics::start_timer(&metrics::BLOCK_PROCESSING_DB_READ);

    let result = if let Some(snapshot) = chain
        .snapshot_cache
        .try_write_for(BLOCK_PROCESSING_CACHE_LOCK_TIMEOUT)
        .and_then(|mut snapshot_cache| {
            snapshot_cache.get_state_for_block_processing(block.parent_root())
        }) {
        Ok((snapshot.into_pre_state(), block))
    } else {
        // Load the blocks parent block from the database, returning invalid if that block is not
        // found.
        //
        // We don't return a DBInconsistent error here since it's possible for a block to
        // exist in fork choice but not in the database yet. In such a case we simply
        // indicate that we don't yet know the parent.
        let root = block.parent_root();
        let parent_block = chain
            .get_block(&block.parent_root())
            .map_err(BlockError::BeaconChainError)?
            .ok_or_else(|| {
                // Return a `MissingBeaconBlock` error instead of a `ParentUnknown` error since
                // we've already checked fork choice for this block.
                //
                // It's an internal error if the block exists in fork choice but not in the
                // database.
                BlockError::from(BeaconChainError::MissingBeaconBlock(block.parent_root()))
            })?;

        // Load the parent blocks state from the database, returning an error if it is not found.
        // It is an error because if we know the parent block we should also know the parent state.
        let parent_state_root = parent_block.state_root();
        let parent_state = chain
            .get_state(&parent_state_root, Some(parent_block.slot()))?
            .ok_or_else(|| {
                BeaconChainError::DBInconsistent(format!("Missing state {:?}", parent_state_root))
            })?;

        Ok((
            PreProcessingSnapshot {
                beacon_block: parent_block,
                beacon_block_root: root,
                pre_state: parent_state,
                beacon_state_root: Some(parent_state_root),
            },
            block,
        ))
    };

    metrics::stop_timer(db_read_timer);

    result
}

/// Performs a cheap (time-efficient) state advancement so the committees and proposer shuffling for
/// `slot` can be obtained from `state`.
///
/// The state advancement is "cheap" since it does not generate state roots. As a result, the
/// returned state might be holistically invalid but the committees/proposers will be correct (since
/// they do not rely upon state roots).
///
/// If the given `state` can already serve the `slot`, the committees will be built on the `state`
/// and `Cow::Borrowed(state)` will be returned. Otherwise, the state will be cloned, cheaply
/// advanced and then returned as a `Cow::Owned`. The end result is that the given `state` is never
/// mutated to be invalid (in fact, it is never changed beyond a simple committee cache build).
fn cheap_state_advance_to_obtain_committees<'a, E: EthSpec>(
    state: &'a mut BeaconState<E>,
    state_root_opt: Option<Hash256>,
    block_slot: Slot,
    spec: &ChainSpec,
) -> Result<Cow<'a, BeaconState<E>>, BlockError<E>> {
    let block_epoch = block_slot.epoch(E::slots_per_epoch());

    if state.current_epoch() == block_epoch {
        state.build_committee_cache(RelativeEpoch::Current, spec)?;

        Ok(Cow::Borrowed(state))
    } else if state.slot() > block_slot {
        Err(BlockError::BlockIsNotLaterThanParent {
            block_slot,
            parent_slot: state.slot(),
        })
    } else {
        let mut state = state.clone_with(CloneConfig::committee_caches_only());
        let target_slot = block_epoch.start_slot(E::slots_per_epoch());

        // Advance the state into the same epoch as the block. Use the "partial" method since state
        // roots are not important for proposer/attester shuffling.
        partial_state_advance(&mut state, state_root_opt, target_slot, spec)
            .map_err(|e| BlockError::BeaconChainError(BeaconChainError::from(e)))?;

        state.build_committee_cache(RelativeEpoch::Current, spec)?;

        Ok(Cow::Owned(state))
    }
}

/// Obtains a read-locked `ValidatorPubkeyCache` from the `chain`.
fn get_validator_pubkey_cache<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
) -> Result<RwLockReadGuard<ValidatorPubkeyCache<T>>, BlockError<T::EthSpec>> {
    chain
        .validator_pubkey_cache
        .try_read_for(VALIDATOR_PUBKEY_CACHE_LOCK_TIMEOUT)
        .ok_or(BeaconChainError::ValidatorPubkeyCacheLockTimeout)
        .map_err(BlockError::BeaconChainError)
}

/// Produces an _empty_ `BlockSignatureVerifier`.
///
/// The signature verifier is empty because it does not yet have any of this block's signatures
/// added to it. Use `Self::apply_to_signature_verifier` to apply the signatures.
fn get_signature_verifier<'a, T: BeaconChainTypes>(
    state: &'a BeaconState<T::EthSpec>,
    validator_pubkey_cache: &'a ValidatorPubkeyCache<T>,
    spec: &'a ChainSpec,
) -> BlockSignatureVerifier<
    'a,
    T::EthSpec,
    impl Fn(usize) -> Option<Cow<'a, PublicKey>> + Clone,
    impl Fn(&'a PublicKeyBytes) -> Option<Cow<'a, PublicKey>>,
> {
    let get_pubkey = move |validator_index| {
        // Disallow access to any validator pubkeys that are not in the current beacon state.
        if validator_index < state.validators().len() {
            validator_pubkey_cache
                .get(validator_index)
                .map(Cow::Borrowed)
        } else {
            None
        }
    };

    let decompressor = move |pk_bytes| {
        // Map compressed pubkey to validator index.
        let validator_index = validator_pubkey_cache.get_index(pk_bytes)?;
        // Map validator index to pubkey (respecting guard on unknown validators).
        get_pubkey(validator_index)
    };

    BlockSignatureVerifier::new(state, get_pubkey, decompressor, spec)
}

/// Verify that `header` was signed with a valid signature from its proposer.
///
/// Return `Ok(())` if the signature is valid, and an `Err` otherwise.
fn verify_header_signature<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    header: &SignedBeaconBlockHeader,
) -> Result<(), BlockError<T::EthSpec>> {
    let proposer_pubkey = get_validator_pubkey_cache(chain)?
        .get(header.message.proposer_index as usize)
        .cloned()
        .ok_or(BlockError::UnknownValidator(header.message.proposer_index))?;
    let (fork, genesis_validators_root) = chain
        .with_head(|head| {
            Ok((
                head.beacon_state.fork(),
                head.beacon_state.genesis_validators_root(),
            ))
        })
        .map_err(|e: BlockError<T::EthSpec>| e)?;

    if header.verify_signature::<T::EthSpec>(
        &proposer_pubkey,
        &fork,
        genesis_validators_root,
        &chain.spec,
    ) {
        Ok(())
    } else {
        Err(BlockError::ProposalSignatureInvalid)
    }
}

fn write_state<T: EthSpec>(prefix: &str, state: &BeaconState<T>, log: &Logger) {
    if WRITE_BLOCK_PROCESSING_SSZ {
        let root = state.tree_hash_root();
        let filename = format!("{}_slot_{}_root_{}.ssz", prefix, state.slot(), root);
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

fn write_block<T: EthSpec>(block: &SignedBeaconBlock<T>, root: Hash256, log: &Logger) {
    if WRITE_BLOCK_PROCESSING_SSZ {
        let filename = format!("block_slot_{}_root{}.ssz", block.slot(), root);
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
