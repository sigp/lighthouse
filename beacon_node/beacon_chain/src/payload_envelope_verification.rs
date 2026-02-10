//! The incremental processing steps (e.g., signatures verified but not the state transition) is
//! represented as a sequence of wrapper-types around the block. There is a linear progression of
//! types, starting at a `SignedBeaconBlock` and finishing with a `Fully VerifiedBlock` (see
//! diagram below).
//!
//! ```ignore
//!            START
//!              |
//!              ▼
//! SignedExecutionPayloadEnvelope
//!              |
//!              |---------------
//!              |              |
//!              |              ▼
//!              |    GossipVerifiedEnvelope
//!              |              |
//!              |---------------
//!              |
//!              ▼
//!  ExecutionPendingEnvelope
//!              |
//!            await
//!              |
//!              ▼
//!             END
//!
//! ```

use crate::NotifyExecutionLayer;
use crate::block_verification::{PayloadVerificationHandle, PayloadVerificationOutcome};
use crate::payload_envelope_verification_types::{EnvelopeImportData, MaybeAvailableEnvelope};
use crate::execution_payload::PayloadNotifier;
use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use educe::Educe;
use slot_clock::SlotClock;
use state_processing::envelope_processing::{EnvelopeProcessingError, process_execution_payload_envelope};
use state_processing::{BlockProcessingError, VerifySignatures};
use std::sync::Arc;
use tracing::{debug, instrument};
use types::{
    BeaconState, BeaconStateError, EthSpec, ExecutionBlockHash, Hash256, SignedBeaconBlock,
    SignedExecutionPayloadEnvelope, Slot,
};

#[derive(Debug, Clone)]
pub enum EnvelopeError {
    /// The envelope's block root is unknown.
    BlockRootUnknown {
        block_root: Hash256,
    },
    /// The signature is invalid.
    BadSignature,
    /// The builder index doesn't match the committed bid
    BuilderIndexMismatch {
        committed_bid: u64,
        envelope: u64,
    },
    // The envelope slot doesn't match the block
    SlotMismatch {
        block: Slot,
        envelope: Slot,
    },
    // The validator index is unknown
    UnknownValidator {
        builder_index: u64,
    },
    // The block hash doesn't match the committed bid
    BlockHashMismatch {
        committed_bid: ExecutionBlockHash,
        envelope: ExecutionBlockHash,
    },
    // Some Beacon Chain Error
    BeaconChainError(Arc<BeaconChainError>),
    // Some Beacon State error
    BeaconStateError(BeaconStateError),
    // Some BlockProcessingError (for electra operations)
    BlockProcessingError(BlockProcessingError),
    // Some EnvelopeProcessingError
    EnvelopeProcessingError(EnvelopeProcessingError),
}

impl From<BeaconChainError> for EnvelopeError {
    fn from(e: BeaconChainError) -> Self {
        EnvelopeError::BeaconChainError(Arc::new(e))
    }
}

impl From<BeaconStateError> for EnvelopeError {
    fn from(e: BeaconStateError) -> Self {
        EnvelopeError::BeaconStateError(e)
    }
}

/// Pull errors up from EnvelopeProcessingError to EnvelopeError
impl From<EnvelopeProcessingError> for EnvelopeError {
    fn from(e: EnvelopeProcessingError) -> Self {
        match e {
            EnvelopeProcessingError::BadSignature => EnvelopeError::BadSignature,
            EnvelopeProcessingError::BeaconStateError(e) => EnvelopeError::BeaconStateError(e),
            EnvelopeProcessingError::BlockHashMismatch {
                committed_bid,
                envelope,
            } => EnvelopeError::BlockHashMismatch {
                committed_bid,
                envelope,
            },
            EnvelopeProcessingError::BlockProcessingError(e) => {
                EnvelopeError::BlockProcessingError(e)
            }
            e => EnvelopeError::EnvelopeProcessingError(e),
        }
    }
}

/// This snapshot is to be used for verifying a envelope of the block.
#[derive(Debug, Clone)]
pub struct EnvelopeProcessingSnapshot<E: EthSpec> {
    /// This state is equivalent to the `self.beacon_block.state_root()` before applying the envelope.
    pub pre_state: BeaconState<E>,
    pub state_root: Hash256,
    pub beacon_block_root: Hash256,
}

#[allow(clippy::type_complexity)]
#[instrument(skip_all, level = "debug", fields(beacon_block_root = %envelope.beacon_block_root()))]
fn load_snapshot<T: BeaconChainTypes>(
    envelope: &SignedExecutionPayloadEnvelope<T::EthSpec>,
    chain: &BeaconChain<T>,
) -> Result<EnvelopeProcessingSnapshot<T::EthSpec>, EnvelopeError> {
    // Reject any block if its block is not known to fork choice.
    //
    // A block that is not in fork choice is either:
    //
    //  - Not yet imported: we should reject this block because we should only import a child
    //  envelope after its parent has been fully imported.
    //  - Pre-finalized: if the block is _prior_ to finalization, we should ignore the envelope
    //  because it will revert finalization. Note that the finalized block is stored in fork
    //  choice, so we will not reject any child of the finalized block (this is relevant during
    //  genesis).

    let fork_choice_read_lock = chain.canonical_head.fork_choice_read_lock();
    let beacon_block_root = envelope.beacon_block_root();
    let Some(proto_beacon_block) = fork_choice_read_lock.get_block(&beacon_block_root) else {
        return Err(EnvelopeError::BlockRootUnknown {
            block_root: beacon_block_root,
        });
    };
    drop(fork_choice_read_lock);

    // TODO(EIP-7732): add metrics here

    let block_state_root = proto_beacon_block.state_root;
    // We can use `get_hot_state` here rather than `get_advanced_hot_state` because the envelope
    // must be from the same slot as its block (so no advance is required).
    let cache_state = true;
    let state = chain
        .store
        .get_hot_state(&block_state_root, cache_state)
        .map_err(|e| EnvelopeError::BeaconChainError(Arc::new(e.into())))?
        .ok_or_else(|| {
            BeaconChainError::DBInconsistent(format!(
                "Missing state for envelope block {block_state_root:?}",
            ))
        })?;

    Ok(EnvelopeProcessingSnapshot {
        pre_state: state,
        state_root: block_state_root,
        beacon_block_root,
    })
}

/// A wrapper around a `SignedExecutionPayloadEnvelope` that indicates it has been approved for re-gossiping on
/// the p2p network.
#[derive(Educe)]
#[educe(Debug(bound = "T: BeaconChainTypes"))]
pub struct GossipVerifiedEnvelope<T: BeaconChainTypes> {
    pub signed_envelope: Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>,
    pub block: Arc<SignedBeaconBlock<T::EthSpec>>,
    pub snapshot: Option<Box<EnvelopeProcessingSnapshot<T::EthSpec>>>,
}

impl<T: BeaconChainTypes> GossipVerifiedEnvelope<T> {
    pub fn new(
        signed_envelope: Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>,
        chain: &BeaconChain<T>,
    ) -> Result<Self, EnvelopeError> {
        let envelope = &signed_envelope.message;
        let payload = &envelope.payload;
        let beacon_block_root = envelope.beacon_block_root;

        // Check that we've seen the beacon block for this envelope and that it passes validation.
        // TODO(EIP-7732): We need a block status table in order to differentiate between:
        //
        // 1. Blocks we haven't seen (IGNORE), and
        // 2. Blocks we've seen that are invalid (REJECT).
        //
        // Presently these two cases are conflated.
        let fork_choice_read_lock = chain.canonical_head.fork_choice_read_lock();
        let Some(proto_block) = fork_choice_read_lock.get_block(&beacon_block_root) else {
            return Err(EnvelopeError::BlockRootUnknown {
                block_root: beacon_block_root,
            });
        };
        drop(fork_choice_read_lock);

        // TODO(EIP-7732): check that we haven't seen another valid `SignedExecutionPayloadEnvelope`
        //                 for this block root from this builder - envelope status table check

        // TODO(EIP-7732): this could be obtained from the ProtoBlock instead of the DB
        //                 but this means the ProtoBlock needs to include something like the ExecutionBid
        //                 will need to answer this question later.
        let block = chain
            .get_full_block(&beacon_block_root)?
            .ok_or_else(|| {
                EnvelopeError::from(BeaconChainError::MissingBeaconBlock(beacon_block_root))
            })
            .map(Arc::new)?;
        let execution_bid = &block
            .message()
            .body()
            .signed_execution_payload_bid()?
            .message;

        // TODO(EIP-7732): Gossip rules for the beacon block contain the following:
        // https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/p2p-interface.md#beacon_block
        // [IGNORE] The block is not from a future slot (with a MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance)
        // [IGNORE] The block is from a slot greater than the latest finalized slot
        // should these kinds of checks be included for envelopes as well?

        // check that the slot of the envelope matches the slot of the parent block
        if envelope.slot != block.slot() {
            return Err(EnvelopeError::SlotMismatch {
                block: block.slot(),
                envelope: envelope.slot,
            });
        }

        // builder index matches committed bid
        if envelope.builder_index != execution_bid.builder_index {
            return Err(EnvelopeError::BuilderIndexMismatch {
                committed_bid: execution_bid.builder_index,
                envelope: envelope.builder_index,
            });
        }

        // the block hash should match the block hash of the execution bid
        if payload.block_hash != execution_bid.block_hash {
            return Err(EnvelopeError::BlockHashMismatch {
                committed_bid: execution_bid.block_hash,
                envelope: payload.block_hash,
            });
        }

        // Get the fork from the proposer cache so we can verify the signature.
        // This is currently the most efficient way to implement envelope signature verification
        // because the `fork` might depend on advancing the parent state.
        let block_slot = envelope.slot;
        let block_epoch = block_slot.epoch(T::EthSpec::slots_per_epoch());
        let proposer_shuffling_decision_block =
            proto_block.proposer_shuffling_root_for_child_block(block_epoch, &chain.spec);
        let mut opt_snapshot = None;
        let envelope_ref = signed_envelope.as_ref();
        let proposer = chain.with_proposer_cache::<_, EnvelopeError>(
            proposer_shuffling_decision_block,
            block_epoch,
            |proposers| proposers.get_slot::<T::EthSpec>(block_slot),
            || {
                debug!(
                    %beacon_block_root,
                    block_hash = %envelope_ref.block_hash(),
                    "Proposer shuffling cache miss for envelope verification"
                );
                // The proposer index was *not* cached and we must load the parent in order to
                // determine the proposer index.
                let snapshot = load_snapshot(envelope_ref, chain)?;
                opt_snapshot = Some(Box::new(snapshot.clone()));
                Ok((snapshot.state_root, snapshot.pre_state))
            },
        )?;
        let fork = proposer.fork;

        // True builder index accounting for self-building.
        let proposer_index = block.message().proposer_index();
        let builder_index = envelope.builder_index;

        let signature_is_valid = {
            let pubkey_cache = chain.validator_pubkey_cache.read();
            let builder_pubkey = pubkey_cache
                .get(builder_index as usize)
                .ok_or_else(|| EnvelopeError::UnknownValidator { builder_index })?;
            signed_envelope.verify_signature(
                builder_pubkey,
                &fork,
                chain.genesis_validators_root,
                &chain.spec,
            )
        };

        if !signature_is_valid {
            return Err(EnvelopeError::BadSignature);
        }

        Ok(Self {
            signed_envelope,
            block,
            snapshot: opt_snapshot,
        })
    }

    pub fn envelope_cloned(&self) -> Arc<SignedExecutionPayloadEnvelope<T::EthSpec>> {
        self.signed_envelope.clone()
    }
}

pub trait IntoExecutionPendingEnvelope<T: BeaconChainTypes>: Sized {
    fn into_execution_pending_envelope(
        self,
        chain: &Arc<BeaconChain<T>>,
        notify_execution_layer: NotifyExecutionLayer,
    ) -> Result<ExecutionPendingEnvelope<T>, EnvelopeError>;
}

pub struct ExecutionPendingEnvelope<T: BeaconChainTypes> {
    pub signed_envelope: MaybeAvailableEnvelope<T::EthSpec>,
    pub import_data: EnvelopeImportData<T::EthSpec>,
    pub payload_verification_handle: PayloadVerificationHandle,
}

impl<T: BeaconChainTypes> IntoExecutionPendingEnvelope<T> for GossipVerifiedEnvelope<T> {
    fn into_execution_pending_envelope(
        self,
        chain: &Arc<BeaconChain<T>>,
        notify_execution_layer: NotifyExecutionLayer,
    ) -> Result<ExecutionPendingEnvelope<T>, EnvelopeError> {
        let signed_envelope = self.signed_envelope;
        let envelope = &signed_envelope.message;
        let payload = &envelope.payload;

        // Verify the execution payload is valid
        let payload_notifier =
            PayloadNotifier::from_envelope(chain.clone(), envelope, notify_execution_layer)?;
        let block_root = envelope.beacon_block_root;
        let slot = self.block.slot();

        let payload_verification_future = async move {
            let chain = payload_notifier.chain.clone();
            // TODO:(gloas): timing metrics
            if let Some(started_execution) = chain.slot_clock.now_duration() {
                chain.block_times_cache.write().set_time_started_execution(
                    block_root,
                    slot,
                    started_execution,
                );
            }

            let payload_verification_status = payload_notifier.notify_new_payload().await?;
            Ok(PayloadVerificationOutcome {
                payload_verification_status,
                // This fork is after the merge so it'll never be the merge transition block
                is_valid_merge_transition_block: false,
            })
        };
        // Spawn the payload verification future as a new task, but don't wait for it to complete.
        // The `payload_verification_future` will be awaited later to ensure verification completed
        // successfully.
        let payload_verification_handle = chain
            .task_executor
            .spawn_handle(
                payload_verification_future,
                "execution_payload_verification",
            )
            .ok_or(BeaconChainError::RuntimeShutdown)?;

        let snapshot = if let Some(snapshot) = self.snapshot {
            *snapshot
        } else {
            load_snapshot(signed_envelope.as_ref(), chain)?
        };
        let mut state = snapshot.pre_state;

        // All the state modifications are done in envelope_processing
        process_execution_payload_envelope(
            &mut state,
            Some(snapshot.state_root),
            &signed_envelope,
            // verify signature already done for GossipVerifiedEnvelope
            VerifySignatures::False,
            &chain.spec,
        )?;

        Ok(ExecutionPendingEnvelope {
            signed_envelope: MaybeAvailableEnvelope::AvailabilityPending {
                block_hash: payload.block_hash,
                envelope: signed_envelope,
            },
            import_data: EnvelopeImportData {
                block_root,
                block: self.block,
                post_state: Box::new(state),
            },
            payload_verification_handle,
        })
    }
}

impl<T: BeaconChainTypes> IntoExecutionPendingEnvelope<T>
    for Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>
{
    fn into_execution_pending_envelope(
        self,
        chain: &Arc<BeaconChain<T>>,
        notify_execution_layer: NotifyExecutionLayer,
    ) -> Result<ExecutionPendingEnvelope<T>, EnvelopeError> {
        // TODO(EIP-7732): figure out how this should be refactored..
        GossipVerifiedEnvelope::new(self, chain)?
            .into_execution_pending_envelope(chain, notify_execution_layer)
    }
}