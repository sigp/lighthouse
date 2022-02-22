//! This module contains various functions for producing and verifying `ExecutionPayloads`.
//!
//! Lighthouse tends to do payload tasks in *slightly* different locations to the specification.
//! This is because some tasks involve calling out to external servers and it's nice to keep those
//! away from our pure `state_processing` and `fork_choice` crates.
//!
//! So, this module contains functions that one might expect to find in other crates, but they live
//! here for good reason.

use crate::otb_verification_service::OptimisticTransitionBlock;
use crate::{
    BeaconChain, BeaconChainError, BeaconChainTypes, BlockError, BlockProductionError,
    ExecutionPayloadError,
};
use execution_layer::{BuilderParams, PayloadStatus};
use fork_choice::{InvalidationOperation, PayloadVerificationStatus};
use proto_array::{Block as ProtoBlock, ExecutionStatus};
use slog::debug;
use slot_clock::SlotClock;
use state_processing::per_block_processing::{
    compute_timestamp_at_slot, is_execution_enabled, is_merge_transition_complete,
    partially_verify_execution_payload,
};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tree_hash::TreeHash;
use types::*;

pub type PreparePayloadResult<Payload> = Result<Payload, BlockProductionError>;
pub type PreparePayloadHandle<Payload> = JoinHandle<Option<PreparePayloadResult<Payload>>>;

#[derive(PartialEq)]
pub enum AllowOptimisticImport {
    Yes,
    No,
}

/// Used to await the result of executing payload with a remote EE.
pub struct PayloadNotifier<T: BeaconChainTypes> {
    pub chain: Arc<BeaconChain<T>>,
    pub block: Arc<SignedBeaconBlock<T::EthSpec>>,
    payload_verification_status: Option<PayloadVerificationStatus>,
}

impl<T: BeaconChainTypes> PayloadNotifier<T> {
    pub fn new(
        chain: Arc<BeaconChain<T>>,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
        state: &BeaconState<T::EthSpec>,
    ) -> Result<Self, BlockError<T::EthSpec>> {
        let payload_verification_status = if is_execution_enabled(state, block.message().body()) {
            // Perform the initial stages of payload verification.
            //
            // We will duplicate these checks again during `per_block_processing`, however these checks
            // are cheap and doing them here ensures we protect the execution engine from junk.
            partially_verify_execution_payload(
                state,
                block.message().execution_payload()?,
                &chain.spec,
            )
            .map_err(BlockError::PerBlockProcessingError)?;
            None
        } else {
            Some(PayloadVerificationStatus::Irrelevant)
        };

        Ok(Self {
            chain,
            block,
            payload_verification_status,
        })
    }

    pub async fn notify_new_payload(
        self,
    ) -> Result<PayloadVerificationStatus, BlockError<T::EthSpec>> {
        if let Some(precomputed_status) = self.payload_verification_status {
            Ok(precomputed_status)
        } else {
            notify_new_payload(&self.chain, self.block.message()).await
        }
    }
}

/// Verify that `execution_payload` contained by `block` is considered valid by an execution
/// engine.
///
/// ## Specification
///
/// Equivalent to the `notify_new_payload` function in the merge Beacon Chain Changes, although it
/// contains a few extra checks by running `partially_verify_execution_payload` first:
///
/// https://github.com/ethereum/consensus-specs/blob/v1.1.9/specs/bellatrix/beacon-chain.md#notify_new_payload
async fn notify_new_payload<'a, T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    block: BeaconBlockRef<'a, T::EthSpec>,
) -> Result<PayloadVerificationStatus, BlockError<T::EthSpec>> {
    let execution_payload = block.execution_payload()?;

    let execution_layer = chain
        .execution_layer
        .as_ref()
        .ok_or(ExecutionPayloadError::NoExecutionConnection)?;

    let new_payload_response = execution_layer
        .notify_new_payload(&execution_payload.execution_payload)
        .await;

    match new_payload_response {
        Ok(status) => match status {
            PayloadStatus::Valid => Ok(PayloadVerificationStatus::Verified),
            PayloadStatus::Syncing | PayloadStatus::Accepted => {
                Ok(PayloadVerificationStatus::Optimistic)
            }
            PayloadStatus::Invalid {
                latest_valid_hash,
                ref validation_error,
            } => {
                debug!(
                    chain.log,
                    "Invalid execution payload";
                    "validation_error" => ?validation_error,
                    "latest_valid_hash" => ?latest_valid_hash,
                    "execution_block_hash" => ?execution_payload.execution_payload.block_hash,
                    "root" => ?block.tree_hash_root(),
                    "graffiti" => block.body().graffiti().as_utf8_lossy(),
                    "proposer_index" => block.proposer_index(),
                    "slot" => block.slot(),
                    "method" => "new_payload",
                );

                // latest_valid_hash == 0 implies that this was the terminal block
                // Hence, we don't need to run `BeaconChain::process_invalid_execution_payload`.
                if latest_valid_hash == ExecutionBlockHash::zero() {
                    return Err(ExecutionPayloadError::RejectedByExecutionEngine { status }.into());
                }
                // This block has not yet been applied to fork choice, so the latest block that was
                // imported to fork choice was the parent.
                let latest_root = block.parent_root();
                chain
                    .process_invalid_execution_payload(&InvalidationOperation::InvalidateMany {
                        head_block_root: latest_root,
                        always_invalidate_head: false,
                        latest_valid_ancestor: latest_valid_hash,
                    })
                    .await?;

                Err(ExecutionPayloadError::RejectedByExecutionEngine { status }.into())
            }
            PayloadStatus::InvalidBlockHash {
                ref validation_error,
            } => {
                debug!(
                    chain.log,
                    "Invalid execution payload block hash";
                    "validation_error" => ?validation_error,
                    "execution_block_hash" => ?execution_payload.execution_payload.block_hash,
                    "root" => ?block.tree_hash_root(),
                    "graffiti" => block.body().graffiti().as_utf8_lossy(),
                    "proposer_index" => block.proposer_index(),
                    "slot" => block.slot(),
                    "method" => "new_payload",
                );

                // Returning an error here should be sufficient to invalidate the block. We have no
                // information to indicate its parent is invalid, so no need to run
                // `BeaconChain::process_invalid_execution_payload`.
                Err(ExecutionPayloadError::RejectedByExecutionEngine { status }.into())
            }
        },
        Err(e) => Err(ExecutionPayloadError::RequestFailed(e).into()),
    }
}

/// Verify that the block which triggers the merge is valid to be imported to fork choice.
///
/// ## Errors
///
/// Will return an error when using a pre-merge fork `state`. Ensure to only run this function
/// after the merge fork.
///
/// ## Specification
///
/// Equivalent to the `validate_merge_block` function in the merge Fork Choice Changes:
///
/// https://github.com/ethereum/consensus-specs/blob/v1.1.5/specs/merge/fork-choice.md#validate_merge_block
pub async fn validate_merge_block<'a, T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    block: BeaconBlockRef<'a, T::EthSpec>,
    allow_optimistic_import: AllowOptimisticImport,
) -> Result<(), BlockError<T::EthSpec>> {
    let spec = &chain.spec;
    let block_epoch = block.slot().epoch(T::EthSpec::slots_per_epoch());
    let execution_payload = block.execution_payload()?;

    if spec.terminal_block_hash != ExecutionBlockHash::zero() {
        if block_epoch < spec.terminal_block_hash_activation_epoch {
            return Err(ExecutionPayloadError::InvalidActivationEpoch {
                activation_epoch: spec.terminal_block_hash_activation_epoch,
                epoch: block_epoch,
            }
            .into());
        }

        if execution_payload.parent_hash() != spec.terminal_block_hash {
            return Err(ExecutionPayloadError::InvalidTerminalBlockHash {
                terminal_block_hash: spec.terminal_block_hash,
                payload_parent_hash: execution_payload.parent_hash(),
            }
            .into());
        }

        return Ok(());
    }

    let execution_layer = chain
        .execution_layer
        .as_ref()
        .ok_or(ExecutionPayloadError::NoExecutionConnection)?;

    let is_valid_terminal_pow_block = execution_layer
        .is_valid_terminal_pow_block_hash(execution_payload.parent_hash(), spec)
        .await
        .map_err(ExecutionPayloadError::from)?;

    match is_valid_terminal_pow_block {
        Some(true) => Ok(()),
        Some(false) => Err(ExecutionPayloadError::InvalidTerminalPoWBlock {
            parent_hash: execution_payload.parent_hash(),
        }
        .into()),
        None => {
            if allow_optimistic_import == AllowOptimisticImport::Yes
                && is_optimistic_candidate_block(chain, block.slot(), block.parent_root()).await?
            {
                debug!(
                    chain.log,
                    "Optimistically importing merge transition block";
                    "block_hash" => ?execution_payload.parent_hash(),
                    "msg" => "the terminal block/parent was unavailable"
                );
                // Store Optimistic Transition Block in Database for later Verification
                OptimisticTransitionBlock::from_block(block)
                    .persist_in_store::<T, _>(&chain.store)?;
                Ok(())
            } else {
                Err(ExecutionPayloadError::UnverifiedNonOptimisticCandidate.into())
            }
        }
    }
}

/// Check to see if a block with the given parameters is valid to be imported optimistically.
pub async fn is_optimistic_candidate_block<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    block_slot: Slot,
    block_parent_root: Hash256,
) -> Result<bool, BeaconChainError> {
    let current_slot = chain.slot()?;
    let inner_chain = chain.clone();

    // Use a blocking task to check if the block is an optimistic candidate. Interacting
    // with the `fork_choice` lock in an async task can block the core executor.
    chain
        .spawn_blocking_handle(
            move || {
                inner_chain
                    .canonical_head
                    .fork_choice_read_lock()
                    .is_optimistic_candidate_block(
                        current_slot,
                        block_slot,
                        &block_parent_root,
                        &inner_chain.spec,
                    )
            },
            "validate_merge_block_optimistic_candidate",
        )
        .await?
        .map_err(BeaconChainError::from)
}

/// Validate the gossip block's execution_payload according to the checks described here:
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/merge/p2p-interface.md#beacon_block
pub fn validate_execution_payload_for_gossip<T: BeaconChainTypes>(
    parent_block: &ProtoBlock,
    block: BeaconBlockRef<'_, T::EthSpec>,
    chain: &BeaconChain<T>,
) -> Result<(), BlockError<T::EthSpec>> {
    // Only apply this validation if this is a merge beacon block.
    if let Ok(execution_payload) = block.body().execution_payload() {
        // This logic should match `is_execution_enabled`. We use only the execution block hash of
        // the parent here in order to avoid loading the parent state during gossip verification.

        let is_merge_transition_complete = match parent_block.execution_status {
            // Optimistically declare that an "unknown" status block has completed the merge.
            ExecutionStatus::Valid(_) | ExecutionStatus::Optimistic(_) => true,
            // It's impossible for an irrelevant block to have completed the merge. It is pre-merge
            // by definition.
            ExecutionStatus::Irrelevant(_) => false,
            // If the parent has an invalid payload then it's impossible to build a valid block upon
            // it. Reject the block.
            ExecutionStatus::Invalid(_) => {
                return Err(BlockError::ParentExecutionPayloadInvalid {
                    parent_root: parent_block.root,
                })
            }
        };

        if is_merge_transition_complete || execution_payload != &<_>::default() {
            let expected_timestamp = chain
                .slot_clock
                .start_of(block.slot())
                .map(|d| d.as_secs())
                .ok_or(BlockError::BeaconChainError(
                    BeaconChainError::UnableToComputeTimeAtSlot,
                ))?;

            // The block's execution payload timestamp is correct with respect to the slot
            if execution_payload.timestamp() != expected_timestamp {
                return Err(BlockError::ExecutionPayloadError(
                    ExecutionPayloadError::InvalidPayloadTimestamp {
                        expected: expected_timestamp,
                        found: execution_payload.timestamp(),
                    },
                ));
            }
        }
    }

    Ok(())
}

/// Gets an execution payload for inclusion in a block.
///
/// ## Errors
///
/// Will return an error when using a pre-merge fork `state`. Ensure to only run this function
/// after the merge fork.
///
/// ## Specification
///
/// Equivalent to the `get_execution_payload` function in the Validator Guide:
///
/// https://github.com/ethereum/consensus-specs/blob/v1.1.5/specs/merge/validator.md#block-proposal
pub fn get_execution_payload<
    T: BeaconChainTypes,
    Payload: ExecPayload<T::EthSpec> + Default + Send + 'static,
>(
    chain: Arc<BeaconChain<T>>,
    state: &BeaconState<T::EthSpec>,
    proposer_index: u64,
    builder_params: BuilderParams,
) -> Result<PreparePayloadHandle<Payload>, BlockProductionError> {
    // Compute all required values from the `state` now to avoid needing to pass it into a spawned
    // task.
    let spec = &chain.spec;
    let current_epoch = state.current_epoch();
    let is_merge_transition_complete = is_merge_transition_complete(state);
    let timestamp = compute_timestamp_at_slot(state, spec).map_err(BeaconStateError::from)?;
    let random = *state.get_randao_mix(current_epoch)?;
    let latest_execution_payload_header_block_hash =
        state.latest_execution_payload_header()?.block_hash;

    // Spawn a task to obtain the execution payload from the EL via a series of async calls. The
    // `join_handle` can be used to await the result of the function.
    let join_handle = chain
        .task_executor
        .clone()
        .spawn_handle(
            async move {
                prepare_execution_payload::<T, Payload>(
                    &chain,
                    is_merge_transition_complete,
                    timestamp,
                    random,
                    proposer_index,
                    latest_execution_payload_header_block_hash,
                    builder_params,
                )
                .await
            },
            "get_execution_payload",
        )
        .ok_or(BlockProductionError::ShuttingDown)?;

    Ok(join_handle)
}

/// Wraps the async `prepare_execution_payload` function as a blocking task.
pub fn prepare_execution_payload_and_blobs_blocking<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    state: &BeaconState<T::EthSpec>,
    proposer_index: u64,
) -> Result<
    Option<(
        ExecutionPayload<T::EthSpec>,
        VariableList<
            KZGCommitment,
            <<T as BeaconChainTypes>::EthSpec as EthSpec>::MaxObjectListSize,
        >,
    )>,
    BlockProductionError,
> {
    let execution_layer = chain
        .execution_layer
        .as_ref()
        .ok_or(BlockProductionError::ExecutionLayerMissing)?;

    execution_layer
        .block_on_generic(|_| async {
            prepare_execution_payload_and_blobs(chain, state, proposer_index).await
        })
        .map_err(BlockProductionError::BlockingFailed)?
}

/// Prepares an execution payload for inclusion in a block.
///
/// Will return `Ok(None)` if the merge fork has occurred, but a terminal block has not been found.
///
/// ## Errors
///
/// Will return an error when using a pre-merge fork `state`. Ensure to only run this function
/// after the merge fork.
///
/// ## Specification
///
/// Equivalent to the `prepare_execution_payload` function in the Validator Guide:
///
/// https://github.com/ethereum/consensus-specs/blob/v1.1.5/specs/merge/validator.md#block-proposal
#[allow(clippy::too_many_arguments)]
pub async fn prepare_execution_payload<T, Payload>(
    chain: &Arc<BeaconChain<T>>,
    is_merge_transition_complete: bool,
    timestamp: u64,
    random: Hash256,
    proposer_index: u64,
    latest_execution_payload_header_block_hash: ExecutionBlockHash,
    builder_params: BuilderParams,
) -> Result<Payload, BlockProductionError>
where
    T: BeaconChainTypes,
    Payload: ExecPayload<T::EthSpec> + Default,
{
    let current_epoch = builder_params.slot.epoch(T::EthSpec::slots_per_epoch());
    let spec = &chain.spec;
    let execution_layer = chain
        .execution_layer
        .as_ref()
        .ok_or(BlockProductionError::ExecutionLayerMissing)?;

    let parent_hash = if !is_merge_transition_complete {
        let is_terminal_block_hash_set = spec.terminal_block_hash != ExecutionBlockHash::zero();
        let is_activation_epoch_reached =
            current_epoch >= spec.terminal_block_hash_activation_epoch;

        if is_terminal_block_hash_set && !is_activation_epoch_reached {
            // Use the "empty" payload if there's a terminal block hash, but we haven't reached the
            // terminal block epoch yet.
            return Ok(<_>::default());
        }

        let terminal_pow_block_hash = execution_layer
            .get_terminal_pow_block_hash(spec, timestamp)
            .await
            .map_err(BlockProductionError::TerminalPoWBlockLookupFailed)?;

        if let Some(terminal_pow_block_hash) = terminal_pow_block_hash {
            terminal_pow_block_hash
        } else {
            // If the merge transition hasn't occurred yet and the EL hasn't found the terminal
            // block, return an "empty" payload.
            return Ok(<_>::default());
        }
    } else {
        latest_execution_payload_header_block_hash
    };

    // Try to obtain the fork choice update parameters from the cached head.
    //
    // Use a blocking task to interact with the `canonical_head` lock otherwise we risk blocking the
    // core `tokio` executor.
    let inner_chain = chain.clone();
    let forkchoice_update_params = chain
        .spawn_blocking_handle(
            move || {
                inner_chain
                    .canonical_head
                    .cached_head()
                    .forkchoice_update_parameters()
            },
            "prepare_execution_payload_forkchoice_update_params",
        )
        .await
        .map_err(BlockProductionError::BeaconChain)?;

    // Note: the suggested_fee_recipient is stored in the `execution_layer`, it will add this parameter.
    //
    // This future is not executed here, it's up to the caller to await it.
    let execution_payload = execution_layer
        .get_payload::<Payload>(
            parent_hash,
            timestamp,
            random,
            proposer_index,
            forkchoice_update_params,
            builder_params,
            &chain.spec,
        )
        .await
        .map_err(BlockProductionError::GetPayloadFailed)?;

    Ok(execution_payload)
}

pub async fn prepare_execution_payload_and_blobs<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    state: &BeaconState<T::EthSpec>,
    proposer_index: u64,
) -> Result<
    Option<(
        ExecutionPayload<T::EthSpec>,
        VariableList<
            KZGCommitment,
            <<T as BeaconChainTypes>::EthSpec as EthSpec>::MaxObjectListSize,
        >,
    )>,
    BlockProductionError,
> {
    let spec = &chain.spec;
    let execution_layer = chain
        .execution_layer
        .as_ref()
        .ok_or(BlockProductionError::ExecutionLayerMissing)?;

    let parent_hash = if !is_merge_transition_complete(state) {
        let is_terminal_block_hash_set = spec.terminal_block_hash != Hash256::zero();
        let is_activation_epoch_reached =
            state.current_epoch() >= spec.terminal_block_hash_activation_epoch;

        if is_terminal_block_hash_set && !is_activation_epoch_reached {
            return Ok(None);
        }

        let terminal_pow_block_hash = execution_layer
            .get_terminal_pow_block_hash(spec)
            .await
            .map_err(BlockProductionError::TerminalPoWBlockLookupFailed)?;

        if let Some(terminal_pow_block_hash) = terminal_pow_block_hash {
            terminal_pow_block_hash
        } else {
            return Ok(None);
        }
    } else {
        state.latest_execution_payload_header()?.block_hash
    };

    let timestamp = compute_timestamp_at_slot(state, spec).map_err(BeaconStateError::from)?;
    let random = *state.get_randao_mix(state.current_epoch())?;
    let finalized_root = state.finalized_checkpoint().root;

    // The finalized block hash is not included in the specification, however we provide this
    // parameter so that the execution layer can produce a payload id if one is not already known
    // (e.g., due to a recent reorg).
    let finalized_block_hash =
        if let Some(block) = chain.fork_choice.read().get_block(&finalized_root) {
            block.execution_status.block_hash()
        } else {
            chain
                .store
                .get_block(&finalized_root)
                .map_err(BlockProductionError::FailedToReadFinalizedBlock)?
                .ok_or(BlockProductionError::MissingFinalizedBlock(finalized_root))?
                .message()
                .body()
                .execution_payload()
                .ok()
                .map(|ep| ep.block_hash)
        };

    // Note: the suggested_fee_recipient is stored in the `execution_layer`, it will add this parameter.
    let execution_payload = execution_layer
        .get_payload(
            parent_hash,
            timestamp,
            random,
            finalized_block_hash.unwrap_or_else(Hash256::zero),
            proposer_index,
        )
        .await
        .map_err(BlockProductionError::GetPayloadFailed)?;

    //FIXME(sean)
    for tx in execution_payload.blob_txns_iter() {
        let versioned_hash = Hash256::zero();
        // get versioned hash
        let blob = execution_layer
            .get_blob::<T::EthSpec>(
                parent_hash,
                timestamp,
                random,
                finalized_root,
                proposer_index,
                versioned_hash,
            )
            .await
            .map_err(BlockProductionError::GetPayloadFailed)?;
    }

    Ok(Some((execution_payload, VariableList::empty())))
}
