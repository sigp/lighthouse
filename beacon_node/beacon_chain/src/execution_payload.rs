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
use execution_layer::{
    BlockProposalContents, BlockProposalContentsType, BuilderParams, NewPayloadRequest,
    PayloadAttributes, PayloadStatus,
};
use fork_choice::{InvalidationOperation, PayloadVerificationStatus};
use proto_array::{Block as ProtoBlock, ExecutionStatus};
use slog::{debug, warn};
use slot_clock::SlotClock;
use state_processing::per_block_processing::{
    compute_timestamp_at_slot, get_expected_withdrawals, is_execution_enabled,
    is_merge_transition_complete, partially_verify_execution_payload,
};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tree_hash::TreeHash;
use types::payload::BlockProductionVersion;
use types::*;

pub type PreparePayloadResult<E> = Result<BlockProposalContentsType<E>, BlockProductionError>;
pub type PreparePayloadHandle<E> = JoinHandle<Option<PreparePayloadResult<E>>>;

#[derive(PartialEq)]
pub enum AllowOptimisticImport {
    Yes,
    No,
}

/// Signal whether the execution payloads of new blocks should be
/// immediately verified with the EL or imported optimistically without
/// any EL communication.
#[derive(Default, Clone, Copy)]
pub enum NotifyExecutionLayer {
    #[default]
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
        notify_execution_layer: NotifyExecutionLayer,
    ) -> Result<Self, BlockError<T::EthSpec>> {
        let payload_verification_status = if is_execution_enabled(state, block.message().body()) {
            // Perform the initial stages of payload verification.
            //
            // We will duplicate these checks again during `per_block_processing`, however these
            // checks are cheap and doing them here ensures we have verified them before marking
            // the block as optimistically imported. This is particularly relevant in the case
            // where we do not send the block to the EL at all.
            let block_message = block.message();
            partially_verify_execution_payload::<_, FullPayload<_>>(
                state,
                block.slot(),
                block_message.body(),
                &chain.spec,
            )
            .map_err(BlockError::PerBlockProcessingError)?;

            match notify_execution_layer {
                NotifyExecutionLayer::No if chain.config.optimistic_finalized_sync => {
                    // Create a NewPayloadRequest (no clones required) and check optimistic sync verifications
                    let new_payload_request: NewPayloadRequest<T::EthSpec> =
                        block_message.try_into()?;
                    if let Err(e) = new_payload_request.perform_optimistic_sync_verifications() {
                        warn!(
                            chain.log,
                            "Falling back to slow block hash verification";
                            "block_number" => ?block_message.execution_payload().map(|payload| payload.block_number()),
                            "info" => "you can silence this warning with --disable-optimistic-finalized-sync",
                            "error" => ?e,
                        );
                        None
                    } else {
                        Some(PayloadVerificationStatus::Optimistic)
                    }
                }
                _ => None,
            }
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
    let execution_layer = chain
        .execution_layer
        .as_ref()
        .ok_or(ExecutionPayloadError::NoExecutionConnection)?;

    let execution_block_hash = block.execution_payload()?.block_hash();
    let new_payload_response = execution_layer.notify_new_payload(block.try_into()?).await;

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
                warn!(
                    chain.log,
                    "Invalid execution payload";
                    "validation_error" => ?validation_error,
                    "latest_valid_hash" => ?latest_valid_hash,
                    "execution_block_hash" => ?execution_block_hash,
                    "root" => ?block.tree_hash_root(),
                    "graffiti" => block.body().graffiti().as_utf8_lossy(),
                    "proposer_index" => block.proposer_index(),
                    "slot" => block.slot(),
                    "method" => "new_payload",
                );

                // Only trigger payload invalidation in fork choice if the
                // `latest_valid_hash` is `Some` and non-zero.
                //
                // A `None` latest valid hash indicates that the EE was unable
                // to determine the most recent valid ancestor. Since `block`
                // has not yet been applied to fork choice, there's nothing to
                // invalidate.
                //
                // An all-zeros payload indicates that an EIP-3675 check has
                // failed regarding the validity of the terminal block. Rather
                // than iterating back in the chain to find the terminal block
                // and invalidating that, we simply reject this block without
                // invalidating anything else.
                if let Some(latest_valid_hash) =
                    latest_valid_hash.filter(|hash| *hash != ExecutionBlockHash::zero())
                {
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
                }

                Err(ExecutionPayloadError::RejectedByExecutionEngine { status }.into())
            }
            PayloadStatus::InvalidBlockHash {
                ref validation_error,
            } => {
                warn!(
                    chain.log,
                    "Invalid execution payload block hash";
                    "validation_error" => ?validation_error,
                    "execution_block_hash" => ?execution_block_hash,
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
    // Only apply this validation if this is a Bellatrix beacon block.
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

        if is_merge_transition_complete || !execution_payload.is_default_with_empty_roots() {
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
/// after the Bellatrix fork.
///
/// ## Specification
///
/// Equivalent to the `get_execution_payload` function in the Validator Guide:
///
/// https://github.com/ethereum/consensus-specs/blob/v1.1.5/specs/merge/validator.md#block-proposal
pub fn get_execution_payload<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    state: &BeaconState<T::EthSpec>,
    parent_block_root: Hash256,
    proposer_index: u64,
    builder_params: BuilderParams,
    builder_boost_factor: Option<u64>,
    block_production_version: BlockProductionVersion,
) -> Result<PreparePayloadHandle<T::EthSpec>, BlockProductionError> {
    // Compute all required values from the `state` now to avoid needing to pass it into a spawned
    // task.
    let spec = &chain.spec;
    let current_epoch = state.current_epoch();
    let is_merge_transition_complete = is_merge_transition_complete(state);
    let timestamp =
        compute_timestamp_at_slot(state, state.slot(), spec).map_err(BeaconStateError::from)?;
    let random = *state.get_randao_mix(current_epoch)?;
    let latest_execution_payload_header_block_hash =
        state.latest_execution_payload_header()?.block_hash();
    let withdrawals = match state {
        &BeaconState::Capella(_) | &BeaconState::Deneb(_) | &BeaconState::Electra(_) => {
            Some(get_expected_withdrawals(state, spec)?.into())
        }
        &BeaconState::Bellatrix(_) => None,
        // These shouldn't happen but they're here to make the pattern irrefutable
        &BeaconState::Base(_) | &BeaconState::Altair(_) => None,
    };
    let parent_beacon_block_root = match state {
        BeaconState::Deneb(_) | BeaconState::Electra(_) => Some(parent_block_root),
        BeaconState::Bellatrix(_) | BeaconState::Capella(_) => None,
        // These shouldn't happen but they're here to make the pattern irrefutable
        BeaconState::Base(_) | BeaconState::Altair(_) => None,
    };

    // Spawn a task to obtain the execution payload from the EL via a series of async calls. The
    // `join_handle` can be used to await the result of the function.
    let join_handle = chain
        .task_executor
        .clone()
        .spawn_handle(
            async move {
                prepare_execution_payload::<T>(
                    &chain,
                    is_merge_transition_complete,
                    timestamp,
                    random,
                    proposer_index,
                    latest_execution_payload_header_block_hash,
                    builder_params,
                    withdrawals,
                    parent_beacon_block_root,
                    builder_boost_factor,
                    block_production_version,
                )
                .await
            },
            "get_execution_payload",
        )
        .ok_or(BlockProductionError::ShuttingDown)?;

    Ok(join_handle)
}

/// Prepares an execution payload for inclusion in a block.
///
/// Will return `Ok(None)` if the Bellatrix fork has occurred, but a terminal block has not been found.
///
/// ## Errors
///
/// Will return an error when using a pre-Bellatrix fork `state`. Ensure to only run this function
/// after the Bellatrix fork.
///
/// ## Specification
///
/// Equivalent to the `prepare_execution_payload` function in the Validator Guide:
///
/// https://github.com/ethereum/consensus-specs/blob/v1.1.5/specs/merge/validator.md#block-proposal
#[allow(clippy::too_many_arguments)]
pub async fn prepare_execution_payload<T>(
    chain: &Arc<BeaconChain<T>>,
    is_merge_transition_complete: bool,
    timestamp: u64,
    random: Hash256,
    proposer_index: u64,
    latest_execution_payload_header_block_hash: ExecutionBlockHash,
    builder_params: BuilderParams,
    withdrawals: Option<Vec<Withdrawal>>,
    parent_beacon_block_root: Option<Hash256>,
    builder_boost_factor: Option<u64>,
    block_production_version: BlockProductionVersion,
) -> Result<BlockProposalContentsType<T::EthSpec>, BlockProductionError>
where
    T: BeaconChainTypes,
{
    let current_epoch = builder_params.slot.epoch(T::EthSpec::slots_per_epoch());
    let spec = &chain.spec;
    let fork = spec.fork_name_at_slot::<T::EthSpec>(builder_params.slot);
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
            return Ok(BlockProposalContentsType::Full(
                BlockProposalContents::Payload {
                    payload: FullPayload::default_at_fork(fork)?,
                    block_value: Uint256::zero(),
                },
            ));
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
            return Ok(BlockProposalContentsType::Full(
                BlockProposalContents::Payload {
                    payload: FullPayload::default_at_fork(fork)?,
                    block_value: Uint256::zero(),
                },
            ));
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

    let suggested_fee_recipient = execution_layer
        .get_suggested_fee_recipient(proposer_index)
        .await;
    let payload_attributes = PayloadAttributes::new(
        timestamp,
        random,
        suggested_fee_recipient,
        withdrawals,
        parent_beacon_block_root,
    );

    let block_contents = execution_layer
        .get_payload(
            parent_hash,
            &payload_attributes,
            forkchoice_update_params,
            builder_params,
            fork,
            &chain.spec,
            builder_boost_factor,
            block_production_version,
        )
        .await
        .map_err(BlockProductionError::GetPayloadFailed)?;

    Ok(block_contents)
}
