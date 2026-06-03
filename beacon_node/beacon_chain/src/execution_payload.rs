//! This module contains various functions for producing and verifying `ExecutionPayloads`.
//!
//! Lighthouse tends to do payload tasks in *slightly* different locations to the specification.
//! This is because some tasks involve calling out to external servers and it's nice to keep those
//! away from our pure `state_processing` and `fork_choice` crates.
//!
//! So, this module contains functions that one might expect to find in other crates, but they live
//! here for good reason.

use crate::{
    BeaconChain, BeaconChainError, BeaconChainTypes, BlockError, BlockProductionError,
    ExecutionPayloadError,
};
use execution_layer::{
    BlockProposalContentsType, BuilderParams, NewPayloadRequest, PayloadAttributes,
    PayloadParameters, PayloadStatus,
};
use fork_choice::{InvalidationOperation, PayloadVerificationStatus};
use proto_array::{Block as ProtoBlock, ExecutionStatus};
use slot_clock::SlotClock;
use state_processing::per_block_processing::{
    compute_timestamp_at_slot, get_expected_withdrawals, is_execution_enabled,
    partially_verify_execution_payload,
};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{Instrument, debug_span, warn};
use types::execution::BlockProductionVersion;
use types::*;

pub type PreparePayloadResult<E> = Result<BlockProposalContentsType<E>, BlockProductionError>;
pub type PreparePayloadHandle<E> = JoinHandle<Option<PreparePayloadResult<E>>>;

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
    ) -> Result<Self, BlockError> {
        let payload_verification_status = if block.fork_name_unchecked().gloas_enabled() {
            // Gloas blocks don't contain an execution payload.
            Some(PayloadVerificationStatus::Irrelevant)
        } else if is_execution_enabled(state, block.message().body()) {
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
                            block_number = ?block_message.execution_payload().map(|payload| payload.block_number()),
                            info = "you can silence this warning with --disable-optimistic-finalized-sync",
                            error = ?e,
                            "Falling back to slow block hash verification"
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

    pub async fn notify_new_payload(self) -> Result<PayloadVerificationStatus, BlockError> {
        if let Some(precomputed_status) = self.payload_verification_status {
            Ok(precomputed_status)
        } else {
            notify_new_payload(
                &self.chain,
                self.block.message().slot(),
                self.block.message().parent_root(),
                self.block.message().try_into()?,
            )
            .await
        }
    }
}

/// Verify that `execution_payload` is considered valid by an execution
/// engine.
///
/// ## Specification
///
/// Equivalent to the `notify_new_payload` function in the merge Beacon Chain Changes, although it
/// contains a few extra checks by running `partially_verify_execution_payload` first:
///
/// https://github.com/ethereum/consensus-specs/blob/v1.1.9/specs/bellatrix/beacon-chain.md#notify_new_payload
pub async fn notify_new_payload<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    slot: Slot,
    parent_beacon_block_root: Hash256,
    new_payload_request: NewPayloadRequest<'_, T::EthSpec>,
) -> Result<PayloadVerificationStatus, BlockError> {
    let execution_layer = chain
        .execution_layer
        .as_ref()
        .ok_or(ExecutionPayloadError::NoExecutionConnection)?;

    let execution_block_hash = new_payload_request.execution_payload_ref().block_hash();
    let new_payload_response = execution_layer
        .notify_new_payload(new_payload_request.clone())
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
                warn!(
                    ?validation_error,
                    ?latest_valid_hash,
                    ?execution_block_hash,
                    %slot,
                    method = "new_payload",
                    "Invalid execution payload"
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
                    chain
                        .process_invalid_execution_payload(&InvalidationOperation::InvalidateMany {
                            head_block_root: parent_beacon_block_root,
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
                    ?validation_error,
                    ?execution_block_hash,
                    %slot,
                    method = "new_payload",
                    "Invalid execution payload block hash"
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

/// Validate the gossip block's execution_payload according to the checks described here:
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/merge/p2p-interface.md#beacon_block
pub fn validate_execution_payload_for_gossip<T: BeaconChainTypes>(
    parent_block: &ProtoBlock,
    block: BeaconBlockRef<'_, T::EthSpec>,
    chain: &BeaconChain<T>,
) -> Result<(), BlockError> {
    // Gloas blocks don't have an execution payload in the block body.
    // Bid-related validations are handled in gossip block verification.
    if block.fork_name_unchecked().gloas_enabled() {
        return Ok(());
    }

    // Only apply this validation if this is a Bellatrix beacon block.
    if let Ok(execution_payload) = block.body().execution_payload() {
        // Check parent execution status to determine if we should validate the payload.
        // We use only the execution status of the parent here to avoid loading the parent state
        // during gossip verification.

        let parent_has_execution = match parent_block.execution_status {
            // Parent has valid or optimistic execution status.
            ExecutionStatus::Valid(_) | ExecutionStatus::Optimistic(_) => true,
            // Pre-merge blocks have irrelevant execution status.
            ExecutionStatus::Irrelevant(_) => false,
            // If the parent has an invalid payload then it's impossible to build a valid block upon
            // it. Reject the block.
            ExecutionStatus::Invalid(_) => {
                return Err(BlockError::ParentExecutionPayloadInvalid {
                    parent_root: parent_block.root,
                });
            }
        };

        if parent_has_execution || !execution_payload.is_default_with_empty_roots() {
            let expected_timestamp = chain
                .slot_clock
                .start_of(block.slot())
                .map(|d| d.as_secs())
                .ok_or(BlockError::BeaconChainError(Box::new(
                    BeaconChainError::UnableToComputeTimeAtSlot,
                )))?;

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
    let timestamp =
        compute_timestamp_at_slot(state, state.slot(), spec).map_err(BeaconStateError::from)?;
    let random = *state.get_randao_mix(current_epoch)?;
    let latest_execution_payload_header = state.latest_execution_payload_header()?;
    let latest_execution_payload_header_block_hash = latest_execution_payload_header.block_hash();
    let latest_execution_payload_header_gas_limit = latest_execution_payload_header.gas_limit();
    let withdrawals = if state.fork_name_unchecked().capella_enabled() {
        Some(Withdrawals::<T::EthSpec>::from(get_expected_withdrawals(state, spec)?).into())
    } else {
        None
    };
    let parent_beacon_block_root = if state.fork_name_unchecked().deneb_enabled() {
        Some(parent_block_root)
    } else {
        None
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
                    timestamp,
                    random,
                    proposer_index,
                    latest_execution_payload_header_block_hash,
                    latest_execution_payload_header_gas_limit,
                    builder_params,
                    withdrawals,
                    parent_beacon_block_root,
                    builder_boost_factor,
                    block_production_version,
                )
                .await
            }
            .instrument(debug_span!("prepare_execution_payload")),
            "prepare_execution_payload",
        )
        .ok_or(BlockProductionError::ShuttingDown)?;

    Ok(join_handle)
}

/// Prepares an execution payload (pre-gloas) for inclusion in a block.
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
    timestamp: u64,
    random: Hash256,
    proposer_index: u64,
    latest_execution_payload_header_block_hash: ExecutionBlockHash,
    latest_execution_payload_header_gas_limit: u64,
    builder_params: BuilderParams,
    withdrawals: Option<Vec<Withdrawal>>,
    parent_beacon_block_root: Option<Hash256>,
    builder_boost_factor: Option<u64>,
    block_production_version: BlockProductionVersion,
) -> Result<BlockProposalContentsType<T::EthSpec>, BlockProductionError>
where
    T: BeaconChainTypes,
{
    let spec = &chain.spec;
    let fork = spec.fork_name_at_slot::<T::EthSpec>(builder_params.slot);

    if fork.gloas_enabled() {
        return Err(BlockProductionError::InvalidBlockVariant(
            "Called pre-gloas prepare_execution_payload on a gloas block".to_string(),
        ));
    }

    let execution_layer = chain
        .execution_layer
        .as_ref()
        .ok_or(BlockProductionError::ExecutionLayerMissing)?;

    let parent_hash = latest_execution_payload_header_block_hash;

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
        .instrument(debug_span!("forkchoice_update_params"))
        .await
        .map_err(|e| BlockProductionError::BeaconChain(Box::new(e)))?;

    let suggested_fee_recipient = execution_layer
        .get_suggested_fee_recipient(proposer_index)
        .await;

    let payload_attributes = PayloadAttributes::new(
        timestamp,
        random,
        suggested_fee_recipient,
        withdrawals,
        parent_beacon_block_root,
        None,
        None,
    );

    let target_gas_limit = execution_layer.get_proposer_gas_limit(proposer_index).await;
    let payload_parameters = PayloadParameters {
        parent_hash,
        parent_gas_limit: Some(latest_execution_payload_header_gas_limit),
        proposer_gas_limit: target_gas_limit,
        payload_attributes: &payload_attributes,
        forkchoice_update_params: &forkchoice_update_params,
        current_fork: fork,
    };

    let block_contents = execution_layer
        .get_payload(
            payload_parameters,
            builder_params,
            &chain.spec,
            builder_boost_factor,
            block_production_version,
        )
        .await
        .map_err(BlockProductionError::GetPayloadFailed)?;

    Ok(block_contents)
}
