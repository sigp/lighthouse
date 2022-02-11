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
use execution_layer::ExecutePayloadResponseStatus;
use fork_choice::PayloadVerificationStatus;
use proto_array::{Block as ProtoBlock, ExecutionStatus};
use slog::debug;
use slot_clock::SlotClock;
use state_processing::per_block_processing::{
    compute_timestamp_at_slot, is_execution_enabled, is_merge_transition_complete,
    partially_verify_execution_payload,
};
use types::*;

/// Verify that `execution_payload` contained by `block` is considered valid by an execution
/// engine.
///
/// ## Specification
///
/// Equivalent to the `execute_payload` function in the merge Beacon Chain Changes, although it
/// contains a few extra checks by running `partially_verify_execution_payload` first:
///
/// https://github.com/ethereum/consensus-specs/blob/v1.1.5/specs/merge/beacon-chain.md#execute_payload
pub fn execute_payload<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    state: &BeaconState<T::EthSpec>,
    block: BeaconBlockRef<T::EthSpec>,
) -> Result<PayloadVerificationStatus, BlockError<T::EthSpec>> {
    if !is_execution_enabled(state, block.body()) {
        return Ok(PayloadVerificationStatus::Irrelevant);
    }

    let execution_payload = block.execution_payload()?;

    // Perform the initial stages of payload verification.
    //
    // We will duplicate these checks again during `per_block_processing`, however these checks
    // are cheap and doing them here ensures we protect the execution payload from junk.
    partially_verify_execution_payload(state, execution_payload, &chain.spec)
        .map_err(BlockError::PerBlockProcessingError)?;

    let execution_layer = chain
        .execution_layer
        .as_ref()
        .ok_or(ExecutionPayloadError::NoExecutionConnection)?;
    let execute_payload_response = execution_layer
        .block_on(|execution_layer| execution_layer.execute_payload(execution_payload));

    match execute_payload_response {
        Ok((status, _latest_valid_hash)) => match status {
            ExecutePayloadResponseStatus::Valid => Ok(PayloadVerificationStatus::Verified),
            // TODO(merge): invalidate any invalid ancestors of this block in fork choice.
            ExecutePayloadResponseStatus::Invalid => {
                Err(ExecutionPayloadError::RejectedByExecutionEngine.into())
            }
            ExecutePayloadResponseStatus::Syncing => Ok(PayloadVerificationStatus::NotVerified),
        },
        Err(_) => Err(ExecutionPayloadError::RejectedByExecutionEngine.into()),
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
pub fn validate_merge_block<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    block: BeaconBlockRef<T::EthSpec>,
) -> Result<(), BlockError<T::EthSpec>> {
    let spec = &chain.spec;
    let block_epoch = block.slot().epoch(T::EthSpec::slots_per_epoch());
    let execution_payload = block.execution_payload()?;

    if spec.terminal_block_hash != Hash256::zero() {
        if block_epoch < spec.terminal_block_hash_activation_epoch {
            return Err(ExecutionPayloadError::InvalidActivationEpoch {
                activation_epoch: spec.terminal_block_hash_activation_epoch,
                epoch: block_epoch,
            }
            .into());
        }

        if execution_payload.parent_hash != spec.terminal_block_hash {
            return Err(ExecutionPayloadError::InvalidTerminalBlockHash {
                terminal_block_hash: spec.terminal_block_hash,
                payload_parent_hash: execution_payload.parent_hash,
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
        .block_on(|execution_layer| {
            execution_layer.is_valid_terminal_pow_block_hash(execution_payload.parent_hash, spec)
        })
        .map_err(ExecutionPayloadError::from)?;

    match is_valid_terminal_pow_block {
        Some(true) => Ok(()),
        Some(false) => Err(ExecutionPayloadError::InvalidTerminalPoWBlock {
            parent_hash: execution_payload.parent_hash,
        }
        .into()),
        None => {
            debug!(
                chain.log,
                "Optimistically accepting terminal block";
                "block_hash" => ?execution_payload.parent_hash,
                "msg" => "the terminal block/parent was unavailable"
            );
            Ok(())
        }
    }
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
            ExecutionStatus::Valid(_) | ExecutionStatus::Unknown(_) => true,
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
            if execution_payload.timestamp != expected_timestamp {
                return Err(BlockError::ExecutionPayloadError(
                    ExecutionPayloadError::InvalidPayloadTimestamp {
                        expected: expected_timestamp,
                        found: execution_payload.timestamp,
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
pub fn get_execution_payload<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    state: &BeaconState<T::EthSpec>,
    proposer_index: u64,
) -> Result<ExecutionPayload<T::EthSpec>, BlockProductionError> {
    Ok(prepare_execution_payload_blocking(chain, state, proposer_index)?.unwrap_or_default())
}

/// Wraps the async `prepare_execution_payload` function as a blocking task.
pub fn prepare_execution_payload_blocking<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    state: &BeaconState<T::EthSpec>,
    proposer_index: u64,
) -> Result<Option<ExecutionPayload<T::EthSpec>>, BlockProductionError> {
    let execution_layer = chain
        .execution_layer
        .as_ref()
        .ok_or(BlockProductionError::ExecutionLayerMissing)?;

    execution_layer
        .block_on_generic(|_| async {
            prepare_execution_payload(chain, state, proposer_index).await
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
pub async fn prepare_execution_payload<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    state: &BeaconState<T::EthSpec>,
    proposer_index: u64,
) -> Result<Option<ExecutionPayload<T::EthSpec>>, BlockProductionError> {
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

    Ok(Some(execution_payload))
}
