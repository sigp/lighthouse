use crate::{BeaconChain, BeaconChainTypes, BlockProductionError};
use state_processing::per_block_processing::{compute_timestamp_at_slot, is_merge_complete};
use types::*;

pub fn prepare_execution_payload_blocking<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    state: &BeaconState<T::EthSpec>,
) -> Result<Option<ExecutionPayload<T::EthSpec>>, BlockProductionError> {
    let execution_layer = chain
        .execution_layer
        .as_ref()
        .ok_or(BlockProductionError::ExecutionLayerMissing)?;

    execution_layer
        .block_on_generic(|_| async { prepare_execution_payload(chain, state).await })
        .map_err(BlockProductionError::BlockingFailed)?
}

pub async fn prepare_execution_payload<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    state: &BeaconState<T::EthSpec>,
) -> Result<Option<ExecutionPayload<T::EthSpec>>, BlockProductionError> {
    let spec = &chain.spec;
    let execution_layer = chain
        .execution_layer
        .as_ref()
        .ok_or(BlockProductionError::ExecutionLayerMissing)?;

    let parent_hash = if !is_merge_complete(&state) {
        let is_terminal_block_hash_set = spec.terminal_block_hash != Hash256::zero();
        let is_activation_epoch_reached =
            state.current_epoch() >= spec.terminal_block_hash_activation_epoch;

        if is_terminal_block_hash_set && !is_activation_epoch_reached {
            return Ok(None);
        }

        let terminal_pow_block_hash = execution_layer
            .get_terminal_pow_block_hash()
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

    let timestamp = compute_timestamp_at_slot(&state, spec).map_err(BeaconStateError::from)?;
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
                .map(|ep| ep.block_hash)
        };

    // Note: the fee_recipient is stored in the `execution_layer`, it will add this parameter.
    let execution_payload = execution_layer
        .get_payload(
            parent_hash,
            timestamp,
            random,
            finalized_block_hash.unwrap_or_else(Hash256::zero),
        )
        .await
        .map_err(BlockProductionError::GetPayloadFailed)?;

    Ok(Some(execution_payload))
}
