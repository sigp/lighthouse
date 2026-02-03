use std::sync::Arc;

use execution_layer::{BlockProposalContentsType, BuilderParams};
use ssz_types::VariableList;
use state_processing::state_advance::complete_state_advance;
use tracing::instrument;
use types::{
    Address, BeaconState, BlockProductionVersion, BuilderIndex, ExecutionPayload,
    ExecutionPayloadBid, Hash256, ProposerPreferences, Slot,
};

use crate::{
    BeaconChain, BeaconChainError, BeaconChainTypes, BlockProductionError,
    execution_payload::get_execution_payload,
};

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Produce an `ExecutionPayloadBid` for some `slot` upon the given `state`.
    #[instrument(level = "debug", skip_all)]
    pub async fn produce_execution_payload_bid(
        self: &Arc<Self>,
        mut state: BeaconState<T::EthSpec>,
        state_root: Hash256,
        execution_payload: ExecutionPayload<T::EthSpec>,
        produce_at_slot: Slot,
        proposer_preferences: Option<ProposerPreferences>,
        builder_index: BuilderIndex,
        value: u64,
    ) -> Result<ExecutionPayloadBid<T::EthSpec>, BlockProductionError> {
        // It is invalid to try to produce a block using a state from a future slot.
        if state.slot() > produce_at_slot {
            return Err(BlockProductionError::StateSlotTooHigh {
                produce_at_slot,
                state_slot: state.slot(),
            });
        }

        // TODO(gloas) add sanity check on value
        // The builder MUST have enough excess balance to fulfill this bid (i.e. `value`) and all pending payments.

        // TODO(gloas) add metrics for execution payload bid production

        // Ensure the state has performed a complete transition into the required slot.
        complete_state_advance(&mut state, Some(state_root), produce_at_slot, &self.spec)?;

        let parent_root = if state.slot() > 0 {
            *state
                .get_block_root(state.slot() - 1)
                .map_err(|_| BlockProductionError::UnableToGetBlockRootFromState)?
        } else {
            state.latest_block_header().canonical_root()
        };

        let proposer_index = state.get_beacon_proposer_index(state.slot(), &self.spec)? as u64;

        let pubkey = state
            .validators()
            .get(proposer_index as usize)
            .map(|v| v.pubkey)
            .ok_or(BlockProductionError::BeaconChain(Box::new(
                BeaconChainError::ValidatorIndexUnknown(proposer_index as usize),
            )))?;

        let builder_params = BuilderParams {
            pubkey,
            slot: state.slot(),
            chain_health: self
                .is_healthy(&parent_root)
                .map_err(|e| BlockProductionError::BeaconChain(Box::new(e)))?,
        };

        // TODO(gloas) this should be BlockProductionVersion::V4
        // V3 is okay for now as long as we're not connected to a builder
        // TODO(gloas) add builder boost factor
        let prepare_payload_handle = get_execution_payload(
            self.clone(),
            &state,
            parent_root,
            proposer_index,
            builder_params,
            None,
            BlockProductionVersion::V3,
        )?;

        let block_contents_type_option = Some(
            prepare_payload_handle
                .await
                .map_err(BlockProductionError::TokioJoin)?
                .ok_or(BlockProductionError::ShuttingDown)??,
        );

        let blob_kzg_commitments = if let Some(block_contents_type) = block_contents_type_option {
            match block_contents_type {
                BlockProposalContentsType::Full(block_proposal_contents) => {
                    let blob_kzg_commitments =
                        block_proposal_contents.blob_kzg_commitments().cloned();

                    if let Some(blob_kzg_commitments) = blob_kzg_commitments {
                        blob_kzg_commitments
                    } else {
                        return Err(BlockProductionError::MissingKzgCommitment(
                            "No KZG commitments from the payload".to_owned(),
                        ));
                    }
                }
                // TODO(gloas) we should never receive a blinded response.
                // Should return some type of `Unexpected` error variant as this should never happen
                // in the V4 block production flow
                BlockProposalContentsType::Blinded(_) => {
                    return Err(BlockProductionError::GloasNotImplemented);
                }
            }
        } else {
            todo!()
        };

        let bid = if let Some(proposer_preferences) = proposer_preferences
            && proposer_preferences.proposal_slot == produce_at_slot
        {
            // Trustless bid
            ExecutionPayloadBid::<T::EthSpec> {
                parent_block_hash: state.latest_block_hash()?.to_owned(),
                parent_block_root: state.get_latest_block_root(state_root),
                block_hash: execution_payload.block_hash(),
                prev_randao: execution_payload.prev_randao(),
                fee_recipient: proposer_preferences.fee_recipient,
                // TODO(gloas) payload construction should factor in the proposers gas limit preferences
                gas_limit: execution_payload.gas_limit(),
                builder_index,
                slot: produce_at_slot,
                value,
                execution_payment: 0,
                blob_kzg_commitments,
            }
        } else if builder_index == u64::MAX {
            // Local bid
            ExecutionPayloadBid::<T::EthSpec> {
                parent_block_hash: state.latest_block_hash()?.to_owned(),
                parent_block_root: state.get_latest_block_root(state_root),
                block_hash: execution_payload.block_hash(),
                prev_randao: execution_payload.prev_randao(),
                fee_recipient: Address::ZERO,
                gas_limit: execution_payload.gas_limit(),
                builder_index,
                slot: produce_at_slot,
                value,
                execution_payment: 0,
                blob_kzg_commitments,
            }
        } else {
            // No proposer preferences and this isn't local building
            // TODO(gloas) this should return a specific error type
            // i.e if proposer prefs are missing and its a trustless bid
            // return an error that communicates that.
            return Err(BlockProductionError::GloasNotImplemented);
        };

        Ok(bid)
    }
}
