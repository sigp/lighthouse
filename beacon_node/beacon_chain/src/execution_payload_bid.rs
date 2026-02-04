use std::{sync::Arc, u64};

use bls::Signature;
use execution_layer::{BlockProposalContentsType, BuilderParams};
use tracing::instrument;
use types::{
    Address, BeaconState, BlockProductionVersion, BuilderIndex, ExecutionPayloadBid,
    ExecutionPayloadGloas, ExecutionRequests, Hash256, SignedExecutionPayloadBid, Slot,
};

use crate::{
    BeaconChain, BeaconChainError, BeaconChainTypes, BlockProductionError,
    execution_payload::get_execution_payload,
};

/// Data needed to construct an ExecutionPayloadEnvelope.
/// The envelope requires the beacon_block_root which can only be computed after the block exists.
pub struct ExecutionPayloadData<E: types::EthSpec> {
    pub payload: ExecutionPayloadGloas<E>,
    pub execution_requests: ExecutionRequests<E>,
    pub builder_index: BuilderIndex,
    pub slot: Slot,
    pub state_root: Hash256,
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    // TODO(gloas) introduce `ProposerPreferences` so we can build out trustless
    // bid building. Right now this only works for local building.
    /// Produce an `ExecutionPayloadBid` for some `slot` upon the given `state`.
    /// This function assumes we've already done the state advance.
    ///
    /// Returns the signed bid, the state, and optionally the payload data needed to construct
    /// the `ExecutionPayloadEnvelope` after the beacon block is created.
    ///
    /// For local building, payload data is always returned (`Some`).
    /// For trustless building, the builder provides the envelope separately, so `None` is returned.
    #[instrument(level = "debug", skip_all)]
    pub async fn produce_execution_payload_bid(
        self: Arc<Self>,
        state: BeaconState<T::EthSpec>,
        state_root_opt: Option<Hash256>,
        produce_at_slot: Slot,
        bid_value: u64,
        builder_index: BuilderIndex,
    ) -> Result<
        (
            SignedExecutionPayloadBid<T::EthSpec>,
            BeaconState<T::EthSpec>,
            Option<ExecutionPayloadData<T::EthSpec>>,
        ),
        BlockProductionError,
    > {
        // TODO(gloas) For non local building, add sanity check on value
        // The builder MUST have enough excess balance to fulfill this bid (i.e. `value`) and all pending payments.

        // TODO(gloas) add metrics for execution payload bid production

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

        let block_contents_type = prepare_payload_handle
            .await
            .map_err(BlockProductionError::TokioJoin)?
            .ok_or(BlockProductionError::ShuttingDown)??;

        let (execution_payload, blob_kzg_commitments, execution_requests) =
            match block_contents_type {
                BlockProposalContentsType::Full(block_proposal_contents) => {
                    let (payload, blob_kzg_commitments, _, execution_requests, _) =
                        block_proposal_contents.deconstruct();

                    if let Some(blob_kzg_commitments) = blob_kzg_commitments
                        && let Some(execution_requests) = execution_requests
                    {
                        (
                            payload.execution_payload(),
                            blob_kzg_commitments,
                            execution_requests,
                        )
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
            };

        let state_root = state_root_opt.ok_or_else(|| BlockProductionError::MissingStateRoot)?;

        // TODO(gloas) this is just a dummy error variant for now
        let execution_payload_gloas = execution_payload
            .as_gloas()
            .map_err(|_| BlockProductionError::GloasNotImplemented)?
            .to_owned();

        let bid = ExecutionPayloadBid::<T::EthSpec> {
            parent_block_hash: state.latest_block_hash()?.to_owned(),
            parent_block_root: state.get_latest_block_root(state_root),
            block_hash: execution_payload.block_hash(),
            prev_randao: execution_payload.prev_randao(),
            fee_recipient: Address::ZERO,
            gas_limit: execution_payload.gas_limit(),
            builder_index,
            slot: produce_at_slot,
            value: bid_value,
            execution_payment: 0,
            blob_kzg_commitments,
        };

        // Store payload data for envelope construction after block is created
        let payload_data = ExecutionPayloadData {
            payload: execution_payload_gloas,
            execution_requests,
            builder_index,
            slot: produce_at_slot,
            state_root,
        };

        // TODO(gloas) this is only local building
        // we'll need to implement builder signature for the trustless path
        Ok((
            SignedExecutionPayloadBid {
                message: bid,
                // TODO(gloas) return better error variant here
                signature: Signature::infinity()
                    .map_err(|_| BlockProductionError::GloasNotImplemented)?,
            },
            state,
            // Local building always returns payload data.
            // Trustless building would return None here.
            Some(payload_data),
        ))
    }
}
