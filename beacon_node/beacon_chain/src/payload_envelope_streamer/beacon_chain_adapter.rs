use std::sync::Arc;

use execution_layer::ExecutionPayloadBodyV2;
#[cfg(test)]
use mockall::automock;
use task_executor::TaskExecutor;
use types::{
    ExecutionBlockHash, ExecutionPayloadGloas, Hash256, SignedExecutionPayloadEnvelopeSummary, Slot,
};

use super::Error;
use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};

/// Exposes the `BeaconChain` functionality required by the payload envelope streamer without
/// coupling its reconstruction logic directly to `BeaconChain`.
pub(crate) struct EnvelopeStreamerBeaconAdapter<T: BeaconChainTypes> {
    chain: Arc<BeaconChain<T>>,
}

#[cfg_attr(test, automock, allow(dead_code))]
impl<T: BeaconChainTypes> EnvelopeStreamerBeaconAdapter<T> {
    pub(crate) fn new(chain: Arc<BeaconChain<T>>) -> Self {
        Self { chain }
    }

    pub(crate) fn executor(&self) -> &TaskExecutor {
        &self.chain.task_executor
    }

    pub(crate) fn get_payload_envelope_summary(
        &self,
        root: &Hash256,
    ) -> Result<Option<SignedExecutionPayloadEnvelopeSummary<T::EthSpec>>, store::Error> {
        self.chain.store.get_payload_envelope_summary(root)
    }

    pub(crate) fn get_envelope_payload(
        &self,
        root: &Hash256,
    ) -> Result<Option<ExecutionPayloadGloas<T::EthSpec>>, store::Error> {
        self.chain.store.get_envelope_payload(root)
    }

    pub(crate) async fn get_payload_bodies_by_hash_v2(
        &self,
        block_hashes: Vec<ExecutionBlockHash>,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV2>>, BeaconChainError> {
        let execution_layer = self
            .chain
            .execution_layer
            .as_ref()
            .ok_or(BeaconChainError::ExecutionLayerMissing)?;

        execution_layer
            .get_payload_bodies_by_hash_v2(block_hashes)
            .await
            .map_err(|error| Error::PayloadBodiesByHashV2Failure(Box::new(error)).into())
    }

    pub(crate) fn get_split_slot(&self) -> Slot {
        self.chain.store.get_split_info().slot
    }

    pub(crate) fn block_has_canonical_payload(
        &self,
        root: &Hash256,
    ) -> Result<bool, BeaconChainError> {
        self.chain
            .canonical_head
            .block_has_canonical_payload(root, &self.chain.spec)
    }
}
