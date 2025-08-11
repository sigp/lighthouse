use crate::fetch_blobs::{EngineGetBlobsOutput, FetchEngineBlobError};
use crate::observed_block_producers::ProposalKey;
use crate::{AvailabilityProcessingStatus, BeaconChain, BeaconChainTypes};
use execution_layer::json_structures::{BlobAndProofV1, BlobAndProofV2};
use kzg::Kzg;
#[cfg(test)]
use mockall::automock;
use std::collections::HashSet;
use std::sync::Arc;
use task_executor::TaskExecutor;
use types::{ChainSpec, ColumnIndex, Hash256, Slot};

/// An adapter to the `BeaconChain` functionalities to remove `BeaconChain` from direct dependency to enable testing fetch blobs logic.
pub(crate) struct FetchBlobsBeaconAdapter<T: BeaconChainTypes> {
    chain: Arc<BeaconChain<T>>,
    spec: Arc<ChainSpec>,
}

#[cfg_attr(test, automock, allow(dead_code))]
impl<T: BeaconChainTypes> FetchBlobsBeaconAdapter<T> {
    pub(crate) fn new(chain: Arc<BeaconChain<T>>) -> Self {
        let spec = chain.spec.clone();
        Self { chain, spec }
    }

    pub(crate) fn spec(&self) -> &Arc<ChainSpec> {
        &self.spec
    }

    pub(crate) fn kzg(&self) -> &Arc<Kzg> {
        &self.chain.kzg
    }

    pub(crate) fn executor(&self) -> &TaskExecutor {
        &self.chain.task_executor
    }

    pub(crate) async fn get_blobs_v1(
        &self,
        versioned_hashes: Vec<Hash256>,
    ) -> Result<Vec<Option<BlobAndProofV1<T::EthSpec>>>, FetchEngineBlobError> {
        let execution_layer = self
            .chain
            .execution_layer
            .as_ref()
            .ok_or(FetchEngineBlobError::ExecutionLayerMissing)?;

        execution_layer
            .get_blobs_v1(versioned_hashes)
            .await
            .map_err(FetchEngineBlobError::RequestFailed)
    }

    pub(crate) async fn get_blobs_v2(
        &self,
        versioned_hashes: Vec<Hash256>,
    ) -> Result<Option<Vec<BlobAndProofV2<T::EthSpec>>>, FetchEngineBlobError> {
        let execution_layer = self
            .chain
            .execution_layer
            .as_ref()
            .ok_or(FetchEngineBlobError::ExecutionLayerMissing)?;

        execution_layer
            .get_blobs_v2(versioned_hashes)
            .await
            .map_err(FetchEngineBlobError::RequestFailed)
    }

    pub(crate) fn blobs_known_for_proposal(
        &self,
        proposer: u64,
        slot: Slot,
    ) -> Option<HashSet<u64>> {
        let proposer_key = ProposalKey::new(proposer, slot);
        self.chain
            .observed_blob_sidecars
            .read()
            .known_for_proposal(&proposer_key)
            .cloned()
    }

    pub(crate) fn data_column_known_for_proposal(
        &self,
        proposal_key: ProposalKey,
    ) -> Option<HashSet<ColumnIndex>> {
        self.chain
            .observed_column_sidecars
            .read()
            .known_for_proposal(&proposal_key)
            .cloned()
    }

    pub(crate) fn cached_blob_indexes(&self, block_root: &Hash256) -> Option<Vec<u64>> {
        self.chain
            .data_availability_checker
            .cached_blob_indexes(block_root)
    }

    pub(crate) fn cached_data_column_indexes(&self, block_root: &Hash256) -> Option<Vec<u64>> {
        self.chain
            .data_availability_checker
            .cached_data_column_indexes(block_root)
    }

    pub(crate) async fn process_engine_blobs(
        &self,
        slot: Slot,
        block_root: Hash256,
        blobs: EngineGetBlobsOutput<T>,
    ) -> Result<AvailabilityProcessingStatus, FetchEngineBlobError> {
        self.chain
            .process_engine_blobs(slot, block_root, blobs)
            .await
            .map_err(FetchEngineBlobError::BlobProcessingError)
    }

    pub(crate) fn fork_choice_contains_block(&self, block_root: &Hash256) -> bool {
        self.chain
            .canonical_head
            .fork_choice_read_lock()
            .contains_block(block_root)
    }
}
