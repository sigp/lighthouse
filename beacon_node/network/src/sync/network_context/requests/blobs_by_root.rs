use lighthouse_network::rpc::methods::BlobsByRootRequest;
use std::sync::Arc;
use types::{blob_sidecar::BlobIdentifier, BlobSidecar, ChainSpec, EthSpec, Hash256};

use super::{ActiveRequestItems, LookupVerifyError};

#[derive(Debug, Clone)]
pub struct BlobsByRootSingleBlockRequest {
    pub block_root: Hash256,
    pub indices: Vec<u64>,
}

impl BlobsByRootSingleBlockRequest {
    pub fn into_request(self, spec: &ChainSpec) -> BlobsByRootRequest {
        BlobsByRootRequest::new(
            self.indices
                .into_iter()
                .map(|index| BlobIdentifier {
                    block_root: self.block_root,
                    index,
                })
                .collect(),
            spec,
        )
    }
}

pub struct BlobsByRootRequestItems<E: EthSpec> {
    request: BlobsByRootSingleBlockRequest,
    items: Vec<Arc<BlobSidecar<E>>>,
}

impl<E: EthSpec> BlobsByRootRequestItems<E> {
    pub fn new(request: BlobsByRootSingleBlockRequest) -> Self {
        Self {
            request,
            items: vec![],
        }
    }
}

impl<E: EthSpec> ActiveRequestItems for BlobsByRootRequestItems<E> {
    type Item = Arc<BlobSidecar<E>>;

    /// Appends a chunk to this multi-item request. If all expected chunks are received, this
    /// method returns `Some`, resolving the request before the stream terminator.
    /// The active request SHOULD be dropped after `add_response` returns an error
    fn add(&mut self, blob: Self::Item) -> Result<bool, LookupVerifyError> {
        let block_root = blob.block_root();
        if self.request.block_root != block_root {
            return Err(LookupVerifyError::UnrequestedBlockRoot(block_root));
        }
        if !blob.verify_blob_sidecar_inclusion_proof() {
            return Err(LookupVerifyError::InvalidInclusionProof);
        }
        if !self.request.indices.contains(&blob.index) {
            return Err(LookupVerifyError::UnrequestedIndex(blob.index));
        }
        if self.items.iter().any(|b| b.index == blob.index) {
            return Err(LookupVerifyError::DuplicateData);
        }

        self.items.push(blob);

        Ok(self.items.len() >= self.request.indices.len())
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
