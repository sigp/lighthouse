use lighthouse_network::{rpc::methods::BlobsByRootRequest, PeerId};
use std::sync::Arc;
use types::{blob_sidecar::BlobIdentifier, BlobSidecar, ChainSpec, EthSpec, Hash256};

use super::LookupVerifyError;

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

pub struct ActiveBlobsByRootRequest<E: EthSpec> {
    request: BlobsByRootSingleBlockRequest,
    blobs: Vec<Arc<BlobSidecar<E>>>,
    resolved: bool,
    pub(crate) peer_id: PeerId,
}

impl<E: EthSpec> ActiveBlobsByRootRequest<E> {
    pub fn new(request: BlobsByRootSingleBlockRequest, peer_id: PeerId) -> Self {
        Self {
            request,
            blobs: vec![],
            resolved: false,
            peer_id,
        }
    }

    /// Appends a chunk to this multi-item request. If all expected chunks are received, this
    /// method returns `Some`, resolving the request before the stream terminator.
    /// The active request SHOULD be dropped after `add_response` returns an error
    pub fn add_response(
        &mut self,
        blob: Arc<BlobSidecar<E>>,
    ) -> Result<Option<Vec<Arc<BlobSidecar<E>>>>, LookupVerifyError> {
        if self.resolved {
            return Err(LookupVerifyError::TooManyResponses);
        }

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
        if self.blobs.iter().any(|b| b.index == blob.index) {
            return Err(LookupVerifyError::DuplicateData);
        }

        self.blobs.push(blob);
        if self.blobs.len() >= self.request.indices.len() {
            // All expected chunks received, return result early
            self.resolved = true;
            Ok(Some(std::mem::take(&mut self.blobs)))
        } else {
            Ok(None)
        }
    }

    pub fn terminate(self) -> Result<(), LookupVerifyError> {
        if self.resolved {
            Ok(())
        } else {
            Err(LookupVerifyError::NotEnoughResponsesReturned {
                expected: self.request.indices.len(),
                actual: self.blobs.len(),
            })
        }
    }

    /// Mark request as resolved (= has returned something downstream) while marking this status as
    /// true for future calls.
    pub fn resolve(&mut self) -> bool {
        std::mem::replace(&mut self.resolved, true)
    }
}
