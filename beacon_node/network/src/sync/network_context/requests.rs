use beacon_chain::get_block_root;
use lighthouse_network::{
    rpc::{
        methods::{BlobsByRootRequest, DataColumnsByRootRequest},
        BlocksByRootRequest, RPCError,
    },
    PeerId,
};
use std::sync::Arc;
use strum::IntoStaticStr;
use types::{
    blob_sidecar::BlobIdentifier, data_column_sidecar::DataColumnIdentifier, BlobSidecar,
    ChainSpec, DataColumnSidecar, EthSpec, Hash256, SignedBeaconBlock,
};

#[derive(Debug, PartialEq, Eq, IntoStaticStr)]
pub enum LookupVerifyError {
    NoResponseReturned,
    NotEnoughResponsesReturned { expected: usize, actual: usize },
    TooManyResponses,
    UnrequestedBlockRoot(Hash256),
    UnrequestedBlobIndex(u64),
    InvalidInclusionProof,
    DuplicateData,
}

pub struct ActiveBlocksByRootRequest {
    request: BlocksByRootSingleRequest,
    resolved: bool,
    pub(crate) peer_id: PeerId,
}

impl ActiveBlocksByRootRequest {
    pub fn new(request: BlocksByRootSingleRequest, peer_id: PeerId) -> Self {
        Self {
            request,
            resolved: false,
            peer_id,
        }
    }

    /// Append a response to the single chunk request. If the chunk is valid, the request is
    /// resolved immediately.
    /// The active request SHOULD be dropped after `add_response` returns an error
    pub fn add_response<E: EthSpec>(
        &mut self,
        block: Arc<SignedBeaconBlock<E>>,
    ) -> Result<Arc<SignedBeaconBlock<E>>, LookupVerifyError> {
        if self.resolved {
            return Err(LookupVerifyError::TooManyResponses);
        }

        let block_root = get_block_root(&block);
        if self.request.0 != block_root {
            return Err(LookupVerifyError::UnrequestedBlockRoot(block_root));
        }

        // Valid data, blocks by root expects a single response
        self.resolved = true;
        Ok(block)
    }

    pub fn terminate(self) -> Result<(), LookupVerifyError> {
        if self.resolved {
            Ok(())
        } else {
            Err(LookupVerifyError::NoResponseReturned)
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct BlocksByRootSingleRequest(pub Hash256);

impl BlocksByRootSingleRequest {
    pub fn into_request(self, spec: &ChainSpec) -> BlocksByRootRequest {
        BlocksByRootRequest::new(vec![self.0], spec)
    }
}

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
            return Err(LookupVerifyError::UnrequestedBlobIndex(blob.index));
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

#[derive(Debug, Clone)]
pub struct DataColumnsByRootSingleBlockRequest {
    pub block_root: Hash256,
    pub indices: Vec<u64>,
}

impl DataColumnsByRootSingleBlockRequest {
    pub fn into_request(self, spec: &ChainSpec) -> DataColumnsByRootRequest {
        DataColumnsByRootRequest::new(
            self.indices
                .into_iter()
                .map(|index| DataColumnIdentifier {
                    block_root: self.block_root,
                    index,
                })
                .collect(),
            spec,
        )
    }
}

pub struct ActiveDataColumnsByRootRequest<E: EthSpec> {
    request: DataColumnsByRootSingleBlockRequest,
    items: Vec<Arc<DataColumnSidecar<E>>>,
    resolved: bool,
}

impl<E: EthSpec> ActiveDataColumnsByRootRequest<E> {
    pub fn new(request: DataColumnsByRootSingleBlockRequest) -> Self {
        Self {
            request,
            items: vec![],
            resolved: false,
        }
    }

    /// Appends a chunk to this multi-item request. If all expected chunks are received, this
    /// method returns `Some`, resolving the request before the stream terminator.
    /// The active request SHOULD be dropped after `add_response` returns an error
    pub fn add_response(
        &mut self,
        data_column: Arc<DataColumnSidecar<E>>,
    ) -> Result<Option<Vec<Arc<DataColumnSidecar<E>>>>, RPCError> {
        if self.resolved {
            return Err(RPCError::InvalidData("too many responses".to_string()));
        }

        let block_root = data_column.block_root();
        if self.request.block_root != block_root {
            return Err(RPCError::InvalidData(format!(
                "un-requested block root {block_root:?}"
            )));
        }
        if !data_column.verify_inclusion_proof() {
            return Err(RPCError::InvalidData("invalid inclusion proof".to_string()));
        }
        if !self.request.indices.contains(&data_column.index) {
            return Err(RPCError::InvalidData(format!(
                "un-requested index {}",
                data_column.index
            )));
        }
        if self.items.iter().any(|b| b.index == data_column.index) {
            return Err(RPCError::InvalidData("duplicated data".to_string()));
        }

        self.items.push(data_column);
        if self.items.len() >= self.request.indices.len() {
            // All expected chunks received, return result early
            self.resolved = true;
            Ok(Some(std::mem::take(&mut self.items)))
        } else {
            Ok(None)
        }
    }

    pub fn terminate(self) -> Option<Vec<Arc<DataColumnSidecar<E>>>> {
        if self.resolved {
            None
        } else {
            Some(self.items)
        }
    }
}
