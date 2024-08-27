use lighthouse_network::service::api_types::DataColumnsByRootRequester;
use lighthouse_network::{rpc::methods::DataColumnsByRootRequest, PeerId};
use std::sync::Arc;
use types::{ChainSpec, DataColumnIdentifier, DataColumnSidecar, EthSpec, Hash256};

use super::LookupVerifyError;

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
    pub(crate) peer_id: PeerId,
    pub(crate) requester: DataColumnsByRootRequester,
}

impl<E: EthSpec> ActiveDataColumnsByRootRequest<E> {
    pub fn new(
        request: DataColumnsByRootSingleBlockRequest,
        peer_id: PeerId,
        requester: DataColumnsByRootRequester,
    ) -> Self {
        Self {
            request,
            items: vec![],
            resolved: false,
            peer_id,
            requester,
        }
    }

    /// Appends a chunk to this multi-item request. If all expected chunks are received, this
    /// method returns `Some`, resolving the request before the stream terminator.
    /// The active request SHOULD be dropped after `add_response` returns an error
    pub fn add_response(
        &mut self,
        data_column: Arc<DataColumnSidecar<E>>,
    ) -> Result<Option<Vec<Arc<DataColumnSidecar<E>>>>, LookupVerifyError> {
        if self.resolved {
            return Err(LookupVerifyError::TooManyResponses);
        }

        let block_root = data_column.block_root();
        if self.request.block_root != block_root {
            return Err(LookupVerifyError::UnrequestedBlockRoot(block_root));
        }
        if !data_column.verify_inclusion_proof() {
            return Err(LookupVerifyError::InvalidInclusionProof);
        }
        if !self.request.indices.contains(&data_column.index) {
            return Err(LookupVerifyError::UnrequestedIndex(data_column.index));
        }
        if self.items.iter().any(|d| d.index == data_column.index) {
            return Err(LookupVerifyError::DuplicateData);
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

    pub fn terminate(self) -> Result<(), LookupVerifyError> {
        if self.resolved {
            Ok(())
        } else {
            Err(LookupVerifyError::NotEnoughResponsesReturned {
                expected: self.request.indices.len(),
                actual: self.items.len(),
            })
        }
    }

    /// Mark request as resolved (= has returned something downstream) while marking this status as
    /// true for future calls.
    pub fn resolve(&mut self) -> bool {
        std::mem::replace(&mut self.resolved, true)
    }
}
