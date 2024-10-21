use lighthouse_network::rpc::methods::DataColumnsByRootRequest;
use std::sync::Arc;
use types::{ChainSpec, DataColumnIdentifier, DataColumnSidecar, EthSpec, Hash256};

use super::{ActiveRequestItems, LookupVerifyError};

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

pub struct DataColumnsByRootRequestItems<E: EthSpec> {
    request: DataColumnsByRootSingleBlockRequest,
    items: Vec<Arc<DataColumnSidecar<E>>>,
}

impl<E: EthSpec> DataColumnsByRootRequestItems<E> {
    pub fn new(request: DataColumnsByRootSingleBlockRequest) -> Self {
        Self {
            request,
            items: vec![],
        }
    }
}

impl<E: EthSpec> ActiveRequestItems for DataColumnsByRootRequestItems<E> {
    type Item = Arc<DataColumnSidecar<E>>;

    /// Appends a chunk to this multi-item request. If all expected chunks are received, this
    /// method returns `Some`, resolving the request before the stream terminator.
    /// The active request SHOULD be dropped after `add_response` returns an error
    fn add(&mut self, data_column: Self::Item) -> Result<bool, LookupVerifyError> {
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

        Ok(self.items.len() >= self.request.indices.len())
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
