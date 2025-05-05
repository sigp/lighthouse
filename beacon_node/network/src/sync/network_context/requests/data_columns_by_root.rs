use lighthouse_network::rpc::methods::DataColumnsByRootRequest;
use std::sync::Arc;
use types::{
    ChainSpec, DataColumnSidecar, DataColumnsByRootIdentifier, EthSpec, Hash256,
    RuntimeVariableList,
};

use super::{ActiveRequestItems, LookupVerifyError};

#[derive(Debug, Clone)]
pub struct DataColumnsByRootSingleBlockRequest {
    pub block_root: Hash256,
    pub indices: Vec<u64>,
}

impl DataColumnsByRootSingleBlockRequest {
    pub fn into_request(self, spec: &ChainSpec) -> DataColumnsByRootRequest {
        let number_of_columns = spec.number_of_columns as usize;
        // TODO we aren't handling the case where self.indices > NUMBER_OF_COLUMNS defined by the
        // spec. Do we do this else where? I think we shall use RuntimeVariableList::new() and
        // handle errors.
        let indices = RuntimeVariableList::from_vec(self.indices, number_of_columns);
        DataColumnsByRootRequest::new(
            vec![DataColumnsByRootIdentifier {
                block_root: self.block_root,
                indices,
            }],
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
            return Err(LookupVerifyError::DuplicatedData(
                data_column.slot(),
                data_column.index,
            ));
        }

        self.items.push(data_column);

        Ok(self.items.len() >= self.request.indices.len())
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
