use lighthouse_network::rpc::methods::DataColumnsByRootRequest;
use ssz_types::VariableList;
use std::{collections::HashMap, sync::Arc};
use types::{
    ChainSpec, DataColumnSidecar, DataColumnsByRootIdentifier, EthSpec, ForkName, Hash256,
};

use super::{ActiveRequestItems, LookupVerifyError};

#[derive(Debug, Clone)]
pub struct DataColumnsByRootBatchBlockRequest {
    pub block_roots: Vec<Hash256>,
    pub indices: Vec<u64>,
}

impl DataColumnsByRootBatchBlockRequest {
    pub fn try_into_request<E: EthSpec>(
        self,
        fork_name: ForkName,
        spec: &ChainSpec,
    ) -> Result<DataColumnsByRootRequest<E>, &'static str> {
        let columns = VariableList::new(self.indices)
            .map_err(|_| "Number of indices exceeds total number of columns")?;
        let ids: Vec<_> = self
            .block_roots
            .into_iter()
            .map(|block_root| DataColumnsByRootIdentifier {
                block_root,
                columns: columns.clone(),
            })
            .collect();
        assert!(ids.len() <= 32);
        Ok(DataColumnsByRootRequest::new(
            ids,
            spec.max_request_blocks(fork_name),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct DataColumnsByRootSingleBlockRequest {
    pub block_root: Hash256,
    pub indices: Vec<u64>,
}

impl DataColumnsByRootSingleBlockRequest {
    pub fn try_into_request<E: EthSpec>(
        self,
        fork_name: ForkName,
        spec: &ChainSpec,
    ) -> Result<DataColumnsByRootRequest<E>, &'static str> {
        let columns = VariableList::new(self.indices)
            .map_err(|_| "Number of indices exceeds total number of columns")?;
        Ok(DataColumnsByRootRequest::new(
            vec![DataColumnsByRootIdentifier {
                block_root: self.block_root,
                columns,
            }],
            spec.max_request_blocks(fork_name),
        ))
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

pub struct DataColumnsByRootRangeRequestItems<E: EthSpec> {
    request: DataColumnsByRootBatchBlockRequest,
    items: HashMap<Hash256, Vec<Arc<DataColumnSidecar<E>>>>,
}

impl<E: EthSpec> DataColumnsByRootRangeRequestItems<E> {
    pub fn new(request: DataColumnsByRootBatchBlockRequest) -> Self {
        Self {
            request,
            items: HashMap::new(),
        }
    }
}

impl<E: EthSpec> ActiveRequestItems for DataColumnsByRootRangeRequestItems<E> {
    type Item = Arc<DataColumnSidecar<E>>;

    /// Appends a chunk to this multi-item request. If all expected chunks are received, this
    /// method returns `Some`, resolving the request before the stream terminator.
    /// The active request SHOULD be dropped after `add_response` returns an error
    fn add(&mut self, data_column: Self::Item) -> Result<bool, LookupVerifyError> {
        let block_root = data_column.block_root();
        if !self.request.block_roots.contains(&block_root) {
            return Err(LookupVerifyError::UnrequestedBlockRoot(block_root));
        }
        if !data_column.verify_inclusion_proof() {
            return Err(LookupVerifyError::InvalidInclusionProof);
        }
        if !self.request.indices.contains(&data_column.index) {
            return Err(LookupVerifyError::UnrequestedIndex(data_column.index));
        }
        if self
            .items
            .values()
            .flatten()
            .any(|d| d.index == data_column.index && d.block_root() == block_root)
        {
            tracing::debug!(
                ?data_column,
                existing_items=?self.items,
                "Duplicated data",
            );
            return Err(LookupVerifyError::DuplicatedData(
                data_column.slot(),
                data_column.index,
            ));
        }

        self.items.entry(block_root).or_default().push(data_column);

        Ok(self
            .items
            .values()
            .map(|columns| columns.len())
            .sum::<usize>()
            >= self.request.indices.len() * self.request.block_roots.len())
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
            .into_values()
            .flatten()
            .collect()
    }
}
