use super::{ActiveRequestItems, LookupVerifyError};
use lighthouse_network::rpc::methods::DataColumnsByRangeRequest;
use std::sync::Arc;
use types::{DataColumnSidecar, EthSpec};

/// Accumulates results of a data_columns_by_range request. Only returns items after receiving the
/// stream termination.
pub struct DataColumnsByRangeRequestItems<E: EthSpec> {
    request: DataColumnsByRangeRequest,
    items: Vec<Arc<DataColumnSidecar<E>>>,
}

impl<E: EthSpec> DataColumnsByRangeRequestItems<E> {
    pub fn new(request: DataColumnsByRangeRequest) -> Self {
        Self {
            request,
            items: vec![],
        }
    }
}

impl<E: EthSpec> ActiveRequestItems for DataColumnsByRangeRequestItems<E> {
    type Item = Arc<DataColumnSidecar<E>>;

    fn add(&mut self, data_column: Self::Item) -> Result<bool, LookupVerifyError> {
        if data_column.slot() < self.request.start_slot
            || data_column.slot() >= self.request.start_slot + self.request.count
        {
            return Err(LookupVerifyError::UnrequestedSlot(data_column.slot()));
        }
        if !self.request.columns.contains(&data_column.index) {
            return Err(LookupVerifyError::UnrequestedIndex(data_column.index));
        }
        if !data_column.verify_inclusion_proof() {
            return Err(LookupVerifyError::InvalidInclusionProof);
        }
        if self.items.iter().any(|existing| {
            existing.slot() == data_column.slot() && existing.index == data_column.index
        }) {
            return Err(LookupVerifyError::DuplicatedData(
                data_column.slot(),
                data_column.index,
            ));
        }

        self.items.push(data_column);

        Ok(self.items.len() >= self.request.count as usize * self.request.columns.len())
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
